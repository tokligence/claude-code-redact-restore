#!/usr/bin/env python3
"""
redmem dispatcher — single entry point for all Claude Code hook events.

Routes to:
- shield (redact-restore.py) for secret protection
- memory module for session archival/search/resume
- autopilot module for overnight /autopilot loops
"""
import json
import os
import re
import subprocess
import sys

HOOKS_DIR = os.path.dirname(os.path.abspath(__file__))
# Ensure memory module is importable when running from any cwd
if HOOKS_DIR not in sys.path:
    sys.path.insert(0, HOOKS_DIR)

# Task/plan tools that trigger state tracking
TASK_PLAN_TOOLS = {"TodoWrite", "TodoRead", "EnterPlanMode", "ExitPlanMode",
                   "TaskCreate", "TaskUpdate"}

# Recall-intent keywords
RECALL_RE = re.compile(
    r"(before|earlier|remember|recall|之前|上次|记得|还记得|migration\s+\d+)",
    re.IGNORECASE,
)

# Autopilot init marker (embedded by the /autopilot slash-command template)
AUTOPILOT_INIT_RE = re.compile(r"<!--\s*autopilot-init:")


def run_shield(input_json: str) -> dict:
    """Run the existing redact-restore.py and capture its output."""
    shield_path = os.path.join(HOOKS_DIR, "redact-restore.py")
    try:
        result = subprocess.run(
            [sys.executable, shield_path],
            input=input_json,
            capture_output=True,
            text=True,
            timeout=25,
        )
        if result.stdout.strip():
            return json.loads(result.stdout.strip())
        return {}
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return {}


def handle_pre_compact(data: dict):
    """Archive turns to SQLite on compact, then flag the session so the
    next UserPromptSubmit can re-inject the tools cheatsheet (Claude may
    have lost mid-session knowledge of available tools during compact)."""
    session_id = data.get("session_id", "")
    cwd = data.get("cwd", "")
    if not session_id:
        return

    try:
        from memory.ingest import archive_turns
        count = archive_turns(session_id, cwd)
        if count > 0:
            sys.stderr.write(f"[redmem] Archived {count} turns\n")
        # Generate session_state.md (Phase 1.5)
        from memory.session_state import generate_session_state
        generate_session_state(session_id, cwd)
        # Update cross-session knowledge index (Phase 4)
        from memory.knowledge import update_session_knowledge
        update_session_knowledge(session_id, cwd)
    except Exception as e:
        sys.stderr.write(f"[redmem] Archive error: {e}\n")

    # Drop the cheatsheet flag — independent of memory's success.
    try:
        from cheatsheet import mark_compact_pending
        mark_compact_pending(session_id)
    except Exception as e:
        sys.stderr.write(f"[redmem] cheatsheet mark error: {e}\n")


def handle_session_start(data: dict):
    """Inject resume context."""
    session_id = data.get("session_id", "")
    if not session_id:
        return

    try:
        # Archive any new turns FIRST to capture anything since last archive
        # (watch daemon may have missed up to its interval window)
        cwd_early = data.get("cwd", "")
        from memory.ingest import archive_turns
        try:
            archive_turns(session_id, cwd_early)
        except Exception:
            pass  # non-fatal, continue with existing archive

        from memory.summarize import build_resume_context
        context = build_resume_context(session_id)
        # Append cross-session knowledge if available
        cwd = data.get("cwd", "")
        if cwd:
            from memory.knowledge import search_knowledge
            # Extract goal from session_state.md (skip markdown boilerplate)
            import os
            goal_query = ""
            state_path = os.path.join(
                os.path.expanduser("~/.claude/vault/sessions"),
                f"{session_id}_state.md"
            )
            if os.path.isfile(state_path):
                with open(state_path) as sf:
                    for line in sf:
                        line = line.strip()
                        if line and not line.startswith("#") and not line.startswith("<!--"):
                            goal_query = line[:200]
                            break
            if not goal_query and context:
                # Fallback: extract first non-heading line from context
                for line in context.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and not line.startswith("<!--"):
                        import re as _re
                        line = _re.sub(r'^\[L\d+\]\s*\w+:\s*', '', line)
                        if line:
                            goal_query = line[:200]
                        break
            knowledge = search_knowledge(cwd, goal_query, current_session_id=session_id) if goal_query else ""
            if knowledge:
                context = (context + "\n\n" + knowledge) if context else knowledge
        if context:
            print(json.dumps({
                "hookSpecificOutput": {
                    "hookEventName": "SessionStart",
                    "additionalContext": context,
                }
            }))
            return
    except Exception as e:
        sys.stderr.write(f"[redmem] Resume error: {e}\n")


def handle_user_prompt_memory(data: dict, shield_result: dict) -> dict:
    """Search archive if recall keywords detected (Phase 2)."""
    prompt = data.get("prompt", "")
    if not RECALL_RE.search(prompt):
        return shield_result

    session_id = data.get("session_id", "")
    if not session_id:
        return shield_result

    try:
        from memory.search import search, format_results
        results = search(session_id, prompt, limit=5)
        if results:
            formatted = format_results(results)
            # Merge with shield's additionalContext if any
            hook_output = shield_result.get("hookSpecificOutput", {})
            existing_ctx = hook_output.get("additionalContext", "")
            if existing_ctx:
                formatted = existing_ctx + "\n\n" + formatted
            shield_result.setdefault("hookSpecificOutput", {})
            shield_result["hookSpecificOutput"]["hookEventName"] = "UserPromptSubmit"
            shield_result["hookSpecificOutput"]["additionalContext"] = formatted
    except Exception as e:
        sys.stderr.write(f"[redmem] Search error: {e}\n")

    return shield_result


def handle_cheatsheet_inject(data: dict) -> str:
    """If PreCompact flagged this session, consume the flag and return
    the cheatsheet text to prepend to additionalContext. Empty string
    otherwise. Fail-open."""
    session_id = data.get("session_id", "") or ""
    if not session_id:
        return ""
    try:
        from cheatsheet import consume_compact_pending, cheatsheet_text
        if consume_compact_pending(session_id):
            return cheatsheet_text()
    except Exception as e:
        sys.stderr.write(f"[redmem] cheatsheet inject error: {e}\n")
    return ""


def handle_autopilot_init(data: dict) -> str:
    """If the user-submitted prompt carries an autopilot-init marker,
    run preflight check and create/refresh the autopilot state. Returns a
    user-visible message to append to UserPromptSubmit's additionalContext
    (empty string if nothing to say). Fail-open on any error."""
    prompt = data.get("prompt", "") or ""
    if not AUTOPILOT_INIT_RE.search(prompt):
        return ""
    try:
        from autopilot.autopilot import handle_init
        msg = handle_init(data)
        return msg or ""
    except Exception as e:
        sys.stderr.write(f"[redmem] autopilot init error: {e}\n")
        return ""


def handle_pretooluse_bash_guard(data: dict) -> dict | None:
    """Autopilot-mode bash guard: deny destructive commands when autopilot
    is active for the session. Returns a deny response dict or None."""
    if data.get("tool_name") != "Bash":
        return None
    try:
        from autopilot.autopilot import check_bash_command
        return check_bash_command(data)
    except Exception as e:
        sys.stderr.write(f"[redmem] bash guard error: {e}\n")
        return None


def handle_pretooluse_image_compress(data: dict) -> dict | None:
    """Transparently downscale large images before Claude reads them, to
    save vision tokens. Active for all sessions; fail-open."""
    if data.get("tool_name") != "Read":
        return None
    try:
        from image_compressor import maybe_compress_read
        return maybe_compress_read(data)
    except Exception as e:
        sys.stderr.write(f"[redmem] image compress error: {e}\n")
        return None


def handle_pretooluse_image_original_req(data: dict) -> dict | None:
    """If CC issued the sentinel bash command `redmem-original <path>`,
    flag the next Read to serve the uncompressed original and deny the
    bash call (which wasn't a real program anyway)."""
    if data.get("tool_name") != "Bash":
        return None
    try:
        from image_compressor import maybe_handle_bash_original_request
        return maybe_handle_bash_original_request(data)
    except Exception as e:
        sys.stderr.write(f"[redmem] image-orig intercept error: {e}\n")
        return None


def handle_posttooluse_image_notice(data: dict) -> dict | None:
    """Emit a PostToolUse additionalContext telling CC the image it just
    read was auto-compressed, plus how to request the original."""
    if data.get("tool_name") != "Read":
        return None
    try:
        from image_compressor import maybe_notify_post_read
        return maybe_notify_post_read(data)
    except Exception as e:
        sys.stderr.write(f"[redmem] image notice error: {e}\n")
        return None


def handle_stop(data: dict):
    """Emit Stop hook decision for autopilot (or allow stop)."""
    try:
        from autopilot.autopilot import handle_stop_hook
        resp = handle_stop_hook(data)
    except Exception as e:
        sys.stderr.write(f"[redmem] autopilot stop-hook error: {e}\n")
        return
    if resp:
        print(json.dumps(resp))


def handle_task_event(data: dict):
    """Track task/plan changes for session state (Phase 1.5)."""
    session_id = data.get("session_id", "")
    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})
    tool_result = data.get("tool_result", {})
    if not session_id:
        return
    try:
        from memory.session_state import track_state_event
        track_state_event(session_id, tool_name, tool_input, tool_result)
    except Exception as e:
        sys.stderr.write(f"[redmem] Task tracking error: {e}\n")


def main():
    raw_input = sys.stdin.read()
    try:
        data = json.loads(raw_input)
    except json.JSONDecodeError:
        sys.exit(0)

    event = data.get("hook_event_name", "")

    # ── PreCompact: archive turns (memory only, shield not involved) ──
    if event == "PreCompact":
        handle_pre_compact(data)
        sys.exit(0)

    # ── SessionStart: inject resume context (memory only) ──
    if event == "SessionStart":
        source = data.get("source", "")
        if source == "resume":
            handle_session_start(data)
        sys.exit(0)

    # ── UserPromptSubmit: shield first, then memory search, then autopilot init ──
    if event == "UserPromptSubmit":
        shield_result = run_shield(raw_input)

        # If shield blocked, don't run memory search / autopilot init
        blocked = shield_result.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"
        if shield_result.get("decision") == "block":
            blocked = True

        # Secret-ops guard — handle "go-secret" / "pass-secret N" / "pass-secret off"
        # keywords that approve a queued PreToolUse Bash command. Runs even if
        # shield blocked because the keyword phrases don't contain secrets and
        # the user might be unblocking unrelated state.
        try:
            from secret_ops_guard import handle_user_prompt as secret_ops_user_prompt
            prompt_text = data.get("prompt") or data.get("user_prompt") or ""
            so_result = secret_ops_user_prompt(data, prompt_text)
            if so_result:
                so_ctx = so_result.get("hookSpecificOutput", {}).get("additionalContext", "")
                if so_ctx:
                    shield_result.setdefault("hookSpecificOutput", {})
                    shield_result["hookSpecificOutput"]["hookEventName"] = "UserPromptSubmit"
                    existing_ctx = shield_result["hookSpecificOutput"].get("additionalContext", "")
                    shield_result["hookSpecificOutput"]["additionalContext"] = (
                        (existing_ctx + "\n\n" + so_ctx) if existing_ctx else so_ctx
                    )
        except Exception:
            pass

        if not blocked:
            shield_result = handle_user_prompt_memory(data, shield_result)
            init_msg = handle_autopilot_init(data)
            cheatsheet_msg = handle_cheatsheet_inject(data)
            extras = [s for s in (cheatsheet_msg, init_msg) if s]
            if extras:
                # Append cheatsheet (post-compact) and/or autopilot init
                # banner to additionalContext so Claude and the user see them.
                shield_result.setdefault("hookSpecificOutput", {})
                shield_result["hookSpecificOutput"]["hookEventName"] = "UserPromptSubmit"
                existing_ctx = shield_result["hookSpecificOutput"].get("additionalContext", "")
                joined = "\n\n".join(extras)
                shield_result["hookSpecificOutput"]["additionalContext"] = (
                    (existing_ctx + "\n\n" + joined) if existing_ctx else joined
                )

        if shield_result:
            print(json.dumps(shield_result))
        sys.exit(0)

    # ── Stop: autopilot may inject continuation and keep the loop going ──
    if event == "Stop":
        handle_stop(data)
        sys.exit(0)

    # ── PreToolUse: shield secret-restore, secret-ops guard, then autopilot bash guard ──
    if event == "PreToolUse":
        shield_result = run_shield(raw_input)

        # If shield denied (e.g. blocked-file read), emit and stop here.
        shield_denied = (
            shield_result.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"
            or shield_result.get("decision") == "block"
        )
        if shield_denied:
            if shield_result:
                print(json.dumps(shield_result))
            sys.exit(0)

        # Secret-ops guard — soft-block PreToolUse Bash on commands that
        # would print prod-grade secrets (aws secretsmanager get-secret-value,
        # SSM SecureString reads, KMS decrypt, RDS master password modify).
        # User authorizes via "go-secret" or "pass-secret N" in the next
        # UserPromptSubmit (handled below).
        try:
            from secret_ops_guard import check as secret_ops_check
            secret_ops_resp = secret_ops_check(data)
            if secret_ops_resp:
                print(json.dumps(secret_ops_resp))
                sys.exit(0)
        except Exception:
            # Never let a guard bug brick the whole hook chain.
            pass

        # Image-original sentinel intercept (runs BEFORE autopilot bash
        # guard — we want CC to be able to request originals even under
        # autopilot, and the sentinel never actually executes a command).
        orig_resp = handle_pretooluse_image_original_req(data)
        if orig_resp:
            print(json.dumps(orig_resp))
            sys.exit(0)

        # Autopilot bash guard (only fires if session has active autopilot state).
        guard_resp = handle_pretooluse_bash_guard(data)
        if guard_resp:
            print(json.dumps(guard_resp))
            sys.exit(0)

        # Image compressor (all sessions). Wins if it rewrites file_path,
        # because shield has no meaningful change for non-blocked Read paths.
        img_resp = handle_pretooluse_image_compress(data)
        if img_resp:
            print(json.dumps(img_resp))
            sys.exit(0)

        if shield_result:
            print(json.dumps(shield_result))
        sys.exit(0)

    # ── PostToolUse: shield restore, task tracking, image notice ──
    if event == "PostToolUse":
        tool_name = data.get("tool_name", "")
        shield_result = run_shield(raw_input)

        if tool_name in TASK_PLAN_TOOLS:
            handle_task_event(data)

        # Image-compressed Read notice (additionalContext). Merge with
        # any additionalContext shield may have produced.
        img_notice = handle_posttooluse_image_notice(data)
        if img_notice:
            new_ctx = img_notice.get("hookSpecificOutput", {}).get("additionalContext", "")
            if new_ctx:
                shield_result.setdefault("hookSpecificOutput", {})
                shield_result["hookSpecificOutput"]["hookEventName"] = "PostToolUse"
                existing_ctx = shield_result["hookSpecificOutput"].get("additionalContext", "")
                shield_result["hookSpecificOutput"]["additionalContext"] = (
                    (existing_ctx + "\n\n" + new_ctx) if existing_ctx else new_ctx
                )

        if shield_result:
            print(json.dumps(shield_result))
        sys.exit(0)

    # ── All other events (SessionEnd, etc.): pass to shield ──
    shield_result = run_shield(raw_input)
    if shield_result:
        print(json.dumps(shield_result))
    sys.exit(0)


if __name__ == "__main__":
    main()
