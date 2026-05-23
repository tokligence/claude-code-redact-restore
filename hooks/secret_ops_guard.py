"""
secret_ops_guard — soft-block PreToolUse on Bash commands that would
expose production-grade secrets (AWS Secrets Manager reads, KMS decrypts,
SSM SecureString reads).

Pattern matches a small explicit list. On match:
  1. Save the pending Bash command to the shared session state file
     (same file claude-secret-shield uses for "go"/"pass" prompt bypass).
  2. Return permissionDecision="deny" with a reason telling Claude that
     the user must type "go-secret" or "pass-secret N" to approve.

When the user types one of those keywords (handled by redact-restore's
UserPromptSubmit logic, extended in a sibling patch), state's
`secret_ops_bypass_remaining` is set. The next PreToolUse with a matching
command + bypass_remaining > 0 is allowed and the counter is decremented.

Distinct keyword space from the existing prompt "go"/"pass" so the two
mechanisms don't interfere — prompt-level secret scanning protects
UserPromptSubmit, this guards PreToolUse Bash.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import sys
import tempfile
from typing import Optional

# Dedicated state file — kept SEPARATE from redact-restore's shield
# session state to avoid cross-feature blob overwrites (Codex R2 [P2]).
# Both files share the session+agent key but live at different paths.
_STATE_PREFIX = ".claude-secret-ops-"


def _session_id(payload: dict) -> str:
    value = payload.get("session_id")
    if isinstance(value, str) and value:
        return value
    return "default"


def _agent_scope(payload: dict) -> str:
    """Mirror redact-restore's get_agent_scope() — checks the same payload
    keys in the same priority so parallel subagents are isolated identically
    across both features (Codex R3 [P1])."""
    for key in ("agent_id", "agent_type", "transcript_path"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    return "main"


def _state_key(payload: dict) -> str:
    return f"{_session_id(payload)}::{_agent_scope(payload)}"


def _state_path(state_key: str) -> str:
    h = hashlib.sha256(state_key.encode("utf-8", errors="replace")).hexdigest()[:16]
    return os.path.join(tempfile.gettempdir(), f"{_STATE_PREFIX}{h}.json")


def _load_state(state_key: str) -> dict:
    try:
        with open(_state_path(state_key), "r") as f:
            return json.load(f) or {}
    except (OSError, json.JSONDecodeError):
        return {}


def _save_state(state_key: str, state: dict) -> None:
    """Raises on OSError / OS-permission errors. Callers (in check() / the
    UserPromptSubmit handler) wrap I/O in try/except and fail-closed on
    error so a non-writable tempdir doesn't silently disable the guard."""
    fd = os.open(_state_path(state_key), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(state, f)


@contextlib.contextmanager
def _exclusive_state(state_key: str):
    """
    Atomic load-modify-save with exclusive file lock (POSIX fcntl).

    Codex R4 [P1]: two parallel PreToolUse Bash hooks for the same
    session/agent could both read remaining=1, both decide to allow,
    both write remaining=0 — over-consuming the user's approval.
    Wrapping the critical section in fcntl.flock(LOCK_EX) serializes
    concurrent hook processes so the read/modify/save is atomic.

    On context exit (normal or via early return), the (possibly
    mutated) state is persisted to disk and the lock is released.

    Caller responsibility: only mutate the yielded `state` dict.
    Raising inside the with-block aborts the write (lock still
    released) — callers wrap with try/except and use _fail_closed().
    """
    path = _state_path(state_key)
    # O_RDWR | O_CREAT — open or create the state file. We hold the
    # fd for the lifetime of the lock so writes & lock share fd.
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        # Read current contents (may be empty)
        os.lseek(fd, 0, 0)
        blob = os.read(fd, 1 << 20) or b"{}"
        try:
            state = json.loads(blob) if blob else {}
            if not isinstance(state, dict):
                state = {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            state = {}

        yield state  # caller mutates `state` in place

        # Persist
        new_blob = json.dumps(state).encode("utf-8")
        os.lseek(fd, 0, 0)
        os.write(fd, new_blob)
        os.ftruncate(fd, len(new_blob))
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


# ─────────────────────────────────────────────────────────────────────────────
# Patterns
#
# Conservative list — only commands that DEFINITELY expose secret material in
# stdout. Adding too many breeds false positives and trains the user to spam
# "pass-secret off".
# ─────────────────────────────────────────────────────────────────────────────
# Helper: an `aws ...` subcommand with optional global flags before it.
# Matches  `aws secretsmanager`, `aws --profile prod secretsmanager`,
#          `aws --region us-east-1 --profile prod secretsmanager`, etc.
def _aws_pat(subcommand: str) -> "re.Pattern":
    return re.compile(
        r"\baws\s+(?:--[a-z-]+(?:[= ]\S+)?\s+)*" + subcommand,
        re.IGNORECASE,
    )


DANGEROUS_BASH_PATTERNS = [
    (
        "aws-secretsmanager-get-secret-value",
        _aws_pat(r"secretsmanager\s+get-secret-value\b"),
    ),
    (
        "aws-ssm-get-parameter-with-decryption",
        _aws_pat(r"ssm\s+get-parameter[s]?\b.*--with-decryption"),
    ),
    (
        "aws-kms-decrypt",
        _aws_pat(r"kms\s+decrypt\b"),
    ),
    (
        "aws-rds-modify-master-password",
        _aws_pat(r"rds\s+modify-db-(?:cluster|instance)\b.*--master-user-password"),
    ),
]


def _match_command(cmd: str) -> Optional[str]:
    """Return the pattern name if cmd matches any dangerous pattern."""
    for name, pat in DANGEROUS_BASH_PATTERNS:
        if pat.search(cmd):
            return name
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Hook entry point
# ─────────────────────────────────────────────────────────────────────────────
def _cmd_fingerprint(cmd: str) -> str:
    """Stable SHA256 fingerprint of a command, used to bind a one-shot
    `go-secret` approval to the exact command the user saw."""
    return hashlib.sha256(cmd.encode("utf-8", errors="replace")).hexdigest()


def _fail_closed(pattern_name: str, exc: Exception) -> dict:
    """
    Return a permission-deny payload when the guard can't persist its
    approval state (e.g. tempdir unavailable in a locked sandbox).
    Failing CLOSED here is critical — Codex R3 [P2] caught that a
    silent `except Exception: pass` upstream would otherwise let the
    dangerous command through.
    """
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                f"🛡️  redmem secret-ops guard: refusing dangerous command "
                f"(pattern {pattern_name}) because the guard cannot persist "
                f"approval state. This is a fail-closed safety stop.\n\n"
                f"Cause: {type(exc).__name__}: {exc}\n\n"
                "Likely fix: ensure $TMPDIR / /tmp is writable, or set TMPDIR "
                "to a writable directory before launching Claude Code."
            ),
        }
    }


def check(payload: dict) -> Optional[dict]:
    """
    Inspect a PreToolUse payload. Return a hookSpecificOutput dict to deny,
    or None to allow.

    Critical section (load + decide + decrement + save) runs under an
    exclusive POSIX flock to make bypass consumption atomic across
    concurrent PreToolUse hooks in the same session (Codex R4 [P1]).
    """
    if payload.get("tool_name") != "Bash":
        return None

    tool_input = payload.get("tool_input") or {}
    cmd = tool_input.get("command") or ""

    pattern_name = _match_command(cmd)
    if not pattern_name:
        return None

    state_key = _state_key(payload)
    cmd_fp = _cmd_fingerprint(cmd)
    # Result carries either the deny payload (or None to allow). We
    # build it inside the locked section, then return after the lock
    # releases so the lock window is as short as possible.
    deny_payload: Optional[dict] = None

    try:
        with _exclusive_state(state_key) as state:
            remaining = state.get("secret_ops_bypass_remaining", 0)

            if remaining == -1:
                # `pass-secret off` — session-wide bypass, no consume.
                return None

            if remaining > 0:
                bound_fp = state.get("secret_ops_bound_fingerprint")
                if bound_fp and bound_fp != cmd_fp:
                    # Bound approval, command doesn't match — refuse and
                    # KEEP the bypass intact so user can retry original.
                    state["pending_secret_op"] = {
                        "command": cmd[:1500],
                        "pattern": pattern_name,
                        "session_id": _session_id(payload),
                        "fingerprint": cmd_fp,
                    }
                    deny_payload = {
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "deny",
                            "permissionDecisionReason": (
                                "🛡️  redmem secret-ops guard: the queued approval is "
                                "bound to a DIFFERENT command than the one the AI "
                                "is now trying to run. Approval is consumed only "
                                "by the exact command the human saw.\n\n"
                                f"Approved command fingerprint: {bound_fp[:12]}…\n"
                                f"Attempted command fingerprint: {cmd_fp[:12]}…\n\n"
                                "To approve this new command, the human types "
                                "'go-secret' (or 'pass-secret N' to allow multiple "
                                "distinct commands)."
                            ),
                        }
                    }
                else:
                    # Allow and decrement atomically
                    state["secret_ops_bypass_remaining"] = remaining - 1
                    state.pop("secret_ops_bound_fingerprint", None)
                    # deny_payload stays None → return None → allow
            else:
                # No bypass — surface to user via Claude Code's native
                # approval UI (permissionDecision="ask" → yellow prompt
                # with Approve/Deny buttons). User clicks Approve to
                # allow this one command; multi-shot bypass still
                # available via the keyword flow below as a fallback.
                state["pending_secret_op"] = {
                    "command": cmd[:1500],
                    "pattern": pattern_name,
                    "session_id": _session_id(payload),
                    "fingerprint": cmd_fp,
                }
                deny_payload = {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "ask",
                        "permissionDecisionReason": (
                            f"🛡️  This command reads a production-grade secret "
                            f"(pattern: {pattern_name}). Approve only if intentional.\n\n"
                            f"Command: {cmd[:200]}{'…' if len(cmd) > 200 else ''}"
                        ),
                    }
                }
    except OSError as e:
        # State file unavailable (e.g. read-only tempdir) — fail CLOSED.
        return _fail_closed(pattern_name, e)

    return deny_payload


# ─────────────────────────────────────────────────────────────────────────────
# UserPromptSubmit helper — used by redact-restore.py
#
# Returns a hookSpecificOutput dict telling Claude to retry the queued
# command, OR None if the prompt isn't a secret-ops bypass keyword.
# ─────────────────────────────────────────────────────────────────────────────
_BYPASS_RE = re.compile(
    r"^(?:go-secret|pass-secret(?:\s+(?:off|\d+))?)\s*\.?$",
    re.IGNORECASE,
)


def handle_user_prompt(payload: dict, prompt: str) -> Optional[dict]:
    text = (prompt or "").strip().lower().rstrip(".")
    if not _BYPASS_RE.match(text + ("" if text.endswith(".") else "")):
        return None

    state_key = _state_key(payload)
    state = _load_state(state_key)
    pending = state.get("pending_secret_op")
    if not pending:
        # User typed the keyword but nothing is queued — treat as no-op,
        # let other handlers see the prompt.
        return None

    if text == "go-secret":
        # Approve exactly one command, BOUND to the queued command's
        # fingerprint. The next PreToolUse must run a command whose
        # SHA256 matches `secret_ops_bound_fingerprint`, otherwise it's
        # refused (Codex R1 [P1] — prevents bait-and-switch on bypass).
        state["secret_ops_bypass_remaining"] = 1
        state["secret_ops_bound_fingerprint"] = pending.get("fingerprint", "")
        state.pop("pending_secret_op", None)
        _save_state(state_key, state)
        ctx = (
            "[redmem secret-ops guard] User approved the queued secret-reading "
            "command with 'go-secret'. The approval is bound to the EXACT "
            "command shown below — retry that command verbatim; the next "
            "PreToolUse will pass. If you change any argument the bypass "
            "is refused and you'll need a fresh 'go-secret'.\n\n"
            f"Queued pattern: {pending.get('pattern')}\n"
            f"Queued command (truncated): {pending.get('command', '')[:200]}\n"
            f"Bound fingerprint: {pending.get('fingerprint','')[:12]}…"
        )
        return {
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "additionalContext": ctx,
            }
        }

    m = re.match(r"^pass-secret(?:\s+(off|\d+))?$", text)
    if m:
        arg = m.group(1)
        if arg == "off":
            state["secret_ops_bypass_remaining"] = -1  # sentinel: session-wide off
            note = "disabled secret-ops scanning for this session"
        elif arg and arg.isdigit():
            n = min(max(int(arg), 1), 100)
            state["secret_ops_bypass_remaining"] = n
            note = f"approved next {n} matching secret-ops commands"
        else:
            # Bare "pass-secret" — approve one
            state["secret_ops_bypass_remaining"] = 1
            note = "approved one queued secret-ops command"
        # `pass-secret` is multi-shot by design — does NOT bind to a
        # single command. User is explicitly allowing a batch.
        state.pop("secret_ops_bound_fingerprint", None)
        state.pop("pending_secret_op", None)
        _save_state(state_key, state)
        ctx = (
            f"[redmem secret-ops guard] User {note}. "
            f"Retry the queued Bash command; next PreToolUse will pass."
        )
        return {
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "additionalContext": ctx,
            }
        }

    return None


# ─────────────────────────────────────────────────────────────────────────────
# Standalone CLI — used by tests, not by the dispatcher (which calls check()
# directly).
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        payload = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    event = payload.get("hook_event_name") or payload.get("hookEventName")
    if event == "PreToolUse":
        result = check(payload)
        if result:
            sys.stdout.write(json.dumps(result))
        sys.exit(0)
    if event == "UserPromptSubmit":
        # Handle wrapped payloads (top-level OR nested `data`),
        # matching redact-restore.get_prompt_text() (Codex R4 [P2]).
        prompt = ""
        for candidate in (payload, payload.get("data") if isinstance(payload.get("data"), dict) else None):
            if not isinstance(candidate, dict):
                continue
            for key in ("user_prompt", "prompt", "message"):
                v = candidate.get(key)
                if isinstance(v, str) and v:
                    prompt = v
                    break
            if prompt:
                break
        result = handle_user_prompt(payload, prompt)
        if result:
            sys.stdout.write(json.dumps(result))
        sys.exit(0)
    sys.exit(0)
