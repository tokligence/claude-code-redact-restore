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

import hashlib
import json
import os
import re
import sys
import tempfile
from typing import Optional

# Same state file as redact-restore so "go-secret" resumption can find it.
_STATE_PREFIX = ".claude-secret-shield-"


def _session_id(payload: dict) -> str:
    return payload.get("session_id") or payload.get("sessionId") or "default"


def _agent_scope(payload: dict) -> str:
    return (
        payload.get("agent_scope")
        or payload.get("agent_id")
        or payload.get("transcript_path", "main")
    )


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
    fd = os.open(_state_path(state_key), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(state, f)


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
def check(payload: dict) -> Optional[dict]:
    """
    Inspect a PreToolUse payload. Return a hookSpecificOutput dict to deny,
    or None to allow.
    """
    if payload.get("tool_name") != "Bash":
        return None

    tool_input = payload.get("tool_input") or {}
    cmd = tool_input.get("command") or ""

    pattern_name = _match_command(cmd)
    if not pattern_name:
        return None

    # Check bypass counter
    state_key = _state_key(payload)
    state = _load_state(state_key)
    remaining = state.get("secret_ops_bypass_remaining", 0)
    if remaining == -1:
        # Disabled for session (after "pass-secret off")
        return None
    if remaining > 0:
        # Allow and decrement
        state["secret_ops_bypass_remaining"] = remaining - 1
        _save_state(state_key, state)
        return None

    # Block — save the pending command so the UserPromptSubmit
    # `go-secret` handler can describe it (and so we can audit later).
    state["pending_secret_op"] = {
        "command": cmd[:1500],  # cap to keep state file small
        "pattern": pattern_name,
        "session_id": _session_id(payload),
    }
    _save_state(state_key, state)

    reason = (
        f"🛡️  redmem secret-ops guard: this command reads a production-grade "
        f"secret (pattern: {pattern_name}).\n\n"
        f"Command: {cmd[:200]}{'…' if len(cmd) > 200 else ''}\n\n"
        f"To approve, the human user types in their next message:\n"
        f"  go-secret        — approve this one command\n"
        f"  pass-secret N    — approve next N matching commands\n"
        f"  pass-secret off  — disable scanning for this session\n\n"
        f"Do NOT ask the user to run this command manually — they will use "
        f"one of the keywords above to authorize it from inside the AI session."
    )

    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


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
        # Approve exactly one command
        state["secret_ops_bypass_remaining"] = 1
        state.pop("pending_secret_op", None)
        _save_state(state_key, state)
        ctx = (
            "[redmem secret-ops guard] User approved the queued secret-reading "
            "command with 'go-secret'. Retry the exact same Bash command now; "
            "the next PreToolUse will pass.\n\n"
            f"Queued pattern: {pending.get('pattern')}\n"
            f"Queued command (truncated): {pending.get('command', '')[:200]}"
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
        prompt = payload.get("prompt") or payload.get("user_prompt") or ""
        result = handle_user_prompt(payload, prompt)
        if result:
            sys.stdout.write(json.dumps(result))
        sys.exit(0)
    sys.exit(0)
