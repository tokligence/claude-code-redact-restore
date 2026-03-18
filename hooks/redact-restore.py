#!/usr/bin/env python3
"""
Claude Code Secret Redact/Restore Hook

Strategy 1: Block list — certain files are never read (.env, credentials, etc.)
Strategy 2: Pattern-based redact — secrets in ANY file are replaced with consistent placeholders
Strategy 3: Restore on write — placeholders are restored to real values when writing files

Session mapping stored at: /tmp/.claude-redact-{session_id}.json

Hook input (stdin JSON):
  - tool_name: "Read" | "Write" | "Edit" | "Bash"
  - tool_input: { file_path, content, command, ... }
  - session_id: string

Hook output (stdout JSON):
  hookSpecificOutput.hookEventName = "PreToolUse"
  hookSpecificOutput.permissionDecision = "allow" | "deny"
  hookSpecificOutput.permissionDecisionReason = string (when deny)
  hookSpecificOutput.updatedInput = {...} (when allow with modifications)

Exit codes:
  0 = allow (or deny via JSON output)
  Non-zero without JSON = error (Claude Code shows stderr)
"""

import sys
import json
import os
import re

# ── Load patterns ────────────────────────────────────────────────────────
# Import from patterns.py in the same directory, or fall back to inline
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_patterns_loaded = False

try:
    # Try importing from the installed location first
    sys.path.insert(0, _SCRIPT_DIR)
    from patterns import BLOCKED_FILES, SECRET_PATTERNS
    _patterns_loaded = True
except ImportError:
    pass

if not _patterns_loaded:
    # Also check ~/.claude/hooks/ (where the installer copies files)
    _hooks_dir = os.path.expanduser("~/.claude/hooks")
    if os.path.isfile(os.path.join(_hooks_dir, "patterns.py")):
        sys.path.insert(0, _hooks_dir)
        try:
            from patterns import BLOCKED_FILES, SECRET_PATTERNS
            _patterns_loaded = True
        except ImportError:
            pass

if not _patterns_loaded:
    # Minimal fallback if patterns.py cannot be found
    BLOCKED_FILES = [
        ".env", ".env.local", ".env.production", ".env.staging",
        "credential.json", "credentials.json", "secrets.yaml", "secrets.json",
        "id_rsa", "id_ed25519", "id_ecdsa", ".pem", ".p12", ".pfx",
        "service-account.json", ".git-credentials", ".netrc",
    ]
    SECRET_PATTERNS = [
        ("OPENAI_KEY", r'sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}'),
        ("ANTHROPIC_KEY", r'sk-ant-[a-zA-Z0-9_\-]{32,100}'),
        ("AWS_ACCESS_KEY", r'(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}'),
        ("GITHUB_PAT_CLASSIC", r'ghp_[A-Za-z0-9]{36}'),
        ("STRIPE_SECRET_KEY", r'sk_live_[A-Za-z0-9]{24,}'),
        ("PRIVATE_KEY_BLOCK", r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'),
        ("GENERIC_SECRET", r'(?i)(?:secret|password|passwd|pwd)["\']?\s*[:=]\s*["\']?[^\s"\']{10,60}["\']?'),
    ]

# ── Compile patterns once ────────────────────────────────────────────────
# This runs once per invocation. Python process startup + compile is ~5-20ms.
COMPILED_PATTERNS = []
for name, regex in SECRET_PATTERNS:
    try:
        COMPILED_PATTERNS.append((name, re.compile(regex)))
    except re.error:
        # Skip invalid regex rather than crashing the hook
        pass

# ── Read hook input ──────────────────────────────────────────────────────
try:
    input_data = json.loads(sys.stdin.read())
except (json.JSONDecodeError, EOFError):
    # If we can't parse input, allow the operation (fail open)
    sys.exit(0)

tool_name = input_data.get("tool_name", "")
tool_input = input_data.get("tool_input", {})
session_id = input_data.get("session_id", "default")

MAPPING_FILE = f"/tmp/.claude-redact-{session_id}.json"


# ── Mapping management ───────────────────────────────────────────────────
def load_mapping():
    """Load the session mapping file. Returns empty mapping on any error."""
    try:
        if os.path.exists(MAPPING_FILE):
            with open(MAPPING_FILE) as f:
                return json.load(f)
    except (json.JSONDecodeError, OSError, PermissionError):
        pass
    return {"secret_to_placeholder": {}, "placeholder_to_secret": {}, "counters": {}}


def save_mapping(mapping):
    """Persist the mapping file with restricted permissions."""
    try:
        fd = os.open(MAPPING_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(mapping, f)
    except OSError:
        pass


def get_placeholder(mapping, secret_value, pattern_name):
    """Get or create a consistent placeholder for a secret value."""
    if secret_value in mapping["secret_to_placeholder"]:
        return mapping["secret_to_placeholder"][secret_value]

    counter = mapping["counters"].get(pattern_name, 0) + 1
    mapping["counters"][pattern_name] = counter
    placeholder = "{{" + f"{pattern_name}_{counter}" + "}}"

    mapping["secret_to_placeholder"][secret_value] = placeholder
    mapping["placeholder_to_secret"][placeholder] = secret_value
    return placeholder


# ── Redact / Restore ─────────────────────────────────────────────────────
def redact_content(content, mapping):
    """Scan content for secrets and replace with placeholders.

    Returns (redacted_content, found_any_secrets).
    The mapping is mutated in place and must be saved by the caller.
    """
    redacted = content
    found_any = False

    for pattern_name, compiled in COMPILED_PATTERNS:
        for match in compiled.finditer(redacted):
            secret = match.group(0)
            # Skip very short matches (likely false positives)
            if len(secret) < 8:
                continue
            placeholder = get_placeholder(mapping, secret, pattern_name)
            redacted = redacted.replace(secret, placeholder)
            found_any = True

    return redacted, found_any


def restore_content(content, mapping):
    """Replace placeholders back to real secret values."""
    restored = content
    for placeholder, secret in mapping.get("placeholder_to_secret", {}).items():
        restored = restored.replace(placeholder, secret)
    return restored


# ── Strategy 1: Check block list ─────────────────────────────────────────
def is_blocked_file(file_path):
    """Check if a file path matches any blocked pattern."""
    if not file_path:
        return False, ""
    basename = os.path.basename(file_path)
    for pattern in BLOCKED_FILES:
        if basename == pattern or file_path.endswith(pattern) or f"/{pattern}" in file_path:
            return True, pattern
    return False, ""


# ── Output helpers ───────────────────────────────────────────────────────
def deny(reason):
    """Output a deny decision and exit."""
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason
        }
    }))
    sys.exit(0)


def allow_with_update(updated_input):
    """Output an allow decision with modified input and exit."""
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "updatedInput": updated_input
        }
    }))
    sys.exit(0)


# ── Handle Read tool ─────────────────────────────────────────────────────
if tool_name == "Read":
    file_path = tool_input.get("file_path", "")

    # Strategy 1: Block list
    blocked, matched_pattern = is_blocked_file(file_path)
    if blocked:
        deny(
            f"BLOCKED: '{os.path.basename(file_path)}' is in the secret files block list "
            f"(matched '{matched_pattern}'). Use .env.example or ask the user for guidance."
        )

    # Strategy 2: Read file ourselves, scan for secrets, return redacted content
    if file_path and os.path.isfile(file_path):
        try:
            with open(file_path, "r", errors="replace") as f:
                content = f.read()
        except (OSError, PermissionError):
            # Can't read the file — let Claude Code handle the error
            sys.exit(0)

        mapping = load_mapping()
        redacted, found_secrets = redact_content(content, mapping)

        if found_secrets:
            save_mapping(mapping)
            deny(
                f"This file contains secrets that have been redacted for safety. "
                f"Here is the redacted content of {file_path}:\n\n"
                f"{redacted}\n\n"
                f"(Placeholders like {{{{OPENAI_KEY_1}}}} represent real secret values. "
                f"Use them as-is in code — they will be automatically restored when you write files.)"
            )

    # No secrets found — allow normal read
    sys.exit(0)


# ── Handle Write tool ────────────────────────────────────────────────────
if tool_name == "Write":
    mapping = load_mapping()
    if not mapping.get("placeholder_to_secret"):
        sys.exit(0)

    content = tool_input.get("content", "")
    restored = restore_content(content, mapping)
    if restored != content:
        allow_with_update({
            "file_path": tool_input.get("file_path", ""),
            "content": restored
        })
    sys.exit(0)


# ── Handle Edit tool ─────────────────────────────────────────────────────
if tool_name == "Edit":
    mapping = load_mapping()
    if not mapping.get("placeholder_to_secret"):
        sys.exit(0)

    old_string = tool_input.get("old_string", "")
    new_string = tool_input.get("new_string", "")
    restored_old = restore_content(old_string, mapping)
    restored_new = restore_content(new_string, mapping)

    if restored_old != old_string or restored_new != new_string:
        updated = dict(tool_input)
        updated["old_string"] = restored_old
        updated["new_string"] = restored_new
        allow_with_update(updated)

    sys.exit(0)


# ── Handle Bash tool ─────────────────────────────────────────────────────
if tool_name == "Bash":
    command = tool_input.get("command", "")

    # Strategy 1: Block commands that cat/read blocked files
    for pattern in BLOCKED_FILES:
        escaped = re.escape(pattern)
        if re.search(
            rf"(cat|head|tail|less|more|bat|source|\.)\s+[^\s|;]*{escaped}",
            command
        ):
            deny(f"BLOCKED: command reads '{pattern}' which is in the secret files block list.")
        # Also catch redirections: < .env
        if re.search(rf"<\s*[^\s]*{escaped}", command):
            deny(f"BLOCKED: command reads '{pattern}' which is in the secret files block list.")

    # Strategy 3: Restore placeholders in bash commands
    mapping = load_mapping()
    if mapping.get("placeholder_to_secret"):
        restored = restore_content(command, mapping)
        if restored != command:
            updated = dict(tool_input)
            updated["command"] = restored
            allow_with_update(updated)

    sys.exit(0)


# ── Allow everything else ────────────────────────────────────────────────
sys.exit(0)
