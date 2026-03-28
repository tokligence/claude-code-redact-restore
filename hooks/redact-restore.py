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
try:
    import importlib.util
    custom_path = os.path.join(_SCRIPT_DIR, "custom-patterns.py")
    if os.path.exists(custom_path):
        spec = importlib.util.spec_from_file_location("custom_patterns", custom_path)
        custom_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(custom_mod)
        if hasattr(custom_mod, "CUSTOM_SECRET_PATTERNS"):
            SECRET_PATTERNS.extend(custom_mod.CUSTOM_SECRET_PATTERNS)
        if hasattr(custom_mod, "CUSTOM_BLOCKED_FILES"):
            BLOCKED_FILES.extend(custom_mod.CUSTOM_BLOCKED_FILES)
except Exception:
    pass

# ── Compile patterns once ────────────────────────────────────────────────
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

try:
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
                matches.append((m.start(), m.end(), matched_value, placeholder))

        if not matches:
            return content, False

        debug_log(f"Found {len(matches)} secret match(es)")

        # Sort by start position descending (replace from end to avoid position shifting)
        matches.sort(key=lambda x: x[0], reverse=True)

        # Deduplicate overlapping matches and replace from end to start
        result = content
        used_ranges = []
        for start, end, secret, placeholder in matches:
            if any(start < ue and end > us for us, ue in used_ranges):
                continue  # Skip overlapping
            result = result[:start] + placeholder + result[end:]
            used_ranges.append((start, end))

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


    # ══════════════════════════════════════════════════════════════════════════
    # PostToolUse: Restore/cleanup file backups after tool completes
    # ══════════════════════════════════════════════════════════════════════════
    if is_post_hook:
        file_path = tool_input.get("file_path", "")
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
                # For Write: file already has correct content (placeholders
                # were restored in PreToolUse). Just clean up backup.
                cleanup_backup(file_path)
        sys.exit(0)



    # ══════════════════════════════════════════════════════════════════════════
    # SessionEnd / Stop hook: Clean up sensitive mapping and backup files
    # ══════════════════════════════════════════════════════════════════════════
    if input_data.get("type") in ("SessionEnd", "Stop") or tool_name in ("SessionEnd", "Stop"):
        debug_log("Session end: cleaning up backups (mapping preserved)")
        # Do NOT delete the global mapping file — it persists across sessions
        debug_log(f"Session ended, mapping preserved at {MAPPING_FILE}")
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

        # Re-redact the file so Claude Code's freshness check passes.
        # PostToolUse will clean up the backup after Write completes.
        if file_path and os.path.isfile(file_path):
            backup_and_redact_file(file_path, mapping)

        # Restore placeholders in the content being written
        restored = restore_content(write_content, mapping)
        if restored != write_content:
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

        # Re-redact the file so Claude Code's freshness check passes and
        # old_string (which contains placeholders) matches the file content.
        # PostToolUse will restore all placeholders in the edited file.
        if file_path and os.path.isfile(file_path):
            if backup_and_redact_file(file_path, mapping):
                # File is now redacted — old_string/new_string should already
                # contain placeholders that match. Don't restore them.
                sys.exit(0)

        # Fallback (file doesn't exist, no secrets, or backup failed):
        # restore placeholders in old_string/new_string so they match the
        # file on disk (which has real values).
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
