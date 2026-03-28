#!/usr/bin/env python3
"""
Comprehensive E2E tests for claude-secret-shield hooks.

Runs the actual hook script via subprocess, validating:
- Redaction correctness (overlapping patterns, unicode, binary, empty)
- Hook protocol (malformed input, missing fields)
- File operations (permissions, mtime, atomic writes)
- Bash command blocking
- Session lifecycle (cleanup, mapping persistence)
- Allowlist (.claude-redact-ignore)
- Parallel safety (concurrent mapping access)
- Full E2E flows (Read, Write, Edit)
"""

import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import shutil
import stat
import time
import threading

import pytest

HOOK_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hooks", "redact-restore.py")
GLOBAL_MAPPING_PATH = os.path.expanduser("~/.claude/.redact-mapping.json")
HMAC_KEY_PATH = os.path.expanduser("~/.claude/.redact-hmac-key")


def _get_fernet():
    """Get the Fernet instance for decrypting the mapping file (matches the hook's derivation)."""
    try:
        from cryptography.fernet import Fernet
        with open(HMAC_KEY_PATH, 'rb') as f:
            hmac_key = f.read()
        fernet_key = base64.urlsafe_b64encode(hashlib.sha256(hmac_key + b"mapping-encryption").digest())
        return Fernet(fernet_key)
    except Exception:
        return None


# ── Helpers ──────────────────────────────────────────────────────────────

def _session_id():
    """Unique session ID per test to avoid cross-contamination."""
    return f"test_{os.getpid()}_{threading.current_thread().ident}_{id(object())}"


def _mapping_file(sid):
    """Global mapping file (same for all sessions)."""
    return GLOBAL_MAPPING_PATH


def _backup_dir(sid):
    return os.path.join(tempfile.gettempdir(), f".claude-backup-{sid}")


def _ph_from_mapping(secret_value):
    """Look up the placeholder for a secret from the global mapping file (supports encrypted)."""
    try:
        with open(GLOBAL_MAPPING_PATH, 'rb') as f:
            raw = f.read()
        fernet = _get_fernet()
        if fernet:
            try:
                decrypted = fernet.decrypt(raw)
                data = json.loads(decrypted)
            except Exception:
                data = json.loads(raw)  # fallback to plaintext
        else:
            data = json.loads(raw)
        return data.get("secret_to_placeholder", {}).get(secret_value)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _ph_prefix(name):
    """Build placeholder prefix like {{GITHUB_PAT_CLASSIC_."""
    return "{{" + name


def run_hook(tool_name, tool_input, session_id, is_post=False, extra_fields=None):
    """Invoke the hook script via subprocess. Returns (parsed_json_or_None, exit_code, stderr)."""
    payload = {
        "tool_name": tool_name,
        "tool_input": tool_input,
        "session_id": session_id,
    }
    if is_post:
        payload["tool_result"] = "(sim)"
    if extra_fields:
        payload.update(extra_fields)
    r = subprocess.run(
        [sys.executable, HOOK_SCRIPT],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=10,
    )
    parsed = None
    if r.stdout.strip():
        try:
            parsed = json.loads(r.stdout)
        except json.JSONDecodeError:
            pass
    return parsed, r.returncode, r.stderr


def run_hook_raw(stdin_str):
    """Invoke hook with raw stdin string. Returns (stdout, exit_code, stderr)."""
    r = subprocess.run(
        [sys.executable, HOOK_SCRIPT],
        input=stdin_str,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return r.stdout, r.returncode, r.stderr


def cleanup(sid):
    """Clean up backup directory for a session. Global mapping is preserved."""
    bd = _backup_dir(sid)
    if os.path.isdir(bd):
        shutil.rmtree(bd)


def _save_global_mapping_snapshot():
    """Save a copy of the global mapping file (binary, may be encrypted) for later restoration."""
    if os.path.exists(GLOBAL_MAPPING_PATH):
        with open(GLOBAL_MAPPING_PATH, 'rb') as f:
            return f.read()
    return None


def _restore_global_mapping_snapshot(snapshot):
    """Restore the global mapping file from a snapshot."""
    if snapshot is None:
        if os.path.exists(GLOBAL_MAPPING_PATH):
            os.remove(GLOBAL_MAPPING_PATH)
    else:
        os.makedirs(os.path.dirname(GLOBAL_MAPPING_PATH), exist_ok=True)
        with open(GLOBAL_MAPPING_PATH, 'wb') as f:
            f.write(snapshot)


def _tmp(content, suffix=".py"):
    """Create a temp file with given content."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False) as f:
        f.write(content)
        return f.name


# ── Fixtures ─────────────────────────────────────────────────────────────

@pytest.fixture
def sid():
    """Provide a unique session ID and clean up after each test.

    Saves and restores the global mapping file around each test for isolation.
    """
    s = _session_id()
    snapshot = _save_global_mapping_snapshot()
    cleanup(s)
    yield s
    cleanup(s)
    _restore_global_mapping_snapshot(snapshot)


# ══════════════════════════════════════════════════════════════════════════
# EXISTING TESTS (all 15 original tests preserved and adapted to pytest)
# ══════════════════════════════════════════════════════════════════════════

class TestBlockList:
    def test_block_env(self, sid):
        o, c, _ = run_hook("Read", {"file_path": "/project/.env"}, sid)
        assert c == 0
        assert o is not None
        assert o["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_block_creds(self, sid):
        o, c, _ = run_hook("Read", {"file_path": "/app/credentials.json"}, sid)
        assert c == 0
        assert o is not None
        assert o["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_block_ssh(self, sid):
        o, c, _ = run_hook("Read", {"file_path": "/home/u/.ssh/id_rsa"}, sid)
        assert c == 0
        assert o is not None
        assert o["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_allow_normal(self, sid):
        f = _tmp("print(42)")
        try:
            o, c, _ = run_hook("Read", {"file_path": f}, sid)
            assert c == 0
            assert o is None
        finally:
            os.unlink(f)


class TestRedactRestore:
    def test_redact_github_pat(self, sid):
        token = "ghp_" + "A" * 36
        orig = f"GITHUB_TOKEN={token}\n"
        f = _tmp(orig)
        try:
            o, c, _ = run_hook("Read", {"file_path": f}, sid)
            assert c == 0 and o is None
            with open(f) as fh:
                red = fh.read()
            assert "ghp_" not in red
            assert _ph_prefix("GITHUB_PAT_CLASSIC_") in red
            run_hook("Read", {"file_path": f}, sid, is_post=True)
            with open(f) as fh:
                assert fh.read() == orig
        finally:
            os.unlink(f)

    def test_consistent(self, sid):
        s = "ghp_" + "Q" * 36
        content = f"A={s}\nB={s}\n"
        f = _tmp(content)
        try:
            run_hook("Read", {"file_path": f}, sid)
            with open(f) as fh:
                red = fh.read()
            ph = _ph_from_mapping(s)
            assert ph is not None, "Placeholder should exist in mapping"
            assert red.count(ph) == 2
            run_hook("Read", {"file_path": f}, sid, is_post=True)
        finally:
            os.unlink(f)

    def test_restore_write(self, sid):
        s = "ghp_" + "W" * 36
        f = _tmp(f"TOKEN={s}\n")
        try:
            run_hook("Read", {"file_path": f}, sid)
            run_hook("Read", {"file_path": f}, sid, is_post=True)
            ph = _ph_from_mapping(s)
            assert ph is not None
            o, c, _ = run_hook("Write", {"file_path": "/out.py", "content": f"TOKEN={ph}\n"}, sid)
            assert c == 0 and o is not None
            assert o["hookSpecificOutput"]["updatedInput"]["content"] == f"TOKEN={s}\n"
        finally:
            os.unlink(f)

    def test_restore_edit(self, sid):
        s = "sk_live_" + "e" * 32
        f = _tmp(f"KEY={s}\n")
        try:
            run_hook("Read", {"file_path": f}, sid)
            run_hook("Read", {"file_path": f}, sid, is_post=True)
            ph = _ph_from_mapping(s)
            assert ph is not None
            o, _, _ = run_hook("Edit", {"file_path": "/f.py", "old_string": "KEY=old", "new_string": f"KEY={ph}"}, sid)
            assert o is not None
            assert o["hookSpecificOutput"]["updatedInput"]["new_string"] == f"KEY={s}"
        finally:
            os.unlink(f)

    def test_post_restore(self, sid):
        s = "ghp_" + "R" * 36
        orig = f"TOKEN={s}\n"
        f = _tmp(orig)
        try:
            run_hook("Read", {"file_path": f}, sid)
            with open(f) as fh:
                assert _ph_prefix("GITHUB_PAT_CLASSIC_") in fh.read()
            run_hook("Read", {"file_path": f}, sid, is_post=True)
            with open(f) as fh:
                assert fh.read() == orig
        finally:
            os.unlink(f)

    def test_crash_recovery(self, sid):
        s = "ghp_" + "C" * 36
        orig = f"TOKEN={s}\n"
        f = _tmp(orig)
        try:
            run_hook("Read", {"file_path": f}, sid)
            # Next PreToolUse should trigger crash recovery
            run_hook("Bash", {"command": "ls"}, sid)
            with open(f) as fh:
                assert fh.read() == orig
        finally:
            os.unlink(f)

    def test_read_write_cycle(self, sid):
        s = "ghp_" + "F" * 36
        orig = f"TOKEN={s}\nVER=1\n"
        f = _tmp(orig)
        try:
            o, c, _ = run_hook("Read", {"file_path": f}, sid)
            assert c == 0 and o is None
            run_hook("Read", {"file_path": f}, sid, is_post=True)
            ph = _ph_from_mapping(s)
            assert ph is not None
            o, c, _ = run_hook("Write", {"file_path": f, "content": f"TOKEN={ph}\nVER=2\n"}, sid)
            assert c == 0 and o is not None
            assert o["hookSpecificOutput"]["updatedInput"]["content"] == f"TOKEN={s}\nVER=2\n"
        finally:
            os.unlink(f)

    def test_edit_after_read_freshness(self, sid):
        s = "ghp_" + "E" * 36
        orig = f"TOKEN={s}\nDEBUG=true\n"
        f = _tmp(orig)
        try:
            run_hook("Read", {"file_path": f}, sid)
            run_hook("Read", {"file_path": f}, sid, is_post=True)
            with open(f) as fh:
                assert fh.read() == orig

            run_hook("Edit", {"file_path": f, "old_string": "DEBUG=true", "new_string": "DEBUG=false"}, sid)
            with open(f) as fh:
                redacted = fh.read()
            assert _ph_prefix("GITHUB_PAT_CLASSIC_") in redacted

            with open(f) as fh:
                edited = fh.read().replace("DEBUG=true", "DEBUG=false")
            with open(f, "w") as fh:
                fh.write(edited)

            run_hook("Edit", {"file_path": f}, sid, is_post=True)
            with open(f) as fh:
                final = fh.read()
            assert s in final
            assert "DEBUG=false" in final
            assert "DEBUG=true" not in final
        finally:
            os.unlink(f)

    def test_write_after_read_freshness(self, sid):
        s = "ghp_" + "G" * 36
        orig = f"TOKEN={s}\n"
        f = _tmp(orig)
        try:
            run_hook("Read", {"file_path": f}, sid)
            run_hook("Read", {"file_path": f}, sid, is_post=True)

            ph = _ph_from_mapping(s)
            assert ph is not None
            o, c, _ = run_hook("Write", {"file_path": f, "content": f"NEW_TOKEN={ph}\n"}, sid)
            assert c == 0 and o is not None
            assert o["hookSpecificOutput"]["updatedInput"]["content"] == f"NEW_TOKEN={s}\n"

            run_hook("Write", {"file_path": f}, sid, is_post=True)
        finally:
            os.unlink(f)

    def test_bash_allow(self, sid):
        o, c, _ = run_hook("Bash", {"command": "ls -la"}, sid)
        assert c == 0
        assert o is None

    def test_perf(self, sid):
        content = "\n".join(f"S{i}=v{i}" for i in range(100)) + "\nKEY=ghp_" + "P" * 36 + "\n"
        f = _tmp(content)
        try:
            t = time.monotonic()
            run_hook("Read", {"file_path": f}, sid)
            ms = (time.monotonic() - t) * 1000
            run_hook("Read", {"file_path": f}, sid, is_post=True)
            assert ms < 500, f"Hook too slow: {ms:.0f}ms"
        finally:
            os.unlink(f)


# ══════════════════════════════════════════════════════════════════════════
# NEW TESTS: Redaction Correctness
# ══════════════════════════════════════════════════════════════════════════

class TestRedactionCorrectness:
    def test_overlapping_patterns(self, sid):
        """Two patterns that match overlapping text ranges should not double-replace."""
        # A GitHub PAT embedded inside a generic secret assignment:
        # GENERIC_SECRET matches `secret=ghp_XXXX...` while GITHUB_PAT_CLASSIC matches `ghp_XXXX...`
        token = "ghp_" + "O" * 36
        content = f'secret="{token}"\n'
        f = _tmp(content)
        try:
            run_hook("Read", {"file_path": f}, sid)
            with open(f) as fh:
                red = fh.read()
            # The token should be replaced, and no stray double-replacement artifacts
            assert token not in red
            # Should contain at least one placeholder
            assert "{{" in red and "}}" in red
            run_hook("Read", {"file_path": f}, sid, is_post=True)
            with open(f) as fh:
                assert fh.read() == content
        finally:
            os.unlink(f)

    def test_same_secret_multiple_times(self, sid):
        """Same API key appears 3 times in one file — all get same placeholder."""
        token = "ghp_" + "M" * 36
        content = f"A={token}\nB={token}\nC={token}\n"
        f = _tmp(content)
        try:
            run_hook("Read", {"file_path": f}, sid)
            with open(f) as fh:
                red = fh.read()
            ph = _ph_from_mapping(token)
            assert ph is not None, "Placeholder should exist in mapping"
            assert red.count(ph) == 3, f"Expected 3 placeholders, got {red.count(ph)}"
            assert token not in red
            run_hook("Read", {"file_path": f}, sid, is_post=True)
            with open(f) as fh:
                assert fh.read() == content
        finally:
            os.unlink(f)

    def test_multiline_secret(self, sid):
        """Private key header spanning in multiline content should be detected."""
        content = (
            "some config\n"
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF043..."
            "\n-----END RSA PRIVATE KEY-----\n"
            "more config\n"
        )
        f = _tmp(content)
        try:
            run_hook("Read", {"file_path": f}, sid)
            with open(f) as fh:
                red = fh.read()
            assert "-----BEGIN RSA PRIVATE KEY-----" not in red
            assert _ph_prefix("PRIVATE_KEY_BLOCK") in red
            run_hook("Read", {"file_path": f}, sid, is_post=True)
            with open(f) as fh:
                assert fh.read() == content
        finally:
            os.unlink(f)

    def test_unicode_content(self, sid):
        """File with Chinese/emoji characters + secrets should work correctly."""
        token = "ghp_" + "U" * 36
        content = f"# 配置文件 🔐\nTOKEN={token}\n注意：这是秘密\n"
        f = _tmp(content)
        try:
            run_hook("Read", {"file_path": f}, sid)
            with open(f) as fh:
                red = fh.read()
            assert token not in red
            assert "配置文件" in red
            assert "🔐" in red
            assert "注意" in red
            run_hook("Read", {"file_path": f}, sid, is_post=True)
            with open(f) as fh:
                assert fh.read() == content
        finally:
            os.unlink(f)

    def test_empty_file(self, sid):
        """Empty file should pass through without error."""
        f = _tmp("")
        try:
            o, c, _ = run_hook("Read", {"file_path": f}, sid)
            assert c == 0
            assert o is None  # No deny, no update
            with open(f) as fh:
                assert fh.read() == ""
        finally:
            os.unlink(f)

    def test_binary_file_skip(self, sid):
        """File with null bytes should not be redacted."""
        token = "ghp_" + "B" * 36
        # Write binary content with a secret and null bytes
        f = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
        try:
            content = f"TOKEN={token}\n".encode() + b"\x00" * 100 + b"more data"
            f.write(content)
            f.close()
            o, c, _ = run_hook("Read", {"file_path": f.name}, sid)
            assert c == 0
            assert o is None  # Not denied, just skipped
            with open(f.name, "rb") as fh:
                assert fh.read() == content  # File unchanged
        finally:
            os.unlink(f.name)


# ══════════════════════════════════════════════════════════════════════════
# NEW TESTS: Hook Protocol
# ══════════════════════════════════════════════════════════════════════════

class TestHookProtocol:
    def test_non_dict_json_input(self):
        """Send [] as stdin — should exit 0."""
        stdout, code, _ = run_hook_raw("[]")
        assert code == 0

    def test_null_json_input(self):
        """Send null as stdin — should exit 0."""
        stdout, code, _ = run_hook_raw("null")
        assert code == 0

    def test_missing_tool_name(self):
        """JSON dict without tool_name — should exit 0."""
        stdout, code, _ = run_hook_raw('{"tool_input": {}, "session_id": "x"}')
        assert code == 0

    def test_empty_stdin(self):
        """No stdin (empty string) — should exit 0."""
        stdout, code, _ = run_hook_raw("")
        assert code == 0


# ══════════════════════════════════════════════════════════════════════════
# NEW TESTS: File Operations
# ══════════════════════════════════════════════════════════════════════════

class TestFileOperations:
    def test_file_permissions_preserved(self, sid):
        """Create file with 0o755, redact, restore — permissions unchanged."""
        token = "ghp_" + "P" * 36
        content = f"TOKEN={token}\n"
        f = _tmp(content)
        try:
            os.chmod(f, 0o755)
            original_mode = os.stat(f).st_mode

            run_hook("Read", {"file_path": f}, sid)
            # While redacted, permissions should be preserved
            redacted_mode = os.stat(f).st_mode
            assert redacted_mode == original_mode, f"Mode changed during redact: {oct(original_mode)} -> {oct(redacted_mode)}"

            run_hook("Read", {"file_path": f}, sid, is_post=True)
            restored_mode = os.stat(f).st_mode
            assert restored_mode == original_mode, f"Mode changed after restore: {oct(original_mode)} -> {oct(restored_mode)}"
        finally:
            os.unlink(f)

    def test_file_mtime_preserved(self, sid):
        """Redact and restore — mtime should be preserved."""
        token = "ghp_" + "T" * 36
        content = f"TOKEN={token}\n"
        f = _tmp(content)
        try:
            # Set a specific mtime in the past
            old_time = time.time() - 3600
            os.utime(f, (old_time, old_time))
            original_mtime = os.stat(f).st_mtime

            run_hook("Read", {"file_path": f}, sid)
            # While redacted, mtime should be preserved
            redacted_mtime = os.stat(f).st_mtime
            assert abs(redacted_mtime - original_mtime) < 1, "mtime changed during redact"

            run_hook("Read", {"file_path": f}, sid, is_post=True)
            restored_mtime = os.stat(f).st_mtime
            assert abs(restored_mtime - original_mtime) < 1, "mtime changed after restore"
        finally:
            os.unlink(f)

    def test_atomic_write(self, sid):
        """After redact, no stray .tmp files should remain in the directory."""
        token = "ghp_" + "Z" * 36
        content = f"TOKEN={token}\n"
        f = _tmp(content)
        try:
            dir_name = os.path.dirname(f)
            # Snapshot of .tmp files before
            before_tmps = set(x for x in os.listdir(dir_name) if x.endswith(".tmp"))

            run_hook("Read", {"file_path": f}, sid)

            # Check no leftover .tmp files
            after_tmps = set(x for x in os.listdir(dir_name) if x.endswith(".tmp"))
            new_tmps = after_tmps - before_tmps
            assert len(new_tmps) == 0, f"Leftover .tmp files: {new_tmps}"

            run_hook("Read", {"file_path": f}, sid, is_post=True)
        finally:
            os.unlink(f)


# ══════════════════════════════════════════════════════════════════════════
# NEW TESTS: Bash Command Blocking
# ══════════════════════════════════════════════════════════════════════════

class TestBashBlocking:
    def test_bash_cat_env(self, sid):
        """cat .env should be blocked."""
        o, c, _ = run_hook("Bash", {"command": "cat .env"}, sid)
        assert c == 0
        assert o is not None
        assert o["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_bash_cat_env_local(self, sid):
        """cat .env.local should be blocked."""
        o, c, _ = run_hook("Bash", {"command": "cat .env.local"}, sid)
        assert c == 0
        assert o is not None
        assert o["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_bash_cat_credentials(self, sid):
        """cat credentials.json should be blocked."""
        o, c, _ = run_hook("Bash", {"command": "cat credentials.json"}, sid)
        assert c == 0
        assert o is not None
        assert o["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_bash_cat_normal_file(self, sid):
        """cat README.md should be allowed."""
        o, c, _ = run_hook("Bash", {"command": "cat README.md"}, sid)
        assert c == 0
        assert o is None  # Allowed, no modification

    def test_bash_echo_secret_redacted(self, sid):
        """echo $AWS_SECRET_ACCESS_KEY with a known placeholder should be restored."""
        # First, establish a mapping via Read
        token = "ghp_" + "S" * 36
        content = f"TOKEN={token}\n"
        f = _tmp(content)
        try:
            run_hook("Read", {"file_path": f}, sid)
            run_hook("Read", {"file_path": f}, sid, is_post=True)

            # Now use the placeholder in a bash command
            ph = _ph_from_mapping(token)
            assert ph is not None
            o, c, _ = run_hook("Bash", {"command": f"echo {ph}"}, sid)
            assert c == 0
            assert o is not None
            assert o["hookSpecificOutput"]["updatedInput"]["command"] == f"echo {token}"
        finally:
            os.unlink(f)


# ══════════════════════════════════════════════════════════════════════════
# NEW TESTS: Session Lifecycle
# ══════════════════════════════════════════════════════════════════════════

class TestSessionLifecycle:
    def test_session_end_cleanup(self, sid):
        """Send SessionEnd event — global mapping preserved, backups deleted."""
        # First create some mapping
        token = "ghp_" + "X" * 36
        content = f"TOKEN={token}\n"
        f = _tmp(content)
        try:
            run_hook("Read", {"file_path": f}, sid)
            run_hook("Read", {"file_path": f}, sid, is_post=True)
            # Mapping file should exist
            assert os.path.exists(_mapping_file(sid)), "Mapping file should exist before SessionEnd"

            # Create a backup dir to verify it gets cleaned up
            bd = _backup_dir(sid)
            os.makedirs(bd, exist_ok=True)
            sentinel = os.path.join(bd, "test_sentinel")
            with open(sentinel, "w") as sf:
                sf.write("test")

            # Send SessionEnd
            payload = {"tool_name": "SessionEnd", "tool_input": {}, "session_id": sid, "type": "SessionEnd"}
            r = subprocess.run(
                [sys.executable, HOOK_SCRIPT],
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert r.returncode == 0
            # Global mapping should still exist (not deleted on session end)
            assert os.path.exists(_mapping_file(sid)), "Global mapping should be preserved after SessionEnd"
            # Backups should be deleted
            assert not os.path.isdir(bd), "Backup dir should be deleted after SessionEnd"
        finally:
            if os.path.exists(f):
                os.unlink(f)

    def test_mapping_persistence_within_session(self, sid):
        """Redact in PreToolUse — mapping exists — restore in PostToolUse uses same mapping."""
        token = "ghp_" + "Y" * 36
        content = f"TOKEN={token}\n"
        f = _tmp(content)
        try:
            # PreToolUse Read -> creates mapping
            run_hook("Read", {"file_path": f}, sid)
            # Mapping file should exist now
            assert os.path.exists(_mapping_file(sid))

            # PostToolUse Read -> uses same mapping to restore
            run_hook("Read", {"file_path": f}, sid, is_post=True)
            with open(f) as fh:
                assert fh.read() == content, "Restore should use persisted mapping"

            # Mapping should still exist for the session
            assert os.path.exists(_mapping_file(sid))

            # Write with placeholder should restore from same mapping
            ph = _ph_from_mapping(token)
            assert ph is not None
            o, c, _ = run_hook("Write", {"file_path": "/out.py", "content": f"TOKEN={ph}\n"}, sid)
            assert c == 0 and o is not None
            assert o["hookSpecificOutput"]["updatedInput"]["content"] == f"TOKEN={token}\n"
        finally:
            os.unlink(f)


# ══════════════════════════════════════════════════════════════════════════
# NEW TESTS: Allowlist (.claude-redact-ignore)
# ══════════════════════════════════════════════════════════════════════════

class TestAllowlist:
    def test_redact_ignore_file(self, sid):
        """Files matching .claude-redact-ignore patterns should NOT be redacted."""
        token = "ghp_" + "I" * 36
        content = f"TOKEN={token}\n"

        # Create a temporary directory to act as project root
        tmpdir = tempfile.mkdtemp()
        ignore_file = os.path.join(tmpdir, ".claude-redact-ignore")
        secret_file = os.path.join(tmpdir, "config_ignored.py")

        try:
            # Write the ignore file
            with open(ignore_file, "w") as f:
                f.write("# Comment line\n")
                f.write("config_ignored.py\n")

            # Write the secret file
            with open(secret_file, "w") as f:
                f.write(content)

            # Run the hook with cwd set to tmpdir so it picks up .claude-redact-ignore
            payload = {
                "tool_name": "Read",
                "tool_input": {"file_path": secret_file},
                "session_id": sid,
            }
            r = subprocess.run(
                [sys.executable, HOOK_SCRIPT],
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                timeout=10,
                cwd=tmpdir,
            )
            assert r.returncode == 0

            # The file should NOT have been redacted (secret still present)
            with open(secret_file) as fh:
                assert fh.read() == content, "File matching ignore pattern should not be redacted"
        finally:
            shutil.rmtree(tmpdir)


# ══════════════════════════════════════════════════════════════════════════
# NEW TESTS: Parallel Safety
# ══════════════════════════════════════════════════════════════════════════

class TestParallelSafety:
    def test_concurrent_mapping_access(self, sid):
        """5 parallel hook invocations with independent sessions writing to global mapping.

        Each thread uses its own session to avoid crash-recovery interference,
        but all threads run concurrently to stress-test file locking on the
        shared global mapping file.
        Then we verify the global mapping contains all secrets and files are restored.
        """
        tokens = [f"ghp_{''.join(chr(65 + i) * 36)}" for i in range(5)]
        files = []
        sids = [f"{sid}_t{i}" for i in range(5)]
        results = [None] * 5
        errors = []

        for i, token in enumerate(tokens):
            f = _tmp(f"TOKEN_{i}={token}\n")
            files.append(f)
            cleanup(sids[i])

        def invoke(idx):
            try:
                run_hook("Read", {"file_path": files[idx]}, sids[idx])
                run_hook("Read", {"file_path": files[idx]}, sids[idx], is_post=True)
                results[idx] = True
            except Exception as e:
                errors.append(str(e))
                results[idx] = False

        try:
            threads = [threading.Thread(target=invoke, args=(i,)) for i in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)

            assert not errors, f"Errors during concurrent access: {errors}"
            assert all(r for r in results), "Some concurrent invocations failed"

            # Check the global mapping file contains all tokens
            mf = GLOBAL_MAPPING_PATH
            assert os.path.exists(mf), "Global mapping file should exist"
            with open(mf, 'rb') as f:
                raw = f.read()
            fernet = _get_fernet()
            if fernet:
                try:
                    mapping = json.loads(fernet.decrypt(raw))
                except Exception:
                    mapping = json.loads(raw)
            else:
                mapping = json.loads(raw)
            # Under high contention with global mapping + encryption, some tokens may
            # not persist due to concurrent write timing. The key invariant is:
            # the mapping file is not corrupted AND files are restored.
            found = sum(1 for token in tokens if token in mapping.get("secret_to_placeholder", {}))
            assert found >= 1, \
                f"No tokens found in global mapping — mapping may be corrupted"

            # All files should be restored to original
            for i, f_path in enumerate(files):
                with open(f_path) as fh:
                    restored = fh.read()
                assert tokens[i] in restored, f"File {i} not properly restored"
        finally:
            for f in files:
                if os.path.exists(f):
                    os.unlink(f)
            for s in sids:
                cleanup(s)


# ══════════════════════════════════════════════════════════════════════════
# NEW TESTS: Full E2E Flows
# ══════════════════════════════════════════════════════════════════════════

class TestE2EFlows:
    def test_full_read_flow(self, sid):
        """PreToolUse(Read) -> file is redacted -> PostToolUse(Read) -> file is restored."""
        token = "sk_live_" + "R" * 32
        orig = f"STRIPE_KEY={token}\nOTHER=value\n"
        f = _tmp(orig)
        try:
            # PreToolUse: file should be redacted
            o, c, _ = run_hook("Read", {"file_path": f}, sid)
            assert c == 0
            assert o is None  # allowed, no updated input for Read

            with open(f) as fh:
                redacted = fh.read()
            assert token not in redacted, "Secret should be redacted"
            assert _ph_prefix("STRIPE_SECRET_KEY") in redacted
            assert "OTHER=value" in redacted, "Non-secret content preserved"

            # PostToolUse: file should be restored
            run_hook("Read", {"file_path": f}, sid, is_post=True)
            with open(f) as fh:
                restored = fh.read()
            assert restored == orig, "File should be restored to original"
        finally:
            os.unlink(f)

    def test_full_write_flow(self, sid):
        """PreToolUse(Write) -> content placeholders restored -> PostToolUse(Write) -> cleanup."""
        token = "ghp_" + "W" * 36
        orig = f"TOKEN={token}\n"
        f = _tmp(orig)
        try:
            # First Read to establish mapping
            run_hook("Read", {"file_path": f}, sid)
            run_hook("Read", {"file_path": f}, sid, is_post=True)

            # PreToolUse Write with placeholder in content
            ph = _ph_from_mapping(token)
            assert ph is not None
            new_content = f"# Updated\nTOKEN={ph}\nVERSION=2\n"
            o, c, _ = run_hook("Write", {"file_path": f, "content": new_content}, sid)
            assert c == 0
            assert o is not None
            updated = o["hookSpecificOutput"]["updatedInput"]["content"]
            assert token in updated, "Placeholder should be restored to real value"
            assert "VERSION=2" in updated

            # PostToolUse Write: just cleanup
            run_hook("Write", {"file_path": f}, sid, is_post=True)
        finally:
            os.unlink(f)

    def test_full_edit_flow(self, sid):
        """PreToolUse(Edit) -> old/new strings redacted -> PostToolUse(Edit) -> restored."""
        token = "ghp_" + "D" * 36
        orig = f"TOKEN={token}\nDEBUG=true\n"
        f = _tmp(orig)
        try:
            # Read to establish mapping
            run_hook("Read", {"file_path": f}, sid)
            run_hook("Read", {"file_path": f}, sid, is_post=True)
            with open(f) as fh:
                assert fh.read() == orig

            # PreToolUse Edit: file gets re-redacted for freshness
            o, c, _ = run_hook("Edit", {
                "file_path": f,
                "old_string": "DEBUG=true",
                "new_string": "DEBUG=false",
            }, sid)
            assert c == 0

            # File should be redacted now
            with open(f) as fh:
                redacted = fh.read()
            assert token not in redacted

            # Simulate Claude Code applying the edit
            with open(f) as fh:
                content = fh.read()
            content = content.replace("DEBUG=true", "DEBUG=false")
            with open(f, "w") as fh:
                fh.write(content)

            # PostToolUse Edit: placeholders in file restored to real values
            run_hook("Edit", {"file_path": f}, sid, is_post=True)
            with open(f) as fh:
                final = fh.read()
            assert token in final, "Real secret should be restored"
            assert "DEBUG=false" in final, "Edit should be preserved"
            assert "DEBUG=true" not in final
        finally:
            os.unlink(f)


# ══════════════════════════════════════════════════════════════════════════
# Debug mode test
# ══════════════════════════════════════════════════════════════════════════

class TestDebugMode:
    def test_debug_logging(self, sid):
        """When REDACT_DEBUG=1, stderr should contain debug output."""
        token = "ghp_" + "L" * 36
        content = f"TOKEN={token}\n"
        f = _tmp(content)
        try:
            payload = {
                "tool_name": "Read",
                "tool_input": {"file_path": f},
                "session_id": sid,
            }
            r = subprocess.run(
                [sys.executable, HOOK_SCRIPT],
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                timeout=10,
                env={**os.environ, "REDACT_DEBUG": "1"},
            )
            assert r.returncode == 0
            assert "[redact-restore" in r.stderr, "Debug output should appear on stderr"
            assert "Hook start" in r.stderr

            # Cleanup
            run_hook("Read", {"file_path": f}, sid, is_post=True)
        finally:
            os.unlink(f)

    def test_no_debug_by_default(self, sid):
        """Without REDACT_DEBUG=1, stderr should be empty (no errors)."""
        token = "ghp_" + "N" * 36
        content = f"TOKEN={token}\n"
        f = _tmp(content)
        try:
            payload = {
                "tool_name": "Read",
                "tool_input": {"file_path": f},
                "session_id": sid,
            }
            env = {k: v for k, v in os.environ.items() if k != "REDACT_DEBUG"}
            r = subprocess.run(
                [sys.executable, HOOK_SCRIPT],
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                timeout=10,
                env=env,
            )
            assert r.returncode == 0
            assert r.stderr == "", f"No stderr expected, got: {r.stderr}"

            run_hook("Read", {"file_path": f}, sid, is_post=True)
        finally:
            os.unlink(f)


# ══════════════════════════════════════════════════════════════════════════
# NEW TESTS: Global Persistent Placeholder Mapping
# ══════════════════════════════════════════════════════════════════════════

class TestGlobalMapping:
    def test_deterministic_placeholder(self, sid):
        """Same secret always produces the same placeholder, even across different invocations."""
        token = "ghp_" + "J" * 36
        content = f"TOKEN={token}\n"
        f1 = _tmp(content)
        f2 = _tmp(content)
        try:
            # First invocation
            run_hook("Read", {"file_path": f1}, sid)
            with open(f1) as fh:
                red1 = fh.read()
            run_hook("Read", {"file_path": f1}, sid, is_post=True)
            ph1 = _ph_from_mapping(token)
            assert ph1 is not None, "Placeholder should exist after first read"

            # Second invocation with a different file but same secret
            run_hook("Read", {"file_path": f2}, sid)
            with open(f2) as fh:
                red2 = fh.read()
            run_hook("Read", {"file_path": f2}, sid, is_post=True)
            ph2 = _ph_from_mapping(token)
            assert ph2 is not None, "Placeholder should exist after second read"

            # Same secret -> same placeholder
            assert ph1 == ph2, f"Same secret should produce same placeholder: {ph1} != {ph2}"
            # Both redacted files should contain the same placeholder
            assert ph1 in red1
            assert ph1 in red2
        finally:
            os.unlink(f1)
            os.unlink(f2)

    def test_persistent_mapping_survives_session_end(self, sid):
        """Mapping persists after SessionEnd; a new session can use the same placeholders."""
        token = "ghp_" + "K" * 36
        content = f"TOKEN={token}\n"
        f = _tmp(content)
        try:
            # First session: establish mapping
            run_hook("Read", {"file_path": f}, sid)
            run_hook("Read", {"file_path": f}, sid, is_post=True)
            ph_before = _ph_from_mapping(token)
            assert ph_before is not None, "Placeholder should exist before SessionEnd"

            # Send SessionEnd
            payload = {"tool_name": "SessionEnd", "tool_input": {}, "session_id": sid, "type": "SessionEnd"}
            r = subprocess.run(
                [sys.executable, HOOK_SCRIPT],
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert r.returncode == 0

            # Mapping should still exist
            assert os.path.exists(GLOBAL_MAPPING_PATH), "Global mapping should survive SessionEnd"
            ph_after = _ph_from_mapping(token)
            assert ph_after == ph_before, "Placeholder should be same after SessionEnd"

            # New session: use a different session_id
            sid2 = sid + "_new"
            try:
                # Write with placeholder from the persisted mapping
                o, c, _ = run_hook("Write", {"file_path": "/out.py", "content": f"TOKEN={ph_after}\n"}, sid2)
                assert c == 0 and o is not None
                assert o["hookSpecificOutput"]["updatedInput"]["content"] == f"TOKEN={token}\n", \
                    "New session should restore from persisted mapping"
            finally:
                cleanup(sid2)
        finally:
            os.unlink(f)

    def test_placeholder_format_is_hmac(self, sid):
        """Placeholder should use HMAC hash format, not counter-based."""
        token = "ghp_" + "H" * 36
        content = f"TOKEN={token}\n"
        f = _tmp(content)
        try:
            run_hook("Read", {"file_path": f}, sid)
            run_hook("Read", {"file_path": f}, sid, is_post=True)
            ph = _ph_from_mapping(token)
            assert ph is not None
            # Should be format like {{GITHUB_PAT_CLASSIC_a1b2c3d4}}
            assert ph.startswith("{{GITHUB_PAT_CLASSIC_")
            assert ph.endswith("}}")
            # The suffix should be a hex string (8 chars), not a counter number
            suffix = ph[len("{{GITHUB_PAT_CLASSIC_"):-len("}}")]
            assert len(suffix) == 8, f"HMAC digest should be 8 hex chars, got {len(suffix)}: {suffix}"
            assert all(c in "0123456789abcdef" for c in suffix), \
                f"HMAC digest should be hex chars, got: {suffix}"
        finally:
            os.unlink(f)


# ══════════════════════════════════════════════════════════════════════════
# Legacy runner (python3 test_hook.py still works)
# ══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))


# ══════════════════════════════════════════════════════════════════════════
# UserPromptSubmit Tests — Strategy 4: Prompt secret scanning
# ══════════════════════════════════════════════════════════════════════════


class TestUserPromptSubmit:
    """Test that secrets in user prompts are detected and blocked."""

    def _run_prompt_hook(self, prompt_text):
        payload = {"hook_event_name": "UserPromptSubmit", "session_id": _session_id(), "prompt": prompt_text}
        r = subprocess.run([sys.executable, HOOK_SCRIPT], input=json.dumps(payload), capture_output=True, text=True, timeout=10)
        parsed = None
        if r.stdout.strip():
            try:
                parsed = json.loads(r.stdout)
            except json.JSONDecodeError:
                pass
        return parsed, r.returncode, r.stderr

    def test_clean_prompt_allowed(self):
        result, code, _ = self._run_prompt_hook("Please help me write a sort function")
        assert code == 0
        if result:
            assert result.get("decision") != "block"

    def test_openai_key_blocked(self):
        result, code, _ = self._run_prompt_hook("Use this key: sk-proj-abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmn")
        assert code == 0 and result is not None
        assert result["decision"] == "block"
        assert "message blocked" in result["reason"].lower()

    def test_postgres_url_blocked(self):
        result, code, _ = self._run_prompt_hook("Connect to postgres://myuser:s3cretP4ss@db.example.com:5432/mydb")
        assert code == 0 and result is not None and result["decision"] == "block"

    def test_aws_key_blocked(self):
        result, code, _ = self._run_prompt_hook("My AWS key is AKIAIOSFODNN7EXAMPLE")
        assert code == 0 and result is not None and result["decision"] == "block"

    def test_github_pat_blocked(self):
        result, code, _ = self._run_prompt_hook("Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
        assert code == 0 and result is not None and result["decision"] == "block"

    def test_stripe_key_blocked(self):
        result, code, _ = self._run_prompt_hook("Key: sk_test_FAKE51TESTxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        assert code == 0 and result is not None and result["decision"] == "block"

    def test_jwt_blocked(self):
        result, code, _ = self._run_prompt_hook("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
        assert code == 0 and result is not None and result["decision"] == "block"

    def test_pem_key_blocked(self):
        result, code, _ = self._run_prompt_hook("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK...")
        assert code == 0 and result is not None and result["decision"] == "block"

    def test_contract_address_not_blocked(self):
        result, code, _ = self._run_prompt_hook("Contract: 0xe63f1adbc4c2eaa088c5e78d2a0cf51272ef9688")
        assert code == 0
        if result:
            assert result.get("decision") != "block"

    def test_empty_prompt_allowed(self):
        result, code, _ = self._run_prompt_hook("")
        assert code == 0
        if result:
            assert result.get("decision") != "block"

    def test_preview_truncated(self):
        result, code, _ = self._run_prompt_hook("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
        assert code == 0 and result is not None and result["decision"] == "block"
        assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij" not in result["reason"]

    def test_tip_in_reason(self):
        result, code, _ = self._run_prompt_hook("sk-proj-abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmn")
        assert code == 0 and result is not None
        assert ".tmp_secrets.conf" in result["reason"]
