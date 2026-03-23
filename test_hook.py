#!/usr/bin/env python3
import json, os, subprocess, sys, tempfile, shutil, time

HOOK_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hooks", "redact-restore.py")
SESSION_ID = "test_" + str(os.getpid())
MAPPING_FILE = f"/tmp/.claude-redact-{SESSION_ID}.json"
BACKUP_DIR = os.path.join(tempfile.gettempdir(), f".claude-backup-{SESSION_ID}")

def _ph(name, n=1):
    return chr(123)*2 + name + chr(95) + str(n) + chr(125)*2

def _ph_prefix(name):
    return chr(123)*2 + name

def run_hook(tool_name, tool_input, session_id=None, is_post=False):
    payload = {"tool_name": tool_name, "tool_input": tool_input, "session_id": session_id or SESSION_ID}
    if is_post: payload["tool_result"] = "(sim)"
    r = subprocess.run([sys.executable, HOOK_SCRIPT], input=json.dumps(payload), capture_output=True, text=True, timeout=10)
    if r.stdout.strip(): return json.loads(r.stdout), r.returncode
    return None, r.returncode

def cleanup():
    if os.path.exists(MAPPING_FILE): os.remove(MAPPING_FILE)
    if os.path.isdir(BACKUP_DIR): shutil.rmtree(BACKUP_DIR)

def _tmp(content, suffix=".py"):
    with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False) as f:
        f.write(content)
        return f.name

def test_block_env():
    o, c = run_hook("Read", {"file_path": "/project/" + chr(46) + "env"})
    assert c == 0 and o and o["hookSpecificOutput"]["permissionDecision"] == "deny"
    print("  PASS: env file blocked")

def test_block_creds():
    o, c = run_hook("Read", {"file_path": "/app/credentials.json"})
    assert c == 0 and o and o["hookSpecificOutput"]["permissionDecision"] == "deny"
    print("  PASS: credentials.json blocked")

def test_block_ssh():
    o, c = run_hook("Read", {"file_path": "/home/u/.ssh/id_rsa"})
    assert c == 0 and o and o["hookSpecificOutput"]["permissionDecision"] == "deny"
    print("  PASS: id_rsa blocked")

def test_allow_normal():
    f = _tmp("print(42)")
    try:
        o, c = run_hook("Read", {"file_path": f})
        assert c == 0 and o is None
        print("  PASS: normal file allowed")
    finally: os.unlink(f)

def test_redact_github_pat():
    token = "ghp_" + "A" * 36
    orig = "GITHUB_TOKEN=" + token + chr(10)
    f = _tmp(orig)
    try:
        o, c = run_hook("Read", {"file_path": f})
        assert c == 0 and o is None, "Read should allow"
        with open(f) as fh: red = fh.read()
        assert "ghp_" not in red
        assert _ph_prefix("GITHUB_PAT_CLASSIC_") in red
        run_hook("Read", {"file_path": f}, is_post=True)
        with open(f) as fh: assert fh.read() == orig
        print("  PASS: GitHub PAT redacted and restored")
    finally: os.unlink(f)

def test_consistent():
    cleanup()
    s = "ghp_" + "Q" * 36
    content = "A=" + s + chr(10) + "B=" + s + chr(10)
    f = _tmp(content)
    try:
        run_hook("Read", {"file_path": f})
        with open(f) as fh: red = fh.read()
        ph = _ph("GITHUB_PAT_CLASSIC")
        assert red.count(ph) == 2, f"Expected 2, got {red.count(ph)}: {red[:100]}"
        run_hook("Read", {"file_path": f}, is_post=True)
        print("  PASS: consistent placeholder")
    finally: os.unlink(f)

def test_restore_write():
    cleanup()
    s = "ghp_" + "W" * 36
    f = _tmp("TOKEN=" + s + chr(10))
    try:
        run_hook("Read", {"file_path": f})
        run_hook("Read", {"file_path": f}, is_post=True)
        ph = _ph("GITHUB_PAT_CLASSIC")
        o, c = run_hook("Write", {"file_path": "/out.py", "content": "TOKEN=" + ph + chr(10)})
        assert c == 0 and o is not None
        assert o["hookSpecificOutput"]["updatedInput"]["content"] == "TOKEN=" + s + chr(10)
        print("  PASS: restore on Write")
    finally: os.unlink(f)

def test_restore_edit():
    cleanup()
    s = "sk_live_" + "e" * 32
    f = _tmp("KEY=" + s + chr(10))
    try:
        run_hook("Read", {"file_path": f})
        run_hook("Read", {"file_path": f}, is_post=True)
        ph = _ph("STRIPE_SECRET_KEY")
        o, _ = run_hook("Edit", {"file_path": "/f.py", "old_string": "KEY=old", "new_string": "KEY=" + ph})
        assert o is not None
        assert o["hookSpecificOutput"]["updatedInput"]["new_string"] == "KEY=" + s
        print("  PASS: restore on Edit")
    finally: os.unlink(f)

def test_post_restore():
    cleanup()
    s = "ghp_" + "R" * 36
    orig = "TOKEN=" + s + chr(10)
    f = _tmp(orig)
    try:
        run_hook("Read", {"file_path": f})
        with open(f) as fh: assert _ph_prefix("GITHUB_PAT_CLASSIC_") in fh.read()
        run_hook("Read", {"file_path": f}, is_post=True)
        with open(f) as fh: assert fh.read() == orig
        print("  PASS: file restored after PostToolUse")
    finally: os.unlink(f)

def test_crash_recovery():
    cleanup()
    s = "ghp_" + "C" * 36
    orig = "TOKEN=" + s + chr(10)
    f = _tmp(orig)
    try:
        run_hook("Read", {"file_path": f})
        run_hook("Bash", {"command": "ls"})
        with open(f) as fh: assert fh.read() == orig, "Crash recovery failed"
        print("  PASS: crash recovery")
    finally: os.unlink(f)

def test_read_write_cycle():
    cleanup()
    s = "ghp_" + "F" * 36
    orig = "TOKEN=" + s + chr(10) + "VER=1" + chr(10)
    f = _tmp(orig)
    try:
        o, c = run_hook("Read", {"file_path": f})
        assert c == 0 and o is None, "Read must be allowed (not denied)"
        run_hook("Read", {"file_path": f}, is_post=True)
        ph = _ph("GITHUB_PAT_CLASSIC")
        o, c = run_hook("Write", {"file_path": f, "content": "TOKEN=" + ph + chr(10) + "VER=2" + chr(10)})
        assert c == 0 and o is not None
        assert o["hookSpecificOutput"]["updatedInput"]["content"] == "TOKEN=" + s + chr(10) + "VER=2" + chr(10)
        print("  PASS: read-then-write cycle (bug fix verified)")
    finally: os.unlink(f)



def test_edit_after_read_freshness():
    """Edit after Read on file with secrets must work (freshness check fix)."""
    cleanup()
    s = 'ghp_' + 'E' * 36
    orig = 'TOKEN=' + s + chr(10) + 'DEBUG=true' + chr(10)
    f = _tmp(orig)
    try:
        # Read (pre + post)
        run_hook('Read', {'file_path': f})
        run_hook('Read', {'file_path': f}, is_post=True)
        # File should be restored to original
        with open(f) as fh:
            assert fh.read() == orig

        # Edit PreToolUse: re-redacts file for freshness check
        run_hook('Edit', {'file_path': f, 'old_string': 'DEBUG=true', 'new_string': 'DEBUG=false'})
        with open(f) as fh:
            redacted = fh.read()
        assert _ph_prefix('GITHUB_PAT_CLASSIC_') in redacted

        # Simulate what Claude Code's Edit tool does: replace in file
        with open(f) as fh:
            edited = fh.read().replace('DEBUG=true', 'DEBUG=false')
        with open(f, 'w') as fh:
            fh.write(edited)

        # Edit PostToolUse: restore placeholders in the edited file
        run_hook('Edit', {'file_path': f}, is_post=True)
        with open(f) as fh:
            final = fh.read()
        assert s in final, 'Real secret not restored'
        assert 'DEBUG=false' in final, 'Edit not preserved'
        assert 'DEBUG=true' not in final, 'Old value still present' 
        print('  PASS: edit after read freshness fix')
    finally:
        os.unlink(f)


def test_write_after_read_freshness():
    """Write after Read on file with secrets must work (freshness check fix)."""
    cleanup()
    s = 'ghp_' + 'G' * 36
    orig = 'TOKEN=' + s + chr(10)
    f = _tmp(orig)
    try:
        run_hook('Read', {'file_path': f})
        run_hook('Read', {'file_path': f}, is_post=True)

        # Write with placeholder
        ph = _ph('GITHUB_PAT_CLASSIC')
        o, c = run_hook('Write', {'file_path': f, 'content': 'NEW_TOKEN=' + ph + chr(10)})
        assert c == 0 and o is not None
        assert o['hookSpecificOutput']['updatedInput']['content'] == 'NEW_TOKEN=' + s + chr(10)

        # PostToolUse for Write: just cleanup
        run_hook('Write', {'file_path': f}, is_post=True)
        print('  PASS: write after read freshness fix')
    finally:
        os.unlink(f)

def test_perf():
    content = chr(10).join(f"S{i}=v{i}" for i in range(100)) + chr(10) + "KEY=ghp_" + "P"*36 + chr(10)
    f = _tmp(content)
    try:
        t = time.monotonic()
        run_hook("Read", {"file_path": f})
        ms = (time.monotonic() - t) * 1000
        run_hook("Read", {"file_path": f}, is_post=True)
        assert ms < 500
        print(f"  PASS: {ms:.0f}ms")
    finally: os.unlink(f)

def test_bash_allow():
    o, c = run_hook("Bash", {"command": "ls -la"})
    assert c == 0 and o is None
    print("  PASS: normal bash allowed")

if __name__ == "__main__":
    tests = [test_block_env, test_block_creds, test_block_ssh, test_allow_normal,
             test_redact_github_pat, test_consistent, test_restore_write,
             test_restore_edit, test_post_restore, test_crash_recovery,
             test_read_write_cycle, test_edit_after_read_freshness,
             test_write_after_read_freshness, test_bash_allow, test_perf]
    print(f"Running {len(tests)} tests...")
    p = f = 0
    for t in tests:
        try: cleanup(); t(); p += 1
        except Exception as e: print(f"  FAIL: {t.__name__}: {e}"); f += 1
    cleanup()
    print(f"Results: {p} passed, {f} failed")
    sys.exit(1 if f else 0)
