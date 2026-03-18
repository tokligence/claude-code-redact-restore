#!/usr/bin/env python3
"""
Tests for the claude-code-redact-restore hook.

Tests the redact/restore roundtrip:
  1. Reading a file with secrets returns redacted content
  2. Same secret always maps to same placeholder
  3. Writing with placeholders restores real values
  4. Mapping is consistent across calls within a session
  5. Block list works for known secret files
  6. Bash command blocking works
  7. Edit tool restore works

Usage:
  python3 test_hook.py
  python3 -m pytest test_hook.py -v
"""

import json
import os
import subprocess
import sys
import tempfile
import shutil

HOOK_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hooks", "redact-restore.py")
SESSION_ID = "test_session_" + str(os.getpid())
MAPPING_FILE = f"/tmp/.claude-redact-{SESSION_ID}.json"


def run_hook(tool_name, tool_input, session_id=None):
    """Run the hook script with given input and return parsed output."""
    payload = {
        "tool_name": tool_name,
        "tool_input": tool_input,
        "session_id": session_id or SESSION_ID,
    }
    result = subprocess.run(
        [sys.executable, HOOK_SCRIPT],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.stdout.strip():
        return json.loads(result.stdout), result.returncode
    return None, result.returncode


def cleanup():
    """Remove test mapping file."""
    if os.path.exists(MAPPING_FILE):
        os.remove(MAPPING_FILE)


def test_block_list_env_file():
    """Strategy 1: .env files should be blocked."""
    output, code = run_hook("Read", {"file_path": "/project/.env"})
    assert code == 0
    assert output is not None
    decision = output["hookSpecificOutput"]
    assert decision["permissionDecision"] == "deny"
    assert "block list" in decision["permissionDecisionReason"].lower()
    print("  PASS: .env file blocked")


def test_block_list_credentials():
    """Strategy 1: credentials.json should be blocked."""
    output, code = run_hook("Read", {"file_path": "/app/config/credentials.json"})
    assert code == 0
    assert output is not None
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    print("  PASS: credentials.json blocked")


def test_block_list_ssh_key():
    """Strategy 1: SSH private keys should be blocked."""
    output, code = run_hook("Read", {"file_path": "/home/user/.ssh/id_rsa"})
    assert code == 0
    assert output is not None
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    print("  PASS: id_rsa blocked")


def test_block_list_pem():
    """Strategy 1: .pem files should be blocked."""
    output, code = run_hook("Read", {"file_path": "/certs/server.pem"})
    assert code == 0
    assert output is not None
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    print("  PASS: .pem file blocked")


def test_allow_normal_file():
    """Normal files without secrets should be allowed."""
    # Create a temp file with no secrets
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write("print('hello world')\nx = 42\n")
        tmpfile = f.name

    try:
        output, code = run_hook("Read", {"file_path": tmpfile})
        assert code == 0
        assert output is None  # No output = allow
        print("  PASS: normal file allowed")
    finally:
        os.unlink(tmpfile)


def test_redact_openai_key():
    """Strategy 2: OpenAI keys should be redacted."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        openai_key = "sk-proj-" + "a" * 20 + "T3BlbkFJ" + "b" * 20
        f.write(f'OPENAI_API_KEY = "{openai_key}"\n')
        tmpfile = f.name

    try:
        output, code = run_hook("Read", {"file_path": tmpfile})
        assert code == 0
        assert output is not None
        decision = output["hookSpecificOutput"]
        assert decision["permissionDecision"] == "deny"
        reason = decision["permissionDecisionReason"]
        # The actual key should NOT appear in the reason
        assert "T3BlbkFJ" not in reason
        # A placeholder should appear
        assert "{{OPENAI_KEY_" in reason
        print("  PASS: OpenAI key redacted")
    finally:
        os.unlink(tmpfile)


def test_redact_github_pat():
    """Strategy 2: GitHub PATs should be redacted."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
        gh_token = "ghp_" + "A" * 36
        f.write(f'export GITHUB_TOKEN="{gh_token}"\n')
        tmpfile = f.name

    try:
        output, code = run_hook("Read", {"file_path": tmpfile})
        assert code == 0
        assert output is not None
        reason = output["hookSpecificOutput"]["permissionDecisionReason"]
        assert "ghp_" not in reason
        assert "{{GITHUB_PAT_CLASSIC_" in reason
        print("  PASS: GitHub PAT redacted")
    finally:
        os.unlink(tmpfile)


def test_redact_aws_key():
    """Strategy 2: AWS access keys should be redacted."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
        aws_key = "AKIA" + "Z" * 16
        f.write(f"[default]\naws_access_key_id = {aws_key}\n")
        tmpfile = f.name

    try:
        output, code = run_hook("Read", {"file_path": tmpfile})
        assert code == 0
        assert output is not None
        reason = output["hookSpecificOutput"]["permissionDecisionReason"]
        assert "AKIA" not in reason  # real key should be redacted
        assert "{{AWS_ACCESS_KEY_" in reason
        print("  PASS: AWS access key redacted")
    finally:
        os.unlink(tmpfile)


def test_redact_stripe_key():
    """Strategy 2: Stripe keys should be redacted."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".env.example", delete=False) as f:
        stripe_key = "sk_live_" + "q" * 32
        f.write(f'STRIPE_KEY={stripe_key}\n')
        tmpfile = f.name

    try:
        output, code = run_hook("Read", {"file_path": tmpfile})
        assert code == 0
        assert output is not None
        reason = output["hookSpecificOutput"]["permissionDecisionReason"]
        assert "sk_live_" not in reason
        assert "{{STRIPE_SECRET_KEY_" in reason
        print("  PASS: Stripe key redacted")
    finally:
        os.unlink(tmpfile)


def test_redact_private_key():
    """Strategy 2: Private key blocks should be redacted."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write('-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n')
        tmpfile = f.name

    try:
        output, code = run_hook("Read", {"file_path": tmpfile})
        assert code == 0
        assert output is not None
        reason = output["hookSpecificOutput"]["permissionDecisionReason"]
        assert "-----BEGIN RSA PRIVATE KEY-----" not in reason
        assert "{{PRIVATE_KEY_BLOCK_" in reason
        print("  PASS: Private key block redacted")
    finally:
        os.unlink(tmpfile)


def test_consistent_placeholder_mapping():
    """Strategy 2: Same secret always maps to same placeholder within a session."""
    cleanup()  # Start fresh

    secret = "ghp_" + "A" * 36
    content = f'TOKEN_A = "{secret}"\nTOKEN_B = "{secret}"\n'

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(content)
        tmpfile = f.name

    try:
        output, code = run_hook("Read", {"file_path": tmpfile})
        assert code == 0
        assert output is not None
        reason = output["hookSpecificOutput"]["permissionDecisionReason"]

        # The placeholder should appear exactly twice (once per occurrence)
        placeholder = "{{GITHUB_PAT_CLASSIC_1}}"
        assert reason.count(placeholder) == 2
        print("  PASS: consistent placeholder mapping")
    finally:
        os.unlink(tmpfile)


def test_mapping_persists_across_calls():
    """Strategy 2: Mapping should persist across separate hook invocations."""
    cleanup()  # Start fresh

    secret = "ghp_" + "P" * 36
    file1_content = f'A = "{secret}"\n'
    file2_content = f'B = "{secret}"\n'

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(file1_content)
        tmpfile1 = f.name
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(file2_content)
        tmpfile2 = f.name

    try:
        # First call — creates the mapping
        output1, _ = run_hook("Read", {"file_path": tmpfile1})
        reason1 = output1["hookSpecificOutput"]["permissionDecisionReason"]

        # Second call — should reuse the same placeholder
        output2, _ = run_hook("Read", {"file_path": tmpfile2})
        reason2 = output2["hookSpecificOutput"]["permissionDecisionReason"]

        # Both should use {{GITHUB_PAT_CLASSIC_1}} (same secret, same placeholder)
        assert "{{GITHUB_PAT_CLASSIC_1}}" in reason1
        assert "{{GITHUB_PAT_CLASSIC_1}}" in reason2
        print("  PASS: mapping persists across calls")
    finally:
        os.unlink(tmpfile1)
        os.unlink(tmpfile2)


def test_restore_on_write():
    """Strategy 3: Placeholders in Write content should be restored to real values."""
    cleanup()  # Start fresh

    # Step 1: Read a file with secrets to create the mapping
    secret = "ghp_" + "W" * 36
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(f'TOKEN = "{secret}"\n')
        tmpfile = f.name

    try:
        run_hook("Read", {"file_path": tmpfile})

        # Step 2: Write with placeholder — should restore real value
        output, code = run_hook("Write", {
            "file_path": "/some/output.py",
            "content": 'TOKEN = "{{GITHUB_PAT_CLASSIC_1}}"\n'
        })
        assert code == 0
        assert output is not None
        updated = output["hookSpecificOutput"]["updatedInput"]
        assert updated["content"] == f'TOKEN = "{secret}"\n'
        print("  PASS: restore on Write")
    finally:
        os.unlink(tmpfile)


def test_restore_on_edit():
    """Strategy 3: Placeholders in Edit new_string should be restored."""
    cleanup()

    secret = "sk_live_" + "e" * 32
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(f'KEY = "{secret}"\n')
        tmpfile = f.name

    try:
        run_hook("Read", {"file_path": tmpfile})

        output, code = run_hook("Edit", {
            "file_path": "/some/file.py",
            "old_string": 'KEY = "old_value"',
            "new_string": 'KEY = "{{STRIPE_SECRET_KEY_1}}"'
        })
        assert code == 0
        assert output is not None
        updated = output["hookSpecificOutput"]["updatedInput"]
        assert updated["new_string"] == f'KEY = "{secret}"'
        print("  PASS: restore on Edit")
    finally:
        os.unlink(tmpfile)


def test_restore_on_bash():
    """Strategy 3: Placeholders in Bash commands should be restored."""
    cleanup()

    secret = "ghp_" + "B" * 36
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(f'TOKEN = "{secret}"\n')
        tmpfile = f.name

    try:
        run_hook("Read", {"file_path": tmpfile})

        output, code = run_hook("Bash", {
            "command": 'curl -H "Authorization: Bearer {{GITHUB_PAT_CLASSIC_1}}" https://api.github.com/user'
        })
        assert code == 0
        assert output is not None
        updated = output["hookSpecificOutput"]["updatedInput"]
        assert secret in updated["command"]
        assert "{{GITHUB_PAT_CLASSIC_1}}" not in updated["command"]
        print("  PASS: restore on Bash")
    finally:
        os.unlink(tmpfile)


def test_bash_block_cat_env():
    """Bash command that reads .env should be blocked."""
    output, code = run_hook("Bash", {"command": "cat .env"})
    assert code == 0
    assert output is not None
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    print("  PASS: bash cat .env blocked")


def test_bash_block_source_env():
    """Bash command that sources .env should be blocked."""
    output, code = run_hook("Bash", {"command": "source .env.production"})
    assert code == 0
    assert output is not None
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    print("  PASS: bash source .env blocked")


def test_bash_allow_normal_command():
    """Normal bash commands should be allowed."""
    output, code = run_hook("Bash", {"command": "ls -la"})
    assert code == 0
    assert output is None
    print("  PASS: normal bash allowed")


def test_write_without_mapping():
    """Write without any mapping should pass through."""
    cleanup()
    output, code = run_hook("Write", {
        "file_path": "/some/file.py",
        "content": "print('hello')\n"
    })
    assert code == 0
    assert output is None
    print("  PASS: write without mapping passes through")


def test_no_false_positive_on_short_strings():
    """Short strings that partially match patterns should not be redacted."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write('x = "short"\nSK = "ab"\n')
        tmpfile = f.name

    try:
        output, code = run_hook("Read", {"file_path": tmpfile})
        assert code == 0
        assert output is None  # No secrets found
        print("  PASS: no false positive on short strings")
    finally:
        os.unlink(tmpfile)


def test_multiple_different_secrets():
    """Multiple different secrets should each get unique placeholders."""
    cleanup()

    with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
        f.write(
            'GITHUB_TOKEN=ghp_FirstTkn0AAAAAAAAAAAAAAAAAAAAAAAAAAA\n'
            f'AWS_KEY={"AKIA" + "Z" * 16}\n'
        )
        tmpfile = f.name

    try:
        output, code = run_hook("Read", {"file_path": tmpfile})
        assert code == 0
        assert output is not None
        reason = output["hookSpecificOutput"]["permissionDecisionReason"]
        assert "{{GITHUB_PAT_CLASSIC_1}}" in reason
        assert "{{AWS_ACCESS_KEY_1}}" in reason
        # Original secrets should not appear
        assert "ghp_" not in reason
        assert "AKIA" not in reason  # real key should be redacted
        print("  PASS: multiple different secrets redacted independently")
    finally:
        os.unlink(tmpfile)


def test_mapping_file_permissions():
    """Mapping file should have 600 permissions."""
    cleanup()

    secret = "ghp_" + "X" * 36
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(f'TOKEN = "{secret}"\n')
        tmpfile = f.name

    try:
        run_hook("Read", {"file_path": tmpfile})
        assert os.path.exists(MAPPING_FILE)
        mode = oct(os.stat(MAPPING_FILE).st_mode)[-3:]
        assert mode == "600", f"Expected 600, got {mode}"
        print("  PASS: mapping file has 600 permissions")
    finally:
        os.unlink(tmpfile)


def test_redact_database_url():
    """Database connection strings with passwords should be redacted."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write('database_url: postgres://myuser:s3cretP@ss@db.example.com:5432/mydb\n')
        tmpfile = f.name

    try:
        output, code = run_hook("Read", {"file_path": tmpfile})
        assert code == 0
        assert output is not None
        reason = output["hookSpecificOutput"]["permissionDecisionReason"]
        assert "s3cretP@ss" not in reason
        assert "{{POSTGRES_URL_" in reason
        print("  PASS: database URL redacted")
    finally:
        os.unlink(tmpfile)


def test_redact_sendgrid_key():
    """SendGrid API keys should be redacted."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write('SENDGRID_API_KEY = "SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst"\n')
        tmpfile = f.name

    try:
        output, code = run_hook("Read", {"file_path": tmpfile})
        assert code == 0
        assert output is not None
        reason = output["hookSpecificOutput"]["permissionDecisionReason"]
        assert "SG." not in reason
        assert "{{SENDGRID_KEY_" in reason
        print("  PASS: SendGrid key redacted")
    finally:
        os.unlink(tmpfile)


def test_performance():
    """Hook should execute in under 100ms for a typical file."""
    import time

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        # Write a realistic file with ~100 lines
        lines = ['# Configuration file\n']
        for i in range(100):
            lines.append(f'SETTING_{i} = "value_{i}"\n')
        lines.append('API_KEY = "ghp_PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP"\n')
        f.writelines(lines)
        tmpfile = f.name

    try:
        start = time.monotonic()
        run_hook("Read", {"file_path": tmpfile})
        elapsed_ms = (time.monotonic() - start) * 1000

        # Should be well under 100ms on modern hardware
        # Allow 500ms for CI/slow machines but warn if > 100ms
        assert elapsed_ms < 500, f"Hook took {elapsed_ms:.0f}ms (limit: 500ms)"
        status = "PASS" if elapsed_ms < 100 else "PASS (slow)"
        print(f"  {status}: hook executed in {elapsed_ms:.0f}ms")
    finally:
        os.unlink(tmpfile)


# ── Run all tests ────────────────────────────────────────────────────────
if __name__ == "__main__":
    tests = [
        test_block_list_env_file,
        test_block_list_credentials,
        test_block_list_ssh_key,
        test_block_list_pem,
        test_allow_normal_file,
        test_redact_openai_key,
        test_redact_github_pat,
        test_redact_aws_key,
        test_redact_stripe_key,
        test_redact_private_key,
        test_redact_database_url,
        test_redact_sendgrid_key,
        test_consistent_placeholder_mapping,
        test_mapping_persists_across_calls,
        test_restore_on_write,
        test_restore_on_edit,
        test_restore_on_bash,
        test_bash_block_cat_env,
        test_bash_block_source_env,
        test_bash_allow_normal_command,
        test_write_without_mapping,
        test_no_false_positive_on_short_strings,
        test_multiple_different_secrets,
        test_mapping_file_permissions,
        test_performance,
    ]

    print(f"\nRunning {len(tests)} tests...\n")
    passed = 0
    failed = 0

    for test in tests:
        try:
            cleanup()
            test()
            passed += 1
        except Exception as e:
            print(f"  FAIL: {test.__name__}: {e}")
            failed += 1

    cleanup()  # Final cleanup

    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed, {len(tests)} total")
    if failed > 0:
        sys.exit(1)
    else:
        print("All tests passed!")
        sys.exit(0)
