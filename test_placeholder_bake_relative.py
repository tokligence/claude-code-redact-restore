#!/usr/bin/env python3
"""Regression test: a Bash read-modify-write that names its file with a
RELATIVE path must not leave a redacted placeholder baked into that file.

The bug this pins
─────────────────
The Bash PostToolUse restore pass collected candidate paths with two regexes
that both required a leading `/`. So the ordinary way an agent edits a file —

    python3 - <<'PY'
    p = 'README.md'
    s = open(p).read()
    ...
    open(p, 'w').write(s)
    PY

— produced no candidates at all, and any placeholder the model wrote back
stayed on disk. Found in this repository's own README, where a documentation
example DSN had been replaced by `{{POSTGRES_URL_...}}` and was sitting in the
worktree ready to be committed. A placeholder in a public README is a broken
doc; the same mechanism in a config file is a broken deploy.

Both directions are asserted: the relative path is now restored, and the
absolute path (which always worked) still is — a rewrite of the extraction
must not trade one for the other.
"""
import json
import os
import subprocess
import sys
import tempfile

import pytest

REPO = os.path.dirname(os.path.abspath(__file__))
HOOK = os.path.join(REPO, "hooks", "redact-restore.py")

SECRET = "postgresql://redmem:pass@localhost:5432/redmem"
PLACEHOLDER = "{{POSTGRES_URL_7bf1817a}}"


@pytest.fixture
def shield_env(tmp_path):
    """An isolated shield home with one placeholder -> secret mapping."""
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    env = dict(os.environ)
    env["HOME"] = str(home)
    env.pop("CLAUDE_REDACT_DISABLE", None)

    session = "test-bake-session"
    mapping = {
        "placeholder_to_secret": {PLACEHOLDER: SECRET},
        "secret_to_placeholder": {SECRET: PLACEHOLDER},
    }
    # The hook reads ~/.claude/.redact-mapping.json, encrypted with the same
    # Fernet key it derives at import time when `cryptography` is installed.
    # Writing plaintext there yields an empty mapping and every assertion
    # below would pass for the wrong reason.
    # The mapping lives at ~/.claude/.redact-mapping.json, encrypted with a
    # Fernet key derived from ~/.claude/.redact-hmac-key. Both are created by
    # the hook itself on first run inside this isolated HOME, so prime them by
    # invoking it once, then derive the same key and write the mapping.
    # Writing plaintext (or the wrong key) yields an empty mapping and every
    # assertion below would pass for the wrong reason.
    subprocess.run(
        [sys.executable, HOOK],
        input=json.dumps({"hook_event_name": "PostToolUse", "tool_name": "Bash",
                          "tool_input": {"command": "true"}, "session_id": session,
                          "cwd": str(tmp_path)}),
        capture_output=True, text=True, env=env, timeout=30,
    )
    key_path = home / ".claude" / ".redact-hmac-key"
    assert key_path.exists(), "hook did not create its HMAC key in the isolated HOME"

    blob = json.dumps(mapping).encode()
    try:
        import base64
        import hashlib

        from cryptography.fernet import Fernet

        fernet_key = base64.urlsafe_b64encode(
            hashlib.sha256(key_path.read_bytes() + b"mapping-encryption").digest()
        )
        blob = Fernet(fernet_key).encrypt(blob)
    except ImportError:
        pass  # hook falls back to plaintext when cryptography is absent
    (home / ".claude" / ".redact-mapping.json").write_bytes(blob)

    return env, session


def _post_bash(env, session, command, cwd):
    payload = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "session_id": session,
        "cwd": str(cwd),
    }
    return subprocess.run(
        [sys.executable, HOOK],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


@pytest.mark.parametrize(
    "command_template",
    [
        # The exact shape that baked this repo's README.
        "python3 - <<'PY'\np = '{rel}'\ns = open(p).read()\nopen(p,'w').write(s)\nPY",
        # Bare, unquoted — equally common in sed/awk one-liners.
        "sed -i '' 's/a/b/' {rel}",
        # Nested relative path.
        "python3 -c \"open('{rel}').read()\"",
    ],
)
def test_relative_path_write_is_restored(shield_env, tmp_path, command_template):
    env, session = shield_env
    target = tmp_path / "README.md"
    target.write_text(f"archive_dsn: \"{PLACEHOLDER}\"\n")

    _post_bash(env, session, command_template.format(rel="README.md"), cwd=tmp_path)

    content = target.read_text()
    assert PLACEHOLDER not in content, (
        "placeholder survived on disk — a relative-path read-modify-write is "
        "the ordinary case, not an edge case"
    )
    assert SECRET in content


def test_absolute_path_still_restored(shield_env, tmp_path):
    """The path that always worked must keep working."""
    env, session = shield_env
    target = tmp_path / "config.yml"
    target.write_text(f"dsn: \"{PLACEHOLDER}\"\n")

    _post_bash(env, session, f"python3 -c \"open('{target}').read()\"", cwd=tmp_path)

    assert PLACEHOLDER not in target.read_text()


def test_subdirectory_relative_path_is_restored(shield_env, tmp_path):
    env, session = shield_env
    sub = tmp_path / "hooks"
    sub.mkdir()
    target = sub / "settings.py"
    target.write_text(f"DSN = \"{PLACEHOLDER}\"\n")

    _post_bash(env, session, "python3 - <<'PY'\np='hooks/settings.py'\nPY", cwd=tmp_path)

    assert PLACEHOLDER not in target.read_text()


def test_unrelated_files_are_left_alone(shield_env, tmp_path):
    """Over-collecting candidates is only acceptable because a candidate is
    touched solely when it carries a live placeholder. A file with no
    placeholder must come back byte-identical."""
    env, session = shield_env
    innocent = tmp_path / "notes.md"
    original = "just some prose, no secrets here\n"
    innocent.write_text(original)

    _post_bash(env, session, "python3 - <<'PY'\np='notes.md'\nPY", cwd=tmp_path)

    assert innocent.read_text() == original
