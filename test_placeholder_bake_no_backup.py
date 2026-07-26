#!/usr/bin/env python3
"""Regression tests: the PostToolUse restore must not depend on a backup file.

Every path here bakes a `{{PLACEHOLDER_deadbeef}}` into a real file on disk,
and every one of them does it because the restore branch is gated on
`os.path.exists(bak_file)`:

  1. Session-id mismatch. `BACKUP_DIR` is `/tmp/.claude-backup-{session_id}`.
     A Read whose PreToolUse and PostToolUse carry different session ids
     (subagent boundary, wrapper re-keying the event) writes the backup into
     one directory and looks for it in another. The file is left redacted
     *permanently* — this is the only bug here that damages a file the user
     never asked to change.

  2. Write creating a file that did not exist. No pre-image, so no backup,
     so the PostToolUse net that scans the written file never runs.

  3. Edit on a file that was clean before the edit. The backup is created
     only when the *pre-edit* content already contained a secret, so an edit
     that introduces a placeholder into a clean file gets no backup either.

For 2 and 3 the placeholder normally never reaches disk, because the Write /
Edit PreToolUse rewrites `content` / `new_string` via `updatedInput`. It
reaches disk when something else in the PreToolUse chain answers first: the
dispatcher returns the FIRST decision it gets, so a `deploy_config_guard`
`ask` on `docker-compose.yml` / `Cargo.toml` discards the shield's rewrite,
and the user's approval then writes the untouched, placeholder-bearing input.
Those two tests reproduce that whole chain rather than asserting on the
PostToolUse handler in isolation.

A placeholder in a public README is a broken doc. The same placeholder in
`docker-compose.yml` is a broken deploy — and the deploy-critical files are
exactly the ones the guard makes this reachable for.

Nothing here uses a real secret or a real placeholder: SECRET is an obvious
dummy and PLACEHOLDER carries a name that is not in anybody's mapping.
"""
import base64
import hashlib
import json
import os
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.abspath(__file__))
HOOK = os.path.join(REPO, "hooks", "redact-restore.py")
DISPATCHER = os.path.join(REPO, "hooks", "redmem_dispatcher.py")

# Deliberately synthetic. `TEST_FAKE_KEY_deadbeef` matches the shield's
# placeholder shape but belongs to no real mapping, so a full-suite run under
# a developer's live shield cannot rewrite this file.
PLACEHOLDER = "{{TEST_FAKE_KEY_deadbeef}}"
SECRET = "not-a-real-secret-value-for-tests-0001"

# Matches GITHUB_PAT_CLASSIC. Used where the test needs the shield to redact
# a file for real rather than to consume a pre-seeded mapping.
FAKE_PAT = "ghp_" + "A" * 36


def _isolated_home(tmp_path):
    """A HOME the shield owns entirely, plus a private TMPDIR.

    TMPDIR matters: `BACKUP_DIR` is derived from `tempfile.gettempdir()`, so
    without it these tests would scatter backup directories through the real
    /tmp and could collide with a live session.
    """
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    tmpdir = tmp_path / "tmp"
    tmpdir.mkdir()
    env = dict(os.environ)
    env["HOME"] = str(home)
    env["TMPDIR"] = str(tmpdir)
    env.pop("CLAUDE_REDACT_DISABLE", None)
    env.pop("REDMEM_ALLOW_DEPLOY_CONFIG", None)
    return env, home


def _seed_mapping(env, home, tmp_path, mapping):
    """Write `mapping` where the hook will actually read it.

    The mapping file is Fernet-encrypted with a key derived from
    ~/.claude/.redact-hmac-key, which the hook creates on first run. Priming
    it with plaintext yields an empty mapping and every assertion below would
    pass for the wrong reason.
    """
    subprocess.run(
        [sys.executable, HOOK],
        input=json.dumps({"hook_event_name": "PostToolUse", "tool_name": "Bash",
                          "tool_input": {"command": "true"},
                          "session_id": "seed", "cwd": str(tmp_path)}),
        capture_output=True, text=True, env=env, timeout=30,
    )
    key_path = home / ".claude" / ".redact-hmac-key"
    assert key_path.exists(), "hook did not create its HMAC key in the isolated HOME"

    blob = json.dumps(mapping).encode()
    try:
        from cryptography.fernet import Fernet

        fernet_key = base64.urlsafe_b64encode(
            hashlib.sha256(key_path.read_bytes() + b"mapping-encryption").digest()
        )
        blob = Fernet(fernet_key).encrypt(blob)
    except ImportError:
        pass  # hook falls back to plaintext when cryptography is absent
    (home / ".claude" / ".redact-mapping.json").write_bytes(blob)


@pytest.fixture
def shield(tmp_path):
    """Isolated HOME carrying exactly one PLACEHOLDER -> SECRET entry."""
    env, home = _isolated_home(tmp_path)
    _seed_mapping(env, home, tmp_path, {
        "placeholder_to_secret": {PLACEHOLDER: SECRET},
        "secret_to_placeholder": {SECRET: PLACEHOLDER},
    })
    return env, home


@pytest.fixture
def shield_empty(tmp_path):
    """Isolated HOME with no mapping — the shield builds its own."""
    env, home = _isolated_home(tmp_path)
    return env, home


def _hook(env, payload):
    return subprocess.run(
        [sys.executable, HOOK],
        input=json.dumps(payload), capture_output=True, text=True,
        env=env, timeout=30,
    )


def _dispatch(env, payload):
    target = (payload.get("tool_input") or {}).get("file_path") \
        if isinstance(payload.get("tool_input"), dict) else None
    if target and os.path.abspath(target).startswith(REPO + os.sep):
        raise AssertionError(
            f"hook payload targets a file inside the repo: {target}\n"
            "Use tmp_path — the shield rewrites its target on disk."
        )
    proc = subprocess.run(
        [sys.executable, DISPATCHER],
        input=json.dumps(payload), capture_output=True, text=True,
        env=env, timeout=30,
    )
    out = proc.stdout.strip()
    return (json.loads(out) if out else None), proc


# ── 1. session-id mismatch ────────────────────────────────────────────────
def test_read_restores_when_posttooluse_carries_a_different_session_id(
    shield_empty, tmp_path
):
    """The damaging one: nobody asked for this file to change.

    PreToolUse redacts the file in place so Claude Code's freshness check
    sees what Claude saw. If the matching PostToolUse cannot find the backup,
    the user's file simply stays redacted — a live secret replaced by a
    placeholder, on disk, with no error anywhere.
    """
    env, _ = shield_empty
    target = tmp_path / "app.conf"
    original = f'token = "{FAKE_PAT}"\n'
    target.write_text(original)

    _hook(env, {"hook_event_name": "PreToolUse", "tool_name": "Read",
                "tool_input": {"file_path": str(target)},
                "session_id": "session-A", "cwd": str(tmp_path)})

    redacted = target.read_text()
    assert FAKE_PAT not in redacted, "PreToolUse did not redact — test proves nothing"
    assert "{{GITHUB_PAT_CLASSIC_" in redacted

    _hook(env, {"hook_event_name": "PostToolUse", "tool_name": "Read",
                "tool_input": {"file_path": str(target)},
                "tool_response": {"type": "text"},
                "session_id": "session-B", "cwd": str(tmp_path)})

    assert target.read_text() == original, (
        "file left redacted after Read — a mismatched session id must not "
        "cost the user their file content"
    )


def test_read_restore_with_matching_session_id_still_works(shield_empty, tmp_path):
    """The path that always worked must keep working, byte for byte,
    including the mtime the backup restore preserves."""
    env, _ = shield_empty
    target = tmp_path / "same-session.conf"
    original = f'token = "{FAKE_PAT}"\n'
    target.write_text(original)
    os.utime(target, (1_600_000_000, 1_600_000_000))

    for event in ("PreToolUse", "PostToolUse"):
        _hook(env, {"hook_event_name": event, "tool_name": "Read",
                    "tool_input": {"file_path": str(target)},
                    "session_id": "session-same", "cwd": str(tmp_path)})

    assert target.read_text() == original
    assert int(os.stat(target).st_mtime) == 1_600_000_000


def test_read_does_not_expand_a_placeholder_it_did_not_write(shield, tmp_path):
    """The repair for a missing backup must not become a second bake.

    A live placeholder does occur at rest: `test_placeholder_bake_relative.py`
    in this repo holds one on line 39, and it resolves against the developer's
    real mapping. If a Read with no backup "repaired" the file by expanding
    every placeholder it found, reading that file would write a real DSN into
    a tracked source file — the README accident pointed the other way, and
    with a worse consequence than a broken doc.

    A Read that never redacted anything has nothing to put back.
    """
    env, _ = shield
    target = tmp_path / "docs.md"
    original = f"Example: {PLACEHOLDER} is a redacted value.\n"
    target.write_text(original)

    for event in ("PreToolUse", "PostToolUse"):
        _hook(env, {"hook_event_name": event, "tool_name": "Read",
                    "tool_input": {"file_path": str(target)},
                    "session_id": "s", "cwd": str(tmp_path)})

    assert target.read_text() == original
    assert SECRET not in target.read_text()


def test_read_ignores_a_stale_backup_from_another_session(shield_empty, tmp_path):
    """Cross-session recovery must not resurrect an unrelated old version.

    An abandoned session can leave a backup for a path that has since been
    edited. Restoring it would silently revert that work, so the backup is
    used only when it reproduces, byte for byte, the redacted file currently
    on disk.
    """
    env, home = shield_empty
    target = tmp_path / "notes.md"
    _hook(env, {"hook_event_name": "PreToolUse", "tool_name": "Read",
                "tool_input": {"file_path": str(target)},
                "session_id": "s", "cwd": str(tmp_path)})  # creates HOME dirs

    stale_dir = tmp_path / "tmp" / ".claude-backup-abandoned"
    stale_dir.mkdir(parents=True)
    digest = hashlib.sha256(str(target).encode()).hexdigest()[:16]
    (stale_dir / f"{digest}.bak").write_text("a much older version\n")
    (stale_dir / f"{digest}.meta").write_text(json.dumps({"original_path": str(target)}))

    current = f'token = "{FAKE_PAT}" and {PLACEHOLDER}\n'
    target.write_text(current)

    _hook(env, {"hook_event_name": "PostToolUse", "tool_name": "Read",
                "tool_input": {"file_path": str(target)},
                "session_id": "other", "cwd": str(tmp_path)})

    assert target.read_text() == current, "a stale backup must not revert the file"


def test_read_posttooluse_leaves_a_clean_file_untouched(shield_empty, tmp_path):
    """The overwhelmingly common case — a Read of a file with no secrets —
    must not be rewritten by the new backup-free path."""
    env, _ = shield_empty
    target = tmp_path / "prose.md"
    original = "nothing sensitive here\n"
    target.write_text(original)
    os.utime(target, (1_600_000_000, 1_600_000_000))

    _hook(env, {"hook_event_name": "PostToolUse", "tool_name": "Read",
                "tool_input": {"file_path": str(target)},
                "session_id": "s", "cwd": str(tmp_path)})

    assert target.read_text() == original
    assert int(os.stat(target).st_mtime) == 1_600_000_000


# ── 2. Write creating a new file ──────────────────────────────────────────
def test_write_to_new_file_is_restored_without_a_backup(shield, tmp_path):
    env, _ = shield
    target = tmp_path / "docker-compose.yml"
    target.write_text(f"    DATABASE_URL: {PLACEHOLDER}\n")  # as the tool wrote it

    _hook(env, {"hook_event_name": "PostToolUse", "tool_name": "Write",
                "tool_input": {"file_path": str(target),
                               "content": f"    DATABASE_URL: {PLACEHOLDER}\n"},
                "tool_response": {"type": "create"},
                "session_id": "s", "cwd": str(tmp_path)})

    assert PLACEHOLDER not in target.read_text(), (
        "a Write that creates a file gets no backup, and the restore was "
        "gated on that backup"
    )
    assert SECRET in target.read_text()


def test_deploy_guard_ask_then_write_does_not_bake_a_placeholder(shield, tmp_path):
    """End-to-end: the reason the PreToolUse rewrite is not a sufficient net.

    The dispatcher returns the first decision produced, and the deploy-config
    guard's `ask` is produced after the shield's `updatedInput` — so the
    rewrite is dropped. Approving the ask writes the ORIGINAL tool_input.
    """
    env, _ = shield
    target = tmp_path / "docker-compose.yml"
    content = f"services:\n  db:\n    environment:\n      DSN: {PLACEHOLDER}\n"

    parsed, _proc = _dispatch(env, {
        "hook_event_name": "PreToolUse", "tool_name": "Write",
        "tool_input": {"file_path": str(target), "content": content},
        "session_id": "s", "cwd": str(tmp_path),
    })
    hso = (parsed or {}).get("hookSpecificOutput", {})
    assert hso.get("permissionDecision") == "ask", (
        "expected the deploy-config guard to answer first — if it no longer "
        "does, this test is no longer reproducing the real chain"
    )
    assert "updatedInput" not in hso, (
        "the shield's placeholder-restored content did not survive the chain"
    )

    # The user approves; Claude Code writes the unmodified tool_input.
    target.write_text(content)

    _dispatch(env, {
        "hook_event_name": "PostToolUse", "tool_name": "Write",
        "tool_input": {"file_path": str(target), "content": content},
        "tool_response": {"type": "create"},
        "session_id": "s", "cwd": str(tmp_path),
    })

    assert PLACEHOLDER not in target.read_text(), (
        "placeholder baked into a deploy-critical file: a broken deploy, "
        "not a broken doc"
    )
    assert SECRET in target.read_text()


# ── 3. Edit on a previously clean file ────────────────────────────────────
def test_edit_that_introduces_a_placeholder_into_a_clean_file_is_restored(
    shield, tmp_path
):
    env, _ = shield
    target = tmp_path / "Cargo.toml"
    target.write_text(f'[package]\nname = "app"\ndsn = "{PLACEHOLDER}"\n')  # post-edit

    _hook(env, {"hook_event_name": "PostToolUse", "tool_name": "Edit",
                "tool_input": {"file_path": str(target),
                               "old_string": 'name = "app"',
                               "new_string": f'name = "app"\ndsn = "{PLACEHOLDER}"'},
                "tool_response": {"type": "update"},
                "session_id": "s", "cwd": str(tmp_path)})

    assert PLACEHOLDER not in target.read_text(), (
        "the Edit backup is created only when the PRE-edit file already held "
        "a secret, so an edit that introduces one gets no restore"
    )
    assert SECRET in target.read_text()


def test_deploy_guard_ask_then_edit_does_not_bake_a_placeholder(shield, tmp_path):
    env, _ = shield
    target = tmp_path / "Cargo.toml"
    clean = '[package]\nname = "app"\n'
    target.write_text(clean)
    new_string = f'name = "app"\ndsn = "{PLACEHOLDER}"'

    parsed, _proc = _dispatch(env, {
        "hook_event_name": "PreToolUse", "tool_name": "Edit",
        "tool_input": {"file_path": str(target), "old_string": 'name = "app"',
                       "new_string": new_string},
        "session_id": "s", "cwd": str(tmp_path),
    })
    hso = (parsed or {}).get("hookSpecificOutput", {})
    assert hso.get("permissionDecision") == "ask"
    assert "updatedInput" not in hso

    target.write_text(clean.replace('name = "app"', new_string))

    _dispatch(env, {
        "hook_event_name": "PostToolUse", "tool_name": "Edit",
        "tool_input": {"file_path": str(target), "old_string": 'name = "app"',
                       "new_string": new_string},
        "tool_response": {"type": "update"},
        "session_id": "s", "cwd": str(tmp_path),
    })

    assert PLACEHOLDER not in target.read_text()
    assert SECRET in target.read_text()


def test_edit_backup_path_still_restores(shield_empty, tmp_path):
    """A file that DID hold a secret before the edit keeps its old behaviour."""
    env, home = shield_empty
    target = tmp_path / "settings.py"
    target.write_text(f'TOKEN = "{FAKE_PAT}"\n')

    _hook(env, {"hook_event_name": "PreToolUse", "tool_name": "Edit",
                "tool_input": {"file_path": str(target), "old_string": "TOKEN",
                               "new_string": "TOKEN"},
                "session_id": "s2", "cwd": str(tmp_path)})
    _hook(env, {"hook_event_name": "PostToolUse", "tool_name": "Edit",
                "tool_input": {"file_path": str(target), "old_string": "TOKEN",
                               "new_string": "TOKEN"},
                "tool_response": {"type": "update"},
                "session_id": "s2", "cwd": str(tmp_path)})

    assert target.read_text() == f'TOKEN = "{FAKE_PAT}"\n'


# ── 4. the fail-open branch has to leave a trace ──────────────────────────
def _error_log(home):
    return home / ".claude" / "vault" / "restore-errors.log"


def test_crash_in_the_restore_path_is_recorded_and_surfaced(shield, tmp_path):
    """A fail-open branch with no evidence is indistinguishable from a
    working one.

    `tool_input` as a string is a real uncaught shape: the PostToolUse
    handler calls `tool_input.get(...)` and the AttributeError unwinds to the
    module-level `except Exception: exit 0`. Before this test the only trace
    was one stderr line nobody reads — which is how a NameError silently
    disabled the entire restore path, absolute paths included.
    """
    env, home = shield

    proc = _hook(env, {"hook_event_name": "PostToolUse", "tool_name": "Write",
                       "tool_input": "not-a-dict",
                       "tool_response": {"type": "create"},
                       "session_id": "s", "cwd": str(tmp_path)})

    assert proc.returncode == 0, "fail-open is correct — a hook bug must not block work"

    log = _error_log(home)
    assert log.exists(), "the restore path crashed and left no durable record"
    entry = json.loads(log.read_text().splitlines()[-1])
    assert entry["kind"] == "exception"
    assert "AttributeError" in entry["error"]
    assert entry["hook_event"] == "PostToolUse"

    out = proc.stdout.strip()
    assert out, "a crashed restore must announce itself in-band, not only on stderr"
    ctx = json.loads(out)["hookSpecificOutput"]["additionalContext"]
    assert "secret-shield" in ctx


def test_unrestorable_placeholder_is_recorded_and_surfaced(shield, tmp_path):
    """The detector for the whole bug class: the restore pass ran and the
    file still carries a live placeholder. That is always a defect — it is
    what every bake in this file looks like from the outside."""
    env, home = shield
    target = tmp_path / "app.yaml"
    target.write_text(f"dsn: {PLACEHOLDER}\n")
    os.chmod(target, 0o444)
    os.chmod(tmp_path, 0o555)  # make the rewrite fail
    try:
        proc = _hook(env, {"hook_event_name": "PostToolUse", "tool_name": "Write",
                           "tool_input": {"file_path": str(target), "content": "x"},
                           "tool_response": {"type": "create"},
                           "session_id": "s", "cwd": str(tmp_path)})
    finally:
        os.chmod(tmp_path, 0o755)
        os.chmod(target, 0o644)

    log = _error_log(home)
    assert log.exists(), "a placeholder the shield could not restore left no record"
    entry = json.loads(log.read_text().splitlines()[-1])
    assert entry["kind"] == "residual_placeholder"
    assert entry["path"] == str(target)
    assert PLACEHOLDER in entry["placeholders"]

    ctx = json.loads(proc.stdout.strip())["hookSpecificOutput"]["additionalContext"]
    assert str(target) in ctx


def test_warning_survives_the_dispatcher(shield, tmp_path):
    """The warning is only worth anything if it reaches the conversation, and
    the dispatcher — not the shield — owns what PostToolUse finally prints."""
    env, _ = shield
    target = tmp_path / "app.yaml"
    target.write_text(f"dsn: {PLACEHOLDER}\n")
    os.chmod(target, 0o444)
    os.chmod(tmp_path, 0o555)
    try:
        parsed, _proc = _dispatch(env, {
            "hook_event_name": "PostToolUse", "tool_name": "Write",
            "tool_input": {"file_path": str(target), "content": "x"},
            "tool_response": {"type": "create"},
            "session_id": "s", "cwd": str(tmp_path),
        })
    finally:
        os.chmod(tmp_path, 0o755)
        os.chmod(target, 0o644)

    hso = (parsed or {}).get("hookSpecificOutput", {})
    assert hso.get("hookEventName") == "PostToolUse"
    assert str(target) in hso.get("additionalContext", "")


def test_error_log_never_carries_a_secret_value(shield, tmp_path):
    env, home = shield
    target = tmp_path / "app.yaml"
    target.write_text(f"dsn: {PLACEHOLDER}\n")
    os.chmod(target, 0o444)
    os.chmod(tmp_path, 0o555)
    try:
        _hook(env, {"hook_event_name": "PostToolUse", "tool_name": "Write",
                    "tool_input": {"file_path": str(target), "content": "x"},
                    "tool_response": {"type": "create"},
                    "session_id": "s", "cwd": str(tmp_path)})
    finally:
        os.chmod(tmp_path, 0o755)
        os.chmod(target, 0o644)

    assert SECRET not in _error_log(home).read_text()


def test_healthy_run_writes_no_error_log(shield, tmp_path):
    """Every alarm has to be worth reading. A successful restore is silent."""
    env, home = shield
    target = tmp_path / "config.yml"
    target.write_text(f"dsn: {PLACEHOLDER}\n")

    proc = _hook(env, {"hook_event_name": "PostToolUse", "tool_name": "Write",
                       "tool_input": {"file_path": str(target), "content": "x"},
                       "tool_response": {"type": "create"},
                       "session_id": "s", "cwd": str(tmp_path)})

    assert SECRET in target.read_text()
    assert not _error_log(home).exists()
    assert proc.stdout.strip() == ""


def test_doc_example_placeholder_does_not_raise_a_false_alarm(shield, tmp_path):
    """`{{OPENAI_KEY_8f3a2b1c}}` appears in this project's own README and in
    CLAUDE.md. A placeholder that belongs to no mapping entry is prose, not
    a failed restore, and must not be reported."""
    env, home = shield
    target = tmp_path / "README.md"
    target.write_text("Values like {{OPENAI_KEY_8f3a2b1c}} are placeholders.\n")

    proc = _hook(env, {"hook_event_name": "PostToolUse", "tool_name": "Write",
                       "tool_input": {"file_path": str(target), "content": "x"},
                       "tool_response": {"type": "create"},
                       "session_id": "s", "cwd": str(tmp_path)})

    assert not _error_log(home).exists()
    assert proc.stdout.strip() == ""
