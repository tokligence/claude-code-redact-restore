#!/usr/bin/env python3
"""The vault must survive a crash and must survive its own concurrency.

`test_vault_integrity.py` pins the incident where an interpreter that could not
READ the mapping went on to overwrite it. These are the two ways the same class
still bites once that hole is closed, both found by adversarial review of the
fix, plus the two smaller faults that came out of the same reading.

  1. A zero-byte mapping was still a clean first run. `save_mapping` opened the
     real path with O_TRUNC, so a writer killed between the open and the write
     left the file present and empty — and `load_mapping` read "exists, but no
     bytes" as "nothing here yet", minted a fresh vault, and orphaned every
     placeholder already written into a file. Both halves are pinned here: an
     existing empty file is unreadable, AND the write can no longer produce
     one, because it commits with a rename.

  2. Read-modify-write races. Hook processes are concurrent by design — one per
     tool call, and tool calls are issued in parallel. Two of them load the same
     mapping, each mints a placeholder, each saves; the second write wins and
     the first process's file keeps a placeholder that nothing can resolve. This
     one is older than the unreadable-vault work and was never introduced by it.

  3. The failure log's rotation had the same shape as (2) in miniature: read the
     tail, rewrite the file. Two processes doing that at once lose a line — the
     log dropping the record it exists to keep, at the moment several things are
     failing at once.

  4. `restore_read_from_foreign_backup` proves a backup is current by
     re-redacting it and comparing. With the vault unreadable, redaction is a
     pass-through, so the comparison always failed and the failure was reported
     as a stale backup. Right refusal, wrong reason — and the reason sends the
     reader looking at the backup instead of at the mapping, which is the thing
     that is actually broken and the only one of the two they can fix.

Every test here runs the hook as a real subprocess against an isolated HOME and
TMPDIR. Nothing in this file may touch the developer's own vault.
"""
import base64
import hashlib
import json
import os
import subprocess
import sys
import time

import pytest

REPO = os.path.dirname(os.path.abspath(__file__))
# Overridable so the pre-fix hook can be run against this same suite; that is
# how each assertion below was shown to fail before it was made to pass.
HOOK = os.environ.get("REDMEM_HOOK_UNDER_TEST") or os.path.join(REPO, "hooks", "redact-restore.py")

VAULT_ENTRIES = 50

# Built by concatenation on purpose: the literal never appears in this file, so
# a full-suite run under the developer's live shield cannot learn it, and this
# tracked file cannot be rewritten by the very restore pass under test. See the
# note at the top of test_placeholder_bake_relative.py for what happens when a
# fixture is realistic enough to become live.
def _fake_pat(letter):
    """A distinct value matching GITHUB_PAT_CLASSIC."""
    return "ghp_" + letter * 36


def _fernet(key_bytes):
    from cryptography.fernet import Fernet

    return Fernet(base64.urlsafe_b64encode(
        hashlib.sha256(key_bytes + b"mapping-encryption").digest()))


@pytest.fixture
def vault(tmp_path):
    """An isolated HOME holding a populated, ENCRYPTED mapping.

    Returns (env, home, read_entries, read_secret_to_placeholder); the readers
    return None / {} when the file no longer decrypts, which is itself a
    symptom rather than a reason to raise.
    """
    pytest.importorskip("cryptography")
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    (tmp_path / "tmp").mkdir()

    key = b"k" * 32
    (home / ".claude" / ".redact-hmac-key").write_bytes(key)
    f = _fernet(key)

    p2s = {"{{FAKE_%02d_0000000%d}}" % (i, i % 10): "irreplaceable-secret-%02d" % i
           for i in range(VAULT_ENTRIES)}
    (home / ".claude" / ".redact-mapping.json").write_bytes(
        f.encrypt(json.dumps({"placeholder_to_secret": p2s,
                              "secret_to_placeholder": {v: k for k, v in p2s.items()}}).encode()))

    env = dict(os.environ)
    env["HOME"] = str(home)
    env["TMPDIR"] = str(tmp_path / "tmp")
    env.pop("CLAUDE_REDACT_DISABLE", None)

    def _decrypted():
        raw = (home / ".claude" / ".redact-mapping.json").read_bytes()
        try:
            return json.loads(f.decrypt(raw))
        except Exception:
            return None

    def read_entries():
        d = _decrypted()
        return None if d is None else len(d["placeholder_to_secret"])

    def read_secret_to_placeholder():
        d = _decrypted()
        return {} if d is None else d.get("secret_to_placeholder", {})

    return env, home, read_entries, read_secret_to_placeholder


def mapping_path(home):
    return home / ".claude" / ".redact-mapping.json"


def error_log(home):
    return home / ".claude" / "vault" / "restore-errors.log"


def _blind_the_interpreter(env, tmp_path):
    """Make `import cryptography` fail in the child, exactly as a machine with a
    freshly-switched `python3` does — without needing such a machine."""
    shim = tmp_path / "blind" / "cryptography"
    shim.mkdir(parents=True)
    (shim / "__init__.py").write_text('raise ImportError("no cryptography here")\n')
    return _with_pythonpath(env, tmp_path / "blind")


def _with_pythonpath(env, path):
    env = dict(env)
    env["PYTHONPATH"] = str(path) + os.pathsep + env.get("PYTHONPATH", "")
    return env


# ── A seam for making the interleaving deterministic ──────────────────────
#
# Real concurrency also appears below, but a race that only sometimes loses data
# is a weak proof that the fix works and a worse proof that the bug was there.
# This shim pins the exact interleaving each failure needs: the first time the
# child tries to WRITE `target`, it either dies there or parks long enough for a
# sibling process to run to completion.
#
# `die` fires AFTER os.open deliberately. The failure being reproduced is a
# process killed once the destructive open has already happened — which under
# the old code means the file has already been truncated. Firing before the call
# would prove nothing. For rename/replace it fires BEFORE, which is a crash on
# the last instant before the commit: the case an atomic write has to survive.
#
# It arrives as `usercustomize`, NOT `sitecustomize`: Homebrew ships its own
# sitecustomize.py that puts /opt/homebrew/lib/python3.12/site-packages back on
# sys.path, so a shim by that name shadows it and `import cryptography` fails in
# the child. Every test here would then have gone red for the reason
# test_vault_integrity.py already covers rather than the one it claims to test —
# a harness that reports the wrong bug. Hence the markers: the shim records that
# it loaded and that it fired, and the tests assert both. An interposer that
# silently does nothing turns each of these into a test of nothing.
_SHIM = '''
import builtins, os, time

TARGET = os.environ["REDMEM_SHIM_TARGET"]
ACTION = os.environ["REDMEM_SHIM_ACTION"]
DELAY = float(os.environ.get("REDMEM_SHIM_DELAY", "0"))
MARKERS = os.environ["REDMEM_SHIM_MARKERS"]
_fired = []

def _mark(name):
    try:
        with open(os.path.join(MARKERS, name), "a") as f:
            f.write("1")
    except OSError:
        pass

_mark("loaded")

def _trip():
    if _fired:
        return
    _fired.append(1)
    _mark("tripped")
    if ACTION == "die":
        os._exit(97)
    time.sleep(DELAY)

def _is_target(p):
    try:
        return os.fspath(p) == TARGET
    except TypeError:
        return False

_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_TRUNC | os.O_APPEND | os.O_CREAT

_real_os_open = os.open
def _os_open(path, flags, mode=0o777, **kw):
    hit = _is_target(path) and (flags & _WRITE_FLAGS)
    if hit and ACTION != "die":
        _trip()
    fd = _real_os_open(path, flags, mode, **kw)
    if hit and ACTION == "die":
        _trip()
    return fd
os.open = _os_open

def _wrap_rename(fn):
    def inner(src, dst, **kw):
        if _is_target(dst):
            _trip()
        return fn(src, dst, **kw)
    return inner
os.replace = _wrap_rename(os.replace)
os.rename = _wrap_rename(os.rename)

_real_open = builtins.open
def _bopen(file, mode="r", *a, **k):
    if _is_target(file) and any(c in mode for c in "wax+"):
        _trip()
    return _real_open(file, mode, *a, **k)
builtins.open = _bopen
'''


class _Interposer:
    """The patched child's env, plus the evidence that it did its job."""

    def __init__(self, env, markers):
        self.env = env
        self._markers = markers

    def assert_fired(self):
        assert (self._markers / "loaded").exists(), (
            "the interposer never loaded in the child — PYTHONPATH or "
            "usercustomize is not doing what this harness assumes, and every "
            "assertion that depends on it proves nothing"
        )
        assert (self._markers / "tripped").exists(), (
            "the interposer loaded but never fired: the child never touched "
            "the path it was supposed to be caught at, so the interleaving "
            "under test never happened"
        )


def _interpose(env, tmp_path, name, target, action, delay=0.0):
    d = tmp_path / ("shim-" + name)
    d.mkdir(parents=True, exist_ok=True)
    (d / "usercustomize.py").write_text(_SHIM)
    markers = tmp_path / ("markers-" + name)
    markers.mkdir(parents=True, exist_ok=True)
    env = _with_pythonpath(env, d)
    env["REDMEM_SHIM_TARGET"] = str(target)
    env["REDMEM_SHIM_ACTION"] = action
    env["REDMEM_SHIM_DELAY"] = str(delay)
    env["REDMEM_SHIM_MARKERS"] = str(markers)
    return _Interposer(env, markers)


def _read_event(path, cwd, session="vault-durability", post=False):
    ev = {"hook_event_name": "PostToolUse" if post else "PreToolUse",
          "tool_name": "Read", "tool_input": {"file_path": str(path)},
          "session_id": session, "cwd": str(cwd)}
    if post:
        ev["tool_response"] = {"type": "text"}
    return ev


def _run_hook(env, payload, timeout=60):
    return subprocess.run([sys.executable, HOOK], input=json.dumps(payload),
                          capture_output=True, text=True, env=env, timeout=timeout)


def _start_hook(env, payload):
    p = subprocess.Popen([sys.executable, HOOK], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True, env=env)
    p.stdin.write(json.dumps(payload))
    p.stdin.close()
    return p


def _log_kinds(home):
    log = error_log(home)
    if not log.exists():
        return []
    out = []
    for line in log.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return out


# ── 1. A zero-byte mapping is not a clean first run ───────────────────────


def test_a_zero_byte_mapping_is_not_a_fresh_start(vault, tmp_path):
    """The gap the sentinel left open.

    `os.path.exists` is true and the bytes are empty, so the old code fell to
    "no mapping yet", minted a new vault and saved it. Nothing about that is
    distinguishable from a first run on a clean machine — except that every
    placeholder already written into a file has just become unresolvable.
    """
    env, home, _read, _s2p = vault
    mapping_path(home).write_bytes(b"")

    target = tmp_path / "config.yml"
    original = 'token = "%s"\n' % _fake_pat("A")
    target.write_text(original)

    _run_hook(env, _read_event(target, tmp_path))

    assert mapping_path(home).read_bytes() == b"", (
        "an empty mapping file was treated as an empty vault and written over; "
        "if it was empty because a writer died mid-truncate, the entries it "
        "held are now gone for good"
    )
    assert target.read_text() == original, (
        "the file was redacted against a vault that could not be read, so the "
        "placeholder it now holds can never be restored"
    )
    kinds = [r["kind"] for r in _log_kinds(home)]
    assert "vault-unreadable" in kinds, f"no trace of the refusal, got {kinds}"


def test_an_absent_mapping_is_still_a_clean_first_run(vault, tmp_path):
    """The control for the test above. 'Zero bytes' must not swallow 'not there
    yet' — otherwise the shield can never bootstrap itself on a new machine, and
    every assertion above passes for a shield that is simply off."""
    env, home, _read, read_s2p = vault
    mapping_path(home).unlink()

    target = tmp_path / "config.yml"
    secret = _fake_pat("B")
    target.write_text('token = "%s"\n' % secret)

    _run_hook(env, _read_event(target, tmp_path))

    assert mapping_path(home).exists(), "a missing mapping was treated as unreadable"
    assert secret not in target.read_text(), "the shield stopped redacting"
    assert read_s2p().get(secret), "the new secret was not persisted"


# ── 2. A crash during save cannot damage the committed vault ──────────────


def test_a_kill_during_save_never_leaves_a_truncated_vault(vault, tmp_path):
    """Kill the writer at the moment it touches the vault path.

    Old code: os.open(..., O_TRUNC) on the real file, then write. Dying between
    those two leaves the file present and zero bytes — which is what makes the
    test above reachable in the first place. New code never opens the committed
    path for writing at all: it writes a temp file, fsyncs it, and renames. A
    death anywhere before the rename leaves the previous vault exactly as it
    was; a death after it leaves the new one, whole.
    """
    env, home, read_entries, _s2p = vault
    before = mapping_path(home).read_bytes()

    target = tmp_path / "config.yml"
    target.write_text('token = "%s"\n' % _fake_pat("C"))

    crashy = _interpose(env, tmp_path, "die", mapping_path(home), "die")
    proc = _run_hook(crashy.env, _read_event(target, tmp_path))
    crashy.assert_fired()
    assert proc.returncode == 97, (
        f"the child did not die where it was supposed to (rc={proc.returncode}, "
        f"stderr={proc.stderr[-400:]})"
    )

    assert mapping_path(home).stat().st_size > 0, (
        "the vault is zero bytes after an interrupted save — every placeholder "
        "already written into a file is now unresolvable"
    )
    assert read_entries() == VAULT_ENTRIES, (
        "the vault no longer decrypts to the entries it held before the crash"
    )
    assert mapping_path(home).read_bytes() == before

    # And the machine still works afterwards: whatever the crash left behind
    # (a temp file next to the vault) must be inert.
    survivor = tmp_path / "after.yml"
    secret = _fake_pat("D")
    survivor.write_text('token = "%s"\n' % secret)
    _run_hook(env, _read_event(survivor, tmp_path))
    assert secret not in survivor.read_text(), "the shield did not recover"
    assert read_entries() > VAULT_ENTRIES, "pre-existing entries were dropped"


# ── 3. Concurrent minting keeps every entry ───────────────────────────────


def test_a_stale_save_does_not_drop_another_process_entry(vault, tmp_path):
    """The race, pinned to one interleaving so it fails every time.

    A loads the mapping and is held at the instant it goes to write. B loads the
    same mapping, mints its own placeholder and saves. A then writes what it
    loaded. Under a last-writer-wins save, B's entry is gone and B's file is
    left holding a placeholder nothing can resolve.
    """
    env, home, read_entries, read_s2p = vault
    secret_a, secret_b = _fake_pat("E"), _fake_pat("F")

    file_a = tmp_path / "a.conf"
    file_a.write_text('token = "%s"\n' % secret_a)
    file_b = tmp_path / "b.conf"
    file_b.write_text('token = "%s"\n' % secret_b)

    slow = _interpose(env, tmp_path, "delay", mapping_path(home), "delay", delay=5.0)
    a = _start_hook(slow.env, _read_event(file_a, tmp_path, session="A"))
    time.sleep(1.5)  # A is now parked at its own write
    slow.assert_fired()
    _run_hook(env, _read_event(file_b, tmp_path, session="B"))
    a.wait(timeout=60)

    s2p = read_s2p()
    assert secret_a in s2p, "the parked process's own entry is missing"
    assert secret_b in s2p, (
        "a concurrent save was overwritten by a stale one; the file it redacted "
        "still holds the placeholder, and the mapping no longer knows it"
    )
    assert read_entries() >= VAULT_ENTRIES + 2, "pre-existing entries were dropped"
    for f, secret in ((file_a, secret_a), (file_b, secret_b)):
        assert secret not in f.read_text(), f"{f.name} was never redacted"


def test_eight_real_hook_processes_at_once_lose_nothing(vault, tmp_path):
    """The same claim without a harness holding the interleaving still.

    Worth having in addition to the deterministic one: it exercises the actual
    lock under the actual contention, and it is the shape the failure takes in
    production, where several tool calls are dispatched at once.
    """
    env, home, read_entries, read_s2p = vault
    secrets = {}
    procs = []
    for letter in "GHIJKLMN":
        secret = _fake_pat(letter)
        f = tmp_path / f"conf-{letter}.yml"
        f.write_text('token = "%s"\n' % secret)
        secrets[letter] = (f, secret)
    for letter, (f, _secret) in secrets.items():
        procs.append(_start_hook(env, _read_event(f, tmp_path, session=letter)))
    for p in procs:
        p.wait(timeout=90)

    s2p = read_s2p()
    missing = [letter for letter, (_f, secret) in secrets.items() if secret not in s2p]
    assert not missing, (
        f"{len(missing)} of {len(secrets)} concurrent hooks had their entry "
        f"overwritten: {missing}. Each of those files was redacted with a "
        f"placeholder the mapping no longer contains."
    )
    assert read_entries() >= VAULT_ENTRIES + len(secrets)


# ── 4. The failure log does not drop a concurrent failure ─────────────────


def _fill_log(home, lines):
    log = error_log(home)
    log.parent.mkdir(parents=True, exist_ok=True)
    filler = json.dumps({"ts": "2026-01-01T00:00:00", "kind": "filler",
                         "pad": "x" * 200}) + "\n"
    log.write_text(filler * lines)
    return log


def test_the_rotating_log_does_not_drop_a_concurrent_failure(vault, tmp_path):
    """Rotation is read-the-tail-then-rewrite, which is the same race in
    miniature. Two processes both read the tail, both rewrite, and the line
    appended in between is gone — the failure log losing a failure, which is
    precisely when it is being read.
    """
    env, home, _read, _s2p = vault
    blind = _blind_the_interpreter(env, tmp_path)

    target = tmp_path / "config.yml"
    target.write_text('token = "%s"\n' % _fake_pat("O"))

    # Calibrate: how many records does one blind run emit? Asserting on a
    # hard-coded number would break the moment the hook records one more thing.
    _run_hook(blind, _read_event(target, tmp_path, session="cal"))
    per_run = sum(1 for r in _log_kinds(home) if r["kind"] == "vault-unreadable")
    assert per_run >= 1, "the calibration run recorded nothing to lose"

    _fill_log(home, 6000)  # comfortably over SHIELD_ERROR_LOG_MAX_BYTES
    assert error_log(home).stat().st_size > 1_000_000

    slow = _interpose(blind, tmp_path, "log", error_log(home), "delay", delay=5.0)
    a = _start_hook(slow.env, _read_event(target, tmp_path, session="A"))
    time.sleep(1.5)  # A is parked mid-rotation
    slow.assert_fired()
    _run_hook(blind, _read_event(target, tmp_path, session="B"))
    a.wait(timeout=60)

    kept = sum(1 for r in _log_kinds(home) if r["kind"] == "vault-unreadable")
    assert kept == 2 * per_run, (
        f"expected {2 * per_run} records from two runs, found {kept} — a "
        f"rotation carried out concurrently with an append swallowed one"
    )


# ── 5. An unverifiable backup names the real cause ────────────────────────


def test_an_unrestorable_read_names_the_vault_not_the_backup(vault, tmp_path):
    """Refusing is right; blaming the backup is not.

    The proof that a foreign backup is current re-redacts it and compares. With
    the vault unreadable, redaction passes content through, so the comparison
    can never succeed and every such Read was reported as a stale backup. The
    backup may be perfect. What is broken is the mapping — which is also
    disabling the shield everywhere else at that moment, and is the only one of
    the two that anyone can actually fix.
    """
    env, home, _read, _s2p = vault
    target = tmp_path / "app.conf"
    secret = _fake_pat("P")
    original = 'token = "%s"\n' % secret
    target.write_text(original)

    # Session A redacts it and files the backup under its own session id.
    _run_hook(env, _read_event(target, tmp_path, session="session-A"))
    redacted = target.read_text()
    assert secret not in redacted, "PreToolUse did not redact — test proves nothing"

    # The matching PostToolUse arrives under another session id, on an
    # interpreter that can no longer read the vault.
    blind = _blind_the_interpreter(env, tmp_path)
    proc = _run_hook(blind, _read_event(target, tmp_path, session="session-B", post=True))

    assert target.read_text() == redacted, (
        "an unverified backup was copied over the file while the vault could "
        "not be read"
    )
    reads = [r for r in _log_kinds(home) if r["kind"] == "unrestorable_read"]
    assert reads, "the refusal was not recorded at all"
    assert reads[-1].get("cause") == "vault_unreadable", (
        f"the failure was recorded as {reads[-1].get('cause') or reads[-1].get('context')!r} "
        f"— it blames the backup, and the backup is not what is broken"
    )
    assert "mapping could not be read" in reads[-1].get("context", "")
    assert "mapping could not be read" in proc.stdout, (
        "the transcript warning still blames the backup; that is the copy a "
        "human actually reads"
    )
