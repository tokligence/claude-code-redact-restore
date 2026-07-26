#!/usr/bin/env python3
"""The mapping vault must survive an interpreter that cannot read it.

The incident this pins
──────────────────────
A 235-entry encrypted `~/.claude/.redact-mapping.json` came back as 6 plaintext
entries mid-session, and then — after being restored from backup — as 1 entry a
few minutes later. Nothing malicious, and no single bad line of code: three
ordinary behaviours composed into a data-destroying one.

  1. `python3` on the machine started resolving to a newer interpreter that had
     no `cryptography` installed, so `FERNET` became None.
  2. `load_mapping` handed the encrypted bytes to `json.loads`, which failed,
     and the handler returned an EMPTY mapping — an unreadable vault and an
     absent vault were the same value.
  3. `save_mapping` opens with `O_TRUNC`. One redaction later, the whole vault
     was replaced by the entries that single invocation happened to mint, in
     plaintext.

Every placeholder already baked into a file became permanently unresolvable,
and the survivors landed unencrypted. The failure is silent by construction:
each step is individually reasonable, and the shield goes on "working".

What the fix must guarantee, and why each half matters
──────────────────────────────────────────────────────
  - The vault is never written over when it could not be read. Fail-open is the
    right posture for a hook that might block someone's edit; it is the wrong
    posture for one that might delete their data.
  - Redaction stops for that invocation. This half is easy to leave out and is
    not optional: minting placeholders while unable to persist the mapping
    writes markers into files that nothing can ever restore. Losing the shield
    for one invocation is recoverable; corrupting a file permanently is not.
  - The failure leaves a trace. A vault that quietly stops working looks exactly
    like a vault that is working.
"""
import base64
import hashlib
import json
import os
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.abspath(__file__))
# Overridable so the pre-fix hook can be run against this same suite; that is
# how each assertion below was shown to fail before it was made to pass.
HOOK = os.environ.get("REDMEM_HOOK_UNDER_TEST") or os.path.join(REPO, "hooks", "redact-restore.py")

# A synthetic, obviously-fake key in the shape the shield's ANTHROPIC_KEY
# pattern matches. It must never resolve against a real mapping — see the note
# at the top of test_placeholder_bake_relative.py for what happens when test
# fixtures are realistic enough to become live.
FAKE_SECRET = "sk-ant-api03-" + "A" * 80
VAULT_ENTRIES = 50


def _fernet(key_bytes):
    from cryptography.fernet import Fernet

    return Fernet(base64.urlsafe_b64encode(
        hashlib.sha256(key_bytes + b"mapping-encryption").digest()))


@pytest.fixture
def vault(tmp_path):
    """An isolated HOME holding a populated, ENCRYPTED mapping.

    Returns (env, home, read_entries) where read_entries() returns the number of
    placeholder entries currently on disk, or None if the file is no longer
    encrypted — which is itself the symptom.
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


def _blind_the_interpreter(env, tmp_path):
    """Make `import cryptography` fail in the child, exactly as a machine with a
    freshly-switched `python3` does — without needing such a machine."""
    shim = tmp_path / "shim" / "cryptography"
    shim.mkdir(parents=True)
    (shim / "__init__.py").write_text('raise ImportError("no cryptography here")\n')
    env = dict(env)
    env["PYTHONPATH"] = str(tmp_path / "shim") + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _read_event(path, cwd):
    return {"hook_event_name": "PreToolUse", "tool_name": "Read",
            "tool_input": {"file_path": str(path)}, "session_id": "vault-integrity",
            "cwd": str(cwd)}


def _run_hook(env, payload):
    return subprocess.run([sys.executable, HOOK], input=json.dumps(payload),
                          capture_output=True, text=True, env=env, timeout=30)


# ── The vault survives ─────────────────────────────────────────────────


def test_an_unreadable_vault_is_never_overwritten(vault, tmp_path):
    """The whole incident in one assertion."""
    env, _home, read_entries, _s2p = vault
    blind = _blind_the_interpreter(env, tmp_path)

    target = tmp_path / "config.yml"
    target.write_text(f'api_key: "{FAKE_SECRET}"\n')

    _run_hook(blind, _read_event(target, tmp_path))

    assert read_entries() == VAULT_ENTRIES, (
        "the mapping was replaced by an interpreter that could not read it — "
        "every placeholder already written into a file is now unresolvable"
    )


def test_redaction_stops_rather_than_minting_placeholders_it_cannot_persist(vault, tmp_path):
    """A placeholder written while the mapping cannot be saved is unrestorable
    forever. Passing the content through loses the shield once; writing an
    orphan marker corrupts the file permanently."""
    env, _home, _read, _s2p = vault
    blind = _blind_the_interpreter(env, tmp_path)

    target = tmp_path / "config.yml"
    original = f'api_key: "{FAKE_SECRET}"\n'
    target.write_text(original)

    _run_hook(blind, _read_event(target, tmp_path))

    assert target.read_text() == original, (
        "the file was redacted although the mapping could not be saved, so the "
        "placeholder it now contains can never be restored"
    )


def test_the_failure_is_recorded_where_someone_can_find_it(vault, tmp_path):
    """A vault that silently stops working is indistinguishable from one that
    works. The trace is the only thing that makes this class discoverable."""
    env, home, _read, _s2p = vault
    blind = _blind_the_interpreter(env, tmp_path)

    target = tmp_path / "config.yml"
    target.write_text(f'api_key: "{FAKE_SECRET}"\n')
    _run_hook(blind, _read_event(target, tmp_path))

    log = home / ".claude" / "vault" / "restore-errors.log"
    assert log.exists(), "no trace of a failure that destroyed data in the old code"
    kinds = [json.loads(line)["kind"] for line in log.read_text().splitlines() if line.strip()]
    assert "vault-unreadable" in kinds, f"expected a vault-unreadable record, got {kinds}"

    body = log.read_text()
    assert FAKE_SECRET not in body, "the failure log must record failures, never values"


def test_a_corrupt_mapping_is_also_left_alone(vault, tmp_path):
    """Same class, different cause: the file is garbage rather than the
    interpreter being blind. Neither may be mistaken for 'no mapping yet'."""
    env, home, _read, _s2p = vault
    mapping = home / ".claude" / ".redact-mapping.json"
    mapping.write_bytes(b"\x00\x01 not json, not fernet \xff")
    before = mapping.read_bytes()

    target = tmp_path / "config.yml"
    target.write_text(f'api_key: "{FAKE_SECRET}"\n')
    _run_hook(env, _read_event(target, tmp_path))

    assert mapping.read_bytes() == before, "an unparseable mapping was overwritten"


# ── Controls: the fix must not disable the shield in the normal case ───


def test_a_healthy_vault_still_redacts_and_still_grows(vault, tmp_path):
    """The guard keys off 'could not read', so a readable mapping must behave
    exactly as before. Without this, every assertion above passes for a shield
    that has simply been turned off."""
    env, _home, read_entries, read_secret_to_placeholder = vault

    target = tmp_path / "config.yml"
    target.write_text(f'api_key: "{FAKE_SECRET}"\n')

    _run_hook(env, _read_event(target, tmp_path))

    assert FAKE_SECRET not in target.read_text(), "the shield stopped redacting"
    # Not an exact count: one line can match several patterns and mint more than
    # one placeholder. What matters is that THIS secret round-trips.
    assert read_secret_to_placeholder().get(FAKE_SECRET), (
        "the new secret was not persisted, so the placeholder now in the file "
        "cannot be restored"
    )
    assert read_entries() > VAULT_ENTRIES, "the pre-existing entries were dropped"


def test_an_absent_mapping_is_still_created_normally(vault, tmp_path):
    """'Unreadable' must not swallow 'not there yet' — a first run on a clean
    machine has to be able to create the vault."""
    env, home, _read, _s2p = vault
    (home / ".claude" / ".redact-mapping.json").unlink()

    target = tmp_path / "config.yml"
    target.write_text(f'api_key: "{FAKE_SECRET}"\n')
    _run_hook(env, _read_event(target, tmp_path))

    assert (home / ".claude" / ".redact-mapping.json").exists(), (
        "a missing mapping was treated as unreadable, so the shield can never "
        "bootstrap itself"
    )
