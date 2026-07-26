#!/usr/bin/env python3
"""The installer must write an interpreter that can actually run the shield.

Why this exists
───────────────
On 2026-07-27 a 235-entry encrypted vault was destroyed twice in one session.
The cause was not in the hook logic: the machine's `python3` had moved to a
build without `cryptography`, so the shield could not decrypt its own mapping,
treated it as empty, and truncated it.

`install.sh` wrote the bare word `python3` into every hook command, which makes
that failure inevitable rather than unlucky, for a reason worth stating: hook
processes do not source your shell rc. A `python3` that resolves correctly when
you type it can resolve to something else entirely when Claude Code spawns the
hook — and an `alias python3=...` makes it worse, because an alias exists ONLY
in interactive shells. It hides the split instead of fixing it. That is exactly
how this went unnoticed.

So the installer now resolves an interpreter, proves it can import
`cryptography`, and writes its ABSOLUTE path. These tests pin that, plus the
consequence that fell out of it: once the command string contains a
machine-specific path, anything that matched hook entries by exact string —
the installer's own de-duplication, and `uninstall.sh` — silently stops
matching. The full suite caught the uninstall half; this file pins the rest.
"""
import json
import os
import shutil
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.abspath(__file__))
INSTALL_SH = os.path.join(REPO, "install.sh")


def _settings(home):
    with open(os.path.join(home, ".claude", "settings.json"), encoding="utf-8") as fh:
        return json.load(fh)


def _hook_commands(settings):
    return [
        h.get("command", "")
        for _event, groups in (settings.get("hooks") or {}).items()
        for g in groups
        for h in g.get("hooks", [])
    ]


@pytest.fixture
def installed(tmp_path):
    """Run the real installer against a HOME that is entirely ours."""
    if not shutil.which("jq"):
        pytest.skip("install.sh requires jq")
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)

    def run():
        env = dict(os.environ)
        env["HOME"] = str(home)
        proc = subprocess.run(["bash", INSTALL_SH], capture_output=True, text=True,
                              env=env, timeout=300)
        assert proc.returncode == 0, f"install.sh failed:\n{proc.stdout[-3000:]}\n{proc.stderr[-2000:]}"
        return proc

    run()
    return home, run


def test_hook_commands_name_an_absolute_interpreter(installed):
    """A bare `python3` is resolved by whatever PATH the hook process inherits,
    which is not the PATH you tested with."""
    home, _ = installed
    commands = _hook_commands(_settings(home))
    assert commands, "installer wrote no hook commands at all"

    for cmd in commands:
        interpreter = cmd.split()[0]
        if not interpreter.endswith(".sh"):  # statusline is a shell script
            assert os.path.isabs(interpreter), (
                f"hook command starts with a PATH-resolved name: {cmd!r} — the "
                f"interpreter a hook gets is not the one you get in a terminal"
            )


def test_the_written_interpreter_can_decrypt_the_vault(installed):
    """An interpreter without `cryptography` installs fine and then protects
    nothing: it cannot read the mapping, so the shield disables itself."""
    home, _ = installed
    interpreters = {
        cmd.split()[0] for cmd in _hook_commands(_settings(home))
        if not cmd.split()[0].endswith(".sh")
    }
    assert interpreters, "no interpreter found in the installed hook commands"

    for interp in interpreters:
        proc = subprocess.run([interp, "-c", "import cryptography"],
                              capture_output=True, text=True, timeout=60)
        assert proc.returncode == 0, (
            f"{interp} cannot import cryptography — the installer accepted an "
            f"interpreter that cannot read the mapping it is meant to protect"
        )


def test_reinstalling_does_not_duplicate_hook_entries(installed):
    """The installer de-duplicates by matching existing entries. Once the
    command carries a machine-specific absolute path, exact-string matching
    stops finding anything and every re-install appends another copy."""
    home, run = installed
    before = {ev: len(groups) for ev, groups in _settings(home)["hooks"].items()}

    run()

    after = {ev: len(groups) for ev, groups in _settings(home)["hooks"].items()}
    assert after == before, f"re-install changed entry counts: {before} -> {after}"


def test_entries_written_by_an_older_version_are_replaced_not_kept(installed):
    """The form this repo used to write. Leaving it behind means two dispatchers
    run for every tool call, and the stale one may point at a hook that no
    longer exists."""
    home, run = installed
    path = os.path.join(home, ".claude", "settings.json")
    settings = _settings(home)
    settings["hooks"]["PreToolUse"].append({
        "matcher": "Read",
        "hooks": [{"type": "command",
                   "command": "python3 ~/.claude/hooks/redmem_dispatcher.py",
                   "timeout": 10}],
    })
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(settings, fh, indent=2)

    run()

    remaining = _hook_commands(_settings(home))
    assert not any(c.startswith("python3 ") for c in remaining), (
        f"a legacy bare-`python3` entry survived the install: {remaining}"
    )
    assert len(_settings(home)["hooks"]["PreToolUse"]) == 1
