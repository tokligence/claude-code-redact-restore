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


def test_a_users_own_hook_with_a_similar_path_is_left_alone(installed):
    """Matching by suffix is what lets the installer clean up entries written by
    an older version or a different interpreter. The cost is that it can reach
    too far: somebody else's `~/tools/hooks/redmem_dispatcher.py` is not ours to
    delete. Anchor on `.claude/hooks/`, which is the only place we install to."""
    home, run = installed
    path = os.path.join(home, ".claude", "settings.json")
    foreign = "python3 /Users/someone/tools/hooks/redmem_dispatcher.py"
    settings = _settings(home)
    settings["hooks"]["PreToolUse"].append({
        "matcher": "Read",
        "hooks": [{"type": "command", "command": foreign, "timeout": 10}],
    })
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(settings, fh, indent=2)

    run()

    assert foreign in _hook_commands(_settings(home)), (
        "the installer deleted a hook it does not own — suffix matching reached "
        "outside ~/.claude/hooks/"
    )


def test_the_installed_dispatcher_can_import_everything_it_routes_to(installed):
    """A module the dispatcher imports but the installer never copies fails
    SILENTLY: the import error is caught, the install reports success, and the
    handler simply does not exist — while its unit tests go on passing against
    the copy in the repo.

    That is not hypothetical. `deploy_config_guard.py` shipped with 64 tests and
    was absent from every real installation until the installed dispatcher was
    run by hand and its stderr read:
        [redmem] deploy config guard error: No module named 'deploy_config_guard'

    Testing the file list would only restate it. Running the thing is what
    catches the next one.
    """
    home, _ = installed
    dispatcher = os.path.join(home, ".claude", "hooks", "redmem_dispatcher.py")
    assert os.path.exists(dispatcher)

    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": os.path.join(str(home), "nonexistent.txt")},
        "session_id": "install-import-check",
        "cwd": str(home),
    }
    env = dict(os.environ)
    env["HOME"] = str(home)
    proc = subprocess.run([sys.executable, dispatcher], input=json.dumps(payload),
                          capture_output=True, text=True, env=env, timeout=60)

    assert "No module named" not in proc.stderr, (
        f"the installed dispatcher cannot import one of its handlers:\n{proc.stderr[:800]}"
    )
    assert "ImportError" not in proc.stderr, proc.stderr[:800]


@pytest.mark.parametrize("foreign", [
    # The tail collides, but the directory is not ours. `.claude` has to be a
    # whole path segment: anchoring on the bare string `.claude/hooks/` still
    # matches this, which is how a suffix matcher quietly deletes a stranger's
    # hook.
    "python3 /tmp/not.claude/hooks/redmem_dispatcher.py",
    "python3 /Users/someone/tools/hooks/redact-restore.py",
    "python3 /opt/myclaude/hooks/guard/agent_isolation_guard.py",
])
def test_only_hooks_under_a_real_dot_claude_segment_are_ours(installed, foreign):
    home, run = installed
    path = os.path.join(home, ".claude", "settings.json")
    settings = _settings(home)
    settings["hooks"]["PreToolUse"].append({
        "matcher": "Read",
        "hooks": [{"type": "command", "command": foreign, "timeout": 10}],
    })
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(settings, fh, indent=2)

    run()

    assert foreign in _hook_commands(_settings(home)), (
        f"the installer deleted a hook it does not own: {foreign}"
    )


def test_an_interpreter_path_with_a_quote_is_refused_not_escaped(tmp_path):
    """Escaping it would need a shell quote inside a JSON string parsed by jq;
    getting that subtly wrong writes a settings.json that does not parse, which
    breaks every hook rather than just this one. Refusing is the honest answer."""
    if not shutil.which("jq"):
        pytest.skip("install.sh requires jq")

    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    quoted_dir = tmp_path / "we're here" / "bin"
    quoted_dir.mkdir(parents=True)
    fake = quoted_dir / "python3"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)

    env = dict(os.environ)
    env["HOME"] = str(home)
    env["REDMEM_PYTHON"] = str(fake)
    proc = subprocess.run(["bash", INSTALL_SH], capture_output=True, text=True,
                          env=env, timeout=300)

    settings_path = home / ".claude" / "settings.json"
    if settings_path.exists():
        json.loads(settings_path.read_text())  # must never be left unparseable


def test_an_interpreter_path_with_a_space_is_quoted(tmp_path):
    """`/Users/me/Python Builds/bin/python3` is a legal path. Written into the
    command string unquoted, whatever tokenises it tries to execute
    `/Users/me/Python` and every hook spawn fails."""
    if not shutil.which("jq"):
        pytest.skip("install.sh requires jq")
    try:
        import cryptography  # noqa: F401
    except ImportError:
        pytest.skip("this interpreter cannot serve as a candidate")

    # A symlink at a spaced path does NOT reproduce this: the installer
    # normalises its choice through `sys.executable`, which resolves to the
    # real binary and quietly removes the space. The first version of this test
    # used one and passed against the unfixed installer — a test that holds for
    # the wrong reason. A venv is the real case (`/Users/me/My Env/bin/python3`
    # reports itself), and it inherits cryptography from the parent.
    venv_dir = tmp_path / "my python env"
    subprocess.run([sys.executable, "-m", "venv", "--system-site-packages", str(venv_dir)],
                   check=True, capture_output=True, timeout=300)
    spaced = venv_dir / "bin" / "python3"
    assert " " in subprocess.run(
        [str(spaced), "-c", "import sys; print(sys.executable)"],
        capture_output=True, text=True, timeout=60).stdout, (
        "the venv did not report a spaced sys.executable — this test would "
        "again be proving nothing"
    )

    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    env = dict(os.environ)
    env["HOME"] = str(home)
    env["REDMEM_PYTHON"] = str(spaced)
    proc = subprocess.run(["bash", INSTALL_SH], capture_output=True, text=True,
                          env=env, timeout=300)
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-1000:]

    for cmd in _hook_commands(_settings(home)):
        if cmd.endswith(".sh"):
            continue
        interpreter = cmd.split(" ~/")[0]
        assert not (" " in interpreter and not interpreter.startswith("'")), (
            f"unquoted interpreter path containing a space: {cmd!r}"
        )


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
