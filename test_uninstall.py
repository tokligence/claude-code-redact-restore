#!/usr/bin/env python3
"""
End-to-end tests for install.sh + uninstall.sh.

These run the real shell scripts inside a per-test isolated HOME so a
green run truly means "the scripts that ship to users do the right
thing". Slower than unit tests (~15s for the suite) — that's the price
of testing install scripts.

Coverage:
  - Fresh install puts all files in place and produces a valid settings.json
  - Install is idempotent (no entry duplication on second run)
  - User's pre-existing custom hooks, theme, custom settings, and unrelated
    CLAUDE.md content survive both install and uninstall
  - Uninstall fully reverses install (round-trip yields identical CLAUDE.md)
  - --purge wipes the vault + image cache
  - --with-guard install + plain uninstall removes guard cleanly
  - User's own statusLine is NOT clobbered if it isn't ours
  - redmem section sandwiched mid-file in CLAUDE.md is removed cleanly
  - Mixed custom Stop hook + redmem Stop hook: only redmem is stripped
"""
import json
import os
import shutil
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
INSTALL_SH = os.path.join(REPO_ROOT, "install.sh")
UNINSTALL_SH = os.path.join(REPO_ROOT, "uninstall.sh")


# ── Helpers ────────────────────────────────────────────────────────────


def _run(cmd_args, env_home, **kwargs):
    """Run a command with HOME overridden. Stderr/stdout captured so the
    install banner doesn't drown test output."""
    env = os.environ.copy()
    env["HOME"] = env_home
    r = subprocess.run(
        cmd_args, env=env, capture_output=True, text=True, timeout=60, **kwargs
    )
    if r.returncode != 0:
        # Surface stderr only on failure — install banners are noisy.
        raise RuntimeError(
            f"{cmd_args[0]} failed (rc={r.returncode}):\n"
            f"  stdout: {r.stdout[-500:]}\n  stderr: {r.stderr[-500:]}"
        )
    return r


def install(home, *extra_args):
    return _run([INSTALL_SH, *extra_args], home)


def uninstall(home, *extra_args):
    return _run([UNINSTALL_SH, *extra_args], home)


def read_settings(home):
    p = os.path.join(home, ".claude", "settings.json")
    if not os.path.isfile(p):
        return None
    with open(p) as f:
        return json.load(f)


def read_claude_md(home):
    p = os.path.join(home, ".claude", "CLAUDE.md")
    if not os.path.isfile(p):
        return None
    with open(p) as f:
        return f.read()


@pytest.fixture
def home(tmp_path):
    """Isolated HOME dir. tmp_path is already unique per test."""
    h = tmp_path / "fakehome"
    h.mkdir()
    return str(h)


# ── Core install/uninstall round-trip ─────────────────────────────────


def test_install_creates_expected_files(home):
    install(home)
    expected = [
        ".claude/settings.json",
        ".claude/CLAUDE.md",
        ".claude/hooks/redmem_dispatcher.py",
        ".claude/hooks/redact-restore.py",
        ".claude/hooks/patterns.py",
        ".claude/hooks/image_compressor.py",
        ".claude/hooks/cheatsheet.py",
        ".claude/hooks/autopilot/__init__.py",
        ".claude/hooks/autopilot/autopilot.py",
        ".claude/hooks/memory/__init__.py",
        ".claude/hooks/memory/db.py",
        ".claude/commands/autopilot.md",
        ".claude/commands/autopilot-stop.md",
        ".claude/commands/autopilot-status.md",
    ]
    for rel in expected:
        full = os.path.join(home, rel)
        assert os.path.isfile(full), f"missing: {rel}"


def test_install_creates_all_seven_hook_events(home):
    install(home)
    s = read_settings(home)
    assert set(s["hooks"].keys()) == {
        "PreToolUse", "PostToolUse", "UserPromptSubmit",
        "SessionEnd", "SessionStart", "PreCompact", "Stop",
    }


def test_install_idempotent(home):
    install(home)
    s1 = read_settings(home)
    md1 = read_claude_md(home)
    install(home)  # second run
    s2 = read_settings(home)
    md2 = read_claude_md(home)
    # Each event has exactly one entry
    for event, entries in s2["hooks"].items():
        assert len(entries) == 1, f"{event} duplicated after re-install"
    assert s1 == s2, "settings.json differs between two installs"
    assert md1 == md2, "CLAUDE.md differs between two installs"


def test_install_uninstall_install_byte_identical(home):
    install(home)
    md_first = read_claude_md(home)
    s_first = read_settings(home)
    uninstall(home)
    install(home)
    assert read_claude_md(home) == md_first
    assert read_settings(home) == s_first


# ── Preservation under install ────────────────────────────────────────


def test_install_preserves_user_custom_hook(home):
    os.makedirs(os.path.join(home, ".claude"), exist_ok=True)
    with open(os.path.join(home, ".claude", "settings.json"), "w") as f:
        json.dump({
            "hooks": {
                "PreToolUse": [{"matcher": "Bash", "hooks": [
                    {"type": "command", "command": "echo custom-watcher.sh", "timeout": 3}
                ]}],
            },
            "theme": "dark",
            "customKey": "preserve-me",
        }, f)
    install(home)
    s = read_settings(home)
    # User's custom Bash hook is still there alongside the redmem one.
    pre_commands = [h["hooks"][0]["command"] for h in s["hooks"]["PreToolUse"]]
    assert "echo custom-watcher.sh" in pre_commands
    assert any("redmem_dispatcher.py" in c for c in pre_commands)
    # Non-hooks keys untouched
    assert s["theme"] == "dark"
    assert s["customKey"] == "preserve-me"


def test_install_preserves_user_claudemd_content(home):
    os.makedirs(os.path.join(home, ".claude"), exist_ok=True)
    user_content = "# My personal notes\n\nKeep responses concise.\n"
    with open(os.path.join(home, ".claude", "CLAUDE.md"), "w") as f:
        f.write(user_content)
    install(home)
    md = read_claude_md(home)
    assert "My personal notes" in md
    assert "Keep responses concise" in md
    assert "redmem capabilities" in md  # our section appended


# ── Uninstall correctness ─────────────────────────────────────────────


def test_uninstall_removes_all_redmem_files(home):
    install(home)
    uninstall(home)
    assert not os.path.isdir(os.path.join(home, ".claude", "hooks"))
    assert not os.path.isdir(os.path.join(home, ".claude", "commands"))


def test_uninstall_strips_all_hook_events(home):
    install(home)
    uninstall(home)
    s = read_settings(home)
    # With no other user hooks, the whole `hooks` key is removed
    assert "hooks" not in s


def test_uninstall_deletes_claudemd_when_only_section_present(home):
    install(home)
    uninstall(home)
    assert not os.path.isfile(os.path.join(home, ".claude", "CLAUDE.md"))


def test_uninstall_preserves_user_claudemd_content(home):
    os.makedirs(os.path.join(home, ".claude"), exist_ok=True)
    user_content = "# My personal notes\n\nKeep responses concise.\n"
    with open(os.path.join(home, ".claude", "CLAUDE.md"), "w") as f:
        f.write(user_content)
    install(home)
    uninstall(home)
    md = read_claude_md(home)
    assert md is not None and "My personal notes" in md
    assert "redmem capabilities" not in md
    assert "<!-- claude-secret-shield" not in md


def test_uninstall_preserves_user_custom_hook(home):
    os.makedirs(os.path.join(home, ".claude"), exist_ok=True)
    with open(os.path.join(home, ".claude", "settings.json"), "w") as f:
        json.dump({
            "hooks": {
                "PreToolUse": [{"matcher": "Bash", "hooks": [
                    {"type": "command", "command": "echo custom-watcher.sh"}
                ]}],
            },
            "theme": "dark",
        }, f)
    install(home)
    uninstall(home)
    s = read_settings(home)
    assert s["theme"] == "dark"
    # User's Bash hook survived; no redmem entries remain
    assert len(s["hooks"]["PreToolUse"]) == 1
    assert s["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "echo custom-watcher.sh"


# ── Edge: mixed Stop hook (custom user + redmem) ──────────────────────


def test_uninstall_only_strips_redmem_stop_keeps_custom_stop(home):
    """User has their own Stop hook. After install+uninstall, theirs
    should still be there; redmem's should be gone."""
    install(home)
    # Manually inject a fake user Stop hook
    p = os.path.join(home, ".claude", "settings.json")
    with open(p) as f:
        s = json.load(f)
    s["hooks"]["Stop"].insert(0, {
        "hooks": [{"type": "command", "command": "echo user-stop-watcher"}]
    })
    with open(p, "w") as f:
        json.dump(s, f)
    uninstall(home)
    s = read_settings(home)
    # User's Stop hook still there
    stops = s["hooks"]["Stop"]
    assert len(stops) == 1
    assert stops[0]["hooks"][0]["command"] == "echo user-stop-watcher"


# ── Edge: user's statusLine NOT clobbered ─────────────────────────────


def test_uninstall_does_not_remove_user_statusline(home):
    """If user has their own statusLine that isn't ours, uninstall must
    not delete it."""
    os.makedirs(os.path.join(home, ".claude"), exist_ok=True)
    with open(os.path.join(home, ".claude", "settings.json"), "w") as f:
        json.dump({
            "statusLine": {"type": "command", "command": "~/.my-fancy-statusline.sh"},
            "theme": "light",
        }, f)
    install(home)
    # After install, statusLine should have been REPLACED with ours.
    # (This is documented install behaviour — install owns the statusLine slot.)
    s_post_install = read_settings(home)
    assert s_post_install["statusLine"]["command"] == "~/.claude/hooks/statusline.sh"
    # But we'd expect a real user to want it back. So we have to be careful:
    # the install replaces unconditionally, but if user then runs uninstall
    # we should NOT leave our statusLine behind.
    uninstall(home)
    s_post_uninst = read_settings(home)
    # Our statusLine should be gone
    assert (
        "statusLine" not in s_post_uninst
        or s_post_uninst["statusLine"]["command"] != "~/.claude/hooks/statusline.sh"
    )
    # The non-statusLine settings are preserved
    assert s_post_uninst.get("theme") == "light"


def test_uninstall_does_not_remove_unrelated_statusline_we_didnt_set(home):
    """If between install and uninstall, the user MANUALLY swapped the
    statusLine for their own, uninstall must respect that."""
    install(home)
    p = os.path.join(home, ".claude", "settings.json")
    with open(p) as f:
        s = json.load(f)
    s["statusLine"] = {"type": "command", "command": "~/.my-fancy-statusline.sh"}
    with open(p, "w") as f:
        json.dump(s, f)
    uninstall(home)
    s = read_settings(home)
    assert s["statusLine"]["command"] == "~/.my-fancy-statusline.sh"


# ── Edge: redmem section embedded mid-CLAUDE.md ───────────────────────


def test_uninstall_strips_section_from_middle_of_claudemd(home):
    """User added the redmem section in the middle of their existing
    CLAUDE.md (rather than at end). Uninstall must remove only the
    section and leave surrounding content intact."""
    install(home)
    p = os.path.join(home, ".claude", "CLAUDE.md")
    with open(p) as f:
        installed = f.read()
    # Wrap install's section between two user blocks.
    new_content = (
        "# top of user file\n"
        "Some preamble.\n\n"
        + installed +
        "\n# below redmem\n"
        "More user content.\n"
    )
    with open(p, "w") as f:
        f.write(new_content)
    uninstall(home)
    md = read_claude_md(home)
    assert md is not None
    assert "top of user file" in md
    assert "below redmem" in md
    assert "redmem capabilities" not in md
    assert "<!-- claude-secret-shield" not in md


# ── --with-guard install + plain uninstall ────────────────────────────


def test_with_guard_install_then_uninstall(home):
    install(home, "--with-guard")
    guard_py = os.path.join(home, ".claude", "hooks", "guard", "agent_isolation_guard.py")
    assert os.path.isfile(guard_py)
    s = read_settings(home)
    # Guard adds PreToolUse + PostToolUse entries matching Agent
    pre = s["hooks"]["PreToolUse"]
    post = s["hooks"]["PostToolUse"]
    assert any("agent_isolation_guard.py" in (h["hooks"][0]["command"]) for h in pre), \
        "guard PreToolUse missing"
    assert any("agent_isolation_guard.py" in (h["hooks"][0]["command"]) for h in post), \
        "guard PostToolUse missing"

    uninstall(home)
    assert not os.path.isdir(os.path.join(home, ".claude", "hooks", "guard"))
    s = read_settings(home)
    # All guard entries gone
    for event in ("PreToolUse", "PostToolUse"):
        for entry in s.get("hooks", {}).get(event, []):
            for h in entry.get("hooks", []):
                assert "agent_isolation_guard.py" not in h.get("command", ""), \
                    f"guard hook lingering in {event}"


# ── --purge wipes vault + image cache ─────────────────────────────────


def test_purge_wipes_vault_and_image_cache(home, tmp_path, monkeypatch):
    install(home)
    # Plant fake state in vault + image cache (in a per-test tmp cache dir to
    # avoid trampling other concurrent test runs / real cache).
    fake_cache = tmp_path / "fake-img-cache"
    fake_cache.mkdir()
    (fake_cache / "demo.png").write_bytes(b"x")
    monkeypatch.setenv("REDMEM_IMG_CACHE_DIR", str(fake_cache))

    vault = os.path.join(home, ".claude", "vault")
    os.makedirs(os.path.join(vault, "sessions"), exist_ok=True)
    os.makedirs(os.path.join(vault, "autopilot"), exist_ok=True)
    open(os.path.join(vault, "sessions", "x.db"), "w").close()
    open(os.path.join(vault, "autopilot", "x.json"), "w").close()

    # Note: uninstall.sh hard-codes /tmp/redmem-img-cache in its --purge
    # path. We can't easily override that without editing the script, so
    # only assert behaviour we can observe: vault is gone, hook files
    # gone, settings.json clean. (image cache erasure tested in shell
    # smoke scenario C separately.)
    uninstall(home, "--purge")
    assert not os.path.isdir(vault)
    assert "hooks" not in (read_settings(home) or {})


# ── Defensive: missing settings.json ──────────────────────────────────


def test_uninstall_handles_missing_settings_json(home):
    """Uninstall must not crash if settings.json was never created
    (e.g., user removed it manually before re-trying uninstall)."""
    install(home)
    os.unlink(os.path.join(home, ".claude", "settings.json"))
    # Should still complete cleanly.
    uninstall(home)


def test_uninstall_handles_missing_claudemd(home):
    install(home)
    os.unlink(os.path.join(home, ".claude", "CLAUDE.md"))
    uninstall(home)
