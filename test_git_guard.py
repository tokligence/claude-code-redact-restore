#!/usr/bin/env python3
"""Tests for hooks/git_guard.py — the always-on PreToolUse(Bash) deny
that catches `git add -A` / `git add --all` / `git add .` anywhere in
the command (including chained commands)."""
import json
import os
import subprocess
import sys

import pytest

HOOKS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hooks")
sys.path.insert(0, HOOKS_DIR)

from git_guard import check_git_add, OPT_OUT_ENV  # noqa: E402


def _payload(command, tool="Bash"):
    return {"tool_name": tool, "tool_input": {"command": command}}


# ── Cases that MUST be denied ──────────────────────────────────────────


@pytest.mark.parametrize("cmd", [
    "git add -A",
    "git add -A ",
    "git add -A .",
    "git add -A path/to/file",
    "git add --all",
    "git add --all ./src",
    "git add .",
    "git add . ",
    "git add  .",
    # Combined flags
    "git add -Av",
    "git add -vA",
    "git add -vAv",
    # Path-before-flag (git accepts flags in any position)
    "git add file.py -A",
    "git add foo.py bar.py --all",
    # Chained commands — the whole reason this guard exists
    "cd repo && git add -A",
    "cd repo && git add -A && git commit",
    "git status; git add -A; git commit -m 'x'",
    "git status && git add --all && git commit",
    "cd subdir && git add .",
    # Subshells
    "(cd repo && git add -A)",
    "(git add --all)",
    # Mixed with other safe commands
    "ls -la && git add -A",
])
def test_denies_git_add_all_forms(cmd):
    resp = check_git_add(_payload(cmd))
    assert resp is not None, f"should have denied: {cmd!r}"
    hso = resp["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"
    assert "gitguard" in hso["permissionDecisionReason"]


# ── Cases that MUST pass through ───────────────────────────────────────


@pytest.mark.parametrize("cmd", [
    # Explicit file paths (safe)
    "git add file.py",
    "git add src/foo.py src/bar.py",
    "git add README.md",
    # Dot-slash paths (NOT the `.` argument)
    "git add ./foo.py",
    "git add ./src/main.py",
    "git add ./relative/file",
    # Other git add modes
    "git add -p",                # interactive
    "git add -p file.py",
    "git add -u",                # tracked-only — explicitly allowed
    "git add -u file.py",
    "git add --update",
    "git add -i",                # interactive index
    "git add -n file.py",        # dry-run
    "git add --intent-to-add file.py",
    # Unrelated git commands
    "git status",
    "git commit -m 'feat: stuff'",
    "git diff",
    "git log --oneline",
    "git push origin main",
    # Unrelated commands entirely
    "ls -A",                     # ls -A is fine (not git add)
    "echo hi",
    "rm -rf /tmp/x",             # different concern, different guard
    "make all",                  # not git
    # Empty / no-op
    "",
])
def test_passes_safe_commands(cmd):
    assert check_git_add(_payload(cmd)) is None, f"should have passed: {cmd!r}"


# ── Tool gating ────────────────────────────────────────────────────────


def test_non_bash_tool_passes_through():
    """Even if a Read tool_input.command somehow says 'git add -A',
    we don't deny — we only guard Bash."""
    assert check_git_add({
        "tool_name": "Read",
        "tool_input": {"command": "git add -A"},
    }) is None


def test_empty_command_passes():
    assert check_git_add({"tool_name": "Bash", "tool_input": {}}) is None
    assert check_git_add({"tool_name": "Bash", "tool_input": {"command": ""}}) is None
    assert check_git_add({"tool_name": "Bash", "tool_input": {"command": "   "}}) is None


def test_malformed_input_doesnt_crash():
    # tool_input not a dict
    assert check_git_add({"tool_name": "Bash", "tool_input": None}) is None
    assert check_git_add({"tool_name": "Bash", "tool_input": "string"}) is None
    # Command not a string
    assert check_git_add({"tool_name": "Bash", "tool_input": {"command": None}}) is None


# ── Hint message content (must educate Claude about workarounds) ─────


def test_deny_hint_mentions_explicit_files_alternative():
    resp = check_git_add(_payload("git add -A"))
    reason = resp["hookSpecificOutput"]["permissionDecisionReason"]
    assert "git add path/to/file" in reason


def test_deny_hint_mentions_git_add_dash_u_alternative():
    resp = check_git_add(_payload("git add -A"))
    reason = resp["hookSpecificOutput"]["permissionDecisionReason"]
    assert "git add -u" in reason


def test_deny_hint_mentions_commit_F_file_workaround():
    """When the trigger appears incidentally (e.g. in a commit -m message),
    the user needs to know they can write the message to a file and use
    `git commit -F`. Without this hint Claude would loop trying variants."""
    resp = check_git_add(_payload("git add -A"))
    reason = resp["hookSpecificOutput"]["permissionDecisionReason"]
    assert "git commit -F" in reason
    assert "incidentally" in reason.lower() or "incidentally" in reason


def test_deny_hint_clarifies_env_var_must_be_set_before_claude():
    """The env-prefix override `REDMEM_ALLOW_GIT_ADD_ALL=1 cmd` does NOT
    work (hook reads CC parent env, not bash subprocess env). The hint
    must say so to prevent users from being misled."""
    resp = check_git_add(_payload("git add -A"))
    reason = resp["hookSpecificOutput"]["permissionDecisionReason"]
    assert OPT_OUT_ENV in reason
    assert "before launching claude" in reason.lower() or \
           "BEFORE launching claude" in reason
    # Should explicitly warn against the per-command prefix form
    assert "does NOT work" in reason or "does not work" in reason.lower()


# ── Override env var ───────────────────────────────────────────────────


def test_opt_out_env_var_disables_guard(monkeypatch):
    monkeypatch.setenv(OPT_OUT_ENV, "1")
    assert check_git_add(_payload("git add -A")) is None
    assert check_git_add(_payload("git add --all")) is None
    assert check_git_add(_payload("git add .")) is None


def test_opt_out_env_var_unset_re_enables(monkeypatch):
    monkeypatch.delenv(OPT_OUT_ENV, raising=False)
    assert check_git_add(_payload("git add -A")) is not None


# ── End-to-end stdin smoke through standalone CLI ─────────────────────


def _run_cli(payload_dict):
    script = os.path.join(HOOKS_DIR, "git_guard.py")
    r = subprocess.run(
        [sys.executable, script],
        input=json.dumps(payload_dict),
        capture_output=True, text=True, timeout=5,
    )
    return r.returncode, r.stdout.strip()


def test_cli_emits_deny_on_match():
    rc, out = _run_cli(_payload("cd foo && git add -A"))
    assert rc == 0
    assert out, "expected deny JSON on stdout"
    d = json.loads(out)
    assert d["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_cli_silent_on_safe_command():
    rc, out = _run_cli(_payload("git add file.py"))
    assert rc == 0
    assert out == "", f"expected empty stdout (pass-through), got: {out!r}"


def test_cli_silent_on_non_bash():
    rc, out = _run_cli(_payload("git add -A", tool="Read"))
    assert rc == 0
    assert out == ""


def test_cli_handles_bad_json():
    script = os.path.join(HOOKS_DIR, "git_guard.py")
    r = subprocess.run(
        [sys.executable, script],
        input="not json at all", capture_output=True, text=True, timeout=5,
    )
    assert r.returncode == 0
    assert r.stdout.strip() == ""
