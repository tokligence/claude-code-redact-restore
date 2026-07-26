#!/usr/bin/env python3
"""End-to-end tests for the deploy-config guard, driven through the real
`redmem_dispatcher.py` process — stdin JSON in, stdout JSON out.

Why these exist separately from `test_deploy_config_guard.py`
────────────────────────────────────────────────────────────
That suite tests `check_deploy_config()` in isolation. It passes whether or
not the function is ever *called*: a guard can be perfectly correct and
completely dead, because the wiring lives somewhere the unit tests do not
look — the dispatcher's routing chain, and the `matcher` in install.sh.

This session produced three separate instances of exactly that shape (a
frontend reading a field the backend never sends, an admin page PATCHing a
payload the backend had required extra fields for since months earlier, a
kill switch whose money gate read a cache instead of the database). So the
wiring gets its own tests.

Two things are asserted here that the unit suite cannot see:
  1. the guard is reached at all for Edit/Write through the real entry point;
  2. it does not swallow the events other handlers own — the dispatcher
     returns on the FIRST handler that produces a response, so a new
     handler inserted in the wrong position silently disables the ones
     after it.
"""
import json
import os
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.abspath(__file__))
DISPATCHER = os.path.join(REPO, "hooks", "redmem_dispatcher.py")
INSTALL_SH = os.path.join(REPO, "install.sh")


def _run(payload: dict, env_extra: dict | None = None):
    # These payloads go through the REAL dispatcher with the REAL environment,
    # so the secret shield runs with the developer's real mapping. A Read
    # PreToolUse redacts its target on disk and relies on the matching
    # PostToolUse to put it back — which a test that only sends PreToolUse
    # never delivers. Aiming that at a file in this repo rewrites the working
    # tree: two tests here used to pass `REPO/README.md`, and every full-suite
    # run silently replaced the example DSN in the published README with a
    # `{{POSTGRES_URL_...}}` placeholder, staged and ready to commit.
    # Hook payloads must therefore name throwaway paths, never repo files.
    target = (payload.get("tool_input") or {}).get("file_path")
    if target and os.path.abspath(target).startswith(REPO + os.sep):
        raise AssertionError(
            f"hook payload targets a file inside the repo: {target}\n"
            "Use tmp_path — the real shield will rewrite it on disk."
        )
    env = dict(os.environ)
    env.pop("REDMEM_ALLOW_DEPLOY_CONFIG", None)
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        [sys.executable, DISPATCHER],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    out = proc.stdout.strip()
    parsed = None
    if out:
        try:
            parsed = json.loads(out)
        except json.JSONDecodeError:
            parsed = None
    return proc, parsed


def _edit(path):
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_input": {"file_path": path, "old_string": "a", "new_string": "b"},
        "session_id": "test-deployguard-e2e",
        "cwd": REPO,
    }


# ── The guard is actually reached ──────────────────────────────────────


def test_editing_a_deploy_config_asks_through_the_real_dispatcher():
    proc, parsed = _run(_edit("/repo/next.config.js"))
    assert proc.returncode == 0
    assert parsed is not None, f"no JSON on stdout; stderr={proc.stderr[:400]}"
    hso = parsed["hookSpecificOutput"]
    assert hso["permissionDecision"] == "ask"
    assert "next.config.js" in hso["permissionDecisionReason"]


def test_writing_a_dockerfile_asks_through_the_real_dispatcher():
    proc, parsed = _run(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"file_path": "/repo/Dockerfile", "content": "FROM scratch"},
            "session_id": "test-deployguard-e2e",
            "cwd": REPO,
        }
    )
    assert parsed is not None
    assert parsed["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_ordinary_source_edit_is_not_intercepted(tmp_path):
    """The guard must be invisible on the overwhelming majority of edits."""
    ordinary = tmp_path / "README.md"
    ordinary.write_text("# ordinary source file\n")
    proc, parsed = _run(_edit(str(ordinary)))
    assert proc.returncode == 0
    if parsed is not None:
        # Another handler (e.g. the shield) may legitimately respond; what
        # must never appear is OUR ask.
        reason = json.dumps(parsed)
        assert "deployguard" not in reason


def test_opt_out_env_reaches_the_hook_process():
    """The override is documented to work as a per-command env prefix, which
    only holds if the child process inherits it."""
    _, parsed = _run(_edit("/repo/Dockerfile"), env_extra={"REDMEM_ALLOW_DEPLOY_CONFIG": "1"})
    if parsed is not None:
        assert "deployguard" not in json.dumps(parsed)


# ── It does not disable the handlers that run after it ─────────────────


def test_bash_events_are_untouched_by_the_new_handler():
    """The guard sits in the PreToolUse chain ahead of other handlers. A Bash
    event must fall straight through it — if this regresses, the autopilot
    bash guard and the shield stop seeing Bash at all."""
    proc, parsed = _run(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "echo hello"},
            "session_id": "test-deployguard-e2e",
            "cwd": REPO,
        }
    )
    assert proc.returncode == 0
    if parsed is not None:
        assert "deployguard" not in json.dumps(parsed)


def test_git_add_all_is_still_denied_after_the_new_handler_was_inserted():
    """The most concrete regression check available: an existing always-on
    guard whose response must still reach stdout."""
    proc, parsed = _run(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git add -A"},
            "session_id": "test-deployguard-e2e",
            "cwd": REPO,
        }
    )
    assert parsed is not None, f"git_guard produced no response; stderr={proc.stderr[:400]}"
    assert parsed["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "gitguard" in parsed["hookSpecificOutput"]["permissionDecisionReason"]


def test_read_events_still_reach_the_image_compressor_path(tmp_path):
    """A Read must not be intercepted by a guard that only cares about writes."""
    ordinary = tmp_path / "README.md"
    ordinary.write_text("# ordinary source file\n")
    proc, parsed = _run(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": str(ordinary)},
            "session_id": "test-deployguard-e2e",
            "cwd": REPO,
        }
    )
    assert proc.returncode == 0
    if parsed is not None:
        assert "deployguard" not in json.dumps(parsed)


# ── The installed matcher actually routes the tools the guard claims ────


def test_installer_matcher_routes_every_tool_the_guard_watches():
    """A guard is only as real as the matcher that routes events to it.

    `check_deploy_config` accepts MultiEdit and NotebookEdit, but if
    install.sh's PreToolUse matcher does not list them, those branches are
    unreachable in a real installation and only the unit tests would ever
    exercise them. This test forces the two to agree — change one and it
    fails until the other follows.
    """
    sys.path.insert(0, os.path.join(REPO, "hooks"))
    from deploy_config_guard import WATCHED_TOOLS

    with open(INSTALL_SH, encoding="utf-8") as fh:
        installer = fh.read()

    line = next(
        (ln for ln in installer.splitlines() if ln.startswith("DISPATCH_PRE=")),
        None,
    )
    assert line is not None, "install.sh no longer defines DISPATCH_PRE"

    routed = set()
    start = line.find('"matcher":"')
    if start != -1:
        start += len('"matcher":"')
        routed = set(line[start : line.find('"', start)].split("|"))

    unreachable = WATCHED_TOOLS - routed
    assert not unreachable, (
        f"deploy_config_guard watches {sorted(unreachable)}, but install.sh's "
        f"PreToolUse matcher only routes {sorted(routed)} — those branches are "
        f"dead in a real installation. Either add them to the matcher or drop "
        f"them from WATCHED_TOOLS."
    )
