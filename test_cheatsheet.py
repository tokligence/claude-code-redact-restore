#!/usr/bin/env python3
"""
Tests for the post-compact cheatsheet flag + injection.

The flow is:
  PreCompact (handled by dispatcher)
    -> cheatsheet.mark_compact_pending(session_id)        # writes flag
  Next UserPromptSubmit
    -> cheatsheet.consume_compact_pending(session_id)     # deletes flag
    -> dispatcher adds cheatsheet_text() to additionalContext

These tests cover the flag side; the dispatcher integration is verified
by an end-to-end stdin test at the bottom.
"""
import json
import os
import subprocess
import sys

import pytest

HOOKS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hooks")
sys.path.insert(0, HOOKS_DIR)

from cheatsheet import (  # noqa: E402
    cheatsheet_text,
    consume_compact_pending,
    mark_compact_pending,
)
import cheatsheet as cs  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_state_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("REDMEM_CHEATSHEET_DIR", str(tmp_path / "flags"))
    return tmp_path / "flags"


def test_mark_then_consume_returns_true(isolated_state_dir):
    assert mark_compact_pending("s1") is True
    assert consume_compact_pending("s1") is True


def test_consume_is_one_shot(isolated_state_dir):
    mark_compact_pending("s2")
    assert consume_compact_pending("s2") is True
    assert consume_compact_pending("s2") is False  # already consumed


def test_consume_without_mark_returns_false(isolated_state_dir):
    assert consume_compact_pending("never-marked") is False


def test_flag_is_per_session(isolated_state_dir):
    mark_compact_pending("sessionA")
    assert consume_compact_pending("sessionB") is False
    assert consume_compact_pending("sessionA") is True


def test_empty_session_id_is_noop(isolated_state_dir):
    assert mark_compact_pending("") is False
    assert consume_compact_pending("") is False


def test_cheatsheet_text_mentions_key_tools():
    text = cheatsheet_text()
    # Spot-check the three things CC most needs to know about
    assert "redmem-original" in text
    assert "{{NAME_hash}}" in text
    assert ".autopilot/" in text
    assert "AUTOPILOT_DONE" in text


# ── End-to-end through the real dispatcher ────────────────────────────


def _run_dispatcher(payload_dict):
    """Invoke redmem_dispatcher.py with the payload on stdin; return its
    parsed stdout JSON (or {} if empty)."""
    script = os.path.join(HOOKS_DIR, "redmem_dispatcher.py")
    r = subprocess.run(
        [sys.executable, script],
        input=json.dumps(payload_dict),
        capture_output=True, text=True, timeout=15,
    )
    out = r.stdout.strip()
    if not out:
        return {}
    return json.loads(out)


def test_e2e_precompact_then_userprompt_injects_cheatsheet(tmp_path, monkeypatch):
    """PreCompact writes flag; the very next UserPromptSubmit
    additionalContext must contain the cheatsheet text."""
    monkeypatch.setenv("REDMEM_CHEATSHEET_DIR", str(tmp_path / "flags"))

    # Step 1: PreCompact — dispatcher writes the flag (its memory ingest
    # may also fire and emit warnings to stderr, that's fine).
    pre = _run_dispatcher({
        "hook_event_name": "PreCompact",
        "session_id": "e2e-cs",
        "cwd": str(tmp_path),
    })
    # PreCompact doesn't return JSON on stdout — empty is normal.
    assert pre == {}
    assert (tmp_path / "flags" / "e2e-cs.flag").is_file(), (
        "PreCompact should have written the flag"
    )

    # Step 2: Next UserPromptSubmit — dispatcher should consume the flag
    # and inject the cheatsheet.
    resp = _run_dispatcher({
        "hook_event_name": "UserPromptSubmit",
        "session_id": "e2e-cs",
        "cwd": str(tmp_path),
        "prompt": "hello after compact",
    })
    ctx = resp.get("hookSpecificOutput", {}).get("additionalContext", "")
    assert "redmem-original" in ctx, (
        f"Expected cheatsheet in additionalContext; got: {ctx[:200]!r}"
    )
    # Flag must now be gone (one-shot).
    assert not (tmp_path / "flags" / "e2e-cs.flag").is_file()


def test_e2e_userprompt_without_pending_flag_omits_cheatsheet(tmp_path, monkeypatch):
    """Normal UserPromptSubmit (no preceding compact) should not include
    the cheatsheet."""
    monkeypatch.setenv("REDMEM_CHEATSHEET_DIR", str(tmp_path / "flags"))
    resp = _run_dispatcher({
        "hook_event_name": "UserPromptSubmit",
        "session_id": "no-compact",
        "cwd": str(tmp_path),
        "prompt": "regular hello",
    })
    ctx = resp.get("hookSpecificOutput", {}).get("additionalContext", "") or ""
    assert "redmem-original" not in ctx
