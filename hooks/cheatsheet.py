#!/usr/bin/env python3
"""
redmem cheatsheet — re-inject a tools summary into Claude's context
immediately after an auto-compact, so it doesn't forget what's available.

Why
───
Claude Code's auto-compact compresses earlier turns into a lossy summary.
Anything the assistant learned mid-session about hooks/sentinels/tools
provided by redmem can disappear. CLAUDE.md is still loaded after
compact, but it covers Shield only — image-compressor's
`redmem-original` sentinel and autopilot's bash-guard rules are easy to
forget once the in-session demonstrations are summarised away.

How
───
There's no documented `PostCompact` hook. We use a portable two-step:

  1. `PreCompact` writes a flag file in the vault for this session.
  2. The next `UserPromptSubmit` checks the flag and, if present, adds a
     short cheatsheet to `hookSpecificOutput.additionalContext` and
     deletes the flag (one-shot).

This is "after compact" from Claude's perspective — the first turn it
takes post-compact sees the reminder. Cost: ~400 tokens, once per compact.

We deliberately frame the cheatsheet as **informational, not directive**:
the user's exact wording was "let CC know these tools exist, in case it
needs them — don't push it to use them now".
"""
from __future__ import annotations

import os
import sys

CHEATSHEET = """\
[redmem] Tools available in this session (auto-injected after compact)

You're running with the redmem plugin. The capabilities below are
informational — use them only when relevant, don't change your default
behaviour just because of this message.

**Image compressor.** Reading images >500KB and >1920px serves a
downscaled cache copy to save vision tokens. If you can't make out
small text or pixel-level UI detail in an image you just read, issue
this sentinel bash command:

    redmem-original /absolute/path/to/image.png

It is NOT a real program — a hook intercepts it, sets a one-shot
session-scoped flag, and denies the bash call. Your next
`Read /absolute/path/to/image.png` in this session will then serve the
uncompressed original.

**Secret shield.** Files with real secrets are presented to you with
values replaced by `{{NAME_hash}}` placeholders. Treat the placeholders
as the real values — the hook restores them when you write back. Never
ask the user to re-enter or reveal a real secret.

**Autopilot mode** (active only when `.autopilot/` exists in the repo
root). The following destructive bash patterns are denied while
autopilot is armed: `rm -rf`, `git reset --hard`, `git checkout -f`,
`git clean -fdx`, `git branch -D`, `git push --force`,
`DROP TABLE|DATABASE|SCHEMA|INDEX`, `TRUNCATE`. Use `mv` to
`~/.autopilot-trash/<timestamp>/`, `git stash`, or `git revert`
instead. Maintain `.autopilot/TASKS.md` (checkbox list), defer
unanswerable decisions to `.autopilot/QUESTIONS.md`, log spec
improvement ideas to `.autopilot/IMPROVE.md`. End by emitting
`[[AUTOPILOT_DONE]]` once you've done all you can.

**Session memory.** When the user says "remember", "before",
"earlier", "之前", "上次", "记得", an archive search of prior sessions
runs automatically and any relevant snippets get injected into your
context. You don't need to invoke this; it happens by itself.
"""

LOG_PREFIX = "[redmem-cheatsheet]"


def _log(msg: str) -> None:
    try:
        sys.stderr.write(f"{LOG_PREFIX} {msg}\n")
    except Exception:
        pass


def _vault_dir() -> str:
    override = os.environ.get("REDMEM_CHEATSHEET_DIR")
    if override:
        return override
    return os.path.expanduser("~/.claude/vault/cheatsheet")


def _flag_path(session_id: str) -> str:
    return os.path.join(_vault_dir(), f"{session_id}.flag")


def mark_compact_pending(session_id: str) -> bool:
    """Called from PreCompact: drop a flag so the next UserPromptSubmit
    in this session knows to inject the cheatsheet."""
    if not session_id:
        return False
    try:
        os.makedirs(_vault_dir(), exist_ok=True)
        with open(_flag_path(session_id), "w", encoding="utf-8") as f:
            f.write(session_id)
        return True
    except OSError as e:
        _log(f"mark failed: {e.__class__.__name__}")
        return False


def consume_compact_pending(session_id: str) -> bool:
    """One-shot: if the flag exists, delete it and return True."""
    if not session_id:
        return False
    p = _flag_path(session_id)
    if not os.path.isfile(p):
        return False
    try:
        os.unlink(p)
    except FileNotFoundError:
        return False
    except OSError:
        pass
    return True


def cheatsheet_text() -> str:
    return CHEATSHEET
