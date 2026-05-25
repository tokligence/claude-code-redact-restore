#!/usr/bin/env python3
"""
git_guard — always-on PreToolUse(Bash) deny for `git add` with the
stage-everything flags (`-A`, `--all`, `.`).

Why
───
Claude Code's `permissions.deny` in settings.json catches simple prefix
forms (e.g. `Bash(git add -A:*)`). But the harness matcher does NOT see
inside chained Bash commands:

    cd repo && git add -A
    git status; git add -A; git commit
    (cd subdir && git add --all)

This hook scans the **entire** Bash command string and denies on any
substring match, closing that gap. Distinct from:

  - `autopilot/bash_guard`: only active during /autopilot, blocks a
    broader destructive set (rm -rf, git reset --hard, …).
  - `secret_ops_guard`:    for cloud secret-manager ops (KMS / SSM).

Why is `git add -A` worth blocking globally?
  - Stages every change including secrets, build artefacts, and
    unrelated WIP — defeats the whole `git diff --staged` review step.
  - On long autopilot runs it's the most common way Claude silently
    drags noise into a commit.

Patterns matched (case sensitive — `-A` not `-a`):
  - `git add -A`              (any position in a flag combo, e.g. -Av)
  - `git add --all`
  - `git add .`               (standalone dot; `./foo` is NOT matched)
  - The above embedded in chained / subshell commands

Override (one-shot escape hatch for rare legit use):
  REDMEM_ALLOW_GIT_ADD_ALL=1 claude        # whole-session
  REDMEM_ALLOW_GIT_ADD_ALL=1 <single cmd>  # one command (env inherits)

Fail-open on any internal error: a hook bug must never deny a safe
command. Logs single-line to stderr with the `[redmem-gitguard]` prefix.
"""
from __future__ import annotations

import json
import os
import re
import sys

LOG_PREFIX = "[redmem-gitguard]"
OPT_OUT_ENV = "REDMEM_ALLOW_GIT_ADD_ALL"

# Single regex covering all three forms. Key invariants:
#   - `\bgit\s+add\b` anchors to the literal command.
#   - `[^&;|<>\n]*?` matches any non-chain-operator characters between
#     `add` and the trigger flag (non-greedy, so we stop at the first
#     trigger), letting us catch `git add file.py -A` where the flag
#     comes after a path.
#   - The trigger alternatives:
#       * `-[a-zA-Z]*A[a-zA-Z]*\b` — any short-flag combo containing
#         literal uppercase `A`: `-A`, `-Av`, `-vA`, `-vAv` all match.
#         Case-sensitive on the A — `-a` (lowercase, not a real git-add
#         flag) is intentionally not matched.
#       * `--all\b` — the long form.
#       * `\s\.(?=\s|$|;|&)` — standalone `.` argument; the lookahead
#         requires the dot to be followed by whitespace, end-of-string,
#         `;`, or `&` so `./path` (dot-slash) is correctly excluded.
GIT_ADD_ALL_RE = re.compile(
    r"\bgit\s+add\b[^&;|<>\n]*?"
    r"(?:-[a-zA-Z]*A[a-zA-Z]*\b|--all\b|\s\.(?=\s|$|;|&))"
)


def _log(msg: str) -> None:
    try:
        sys.stderr.write(f"{LOG_PREFIX} {msg}\n")
    except Exception:
        pass


def check_git_add(data: dict) -> dict | None:
    """
    Returns a deny response dict if the Bash command stages everything,
    else None. Fail-open on any exception.
    """
    try:
        if data.get("tool_name") != "Bash":
            return None
        if os.environ.get(OPT_OUT_ENV):
            return None
        tool_input = data.get("tool_input") or {}
        if not isinstance(tool_input, dict):
            return None
        command = (tool_input.get("command") or "").strip()
        if not command:
            return None
        m = GIT_ADD_ALL_RE.search(command)
        if not m:
            return None
        matched = m.group().strip()
        _log(f"deny — matched {matched!r} in: {command[:120]!r}")
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    f"[redmem-gitguard] `git add -A` / `git add --all` / "
                    f"`git add .` is denied (matched `{matched}` in this "
                    f"command). Bulk-staging drags in secrets, build "
                    f"artefacts, and unrelated WIP — list files explicitly:\n"
                    f"  git add path/to/file.py [more files…]\n"
                    f"or use `git add -u` to stage only TRACKED changes (no "
                    f"new files). One-shot override: prefix your command "
                    f"with `{OPT_OUT_ENV}=1`."
                ),
            }
        }
    except Exception as e:
        _log(f"unexpected error: {e.__class__.__name__}: {e}")
        return None


# Standalone CLI for direct settings.json wiring (one hook entry, no
# dispatcher dependency). Reads PreToolUse stdin, prints deny JSON or
# exits 0 silently for pass-through.
if __name__ == "__main__":
    try:
        raw = sys.stdin.read()
        data = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        sys.exit(0)
    resp = check_git_add(data)
    if resp:
        sys.stdout.write(json.dumps(resp))
    sys.exit(0)
