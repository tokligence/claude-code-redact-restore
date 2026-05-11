# redmem

**red**act + **mem**ory — industrial-grade Claude Code infrastructure.

Secret protection + persistent session memory in one plugin.

## The Problem

Claude Code has two fundamental gaps:

### Secrets Leak to the API

Claude Code's tools (Read, Edit, Bash) read files containing API keys, database
passwords, and private keys. Without protection, these flow to the API in plaintext.

### Context Gets Lost

When a long conversation triggers `/compact`, the system generates a lossy summary
and discards original turns. Three failure modes worsen over time:

1. **State amnesia** — Claude reports stale progress after compaction.
2. **Detail loss** — decisions, error messages, and workarounds discussed early
   in the session are permanently gone.
3. **Session ceiling** — sessions spanning days degrade as repeated compactions
   compound information loss.

## The Solution

One plugin, one dispatcher, two capabilities:

```
redmem_dispatcher.py
  |-- shield/  -- 205 regex patterns, 42 blocked files
  |             Redacts secrets before Claude sees them
  |             Restores real values when Claude writes
  |
  +-- memory/  -- SQLite FTS5, session state, auto-recall
                Archives full conversation before compact
                Restores context on resume
                Auto-searches history on recall keywords
```

**Why merged?** Shield and memory share hook events (UserPromptSubmit, PostToolUse).
As separate plugins, hook ordering is unreliable. One dispatcher guarantees shield
runs first (code-level if/return), memory runs second on safe data only.

## Relationship with Claude Code's Native Recap

As of Claude Code 2.1.108 (released 2026-04-14), Claude Code ships a **native
`※ recap:`** feature that auto-generates a summary when resuming sessions.
This is a server-side feature — all client versions receive it.

redmem **complements** the native recap, not competes with it:

| Capability | Native Recap | redmem |
|------------|--------------|--------|
| Summarize current session on resume | ✓ | ✓ (may overlap) |
| Early turns discarded by compact | ✗ | ✓ — FTS5 search over vault |
| Other sessions' related work | ✗ | ✓ — `knowledge.db` |
| "Remember when we discussed X" auto-search | ✗ | ✓ — UserPromptSubmit hook |
| Project-level knowledge across sessions | ✗ | ✓ |
| Full conversation archive (lossless) | ✗ | ✓ — SQLite FTS5 |
| Secret protection | ✗ | ✓ — shield layer |

**Short version:** native recap is "inside the session"; redmem is "outside the
session." They run in parallel without conflict — native recap displays via
`※ recap:` prefix, redmem injects via `additionalContext`.

No configuration needed. If you ever want to disable native recap:
`/config` in Claude Code.

## Features

### Secret Protection (Layer A)

- 205 regex patterns (AWS, OpenAI, Anthropic, GitHub, Stripe, database URLs,
  private keys, Web3 wallets, BIP39 mnemonics, ...)
- 42 blocked file patterns (.env, credentials.json, id_rsa, ...)
- Deterministic `{{NAME_hash}}` placeholders (HMAC-based, stable across sessions)
- Auto-restore on write/edit — Claude writes placeholders, disk gets real values
- User prompt scanning — blocks messages containing raw secrets
- Housekeeping files (`.tmp_secrets.*`) auto-registered in `.git/info/exclude`
  on first create — never leak into `git status` or `.gitignore`

### Tool-availability reminder (post-compact)

Claude Code's auto-compact compresses earlier turns into a lossy summary.
Mid-session demonstrations of redmem capabilities (the `redmem-original`
sentinel, autopilot's bash-guard rules, etc.) can disappear. redmem
re-injects a concise cheatsheet on the **first UserPromptSubmit after
each compact**:

- `PreCompact` writes a flag for the session.
- The next `UserPromptSubmit` consumes the flag and prepends a short
  capability summary to `hookSpecificOutput.additionalContext`.

Cost: ~400 tokens, once per compact. Phrasing is deliberately
informational ("here's what's available") rather than directive ("now
use this") — Claude doesn't change behaviour because of the reminder,
it just remembers the tools exist when relevant.

CLAUDE.md is also auto-extended at install time with the same tool
summary, so new/resumed sessions know what's available from the start.
(The reminder is for sessions that lose this knowledge mid-session via
compaction.)

### Session Memory (Layer B)

- **PreCompact archive** — full conversation saved to SQLite FTS5 before compaction
- **Resume restore** — session state + recent context injected on `--resume`
- **Auto-recall** — "remember", "before", "earlier", "\u4e4b\u524d" triggers automatic archive search
- **Session state** — structured Goal/Plan/Done/Blocked/Decisions file, auto-generated
- **Task tracking** — captures TaskCreate/TaskUpdate/Plan changes via PostToolUse hook
- **Full-text search** — BM25 ranking with porter stemmer + unicode support

### Image Compressor (always on)

Claude's vision API charges by image tile — a single 4K screenshot can
cost 6–12k tokens per Read. redmem transparently downscales large images
before they reach the API: a PreToolUse hook rewrites `tool_input.file_path`
to a cached, compressed copy (longest side ≤ 1920px, format preserved).

- **Scope** — all sessions, every Read of an image file. Not autopilot-gated.
- **Thresholds** — skips images < 500 KB OR with longest side < 1920 px.
- **Tool** — macOS-native `sips` (no Python deps). Falls back to original
  file on non-macOS systems or any error.
- **Cache** — `/tmp/redmem-img-cache/<sha1>-<mtime>.<ext>`. mtime in the
  filename auto-invalidates when you edit the source.
- **Transparent** — the original file on disk is untouched; only
  Claude's view gets the smaller copy.

**Opt out (three granularities):**

| Scope | How |
|-------|-----|
| Host-wide | `export REDMEM_NO_IMAGE_COMPRESS=1` |
| One project | `touch <repo>/.redmem-no-compress` |
| One image | name it `foo.orig.png` or `foo.nocompress.png` |

**Typical savings** (iPhone screenshot, 3024×4032, 2.5 MB): ~66% fewer
vision tokens per Read. Over an autopilot-style overnight run, that's
tens of thousands of tokens.

**When Claude needs pixel-level detail** — fully automatic, no renaming:

```
  1. Claude reads a big screenshot → sees the 1920px version.
  2. redmem appends a PostToolUse note telling Claude:
       "This image was downscaled 4032×3024 → 1920×1440.
        If you need fine detail, run `redmem-original /path/to/img.png`."
  3. Claude, if it can't make out small text, issues:
       Bash(redmem-original /path/to/img.png)
  4. A PreToolUse(Bash) hook intercepts that sentinel command, sets a
     session-scoped flag, and *denies* — no shell command actually runs.
  5. Claude re-issues `Read /path/to/img.png`. The hook sees the flag
     (one-shot, then cleared) and passes the uncompressed original
     through. Claude sees full resolution.
```

The sentinel `redmem-original` is **not a real program** on disk — it's
a signalling channel between Claude and the hook. You don't need to
install anything, and you don't need to rename files by hand.

### Guard (optional)

An opt-in third capability that prevents the most common footgun in
Claude Code parallel-agent workflows: the parent spawns multiple `Agent`
tool calls that touch the same git repo without `isolation: "worktree"`,
and the concurrent runs stomp on each other's uncommitted changes.

- **What it does** — When `PreToolUse(Agent)` fires, the guard checks
  whether another non-isolated Agent is already active in the same repo.
  If so, it denies the new call with a message telling you to pass
  `isolation: "worktree"` or wait. `PostToolUse(Agent)` clears the
  tracking entry.
- **Scope** — Ergonomics, not security. The guard fails open on any
  internal error (corrupt state, git missing, disk full) — it will
  never brick your workflow.
- **Enable** — `./install.sh --with-guard` (default install is unchanged).
- **Bypass a single call** — `touch ~/.claude/vault/.guard_bypass` before
  triggering the Agent call. The file is deleted the first time the
  guard would otherwise deny.
- **Disable entirely** — remove the two `guard/agent_isolation_guard.py`
  entries from `~/.claude/settings.json`, or re-run `./uninstall.sh`.

State file: `~/.claude/vault/active_agents.json`. Stale entries (older
than 45 minutes) are purged automatically on every invocation.

### Autopilot (overnight spec-driven loop)

Let Claude work unattended on a spec while you sleep, with multiple safety
layers. Three slash commands:

```
/autopilot [max_loop=150] <full-spec-path>   # start (runs preflight check)
/autopilot-stop                              # disengage explicitly
/autopilot-status                            # show progress
```

#### Recommended overnight recipe

```bash
# 1. Isolate: create a worktree so a misfire can't touch your main tree
git worktree add ../$(basename $PWD)-autopilot-$(date +%s) -b autopilot/<name>
cd ../*-autopilot-*

# 2. Launch Claude here, skip permission prompts so it doesn't wait for you
claude --dangerously-skip-permissions

# 3. In the session, start the loop with your spec
/autopilot 200 /absolute/path/to/spec.md
# ...go to sleep. Come back, review the branch, merge or discard.
```

#### Safety stack

1. **Git worktree isolation (strongly recommended)** — blast radius
   contained to one directory. `git worktree remove --force` is a clean
   rollback.
2. **Preflight health check** — `/autopilot` refuses to arm on protected
   branches (`main`, `master`, `trunk`, `develop`, `dev`) or on a dirty
   working tree. Warns if you're not in a worktree.
3. **Destructive-command guard** — while autopilot is active, a
   `PreToolUse(Bash)` hook denies: `rm -rf`, `find -exec rm`,
   `git reset --hard`, `git checkout -f`, `git clean -fdx`,
   `git branch -D`, `git push --force`, `DROP TABLE`, `TRUNCATE`. Claude
   is told why and picks a safer alternative. **Only active in autopilot
   mode** — normal sessions are unaffected.
4. **Loop-level halt conditions** — `max_loop` reached (default 150),
   5 consecutive turns with no repo change (stuck detector), or 10h wall
   clock.
5. **Graceful human takeover** — just type anything. The `Stop` hook
   sees the absence of the continuation marker on the last user message
   and disengages automatically; no command needed.
6. **Fail-open** — any hook error allows stop, so a plugin bug can never
   trap a session in an unstoppable loop.

#### What you'll find in the morning

All artifacts live under `.autopilot/` inside the worktree. redmem
auto-registers `/.autopilot/` into `.git/info/exclude` at
`/autopilot` init time — so nothing in this directory ever pollutes
`git status`, PRs, or your team's shared `.gitignore`.

| File | Meaning |
|------|---------|
| `.autopilot/TASKS.md` | Claude's live checklist; unchecked = left over. |
| `.autopilot/QUESTIONS.md` | Decisions Claude deferred to you (it was told not to ask). |
| `.autopilot/IMPROVE.md` | Claude's suggestions for the spec itself. |
| `.autopilot/DONE.md` | Claude emitted `[[AUTOPILOT_DONE]]` — it thinks it's finished. |
| `.autopilot/HALTED.md` | A halt condition tripped (max_loop / stuck / wall-clock). |
| `.autopilot/README.md` | Auto-generated guide to this directory. |

Safe to `rm -rf .autopilot/` any time — nothing is shared.

State file (separate, plugin-internal): `~/.claude/vault/autopilot/<session_id>.json`
— progress, iter count, last fingerprint, branch, worktree flag.

#### Pairing with `--dangerously-skip-permissions`

The bash guard is what makes skip-permission actually safe for overnight
use. Without the guard, one ambiguous spec turn could `rm -rf` your work.
With the guard, the most dangerous 10% of commands are denied by policy
and Claude is redirected to reversible alternatives.

## Quick Start

```bash
pip install redmem
redmem install    # configures Claude Code hooks
# Done. Protection + memory are automatic from now on.
```

## Uninstall

```bash
./uninstall.sh                       # remove redmem, keep memory archive
./uninstall.sh --purge               # also wipe vault + image cache + secret mappings
./uninstall.sh --keep-custom-patterns  # don't delete custom-patterns.py
```

Designed to never make things worse. It:
- removes only files that `install.sh` puts down (won't touch your own scripts in `~/.claude/hooks/`),
- strips only hook entries whose command path points at redmem (your custom hooks survive),
- strips only the managed CLAUDE.md section between the markers (your other CLAUDE.md content is preserved),
- preserves the memory archive at `~/.claude/vault/sessions/` by default — `--purge` is the explicit opt-in to wipe it,
- preserves your own `statusLine` if it isn't ours.

Verified end-to-end by `test_uninstall.py` (19 tests): clean install→uninstall round-trip produces a byte-identical CLAUDE.md, custom hooks/statusLine/theme survive, mid-file CLAUDE.md sections are sliced cleanly, and `--with-guard` installs are reversible too. Worst-case escape hatch from any future bug.

## How It Works

```
Claude Code event
  |
  v
redmem_dispatcher.py  (single gateway; shield/memory/autopilot/image-compressor/cheatsheet inside)
  |
  +-- UserPromptSubmit
  |     1. Shield: scan prompt for secret paste; block if found
  |     2. Memory: search archive on recall keywords (remember/before/之前/...)
  |     3. Autopilot init: if /autopilot was issued, run preflight + arm state
  |     4. Cheatsheet: inject post-compact tools reminder if flagged
  |
  +-- PreToolUse (Read/Write/Edit/Bash)
  |     1. Shield: secret redact/restore on file_path/content
  |     2. Image-original sentinel: intercept `redmem-original <path>` Bash
  |     3. Autopilot bash guard: deny rm-rf / git reset --hard / etc when armed
  |     4. Image compressor: rewrite Read of large images to a cache copy
  |
  +-- PostToolUse (Read/Write/Edit/Bash/Todo*/Task*/Plan*)
  |     1. Shield: restore files / scan residual placeholders
  |     2. Memory: track task/plan events → state_events
  |     3. Image notice: tell Claude how to fetch original if a compressed
  |        image was just served
  |
  +-- PreCompact
  |     1. Memory: archive turns to SQLite FTS5 + generate session_state.md
  |     2. Cheatsheet: flag this session so next UserPromptSubmit re-injects
  |        the tools cheatsheet (post-compact reminder)
  |
  +-- SessionStart (resume)
  |     Memory: inject session state + recent context as additionalContext
  |
  +-- Stop
  |     Autopilot: emit continuation if loop active and CC didn't signal done
  |
  +-- SessionEnd
        Shield: cleanup backup directory
```

## CLI

```bash
redmem install                          # configure hooks in settings.json
redmem search --query "migration 076"   # search session history
redmem timeline                         # file change history
redmem stats                            # archive statistics
redmem check                            # verify installation health
redmem gc --older-than 90d              # prune old archives
```

## Archiving Running Sessions (Catchup)

Hooks only fire for new sessions started after install. For **currently running
sessions** (which can't be restarted without losing context), use `redmem_catchup.py`:

```bash
# One-time: archive all sessions modified in the last 60 days (default)
python3 ~/.claude/hooks/redmem_catchup.py

# Target a specific session
python3 ~/.claude/hooks/redmem_catchup.py --session <uuid>

# Watch mode: incrementally archive every 60 seconds
python3 ~/.claude/hooks/redmem_catchup.py --watch

# Custom interval (default 60s)
python3 ~/.claude/hooks/redmem_catchup.py --watch --interval 30
```

**Safety guarantees:**
- Catchup only **reads** JSONL files, never modifies them
- Idempotent — only ingests turns after the last archived `line_number`
- Skips partial writes (last line without trailing `\n`) — caught on next run
- Zero impact on running Claude Code sessions

**Persistent watch (optional):** set up via launchd (macOS) or systemd (Linux).
See [docs/watch-daemon.md](docs/watch-daemon.md) for platform-specific examples.

## Backend Configuration

redmem supports pluggable backends via `~/.claude/redmem.yaml`:

```yaml
# Local mode (default, zero config)
backend:
  archive: sqlite    # SQLite FTS5, one file per session

# PostgreSQL mode (local or enterprise, multi-tenant)
backend:
  archive: postgres
  archive_dsn: "postgresql://redmem:pass@localhost:5432/redmem"
```

See [architecture.md](docs/design/architecture.md) for PostgreSQL schema with
row-level security, SECURITY DEFINER role mapping, and enterprise deployment.

## Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| **0. Restructure** | Done | Dispatcher wraps existing shield, memory module alongside |
| **1. MVP Memory** | Done | Ingest, search, summarize, PreCompact/SessionStart hooks |
| **1.5 Session State** | Done | session_state.md, task/plan tracking via PostToolUse |
| **2. Smart Recall** | Done | Auto-search archive on recall keywords in UserPromptSubmit |
| **3. Cross-Session Knowledge** | Done | Project-level `knowledge.db` indexing session summaries + key entities across all sessions. Enables "who solved this before?" and new-session onboarding from prior sessions. |
| **4. Semantic Search** | On Hold | sqlite-vec + embedding model for fuzzy recall. Requires external deps (~200MB fastembed or ~2GB torch). FTS5 keyword search is sufficient for most code conversations. Will implement as optional: `pip install redmem[semantic]` |

### Other TODO

- [ ] README.md: update installation instructions once PyPI package ready
- [ ] install.sh: adapt for redmem_dispatcher.py + memory hooks
- [ ] CLI tool: `redmem search/stats/gc/timeline/export/check` implementation
- [ ] Migration path: detect old claude-secret-shield settings.json, auto-upgrade
- [ ] pyproject.toml: package metadata for PyPI
- [ ] Latency analysis in architecture.md

## Tests

```bash
# Shield tests (185)
python3 test_hook.py

# Memory tests (21)
python3 -m pytest test_memory.py -v

# Guard tests (11, only needed if you use --with-guard)
python3 test_guard.py

# All tests
python3 test_hook.py && python3 -m pytest test_memory.py -v && python3 test_guard.py
```

## Documentation

- [Architecture & Technical Design](docs/design/architecture.md) — full specification
  including database schema, dispatcher design, pluggable backends, security model,
  JSONL format verification, and implementation phases.
- [Security Model](docs/SECURITY.md) — secret protection details
- [Pattern Reference](docs/PATTERNS.md) — all 205 regex patterns

## License

Apache 2.0
