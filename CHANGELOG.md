# Changelog

All notable changes to redmem will be documented in this file.

## [Unreleased]

### Added
- **git_guard** (`hooks/git_guard.py`): always-on `PreToolUse(Bash)` deny for `git add -A` / `git add --all` / `git add .` (incl. combined flags `-Av` / `-vA`). Closes the gap left by `settings.json` permission rules, which only see literal command prefixes and miss chained Bash like `cd repo && git add -A`. The regex scans the whole command, distinguishes `.` (standalone arg) from `./path` (excluded), and never matches `git add -u` (the safe tracked-only alternative). Escape hatch via `REDMEM_ALLOW_GIT_ADD_ALL=1`. Fail-open. Wired through the dispatcher and also installable as a direct hook for users who want the protection without swapping the rest of redmem.
  - 55 tests (`test_git_guard.py`): 23 parameterised must-deny cases (incl. combined flags + chains + subshells), 19 must-pass safe cases (explicit paths, `-u`, `-p`, dot-slash, unrelated commands), opt-out env behaviour, malformed-input fail-open, and standalone CLI smoke tests.
- **Post-compact tools cheatsheet** (`hooks/cheatsheet.py`): re-injects a concise capability summary into Claude's context on the first `UserPromptSubmit` after each auto-compact, so it remembers `redmem-original`, the autopilot bash-guard rules, the shield placeholder protocol, and memory-recall keywords even after lossy compaction. `PreCompact` writes a session-scoped flag; the next `UserPromptSubmit` consumes the flag (one-shot) and prepends the cheatsheet text via `additionalContext`. ~400 tokens per compact. Phrased as informational, not directive.
  - Install also extends the managed CLAUDE.md section (`<!-- claude-secret-shield:* -->` markers, name preserved for upgrade idempotency) to cover all redmem tools — Shield, Image compressor, Autopilot, Memory — instead of Shield only.
  - 8 tests (`test_cheatsheet.py`) including two end-to-end stdin runs against the real dispatcher.
- **Image compressor** (`hooks/image_compressor.py`): transparently downscale large images before Claude reads them, cutting vision tokens (~66% on a typical phone screenshot) without altering the on-disk file.
  - Fires from `PreToolUse(Read)` via the dispatcher; returns `updatedInput` with a compressed cache path.
  - Thresholds: only rewrites images > 500 KB AND longest side > 1920 px. Smaller images pass through unchanged.
  - Uses macOS-native `sips` (no Python dependencies); fail-open on non-macOS or any tool error.
  - Cache: `/tmp/redmem-img-cache/<sha1>-<mtime>.<ext>` — mtime in filename ensures edits invalidate.
  - Three opt-out layers: `REDMEM_NO_IMAGE_COMPRESS=1` env (host-wide), `.redmem-no-compress` file (per-project), `.orig.` / `.nocompress.` filename marker (per-image).
  - **Automatic request-original flow**: after Claude reads a compressed image, a PostToolUse `additionalContext` tells it exactly how to get the uncompressed version if it needs pixel-level detail. Claude issues the sentinel bash command `redmem-original <path>`; a PreToolUse(Bash) hook intercepts it (the command is not a real program), writes a session-scoped flag, and denies. The next `Read <path>` in that session sees the flag and passes the original through uncompressed. No human renaming; the sentinel runs entirely in-hook.
  - 36 tests (`test_image_compressor.py`) covering opt-outs, thresholds, cache invalidation, sentinel-bash intercept, flag one-shot + session scoping, PostToolUse notice sidecar logic, and a real-`sips` integration test (skipped where unavailable).
- **Autopilot module** (`hooks/autopilot/`): overnight spec-driven loop that keeps Claude Code working unattended.
  - Three slash commands: `/autopilot [max_loop=150] <full-spec-path>`, `/autopilot-stop`, `/autopilot-status`.
  - Stop-hook re-injects a continuation message every turn until Claude emits `[[AUTOPILOT_DONE]]` or a halt condition trips (max_loop, 5-turn no-repo-change streak, 10h wall clock).
  - Graceful human takeover: typing any non-continuation message auto-disengages the loop (hook detects absence of the continuation marker and pauses state — no command needed).
  - **Preflight health check**: `/autopilot` refuses to arm on protected branches (main/master/trunk/develop/dev), refuses on a dirty working tree, and warns when not in a git worktree.
  - **Bash guard** (only active during autopilot): `PreToolUse(Bash)` denies `rm -rf`, `find -exec rm`, `git reset --hard`, `git checkout -f`, `git clean -fdx`, `git branch -D`, `git push --force`, `DROP TABLE`/`DATABASE`/`SCHEMA`/`INDEX`, and `TRUNCATE TABLE`. Claude is told why and picks a safer alternative.
  - **Artifacts under `.autopilot/`**: `TASKS.md`, `QUESTIONS.md`, `IMPROVE.md`, `DONE.md`, `HALTED.md`, auto-generated `README.md`. Plugin auto-registers `/.autopilot/` into `.git/info/exclude` so nothing leaks into git.
  - Fail-open: any hook error allows stop, preventing a plugin bug from trapping a session in an unstoppable loop.
  - `test_autopilot.py`: 58 tests (arg parsing, state round-trip, all stop-hook decision branches, 21 parameterized bash-guard samples, preflight refusal/warn cases, idempotent git-exclude register).
- **Guard module** (optional, opt-in via `./install.sh --with-guard`): agent isolation guard that denies concurrent non-isolated `Agent` tool calls targeting the same git repo, preventing parallel subagents from stomping on each other's uncommitted changes. Standalone hook (not routed through the dispatcher); fail-open on any internal error. Includes `.guard_bypass` one-shot override and 11 hermetic tests (`test_guard.py`).
- **Memory module** (Phase 0-2): persistent session archive for Claude Code
  - `hooks/memory/db.py`: SQLite FTS5 schema + connection management
  - `hooks/memory/transcript_parser.py`: Claude Code JSONL parser (verified append-only format, skips compact_boundary/isCompactSummary markers)
  - `hooks/memory/ingest.py`: incremental turn archival (line_number based dedup)
  - `hooks/memory/search.py`: FTS5 full-text search with query sanitization (handles FTS5 syntax chars in natural language)
  - `hooks/memory/summarize.py`: resume context builder (session_state > milestone > recent turns, token-budgeted)
  - `hooks/memory/session_state.py`: heuristic session state generation (Goal/Plan/Done/Blocked/Decisions) + task/plan event tracking
  - `hooks/redmem_dispatcher.py`: single entry point routing to shield or memory based on hook event
  - `test_memory.py`: 21 tests covering DB, FTS5, parser, ingest, search, resume, session state
- **Pluggable backend architecture**: ArchiveBackend + VectorBackend abstract interfaces; SQLite (default) and PostgreSQL (enterprise) implementations documented
- **Architecture document** (`docs/design/architecture.md`): full technical specification, 13 rounds of Codex adversarial review

### Fixed
- **`uninstall.sh` rewritten** to cover all current redmem files and hook events. The old uninstaller was a leftover from the `claude-secret-shield` era and didn't know about the dispatcher, the autopilot/memory/guard modules, the image compressor, the cheatsheet helper, the slash commands, or the `PreCompact` / `SessionStart` / `Stop` event entries — running it would have left an inconsistent half-install. New version: removes every file install.sh writes, strips redmem entries from all seven hook events (jq filter fixed — old version's `any(.; ...)` against an array silently matched nothing), strips the managed CLAUDE.md section, preserves user-authored content (custom hooks, theme, other settings, unrelated CLAUDE.md sections, `custom-patterns.py`, the memory vault). Adds `--purge` to wipe the vault + `/tmp/redmem-img-cache/` + per-session secret mappings. Verified: clean uninstall, custom-hook preservation, `--purge` wipes, and install→uninstall→install round-trip produces a byte-identical CLAUDE.md.
- **Write tool silent failure**: PreToolUse(Write) no longer causes data loss when PostToolUse falls back to backup restore. Content-based crash recovery (hash + placeholder detection) replaces flag-based approach. (Codex R5-R10, 6 rounds)
- **Crash recovery safety**: Write backups distinguished from Read backups; restore_pending_backups uses content comparison to detect completed writes
- **Placeholder regex**: crash recovery now matches pattern names containing digits (e.g. AWS_S3_ARN, DB2_URL) with `[A-Z0-9_]+`

### Changed
- Renamed from claude-secret-shield to redmem (redact + memory)
- Repository: github.com/tokligence/redmem
- **Shield housekeeping moved from `.gitignore` to `.git/info/exclude`**: `.tmp_secrets.*` temp files are now registered in git's *local* exclude list at file-create time (previously appended to the user's shared `.gitignore` on first Read, which leaked into PRs and never fired if Claude didn't Read the file). Existing stray `.tmp_secrets.*` files in users' working trees can be safely deleted; the new behavior prevents recurrence.
- **PreToolUse and PostToolUse now route through the dispatcher** instead of calling shield directly, so the autopilot bash guard + image compressor + image notice can all share one gateway. Shield is still invoked as the first step inside the dispatcher (same semantics, one extra subprocess hop). `SHIELD_POST` direct entry removed; `DISPATCH_POST` covers the combined matcher `Read|Write|Edit|Bash|Todo*|Task*|Plan*`.
- **install.sh prefers local files over curl** when run from a checked-out repo (`SCRIPT_DIR/hooks/...` / `SCRIPT_DIR/commands/...`). Earlier versions always fetched from GitHub main, which prevented installing a WIP branch locally.

## [Pre-rename] claude-secret-shield

All prior history preserved in git log. Key features:
- 4-layer secret protection (prompt scan, file block, pattern redact, write restore)
- 205 regex patterns + 42 blocked file patterns
- HMAC-based deterministic placeholders
- Crash recovery with pending backup restoration
- 185 tests
