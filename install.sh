#!/bin/sh
# redmem — One-line installer
# Usage:
#   curl -sL https://raw.githubusercontent.com/tokligence/redmem/main/install.sh | sh
#   ./install.sh                 # default: shield + memory only
#   ./install.sh --with-guard    # also install optional agent isolation guard
#
# What this does:
#   1. Installs shield hooks (secret redaction) to ~/.claude/hooks/
#   2. Installs memory module (session archive) to ~/.claude/hooks/memory/
#   3. Installs the dispatcher (single entry point) to ~/.claude/hooks/
#   4. (opt-in, --with-guard) Installs agent isolation guard hook
#   5. Merges hook config into ~/.claude/settings.json (preserves existing settings)
#   6. Creates vault directory for session archives
#   7. Migrates from old claude-secret-shield if detected

set -e

INSTALL_GUARD=false
for arg in "$@"; do
  case "$arg" in
    --with-guard) INSTALL_GUARD=true ;;
    -h|--help)
      sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "  WARN: unknown argument: $arg"
      ;;
  esac
done

HOOKS_DIR="$HOME/.claude/hooks"
MEMORY_DIR="$HOOKS_DIR/memory"
GUARD_DIR="$HOOKS_DIR/guard"
AUTOPILOT_DIR="$HOOKS_DIR/autopilot"
COMMANDS_DIR="$HOME/.claude/commands"
AUTOPILOT_STATE_DIR="$HOME/.claude/vault/autopilot"
VAULT_DIR="$HOME/.claude/vault/sessions"
SETTINGS_FILE="$HOME/.claude/settings.json"
BASE_URL="https://raw.githubusercontent.com/tokligence/redmem/main"
SCRIPT_DIR=$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo "")

echo ""
echo "  redmem (redact + memory)"
echo "  ────────────────────────"
echo "  Secret protection + persistent session memory for Claude Code."
echo ""

# ── Prerequisites ───────────────────────────────────────────────────────
if ! command -v jq >/dev/null 2>&1; then
  echo "  ERROR: jq is required. Install it:"
  echo "    macOS: brew install jq"
  echo "    Ubuntu: sudo apt install jq"
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "  ERROR: python3 is required."
  exit 1
fi

# ── Pick an interpreter that can actually run the shield ────────────────
# Hook commands get an ABSOLUTE path, resolved and verified here, rather than
# the bare word `python3`. Two reasons, both learned the hard way:
#
#   1. Hook processes do not source your shell rc, so a `python3` that resolves
#      correctly when you type it can resolve to something else entirely when
#      Claude Code spawns the hook. An `alias python3=...` is worse than
#      useless: it exists ONLY in interactive shells, so it hides the split
#      instead of fixing it.
#   2. `cryptography` is not optional in practice. Without it the mapping
#      cannot be decrypted, and on 2026-07-27 a machine whose `python3` had
#      silently moved to a build without it destroyed a 235-entry vault twice
#      in one session. The shield now fails safe rather than destroying, but
#      failing safe means NOT REDACTING — so a crypto-less interpreter still
#      turns the shield off. Better to refuse to install than to install one
#      that cannot protect anything.
PYTHON_BIN=""
for _candidate in \
  "${REDMEM_PYTHON:-}" \
  "$(command -v python3 2>/dev/null)" \
  /opt/homebrew/bin/python3.13 /opt/homebrew/bin/python3.12 /opt/homebrew/bin/python3.11 \
  /usr/local/bin/python3 /usr/bin/python3
do
  [ -n "$_candidate" ] || continue
  [ -x "$_candidate" ] || continue
  if "$_candidate" -c 'import cryptography' >/dev/null 2>&1; then
    PYTHON_BIN="$("$_candidate" -c 'import sys; print(sys.executable)')"
    break
  fi
done

if [ -z "$PYTHON_BIN" ]; then
  echo "  ERROR: refusing to install — this would disable redaction."
  echo ""
  echo "  No python3 with the 'cryptography' module was found."
  echo ""
  echo "  The secret shield stores its placeholder->secret mapping encrypted."
  echo "  An interpreter without 'cryptography' cannot read it, so the shield"
  echo "  would install and then quietly not protect anything."
  echo ""
  echo "  Fix either way:"
  echo "    <your python3> -m pip install cryptography"
  echo "    REDMEM_PYTHON=/path/to/python3 ./install.sh"
  exit 1
fi

# A path with a space would be split by whatever tokenises the command
# string, and every hook spawn would fail on the first fragment.
PYTHON_CMD="$PYTHON_BIN"
case "$PYTHON_BIN" in
  *\'*)
    # Refused rather than escaped. The command string is embedded in JSON that
    # jq parses with --argjson, so shell-escaping a quote (' -> '\'') would put
    # a backslash inside a JSON string literal and produce settings.json that
    # does not parse. Hand-rolling two layers of quoting to support a python
    # path containing an apostrophe is not worth the way it fails.
    echo "  ERROR: refusing to install - the interpreter path contains a single quote."
    echo "    $PYTHON_BIN"
    echo "  Use REDMEM_PYTHON to point at an interpreter whose path has none."
    exit 1
    ;;
  *[[:space:]]*) PYTHON_CMD="'$PYTHON_BIN'" ;;
esac

echo "  -> Hook interpreter: $PYTHON_BIN"
if [ "$PYTHON_BIN" != "$(command -v python3 2>/dev/null)" ]; then
  echo "     (note: differs from the python3 on your PATH — the absolute path"
  echo "      is what gets written into settings.json, deliberately)"
fi

# ── Detect migration from claude-secret-shield ──────────────────────────
MIGRATING=false
if [ -f "$HOOKS_DIR/redact-restore.py" ] && ! [ -f "$HOOKS_DIR/redmem_dispatcher.py" ]; then
  MIGRATING=true
  echo "  -> Detected existing claude-secret-shield installation"
  echo "     Will migrate to redmem (preserving custom-patterns.py)"
fi

# ── Create directories ──────────────────────────────────────────────────
mkdir -p "$HOOKS_DIR"
mkdir -p "$MEMORY_DIR"
mkdir -p "$AUTOPILOT_DIR"
mkdir -p "$AUTOPILOT_STATE_DIR"
mkdir -p "$COMMANDS_DIR"
mkdir -p "$VAULT_DIR"
chmod 700 "$VAULT_DIR"
chmod 700 "$AUTOPILOT_STATE_DIR"

# Helper: install a file, preferring local SCRIPT_DIR copy over curl.
# Lets `./install.sh` from a checked-out repo install the current WIP
# instead of last-pushed code.
install_file() {
  SRC_REL="$1"       # e.g. "hooks/redact-restore.py"
  DEST_ABS="$2"      # e.g. "$HOOKS_DIR/redact-restore.py"
  if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/$SRC_REL" ]; then
    cp "$SCRIPT_DIR/$SRC_REL" "$DEST_ABS"
  else
    curl -fsSL "$BASE_URL/$SRC_REL" -o "$DEST_ABS"
  fi
}

# ── Install shield files ────────────────────────────────────────────────
echo "  -> Installing shield (secret protection)..."
install_file "hooks/redact-restore.py"       "$HOOKS_DIR/redact-restore.py"
chmod +x "$HOOKS_DIR/redact-restore.py"
install_file "hooks/patterns.py"             "$HOOKS_DIR/patterns.py"
install_file "hooks/custom-patterns.example.py" "$HOOKS_DIR/custom-patterns.example.py"
install_file "hooks/secret_ops_guard.py"     "$HOOKS_DIR/secret_ops_guard.py"
chmod +x "$HOOKS_DIR/secret_ops_guard.py"
install_file "hooks/mask-output.py"          "$HOOKS_DIR/mask-output.py"
install_file "hooks/statusline.sh"           "$HOOKS_DIR/statusline.sh"
chmod +x "$HOOKS_DIR/statusline.sh"

# Preserve user custom patterns
if [ -f "$HOOKS_DIR/custom-patterns.py" ]; then
  echo "  OK: Existing custom-patterns.py preserved"
fi
echo "  OK: Shield installed"

# ── Install memory module ───────────────────────────────────────────────
echo "  -> Installing memory (session archive)..."
for FILE in __init__.py db.py transcript_parser.py ingest.py search.py summarize.py session_state.py knowledge.py; do
  install_file "hooks/memory/$FILE" "$MEMORY_DIR/$FILE"
done
echo "  OK: Memory module installed"

# ── Install dispatcher + image compressor ──────────────────────────────
echo "  -> Installing dispatcher..."
install_file "hooks/redmem_dispatcher.py" "$HOOKS_DIR/redmem_dispatcher.py"
chmod +x "$HOOKS_DIR/redmem_dispatcher.py"
install_file "hooks/redmem_catchup.py"    "$HOOKS_DIR/redmem_catchup.py"
chmod +x "$HOOKS_DIR/redmem_catchup.py"
install_file "hooks/image_compressor.py"  "$HOOKS_DIR/image_compressor.py"
chmod +x "$HOOKS_DIR/image_compressor.py"
install_file "hooks/cheatsheet.py"        "$HOOKS_DIR/cheatsheet.py"
install_file "hooks/git_guard.py"         "$HOOKS_DIR/git_guard.py"
chmod +x "$HOOKS_DIR/git_guard.py"
# The dispatcher imports this unconditionally. Leaving it out does not fail the
# install — the import error is caught — so the guard simply does not exist in
# any real installation while its 64 tests go on passing against the module in
# the repo. Found by running the installed dispatcher and reading its stderr:
# `[redmem] deploy config guard error: No module named 'deploy_config_guard'`.
install_file "hooks/deploy_config_guard.py" "$HOOKS_DIR/deploy_config_guard.py"
echo "  OK: Dispatcher + catchup + image compressor + cheatsheet + guards installed"

# ── Autopilot module + slash commands ───────────────────────────────────
echo "  -> Installing autopilot module..."
install_file "hooks/autopilot/__init__.py" "$AUTOPILOT_DIR/__init__.py"
install_file "hooks/autopilot/autopilot.py" "$AUTOPILOT_DIR/autopilot.py"
chmod +x "$AUTOPILOT_DIR/autopilot.py"

for CMD in autopilot.md autopilot-stop.md autopilot-status.md; do
  install_file "commands/$CMD" "$COMMANDS_DIR/$CMD"
done
echo "  OK: Autopilot + slash commands installed"

# ── Guard (optional, opt-in via --with-guard) ───────────────────────────
if [ "$INSTALL_GUARD" = true ]; then
  echo "  -> Installing guard (agent isolation)..."
  mkdir -p "$GUARD_DIR"
  if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/hooks/guard/agent_isolation_guard.py" ]; then
    cp "$SCRIPT_DIR/hooks/guard/agent_isolation_guard.py" "$GUARD_DIR/agent_isolation_guard.py"
  else
    curl -fsSL "$BASE_URL/hooks/guard/agent_isolation_guard.py" -o "$GUARD_DIR/agent_isolation_guard.py"
  fi
  chmod +x "$GUARD_DIR/agent_isolation_guard.py"
  mkdir -p "$HOME/.claude/vault"
  echo "  OK: Guard installed"
fi

# ── Remove legacy files ─────────────────────────────────────────────────
if [ -f "$HOOKS_DIR/redact-secrets.sh" ]; then
  rm "$HOOKS_DIR/redact-secrets.sh"
  echo "  OK: Removed legacy redact-secrets.sh"
fi

# ── Configure settings.json ─────────────────────────────────────────────
echo "  -> Configuring Claude Code settings..."

# SessionEnd still calls shield directly — it's a simple cleanup pass
# and doesn't need the dispatcher's multi-module routing.
SHIELD_SESSION_END='{"hooks":[{"type":"command","command":"'"$PYTHON_CMD"' ~/.claude/hooks/redact-restore.py","timeout":5}]}'

# Dispatcher hooks. The dispatcher is the single gateway for PreToolUse,
# PostToolUse, UserPromptSubmit, Stop, PreCompact, and SessionStart —
# it internally routes to shield / memory / autopilot / image compressor.
# One matcher per event keeps settings.json clean.
DISPATCH_PRE='{"matcher":"Read|Write|Edit|MultiEdit|NotebookEdit|Bash","hooks":[{"type":"command","command":"'"$PYTHON_CMD"' ~/.claude/hooks/redmem_dispatcher.py","timeout":10}]}'
DISPATCH_POST='{"matcher":"Read|Write|Edit|Bash|TodoWrite|TodoRead|EnterPlanMode|ExitPlanMode|TaskCreate|TaskUpdate","hooks":[{"type":"command","command":"'"$PYTHON_CMD"' ~/.claude/hooks/redmem_dispatcher.py","timeout":10}]}'
DISPATCH_PROMPT='{"hooks":[{"type":"command","command":"'"$PYTHON_CMD"' ~/.claude/hooks/redmem_dispatcher.py","timeout":5}]}'
DISPATCH_COMPACT='{"hooks":[{"type":"command","command":"'"$PYTHON_CMD"' ~/.claude/hooks/redmem_dispatcher.py","timeout":30,"statusMessage":"Archiving session..."}]}'
DISPATCH_RESUME='{"matcher":"resume","hooks":[{"type":"command","command":"'"$PYTHON_CMD"' ~/.claude/hooks/redmem_dispatcher.py","timeout":10,"statusMessage":"Loading session memory..."}]}'
DISPATCH_STOP='{"hooks":[{"type":"command","command":"'"$PYTHON_CMD"' ~/.claude/hooks/redmem_dispatcher.py","timeout":15}]}'

if [ -f "$SETTINGS_FILE" ]; then
  EXISTING=$(cat "$SETTINGS_FILE")
  HAS_HOOKS=$(echo "$EXISTING" | jq 'has("hooks")' 2>/dev/null || echo "false")
else
  EXISTING='{}'
  HAS_HOOKS="false"
fi

# Build the complete hooks config
# Strategy: remove all old redact-restore.py and redmem_dispatcher.py entries, then add fresh
if [ "$HAS_HOOKS" = "true" ]; then
  UPDATED=$(echo "$EXISTING" | jq     --argjson dispatch_pre "$DISPATCH_PRE"     --argjson dispatch_post "$DISPATCH_POST"     --argjson shield_end "$SHIELD_SESSION_END"     --argjson dispatch_prompt "$DISPATCH_PROMPT"     --argjson dispatch_compact "$DISPATCH_COMPACT"     --argjson dispatch_resume "$DISPATCH_RESUME"     --argjson dispatch_stop "$DISPATCH_STOP" '
    # Clean old entries
    def remove_old:
      map(select(
        # Match by script path, not by the whole command: the interpreter
        # prefix is now an absolute path resolved at install time, so an exact
        # comparison would fail to clean up entries written by any other
        # machine, any earlier version, or a different interpreter — and every
        # re-install would append a duplicate instead of replacing.
        ((.hooks[0].command // "") | (endswith("/.claude/hooks/redact-restore.py") or endswith("~/.claude/hooks/redact-restore.py")) | not) and
        ((.hooks[0].command // "") | (endswith("/.claude/hooks/redmem_dispatcher.py") or endswith("~/.claude/hooks/redmem_dispatcher.py")) | not) and
        ((.hooks[0].command // "") | (endswith("/.claude/hooks/redact-secrets.sh") or endswith("~/.claude/hooks/redact-secrets.sh")) | not)
      ));

    .hooks.PreToolUse = ((.hooks.PreToolUse // []) | remove_old) + [$dispatch_pre]
    | .hooks.PostToolUse = ((.hooks.PostToolUse // []) | remove_old) + [$dispatch_post]
    | .hooks.SessionEnd = [$shield_end]
    | .hooks.UserPromptSubmit = ((.hooks.UserPromptSubmit // []) | remove_old) + [$dispatch_prompt]
    | .hooks.PreCompact = ((.hooks.PreCompact // []) | remove_old) + [$dispatch_compact]
    | .hooks.SessionStart = ((.hooks.SessionStart // []) | remove_old) + [$dispatch_resume]
    | .hooks.Stop = ((.hooks.Stop // []) | remove_old) + [$dispatch_stop]
    | .statusLine = {"type": "command", "command": "~/.claude/hooks/statusline.sh"}
  ')
else
  UPDATED=$(echo "$EXISTING" | jq     --argjson dispatch_pre "$DISPATCH_PRE"     --argjson dispatch_post "$DISPATCH_POST"     --argjson shield_end "$SHIELD_SESSION_END"     --argjson dispatch_prompt "$DISPATCH_PROMPT"     --argjson dispatch_compact "$DISPATCH_COMPACT"     --argjson dispatch_resume "$DISPATCH_RESUME"     --argjson dispatch_stop "$DISPATCH_STOP" '
    .hooks = {
      PreToolUse: [$dispatch_pre],
      PostToolUse: [$dispatch_post],
      SessionEnd: [$shield_end],
      UserPromptSubmit: [$dispatch_prompt],
      PreCompact: [$dispatch_compact],
      SessionStart: [$dispatch_resume],
      Stop: [$dispatch_stop]
    }
    | .statusLine = {"type": "command", "command": "~/.claude/hooks/statusline.sh"}
  ')
fi

echo "$UPDATED" | jq '.' > "$SETTINGS_FILE"
echo "  OK: Updated $SETTINGS_FILE"

# ── Guard hook entries in settings.json (opt-in) ────────────────────────
if [ "$INSTALL_GUARD" = true ]; then
  GUARD_PRE='{"matcher":"Agent","hooks":[{"type":"command","command":"'"$PYTHON_CMD"' ~/.claude/hooks/guard/agent_isolation_guard.py","timeout":5}]}'
  GUARD_POST='{"matcher":"Agent","hooks":[{"type":"command","command":"'"$PYTHON_CMD"' ~/.claude/hooks/guard/agent_isolation_guard.py","timeout":5}]}'

  GUARD_UPDATED=$(cat "$SETTINGS_FILE" | jq \
    --argjson guard_pre "$GUARD_PRE" \
    --argjson guard_post "$GUARD_POST" '
    # Strip any existing guard entries so re-running install is idempotent.
    def strip_guard:
      map(select(
        # Suffix match, for the same reason as remove_old above: the
        # interpreter prefix is resolved per machine, so exact comparison
        # would duplicate this entry on every re-install.
        ((.hooks[0].command // "") | (endswith("/.claude/hooks/guard/agent_isolation_guard.py") or endswith("~/.claude/hooks/guard/agent_isolation_guard.py")) | not)
      ));
      .hooks.PreToolUse  = ((.hooks.PreToolUse  // []) | strip_guard) + [$guard_pre]
    | .hooks.PostToolUse = ((.hooks.PostToolUse // []) | strip_guard) + [$guard_post]
  ')
  echo "$GUARD_UPDATED" | jq '.' > "$SETTINGS_FILE"
  echo "  OK: Guard hook entries merged into $SETTINGS_FILE"
fi

# ── CLAUDE.md guidance ──────────────────────────────────────────────────
CLAUDE_MD="$HOME/.claude/CLAUDE.md"
MARKER_START="<!-- claude-secret-shield:start -->"
MARKER_END="<!-- claude-secret-shield:end -->"

SHIELD_SECTION="${MARKER_START}
## redmem capabilities

This environment uses the **redmem** plugin. The following are informational —
use them when relevant; don't change your default behaviour because of this
section.

### Secret shield

Values like \`{{OPENAI_KEY_8f3a2b1c}}\`, \`{{WALLET_PRIVATE_KEY_d4e5f6a7}}\`
in any file you read are **redacted placeholders** — the real values have
been replaced for safety, and the hook restores them on write.
- Treat placeholders as the actual secret values for all tasks.
- Use them as-is in code, file edits, and shell commands.
- **Never** ask the user to substitute, reveal, or re-enter the real values.
- **Never** attempt to guess, decode, or reconstruct the original secrets.

### Image compressor

Reading images larger than 500 KB and longer than 1920 px on the long side
serves a downscaled cache copy automatically (saves vision tokens). If you
cannot make out small text or pixel-level UI detail in an image you just
read, run this sentinel bash command:

    redmem-original /absolute/path/to/image.png

It is **not a real program** — a hook intercepts it, sets a one-shot
session-scoped flag, and denies the bash call. The next \`Read\` of that
path in this session will then serve the uncompressed original.

### Autopilot

If \`.autopilot/\` exists in the repo root, autopilot mode is armed. While
armed, destructive bash patterns are denied: \`rm -rf\`, \`git reset --hard\`,
\`git checkout -f\`, \`git clean -fdx\`, \`git branch -D\`,
\`git push --force\`, \`DROP TABLE|DATABASE|SCHEMA|INDEX\`, \`TRUNCATE\`.
Reach for \`mv\` to \`~/.autopilot-trash/<timestamp>/\`, \`git stash\`, or
\`git revert\` instead. Maintain \`.autopilot/TASKS.md\`, defer
unanswerable decisions to \`.autopilot/QUESTIONS.md\`, log spec
improvements to \`.autopilot/IMPROVE.md\`. End by emitting
\`[[AUTOPILOT_DONE]]\` once you've done all you can.

### Session memory

When the user says \"remember\", \"before\", \"earlier\", \"之前\",
\"上次\", \"记得\", an archive search of prior sessions runs automatically
and any relevant snippets get injected into your context. You don't need
to invoke this.
${MARKER_END}"

echo "  -> Configuring CLAUDE.md..."

if [ -f "$CLAUDE_MD" ]; then
  if grep -qF "$MARKER_START" "$CLAUDE_MD"; then
    python3 -c "
import sys, re
with open(sys.argv[1], 'r') as f:
    content = f.read()
pattern = re.escape(sys.argv[2]) + r'.*?' + re.escape(sys.argv[3])
result = re.sub(pattern, sys.argv[4], content, count=1, flags=re.DOTALL)
with open(sys.argv[1], 'w') as f:
    f.write(result)
" "$CLAUDE_MD" "$MARKER_START" "$MARKER_END" "$SHIELD_SECTION"
    echo "  OK: Updated existing section in $CLAUDE_MD"
  else
    printf '\n%s\n' "$SHIELD_SECTION" >> "$CLAUDE_MD"
    echo "  OK: Appended section to $CLAUDE_MD"
  fi
else
  printf '%s\n' "$SHIELD_SECTION" > "$CLAUDE_MD"
  echo "  OK: Created $CLAUDE_MD"
fi

# ── Summary ─────────────────────────────────────────────────────────────
echo ""
if [ "$MIGRATING" = true ]; then
  echo "  Migration from claude-secret-shield complete!"
else
  echo "  Installation complete!"
fi
echo ""
echo "  What redmem does:"
echo "    Shield: Secrets in files are replaced with {{PLACEHOLDER}} tokens"
echo "    Shield: Blocked files (.env, credentials) are never read"
echo "    Shield: Placeholders restored to real values on write"
echo "    Shield: User prompts scanned for accidental secret paste"
echo "    Memory: Full conversation archived to SQLite before /compact"
echo "    Memory: Session state + context restored on --resume"
echo "    Memory: Auto-recall from archive when you say \"remember\"/\"before\""
echo "    Memory: Cross-session knowledge index for project continuity"
echo ""
echo "  Files:"
echo "    Shield hooks:   ~/.claude/hooks/redact-restore.py + patterns.py"
echo "    Memory module:  ~/.claude/hooks/memory/*.py"
echo "    Dispatcher:     ~/.claude/hooks/redmem_dispatcher.py"
echo "    Archives:       ~/.claude/vault/sessions/"
echo "    Custom patterns: ~/.claude/hooks/custom-patterns.py (never overwritten)"
echo ""
echo "  To add custom secret patterns:"
echo "    cp ~/.claude/hooks/custom-patterns.example.py ~/.claude/hooks/custom-patterns.py"
echo "    # Edit custom-patterns.py"
echo ""
echo "  Re-running install.sh upgrades redmem without affecting custom patterns."
echo ""
echo "  Restart Claude Code for changes to take effect."
echo ""

if [ "$INSTALL_GUARD" = true ]; then
  echo "  -> Guard installed. To bypass a single Agent call:"
  echo "       touch ~/.claude/vault/.guard_bypass"
  echo "     To disable entirely: remove the two hook entries in ~/.claude/settings.json"
  echo "     matching 'guard/agent_isolation_guard.py'."
  echo ""
fi

# ── One-time catchup: archive existing sessions ─────────────────────────
echo "  -> Archiving existing sessions (last 60 days)..."
if python3 "$HOOKS_DIR/redmem_catchup.py" --max-age-days 60 2>&1; then
  echo "  OK: Catchup complete"
else
  echo "  WARN: Catchup had errors (not fatal — run manually later)"
fi

echo ""
echo "  Tips:"
echo "    - For continuous archival of long-running sessions:"
echo "        python3 ~/.claude/hooks/redmem_catchup.py --watch"
echo "    - Or set up as a launchd/systemd daemon:"
echo "        https://github.com/tokligence/redmem/blob/main/docs/watch-daemon.md"
echo ""
