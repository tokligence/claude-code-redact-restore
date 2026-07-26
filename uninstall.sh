#!/bin/sh
# redmem — Uninstaller
# Usage:
#   curl -sL https://raw.githubusercontent.com/tokligence/redmem/main/uninstall.sh | sh
#   ./uninstall.sh                       # default: remove redmem, keep memory vault
#   ./uninstall.sh --purge               # also delete the memory vault + image cache
#   ./uninstall.sh --keep-custom-patterns  # don't remove ~/.claude/hooks/custom-patterns.py
#
# What this does (default):
#   1. Removes redmem hook files (dispatcher, shield, memory module, autopilot,
#      image_compressor, cheatsheet, statusline, mask-output, redmem_catchup)
#   2. Removes redmem slash commands (autopilot.md, autopilot-stop.md, autopilot-status.md)
#   3. Strips redmem hook entries from ~/.claude/settings.json (every event)
#   4. Strips the redmem managed section from ~/.claude/CLAUDE.md
#   5. Preserves: memory vault (~/.claude/vault/sessions/), session archive (~/.claude/vault/*.db),
#      user's custom-patterns.py, all unrelated CLAUDE.md content, all unrelated settings.
#
# Add --purge to also wipe:
#   - ~/.claude/vault/sessions/, ~/.claude/vault/autopilot/, ~/.claude/vault/cheatsheet/
#   - /tmp/redmem-img-cache/
#   - /tmp/.claude-redact-*.json (session secret mappings)

set -e

PURGE=false
KEEP_CUSTOM_PATTERNS=false
for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=true ;;
    --keep-custom-patterns) KEEP_CUSTOM_PATTERNS=true ;;
    -h|--help)
      sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "  WARN: unknown argument: $arg"
      ;;
  esac
done

HOOKS_DIR="$HOME/.claude/hooks"
MEMORY_DIR="$HOOKS_DIR/memory"
AUTOPILOT_DIR="$HOOKS_DIR/autopilot"
GUARD_DIR="$HOOKS_DIR/guard"
COMMANDS_DIR="$HOME/.claude/commands"
SETTINGS_FILE="$HOME/.claude/settings.json"
CLAUDE_MD="$HOME/.claude/CLAUDE.md"
AUTOPILOT_STATE_DIR="$HOME/.claude/vault/autopilot"
CHEATSHEET_DIR="$HOME/.claude/vault/cheatsheet"
SESSIONS_DIR="$HOME/.claude/vault/sessions"
IMG_CACHE_DIR="/tmp/redmem-img-cache"

echo ""
echo "  redmem — uninstall"
echo "  ──────────────────"
echo ""

# ── Remove hook scripts ───────────────────────────────────────────────
removed_count=0
for f in redact-restore.py patterns.py redact-secrets.sh custom-patterns.example.py \
         mask-output.py statusline.sh redmem_dispatcher.py redmem_catchup.py \
         image_compressor.py cheatsheet.py git_guard.py secret_ops_guard.py; do
  if [ -f "$HOOKS_DIR/$f" ]; then
    rm "$HOOKS_DIR/$f"
    removed_count=$((removed_count + 1))
  fi
done

# custom-patterns.py: user-authored. Keep by default unless explicitly --purge.
if [ -f "$HOOKS_DIR/custom-patterns.py" ]; then
  if [ "$KEEP_CUSTOM_PATTERNS" = true ] || [ "$PURGE" = false ]; then
    echo "  -> Preserved $HOOKS_DIR/custom-patterns.py (your own file)"
  else
    rm "$HOOKS_DIR/custom-patterns.py"
    removed_count=$((removed_count + 1))
  fi
fi
echo "  OK: Removed $removed_count hook script(s)"

# ── Remove module dirs ────────────────────────────────────────────────
for d in "$MEMORY_DIR" "$AUTOPILOT_DIR" "$GUARD_DIR"; do
  if [ -d "$d" ]; then
    rm -rf "$d"
    echo "  OK: Removed $d"
  fi
done

# Hooks dir cleanup: remove pycache and the dir itself if empty
find "$HOOKS_DIR" -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
if [ -d "$HOOKS_DIR" ]; then
  # Only remove the hooks dir if empty (preserves any user-added hooks).
  rmdir "$HOOKS_DIR" 2>/dev/null && echo "  OK: Removed empty $HOOKS_DIR" || \
    echo "  -> Kept $HOOKS_DIR (contains files we didn't install)"
fi

# ── Remove slash commands ─────────────────────────────────────────────
for cmd in autopilot.md autopilot-stop.md autopilot-status.md; do
  if [ -f "$COMMANDS_DIR/$cmd" ]; then
    rm "$COMMANDS_DIR/$cmd"
    echo "  OK: Removed $COMMANDS_DIR/$cmd"
  fi
done
# Remove commands dir if empty
if [ -d "$COMMANDS_DIR" ]; then
  rmdir "$COMMANDS_DIR" 2>/dev/null || true
fi

# ── Strip hook entries from settings.json ─────────────────────────────
if [ -f "$SETTINGS_FILE" ] && command -v jq >/dev/null 2>&1; then
  # An entry is "ours" if any hook inside points at one of the commands we install.
  # Matches both wrapped form (".hooks[].command") and rare flat form (".command").
  UPDATED=$(cat "$SETTINGS_FILE" | jq '
    # Matched by SCRIPT PATH, not by the whole command string. install.sh
    # writes an absolute interpreter path resolved on the installing machine,
    # so any exact comparison here uninstalls cleanly on the machine that
    # wrote it and silently leaves entries behind everywhere else — including
    # after the installing machine changes its python. Leftovers are worse
    # than a failed uninstall: the entries stay, the hook files are gone, and
    # every tool call starts failing to spawn.
    def is_redmem_command:
      (. // "")
      | (endswith(".claude/hooks/redmem_dispatcher.py")
         or endswith(".claude/hooks/redact-restore.py")
         or endswith(".claude/hooks/guard/agent_isolation_guard.py")
         or endswith(".claude/hooks/redact-secrets.sh"));

    def is_redmem_hook:
      any((.hooks // [])[].command?; is_redmem_command)
      or (.command? | is_redmem_command);

    def strip(event):
      if .hooks[event] then
        .hooks[event] = [ .hooks[event][] | select(is_redmem_hook | not) ]
        | if .hooks[event] == [] then del(.hooks[event]) else . end
      else . end;

    strip("PreToolUse")
    | strip("PostToolUse")
    | strip("UserPromptSubmit")
    | strip("SessionEnd")
    | strip("SessionStart")
    | strip("PreCompact")
    | strip("Stop")
    | if (.hooks // {}) == {} then del(.hooks) else . end
    | if .statusLine?.command == "~/.claude/hooks/statusline.sh" then del(.statusLine) else . end
  ')
  echo "$UPDATED" | jq '.' > "$SETTINGS_FILE"
  echo "  OK: Stripped redmem entries from $SETTINGS_FILE"
fi

# ── Strip managed CLAUDE.md section ───────────────────────────────────
if [ -f "$CLAUDE_MD" ]; then
  MARKER_START="<!-- claude-secret-shield:start -->"
  MARKER_END="<!-- claude-secret-shield:end -->"
  if grep -qF "$MARKER_START" "$CLAUDE_MD"; then
    python3 -c "
import re, sys
path = sys.argv[1]
start = sys.argv[2]
end = sys.argv[3]
with open(path, 'r') as f:
    content = f.read()
# Remove the marker block and a single optional leading/trailing blank line.
pattern = re.compile(r'\n*' + re.escape(start) + r'.*?' + re.escape(end) + r'\n?', re.DOTALL)
new_content = pattern.sub('', content, count=1)
# Trim trailing whitespace so file doesn't keep growing/shrinking weirdly.
new_content = new_content.rstrip() + '\n' if new_content.strip() else ''
with open(path, 'w') as f:
    f.write(new_content)
" "$CLAUDE_MD" "$MARKER_START" "$MARKER_END"
    # If the file is now empty, remove it (we created it; user has nothing else).
    if [ ! -s "$CLAUDE_MD" ]; then
      rm "$CLAUDE_MD"
      echo "  OK: Removed $CLAUDE_MD (was empty after section removal)"
    else
      echo "  OK: Stripped managed section from $CLAUDE_MD"
    fi
  fi
fi

# ── Purge transient state (opt-in) ────────────────────────────────────
if [ "$PURGE" = true ]; then
  echo ""
  echo "  --purge: wiping memory vault + transient state..."
  for d in "$AUTOPILOT_STATE_DIR" "$CHEATSHEET_DIR" "$SESSIONS_DIR" "$IMG_CACHE_DIR"; do
    if [ -d "$d" ]; then
      rm -rf "$d"
      echo "  OK: Removed $d"
    fi
  done
  # Also remove session secret mapping files
  removed=0
  for f in /tmp/.claude-redact-*.json; do
    if [ -f "$f" ]; then
      rm "$f"
      removed=$((removed + 1))
    fi
  done
  [ "$removed" -gt 0 ] && echo "  OK: Removed $removed session secret mapping file(s)"
  # And try to clean the vault dir if now empty
  rmdir "$HOME/.claude/vault" 2>/dev/null || true
fi

# ── Done ──────────────────────────────────────────────────────────────
echo ""
echo "  Uninstalled."
if [ "$PURGE" = false ]; then
  echo "  Memory archive preserved at $SESSIONS_DIR (use --purge to wipe)."
fi
echo "  Restart Claude Code for hook changes to take effect."
echo ""
