#!/bin/sh
# Uninstall claude-code-redact-restore
# Usage: curl -sL https://raw.githubusercontent.com/tokligence/claude-code-redact-restore/main/uninstall.sh | sh

set -e

HOOKS_DIR="$HOME/.claude/hooks"
SETTINGS_FILE="$HOME/.claude/settings.json"

echo ""
echo "  Uninstalling claude-code-redact-restore..."
echo ""

# Remove hook files
for f in redact-restore.py patterns.py redact-secrets.sh; do
  if [ -f "$HOOKS_DIR/$f" ]; then
    rm "$HOOKS_DIR/$f"
    echo "  OK: Removed $HOOKS_DIR/$f"
  fi
done

# Remove session mapping files
REMOVED_MAPS=0
for f in /tmp/.claude-redact-*.json; do
  if [ -f "$f" ]; then
    rm "$f"
    REMOVED_MAPS=$((REMOVED_MAPS + 1))
  fi
done
if [ "$REMOVED_MAPS" -gt 0 ]; then
  echo "  OK: Removed $REMOVED_MAPS session mapping file(s)"
fi

# Remove from settings.json
if [ -f "$SETTINGS_FILE" ] && command -v jq >/dev/null 2>&1; then
  UPDATED=$(cat "$SETTINGS_FILE" | jq '
    if .hooks.PreToolUse then
      .hooks.PreToolUse = [
        .hooks.PreToolUse[]
        | select(
            (.hooks[0].command != "~/.claude/hooks/redact-secrets.sh") and
            (.hooks[0].command != "python3 ~/.claude/hooks/redact-restore.py")
          )
      ]
    else . end
    | if .hooks.PostToolUse then
      .hooks.PostToolUse = [
        .hooks.PostToolUse[]
        | select(
            (.hooks[0].command != "python3 ~/.claude/hooks/redact-restore.py")
          )
      ]
    else . end
    | if .hooks.SessionEnd then
      .hooks.SessionEnd = [
        .hooks.SessionEnd[]
        | select(
            (.hooks[0].command != "python3 ~/.claude/hooks/redact-restore.py")
          )
      ]
    else . end
    | if .hooks.PreToolUse == [] then del(.hooks.PreToolUse) else . end
    | if .hooks.PostToolUse == [] then del(.hooks.PostToolUse) else . end
    | if .hooks.SessionEnd == [] then del(.hooks.SessionEnd) else . end
    | if .hooks == {} then del(.hooks) else . end
  ')
  echo "$UPDATED" | jq '.' > "$SETTINGS_FILE"
  echo "  OK: Removed hook from settings.json"
fi

echo ""
echo "  Uninstalled. Restart Claude Code for changes to take effect."
echo ""
