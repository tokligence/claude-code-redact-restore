#!/bin/sh
# claude-code-redact-restore — One-line installer
# Usage: curl -sL https://raw.githubusercontent.com/tokligence/claude-code-redact-restore/main/install.sh | sh
#
# What this does:
#   1. Installs the redact-restore hook (Python) to ~/.claude/hooks/
#   2. Installs the patterns file to ~/.claude/hooks/
#   3. Merges hook config into ~/.claude/settings.json (preserves existing settings)
#   4. Done — next Claude Code session will redact secrets automatically.

set -e

HOOKS_DIR="$HOME/.claude/hooks"
SETTINGS_FILE="$HOME/.claude/settings.json"
BASE_URL="https://raw.githubusercontent.com/tokligence/claude-code-redact-restore/main"

echo ""
echo "  claude-code-redact-restore"
echo "  ----------------------------"
echo "  Prevents Claude Code from seeing your secrets."
echo "  Secrets are replaced with placeholders and restored on write."
echo ""

# Check prerequisites
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

# Create hooks directory
mkdir -p "$HOOKS_DIR"

# Download hook files
echo "  -> Downloading hook script..."
curl -fsSL "$BASE_URL/hooks/redact-restore.py" -o "$HOOKS_DIR/redact-restore.py"
chmod +x "$HOOKS_DIR/redact-restore.py"
echo "  OK: Installed $HOOKS_DIR/redact-restore.py"

echo "  -> Downloading patterns..."
curl -fsSL "$BASE_URL/hooks/patterns.py" -o "$HOOKS_DIR/patterns.py"
echo "  OK: Installed $HOOKS_DIR/patterns.py"

# Remove old bash hook if present
if [ -f "$HOOKS_DIR/redact-secrets.sh" ]; then
  rm "$HOOKS_DIR/redact-secrets.sh"
  echo "  OK: Removed old redact-secrets.sh hook"
fi

# Merge into settings.json
echo "  -> Configuring Claude Code settings..."

HOOK_CONFIG='{
  "matcher": "Read|Write|Edit|Bash",
  "hooks": [
    {
      "type": "command",
      "command": "python3 ~/.claude/hooks/redact-restore.py",
      "timeout": 5
    }
  ]
}'

# Also define old hook config for cleanup
OLD_HOOK_CMD="~/.claude/hooks/redact-secrets.sh"

if [ -f "$SETTINGS_FILE" ]; then
  EXISTING=$(cat "$SETTINGS_FILE")

  HAS_HOOKS=$(echo "$EXISTING" | jq 'has("hooks")' 2>/dev/null || echo "false")

  if [ "$HAS_HOOKS" = "true" ]; then
    # Remove any old hook entries (both old bash hook and previous python hook)
    UPDATED=$(echo "$EXISTING" | jq --argjson hook "$HOOK_CONFIG" '
      .hooks.PreToolUse = (
        (.hooks.PreToolUse // [])
        | map(select(
            (.hooks[0].command != "~/.claude/hooks/redact-secrets.sh") and
            (.hooks[0].command != "python3 ~/.claude/hooks/redact-restore.py")
          ))
      ) + [$hook]
    ')
  else
    UPDATED=$(echo "$EXISTING" | jq --argjson hook "$HOOK_CONFIG" '
      .hooks = { "PreToolUse": [$hook] }
    ')
  fi

  echo "$UPDATED" | jq '.' > "$SETTINGS_FILE"
else
  jq -n --argjson hook "$HOOK_CONFIG" '{
    hooks: { PreToolUse: [$hook] }
  }' > "$SETTINGS_FILE"
fi

echo "  OK: Updated $SETTINGS_FILE"

echo ""
echo "  Installation complete!"
echo ""
echo "  How it works:"
echo "    - Strategy 1: Blocked files (.env, credentials, etc.) are never read"
echo "    - Strategy 2: Secrets in any file are replaced with {{PLACEHOLDER}} tokens"
echo "    - Strategy 3: Placeholders are restored to real values when writing files"
echo ""
echo "  Customize patterns: edit ~/.claude/hooks/patterns.py"
echo "  Session mappings:   /tmp/.claude-redact-{session_id}.json"
echo ""
echo "  Restart Claude Code for changes to take effect."
echo ""
