#!/bin/sh
# claude-secret-shield — One-line installer
# Usage: curl -sL https://raw.githubusercontent.com/tokligence/claude-secret-shield/main/install.sh | sh
#
# What this does:
#   1. Installs the redact-restore hook (Python) to ~/.claude/hooks/
#   2. Installs the patterns file to ~/.claude/hooks/
#   3. Merges hook config into ~/.claude/settings.json (preserves existing settings)
#   4. Done — next Claude Code session will redact secrets automatically.

set -e

HOOKS_DIR="$HOME/.claude/hooks"
SETTINGS_FILE="$HOME/.claude/settings.json"
BASE_URL="https://raw.githubusercontent.com/tokligence/claude-secret-shield/main"

echo ""
echo "  claude-secret-shield"
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

# Install custom-patterns example (never overwrite user's custom file)
echo "  -> Downloading custom-patterns example..."
curl -fsSL "$BASE_URL/hooks/custom-patterns.example.py" -o "$HOOKS_DIR/custom-patterns.example.py"
echo "  OK: Installed $HOOKS_DIR/custom-patterns.example.py"

if [ -f "$HOOKS_DIR/custom-patterns.py" ]; then
  echo "  OK: Existing custom-patterns.py preserved (not overwritten)"
fi

# Remove old bash hook if present
if [ -f "$HOOKS_DIR/redact-secrets.sh" ]; then
  rm "$HOOKS_DIR/redact-secrets.sh"
  echo "  OK: Removed old redact-secrets.sh hook"
fi

# Merge into settings.json
echo "  -> Configuring Claude Code settings..."

PRE_HOOK_CONFIG='{
  "matcher": "Read|Write|Edit|Bash",
  "hooks": [
    {
      "type": "command",
      "command": "python3 ~/.claude/hooks/redact-restore.py",
      "timeout": 5}]
    }
  ]
}'

POST_HOOK_CONFIG='{
  "matcher": "Read|Write|Edit",
  "hooks": [
    {
      "type": "command",
      "command": "python3 ~/.claude/hooks/redact-restore.py",
      "timeout": 5}]
    }
  ]
}'


SESSION_END_HOOK_CONFIG='{"hooks":[{"type":"command","command":"python3 ~/.claude/hooks/redact-restore.py","timeout":5}]}'

PROMPT_HOOK_CONFIG='{"hooks":[{"type":"command","command":"python3 ~/.claude/hooks/redact-restore.py","timeout":5}]}'
if [ -f "$SETTINGS_FILE" ]; then
  EXISTING=$(cat "$SETTINGS_FILE")

  HAS_HOOKS=$(echo "$EXISTING" | jq 'has("hooks")' 2>/dev/null || echo "false")

  if [ "$HAS_HOOKS" = "true" ]; then
    # Remove any old hook entries, add PreToolUse, PostToolUse, UserPromptSubmit, SessionEnd
    UPDATED=$(echo "$EXISTING" | jq \
      --argjson pre_hook "$PRE_HOOK_CONFIG" \
      --argjson post_hook "$POST_HOOK_CONFIG" \
      --argjson stop_hook "$SESSION_END_HOOK_CONFIG" \
      --argjson prompt_hook "$PROMPT_HOOK_CONFIG" '
      .hooks.PreToolUse = (
        (.hooks.PreToolUse // [])
        | map(select(
            (.hooks[0].command != "~/.claude/hooks/redact-secrets.sh") and
            (.hooks[0].command != "python3 ~/.claude/hooks/redact-restore.py")
          ))
      ) + [$pre_hook]
      |
      .hooks.PostToolUse = (
        (.hooks.PostToolUse // [])
        | map(select(
            (.hooks[0].command != "python3 ~/.claude/hooks/redact-restore.py")
          ))
      ) + [$post_hook]
      |
      .hooks.SessionEnd = [$stop_hook]
      |
      .hooks.UserPromptSubmit = (
        (.hooks.UserPromptSubmit // [])
        | map(select(
            (.hooks[0].command != "python3 ~/.claude/hooks/redact-restore.py") and
            (.command != "python3 ~/.claude/hooks/redact-restore.py")
          ))
      ) + [$prompt_hook]
    ')
  else
    UPDATED=$(echo "$EXISTING" | jq \
      --argjson pre_hook "$PRE_HOOK_CONFIG" \
      --argjson post_hook "$POST_HOOK_CONFIG" \
      --argjson stop_hook "$SESSION_END_HOOK_CONFIG" \
      --argjson prompt_hook "$PROMPT_HOOK_CONFIG" '
      .hooks = { "PreToolUse": [$pre_hook], "PostToolUse": [$post_hook], "SessionEnd": [$stop_hook], "UserPromptSubmit": [$prompt_hook] }
    ')
  fi

  echo "$UPDATED" | jq '.' > "$SETTINGS_FILE"
else
  jq -n \
    --argjson pre_hook "$PRE_HOOK_CONFIG" \
    --argjson post_hook "$POST_HOOK_CONFIG" \
    --argjson stop_hook "$SESSION_END_HOOK_CONFIG" \
    --argjson prompt_hook "$PROMPT_HOOK_CONFIG" '{
    hooks: { PreToolUse: [$pre_hook], PostToolUse: [$post_hook], SessionEnd: [$stop_hook], UserPromptSubmit: [$prompt_hook] }
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
echo "    - Strategy 4: User prompts are scanned — blocks if secrets are pasted"
echo ""
echo "  Upstream patterns:  ~/.claude/hooks/patterns.py (updated on each install)"
echo "  Custom patterns:    ~/.claude/hooks/custom-patterns.py (never overwritten)"
echo "  Session mappings:   /tmp/.claude-redact-{session_id}.json"
echo ""
echo "  To add your own patterns, copy the example file:"
echo "    cp ~/.claude/hooks/custom-patterns.example.py ~/.claude/hooks/custom-patterns.py"
echo "  Then edit custom-patterns.py to add your patterns."
echo ""
echo "  Re-running install.sh updates upstream patterns without affecting your custom patterns."
echo ""
echo "  Restart Claude Code for changes to take effect."
echo ""
