#!/bin/bash
# claude-secret-shield — Prevent Claude Code from reading secret files
# https://github.com/tokligence/claude-secret-shield
#
# Intercepts Read and Bash tool calls. Blocks access to files matching
# secret patterns (.env, credentials, private keys, etc.).
#
# Install: curl -sL https://raw.githubusercontent.com/tokligence/claude-secret-shield/main/install.sh | sh

set -euo pipefail

INPUT=$(cat)
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty')
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

# ── Configurable patterns ──────────────────────────────────────────────
# Add your own patterns to ~/.claude/hooks/redact-patterns.txt (one per line)
DEFAULT_PATTERNS=(
  ".env"
  ".env.local"
  ".env.production"
  ".env.staging"
  ".env.development"
  "credential.json"
  "credential.enc"
  "credentials.json"
  "secrets.yaml"
  "secrets.json"
  "secret.key"
  ".private"
  "id_rsa"
  "id_ed25519"
  "id_ecdsa"
  "id_dsa"
  ".pem"
  ".p12"
  ".pfx"
  "keystore"
  "service-account.json"
  "gcp-credentials.json"
  "aws-credentials"
)

# Load custom patterns if file exists
CUSTOM_PATTERNS_FILE="$HOME/.claude/hooks/redact-patterns.txt"
PATTERNS=("${DEFAULT_PATTERNS[@]}")
if [ -f "$CUSTOM_PATTERNS_FILE" ]; then
  while IFS= read -r line; do
    [ -n "$line" ] && [[ ! "$line" =~ ^# ]] && PATTERNS+=("$line")
  done < "$CUSTOM_PATTERNS_FILE"
fi

# ── Check function ─────────────────────────────────────────────────────
matches_secret() {
  local path="$1"
  for pattern in "${PATTERNS[@]}"; do
    if [[ "$path" == *"$pattern"* ]]; then
      echo "$pattern"
      return 0
    fi
  done
  return 1
}

# ── Read tool — block reading secret files ─────────────────────────────
if [ "$TOOL_NAME" = "Read" ] && [ -n "$FILE_PATH" ]; then
  matched=$(matches_secret "$FILE_PATH") && {
    echo "🔒 Blocked: reading '$FILE_PATH' — matches secret pattern '$matched'. Use .env.example instead." >&2
    exit 2
  }
fi

# ── Bash tool — block commands that read secret files ──────────────────
if [ "$TOOL_NAME" = "Bash" ] && [ -n "$COMMAND" ]; then
  for pattern in "${PATTERNS[@]}"; do
    # Match: cat .env, head .env.local, source .env, etc.
    if echo "$COMMAND" | grep -qE "(cat|head|tail|less|more|bat|source|\.)\s+[^ ]*${pattern}"; then
      echo "🔒 Blocked: command reads '$pattern' — contains secrets." >&2
      exit 2
    fi
    # Match: cat < .env, grep something .env
    if echo "$COMMAND" | grep -qE "[<|]\s*[^ ]*${pattern}"; then
      echo "🔒 Blocked: command reads '$pattern' — contains secrets." >&2
      exit 2
    fi
  done
fi

# ── Write tool — block writing to secret files (prevent accidental overwrite)
if [ "$TOOL_NAME" = "Write" ] && [ -n "$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')" ]; then
  WRITE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path')
  matched=$(matches_secret "$WRITE_PATH") && {
    echo "🔒 Blocked: writing to '$WRITE_PATH' — matches secret pattern '$matched'." >&2
    exit 2
  }
fi

# ── Allow everything else ──────────────────────────────────────────────
exit 0
