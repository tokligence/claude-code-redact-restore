---
name: install-redact
description: Install the Claude Code secret redaction hooks to protect API keys and credentials from being seen by Claude
user_invocable: true
---

# Install Claude Code Secret Redaction

The user wants to install secret redaction hooks for Claude Code. This protects API keys, tokens, and passwords from being visible to Claude.

## Step 1: Download and install

Run this single command:

```bash
git clone https://github.com/tokligence/claude-code-redact-restore.git /tmp/claude-redact-install && bash /tmp/claude-redact-install/install.sh && rm -rf /tmp/claude-redact-install
```

This will:
1. Clone the repo to a temp directory
2. Copy hook scripts to `~/.claude/hooks/`
3. Register PreToolUse + PostToolUse + SessionEnd hooks in Claude Code settings
4. Clean up the temp clone

## Step 2: Verify

```bash
# Check hooks registered
python3 -c "import json; h=json.load(open('$HOME/.claude/settings.json')).get('hooks',{}); print(f'Hooks: Pre={len(h.get(\"PreToolUse\",[]))}, Post={len(h.get(\"PostToolUse\",[]))}, Session={len(h.get(\"SessionEnd\",[])))}')"
```

Expected output: `Hooks: Pre=1, Post=1, Session=1`

## Step 3: Restart Claude Code

The user must restart Claude Code (or start a new session) for hooks to take effect.

## What happens after installation

- When Claude reads any file, secrets are automatically replaced with placeholders like `{{OPENAI_KEY_a1b2c3d4}}`
- When Claude writes code, placeholders are silently restored to real values
- 108 secret patterns detected (OpenAI, AWS, GitHub, Stripe, database URLs, private keys, JWTs, etc.)
- 30 sensitive file types blocked entirely (.env, credentials.json, id_rsa, etc.)
- Mapping encrypted at rest with Fernet

## To uninstall later

```bash
git clone https://github.com/tokligence/claude-code-redact-restore.git /tmp/claude-redact-install && bash /tmp/claude-redact-install/uninstall.sh && rm -rf /tmp/claude-redact-install
```

## Important security note

Tell the user: This prevents Claude from **seeing** secrets in files. It does NOT prevent Claude from running arbitrary code to access secrets. Use alongside proper secret management (vaults, env vars, short-lived tokens).
