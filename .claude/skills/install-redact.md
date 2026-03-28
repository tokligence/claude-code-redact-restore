---
name: install-redact
description: Install the Claude Code secret redaction hooks to protect API keys and credentials from being seen by Claude
user_invocable: true
---

# Install Claude Code Secret Redaction

You are installing the `claude-code-redact-restore` hook system. This protects the user's secrets (API keys, tokens, passwords) from being seen by Claude Code.

## What it does

- **108 regex patterns** detect secrets in ANY file Claude reads (OpenAI, AWS, GitHub, Stripe, database URLs, private keys, JWTs, etc.)
- **30 file types** are blocked entirely (.env, credentials.json, id_rsa, .pem, etc.)
- **Secrets are replaced** with consistent placeholders like `{{OPENAI_KEY_a1b2c3d4}}` before Claude sees them
- **Placeholders are restored** to real values when Claude writes code
- **Mapping is encrypted** at rest with Fernet (AES + HMAC-SHA256)
- **Same secret = same placeholder** across all sessions (HMAC-based, deterministic)

## Installation steps

Run these commands:

```bash
# 1. Clone the repo
git clone https://github.com/tokligence/claude-code-redact-restore.git ~/.claude-redact-restore

# 2. Run the installer
bash ~/.claude-redact-restore/install.sh
```

The installer will:
1. Copy hook scripts to `~/.claude/hooks/`
2. Register 3 hooks in Claude Code settings (PreToolUse, PostToolUse, SessionEnd)
3. Generate an HMAC key at `~/.claude/.redact-hmac-key` (first run only)

## Verify installation

```bash
# Check hooks are registered
cat ~/.claude/settings.json | python3 -c "import sys,json; h=json.load(sys.stdin).get('hooks',{}); print(f'PreToolUse: {len(h.get(\"PreToolUse\",[]))} hooks'); print(f'PostToolUse: {len(h.get(\"PostToolUse\",[]))} hooks'); print(f'SessionEnd: {len(h.get(\"SessionEnd\",[]))} hooks')"

# Test with a fake secret
echo 'API_KEY=sk-proj-EXAMPLE-TEST-1234567890123456' > /tmp/test-redact.txt
echo '{"tool_name":"Read","tool_input":{"file_path":"/tmp/test-redact.txt"},"session_id":"test"}' | python3 ~/.claude/hooks/redact-restore.py
cat /tmp/test-redact.txt  # Should show {{OPENAI_PROJECT_KEY_...}} instead of the key
# Clean up
rm /tmp/test-redact.txt
```

## Uninstall

```bash
bash ~/.claude-redact-restore/uninstall.sh
```

## Important: Security scope

This tool prevents Claude from **seeing** your secrets in files. It does NOT prevent:
- Claude running arbitrary code to access secrets (e.g., `python3 -c "open('.env').read()"`)
- Prompt injection attacks
- Secrets in binary files or unknown formats

Use it as one layer alongside proper secret management (vaults, env vars, short-lived tokens).

## Troubleshooting

Enable debug mode to see what the hook is doing:
```bash
export REDACT_DEBUG=1
# Then use Claude Code normally — check stderr for hook logs
```

## Configuration

Create `~/.claude-redact-ignore` or `.claude-redact-ignore` in your project to skip files:
```
# Skip test fixtures with fake secrets
tests/fixtures/*
config/example.yaml
```
