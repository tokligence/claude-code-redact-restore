# claude-code-redact-restore

Prevent [Claude Code](https://claude.ai/code) from seeing your secrets. Secrets are automatically redacted when files are read, and restored when files are written. One-line install.

## The Problem

Claude Code can read `.env` files, credentials, and private keys in your project. If you're not careful, secrets end up in the conversation context and potentially in logs.

## The Solution

A Claude Code hook (Python) that implements three strategies:

| Strategy | What it does |
|----------|-------------|
| **Block list** | Certain files (`.env`, `credentials.json`, `id_rsa`, etc.) are never read at all |
| **Smart redact** | Secrets in *any* file are replaced with consistent `{{PLACEHOLDER}}` tokens before Claude sees them |
| **Auto restore** | When Claude writes/edits files or runs commands, placeholders are silently restored to real values |

```
You: "Read config.py"
Claude sees:  API_KEY = "{{OPENAI_KEY_1}}"

You: "Update the API key variable name"
Claude writes: OPENAI_API_KEY = "{{OPENAI_KEY_1}}"
Actually saved: OPENAI_API_KEY = "sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ..."
```

## Install

```bash
curl -sL https://raw.githubusercontent.com/tokligence/claude-code-redact-restore/main/install.sh | sh
```

Restart Claude Code after installing.

**Prerequisites:** Python 3.6+, jq

## Uninstall

```bash
curl -sL https://raw.githubusercontent.com/tokligence/claude-code-redact-restore/main/uninstall.sh | sh
```

## How It Works

### Strategy 1: Block List

Files matching these names are completely blocked from being read:

| Pattern | Examples |
|---------|----------|
| `.env*` | `.env`, `.env.local`, `.env.production`, `.env.staging` |
| `credential*` | `credential.json`, `credentials.json` |
| `secrets.*` | `secrets.yaml`, `secrets.json`, `secrets.toml` |
| SSH keys | `id_rsa`, `id_ed25519`, `id_ecdsa` |
| Certificates | `.pem`, `.p12`, `.pfx` |
| Cloud creds | `service-account.json`, `gcp-credentials.json` |
| Auth files | `.npmrc`, `.pypirc`, `.git-credentials`, `.netrc` |

### Strategy 2: Smart Redact

For every other file, the hook scans content against 100+ secret patterns (ported from [gitleaks](https://github.com/gitleaks/gitleaks) and tokligence_guard). Detected patterns include:

- **AI/ML:** OpenAI, Anthropic, Groq, Perplexity, Hugging Face, Replicate, DeepSeek
- **Cloud:** AWS, GCP/Firebase, Azure, DigitalOcean, Alibaba, Tencent
- **DevOps:** GitHub, GitLab, Bitbucket, npm, PyPI, Docker Hub, Terraform, Vault
- **Payment:** Stripe, Square, PayPal/Braintree, Adyen, Flutterwave
- **Messaging:** Slack, Discord, Twilio, SendGrid, Mailchimp, Telegram, Teams
- **Database:** PostgreSQL, MySQL, MongoDB, Redis (connection strings with passwords)
- **Monitoring:** New Relic, Sentry, Dynatrace
- **Other:** Shopify, HubSpot, Postman, PlanetScale, Contentful, and many more

Each detected secret is replaced with a consistent placeholder like `{{GITHUB_PAT_CLASSIC_1}}`. The same secret always maps to the same placeholder within a session.

### Strategy 3: Auto Restore

When Claude Code calls Write, Edit, or Bash tools, the hook intercepts the input and replaces any placeholders back to their real values. This is transparent to both you and Claude.

### Session Mapping

The secret-to-placeholder mapping is stored at `/tmp/.claude-redact-{session_id}.json` with `chmod 600`. Each Claude Code session gets its own mapping file. Mappings are cleaned up on uninstall.

## Customizing Patterns

Edit `~/.claude/hooks/patterns.py` to:

- Add files to `BLOCKED_FILES`
- Add regex patterns to `SECRET_PATTERNS`
- Remove patterns you don't need

Each pattern is a tuple of `(name, regex_string)`:

```python
SECRET_PATTERNS = [
    # ... existing patterns ...
    ("MY_INTERNAL_TOKEN", r'myapp_[a-zA-Z0-9]{32}'),
]
```

## Running Tests

```bash
python3 test_hook.py
```

Tests cover:
- Block list for known secret files
- Redaction of OpenAI, GitHub, AWS, Stripe, SendGrid, database URL, and private key patterns
- Consistent placeholder mapping (same secret = same placeholder)
- Mapping persistence across separate hook invocations
- Restore on Write, Edit, and Bash tool calls
- Bash command blocking (cat .env, source .env, etc.)
- Mapping file permissions (600)
- Performance (< 100ms per invocation)

## Performance

The hook executes in ~10-30ms per tool call (Python startup + regex compilation). All patterns are compiled once per invocation. The mapping file is a small JSON file read/written with standard I/O.

## Architecture

```
Claude Code tool call
        |
        v
  PreToolUse hook
        |
        +---> Read: block list check -> read file -> scan patterns -> deny with redacted content
        |
        +---> Write/Edit: load mapping -> restore placeholders -> allow with updated input
        |
        +---> Bash: block list check -> restore placeholders in command -> allow with updated input
        |
        v
  Claude Code executes tool (with real values restored)
```

## FAQ

**Q: Does this affect the current session?**
A: No, hooks take effect on the next Claude Code session.

**Q: Can Claude still use environment variables at runtime?**
A: Yes. It just can't see the raw values. Placeholders work transparently.

**Q: What if I need Claude to see a specific secret?**
A: Remove the pattern from `~/.claude/hooks/patterns.py` or temporarily uninstall.

**Q: Is any data sent externally?**
A: No. Everything runs locally. The mapping file is on your filesystem with restricted permissions.

**Q: What happens if the hook crashes?**
A: The hook is designed to fail open. If it cannot parse input or read files, it allows the operation to proceed normally.

## License

MIT
