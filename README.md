# claude-code-redact-restore

Prevent [Claude Code](https://claude.ai/code) from seeing your secrets. Secrets are automatically redacted when files are read, and restored when files are written. One-line install.

## The Problem

Claude Code can read files with credentials and private keys in your project. If you are not careful, secrets end up in the conversation context and potentially in logs.

## The Solution

A Claude Code hook (Python) that implements three strategies:

| Strategy | What it does |
|----------|-------------|
| **Block list** | Certain files are never read at all |
| **Smart redact** | Secrets in *any* file are replaced with consistent placeholder tokens before Claude sees them |
| **Auto restore** | When Claude writes/edits files or runs commands, placeholders are silently restored to real values |

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

## Architecture

### System Overview

```
~/.claude/
  settings.json          # Hook registration (PreToolUse + PostToolUse)
  hooks/
    redact-restore.py    # Main hook script (handles both Pre and Post)
    patterns.py          # 100+ secret regex patterns (upstream, updated on install)
    custom-patterns.py   # User custom patterns (never overwritten)

/tmp/
  .claude-redact-{session_id}.json   # Secret-to-placeholder mapping (chmod 600)
  .claude-backup-{session_id}/       # Temporary file backups during Read
```

### Hook Registration

The hook registers for **three** Claude Code hook events:

| Hook Event | Matcher | Purpose |
|------------|---------|---------|
| PreToolUse | Read, Write, Edit, Bash | Intercept tool calls before execution |
| PostToolUse | Read, Write, Edit | Restore/cleanup files after tool completes |
| SessionEnd | (all) | Clean up sensitive mapping and backup files on exit |

### Request Processing Flow

```
Claude Code issues a tool call (Read, Write, Edit, or Bash)
        |
        v
  PreToolUse Hook
        |
  +-----+------+------+------+
  |            |         |         |
  v            v         v         v
 Read       Write     Edit      Bash
  |            |         |         |
  v            v         v         v
 Block       Load      Load     Block
 list?       mapping   mapping  list?
  |            |         |         |
  v            v         v         v
 Read file   Restore   Restore  Restore
 Scan for    place-    place-   place-
 secrets     holders   holders  holders
  |            |         |         |
  v            v         v         v
 Backup +    allow      allow    allow
 overwrite   with       with     with
 with        update     update   update
 redacted
  |
  v
  allow
        |
        v
  Claude Code executes tool (with real values restored)
        |
        v
  PostToolUse Hook (Read, Write, Edit)
        |
        v
  Read:  restore original from backup
  Edit:  restore placeholders in edited file
  Write: cleanup backup files

  SessionEnd Hook (on session exit)
        |
        v
  Delete /tmp mapping + backup files
```

### Detailed Read Flow (The Core Mechanism)

```
1. PreToolUse fires for Read(/path/to/config.py)
2. Hook reads the file from disk
3. Hook scans content against 100+ regex patterns
4. Hook creates/loads session mapping (secret <-> placeholder)
5. Hook backs up original file to /tmp/.claude-backup-{session}/
6. Hook overwrites original with redacted content (preserves timestamps)
7. Hook exits 0 (allow) -- Claude Code reads file normally
   -> Claude Code registers the file as read (KEY!)
   -> Claude sees redacted content with placeholders
8. PostToolUse fires -- hook restores original from backup
```

**Why this design?** Claude Code tracks which files have been "read" internally.
If the Read tool is denied or redirected to a temp file, Claude Code will not
register the original file path as read. Then Write/Edit to that file fails with
"file has not been read yet". By temporarily overwriting the original file with
redacted content and allowing Read to proceed normally, we satisfy Claude Code's
internal tracking.

### Session Mapping Consistency

The secret-to-placeholder mapping persists across all hook invocations within a
session via /tmp/.claude-redact-{session_id}.json. The same secret always maps
to the same placeholder. When Claude writes code using a placeholder, the Write
hook loads the mapping and restores the real value transparently.

### Crash Recovery

If Claude Code crashes between PreToolUse (file overwritten) and PostToolUse
(file restored), the backup remains on disk. On the next hook invocation,
restore_pending_backups() runs at startup and restores any orphaned backups
automatically.

## Supported Secret Patterns

100+ patterns ported from gitleaks and tokligence_guard:

- **AI/ML:** OpenAI, Anthropic, Groq, Perplexity, Hugging Face, Replicate, DeepSeek
- **Cloud:** AWS, GCP/Firebase, Azure, DigitalOcean, Alibaba, Tencent
- **DevOps:** GitHub, GitLab, Bitbucket, npm, PyPI, Docker Hub, Terraform, Vault
- **Payment:** Stripe, Square, PayPal/Braintree, Adyen, Flutterwave
- **Messaging:** Slack, Discord, Twilio, SendGrid, Mailchimp, Telegram, Teams
- **Database:** PostgreSQL, MySQL, MongoDB, Redis (connection strings with passwords)
- **Monitoring:** New Relic, Sentry, Dynatrace
- **Other:** Shopify, HubSpot, Postman, PlanetScale, Contentful, and many more

## Custom Patterns

Add your own patterns in ~/.claude/hooks/custom-patterns.py (never overwritten by install):

```python
CUSTOM_SECRET_PATTERNS = [
    ("MY_INTERNAL_TOKEN", r"mycompany_tok_[A-Za-z0-9]{32,}"),
]
CUSTOM_BLOCKED_FILES = [
    "my-secret-config.yaml",
]
```

## Running Tests

```bash
python3 test_hook.py
```

Tests cover block list, redaction, backup/restore, crash recovery,
read-then-write cycle (the key bug fix), and performance.

## Performance

~10-30ms per tool call (Python startup + regex compilation).

## License

Apache 2.0
