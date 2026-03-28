# Security Guide -- How Your Secrets Are Protected

This document explains how claude-secret-shield protects your secrets.
It is written for developers who are not cryptographers. No prior knowledge of
cryptography is assumed.

## The Problem

When you use Claude Code, it reads your files. Your files contain API keys,
database passwords, private keys, and other secrets. Without protection,
Claude sees your real secrets -- they end up in the conversation context and
potentially in logs or training data.

For example, if your `config.py` contains:

```python
OPENAI_API_KEY = "sk-proj-EXAMPLE-FAKE-KEY-1234567"
DATABASE_URL = "postgres://admin:s3cret_p@ss@db.example.com/prod"
```

Claude Code would see both of those real values when it reads the file.

## The Solution: 3 Layers of Protection

```
                         Your Files
                              |
         +--------------------+--------------------+
         |                    |                    |
    Layer 1              Layer 2              Layer 3
   DON'T SHOW IT       REPLACE IT           LOCK IT UP
         |                    |                    |
         v                    v                    v
   Block dangerous      Swap secrets         Encrypt the
   files entirely       with harmless        secret-to-
   (.env, id_rsa)       placeholders         placeholder
                                             mapping file
```

### Layer 1: Don't Show It (File Blocking)

**Analogy:** A bouncer at a nightclub. Some files are too dangerous to let
Claude see at all, so the bouncer stops them at the door.

When Claude tries to read `.env`, `credentials.json`, `id_rsa`, or any of
the 30 blocked file types, the hook denies the read entirely. Claude gets
an error message like:

> BLOCKED: '.env' is in the secret files block list. Use .env.example
> or ask the user for guidance.

The full block list includes:

- Environment files: `.env`, `.env.local`, `.env.production`, `.env.staging`, `.env.development`, `.env.test`
- Credential files: `credential.json`, `credentials.json`, `secrets.yaml`, `secrets.json`, `secrets.toml`, `secret.key`
- Private keys: `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`, `.pem`, `.p12`, `.pfx`, `keystore.jks`
- Cloud credentials: `service-account.json`, `gcp-credentials.json`, `aws-credentials`
- Auth tokens: `.npmrc`, `.pypirc`, `.docker/config.json`, `.git-credentials`, `.netrc`
- Other: `.private`, `credential.enc`

### Layer 2: Replace It (Pattern Redaction)

**Analogy:** A translator at a border crossing. The translator reads your
document and replaces every sensitive word with a code word before showing
it to the officer. The officer sees the code words and can work with the
document, but never learns the real words.

For every file that is not blocked, the hook scans the content against 108
regex patterns. When it finds a match, it replaces the secret with a
deterministic placeholder:

```
Before (what's on disk):     sk-proj-EXAMPLE-FAKE-KEY-1234567
After (what Claude sees):    {{OPENAI_KEY_a1b2c3d4}}
```

The placeholder name tells Claude what kind of secret it is (an OpenAI key),
and the suffix (`a1b2c3d4`) makes it unique. Claude can write code using the
placeholder, and the hook will silently swap it back to the real value when
Claude writes or edits the file.

**Why "deterministic"?** The same secret always produces the same placeholder.
If your OpenAI key appears in 5 different files, it gets the same placeholder
in all 5. This is achieved using HMAC (explained below).

### Layer 3: Lock It Up (Encrypted Mapping)

The hook needs to remember which placeholder maps to which secret. This mapping
is stored in a file. But the mapping contains your real secrets -- so it needs
to be encrypted.

**Analogy:** You have a codebook that translates code words back to real words.
You keep the codebook in a locked safe. Even if someone finds the safe, they
cannot read the codebook without the combination.

The mapping file (`~/.claude/.redact-mapping.json`) is encrypted with Fernet,
which combines AES encryption and HMAC authentication (both explained below).

## Cryptographic Concepts Explained

### What is HMAC?

**HMAC** = Hash-based Message Authentication Code.

**Analogy:** Imagine you have a special fingerprint machine that only you own.
You put in any document and it stamps a unique fingerprint on it. The same
document always gets the same fingerprint. But nobody else has your machine,
so nobody else can produce the same fingerprints.

Here is what HMAC does:

```
  Your secret value           Your personal key
  (e.g., "sk-proj-XXX...")    (stored in ~/.claude/.redact-hmac-key)
         |                           |
         +------ HMAC-SHA256 --------+
                    |
                    v
              "a1b2c3d4"
         (deterministic fingerprint)
```

Key properties:
- **Deterministic:** Same input + same key = always the same output
- **Unique per key:** A different key produces a completely different output
- **One-way:** You cannot reverse the output back to the input
- **Fixed size:** No matter how long the input, the output is always the same length

We use HMAC to generate placeholder suffixes. Your API key `sk-proj-XXX...`
always becomes `{{OPENAI_KEY_a1b2c3d4}}` on your machine, because your
machine has your unique key. On someone else's machine (different key),
the same API key would produce a completely different placeholder.

### What is SHA-256?

**SHA-256** is a one-way hash function. It takes any input and produces a
fixed 256-bit (32-byte) output.

**Analogy:** A meat grinder. You can turn a steak into ground meat, but you
cannot turn ground meat back into a steak. And two different steaks produce
slightly different ground meat (you can tell them apart), but you cannot
reconstruct either original steak.

```
  Any input (any length)
         |
     SHA-256
         |
         v
  Fixed 32-byte output (looks like: a3f2b8c9d1e4...)
```

Key properties:
- **One-way:** Cannot reverse the output back to the input
- **Deterministic:** Same input always produces the same output
- **Avalanche effect:** Changing even 1 bit of input completely changes the output
- **Collision resistant:** It is practically impossible to find two different inputs that produce the same output

We use SHA-256 for two things:
1. As part of HMAC-SHA256 (for generating placeholders)
2. To derive the Fernet encryption key from the HMAC key (key derivation, explained below)

### What is Fernet Encryption?

**Fernet** is an encryption recipe from the `cryptography` Python library.
It combines two things: AES encryption and HMAC authentication.

**Analogy:** Think of AES as a safe and HMAC as a tamper-evident seal.

- **AES** (Advanced Encryption Standard) is the safe. You put your data inside,
  lock it with a key, and nobody can read it without the key. We use AES-128-CBC,
  which means 128-bit keys and Cipher Block Chaining mode.

- **HMAC** is the tamper-evident seal. After locking the safe, you put a seal on it.
  If anyone changes even one byte of the encrypted data, the seal breaks. When you
  open the safe, you check the seal first -- if it is broken, you refuse to open it.

Here is what happens when the mapping file is saved (encrypted):

```
  Your mapping data (JSON)
         |
    AES-128-CBC encrypt (scrambles the data)
         |
    HMAC-SHA256 sign (adds tamper-evident seal)
         |
         v
  Encrypted blob (looks like random bytes)
  Saved to ~/.claude/.redact-mapping.json
```

And when it is loaded (decrypted):

```
  Encrypted blob from disk
         |
    HMAC-SHA256 verify (check the seal)
         |
    If seal is broken --> ERROR: "InvalidToken" (reject the file)
    If seal is intact --> continue
         |
    AES-128-CBC decrypt (unscramble the data)
         |
         v
  Your mapping data (JSON)
```

If anyone tampers with the encrypted file -- even changing a single byte --
the HMAC verification fails and the hook refuses to load it. This protects
against both accidental corruption and deliberate tampering.

### What is Key Derivation?

We have ONE master key: the HMAC key stored at `~/.claude/.redact-hmac-key`.
But we need to use cryptographic keys for TWO different purposes:

1. Generating placeholder names (HMAC)
2. Encrypting the mapping file (Fernet)

**Why not use the same key for both?** Security principle: key separation.
Using the same key for two different cryptographic operations can create
subtle vulnerabilities. If an attacker learns something about the key from
one use, it should not help them with the other use.

So we derive two different keys from the master key:

```
  Master key (~/.claude/.redact-hmac-key, 32 random bytes)
         |
         +----> Used directly for HMAC placeholder generation
         |
         +----> SHA-256(master_key + "mapping-encryption")
                        |
                        v
                 Derived 32-byte key
                        |
                 base64url encode
                        |
                        v
                 Fernet encryption key
```

The string `"mapping-encryption"` is called a "context separator." It ensures
that even though both keys come from the same master key, they are
cryptographically independent.

## What Each File Does

### ~/.claude/.redact-hmac-key

- **Contents:** 32 bytes of cryptographically random data
- **Permissions:** `0400` (read-only, owner only)
- **Created:** Once, on first hook invocation (using `os.urandom(32)`)
- **Purpose:** Master key for placeholder generation and encryption key derivation

This is your personal master key. It is generated once and used for as long as
you keep it. It is never shared, never backed up to git, and never transmitted
anywhere.

**If deleted:** A new key is generated on the next hook invocation. The old
encrypted mapping becomes unreadable (which is actually good -- the old secrets
are safe). New placeholders will be generated for the same secrets. There is no
data loss, just different placeholder names.

### ~/.claude/.redact-mapping.json

- **Contents:** Fernet-encrypted JSON (or plaintext JSON if `cryptography` is not installed)
- **Permissions:** `0600` (read/write, owner only)
- **Created:** On first secret detection
- **Purpose:** Bidirectional mapping between secrets and placeholders

The JSON structure inside (after decryption) looks like:

```json
{
  "secret_to_placeholder": {
    "sk-proj-EXAMPLE...": "{{OPENAI_KEY_a1b2c3d4}}",
    "postgres://admin:s3cret...": "{{POSTGRES_URL_e5f6g7h8}}"
  },
  "placeholder_to_secret": {
    "{{OPENAI_KEY_a1b2c3d4}}": "sk-proj-EXAMPLE...",
    "{{POSTGRES_URL_e5f6g7h8}}": "postgres://admin:s3cret..."
  }
}
```

The mapping persists across sessions -- the same secret always gets the same
placeholder. When the mapping exceeds 10,000 entries, the oldest half is
automatically evicted (LRU eviction).

### /tmp/.claude-backup-{session_id}/

- **Contents:** Per-file backups (`.bak` files) and metadata (`.meta` files)
- **Permissions:** Directory is `0700` (owner only)
- **Created:** When the hook redacts a file during Read
- **Deleted:** When the session ends (SessionEnd hook)

These are temporary copies of your original files, created before the hook
overwrites them with redacted content. After Claude finishes reading, the
original is restored from the backup. If Claude Code crashes before
restoration, the backups survive and are automatically restored on the next
hook invocation (crash recovery).

## Threat Model

### What it protects against

| Threat | How it is mitigated |
|--------|---------------------|
| Claude seeing your real API keys | Secrets are redacted before Claude reads the file |
| Mapping file exposure (someone reads the file) | Encrypted with Fernet; looks like random bytes without the key |
| Race conditions from parallel tool calls | `fcntl` file locking (shared for reads, exclusive for writes) |
| Process crash mid-write | Atomic writes (tempfile + rename); crash recovery restores orphaned backups |
| Accidental file corruption | Fernet HMAC detects any tampering or corruption |
| Claude running `cat .env` via Bash | Bash command blocking intercepts reads of blocked files |
| Git committing the mapping file | The mapping is in `~/.claude/`, not in your project directory |

### What it does NOT protect against

| Limitation | Explanation |
|------------|-------------|
| Root user on your machine | Root can read any file, including the HMAC key and mapping |
| Memory dump while hook is running | Secrets are briefly in RAM during redaction/restoration |
| Someone with both the HMAC key AND the mapping file | They can decrypt the mapping and recover all secrets |
| Claude deliberately bypassing the hook | For example, Claude could write a Python script that reads `.env` directly. Bash command blocking mitigates the common cases but is not bulletproof |
| Secrets in tool output (stdout/stderr) | If a command prints a secret to stdout, the PostToolUse hook does not redact it (the secret is already in Claude's context) |
| Network exfiltration | The hook runs locally; it does not inspect network traffic |

### If your HMAC key is compromised

If you suspect your HMAC key has been exposed:

1. Delete the key and mapping:
   ```bash
   rm ~/.claude/.redact-hmac-key ~/.claude/.redact-mapping.json
   ```
2. Restart Claude Code. A new key is generated automatically.
3. Rotate any secrets that may have been exposed.

The old mapping becomes permanently unreadable (the derived Fernet key dies
with the old HMAC key). All placeholders reset -- this is a minor
inconvenience (Claude will generate new placeholders for secrets it
encounters), not a security issue.

## How the Pieces Fit Together

Here is the full lifecycle of a secret, from disk through Claude and back:

```
Step 1: Claude asks to Read config.py
        Hook reads the real file from disk

Step 2: Hook scans content, finds "sk-proj-EXAMPLE..."
        HMAC(key, "sk-proj-EXAMPLE...") --> "a1b2c3d4"
        Placeholder = {{OPENAI_KEY_a1b2c3d4}}

Step 3: Hook stores mapping:
        "sk-proj-EXAMPLE..." <--> {{OPENAI_KEY_a1b2c3d4}}
        Encrypts mapping with Fernet, saves to disk

Step 4: Hook backs up original, overwrites file with redacted version
        Claude reads: OPENAI_API_KEY = "{{OPENAI_KEY_a1b2c3d4}}"

Step 5: PostToolUse fires, hook restores original from backup
        File on disk is back to normal

Step 6: Claude writes new code using {{OPENAI_KEY_a1b2c3d4}}
        Hook loads mapping, replaces placeholder with real value
        File on disk has the real secret
```

Claude never sees the real secret. Your files always have real values.
The mapping file on disk is encrypted. The key exists only on your machine.

## Comparison with Alternatives

| Feature | claude-secret-shield | .gitignore | .env vault (Doppler, etc.) | Manual review |
|---------|---------------------------|-----------|---------------------------|---------------|
| Automatic | Yes | No | Partial | No |
| Works with Claude Code | Yes | No (Claude still reads) | No | Yes (tedious) |
| Catches secrets in any file | Yes (140 patterns) | No | No | Human judgment |
| Encrypted mapping | Yes (Fernet) | N/A | Yes | N/A |
| Cross-session consistency | Yes (HMAC) | N/A | N/A | N/A |
| Blocks dangerous files | Yes (30 types) | Prevents git commit only | No | No |
| Bash command protection | Yes | No | No | No |
| Zero config | Yes (one-line install) | Requires manual setup | Requires account | Requires discipline |
| Works offline | Yes | Yes | No (cloud service) | Yes |

## Frequently Asked Security Questions

**Q: Can Claude figure out the real secret from the placeholder?**

No. The placeholder suffix is derived via HMAC-SHA256, which is a one-way
function. Even if Claude sees `{{OPENAI_KEY_a1b2c3d4}}`, it cannot reverse
`a1b2c3d4` back to the original key. The placeholder name (`OPENAI_KEY`)
tells Claude the type of secret, but not its value.

**Q: Is the `cryptography` package required?**

No, but it is strongly recommended. Without it, the mapping file is stored as
plaintext JSON. It still has restricted file permissions (0600), which prevents
other users on the system from reading it. But if an attacker gains access to
your user account, they can read the plaintext mapping directly. With Fernet
encryption, they would also need the HMAC key.

**Q: What if two secrets produce the same HMAC hash (collision)?**

The hook detects hash collisions and appends an `x` character to the suffix
until the collision is resolved. In practice, with SHA-256 truncated to 8 hex
characters (32 bits), you would need approximately 65,000 secrets before a
collision becomes probable (birthday bound). The 10,000 entry limit provides
additional safety margin.

**Q: Can I audit what secrets have been detected?**

Enable debug mode (`REDACT_DEBUG=1`) to see which patterns matched during
each hook invocation. The mapping file itself contains all detected secrets
(encrypted), but you should not need to decrypt it manually.

**Q: Does this protect secrets in Claude's memory?**

No. Once Claude has read a redacted file, the placeholders are in its context
window. If Claude somehow inferred or guessed the real values from other context,
the hook cannot prevent that. The hook's job is to prevent Claude from seeing
the real values in the first place.
