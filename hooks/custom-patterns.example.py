# Custom secret patterns for claude-secret-shield
# Copy this file to ~/.claude/hooks/custom-patterns.py and add your patterns.
# This file is NEVER overwritten by install.sh upgrades.

CUSTOM_SECRET_PATTERNS = [
    # ("PATTERN_NAME", r"regex_pattern_here"),
    # Example:
    # ("MY_INTERNAL_TOKEN", r"mycompany_tok_[A-Za-z0-9]{32,}"),
]

CUSTOM_BLOCKED_FILES = [
    # "my-secret-config.yaml",
]
