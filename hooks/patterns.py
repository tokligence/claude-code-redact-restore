"""
Secret patterns for claude-code-redact-restore

Users can customize by editing this file or adding patterns to:
  ~/.claude/hooks/redact-patterns.py

Patterns sourced from 150+ providers via tokligence_guard and gitleaks.
"""

# ── Strategy 1: Block list ──────────────────────────────────────────────
# Files that should NEVER be read by Claude Code.
# Matched by checking if the file path ends with or contains the pattern.
BLOCKED_FILES = [
    ".env",
    ".env.local",
    ".env.production",
    ".env.staging",
    ".env.development",
    ".env.test",
    "credential.json",
    "credential.enc",
    "credentials.json",
    "secrets.yaml",
    "secrets.json",
    "secrets.toml",
    "secret.key",
    ".private",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    ".pem",
    ".p12",
    ".pfx",
    "keystore.jks",
    "service-account.json",
    "gcp-credentials.json",
    "aws-credentials",
    ".npmrc",            # often contains auth tokens
    ".pypirc",           # often contains auth tokens
    ".docker/config.json",
    ".git-credentials",
    ".netrc",
]

# ── Strategy 2: Secret patterns ─────────────────────────────────────────
# Each tuple is (name, regex_string).
# The regex MUST match the secret value itself (not context around it).
# Patterns are ordered by specificity: most specific first to avoid
# a generic pattern consuming a match before a specific one runs.
#
# IMPORTANT: These are compiled once at import time for performance.

SECRET_PATTERNS = [
    # ================================================================
    # AI / ML PROVIDERS
    # ================================================================

    # OpenAI (new format with T3BlbkFJ marker)
    ("OPENAI_KEY", r'sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}'),
    # OpenAI project key
    ("OPENAI_PROJECT_KEY", r'sk-proj-[A-Za-z0-9_-]{48,156}'),
    # OpenAI service account key
    ("OPENAI_SVCACCT_KEY", r'sk-svcacct-[A-Za-z0-9_-]{58,74}'),
    # OpenAI admin key
    ("OPENAI_ADMIN_KEY", r'sk-admin-[A-Za-z0-9_-]{58,74}'),
    # Anthropic
    ("ANTHROPIC_KEY", r'sk-ant-api03-[a-zA-Z0-9_\-]{93}AA'),
    ("ANTHROPIC_KEY_SHORT", r'sk-ant-[a-zA-Z0-9_\-]{32,100}'),
    # Groq
    ("GROQ_KEY", r'gsk_[a-zA-Z0-9]{52}'),
    # Perplexity
    ("PERPLEXITY_KEY", r'pplx-[a-zA-Z0-9]{48}'),
    # Hugging Face
    ("HUGGINGFACE_TOKEN", r'hf_[a-zA-Z0-9]{34,}'),
    # Replicate
    ("REPLICATE_TOKEN", r'r8_[a-zA-Z0-9]{37}'),
    # DeepSeek
    ("DEEPSEEK_KEY", r'sk-[a-f0-9]{48}'),
    # Google AI / Gemini / Firebase
    ("GCP_API_KEY", r'AIza[0-9A-Za-z_-]{35}'),

    # ================================================================
    # CLOUD PROVIDERS
    # ================================================================

    # AWS
    ("AWS_ACCESS_KEY", r'(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}'),
    ("AWS_SECRET_KEY", r'(?i)(?:aws)?_?(?:secret)?_?(?:access)?_?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40}["\']?'),
    ("AWS_SESSION_TOKEN", r'(?i)aws_?session_?token["\']?\s*[:=]\s*["\']?[A-Za-z0-9/+=]{100,}["\']?'),
    # Azure
    ("AZURE_STORAGE_KEY", r'(?i)(?:DefaultEndpointsProtocol|AccountKey)\s*=\s*[A-Za-z0-9+/=]{86,88}'),
    # DigitalOcean
    ("DIGITALOCEAN_PAT", r'dop_v1_[a-f0-9]{64}'),
    ("DIGITALOCEAN_OAUTH", r'doo_v1_[a-f0-9]{64}'),
    ("DIGITALOCEAN_REFRESH", r'dor_v1_[a-f0-9]{64}'),
    # Alibaba Cloud
    ("ALIBABA_ACCESS_KEY", r'LTAI[A-Za-z0-9]{20}'),
    # Tencent Cloud
    ("TENCENT_SECRET_ID", r'AKID[A-Za-z0-9]{32}'),

    # ================================================================
    # DEVOPS / CI-CD / PACKAGE REGISTRIES
    # ================================================================

    # GitHub
    ("GITHUB_PAT_CLASSIC", r'ghp_[A-Za-z0-9]{36}'),
    ("GITHUB_PAT_FINE", r'github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9]{59}'),
    ("GITHUB_OAUTH", r'gho_[A-Za-z0-9]{36}'),
    ("GITHUB_USER_TOKEN", r'ghu_[A-Za-z0-9]{36}'),
    ("GITHUB_SERVER_TOKEN", r'ghs_[A-Za-z0-9]{36}'),
    ("GITHUB_REFRESH_TOKEN", r'ghr_[A-Za-z0-9]{36,76}'),
    # GitLab
    ("GITLAB_PAT", r'glpat-[A-Za-z0-9_-]{20,}'),
    ("GITLAB_PIPELINE", r'glptt-[A-Za-z0-9_-]{40}'),
    ("GITLAB_RUNNER", r'glrt-[A-Za-z0-9_-]{20,}'),
    ("GITLAB_DEPLOY", r'gldt-[A-Za-z0-9_-]{20,}'),
    ("GITLAB_FEED", r'glft-[A-Za-z0-9_-]{20,}'),
    # Bitbucket
    ("BITBUCKET_TOKEN", r'ATBB[A-Za-z0-9_-]{32,}'),
    # npm
    ("NPM_TOKEN", r'npm_[A-Za-z0-9]{36}'),
    # PyPI
    ("PYPI_TOKEN", r'pypi-[A-Za-z0-9_-]{50,}'),
    # Docker Hub
    ("DOCKERHUB_PAT", r'dckr_pat_[A-Za-z0-9_-]{27,}'),
    # RubyGems
    ("RUBYGEMS_KEY", r'rubygems_[a-f0-9]{48}'),
    # NuGet
    ("NUGET_KEY", r'oy2[a-z0-9]{43}'),
    # Clojars
    ("CLOJARS_TOKEN", r'CLOJARS_[a-zA-Z0-9]{60}'),
    # Terraform Cloud
    ("TERRAFORM_TOKEN", r'[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9_-]{60,70}'),
    # HashiCorp Vault
    ("VAULT_TOKEN", r'hvs\.[a-zA-Z0-9_-]{24,}'),
    ("VAULT_BATCH_TOKEN", r'hvb\.[a-zA-Z0-9_-]{24,}'),
    # Pulumi
    ("PULUMI_TOKEN", r'pul-[a-f0-9]{40}'),
    # Grafana
    ("GRAFANA_CLOUD_TOKEN", r'glc_[A-Za-z0-9_-]{32,}'),
    ("GRAFANA_SERVICE_ACCT", r'glsa_[A-Za-z0-9_-]{32}_[A-Fa-f0-9]{8}'),
    # Doppler
    ("DOPPLER_TOKEN", r'dp\.pt\.[a-zA-Z0-9]{43}'),
    # Prefect
    ("PREFECT_TOKEN", r'pnu_[a-zA-Z0-9]{36}'),
    # Linear
    ("LINEAR_KEY", r'lin_api_[A-Za-z0-9]{40}'),
    # Scalingo
    ("SCALINGO_TOKEN", r'tk-us-[a-zA-Z0-9_-]{48}'),

    # ================================================================
    # PAYMENT PROCESSORS
    # ================================================================

    # Stripe
    ("STRIPE_SECRET_KEY", r'sk_live_[A-Za-z0-9]{24,}'),
    ("STRIPE_TEST_KEY", r'sk_test_[A-Za-z0-9]{24,}'),
    ("STRIPE_RESTRICTED_KEY", r'rk_live_[A-Za-z0-9]{24,}'),
    ("STRIPE_WEBHOOK_SECRET", r'whsec_[A-Za-z0-9]{32,}'),
    # Square
    ("SQUARE_ACCESS_TOKEN", r'sq0atp-[A-Za-z0-9_-]{22}'),
    ("SQUARE_OAUTH_SECRET", r'sq0csp-[A-Za-z0-9_-]{43}'),
    # PayPal / Braintree
    ("PAYPAL_BRAINTREE_TOKEN", r'access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}'),
    # Adyen
    ("ADYEN_KEY", r'AQE[a-zA-Z0-9]{100,}'),
    # Flutterwave
    ("FLUTTERWAVE_SECRET", r'FLWSECK(?:_TEST)?-[a-f0-9]{32}-X'),
    ("FLUTTERWAVE_PUBLIC", r'FLWPUBK(?:_TEST)?-[a-f0-9]{32}-X'),

    # ================================================================
    # COMMUNICATION / MESSAGING
    # ================================================================

    # Slack
    ("SLACK_BOT_TOKEN", r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}'),
    ("SLACK_USER_TOKEN", r'xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}'),
    ("SLACK_APP_TOKEN", r'xapp-[0-9]+-[A-Za-z0-9]+-[0-9]+-[a-zA-Z0-9]+'),
    ("SLACK_WEBHOOK", r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[a-zA-Z0-9]{20,30}'),
    # Discord
    ("DISCORD_BOT_TOKEN", r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}'),
    ("DISCORD_WEBHOOK", r'https://(?:discord\.com|discordapp\.com)/api/webhooks/[0-9]{17,20}/[a-zA-Z0-9_-]{60,70}'),
    # Twilio
    ("TWILIO_ACCOUNT_SID", r'AC[a-f0-9]{32}'),
    ("TWILIO_API_KEY", r'SK[a-fA-F0-9]{32}'),
    # SendGrid
    ("SENDGRID_KEY", r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'),
    # Mailchimp
    ("MAILCHIMP_KEY", r'[a-f0-9]{32}-us[0-9]{1,2}'),
    # Mailgun
    ("MAILGUN_KEY", r'key-[a-f0-9]{32}'),
    # Telegram
    ("TELEGRAM_BOT_TOKEN", r'\d{8,10}:[A-Za-z0-9_-]{35}'),
    # Microsoft Teams webhook
    ("TEAMS_WEBHOOK", r'https://[a-z0-9-]+\.webhook\.office\.com/webhookb2/[a-f0-9-]{36}@[a-f0-9-]{36}/IncomingWebhook/[a-f0-9]{32}/[a-f0-9-]{36}'),

    # ================================================================
    # DATABASE / STORAGE
    # ================================================================

    # Connection strings with passwords
    ("MONGODB_URL", r'mongodb(?:\+srv)?://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+'),
    ("POSTGRES_URL", r'postgres(?:ql)?://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+'),
    ("MYSQL_URL", r'mysql://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+'),
    ("REDIS_URL", r'rediss?://[^\s"\'<>]*:[^\s"\'<>@]+@[^\s"\'<>]+'),
    # PlanetScale
    ("PLANETSCALE_PASSWORD", r'pscale_pw_[A-Za-z0-9_-]{43}'),
    ("PLANETSCALE_TOKEN", r'pscale_tkn_[A-Za-z0-9_-]{43}'),
    ("PLANETSCALE_OAUTH", r'pscale_oauth_[A-Za-z0-9_-]{43}'),
    # Contentful
    ("CONTENTFUL_TOKEN", r'CFPAT-[a-zA-Z0-9_-]{43}'),

    # ================================================================
    # ANALYTICS / MONITORING
    # ================================================================

    # New Relic
    ("NEWRELIC_KEY", r'NRAK-[A-Z0-9]{27}'),
    ("NEWRELIC_BROWSER_KEY", r'NRJS-[a-f0-9]{19}'),
    # Sentry
    ("SENTRY_DSN", r'https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+'),
    ("SENTRY_AUTH_TOKEN", r'sntrys_[A-Za-z0-9_]{38,}'),
    # Dynatrace
    ("DYNATRACE_TOKEN", r'dt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}'),

    # ================================================================
    # AUTH PROVIDERS
    # ================================================================

    # 1Password
    ("ONEPASSWORD_SECRET_KEY", r'A3-[A-Z0-9]{6}-[A-Z0-9]{6}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}'),
    # Age encryption
    ("AGE_SECRET_KEY", r'AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}'),

    # ================================================================
    # OTHER SERVICES
    # ================================================================

    # Shopify
    ("SHOPIFY_ACCESS_TOKEN", r'shpat_[a-fA-F0-9]{32}'),
    ("SHOPIFY_CUSTOM_APP", r'shpca_[a-fA-F0-9]{32}'),
    ("SHOPIFY_PRIVATE_APP", r'shppa_[a-fA-F0-9]{32}'),
    ("SHOPIFY_SHARED_SECRET", r'shpss_[a-fA-F0-9]{32}'),
    # HubSpot
    ("HUBSPOT_PAT", r'pat-(?:na1|eu1)-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'),
    # Postman
    ("POSTMAN_KEY", r'PMAK-[A-Za-z0-9]{24}-[A-Za-z0-9]{34}'),
    # Infracost
    ("INFRACOST_KEY", r'ico-[A-Za-z0-9]{32}'),
    # EasyPost
    ("EASYPOST_KEY", r'EZAK[a-f0-9]{54}'),
    # JFrog
    ("JFROG_KEY", r'AKC[a-zA-Z0-9]{10,}'),
    # Duffel
    ("DUFFEL_TOKEN", r'duffel_(?:test|live)_[A-Za-z0-9_-]{43}'),
    # Readme
    ("README_KEY", r'rdme_[a-f0-9]{70}'),
    # Frame.io
    ("FRAMEIO_TOKEN", r'fio-u-[A-Za-z0-9_-]{64}'),
    # Typeform
    ("TYPEFORM_PAT", r'tfp_[a-zA-Z0-9_-]{44}_[a-zA-Z0-9_-]{14}'),

    # ================================================================
    # GIT CREDENTIALS (URLs with embedded tokens)
    # ================================================================

    ("GIT_URL_GITHUB_PAT", r'https://[^:]+:ghp_[a-zA-Z0-9]{36}@github\.com[^\s]*'),
    ("GIT_URL_GITLAB_PAT", r'https://[^:]+:glpat-[a-zA-Z0-9_-]{20,}@[a-z0-9.-]+[^\s]*'),
    ("GIT_URL_GENERIC", r'https://[a-zA-Z0-9._-]+:[a-zA-Z0-9_-]{20,}@(?:github|gitlab|bitbucket)\.[a-z]+[^\s]*'),

    # ================================================================
    # PRIVATE KEYS / TOKENS
    # ================================================================

    # Private key PEM blocks
    ("PRIVATE_KEY_BLOCK", r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'),
    # JWT tokens
    ("JWT_TOKEN", r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),

    # ================================================================
    # GENERIC PATTERNS (lower priority — listed last)
    # ================================================================

    # Generic key=value secrets (in env-like contexts)
    ("GENERIC_API_KEY", r'(?i)(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']?[A-Za-z0-9_-]{20,60}["\']?'),
    ("GENERIC_SECRET", r'(?i)(?:secret|password|passwd|pwd)["\']?\s*[:=]\s*["\']?[^\s"\']{10,60}["\']?'),
    # Base64 secrets in env-like contexts
    ("BASE64_SECRET", r'(?i)(?:KEY|SECRET|TOKEN|PASSWORD)\s*[:=]\s*[A-Za-z0-9+/]{40,}={0,2}'),
]
