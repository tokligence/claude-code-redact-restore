"""
Secret patterns for claude-secret-shield

Users can customize by editing this file or adding patterns to:
  ~/.claude/hooks/redact-patterns.py

183 secret patterns + 48 blocked files, sourced from 200+ providers
via tokligence_guard, gitleaks, and GitHub secret scanning coverage.

March 2026 additions: LangSmith, PostHog, Pinecone, Vercel, Atlassian, Brevo.
April 2026 additions: Web3 wallet private keys, mnemonics, Infura, Alchemy.
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
    ".aws/credentials",
    ".aws/config",
    ".aws/cli/cache",
    ".aws/sso/cache",
    ".npmrc",            # often contains auth tokens
    ".pypirc",           # often contains auth tokens
    ".docker/config.json",
    ".git-credentials",
    ".netrc",
    ".env.staging.local",
    ".env.production.local",
    "token.json",
    "oauth-credentials.json",
    ".kaggle/kaggle.json",
    "application-default-credentials.json",
    # Web3 / Crypto wallet files that almost certainly contain secrets
    "mnemonic.txt",
    ".secret",
    # NOTE: hardhat.config.js/ts, truffle-config.js, foundry.toml, brownie-config.yaml
    # are NOT blocked — they are scanned and redacted instead, since modern configs
    # rarely embed secrets directly (they use process.env or .env files).
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
    # Cohere
    ("CO_API_KEY", r'co-[a-zA-Z0-9]{40}'),
    # Fireworks AI
    ("FIREWORKS_KEY", r'fw_[a-zA-Z0-9]{40,}'),
    # LangSmith (March 2026 GitHub secret scanning)
    ("LANGSMITH_KEY", r'lsv2_pt_[a-f0-9]{32}_[a-f0-9]{10}'),
    # PostHog (March 2026 GitHub secret scanning)
    ("POSTHOG_TOKEN", r'phx_[a-zA-Z0-9]{40,}'),
    # Pinecone (March 2026 GitHub secret scanning)
    ("PINECONE_KEY", r'pcsk_[a-zA-Z0-9_-]{50,}'),
    # Google AI / Gemini / Firebase
    ("GCP_API_KEY", r'AIza[0-9A-Za-z_-]{35}'),

    # ================================================================
    # CLOUD PROVIDERS
    # ================================================================

    # AWS — credentials
    ("AWS_ACCESS_KEY", r'(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}'),
    ("AWS_SECRET_KEY", r'(?i)(?:aws_?secret_?access_?key|secret_?access_?key|SecretAccessKey)["\']?\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40}["\']?'),
    ("AWS_SESSION_TOKEN", r'(?i)(?:aws_?session_?token|aws_?security_?token|session_?token|security_?token|SessionToken)["\']?\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40,}["\']?'),
    # AWS — resource ARNs (account ID + resource name leak org structure and naming conventions)
    # Matches: arn:aws:secretsmanager:region:123456789012:secret:my/path-suffix
    ("AWS_SECRETSMANAGER_ARN", r'arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:\d{12}:secret:[A-Za-z0-9/_+=.@!\-]+'),
    # Matches: arn:aws:rds:region:123456789012:cluster:name  or  cluster-snapshot:name
    ("AWS_RDS_ARN", r'arn:aws[a-z-]*:rds:[a-z0-9-]+:\d{12}:(?:cluster|cluster-snapshot|db|snapshot|cluster-endpoint):[A-Za-z0-9_!:/\-]+'),
    # Matches: arn:aws:kms:region:123456789012:key/uuid  or  alias/name
    ("AWS_KMS_ARN", r'arn:aws[a-z-]*:kms:[a-z0-9-]+:\d{12}:(?:key|alias)/[A-Za-z0-9_/\-]+'),
    # Matches: arn:aws:iam::123456789012:role/path/name  or  user/name  or  policy/name
    ("AWS_IAM_ARN", r'arn:aws[a-z-]*:iam::\d{12}:(?:role|user|policy|instance-profile|group|saml-provider|oidc-provider|server-certificate)[/:][A-Za-z0-9+=,.@_/\-]+'),
    # Matches: arn:aws:s3:::bucket-name/key (no region, no account)
    ("AWS_S3_ARN", r'arn:aws[a-z-]*:s3:::[a-z0-9.\-]{3,63}(?:/[A-Za-z0-9_!.*\'()/\-]*)?'),
    # Matches: arn:aws:lambda:region:123456789012:function:name
    ("AWS_LAMBDA_ARN", r'arn:aws[a-z-]*:lambda:[a-z0-9-]+:\d{12}:function:[A-Za-z0-9_\-]+(?::\$LATEST|:[A-Za-z0-9_\-]+)?'),
    # Matches: arn:aws:ecs:region:123456789012:task-definition/name:revision  / cluster/name / service/cluster/name
    ("AWS_ECS_ARN", r'arn:aws[a-z-]*:ecs:[a-z0-9-]+:\d{12}:(?:task-definition|cluster|service|task|container-instance)/[A-Za-z0-9_/\-]+(?::\d+)?'),
    # Generic ARN catchall (account ID is the sensitive bit)
    ("AWS_GENERIC_ARN", r'arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[A-Za-z0-9_/:.@*\-]+'),
    # Bare account ID in AWS contexts (12 digits after account-id label)
    ("AWS_ACCOUNT_ID", r'(?i)(?:aws[_-]?account[_-]?(?:id|number)|caller[_-]?account|aws[_-]?owner[_-]?id)["\']?\s*[:=]\s*["\']?\d{12}["\']?'),
    # ECR registry URI: 123456789012.dkr.ecr.region.amazonaws.com
    ("AWS_ECR_REGISTRY", r'\d{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com(?:/[A-Za-z0-9_/.\-]+)?'),
    # RDS endpoint: cluster-id.cluster-xxx.region.rds.amazonaws.com  (cluster-xxx is the resource id, leaks)
    ("AWS_RDS_ENDPOINT", r'[a-z0-9-]+\.cluster-[a-z0-9]+\.[a-z0-9-]+\.rds\.amazonaws\.com(?::\d+)?'),
    # Azure
    ("AZURE_STORAGE_KEY", r'(?i)(?:DefaultEndpointsProtocol|AccountKey)\s*=\s*[A-Za-z0-9+/=]{86,88}'),
    # Azure resource IDs (subscription ID + resource group + name leak structure)
    ("AZURE_RESOURCE_ID", r'/subscriptions/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/resourceGroups/[A-Za-z0-9_\-.()]+(?:/providers/[A-Za-z0-9_/.\-]+)?'),
    ("AZURE_SUBSCRIPTION_ID", r'(?i)(?:subscription[_-]?id|azure[_-]?sub(?:scription)?)["\']?\s*[:=]\s*["\']?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}["\']?'),
    ("AZURE_TENANT_ID", r'(?i)(?:tenant[_-]?id|azure[_-]?tenant|aad[_-]?tenant)["\']?\s*[:=]\s*["\']?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}["\']?'),
    ("AZURE_KEYVAULT_URI", r'https://[a-z0-9\-]+\.vault\.azure\.net(?:/[A-Za-z0-9/_\-]+)?'),
    ("AZURE_STORAGE_URL", r'https://[a-z0-9]{3,24}\.(?:blob|file|queue|table|dfs)\.core\.windows\.net(?:/[A-Za-z0-9/_\-]*)?'),
    # DigitalOcean
    ("DIGITALOCEAN_PAT", r'dop_v1_[a-f0-9]{64}'),
    ("DIGITALOCEAN_OAUTH", r'doo_v1_[a-f0-9]{64}'),
    ("DIGITALOCEAN_REFRESH", r'dor_v1_[a-f0-9]{64}'),
    # Alibaba Cloud
    ("ALIBABA_ACCESS_KEY", r'LTAI[A-Za-z0-9]{20}'),
    # Tencent Cloud
    ("TENCENT_SECRET_ID", r'AKID[A-Za-z0-9]{32}'),
    # GCP service account private key id
    ("GCP_SA_PRIVATE_KEY_ID", r'"private_key_id"\s*:\s*"[a-f0-9]{40}"'),
    # GCP resource paths (project ID + resource leak structure)
    ("GCP_SECRET_NAME", r'projects/[a-z][a-z0-9\-]{4,28}[a-z0-9]/' + 'secrets' + r'/[A-Za-z0-9_\-]+(?:/versions/[a-zA-Z0-9_\-]+)?'),
    ("GCP_KMS_KEY", r'projects/[a-z][a-z0-9\-]{4,28}[a-z0-9]/locations/[a-z0-9\-]+/keyRings/[A-Za-z0-9_\-]+/cryptoKeys/[A-Za-z0-9_\-]+(?:/cryptoKeyVersions/\d+)?'),
    ("GCP_SA_EMAIL", r'[a-z][a-z0-9\-]{4,28}[a-z0-9]@[a-z][a-z0-9\-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com'),
    ("GCP_PROJECT_ID", r'(?i)(?:gcp[_-]?project[_-]?id|google[_-]?project[_-]?id|gcloud[_-]?project)["\']?\s*[:=]\s*["\']?[a-z][a-z0-9\-]{4,28}[a-z0-9]["\']?'),
    # Azure AD app secret
    ("AZURE_AD_SECRET", r'(?i)(?:azure|ad|aad)[_-]?(?:client)?[_-]?secret["\']?\s*[:=]\s*["\']?~[A-Za-z0-9_~.-]{34}["\']?'),
    # Azure SQL connection string
    ("AZURE_SQL_CONN", r'(?i)Server=.*\.database\.windows\.net.*Password=[^;]+'),
    # IBM Cloud API key
    ("IBM_CLOUD_KEY", r'(?i)ibm[_-]?(?:cloud)?[_-]?api[_-]?key["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_-]{44}["\']?'),

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
    # CircleCI
    ("CIRCLECI_TOKEN", r'(?i)(?:circle[_-]?ci[_-]?token|CIRCLE_TOKEN)["\']?\s*[:=]\s*["\']?[a-f0-9]{40}["\']?'),
    # Buildkite
    ("BUILDKITE_TOKEN", r'bkua_[a-zA-Z0-9]{40}'),
    # Fly.io
    ("FLYIO_TOKEN", r'fo1_[a-zA-Z0-9_-]{43}'),
    # Render
    ("RENDER_TOKEN", r'rnd_[a-zA-Z0-9]{32,}'),
    # Vercel (March 2026 GitHub secret scanning)
    ("VERCEL_TOKEN", r'vercel_[a-zA-Z0-9]{24,}'),
    # Supabase service key
    ("SUPABASE_KEY", r'sbp_[a-f0-9]{40}'),
    # SonarQube
    ("SONARQUBE_TOKEN", r'sqp_[a-f0-9]{40}'),
    # Databricks
    ("DATABRICKS_TOKEN", r'dapi[a-f0-9]{32}'),

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
    # Razorpay
    ("RAZORPAY_KEY", r'rzp_(?:live|test)_[a-zA-Z0-9]{14}'),
    # Plaid
    ("PLAID_TOKEN", r'(?:access|client|secret|public)-(?:sandbox|development|production)-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'),

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
    # Lark / Feishu group bot webhooks
    ("LARK_WEBHOOK", r'https://(?:open\.larksuite\.com|open\.feishu\.cn)/open-apis/bot/v2/hook/[A-Za-z0-9_-]{20,}'),
    ("LARK_WEBHOOK_SECRET", r'(?i)(?:lark|feishu)[_-]?(?:webhook[_-]?)?secret["\']?\s*[:=]\s*["\']?[A-Za-z0-9+/=_-]{16,}["\']?'),
    # Microsoft Teams webhook
    ("TEAMS_WEBHOOK", r'https://[a-z0-9-]+\.webhook\.office\.com/webhookb2/[a-f0-9-]{36}@[a-f0-9-]{36}/IncomingWebhook/[a-f0-9]{32}/[a-f0-9-]{36}'),
    # Brevo/Sendinblue (March 2026)
    ("BREVO_KEY", r'xkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}'),
    # Intercom (base64 tok: prefix)
    ("INTERCOM_TOKEN", r'dG9rO[a-zA-Z0-9_-]{36,}='),

    # ================================================================
    # DATABASE / STORAGE
    # ================================================================

    # Connection strings with passwords
    ("MONGODB_URL", r'mongodb(?:\+srv)?://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+'),
    ("POSTGRES_URL", r'postgres(?:ql)?(?:\+[a-z0-9_]+)?://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+'),
    ("MYSQL_URL", r'mysql(?:\+[a-z0-9_]+)?://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+'),
    # MSSQL (SQL Server)
    ("MSSQL_URL", r'mssql(?:\+[a-z0-9_]+)?://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+'),
    # Oracle
    ("ORACLE_URL", r'oracle(?:\+[a-z0-9_]+)?://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+'),
    # CockroachDB (uses cockroachdb:// scheme)
    ("COCKROACHDB_URL", r'cockroachdb(?:\+[a-z0-9_]+)?://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+'),
    # MariaDB (explicit scheme, not just mysql://)
    ("MARIADB_URL", r'mariadb(?:\+[a-z0-9_]+)?://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+'),
    # TiDB (uses mysql protocol but has tidb:// scheme in some tools)
    ("TIDB_URL", r'tidb(?:\+[a-z0-9_]+)?://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+'),
    # ClickHouse
    ("CLICKHOUSE_URL", r'clickhouse(?:\+[a-z0-9_]+)?://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+'),
    # DB2
    ("DB2_URL", r'db2(?:\+[a-z0-9_]+)?://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+'),
    # SAP HANA
    ("HANA_URL", r'hana(?:\+[a-z0-9_]+)?://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+'),
    # Firebird
    ("FIREBIRD_URL", r'firebird(?:\+[a-z0-9_]+)?://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+'),
    # SQL Server (sqlserver:// scheme, different from mssql+pyodbc://)
    ("SQLSERVER_URL", r'sqlserver://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>;]+'),
    # Snowflake
    ("SNOWFLAKE_URL", r'snowflake://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+'),
    # Amazon Redshift
    ("REDSHIFT_URL", r'redshift(?:\+[a-z0-9_]+)?://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+'),
    # Cassandra / ScyllaDB
    ("CASSANDRA_URL", r'(?:cassandra|scylla)(?:\+[a-z0-9_]+)?://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+'),
    # Neo4j / Bolt
    ("NEO4J_URL", r'(?:neo4j|bolt)(?:\+[a-z]+)?://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+'),
    # CouchDB
    ("COUCHDB_URL", r'couchdb://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+'),
    # ArangoDB
    ("ARANGODB_URL", r'arangodb://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+'),
    # AMQP / RabbitMQ
    ("AMQP_URL", r'amqps?://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+'),
    # NATS
    ("NATS_URL", r'nats://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+'),
    # MQTT
    ("MQTT_URL", r'mqtts?://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+'),
    # STOMP
    ("STOMP_URL", r'stomp://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+'),
    # Databricks
    ("DATABRICKS_URL", r'databricks://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+'),
    # FTP / SFTP
    ("FTP_URL", r's?ftp://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+'),
    # LDAP
    ("LDAP_URL", r'ldaps?://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+'),
    # Generic HTTP(S) with user:password@ (catches ES, OpenSearch, CouchDB, ArangoDB, ClickHouse HTTP, etc.)
    ("HTTP_BASIC_AUTH_URL", r'https?://[a-zA-Z0-9._-]+:[^\s"\'<>@]+@[^\s"\'<>]+'),
    ("REDIS_URL", r'rediss?://[^\s"\'<>]*:[^\s"\'<>@]+@[^\s"\'<>]+'),
    ("REDIS_AUTH_TOKEN", r'(?i)(?:redis[_-]?(?:auth[_-]?)?token|requirepass)["\']?\s*[:=]\s*["\']?[A-Za-z0-9+/=_-]{16,}["\']?'),
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
    # Datadog
    ("DATADOG_KEY", r'dd[a-z]{1}[a-f0-9]{40}'),
    # LaunchDarkly
    ("LAUNCHDARKLY_KEY", r'(?:api|sdk|mob)-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'),

    # ================================================================
    # AUTH PROVIDERS
    # ================================================================

    # 1Password
    ("ONEPASSWORD_SECRET_KEY", r'A3-[A-Z0-9]{6}-[A-Z0-9]{6}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}'),
    # Age encryption
    ("AGE_SECRET_KEY", r'AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}'),
    # Okta
    ("OKTA_TOKEN", r'00[a-zA-Z0-9_-]{40}'),

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
    # Airtable
    ("AIRTABLE_PAT", r'pat[a-zA-Z0-9]{14}\.[a-f0-9]{64}'),
    # Notion
    ("NOTION_TOKEN", r'ntn_[a-zA-Z0-9]{43,}'),
    ("NOTION_SECRET", r'secret_[a-zA-Z0-9]{43,}'),
    # Asana
    ("ASANA_PAT", r'[0-9]{1}/[0-9]{13}:[a-zA-Z0-9]{32}'),
    # Figma
    ("FIGMA_PAT", r'figd_[a-zA-Z0-9_-]{40,}'),
    # Contentstack
    ("CONTENTSTACK_TOKEN", r'cs[a-z0-9]{35}'),
    # Atlassian API token (March 2026)
    ("ATLASSIAN_TOKEN", r'ATATT[a-zA-Z0-9_-]{60,}'),
    # Cloudflare API token
    ("CLOUDFLARE_API_TOKEN", r'v1\.0-[a-f0-9]{24}-[a-f0-9]{146}'),

    # ================================================================
    # WEB3 / CRYPTO WALLETS
    # ================================================================

    # Ethereum / EVM private key — context-based to avoid matching tx hashes, addresses, etc.
    # Matches: private_key = "0x...", privateKey: "0x...", wallet_secret=0x..., etc.
    # Prefix \w*[_-]? captures the full variable name (e.g., DEPLOYER_PRIVATE_KEY) so this
    # pattern is at least as long as HEX_CREDENTIAL and wins the overlap resolution.
    ("WALLET_PRIVATE_KEY", r'(?i)\w*[_-]?(?:private[_-]?key|secret[_-]?key|wallet[_-]?(?:secret|private|key)|sign(?:ing|er)[_-]?key|deployer[_-]?key|owner[_-]?key|account[_-]?key|eth(?:ereum)?[_-]?(?:private[_-]?)?key|hot[_-]?wallet[_-]?key|cold[_-]?wallet[_-]?key)["\']?\s*[:=]\s*["\']?(?:0x)?[a-fA-F0-9]{64}["\']?'),
    # Context-based catch-all: quoted 0x+64hex in an assignment (e.g. key = "0xabc...")
    ("HEX_CREDENTIAL", r'(?i)(?:\w+)["\']?\s*[:=]\s*["\']0x[a-fA-F0-9]{64}["\']'),
    # Bare catch-all: any 0x+64hex without context. Catches raw pastes in prompts.
    # In file scanning, auto-suppressed if >3 matches per file (likely tx hashes / bytes32).
    ("HEX_CREDENTIAL_BARE", r'\b0x[a-fA-F0-9]{64}\b'),
    # BIP39 mnemonic / seed phrase — context-based to avoid matching normal English text
    ("WALLET_MNEMONIC", r'(?i)(?:mnemonic|seed[_-]?phrase|recovery[_-]?phrase|hd[_-]?wallet|wallet[_-]?words|secret[_-]?phrase|backup[_-]?phrase)["\']?\s*[:=]\s*["\']?[a-z]+(?:\s+[a-z]+){11,23}["\']?'),
    # Bitcoin WIF (Wallet Import Format) — distinctive prefix makes it low false-positive
    # 51 chars for uncompressed (5-prefix), 52 chars for compressed (K/L-prefix)
    ("BTC_PRIVATE_KEY", r'\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b'),
    # Solana private key (base58-encoded 64-byte keypair, 87-88 chars)
    # Context-based to avoid matching other base58 strings
    ("SOLANA_PRIVATE_KEY", r'(?i)(?:solana[_-]?(?:private[_-]?)?key|sol[_-]?(?:private[_-]?)?key|solana[_-]?keypair|phantom[_-]?key)["\']?\s*[:=]\s*["\']?[1-9A-HJ-NP-Za-km-z]{87,88}["\']?'),
    # Infura API key (context-based)
    ("INFURA_KEY", r'(?i)(?:infura[_-]?(?:api[_-]?)?(?:key|token|id|secret)|infura[_-]?project[_-]?(?:id|secret))["\']?\s*[:=]\s*["\']?[a-f0-9]{32}["\']?'),
    # Infura RPC endpoint URL — HTTP and WebSocket (most common leak vector for Infura keys)
    ("INFURA_URL", r'(?:https?|wss?)://[a-z0-9-]+\.infura\.io/(?:v3|ws/v3)/[a-f0-9]{32}'),
    # Alchemy API key (context-based)
    ("ALCHEMY_KEY", r'(?i)(?:alchemy[_-]?(?:api[_-]?)?(?:key|token|secret))["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_-]{32,}["\']?'),
    # Alchemy RPC endpoint URL — HTTP and WebSocket (most common leak vector for Alchemy keys)
    ("ALCHEMY_URL", r'(?:https?|wss?)://[a-z0-9-]+\.(?:g\.)?alchemy\.com/v2/[a-zA-Z0-9_-]{32,}'),
    # Etherscan API key (context-based)
    ("ETHERSCAN_KEY", r'(?i)(?:etherscan[_-]?(?:api[_-]?)?key|(?:bsc|polygon|arb|ftm|optimism)scan[_-]?(?:api[_-]?)?key)["\']?\s*[:=]\s*["\']?[a-zA-Z0-9]{34}["\']?'),
    # Ankr RPC endpoint URL
    ("ANKR_URL", r'https://rpc\.ankr\.com/[a-z0-9_-]+/[a-f0-9]{64}'),
    # QuickNode RPC endpoint URL
    ("QUICKNODE_URL", r'(?:https?|wss?)://[a-z0-9-]+\.(?:[a-z]+-)?quiknode\.pro/[a-f0-9]{40,}'),

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
    ("JWT_SECRET", r'(?i)jwt[_-]?secret["\']?\s*[:=]\s*["\']?[A-Za-z0-9+/=_-]{24,}["\']?'),

    # ================================================================
    # DATABASE / CACHE CONNECTION STRINGS (with embedded password)
    # ================================================================

    # Postgres / MySQL / Mongo / Redis URIs with inline credentials —
    # common in env files, DB row dumps, log output, error tracebacks.
    ("POSTGRES_URI_WITH_PWD", r'postgres(?:ql)?://[^:\s]+:[^@\s]{4,}@[^/\s]+'),
    ("MYSQL_URI_WITH_PWD",    r'mysql://[^:\s]+:[^@\s]{4,}@[^/\s]+'),
    ("MONGODB_URI_WITH_PWD",  r'mongodb(?:\+srv)?://[^:\s]+:[^@\s]{4,}@[^/\s]+'),
    ("REDIS_URI_WITH_AUTH",   r'rediss?://[^:\s]*:[^@\s]{4,}@[^/\s]+'),

    # ================================================================
    # KYC / IDENTITY PROVIDER TOKENS
    # ================================================================

    # Sumsub KYC token — `sbx:` sandbox or `prd:` production prefix.
    ("SUMSUB_TOKEN", r'(?:sbx|prd):[a-zA-Z0-9_-]+\.[a-zA-Z0-9]+'),

    # ================================================================
    # PII / PERSONAL DATA
    # ================================================================

    # Bare email addresses with high-value TLDs (.ai, .org, gmail.com) — always PII regardless of context
    ("EMAIL_AI_DOMAIN", r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9-]+\.ai\b'),
    ("EMAIL_GMAIL", r'[a-zA-Z0-9._%+-]+@gmail\.com\b'),
    ("EMAIL_ORG_DOMAIN", r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9-]+\.org\b'),

    # Email addresses in config/env assignment context (not in comments, docs, git, mailto)
    ("EMAIL_IN_CONFIG", r'(?i)(?<![a-z])(?:e?mail(?:_(?:user(?:name)?|from|to|address|sender|recipient|account))|smtp_?(?:user(?:name)?|from|sender)|(?:from|to|contact|user|admin|notify|reply)_e?mail|sendgrid_(?:from|to|sender)|mail_(?:from|user(?:name)?|sender|address)|email)["\'\']?\s*[:=]\s*["\'\']?[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}["\'\']?'),

    # ================================================================
    # GENERIC PATTERNS (lower priority — listed last)
    # ================================================================

    # Generic key=value secrets (in env-like contexts)
    ("GENERIC_API_KEY", r'(?i)(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']?[A-Za-z0-9_-]{20,60}["\']?'),
    ("GENERIC_SECRET", r'(?i)(?:secret|password|passwd|pwd)["\']?\s*[:=]\s*["\']?[^\s"\']{10,80}["\']?'),
    # Base64 secrets in env-like contexts
    ("BASE64_SECRET", r'(?i)(?:KEY|SECRET|TOKEN|PASSWORD)\s*[:=]\s*[A-Za-z0-9+/]{40,}={0,2}'),
]
