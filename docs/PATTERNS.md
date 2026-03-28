# Secret Patterns Reference

> Claude Secret Shield — Complete pattern catalog
>
> 140 detection patterns + 36 blocked file types

---

## Blocked Files (36 types)

These files are blocked from being read by Claude entirely:

| Category | Files |
|----------|-------|
| Environment | `.env`, `.env.local`, `.env.production`, `.env.staging`, `.env.development`, `.env.test`, `.env.staging.local`, `.env.production.local` |
| Credentials | `credential.json`, `credential.enc`, `credentials.json`, `secrets.yaml`, `secrets.json`, `secrets.toml`, `secret.key`, `token.json`, `oauth-credentials.json` |
| SSH/Crypto | `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`, `.pem`, `.p12`, `.pfx`, `keystore.jks`, `.private` |
| Cloud | `service-account.json`, `gcp-credentials.json`, `aws-credentials`, `application-default-credentials.json`, `.kaggle/kaggle.json` |
| Package Registries | `.npmrc`, `.pypirc` |
| Other | `.docker/config.json`, `.git-credentials`, `.netrc` |

---

## Secret Patterns (140 patterns, 10 categories)

### AI / ML Providers (17 patterns)

| Pattern | Prefix | Provider | Example Format |
|---------|--------|----------|---------------|
| OPENAI_KEY | `sk-..T3Blb***..` | OpenAI | `sk-proj-{marker-redacted}` |
| OPENAI_PROJECT_KEY | `sk-proj-` | OpenAI | `sk-proj-{48-156 chars}` |
| OPENAI_SVCACCT_KEY | `sk-svcacct-` | OpenAI | `sk-svcacct-{58-74 chars}` |
| OPENAI_ADMIN_KEY | `sk-admin-` | OpenAI | `sk-admin-{58-74 chars}` |
| ANTHROPIC_KEY | `sk-ant-api03-` | Anthropic | `sk-ant-api03-{93 chars}AA` |
| ANTHROPIC_KEY_SHORT | `sk-ant-` | Anthropic | `sk-ant-{32-100 chars}` |
| GROQ_KEY | `gsk_` | Groq | `gsk_{52 chars}` |
| PERPLEXITY_KEY | `pplx-` | Perplexity | `pplx-{48 chars}` |
| HUGGINGFACE_TOKEN | `hf_` | Hugging Face | `hf_{34+ chars}` |
| REPLICATE_TOKEN | `r8_` | Replicate | `r8_{37 chars}` |
| DEEPSEEK_KEY | `sk-` + hex | DeepSeek | `sk-{48 hex chars}` |
| GCP_API_KEY | `AIza` | Google AI/Gemini | `AIza{35 chars}` |
| CO_API_KEY | `co-` | Cohere | `co-{40 chars}` |
| FIREWORKS_KEY | `fw_` | Fireworks AI | `fw_{40+ chars}` |
| LANGSMITH_KEY | `lsv2_pt_` | LangSmith | `lsv2_pt_{32 hex}_{10 hex}` |
| POSTHOG_TOKEN | `phx_` | PostHog | `phx_{40+ chars}` |
| PINECONE_KEY | `pcsk_` | Pinecone | `pcsk_{50+ chars}` |

### Cloud Providers (13 patterns)

| Pattern | Prefix | Provider |
|---------|--------|----------|
| AWS_ACCESS_KEY | `AKIA` / `ASIA` | AWS |
| AWS_SECRET_KEY | context-based | AWS |
| AWS_SESSION_TOKEN | context-based | AWS |
| AZURE_STORAGE_KEY | `AccountKey=` | Azure |
| AZURE_AD_SECRET | `~` + context | Azure AD |
| AZURE_SQL_CONN | `Password=` in conn string | Azure SQL |
| DIGITALOCEAN_PAT | `dop_v1_` | DigitalOcean |
| DIGITALOCEAN_OAUTH | `doo_v1_` | DigitalOcean |
| DIGITALOCEAN_REFRESH | `dor_v1_` | DigitalOcean |
| ALIBABA_ACCESS_KEY | `LTAI` | Alibaba Cloud |
| TENCENT_SECRET_ID | `AKID` | Tencent Cloud |
| GCP_SA_PRIVATE_KEY_ID | JSON context | GCP |
| IBM_CLOUD_KEY | context-based | IBM Cloud |

### DevOps / CI-CD / Package Registries (36 patterns)

| Pattern | Prefix | Provider |
|---------|--------|----------|
| GITHUB_PAT_CLASSIC | `ghp_` | GitHub |
| GITHUB_PAT_FINE | `github_pat_` | GitHub |
| GITHUB_OAUTH | `gho_` | GitHub |
| GITHUB_USER_TOKEN | `ghu_` | GitHub |
| GITHUB_SERVER_TOKEN | `ghs_` | GitHub |
| GITHUB_REFRESH_TOKEN | `ghr_` | GitHub |
| GITLAB_PAT | `glpat-` | GitLab |
| GITLAB_PIPELINE | `glptt-` | GitLab |
| GITLAB_RUNNER | `glrt-` | GitLab |
| GITLAB_DEPLOY | `gldt-` | GitLab |
| GITLAB_FEED | `glft-` | GitLab |
| BITBUCKET_TOKEN | `ATBB` | Bitbucket |
| NPM_TOKEN | `npm_` | npm |
| PYPI_TOKEN | `pypi-` | PyPI |
| DOCKERHUB_PAT | `dckr_pat_` | Docker Hub |
| RUBYGEMS_KEY | `rubygems_` | RubyGems |
| NUGET_KEY | `oy2` | NuGet |
| CLOJARS_TOKEN | `CLOJARS_` | Clojars |
| TERRAFORM_TOKEN | `.atlasv1.` | Terraform Cloud |
| VAULT_TOKEN | `hvs.` | HashiCorp Vault |
| VAULT_BATCH_TOKEN | `hvb.` | HashiCorp Vault |
| PULUMI_TOKEN | `pul-` | Pulumi |
| GRAFANA_CLOUD_TOKEN | `glc_` | Grafana |
| GRAFANA_SERVICE_ACCT | `glsa_` | Grafana |
| DOPPLER_TOKEN | `dp.pt.` | Doppler |
| PREFECT_TOKEN | `pnu_` | Prefect |
| LINEAR_KEY | `lin_api_` | Linear |
| SCALINGO_TOKEN | `tk-us-` | Scalingo |
| CIRCLECI_TOKEN | context-based | CircleCI |
| BUILDKITE_TOKEN | `bkua_` | Buildkite |
| FLYIO_TOKEN | `fo1_` | Fly.io |
| RENDER_TOKEN | `rnd_` | Render |
| SUPABASE_KEY | `sbp_` | Supabase |
| SONARQUBE_TOKEN | `sqp_` | SonarQube |
| DATABRICKS_TOKEN | `dapi` | Databricks |
| VERCEL_TOKEN | `vercel_` | Vercel |

### Payment Processors (12 patterns)

| Pattern | Prefix | Provider |
|---------|--------|----------|
| STRIPE_SECRET_KEY | `sk_live_` | Stripe |
| STRIPE_TEST_KEY | `sk_test_` | Stripe |
| STRIPE_RESTRICTED_KEY | `rk_live_` | Stripe |
| STRIPE_WEBHOOK_SECRET | `whsec_` | Stripe |
| SQUARE_ACCESS_TOKEN | `sq0atp-` | Square |
| SQUARE_OAUTH_SECRET | `sq0csp-` | Square |
| PAYPAL_BRAINTREE_TOKEN | `access_token$production$` | PayPal/Braintree |
| ADYEN_KEY | `AQE` | Adyen |
| FLUTTERWAVE_SECRET | `FLWSECK` | Flutterwave |
| FLUTTERWAVE_PUBLIC | `FLWPUBK` | Flutterwave |
| RAZORPAY_KEY | `rzp_live_` / `rzp_test_` | Razorpay |
| PLAID_TOKEN | `access-sandbox-` etc. | Plaid |

### Communication / Messaging (15 patterns)

| Pattern | Prefix | Provider |
|---------|--------|----------|
| SLACK_BOT_TOKEN | `xoxb-` | Slack |
| SLACK_USER_TOKEN | `xoxp-` | Slack |
| SLACK_APP_TOKEN | `xapp-` | Slack |
| SLACK_WEBHOOK | `hooks.slack.com` | Slack |
| DISCORD_BOT_TOKEN | `[MN]...` 3-part | Discord |
| DISCORD_WEBHOOK | `discord.com/api/webhooks` | Discord |
| TWILIO_ACCOUNT_SID | `AC` + hex | Twilio |
| TWILIO_API_KEY | `SK` + hex | Twilio |
| SENDGRID_KEY | `SG.` | SendGrid |
| MAILCHIMP_KEY | hex + `-us` | Mailchimp |
| MAILGUN_KEY | `key-` | Mailgun |
| TELEGRAM_BOT_TOKEN | digits + `:` | Telegram |
| TEAMS_WEBHOOK | `webhook.office.com` | MS Teams |
| INTERCOM_TOKEN | `dG9rO` (base64 "tok:") | Intercom |
| BREVO_KEY | `xkeysib-` | Brevo/Sendinblue |

### Database / Storage (8 patterns)

| Pattern | Format | Provider |
|---------|--------|----------|
| MONGODB_URL | `mongodb://user:pass@host` | MongoDB |
| POSTGRES_URL | `postgresql://user:pass@host` | PostgreSQL |
| MYSQL_URL | `mysql://user:pass@host` | MySQL |
| REDIS_URL | `redis://:pass@host` | Redis |
| PLANETSCALE_PASSWORD | `pscale_pw_` | PlanetScale |
| PLANETSCALE_TOKEN | `pscale_tkn_` | PlanetScale |
| PLANETSCALE_OAUTH | `pscale_oauth_` | PlanetScale |
| CONTENTFUL_TOKEN | `CFPAT-` | Contentful |

### Analytics / Monitoring (7 patterns)

| Pattern | Prefix | Provider |
|---------|--------|----------|
| NEWRELIC_KEY | `NRAK-` | New Relic |
| NEWRELIC_BROWSER_KEY | `NRJS-` | New Relic |
| SENTRY_DSN | `https://hex@*.ingest.sentry.io` | Sentry |
| SENTRY_AUTH_TOKEN | `sntrys_` | Sentry |
| DYNATRACE_TOKEN | `dt0c01.` | Dynatrace |
| DATADOG_KEY | `dd` + letter + hex | Datadog |
| LAUNCHDARKLY_KEY | `api-` / `sdk-` / `mob-` | LaunchDarkly |

### Auth Providers (3 patterns)

| Pattern | Prefix | Provider |
|---------|--------|----------|
| ONEPASSWORD_SECRET_KEY | `A3-` | 1Password |
| AGE_SECRET_KEY | `AGE-SECRET-KEY-1` | Age encryption |
| OKTA_TOKEN | `00` + alphanumeric | Okta |

### Other Services (24 patterns)

| Pattern | Prefix | Provider |
|---------|--------|----------|
| SHOPIFY_ACCESS_TOKEN | `shpat_` | Shopify |
| SHOPIFY_CUSTOM_APP | `shpca_` | Shopify |
| SHOPIFY_PRIVATE_APP | `shppa_` | Shopify |
| SHOPIFY_SHARED_SECRET | `shpss_` | Shopify |
| HUBSPOT_PAT | `pat-na1-` / `pat-eu1-` | HubSpot |
| POSTMAN_KEY | `PMAK-` | Postman |
| INFRACOST_KEY | `ico-` | Infracost |
| EASYPOST_KEY | `EZAK` | EasyPost |
| JFROG_KEY | `AKC` | JFrog |
| DUFFEL_TOKEN | `duffel_live_` / `duffel_test_` | Duffel |
| README_KEY | `rdme_` | Readme.com |
| FRAMEIO_TOKEN | `fio-u-` | Frame.io |
| TYPEFORM_PAT | `tfp_` | Typeform |
| AIRTABLE_PAT | `pat` + `.` + hex | Airtable |
| NOTION_TOKEN | `ntn_` | Notion |
| NOTION_SECRET | `secret_` | Notion |
| ASANA_PAT | `digit/13digits:32chars` | Asana |
| FIGMA_PAT | `figd_` | Figma |
| CONTENTSTACK_TOKEN | `cs` + alphanum | Contentstack |
| CLOUDFLARE_API_TOKEN | `v1.0-` | Cloudflare |
| ATLASSIAN_TOKEN | `ATATT` | Atlassian |

### Private Keys / Tokens (5 patterns)

| Pattern | Format | What |
|---------|--------|------|
| PRIVATE_KEY_BLOCK | `-----BEGIN...PRIVATE KEY-----` | PEM private key header |
| JWT_TOKEN | `eyJ...eyJ...` | JSON Web Token (3 parts) |
| GIT_URL_GITHUB_PAT | `https://user:ghp_@github.com` | GitHub PAT in Git URL |
| GIT_URL_GITLAB_PAT | `https://user:glpat-@gitlab.com` | GitLab PAT in Git URL |
| GIT_URL_GENERIC | `https://user:token@host` | Generic token in Git URL |

### Generic Patterns (3 patterns, lowest priority)

| Pattern | Context | What |
|---------|---------|------|
| GENERIC_API_KEY | `api_key=`, `apikey:` | Generic API key assignment |
| GENERIC_SECRET | `password=`, `secret:` | Generic secret assignment |
| BASE64_SECRET | `SECRET=`, `TOKEN:` + base64 | Base64-encoded secret in assignment |

---

## Pattern Selection Criteria

We only include patterns that meet these criteria:

1. **Distinctive prefix** — The pattern has a unique prefix (e.g., `ghp_`, `sk-ant-`, `AKIA`) that minimizes false positives
2. **Sufficient length** — Minimum token length prevents matching common strings
3. **Specific character set** — The regex constrains to the actual character set used by the provider

We explicitly **exclude** patterns that:
- Are just UUID format (too many false positives)
- Require multi-field context without a distinctive prefix
- Match common strings like 32-char hex without context
- Conflict with other patterns (e.g., Mapbox `sk.` vs OpenAI `sk-`)

## Adding Custom Patterns

Create `~/.claude/hooks/custom-patterns.py`:

```python
CUSTOM_SECRET_PATTERNS = [
    ("MY_INTERNAL_TOKEN", r'mycompany_[a-zA-Z0-9]{32}'),
]

CUSTOM_BLOCKED_FILES = [
    "internal-secrets.yaml",
]
```
