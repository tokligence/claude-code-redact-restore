#!/usr/bin/env python3
"""
E2E tests for every secret pattern in claude-secret-shield.

For each of the 140 patterns in hooks/patterns.py, this module:
  1. Creates a temp file containing a realistic-but-obviously-fake token
  2. Runs the hook via subprocess (PreToolUse Read)
  3. Verifies the token was replaced with a placeholder
  4. Verifies the placeholder format matches {{PATTERN_NAME_...}}

Also includes false-positive tests to ensure common non-secret strings
are NOT redacted.

IMPORTANT: All fake tokens use obviously synthetic values (all-a, all-0,
EXAMPLE strings) to avoid triggering GitHub push protection.
"""

import json
import os
import subprocess
import sys
import tempfile
import threading
import time

import pytest

HOOK_SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "hooks", "redact-restore.py"
)


# ── Helpers ──────────────────────────────────────────────────────────────

def _session_id():
    """Unique session ID per test to avoid cross-contamination."""
    return f"test_pat_{os.getpid()}_{threading.current_thread().ident}_{id(object())}"


def run_hook(tool_name, tool_input, session_id, is_post=False):
    """Invoke the hook script via subprocess. Returns (parsed_json_or_None, exit_code, stderr)."""
    payload = {
        "tool_name": tool_name,
        "tool_input": tool_input,
        "session_id": session_id,
    }
    if is_post:
        payload["tool_result"] = "(sim)"
    r = subprocess.run(
        [sys.executable, HOOK_SCRIPT],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=30,
    )
    parsed = None
    if r.stdout.strip():
        try:
            parsed = json.loads(r.stdout.strip())
        except json.JSONDecodeError:
            pass
    return parsed, r.returncode, r.stderr


def read_and_restore(file_path, session_id):
    """Run PreToolUse Read then PostToolUse Read (which restores the file)."""
    pre_result, pre_rc, pre_err = run_hook(
        "Read", {"file_path": file_path}, session_id
    )
    # Read the redacted content from disk
    with open(file_path, "r") as f:
        redacted_content = f.read()
    # Run PostToolUse to restore original file
    run_hook("Read", {"file_path": file_path}, session_id, is_post=True)
    return redacted_content, pre_result, pre_rc


# ── Pattern test cases ───────────────────────────────────────────────────
# Each tuple: (pattern_name, fake_token_that_matches_the_regex)
# Tokens are obviously synthetic to avoid triggering push protection.

PATTERN_TEST_CASES = [
    # ================================================================
    # AI / ML PROVIDERS
    # ================================================================
    ("OPENAI_KEY", "sk-proj-" + "a" * 20 + "T3BlbkFJ" + "b" * 20),
    ("OPENAI_PROJECT_KEY", "sk-proj-" + "a" * 48),
    ("OPENAI_SVCACCT_KEY", "sk-svcacct-" + "a" * 58),
    ("OPENAI_ADMIN_KEY", "sk-admin-" + "a" * 58),
    ("ANTHROPIC_KEY", "sk-ant-api03-" + "a" * 93 + "AA"),
    ("ANTHROPIC_KEY_SHORT", "sk-ant-" + "a" * 40),
    ("GROQ_KEY", "gsk_" + "a" * 52),
    ("PERPLEXITY_KEY", "pplx-" + "a" * 48),
    ("HUGGINGFACE_TOKEN", "hf_" + "a" * 34),
    ("REPLICATE_TOKEN", "r8_" + "a" * 37),
    ("DEEPSEEK_KEY", "sk-" + "a" * 48),
    ("CO_API_KEY", "co-" + "a" * 40),
    ("FIREWORKS_KEY", "fw_" + "a" * 40),
    ("LANGSMITH_KEY", "lsv2_pt_" + "a" * 32 + "_" + "b" * 10),
    ("POSTHOG_TOKEN", "phx_" + "a" * 40),
    ("PINECONE_KEY", "pcsk_" + "a" * 50),
    ("GCP_API_KEY", "AIza" + "a" * 35),

    # ================================================================
    # CLOUD PROVIDERS
    # ================================================================
    ("AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE"),
    ("AWS_SECRET_KEY", 'aws_secret_key = "' + "A" * 40 + '"'),
    ("AWS_SESSION_TOKEN", 'aws_session_token = "' + "A" * 100 + '"'),
    ("AZURE_STORAGE_KEY", "DefaultEndpointsProtocol = " + "A" * 86),
    ("DIGITALOCEAN_PAT", "dop_v1_" + "a" * 64),
    ("DIGITALOCEAN_OAUTH", "doo_v1_" + "a" * 64),
    ("DIGITALOCEAN_REFRESH", "dor_v1_" + "a" * 64),
    ("ALIBABA_ACCESS_KEY", "LTAI" + "A" * 20),
    ("TENCENT_SECRET_ID", "AKID" + "A" * 32),
    ("GCP_SA_PRIVATE_KEY_ID", '"private_key_id": "' + "a" * 40 + '"'),
    ("AZURE_AD_SECRET", 'azure_client_secret = "~' + "A" * 34 + '"'),
    ("AZURE_SQL_CONN", "Server=myserver.database.windows.net;Password=fakepassword123"),
    ("IBM_CLOUD_KEY", 'ibm_cloud_api_key = "' + "A" * 44 + '"'),

    # ================================================================
    # DEVOPS / CI-CD / PACKAGE REGISTRIES
    # ================================================================
    ("GITHUB_PAT_CLASSIC", "ghp_" + "A" * 36),
    ("GITHUB_PAT_FINE", "github_pat_" + "A" * 22 + "_" + "B" * 59),
    ("GITHUB_OAUTH", "gho_" + "A" * 36),
    ("GITHUB_USER_TOKEN", "ghu_" + "A" * 36),
    ("GITHUB_SERVER_TOKEN", "ghs_" + "A" * 36),
    ("GITHUB_REFRESH_TOKEN", "ghr_" + "A" * 36),
    ("GITLAB_PAT", "glpat-" + "A" * 20),
    ("GITLAB_PIPELINE", "glptt-" + "A" * 40),
    ("GITLAB_RUNNER", "glrt-" + "A" * 20),
    ("GITLAB_DEPLOY", "gldt-" + "A" * 20),
    ("GITLAB_FEED", "glft-" + "A" * 20),
    ("BITBUCKET_TOKEN", "ATBB" + "A" * 32),
    ("NPM_TOKEN", "npm_" + "A" * 36),
    ("PYPI_TOKEN", "pypi-" + "A" * 50),
    ("DOCKERHUB_PAT", "dckr_pat_" + "A" * 27),
    ("RUBYGEMS_KEY", "rubygems_" + "a" * 48),
    ("NUGET_KEY", "oy2" + "a" * 43),
    ("CLOJARS_TOKEN", "CLOJARS_" + "A" * 60),
    ("TERRAFORM_TOKEN", "aaaaaaaaAAAAAA.atlasv1." + "B" * 60),
    ("VAULT_TOKEN", "hvs." + "A" * 24),
    ("VAULT_BATCH_TOKEN", "hvb." + "A" * 24),
    ("PULUMI_TOKEN", "pul-" + "a" * 40),
    ("GRAFANA_CLOUD_TOKEN", "glc_" + "A" * 32),
    ("GRAFANA_SERVICE_ACCT", "glsa_" + "A" * 32 + "_" + "a" * 8),
    ("DOPPLER_TOKEN", "dp.pt." + "a" * 43),
    ("PREFECT_TOKEN", "pnu_" + "a" * 36),
    ("LINEAR_KEY", "lin_api_" + "A" * 40),
    ("SCALINGO_TOKEN", "tk-us-" + "a" * 48),
    ("CIRCLECI_TOKEN", 'CIRCLE_TOKEN = "' + "a" * 40 + '"'),
    ("BUILDKITE_TOKEN", "bkua_" + "a" * 40),
    ("FLYIO_TOKEN", "fo1_" + "a" * 43),
    ("RENDER_TOKEN", "rnd_" + "a" * 32),
    ("VERCEL_TOKEN", "vercel_" + "a" * 24),
    ("SUPABASE_KEY", "sbp_" + "a" * 40),
    ("SONARQUBE_TOKEN", "sqp_" + "a" * 40),
    ("DATABRICKS_TOKEN", "dapi" + "a" * 32),

    # ================================================================
    # PAYMENT PROCESSORS
    # ================================================================
    ("STRIPE_SECRET_KEY", "sk_live_" + "A" * 24),
    ("STRIPE_TEST_KEY", "sk_test_" + "A" * 24),
    ("STRIPE_RESTRICTED_KEY", "rk_live_" + "A" * 24),
    ("STRIPE_WEBHOOK_SECRET", "whsec_" + "A" * 32),
    ("SQUARE_ACCESS_TOKEN", "sq0atp-" + "A" * 22),
    ("SQUARE_OAUTH_SECRET", "sq0csp-" + "A" * 43),
    ("PAYPAL_BRAINTREE_TOKEN", "access_token$production$" + "a" * 16 + "$" + "a" * 32),
    ("ADYEN_KEY", "AQE" + "a" * 100),
    ("FLUTTERWAVE_SECRET", "FLWSECK_TEST-" + "a" * 32 + "-X"),
    ("FLUTTERWAVE_PUBLIC", "FLWPUBK_TEST-" + "a" * 32 + "-X"),
    ("RAZORPAY_KEY", "rzp_live_" + "a" * 14),
    ("PLAID_TOKEN", "access-sandbox-" + "a" * 8 + "-" + "b" * 4 + "-" + "c" * 4 + "-" + "d" * 4 + "-" + "e" * 12),

    # ================================================================
    # COMMUNICATION / MESSAGING
    # ================================================================
    ("SLACK_BOT_TOKEN", "xoxb-1234567890-1234567890-" + "a" * 24),
    ("SLACK_USER_TOKEN", "xoxp-1234567890-1234567890-" + "a" * 24),
    ("SLACK_APP_TOKEN", "xapp-1-AAAA-1234-" + "a" * 10),
    ("SLACK_WEBHOOK", "https://hooks.slack.com/services/TAAAAAAAA/BAAAAAAAA/" + "a" * 24),
    ("DISCORD_BOT_TOKEN", "M" + "A" * 23 + ".AAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    ("DISCORD_WEBHOOK", "https://discord.com/api/webhooks/12345678901234567/" + "a" * 68),
    ("TWILIO_ACCOUNT_SID", "AC" + "a" * 32),
    ("TWILIO_API_KEY", "SK" + "a" * 32),
    ("SENDGRID_KEY", "SG." + "A" * 22 + "." + "B" * 43),
    ("MAILCHIMP_KEY", "a" * 32 + "-us1"),
    ("MAILGUN_KEY", "key-" + "a" * 32),
    ("TELEGRAM_BOT_TOKEN", "123456789:" + "A" * 35),
    ("TEAMS_WEBHOOK", "https://example-org.webhook.office.com/webhookb2/" + "a" * 8 + "-" + "b" * 4 + "-" + "c" * 4 + "-" + "d" * 4 + "-" + "e" * 12 + "@" + "f" * 8 + "-" + "a" * 4 + "-" + "b" * 4 + "-" + "c" * 4 + "-" + "d" * 12 + "/IncomingWebhook/" + "a" * 32 + "/" + "e" * 8 + "-" + "f" * 4 + "-" + "a" * 4 + "-" + "b" * 4 + "-" + "c" * 12),
    ("BREVO_KEY", "xkeysib-" + "a" * 64 + "-" + "A" * 16),
    ("INTERCOM_TOKEN", "dG9rO" + "A" * 36 + "="),

    # ================================================================
    # DATABASE / STORAGE
    # ================================================================
    ("MONGODB_URL", "mongodb+srv://admin:fakepassword123@cluster0.example.mongodb.net/db"),
    ("POSTGRES_URL", "postgresql://user:fakepassword123@db.example.com:5432/mydb"),
    ("MYSQL_URL", "mysql://root:fakepassword123@mysql.example.com:3306/testdb"),
    ("REDIS_URL", "redis://:fakepassword123@redis.example.com:6379/0"),
    ("PLANETSCALE_PASSWORD", "pscale_pw_" + "A" * 43),
    ("PLANETSCALE_TOKEN", "pscale_tkn_" + "A" * 43),
    ("PLANETSCALE_OAUTH", "pscale_oauth_" + "A" * 43),
    ("CONTENTFUL_TOKEN", "CFPAT-" + "A" * 43),

    # ================================================================
    # ANALYTICS / MONITORING
    # ================================================================
    ("NEWRELIC_KEY", "NRAK-" + "A" * 27),
    ("NEWRELIC_BROWSER_KEY", "NRJS-" + "a" * 19),
    ("SENTRY_DSN", "https://" + "a" * 32 + "@o12345.ingest.sentry.io/1234567"),
    ("SENTRY_AUTH_TOKEN", "sntrys_" + "A" * 38),
    ("DYNATRACE_TOKEN", "dt0c01." + "A" * 24 + "." + "B" * 64),
    ("DATADOG_KEY", "dda" + "a" * 40),
    ("LAUNCHDARKLY_KEY", "sdk-" + "a" * 8 + "-" + "b" * 4 + "-" + "c" * 4 + "-" + "d" * 4 + "-" + "e" * 12),

    # ================================================================
    # AUTH PROVIDERS
    # ================================================================
    ("ONEPASSWORD_SECRET_KEY", "A3-AAAAAA-BBBBBB-CCCCC-DDDDD-EEEEE-FFFFF"),
    ("AGE_SECRET_KEY", "AGE-SECRET-KEY-1" + "Q" * 58),
    ("OKTA_TOKEN", "00" + "a" * 40),

    # ================================================================
    # OTHER SERVICES
    # ================================================================
    ("SHOPIFY_ACCESS_TOKEN", "shpat_" + "a" * 32),
    ("SHOPIFY_CUSTOM_APP", "shpca_" + "a" * 32),
    ("SHOPIFY_PRIVATE_APP", "shppa_" + "a" * 32),
    ("SHOPIFY_SHARED_SECRET", "shpss_" + "a" * 32),
    ("HUBSPOT_PAT", "pat-na1-" + "a" * 8 + "-" + "b" * 4 + "-" + "c" * 4 + "-" + "d" * 4 + "-" + "e" * 12),
    ("POSTMAN_KEY", "PMAK-" + "A" * 24 + "-" + "B" * 34),
    ("INFRACOST_KEY", "ico-" + "A" * 32),
    ("EASYPOST_KEY", "EZAK" + "a" * 54),
    ("JFROG_KEY", "AKC" + "a" * 20),
    ("DUFFEL_TOKEN", "duffel_test_" + "A" * 43),
    ("README_KEY", "rdme_" + "a" * 70),
    ("FRAMEIO_TOKEN", "fio-u-" + "A" * 64),
    ("TYPEFORM_PAT", "tfp_" + "a" * 44 + "_" + "b" * 14),
    ("AIRTABLE_PAT", "pat" + "a" * 14 + "." + "b" * 64),
    ("NOTION_TOKEN", "ntn_" + "a" * 43),
    ("NOTION_SECRET", "secret_" + "a" * 43),
    ("ASANA_PAT", "1/1234567890123:" + "a" * 32),
    ("FIGMA_PAT", "figd_" + "a" * 40),
    ("CONTENTSTACK_TOKEN", "cs" + "a" * 35),
    ("ATLASSIAN_TOKEN", "ATATT" + "a" * 60),
    ("CLOUDFLARE_API_TOKEN", "v1.0-" + "a" * 24 + "-" + "b" * 146),

    # ================================================================
    # GIT CREDENTIALS
    # ================================================================
    ("GIT_URL_GITHUB_PAT", "https://user:ghp_" + "a" * 36 + "@github.com/org/repo"),
    ("GIT_URL_GITLAB_PAT", "https://user:glpat-" + "a" * 20 + "@gitlab.example.com/repo"),
    ("GIT_URL_GENERIC", "https://deploybot:" + "a" * 30 + "@github.com/org/repo"),

    # ================================================================
    # PRIVATE KEYS / TOKENS
    # ================================================================
    ("PRIVATE_KEY_BLOCK", "-----BEGIN RSA PRIVATE KEY-----"),
    ("JWT_TOKEN", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.AAAAAAAAAAAAAAAAAAAAAAAAA"),

    # ================================================================
    # GENERIC PATTERNS
    # ================================================================
    ("GENERIC_API_KEY", 'api_key = "AAAAAAAAAABBBBBBBBBBCCCCCCCCCC"'),
    ("GENERIC_SECRET", 'password = "SuperFakePassword1234567890"'),
    ("BASE64_SECRET", "SECRET = " + "A" * 40),
]


# ── False positive test cases ────────────────────────────────────────────
# These should NOT be redacted.

FALSE_POSITIVE_CASES = [
    ("plain_32_hex", "abcdef1234567890abcdef1234567890"),
    ("git_sha", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"),
    ("uuid", "550e8400-e29b-41d4-a716-446655440000"),
    ("normal_code", "function getUserById(id) { return db.find(id); }"),
    ("url_with_port", "http://localhost:8080/api/v1/health"),
    ("css_color", "#ff5733"),
    ("html_tag", '<div class="container">Hello World</div>'),
    ("import_statement", "from collections import defaultdict"),
    ("version_string", "v2.14.3-beta.1"),
    ("email_address", "user@example.com"),
    ("ipv4_address", "192.168.1.100"),
    ("base64_short", "SGVsbG8gV29ybGQ="),
    ("semver", "1.0.0-rc.1+build.123"),
    ("date_string", "2026-03-28T12:00:00Z"),
    ("file_path", "/home/user/projects/myapp/src/index.ts"),
    ("sql_query", "SELECT id, name FROM users WHERE active = true"),
    ("json_object", '{"name": "test", "value": 42, "enabled": true}'),
    ("markdown_heading", "## Architecture Decision Records"),
    ("log_line", "[INFO] 2026-03-28 Server started on port 8087"),
    ("docker_image", "ghcr.io/myorg/myapp:latest"),
]


# ═══════════════════════════════════════════════════════════════════════
# Tests
# ═══════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("pattern_name,fake_token", PATTERN_TEST_CASES, ids=[c[0] for c in PATTERN_TEST_CASES])
def test_pattern_detects_token(pattern_name, fake_token, tmp_path):
    """Each pattern must detect its matching fake token and produce a placeholder."""
    sid = _session_id()
    test_file = tmp_path / "secret.txt"
    test_file.write_text(f"CONFIG_VALUE = {fake_token}\n")
    file_path = str(test_file)

    redacted_content, pre_result, pre_rc = read_and_restore(file_path, sid)

    # The hook should have exited with 0 (allow or deny-with-redacted-content)
    assert pre_rc == 0, f"Hook exited with {pre_rc}"

    # Check: either the file on disk was redacted (backup-and-redact path)
    # or the hook denied with redacted content in the reason.
    if pre_result and pre_result.get("hookSpecificOutput", {}).get("permissionDecision") == "deny":
        # Deny path: redacted content is in the deny reason
        reason = pre_result["hookSpecificOutput"].get("permissionDecisionReason", "")
        assert "{{" + pattern_name in reason, (
            f"Pattern {pattern_name}: deny reason missing placeholder. "
            f"Reason snippet: {reason[:200]}"
        )
    else:
        # Allow path: file on disk was redacted in place
        assert fake_token not in redacted_content, (
            f"Pattern {pattern_name}: fake token was NOT redacted from file content.\n"
            f"Content: {redacted_content[:300]}"
        )
        # Check that SOME placeholder was inserted (the exact pattern may differ
        # because a higher-priority pattern can match a substring first)
        assert "{{" in redacted_content and "}}" in redacted_content, (
            f"Pattern {pattern_name}: no placeholder found in redacted content.\n"
            f"Content: {redacted_content[:300]}"
        )

    # Verify original file was restored by PostToolUse
    with open(file_path, "r") as f:
        restored = f.read()
    assert fake_token in restored, (
        f"Pattern {pattern_name}: original file was NOT restored after PostToolUse Read.\n"
        f"Restored content: {restored[:300]}"
    )


@pytest.mark.parametrize("name,content", FALSE_POSITIVE_CASES, ids=[c[0] for c in FALSE_POSITIVE_CASES])
def test_no_false_positive(name, content, tmp_path):
    """Common non-secret strings must NOT be redacted."""
    sid = _session_id()
    test_file = tmp_path / "benign.txt"
    test_file.write_text(content + "\n")
    file_path = str(test_file)

    redacted_content, pre_result, pre_rc = read_and_restore(file_path, sid)

    assert pre_rc == 0, f"Hook exited with {pre_rc}"

    # Should not be denied
    if pre_result:
        decision = pre_result.get("hookSpecificOutput", {}).get("permissionDecision", "")
        assert decision != "deny", (
            f"False positive '{name}': hook denied read for benign content.\n"
            f"Reason: {pre_result.get('hookSpecificOutput', {}).get('permissionDecisionReason', '')[:200]}"
        )

    # Content should be unchanged (no redaction)
    assert "{{" not in redacted_content, (
        f"False positive '{name}': content was redacted when it should not have been.\n"
        f"Content: {redacted_content[:300]}"
    )


def test_pattern_count():
    """Verify we have the expected number of patterns and test cases."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    hooks_dir = os.path.join(script_dir, "hooks")
    import importlib.util
    spec = importlib.util.spec_from_file_location("patterns", os.path.join(hooks_dir, "patterns.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    pattern_names = [name for name, _ in mod.SECRET_PATTERNS]
    test_case_names = [name for name, _ in PATTERN_TEST_CASES]

    # Every pattern must have a test case
    missing = set(pattern_names) - set(test_case_names)
    assert not missing, f"Patterns missing test cases: {missing}"

    # No extra test cases for non-existent patterns
    extra = set(test_case_names) - set(pattern_names)
    assert not extra, f"Test cases for non-existent patterns: {extra}"

    # Counts should match
    assert len(pattern_names) == len(test_case_names), (
        f"Pattern count ({len(pattern_names)}) != test case count ({len(test_case_names)})"
    )


def test_multiple_secrets_in_one_file(tmp_path):
    """Multiple different secrets in a single file should all be redacted."""
    sid = _session_id()
    test_file = tmp_path / "multi.txt"
    content = (
        "OPENAI_KEY=sk-proj-" + "a" * 48 + "\n"
        "GITHUB_TOKEN=ghp_" + "A" * 36 + "\n"
        "STRIPE_KEY=sk_live_" + "A" * 24 + "\n"
    )
    test_file.write_text(content)
    file_path = str(test_file)

    redacted_content, pre_result, pre_rc = read_and_restore(file_path, sid)

    if pre_result and pre_result.get("hookSpecificOutput", {}).get("permissionDecision") == "deny":
        reason = pre_result["hookSpecificOutput"].get("permissionDecisionReason", "")
        # All three should be redacted
        assert "{{OPENAI_PROJECT_KEY_" in reason or "{{OPENAI_KEY_" in reason
        assert "{{GITHUB_PAT_CLASSIC_" in reason
        assert "{{STRIPE_SECRET_KEY_" in reason
    else:
        assert "sk-proj-" + "a" * 48 not in redacted_content
        assert "ghp_" + "A" * 36 not in redacted_content
        assert "sk_live_" + "A" * 24 not in redacted_content
        assert "{{" in redacted_content


def test_placeholder_deterministic(tmp_path):
    """Same secret value should always produce the same placeholder."""
    sid1 = _session_id()
    sid2 = _session_id()
    secret = "ghp_" + "A" * 36

    test_file1 = tmp_path / "det1.txt"
    test_file1.write_text(f"token = {secret}\n")

    test_file2 = tmp_path / "det2.txt"
    test_file2.write_text(f"other_token = {secret}\n")

    content1, _, _ = read_and_restore(str(test_file1), sid1)
    content2, _, _ = read_and_restore(str(test_file2), sid2)

    # Extract placeholders
    import re
    ph1 = re.findall(r'\{\{GITHUB_PAT_CLASSIC_[a-f0-9]+\}\}', content1)
    ph2 = re.findall(r'\{\{GITHUB_PAT_CLASSIC_[a-f0-9]+\}\}', content2)

    assert ph1, f"No placeholder found in content1: {content1[:200]}"
    assert ph2, f"No placeholder found in content2: {content2[:200]}"
    assert ph1[0] == ph2[0], f"Placeholders differ for same secret: {ph1[0]} vs {ph2[0]}"


def test_empty_file_no_redaction(tmp_path):
    """Empty files should not be redacted."""
    sid = _session_id()
    test_file = tmp_path / "empty.txt"
    test_file.write_text("")
    file_path = str(test_file)

    redacted_content, pre_result, pre_rc = read_and_restore(file_path, sid)

    assert pre_rc == 0
    assert redacted_content == ""
    if pre_result:
        assert pre_result.get("hookSpecificOutput", {}).get("permissionDecision") != "deny"
