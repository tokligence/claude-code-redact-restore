#!/usr/bin/env python3
"""Tests for hooks/deploy_config_guard.py — the always-on PreToolUse `ask`
for edits to files the deploy pipeline consumes.

The guard's value is entirely in what it does NOT fire on: a prompt that
appears on ordinary source edits gets muted within a day, and then the one
edit that matters sails through. So the negative cases below are the real
test surface, not filler."""
import os
import sys

import pytest

HOOKS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hooks")
sys.path.insert(0, HOOKS_DIR)

from deploy_config_guard import (  # noqa: E402
    OPT_OUT_ENV,
    check_deploy_config,
    classify_path,
)


def _payload(path, tool="Edit"):
    return {"tool_name": tool, "tool_input": {"file_path": path}}


# ── Must ask ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "path",
    [
        # The observed incident: deleting `output: 'standalone'` to fix a
        # local dev server, three lines away from the Dockerfile that
        # copies `.next/standalone`.
        "/repo/next.config.js",
        "/repo/next.config.mjs",
        "/repo/vite.config.ts",
        "/repo/Dockerfile",
        "/repo/Dockerfile.prod",
        "/repo/.dockerignore",
        "/repo/docker-compose.yml",
        "/repo/docker-compose.override.yaml",
        "/repo/.github/workflows/deploy.yml",
        "/repo/.gitlab-ci.yml",
        "/repo/Jenkinsfile",
        "/repo/Cargo.toml",
        "/repo/pyproject.toml",
        "/repo/setup.py",
        "/repo/go.mod",
        "/repo/vercel.json",
        "/repo/fly.toml",
        "/repo/Procfile",
        "/repo/serverless.yml",
        "/repo/k8s/deployment.yaml",
        "/repo/charts/values.yaml",
        # Relative paths and nested repos must match too — the hook sees
        # whatever the tool was handed.
        "next.config.js",
        "services/api/Dockerfile",
    ],
)
def test_deploy_critical_paths_ask(path):
    out = check_deploy_config(_payload(path))
    assert out is not None, f"{path} should have prompted"
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "ask"
    assert path in hso["permissionDecisionReason"]


@pytest.mark.parametrize("tool", ["Edit", "Write", "MultiEdit"])
def test_all_writing_tools_are_covered(tool):
    assert check_deploy_config(_payload("/repo/Dockerfile", tool=tool)) is not None


def test_notebook_edit_uses_its_own_path_key():
    out = check_deploy_config(
        {"tool_name": "NotebookEdit", "tool_input": {"notebook_path": "/repo/Dockerfile"}}
    )
    assert out is not None


# ── Must NOT ask ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "path",
    [
        # Ordinary source. The overwhelming majority of edits.
        "/repo/src/main.rs",
        "/repo/src/app/page.tsx",
        "/repo/README.md",
        # Lockfiles churn on every dependency change and a stale one fails
        # loudly at install time, not silently at deploy time.
        "/repo/package-lock.json",
        "/repo/Cargo.lock",
        "/repo/yarn.lock",
        # Secrets are the secret shield's job, not this guard's.
        "/repo/.env",
        "/repo/.env.production",
        # Test configs break tests — a visible failure, which is exactly
        # the kind this guard is not for.
        "/repo/jest.config.js",
        "/repo/vitest.config.ts",
        "/repo/playwright.config.ts",
        # Near-misses that must not trip the patterns.
        "/repo/docs/Dockerfile-explained.md",
        "/repo/src/next.config.test.ts",
        "/repo/app/components/AppYaml.tsx",
    ],
)
def test_ordinary_paths_pass(path):
    assert check_deploy_config(_payload(path)) is None, f"{path} should not have prompted"


@pytest.mark.parametrize("tool", ["Read", "Bash", "Grep", "Agent"])
def test_non_writing_tools_pass(tool):
    """Reading a Dockerfile is not editing one."""
    assert check_deploy_config({"tool_name": tool, "tool_input": {"file_path": "/repo/Dockerfile"}}) is None


def test_opt_out_env_disables_the_guard(monkeypatch):
    monkeypatch.setenv(OPT_OUT_ENV, "1")
    assert check_deploy_config(_payload("/repo/Dockerfile")) is None


def test_opt_out_only_on_exact_value(monkeypatch):
    """A stray truthy-looking value must not silently disarm the guard."""
    monkeypatch.setenv(OPT_OUT_ENV, "true")
    assert check_deploy_config(_payload("/repo/Dockerfile")) is not None


# ── Fail-open ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"tool_name": "Edit"},
        {"tool_name": "Edit", "tool_input": None},
        {"tool_name": "Edit", "tool_input": {}},
        {"tool_name": "Edit", "tool_input": {"file_path": None}},
        {"tool_name": "Edit", "tool_input": {"file_path": ""}},
        {"tool_name": "Edit", "tool_input": "not-a-dict"},
    ],
)
def test_malformed_input_fails_open(data):
    """A hook bug must never block a safe edit."""
    assert check_deploy_config(data) is None


def test_classify_path_is_reusable_and_labels_specifically():
    assert classify_path("/repo/.github/workflows/deploy.yml") == "GitHub Actions workflow"
    assert classify_path("/repo/Dockerfile") == "Dockerfile"
    assert classify_path("/repo/src/lib.rs") is None


def test_reason_names_the_local_convenience_trap():
    """The message has to explain the failure mode, not just flag the file —
    the reader is deciding in one second whether this edit is the work or a
    workaround."""
    reason = check_deploy_config(_payload("/repo/next.config.js"))["hookSpecificOutput"][
        "permissionDecisionReason"
    ]
    assert "locally" in reason
    assert "deploy" in reason.lower()
    assert OPT_OUT_ENV in reason
