#!/usr/bin/env python3
"""
deploy_config_guard — always-on PreToolUse(Edit|Write|MultiEdit|NotebookEdit)
`ask` for edits to files the deploy pipeline consumes.

Why
───
The failure this catches has a specific shape, and it is not carelessness —
it is a rational local decision with a non-local consequence:

    An agent needs a dev server, a test run, or a browser session to work.
    Something in the build config is in the way. It edits the config. The
    task now succeeds, the agent reports success honestly, and the edit
    rides along in the diff to production.

Observed instance (2026-07, parallel frontend streams): an agent deleted
`output: 'standalone'` from `next.config.js` so a local dev server would
behave. The production Dockerfile's very next line is
`COPY --from=builder /app/.next/standalone ./`. Shipping it would have
failed the image build — with a symptom pointing at Next.js or the
dependency tree, nowhere near the one-line config deletion three commits
back. It was caught only because a human happened to read an uncommitted
diff.

Why the whole class is nasty:
  - The change is *correct* in the environment where it was made.
  - Tests still pass — build config is not usually under test.
  - Nothing in the diff looks alarming; one deleted line in a config file.
  - Blast radius is the deploy, i.e. the moment with the least context
    available and the highest time pressure.

Why `ask` and not `deny`
────────────────────────
People legitimately edit these files — that is how infrastructure work
happens. A deny would be wrong most of the time and would train everyone
to set the override permanently, which is worse than no guard. `ask` puts
one human decision in front of the class of edit whose cost is paid later
by someone else. Answering it takes a second when the edit is intentional.

Distinct from:
  - `git_guard`:              staging hygiene (`git add -A`)
  - `autopilot/bash_guard`:   destructive shell, autopilot only
  - `guard/agent_isolation_guard`: two agents in one git tree

Those protect the repository. This one protects the *pipeline*, which no
amount of git isolation covers: every worktree shares the deploy config's
meaning, and a worktree-isolated agent can still poison a release.

Matched paths (basename or path fragment, case-insensitive)
  - container / orchestration: Dockerfile*, docker-compose*.y*ml, .dockerignore
  - CI/CD:                     .github/workflows/*, .gitlab-ci.yml, Jenkinsfile
  - JS/TS build:               next.config.*, vite.config.*, webpack.config.*,
                               rollup.config.*, nuxt.config.*, svelte.config.*,
                               angular.json, turbo.json
  - Rust:                      Cargo.toml (profiles/features reach the binary)
  - Python packaging:          pyproject.toml, setup.py, MANIFEST.in
  - Go:                        go.mod
  - platform manifests:        vercel.json, netlify.toml, fly.toml, railway.*,
                               app.yaml, Procfile, serverless.y*ml, k8s manifests
                               under deploy/ or k8s/, helm chart values

Deliberately NOT matched: lockfiles (churn constantly, and a stale lock is
loud rather than silent), `.env*` (already covered by the secret shield),
and test configs (`jest.config`, `vitest.config`, `playwright.config`) —
those break tests, which is a visible failure, not a silent one.

Override
  REDMEM_ALLOW_DEPLOY_CONFIG=1 claude        # whole session
  REDMEM_ALLOW_DEPLOY_CONFIG=1 <single cmd>  # one command (env inherits)

Fail mode: FAIL-OPEN. A hook bug must never block a safe edit. Any
exception is logged single-line to stderr with `[redmem-deployguard]`.
"""
import os
import re

OPT_OUT_ENV = "REDMEM_ALLOW_DEPLOY_CONFIG"

WATCHED_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}

# (regex over the POSIX-normalised path, human label). Ordered most- to
# least-specific so the reported label is the useful one.
DEPLOY_CRITICAL: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(^|/)\.github/workflows/[^/]+\.ya?ml$", re.I), "GitHub Actions workflow"),
    (re.compile(r"(^|/)(docker-compose[^/]*\.ya?ml|compose\.ya?ml)$", re.I), "Docker Compose file"),
    # `Dockerfile`, `Dockerfile.prod`, `api.Dockerfile` — but NOT prose that
    # merely starts with the word (`Dockerfile-explained.md`). Caught by this
    # file's own test suite, which is the point of having one.
    (re.compile(r"(^|/)([\w.-]+\.)?Dockerfile(\.[\w-]+)?$", re.I), "Dockerfile"),
    (re.compile(r"(^|/)\.dockerignore$", re.I), "Docker build context filter"),
    (re.compile(r"(^|/)\.gitlab-ci\.ya?ml$", re.I), "GitLab CI pipeline"),
    (re.compile(r"(^|/)Jenkinsfile$", re.I), "Jenkins pipeline"),
    (re.compile(r"(^|/)(next|nuxt|vite|webpack|rollup|svelte)\.config\.[cm]?[jt]s$", re.I), "frontend build config"),
    (re.compile(r"(^|/)(angular|turbo)\.json$", re.I), "frontend build config"),
    (re.compile(r"(^|/)Cargo\.toml$", re.I), "Cargo manifest (profiles/features reach the shipped binary)"),
    (re.compile(r"(^|/)(pyproject\.toml|setup\.py|MANIFEST\.in)$", re.I), "Python packaging config"),
    (re.compile(r"(^|/)go\.mod$", re.I), "Go module file"),
    (re.compile(r"(^|/)(vercel\.json|netlify\.toml|fly\.toml|railway\.(json|toml)|app\.yaml|Procfile)$", re.I), "platform deploy manifest"),
    (re.compile(r"(^|/)serverless\.ya?ml$", re.I), "Serverless manifest"),
    (re.compile(r"(^|/)(k8s|kubernetes|deploy|charts?)/[^/]*\.ya?ml$", re.I), "deployment manifest"),
]


def _log(msg: str) -> None:
    import sys

    sys.stderr.write(f"[redmem-deployguard] {msg}\n")


def classify_path(path: str) -> str | None:
    """Return a human label when `path` is deploy-critical, else None."""
    if not path:
        return None
    normalised = str(path).replace("\\", "/")
    for pattern, label in DEPLOY_CRITICAL:
        if pattern.search(normalised):
            return label
    return None


def _target_path(tool_input: dict) -> str:
    for key in ("file_path", "notebook_path", "path"):
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def check_deploy_config(data: dict) -> dict | None:
    """PreToolUse hook body. Returns an `ask` response dict, or None to pass.

    Fail-open by construction: every unexpected shape returns None.
    """
    try:
        if os.environ.get(OPT_OUT_ENV) == "1":
            return None
        if data.get("tool_name") not in WATCHED_TOOLS:
            return None

        tool_input = data.get("tool_input")
        if not isinstance(tool_input, dict):
            return None

        path = _target_path(tool_input)
        label = classify_path(path)
        if label is None:
            return None

        _log(f"ask — {label}: {path}")
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": (
                    f"[redmem-deployguard] This edits a {label}:\n"
                    f"  {path}\n\n"
                    f"The deploy pipeline consumes this file, so the change ships "
                    f"even though it was made for the machine you are on now.\n\n"
                    f"Approve if the change IS the work.\n\n"
                    f"Decline if you are editing it to make something work locally — "
                    f"a dev server, a test run, a browser session. That edit succeeds "
                    f"here and fails at deploy time, with a symptom that points "
                    f"somewhere else entirely. Use a local override instead: a dev "
                    f"command that does not read this file, an env var, or a "
                    f"gitignored local config.\n\n"
                    f"To silence for a session: {OPT_OUT_ENV}=1 claude"
                ),
            }
        }
    except Exception as e:  # pragma: no cover — fail-open safety net
        _log(f"error (failing open): {e}")
        return None
