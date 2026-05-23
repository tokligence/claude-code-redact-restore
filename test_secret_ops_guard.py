"""
Unit tests for hooks/secret_ops_guard.py

The guard intercepts PreToolUse Bash commands that would expose
production-grade secrets, soft-blocks them with a deny reason, and
allows the user to authorize via "go-secret" / "pass-secret N" /
"pass-secret off" keywords in the next UserPromptSubmit.
"""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Load the hook module from its on-disk path (it's not a package).
_HOOK_PATH = Path(__file__).parent / "hooks" / "secret_ops_guard.py"
_spec = importlib.util.spec_from_file_location("secret_ops_guard", _HOOK_PATH)
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)


def _payload(session_id, command, *, tool="Bash", agent="main", event="PreToolUse"):
    return {
        "hook_event_name": event,
        "session_id": session_id,
        "agent_scope": agent,
        "tool_name": tool,
        "tool_input": {"command": command},
    }


def _prompt_payload(session_id, prompt, *, agent="main"):
    return {
        "hook_event_name": "UserPromptSubmit",
        "session_id": session_id,
        "agent_scope": agent,
        "prompt": prompt,
    }


def _clear_state(session_id, agent="main"):
    """Delete the per-session state file so each test starts fresh."""
    key = f"{session_id}::{agent}"
    path = guard._state_path(key)
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


class TestPatternMatching(unittest.TestCase):
    def test_matches_aws_secretsmanager_get_secret_value(self):
        cmd = "aws secretsmanager get-secret-value --secret-id kleepay/prod/jwt"
        self.assertEqual(
            guard._match_command(cmd),
            "aws-secretsmanager-get-secret-value",
        )

    def test_matches_aws_secretsmanager_with_profile_flag(self):
        cmd = "aws --profile prod secretsmanager get-secret-value --secret-id foo"
        self.assertEqual(
            guard._match_command(cmd),
            "aws-secretsmanager-get-secret-value",
        )

    def test_matches_ssm_get_parameter_with_decryption(self):
        cmd = "aws ssm get-parameter --name /app/secret --with-decryption"
        self.assertEqual(
            guard._match_command(cmd),
            "aws-ssm-get-parameter-with-decryption",
        )

    def test_matches_kms_decrypt(self):
        cmd = "aws kms decrypt --ciphertext-blob fileb://encrypted.bin"
        self.assertEqual(guard._match_command(cmd), "aws-kms-decrypt")

    def test_matches_rds_master_password_modify(self):
        cmd = "aws rds modify-db-cluster --db-cluster-identifier foo --master-user-password new"
        self.assertEqual(
            guard._match_command(cmd),
            "aws-rds-modify-master-password",
        )

    def test_does_not_match_benign_commands(self):
        for cmd in [
            "ls /tmp",
            "git status",
            "aws s3 ls",
            "aws secretsmanager list-secrets",  # listing names only, no values
            "aws ssm get-parameter --name /app/secret",  # no --with-decryption
            "aws rds describe-db-clusters",
        ]:
            self.assertIsNone(
                guard._match_command(cmd),
                f"benign command '{cmd}' should NOT match",
            )


class TestPreToolUseCheck(unittest.TestCase):
    def setUp(self):
        self.session = "test-pretool-" + os.urandom(4).hex()
        _clear_state(self.session)

    def tearDown(self):
        _clear_state(self.session)

    def test_non_bash_tool_passes(self):
        payload = _payload(self.session, "ignored", tool="Read")
        self.assertIsNone(guard.check(payload))

    def test_benign_bash_passes(self):
        payload = _payload(self.session, "ls /tmp")
        self.assertIsNone(guard.check(payload))

    def test_dangerous_bash_denies(self):
        payload = _payload(
            self.session,
            "aws secretsmanager get-secret-value --secret-id foo --profile prod",
        )
        resp = guard.check(payload)
        self.assertIsNotNone(resp)
        self.assertEqual(
            resp["hookSpecificOutput"]["permissionDecision"],
            "deny",
        )
        reason = resp["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("aws-secretsmanager-get-secret-value", reason)
        self.assertIn("go-secret", reason)
        self.assertIn("pass-secret", reason)

    def test_denied_command_is_queued_in_state(self):
        cmd = "aws secretsmanager get-secret-value --secret-id foo"
        guard.check(_payload(self.session, cmd))
        state = guard._load_state(f"{self.session}::main")
        self.assertIn("pending_secret_op", state)
        self.assertEqual(state["pending_secret_op"]["pattern"], "aws-secretsmanager-get-secret-value")
        self.assertEqual(state["pending_secret_op"]["command"], cmd)

    def test_bypass_remaining_consumes_one_allow(self):
        # Pre-set state to simulate "pass-secret 1" approval (multi-shot,
        # NO fingerprint binding — any matching dangerous command allowed)
        key = f"{self.session}::main"
        guard._save_state(key, {"secret_ops_bypass_remaining": 1})
        cmd = "aws secretsmanager get-secret-value --secret-id foo"
        # First call → allowed, counter decremented
        self.assertIsNone(guard.check(_payload(self.session, cmd)))
        state = guard._load_state(key)
        self.assertEqual(state["secret_ops_bypass_remaining"], 0)
        # Second call → blocked again
        resp = guard.check(_payload(self.session, cmd))
        self.assertIsNotNone(resp)


class TestFingerprintBinding(unittest.TestCase):
    """`go-secret` binds the approval to the exact queued command.
    Prevents bait-and-switch where AI swaps in a different secret read."""

    def setUp(self):
        self.session = "test-fp-" + os.urandom(4).hex()
        _clear_state(self.session)

    def tearDown(self):
        _clear_state(self.session)

    def test_go_secret_records_fingerprint(self):
        cmd = "aws secretsmanager get-secret-value --secret-id foo"
        guard.check(_payload(self.session, cmd))  # queue
        guard.handle_user_prompt(
            _prompt_payload(self.session, "go-secret"), "go-secret"
        )
        state = guard._load_state(f"{self.session}::main")
        self.assertIn("secret_ops_bound_fingerprint", state)
        expected_fp = guard._cmd_fingerprint(cmd)
        self.assertEqual(state["secret_ops_bound_fingerprint"], expected_fp)

    def test_go_secret_approved_command_passes(self):
        cmd = "aws secretsmanager get-secret-value --secret-id foo"
        guard.check(_payload(self.session, cmd))
        guard.handle_user_prompt(
            _prompt_payload(self.session, "go-secret"), "go-secret"
        )
        # Same exact command → allowed
        self.assertIsNone(guard.check(_payload(self.session, cmd)))

    def test_go_secret_different_command_blocked(self):
        """Bait-and-switch: user approves cmd A, AI tries cmd B."""
        cmd_a = "aws secretsmanager get-secret-value --secret-id staging/foo"
        cmd_b = "aws secretsmanager get-secret-value --secret-id production/PROD"
        guard.check(_payload(self.session, cmd_a))
        guard.handle_user_prompt(
            _prompt_payload(self.session, "go-secret"), "go-secret"
        )
        # Different command → denied even with bypass active
        resp = guard.check(_payload(self.session, cmd_b))
        self.assertIsNotNone(resp)
        reason = resp["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("DIFFERENT command", reason)

        # Bypass NOT consumed — user can still retry the original
        state = guard._load_state(f"{self.session}::main")
        self.assertEqual(state["secret_ops_bypass_remaining"], 1)
        self.assertEqual(
            state["secret_ops_bound_fingerprint"], guard._cmd_fingerprint(cmd_a)
        )
        # Original command still works
        self.assertIsNone(guard.check(_payload(self.session, cmd_a)))

    def test_pass_secret_n_does_NOT_bind(self):
        """`pass-secret 3` is explicit batch approval — no fingerprint binding."""
        cmd_a = "aws secretsmanager get-secret-value --secret-id foo"
        cmd_b = "aws kms decrypt --ciphertext-blob bar"  # different command, different pattern
        guard.check(_payload(self.session, cmd_a))
        guard.handle_user_prompt(
            _prompt_payload(self.session, "pass-secret 3"), "pass-secret 3"
        )
        # All 3 allowed even with different commands
        self.assertIsNone(guard.check(_payload(self.session, cmd_a)))
        self.assertIsNone(guard.check(_payload(self.session, cmd_b)))
        self.assertIsNone(guard.check(_payload(self.session, cmd_a)))
        # 4th blocked
        self.assertIsNotNone(guard.check(_payload(self.session, cmd_a)))

    def test_one_shot_binding_consumed_after_use(self):
        """After approved command runs, the binding is cleared — next
        secret op needs fresh approval."""
        cmd = "aws kms decrypt --ciphertext-blob foo"
        guard.check(_payload(self.session, cmd))
        guard.handle_user_prompt(
            _prompt_payload(self.session, "go-secret"), "go-secret"
        )
        # Use the approval
        self.assertIsNone(guard.check(_payload(self.session, cmd)))
        # State should have bypass=0 AND no fingerprint
        state = guard._load_state(f"{self.session}::main")
        self.assertEqual(state["secret_ops_bypass_remaining"], 0)
        self.assertNotIn("secret_ops_bound_fingerprint", state)
        # Next attempt → re-blocked
        self.assertIsNotNone(guard.check(_payload(self.session, cmd)))

    def test_bypass_off_session_wide(self):
        key = f"{self.session}::main"
        guard._save_state(key, {"secret_ops_bypass_remaining": -1})
        cmd = "aws kms decrypt --ciphertext-blob foo"
        for _ in range(5):
            self.assertIsNone(guard.check(_payload(self.session, cmd)))
        # Counter stays at -1 (sentinel never decremented)
        self.assertEqual(
            guard._load_state(key)["secret_ops_bypass_remaining"], -1
        )


class TestUserPromptSubmit(unittest.TestCase):
    def setUp(self):
        self.session = "test-prompt-" + os.urandom(4).hex()
        _clear_state(self.session)

    def tearDown(self):
        _clear_state(self.session)

    def _queue_command(self, cmd="aws secretsmanager get-secret-value --secret-id foo"):
        guard.check(_payload(self.session, cmd))

    def test_unrelated_prompt_passes(self):
        result = guard.handle_user_prompt(
            _prompt_payload(self.session, "Hello, please write a function"),
            "Hello, please write a function",
        )
        self.assertIsNone(result)

    def test_go_secret_without_queued_command_is_noop(self):
        result = guard.handle_user_prompt(
            _prompt_payload(self.session, "go-secret"),
            "go-secret",
        )
        # No pending command → returns None (lets other hooks see the prompt)
        self.assertIsNone(result)

    def test_go_secret_approves_one_command(self):
        self._queue_command()
        result = guard.handle_user_prompt(
            _prompt_payload(self.session, "go-secret"),
            "go-secret",
        )
        self.assertIsNotNone(result)
        ctx = result["hookSpecificOutput"]["additionalContext"]
        self.assertIn("go-secret", ctx)
        self.assertIn("aws-secretsmanager-get-secret-value", ctx)

        state = guard._load_state(f"{self.session}::main")
        self.assertEqual(state["secret_ops_bypass_remaining"], 1)
        self.assertNotIn("pending_secret_op", state)

    def test_pass_secret_n_sets_counter(self):
        self._queue_command()
        result = guard.handle_user_prompt(
            _prompt_payload(self.session, "pass-secret 3"),
            "pass-secret 3",
        )
        self.assertIsNotNone(result)
        state = guard._load_state(f"{self.session}::main")
        self.assertEqual(state["secret_ops_bypass_remaining"], 3)

    def test_pass_secret_off_disables_session(self):
        self._queue_command()
        result = guard.handle_user_prompt(
            _prompt_payload(self.session, "pass-secret off"),
            "pass-secret off",
        )
        self.assertIsNotNone(result)
        state = guard._load_state(f"{self.session}::main")
        self.assertEqual(state["secret_ops_bypass_remaining"], -1)

    def test_bare_pass_secret_approves_one(self):
        self._queue_command()
        result = guard.handle_user_prompt(
            _prompt_payload(self.session, "pass-secret"),
            "pass-secret",
        )
        self.assertIsNotNone(result)
        state = guard._load_state(f"{self.session}::main")
        self.assertEqual(state["secret_ops_bypass_remaining"], 1)

    def test_pass_secret_clamped_to_100(self):
        self._queue_command()
        guard.handle_user_prompt(
            _prompt_payload(self.session, "pass-secret 9999"),
            "pass-secret 9999",
        )
        state = guard._load_state(f"{self.session}::main")
        self.assertEqual(state["secret_ops_bypass_remaining"], 100)

    def test_case_insensitive_keywords(self):
        self._queue_command()
        result = guard.handle_user_prompt(
            _prompt_payload(self.session, "GO-SECRET"),
            "GO-SECRET",
        )
        self.assertIsNotNone(result)


class TestEndToEndFlow(unittest.TestCase):
    """Exercise the round-trip: queued → approved → allowed → re-blocked."""

    def setUp(self):
        self.session = "test-e2e-" + os.urandom(4).hex()
        _clear_state(self.session)

    def tearDown(self):
        _clear_state(self.session)

    def test_go_secret_then_command_then_command_again(self):
        cmd = "aws secretsmanager get-secret-value --secret-id myapp/staging/jwt"

        # Step 1: Bash → denied + queued
        deny = guard.check(_payload(self.session, cmd))
        self.assertEqual(deny["hookSpecificOutput"]["permissionDecision"], "deny")

        # Step 2: User types "go-secret" → bypass=1, queue cleared
        prompt_ack = guard.handle_user_prompt(
            _prompt_payload(self.session, "go-secret"), "go-secret"
        )
        self.assertIsNotNone(prompt_ack)

        # Step 3: Bash retried → allowed (bypass consumed)
        self.assertIsNone(guard.check(_payload(self.session, cmd)))

        # Step 4: Bash retried again → denied (bypass exhausted)
        deny2 = guard.check(_payload(self.session, cmd))
        self.assertEqual(deny2["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_pass_secret_3_allows_three_then_blocks_fourth(self):
        cmd = "aws kms decrypt --ciphertext-blob fileb://x"

        guard.check(_payload(self.session, cmd))  # queue
        guard.handle_user_prompt(
            _prompt_payload(self.session, "pass-secret 3"), "pass-secret 3"
        )

        # Three allowed
        self.assertIsNone(guard.check(_payload(self.session, cmd)))
        self.assertIsNone(guard.check(_payload(self.session, cmd)))
        self.assertIsNone(guard.check(_payload(self.session, cmd)))

        # Fourth blocked
        resp = guard.check(_payload(self.session, cmd))
        self.assertIsNotNone(resp)

    def test_sessions_are_isolated(self):
        """Approval in session A must not leak into session B."""
        cmd = "aws secretsmanager get-secret-value --secret-id foo"

        sess_a = "session-iso-a"
        sess_b = "session-iso-b"
        _clear_state(sess_a)
        _clear_state(sess_b)

        # Session A: queue + go-secret + allow
        guard.check(_payload(sess_a, cmd))
        guard.handle_user_prompt(_prompt_payload(sess_a, "go-secret"), "go-secret")
        self.assertIsNone(guard.check(_payload(sess_a, cmd)))

        # Session B: same command → denied (no bypass in B's state)
        deny_b = guard.check(_payload(sess_b, cmd))
        self.assertIsNotNone(deny_b)
        self.assertEqual(deny_b["hookSpecificOutput"]["permissionDecision"], "deny")

        _clear_state(sess_a)
        _clear_state(sess_b)


class TestAgentScopeIsolation(unittest.TestCase):
    """Codex R3 [P1] — different agent_type values must produce
    different state keys so subagents don't share approval state."""

    def test_agent_type_isolates_state_key(self):
        p_main = {"session_id": "s1", "agent_type": "main-thread"}
        p_sub = {"session_id": "s1", "agent_type": "code-reviewer"}
        self.assertNotEqual(guard._state_key(p_main), guard._state_key(p_sub))

    def test_agent_id_isolates_state_key(self):
        p1 = {"session_id": "s1", "agent_id": "alpha"}
        p2 = {"session_id": "s1", "agent_id": "beta"}
        self.assertNotEqual(guard._state_key(p1), guard._state_key(p2))

    def test_no_agent_info_uses_main_sentinel(self):
        p = {"session_id": "s1"}
        self.assertEqual(guard._state_key(p), "s1::main")

    def test_go_secret_does_not_leak_across_agent_types(self):
        """Approve a command for agent_type='alpha'; agent_type='beta'
        in the same session must still be blocked."""
        cmd = "aws kms decrypt --ciphertext-blob foo"

        # Two payloads — same session, different agent_type
        p_alpha = {"session_id": "agent-iso-sess", "agent_type": "alpha",
                   "tool_name": "Bash", "tool_input": {"command": cmd}}
        p_beta = {"session_id": "agent-iso-sess", "agent_type": "beta",
                  "tool_name": "Bash", "tool_input": {"command": cmd}}

        # Clear any state
        for p in (p_alpha, p_beta):
            try:
                os.remove(guard._state_path(guard._state_key(p)))
            except FileNotFoundError:
                pass

        # Queue + approve in alpha
        guard.check(p_alpha)
        guard.handle_user_prompt(
            {**p_alpha, "prompt": "go-secret"}, "go-secret"
        )

        # Beta with same session sees no approval — still denied
        resp = guard.check(p_beta)
        self.assertIsNotNone(resp)
        self.assertEqual(
            resp["hookSpecificOutput"]["permissionDecision"], "deny"
        )

        # Cleanup
        for p in (p_alpha, p_beta):
            try:
                os.remove(guard._state_path(guard._state_key(p)))
            except FileNotFoundError:
                pass


class TestConcurrencyAtomicBypass(unittest.TestCase):
    """Codex R4 [P1] — bypass consumption must be atomic under
    parallel PreToolUse hooks.

    Codex R6 [P3]: fcntl.flock is process-scoped on POSIX, so same-process
    threads do NOT exercise the lock. This test spawns 8 separate
    subprocesses (modelling concurrent hook processes) to actually
    validate the production locking model."""

    def test_parallel_check_consumes_only_one_bypass(self):
        import concurrent.futures

        session = "race-test-" + os.urandom(4).hex()
        key = f"{session}::main"
        _clear_state(session)

        # Seed state with a single multi-shot bypass.
        guard._save_state(key, {"secret_ops_bypass_remaining": 1})

        cmd = "aws kms decrypt --ciphertext-blob foo"
        payload = _payload(session, cmd)

        def run_one_subprocess(_ignored):
            # Each call spawns a fresh Python process running the hook's
            # __main__ block on the same session state file. fcntl.flock
            # in those processes is what serializes them.
            r = subprocess.run(
                [sys.executable, str(_HOOK_PATH)],
                input=json.dumps(payload),
                capture_output=True, text=True, timeout=15,
            )
            return r.stdout.strip()

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            outputs = list(pool.map(run_one_subprocess, range(8)))

        # Exactly ONE child should produce empty stdout (= allow).
        # The other seven should produce a JSON deny payload.
        allowed = sum(1 for o in outputs if o == "")
        denied = sum(1 for o in outputs if o and json.loads(o).get(
            "hookSpecificOutput", {}
        ).get("permissionDecision") == "deny")
        self.assertEqual(
            allowed, 1,
            f"expected 1 allow, got {allowed} (denied={denied}). "
            f"flock race leaked extra bypasses across processes."
        )
        self.assertEqual(denied, 7)

        # State should show bypass exhausted
        state = guard._load_state(key)
        self.assertEqual(state.get("secret_ops_bypass_remaining", 0), 0)

        _clear_state(session)


class TestWrappedPayloadPromptExtract(unittest.TestCase):
    """Codex R4 [P2] — the __main__ block + dispatcher must extract
    prompts from wrapped payloads (top-level OR nested under `data`)."""

    def test_main_block_handles_nested_data_user_prompt(self):
        """Direct subprocess call with a wrapped payload should still
        recognize 'go-secret' and ack the queued command."""
        session = "wrap-test-" + os.urandom(4).hex()
        _clear_state(session)

        # Queue a command (top-level payload, works either way)
        guard.check(_payload(session, "aws kms decrypt --ciphertext-blob z"))

        # Now send a wrapped UserPromptSubmit where prompt is under data.message
        wrapped = {
            "hook_event_name": "UserPromptSubmit",
            "session_id": session,
            "data": {"message": "go-secret"},
        }
        result = subprocess.run(
            [sys.executable, str(_HOOK_PATH)],
            input=json.dumps(wrapped),
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.stdout.strip(), f"expected non-empty stdout, got {result.stdout!r}")
        ack = json.loads(result.stdout)
        ctx = ack.get("hookSpecificOutput", {}).get("additionalContext", "")
        self.assertIn("go-secret", ctx)

        _clear_state(session)


class TestFailClosed(unittest.TestCase):
    """Codex R3 [P2] — when state I/O fails (e.g. unwritable tempdir),
    the guard must DENY the dangerous command, not silently let it
    through via the dispatcher's outer except-Exception."""

    def test_check_fails_closed_when_state_unsavable(self):
        # Simulate unwritable tempdir by patching _state_path to point at
        # a directory that doesn't exist (os.open will raise FileNotFoundError).
        original = guard._state_path
        guard._state_path = lambda _k: "/nonexistent-path/no-such-dir/state.json"
        try:
            payload = _payload("fc-test", "aws kms decrypt --ciphertext-blob x")
            resp = guard.check(payload)
            self.assertIsNotNone(resp)
            self.assertEqual(
                resp["hookSpecificOutput"]["permissionDecision"], "deny"
            )
            # Verify the deny reason indicates the fail-closed reason
            reason = resp["hookSpecificOutput"]["permissionDecisionReason"]
            self.assertIn("fail-closed", reason)
        finally:
            guard._state_path = original
            _clear_state("fc-test")


if __name__ == "__main__":
    unittest.main()
