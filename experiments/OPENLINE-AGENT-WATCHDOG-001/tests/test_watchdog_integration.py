import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "experiments" / "OPENLINE-AGENT-WATCHDOG-001"))
sys.path.insert(0, str(ROOT / "experiments" / "SELF-HEALING-PROJECTS-001"))
sys.path.insert(0, str(ROOT / "experiments" / "OPENLINE-PROTECT-001"))

from watchdog import (
    AgentWatchdog,
    Attempt,
    ExecutionSupervisor,
    ProgressEvidence,
    _canonical_json,
)
from project import ProjectLedger


class TestAgentWatchdogIntegration(unittest.TestCase):
    def setUp(self) -> None:
        self.owner_priv = Ed25519PrivateKey.generate()
        self.owner_pub = self.owner_priv.public_key()
        self.sup_priv = Ed25519PrivateKey.generate()

    def test_1_legitimate_repetitive_work_continues(self) -> None:
        """
        Requirement 6a: Verify that legitimate repetitive work (identical command text across
        many attempts) continues when receiver-verified progress (narrowing failing assertions
        or verified prerequisite steps) is observed.
        """
        sup = ExecutionSupervisor(
            project_id="proj-1",
            run_id="run-1",
            objective_id="repair:service:refund_engine",
            allowed_paths=["services/refund_service.py"],
            owner_public_key=self.owner_pub,
            supervisor_signing_key=self.sup_priv,
            max_stagnant_attempts=3,
            max_elapsed_s=120.0,
            max_spend_micros=100_000,
        )

        # 6 attempts running the exact same command "pytest -q", narrowing failures 5 -> 4 -> 3 -> 2 -> 1 -> 0
        failures_sequence = [5, 4, 3, 2, 1, 0]
        for idx, fails in enumerate(failures_sequence, start=1):
            ev = ProgressEvidence(
                evidence_verified_by_receiver=True,
                accepted_head_before="a1b2c3",
                accepted_head_after="a1b2c3" if fails > 0 else "d4e5f6",
                head_advanced=(fails == 0),
                validator_exit_code=1 if fails > 0 else 0,
                failing_assertions_count=fails,
                deliverable_standing_before="REOPEN",
                deliverable_standing_after="REOPEN" if fails > 0 else "CURRENT",
            )
            att = Attempt(
                attempt_id=f"att-{idx}",
                assignment_id="asgn-1",
                worker_member="bob",
                objective_id="repair:service:refund_engine",
                command_text="pytest -q",  # identical repetitive command
                agent_self_reported_success=False,
                candidate_tree_sha256=f"tree-{idx}",
                elapsed_s=2.0,
                spend_micros=1_000,
                evidence=ev,
            )
            rec = sup.record_and_enforce(att)
            self.assertEqual(rec["payload"]["enforced_action"], "CONTINUE")
            self.assertEqual(sup.status, "ACTIVE")

        # Only the first baseline attempt (5 failures) had no prior baseline to narrow;
        # attempts 2..6 all narrowed failures or advanced head, resetting consecutive_stagnant_attempts to 0!
        self.assertEqual(sup.watchdog.consecutive_stagnant_attempts, 0)

    def test_2_superficial_action_changes_and_self_reports_cannot_evade_stagnation(self) -> None:
        """
        Requirement 3 & 6b: Superficial command text changes and agent self-reported success
        cannot evade stagnation detection when receiver-verified progress does not advance.
        """
        sup = ExecutionSupervisor(
            project_id="proj-1",
            run_id="run-2",
            objective_id="repair:service:refund_engine",
            allowed_paths=["services/refund_service.py"],
            owner_public_key=self.owner_pub,
            supervisor_signing_key=self.sup_priv,
            max_stagnant_attempts=3,
        )

        varying_commands = [
            "pytest -q tests/test_refund.py",
            "python3 -m pytest -vv -k refund --tb=short",
            "PYTHONDONTWRITEBYTECODE=1 pytest --maxfail=1 tests/",
        ]
        for idx, cmd in enumerate(varying_commands, start=1):
            ev = ProgressEvidence(
                evidence_verified_by_receiver=True,
                accepted_head_before="a1b2c3",
                accepted_head_after="a1b2c3",
                head_advanced=False,
                validator_exit_code=1,
                failing_assertions_count=2,  # stuck at 2 failures
                deliverable_standing_before="REOPEN",
                deliverable_standing_after="REOPEN",
            )
            att = Attempt(
                attempt_id=f"att-stag-{idx}",
                assignment_id="asgn-1",
                worker_member="bob",
                objective_id="repair:service:refund_engine",
                command_text=cmd,
                agent_self_reported_success=True,  # agent falsely claims success every time
                candidate_tree_sha256=f"tree-stag-{idx}",
                elapsed_s=3.0,
                spend_micros=2_000,
                evidence=ev,
            )
            rec = sup.record_and_enforce(att)
            if idx < 3:
                self.assertEqual(rec["payload"]["enforced_action"], "CONTINUE")
            else:
                self.assertEqual(rec["event_type"], "ENFORCED_STOP_STAGNATION")
                self.assertEqual(rec["payload"]["enforced_action"], "HALT_STAGNANT_AGENT")
                self.assertEqual(sup.status, "HALTED_STAGNATION")

        # A 4th attempt after HALTED_STAGNATION is strictly refused by the supervisor
        att4 = Attempt(
            attempt_id="att-stag-4",
            assignment_id="asgn-1",
            worker_member="bob",
            objective_id="repair:service:refund_engine",
            command_text="echo bypassed",
            agent_self_reported_success=True,
            candidate_tree_sha256="tree-stag-4",
            elapsed_s=1.0,
            spend_micros=500,
            evidence=None,
        )
        rec4 = sup.record_and_enforce(att4)
        self.assertEqual(rec4["event_type"], "REFUSED_RUN_NOT_ACTIVE")

    def test_3_missing_or_unverified_evidence_never_becomes_invented_progress(self) -> None:
        """
        Requirement 6c: Missing evidence (None) or unverified evidence (evidence_verified_by_receiver=False)
        never counts as progress even if the agent claims head_advanced=True and validator_exit_code=0.
        """
        wd = AgentWatchdog(objective_id="repair:service:refund_engine", max_stagnant_attempts=2)

        # Attempt 1: evidence is None
        d1 = wd.observe(
            Attempt(
                attempt_id="a1",
                assignment_id="asgn-1",
                worker_member="bob",
                objective_id="repair:service:refund_engine",
                command_text="git commit -m fix",
                agent_self_reported_success=True,
                candidate_tree_sha256="t1",
                elapsed_s=1.0,
                spend_micros=100,
                evidence=None,
            )
        )
        self.assertFalse(d1.observed_progress)
        self.assertEqual(d1.progress_reason, "MISSING_OR_UNVERIFIED_EVIDENCE")
        self.assertEqual(d1.action, "CONTINUE")

        # Attempt 2: unverified evidence claiming head advanced and 0 failures
        d2 = wd.observe(
            Attempt(
                attempt_id="a2",
                assignment_id="asgn-1",
                worker_member="bob",
                objective_id="repair:service:refund_engine",
                command_text="pytest",
                agent_self_reported_success=True,
                candidate_tree_sha256="t2",
                elapsed_s=1.0,
                spend_micros=100,
                evidence=ProgressEvidence(
                    evidence_verified_by_receiver=False,  # NOT verified by receiver
                    accepted_head_before="old",
                    accepted_head_after="new",
                    head_advanced=True,
                    validator_exit_code=0,
                    failing_assertions_count=0,
                ),
            )
        )
        self.assertFalse(d2.observed_progress)
        self.assertEqual(d2.progress_reason, "MISSING_OR_UNVERIFIED_EVIDENCE")
        self.assertEqual(d2.action, "STOP_STAGNATION")

    def test_4_uncertain_external_mutations_cannot_be_blindly_retried(self) -> None:
        """
        Requirement 4 & 6d: Uncertain external mutations immediately trigger
        STOP_UNCERTAIN_MUTATION and block any retry until owner-signed reconciliation.
        """
        sup = ExecutionSupervisor(
            project_id="proj-1",
            run_id="run-4",
            objective_id="repair:service:refund_engine",
            allowed_paths=["services/refund_service.py"],
            owner_public_key=self.owner_pub,
            supervisor_signing_key=self.sup_priv,
            max_stagnant_attempts=3,
        )

        uncertain_attempt = Attempt(
            attempt_id="att-uncertain-1",
            assignment_id="asgn-1",
            worker_member="bob",
            objective_id="repair:service:refund_engine",
            command_text="curl -X POST https://billing.local/refund",
            agent_self_reported_success=False,
            candidate_tree_sha256="t-unc-1",
            elapsed_s=2.5,
            spend_micros=1_500,
            evidence=ProgressEvidence(
                evidence_verified_by_receiver=True,
                accepted_head_before="h1",
                accepted_head_after="h1",
                head_advanced=False,
                external_mutation_state="UNCERTAIN",
            ),
        )
        rec1 = sup.record_and_enforce(uncertain_attempt)
        self.assertEqual(rec1["event_type"], "ENFORCED_STOP_UNCERTAIN_MUTATION")
        self.assertEqual(sup.status, "HALTED_UNCERTAIN_MUTATION")
        self.assertTrue(sup.reconciliation_required)

        # Blind retry is blocked
        retry_rec = sup.record_and_enforce(uncertain_attempt)
        self.assertEqual(retry_rec["event_type"], "REFUSED_RUN_NOT_ACTIVE")

        # Forged signature reconciliation fails
        forged_priv = Ed25519PrivateKey.generate()
        bad_payload = {
            "action": "RECONCILE_UNCERTAIN_MUTATION",
            "project_id": "proj-1",
            "run_id": "run-4",
            "attempt_id": "att-uncertain-1",
            "resolution": "ROLLED_BACK",
        }
        bad_sig = forged_priv.sign(_canonical_json(bad_payload)).hex()
        bad_rec = sup.reconcile_uncertain_mutation(
            attempt_id="att-uncertain-1",
            resolution="ROLLED_BACK",
            owner_signature_hex=bad_sig,
        )
        self.assertEqual(bad_rec["event_type"], "REFUSED_INVALID_RECONCILIATION_SIGNATURE")
        self.assertTrue(sup.reconciliation_required)

        # Valid owner signature reconciles and permits resumption
        good_sig = self.owner_priv.sign(_canonical_json(bad_payload)).hex()
        good_rec = sup.reconcile_uncertain_mutation(
            attempt_id="att-uncertain-1",
            resolution="ROLLED_BACK",
            owner_signature_hex=good_sig,
        )
        self.assertEqual(good_rec["event_type"], "UNCERTAIN_MUTATION_RECONCILED")
        self.assertEqual(sup.status, "ACTIVE")
        self.assertFalse(sup.reconciliation_required)

    def test_5_pivot_authority_and_budget_bounds(self) -> None:
        """
        Requirement 4 & 5: Cumulative budget/time stops enforced; agent-proposed pivot cannot
        redefine objective, reset stagnation counter, or expand permissions; owner Ed25519
        signature starts a new bounded run.
        """
        sup = ExecutionSupervisor(
            project_id="proj-1",
            run_id="run-5",
            objective_id="repair:service:refund_engine",
            allowed_paths=["services/refund_service.py"],
            owner_public_key=self.owner_pub,
            supervisor_signing_key=self.sup_priv,
            max_stagnant_attempts=3,
            max_elapsed_s=10.0,
            max_spend_micros=5_000,
        )

        # 1 stagnant attempt
        att1 = Attempt(
            attempt_id="a1",
            assignment_id="asgn-1",
            worker_member="bob",
            objective_id="repair:service:refund_engine",
            command_text="pytest",
            agent_self_reported_success=False,
            candidate_tree_sha256="t1",
            elapsed_s=4.0,
            spend_micros=2_000,
            evidence=ProgressEvidence(
                evidence_verified_by_receiver=True,
                accepted_head_before="h1",
                accepted_head_after="h1",
                head_advanced=False,
                failing_assertions_count=3,
            ),
        )
        sup.record_and_enforce(att1)
        self.assertEqual(sup.watchdog.consecutive_stagnant_attempts, 1)

        # Worker proposes a pivot to relax the objective and expand allowed_paths to contracts/
        piv = sup.propose_pivot(
            worker_member="bob",
            proposed_objective_id="repair:trivial_doc_update",
            requested_allowed_paths=["services/refund_service.py", "contracts/refund_policy.json"],
            rationale="Refund engine is too hard; let me edit the contract instead.",
        )
        self.assertEqual(piv["event_type"], "REFUSED_UNAUTHORIZED_PIVOT")
        # Objective, allowed_paths, and stagnation counter remain strictly untouched
        self.assertEqual(sup.objective_id, "repair:service:refund_engine")
        self.assertEqual(sup.allowed_paths, ("services/refund_service.py",))
        self.assertEqual(sup.watchdog.consecutive_stagnant_attempts, 1)

        # Next attempt exceeds max_elapsed_s (4.0 + 7.5 = 11.5 > 10.0) even though it narrowed failures
        att2 = Attempt(
            attempt_id="a2",
            assignment_id="asgn-1",
            worker_member="bob",
            objective_id="repair:service:refund_engine",
            command_text="pytest",
            agent_self_reported_success=False,
            candidate_tree_sha256="t2",
            elapsed_s=7.5,
            spend_micros=2_000,
            evidence=ProgressEvidence(
                evidence_verified_by_receiver=True,
                accepted_head_before="h1",
                accepted_head_after="h1",
                head_advanced=False,
                failing_assertions_count=2,
            ),
        )
        rec2 = sup.record_and_enforce(att2)
        self.assertEqual(rec2["event_type"], "ENFORCED_STOP_BUDGET_OR_TIME")
        self.assertEqual(sup.status, "HALTED_BUDGET_OR_TIME")

        # Owner signs authorization for a new bounded run
        auth_payload = {
            "action": "AUTHORIZE_PIVOT_NEW_RUN",
            "project_id": "proj-1",
            "previous_run_id": "run-5",
            "new_run_id": "run-6",
            "new_objective_id": "repair:service:refund_engine:v2",
            "new_allowed_paths": ["contracts/refund_policy.json", "services/refund_service.py"],
            "max_elapsed_s": 60.0,
            "max_spend_micros": 50_000,
        }
        owner_sig = self.owner_priv.sign(_canonical_json(auth_payload)).hex()
        auth_rec = sup.authorize_pivot_and_new_run(
            new_run_id="run-6",
            new_objective_id="repair:service:refund_engine:v2",
            new_allowed_paths=["services/refund_service.py", "contracts/refund_policy.json"],
            max_elapsed_s=60.0,
            max_spend_micros=50_000,
            owner_signature_hex=owner_sig,
        )
        self.assertEqual(auth_rec["event_type"], "OWNER_AUTHORIZED_NEW_BOUNDED_RUN")
        self.assertEqual(sup.status, "ACTIVE")
        self.assertEqual(sup.run_id, "run-6")
        self.assertEqual(sup.watchdog.consecutive_stagnant_attempts, 0)


if __name__ == "__main__":
    unittest.main()
