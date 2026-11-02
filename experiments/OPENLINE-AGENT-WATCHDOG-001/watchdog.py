"""
OpenLine Agent Watchdog & Bounded Execution Supervisor
Candidate: openline-living-projects-rc2
Branch: engineering/argon-living-projects-rc2-watchdog-20261101

Provenance Disclosure:
The external GitHub repository `terryncew/openline-agent-watchdog` (branch
`fix/watchdog-observed-progress-001`, referenced in Gmail CI threads 19c71b1bf5a53a07
at commits 07b4ad2 / 719ce1f / 45bae33 / dfbf0b0 and Argon repo entry #39) is not cached
in the offline VM or Google Drive environment. This module provides the clean-room
implementation of the exact `AgentWatchdog`, `Attempt`, and `ProgressEvidence`
interfaces and `ExecutionSupervisor` enforcement contract required by the
Argon Watchdog Addendum.

Design invariants:
1. Advisory Watchdog, Enforcing Supervisor: `AgentWatchdog` evaluates `Attempt` records
   using only receiver-verified `ProgressEvidence` and emits advisory decisions;
   `ExecutionSupervisor` enforces stagnation stops, cumulative time/spend budgets,
   and uncertain external mutation locks (`CAS_PENDING` / `UNCERTAIN`).
2. Observed Progress Only: Self-reported agent success (`agent_self_reported_success=True`)
   and superficial command text changes (`command_text`) never count as progress.
   Missing or unverified `ProgressEvidence` is treated as zero progress.
3. Authority Preservation: A watchdog STOP never erases previously accepted commits
   or inherited memories. Proposed pivots cannot silently redefine objectives, reset
   stagnation counters, or expand `allowed_paths`; changing objectives requires an
   Ed25519 owner signature and starts a new bounded run epoch.
4. No Experimental Equations in Production Decisions: Coherence Dynamics (`kappa`,
   `Phi*`) are excluded from stopping and authorization logic.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
import hashlib
import json
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import InvalidSignature


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class ProgressEvidence:
    """
    Independently verified project progress observed by the receiving system.
    Never populated from an agent's self-report.
    """
    evidence_verified_by_receiver: bool
    accepted_head_before: str
    accepted_head_after: str
    head_advanced: bool
    validator_exit_code: Optional[int] = None
    failing_assertions_count: Optional[int] = None
    deliverable_standing_before: str = "REOPEN"
    deliverable_standing_after: str = "REOPEN"
    prerequisite_advanced: bool = False
    prerequisite_id: Optional[str] = None
    external_mutation_state: str = "NONE"  # "NONE" | "VERIFIED_LOCAL" | "UNCERTAIN"
    receipt_sha256: Optional[str] = None


@dataclass(frozen=True)
class Attempt:
    """
    A single bounded agent execution attempt observed by the receiver.
    """
    attempt_id: str
    assignment_id: str
    worker_member: str
    objective_id: str
    command_text: str
    agent_self_reported_success: bool
    candidate_tree_sha256: str
    elapsed_s: float
    spend_micros: int
    evidence: Optional[ProgressEvidence] = None


@dataclass(frozen=True)
class WatchdogDecision:
    """
    Advisory verdict emitted by AgentWatchdog after inspecting an Attempt.
    """
    action: str  # "CONTINUE" | "STOP_STAGNATION" | "STOP_UNCERTAIN_MUTATION" | "STOP_OBJECTIVE_DRIFT"
    observed_progress: bool
    progress_reason: str
    consecutive_stagnant_attempts: int
    max_stagnant_attempts: int
    best_failing_assertions_count: Optional[int]
    advisory_note: str


class AgentWatchdog:
    """
    Observed-progress loop and stagnation detector (`fix/watchdog-observed-progress-001` contract).
    Evaluates completed `Attempt` instances strictly via receiver-verified `ProgressEvidence`.
    """

    def __init__(self, objective_id: str, max_stagnant_attempts: int = 3) -> None:
        if max_stagnant_attempts < 1:
            raise ValueError("max_stagnant_attempts must be >= 1")
        self.objective_id: str = objective_id
        self.max_stagnant_attempts: int = max_stagnant_attempts
        self.consecutive_stagnant_attempts: int = 0
        self.best_failing_assertions_count: Optional[int] = None
        self.verified_prerequisites: set[str] = set()
        self.history: List[Tuple[Attempt, WatchdogDecision]] = []

    def observe(self, attempt: Attempt) -> WatchdogDecision:
        # 1. Check objective consistency (agent cannot silently drift objective mid-run)
        if attempt.objective_id != self.objective_id:
            decision = WatchdogDecision(
                action="STOP_OBJECTIVE_DRIFT",
                observed_progress=False,
                progress_reason="UNAUTHORIZED_OBJECTIVE_CHANGE",
                consecutive_stagnant_attempts=self.consecutive_stagnant_attempts + 1,
                max_stagnant_attempts=self.max_stagnant_attempts,
                best_failing_assertions_count=self.best_failing_assertions_count,
                advisory_note=f"Attempt objective '{attempt.objective_id}' != bound objective '{self.objective_id}'.",
            )
            self.consecutive_stagnant_attempts += 1
            self.history.append((attempt, decision))
            return decision

        ev = attempt.evidence

        # 2. Missing or unverified evidence never becomes invented progress
        if ev is None or not ev.evidence_verified_by_receiver:
            self.consecutive_stagnant_attempts += 1
            action = (
                "STOP_STAGNATION"
                if self.consecutive_stagnant_attempts >= self.max_stagnant_attempts
                else "CONTINUE"
            )
            decision = WatchdogDecision(
                action=action,
                observed_progress=False,
                progress_reason="MISSING_OR_UNVERIFIED_EVIDENCE",
                consecutive_stagnant_attempts=self.consecutive_stagnant_attempts,
                max_stagnant_attempts=self.max_stagnant_attempts,
                best_failing_assertions_count=self.best_failing_assertions_count,
                advisory_note="ProgressEvidence is missing or not receiver-verified; self-reported success ignored.",
            )
            self.history.append((attempt, decision))
            return decision

        # 3. Uncertain external mutation requires immediate stop & reconciliation (no blind retry)
        if ev.external_mutation_state == "UNCERTAIN":
            self.consecutive_stagnant_attempts += 1
            decision = WatchdogDecision(
                action="STOP_UNCERTAIN_MUTATION",
                observed_progress=False,
                progress_reason="UNCERTAIN_EXTERNAL_MUTATION",
                consecutive_stagnant_attempts=self.consecutive_stagnant_attempts,
                max_stagnant_attempts=self.max_stagnant_attempts,
                best_failing_assertions_count=self.best_failing_assertions_count,
                advisory_note="External mutation state is UNCERTAIN; blind retry forbidden until reconciled.",
            )
            self.history.append((attempt, decision))
            return decision

        # 4. Evaluate independently verified progress (ignoring command_text and agent_self_reported_success)
        observed_progress = False
        progress_reason = "NO_VERIFIED_PROGRESS"

        if ev.head_advanced and ev.accepted_head_after != ev.accepted_head_before:
            observed_progress = True
            progress_reason = "ACCEPTED_HEAD_ADVANCED"
        elif ev.deliverable_standing_before != "CURRENT" and ev.deliverable_standing_after == "CURRENT":
            observed_progress = True
            progress_reason = "DELIVERABLE_STANDING_CURRENT"
        elif ev.prerequisite_advanced and ev.prerequisite_id and ev.prerequisite_id not in self.verified_prerequisites:
            self.verified_prerequisites.add(ev.prerequisite_id)
            observed_progress = True
            progress_reason = f"VERIFIED_PREREQUISITE_ADVANCED:{ev.prerequisite_id}"
        elif ev.failing_assertions_count is not None:
            if self.best_failing_assertions_count is None:
                # First baseline measurement: only counts as progress if 0 failures (passing)
                self.best_failing_assertions_count = ev.failing_assertions_count
                if ev.failing_assertions_count == 0 and ev.validator_exit_code == 0:
                    observed_progress = True
                    progress_reason = "VALIDATOR_PASSED_ZERO_FAILURES"
            elif ev.failing_assertions_count < self.best_failing_assertions_count:
                self.best_failing_assertions_count = ev.failing_assertions_count
                observed_progress = True
                progress_reason = "FAILING_ASSERTIONS_NARROWED"

        if observed_progress:
            self.consecutive_stagnant_attempts = 0
            decision = WatchdogDecision(
                action="CONTINUE",
                observed_progress=True,
                progress_reason=progress_reason,
                consecutive_stagnant_attempts=0,
                max_stagnant_attempts=self.max_stagnant_attempts,
                best_failing_assertions_count=self.best_failing_assertions_count,
                advisory_note=f"Receiver-verified progress observed ({progress_reason}).",
            )
        else:
            self.consecutive_stagnant_attempts += 1
            action = (
                "STOP_STAGNATION"
                if self.consecutive_stagnant_attempts >= self.max_stagnant_attempts
                else "CONTINUE"
            )
            decision = WatchdogDecision(
                action=action,
                observed_progress=False,
                progress_reason=progress_reason,
                consecutive_stagnant_attempts=self.consecutive_stagnant_attempts,
                max_stagnant_attempts=self.max_stagnant_attempts,
                best_failing_assertions_count=self.best_failing_assertions_count,
                advisory_note=(
                    f"No receiver-verified progress ({self.consecutive_stagnant_attempts}/"
                    f"{self.max_stagnant_attempts} stagnant attempts)."
                ),
            )

        self.history.append((attempt, decision))
        return decision


class ExecutionSupervisor:
    """
    Receiver-side execution supervisor that enforces:
    - Advisory AgentWatchdog decisions (STOP_STAGNATION, STOP_OBJECTIVE_DRIFT, STOP_UNCERTAIN_MUTATION)
    - Cumulative time (`max_elapsed_s`) and spend (`max_spend_micros`) limits
    - Uncertain mutation reconciliation locks (preventing blind retry)
    - Authority preservation (a STOP never erases accepted work; agent-proposed pivots
      cannot silently redefine the objective, reset stagnation counters, or expand permissions).
    """

    def __init__(
        self,
        *,
        project_id: str,
        run_id: str,
        objective_id: str,
        allowed_paths: Sequence[str],
        owner_public_key: Ed25519PublicKey,
        supervisor_signing_key: Ed25519PrivateKey,
        max_stagnant_attempts: int = 3,
        max_elapsed_s: float = 300.0,
        max_spend_micros: int = 500_000,
        project_ledger: Any = None,
    ) -> None:
        self.project_id = project_id
        self.run_id = run_id
        self.objective_id = objective_id
        self.allowed_paths = tuple(sorted(set(allowed_paths)))
        self.owner_public_key = owner_public_key
        self.supervisor_signing_key = supervisor_signing_key
        self.max_elapsed_s = float(max_elapsed_s)
        self.max_spend_micros = int(max_spend_micros)
        self.project_ledger = project_ledger

        self.watchdog = AgentWatchdog(
            objective_id=objective_id,
            max_stagnant_attempts=max_stagnant_attempts,
        )
        self.cumulative_elapsed_s: float = 0.0
        self.cumulative_spend_micros: int = 0
        self.status: str = "ACTIVE"  # "ACTIVE" | "HALTED_STAGNATION" | "HALTED_BUDGET_OR_TIME" | "HALTED_UNCERTAIN_MUTATION" | "HALTED_OBJECTIVE_DRIFT"
        self.reconciliation_required: bool = False
        self.receipts: List[Dict[str, Any]] = []

    def _emit_receipt(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        body = {
            "schema": "openline.supervisor.decision.v1",
            "project_id": self.project_id,
            "run_id": self.run_id,
            "objective_id": self.objective_id,
            "allowed_paths": list(self.allowed_paths),
            "event_type": event_type,
            "supervisor_status": self.status,
            "cumulative_elapsed_s": round(self.cumulative_elapsed_s, 6),
            "cumulative_spend_micros": self.cumulative_spend_micros,
            "payload": payload,
        }
        sig = self.supervisor_signing_key.sign(_canonical_json(body)).hex()
        receipt = {
            **body,
            "receipt_sha256": _sha256_hex(_canonical_json(body)),
            "supervisor_signature": sig,
        }
        self.receipts.append(receipt)
        return receipt

    def record_and_enforce(self, attempt: Attempt, *, deliverable_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Inspects a completed attempt, consults the advisory AgentWatchdog,
        and enforces bounded execution rules.
        """
        # 1. Refuse execution if supervisor is already halted or awaiting mutation reconciliation
        if self.reconciliation_required or self.status != "ACTIVE":
            return self._emit_receipt(
                "REFUSED_RUN_NOT_ACTIVE",
                {
                    "attempt_id": attempt.attempt_id,
                    "worker_member": attempt.worker_member,
                    "reason": f"Supervisor is {self.status} (reconciliation_required={self.reconciliation_required}).",
                    "enforced_action": "REJECT_ATTEMPT",
                },
            )

        # 2. Accumulate resource usage
        self.cumulative_elapsed_s += max(0.0, float(attempt.elapsed_s))
        self.cumulative_spend_micros += max(0, int(attempt.spend_micros))

        # 3. Consult advisory watchdog
        wd_decision = self.watchdog.observe(attempt)

        # 4. Enforce uncertain mutation lock immediately (highest priority safety stop)
        if wd_decision.action == "STOP_UNCERTAIN_MUTATION":
            self.status = "HALTED_UNCERTAIN_MUTATION"
            self.reconciliation_required = True
            return self._emit_receipt(
                "ENFORCED_STOP_UNCERTAIN_MUTATION",
                {
                    "attempt_id": attempt.attempt_id,
                    "worker_member": attempt.worker_member,
                    "watchdog_decision": asdict(wd_decision),
                    "enforced_action": "HALT_RECONCILE_REQUIRED",
                },
            )

        # 5. Enforce objective drift stop
        if wd_decision.action == "STOP_OBJECTIVE_DRIFT":
            self.status = "HALTED_OBJECTIVE_DRIFT"
            return self._emit_receipt(
                "ENFORCED_STOP_OBJECTIVE_DRIFT",
                {
                    "attempt_id": attempt.attempt_id,
                    "worker_member": attempt.worker_member,
                    "watchdog_decision": asdict(wd_decision),
                    "enforced_action": "HALT_UNAUTHORIZED_OBJECTIVE",
                },
            )

        # 6. Enforce cumulative budget and time limits
        if self.cumulative_elapsed_s > self.max_elapsed_s or self.cumulative_spend_micros > self.max_spend_micros:
            self.status = "HALTED_BUDGET_OR_TIME"
            return self._emit_receipt(
                "ENFORCED_STOP_BUDGET_OR_TIME",
                {
                    "attempt_id": attempt.attempt_id,
                    "worker_member": attempt.worker_member,
                    "max_elapsed_s": self.max_elapsed_s,
                    "max_spend_micros": self.max_spend_micros,
                    "watchdog_decision": asdict(wd_decision),
                    "enforced_action": "HALT_BUDGET_EXCEEDED",
                },
            )

        # 7. Enforce watchdog stagnation stop (preserving all previously accepted commits)
        if wd_decision.action == "STOP_STAGNATION":
            self.status = "HALTED_STAGNATION"
            quarantined_memory_id = None
            if self.project_ledger is not None and deliverable_id:
                try:
                    mem_id = f"mem-watchdog-stag-{self.run_id}-{attempt.attempt_id}"
                    basis = self.objective_id.split(":")[-1] if ":" in self.objective_id else self.objective_id
                    self.project_ledger.propose_memory(
                        mem_id,
                        deliverable_id,
                        attempt.worker_member,
                        basis,
                        attempt.candidate_tree_sha256,
                        f"Watchdog halted {attempt.worker_member} after {wd_decision.consecutive_stagnant_attempts} stagnant attempts (last cmd: {attempt.command_text[:80]})",
                        f"AVOID_STAGNANT_LOOP: {attempt.worker_member} repeated {wd_decision.consecutive_stagnant_attempts} attempts without advancing receiver-verified progress on {basis}",
                        assignment_id=attempt.assignment_id,
                    )
                    self.project_ledger.quarantine_memory(
                        attempt.assignment_id,
                        reason=f"STOP_STAGNATION ({wd_decision.consecutive_stagnant_attempts}/{wd_decision.max_stagnant_attempts})",
                        receipt_sha256=attempt.evidence.receipt_sha256 if attempt.evidence else None,
                    )
                    quarantined_memory_id = mem_id
                except Exception:
                    pass
            return self._emit_receipt(
                "ENFORCED_STOP_STAGNATION",
                {
                    "attempt_id": attempt.attempt_id,
                    "worker_member": attempt.worker_member,
                    "deliverable_id": deliverable_id,
                    "quarantined_memory_id": quarantined_memory_id,
                    "preserved_accepted_head": attempt.evidence.accepted_head_after if attempt.evidence else None,
                    "watchdog_decision": asdict(wd_decision),
                    "enforced_action": "HALT_STAGNANT_AGENT",
                },
            )

        # 8. Otherwise allow continuation
        return self._emit_receipt(
            "ATTEMPT_OBSERVED_CONTINUE",
            {
                "attempt_id": attempt.attempt_id,
                "worker_member": attempt.worker_member,
                "watchdog_decision": asdict(wd_decision),
                "enforced_action": "CONTINUE",
            },
        )

    def propose_pivot(
        self,
        *,
        worker_member: str,
        proposed_objective_id: str,
        requested_allowed_paths: Sequence[str],
        rationale: str,
    ) -> Dict[str, Any]:
        """
        Handles an agent-proposed pivot.
        Per Requirement 5: A proposed pivot MUST NOT silently redefine the objective,
        reset the stagnation counter, or expand an agent's permissions.
        Changing objectives requires owner authorization and a new bounded run.
        """
        expanding_paths = sorted(set(requested_allowed_paths) - set(self.allowed_paths))
        return self._emit_receipt(
            "REFUSED_UNAUTHORIZED_PIVOT",
            {
                "worker_member": worker_member,
                "proposed_objective_id": proposed_objective_id,
                "bound_objective_id": self.objective_id,
                "requested_allowed_paths": list(requested_allowed_paths),
                "unauthorized_path_expansion": expanding_paths,
                "stagnant_attempts_preserved": self.watchdog.consecutive_stagnant_attempts,
                "rationale": rationale,
                "enforced_action": "OWNER_AUTHORIZATION_AND_NEW_RUN_REQUIRED",
            },
        )

    def authorize_pivot_and_new_run(
        self,
        *,
        new_run_id: str,
        new_objective_id: str,
        new_allowed_paths: Sequence[str],
        max_elapsed_s: float,
        max_spend_micros: int,
        owner_signature_hex: str,
    ) -> Dict[str, Any]:
        """
        Verifies an owner Ed25519 signature to authorize a new objective/scope and start
        a fresh bounded run without erasing previously accepted work.
        """
        auth_payload = {
            "action": "AUTHORIZE_PIVOT_NEW_RUN",
            "project_id": self.project_id,
            "previous_run_id": self.run_id,
            "new_run_id": new_run_id,
            "new_objective_id": new_objective_id,
            "new_allowed_paths": sorted(set(new_allowed_paths)),
            "max_elapsed_s": float(max_elapsed_s),
            "max_spend_micros": int(max_spend_micros),
        }
        try:
            self.owner_public_key.verify(bytes.fromhex(owner_signature_hex), _canonical_json(auth_payload))
        except (ValueError, InvalidSignature) as exc:
            return self._emit_receipt(
                "REFUSED_INVALID_OWNER_PIVOT_SIGNATURE",
                {
                    "new_run_id": new_run_id,
                    "new_objective_id": new_objective_id,
                    "error": f"Invalid owner Ed25519 signature: {exc}",
                    "enforced_action": "REJECT_PIVOT",
                },
            )

        self.run_id = new_run_id
        self.objective_id = new_objective_id
        self.allowed_paths = tuple(sorted(set(new_allowed_paths)))
        self.max_elapsed_s = float(max_elapsed_s)
        self.max_spend_micros = int(max_spend_micros)
        self.cumulative_elapsed_s = 0.0
        self.cumulative_spend_micros = 0
        self.status = "ACTIVE"
        self.reconciliation_required = False
        self.watchdog = AgentWatchdog(
            objective_id=new_objective_id,
            max_stagnant_attempts=self.watchdog.max_stagnant_attempts,
        )
        return self._emit_receipt(
            "OWNER_AUTHORIZED_NEW_BOUNDED_RUN",
            {
                "new_run_id": new_run_id,
                "new_objective_id": new_objective_id,
                "new_allowed_paths": list(self.allowed_paths),
                "enforced_action": "NEW_BOUNDED_RUN_STARTED",
            },
        )

    def reconcile_uncertain_mutation(
        self,
        *,
        attempt_id: str,
        resolution: str,  # "ROLLED_BACK" | "VERIFIED_COMMITTED"
        owner_signature_hex: str,
    ) -> Dict[str, Any]:
        """
        Reconciles an uncertain external mutation with an owner Ed25519 signature.
        """
        rec_payload = {
            "action": "RECONCILE_UNCERTAIN_MUTATION",
            "project_id": self.project_id,
            "run_id": self.run_id,
            "attempt_id": attempt_id,
            "resolution": resolution,
        }
        try:
            self.owner_public_key.verify(bytes.fromhex(owner_signature_hex), _canonical_json(rec_payload))
        except (ValueError, InvalidSignature) as exc:
            return self._emit_receipt(
                "REFUSED_INVALID_RECONCILIATION_SIGNATURE",
                {
                    "attempt_id": attempt_id,
                    "error": f"Invalid owner signature: {exc}",
                    "enforced_action": "REMAIN_HALTED",
                },
            )

        self.reconciliation_required = False
        self.status = "ACTIVE"
        return self._emit_receipt(
            "UNCERTAIN_MUTATION_RECONCILED",
            {
                "attempt_id": attempt_id,
                "resolution": resolution,
                "enforced_action": "RESUME_PERMITTED",
            },
        )


# --- RC3 Integration with Hardened DurableGraphWatchdog (1P6tejwjy6EzYhspMPLu0qR_P5YbZ10V9) ---
import sys as _sys
from pathlib import Path as _Path
_GW_DIR = _Path(__file__).resolve().parents[1] / "OPENLINE-GRAPH-WATCHDOG-001" / "openline_graph_watchdog"
if str(_GW_DIR) not in _sys.path:
    _sys.path.insert(0, str(_GW_DIR))
from graph_watchdog import VerifiedAttempt, CrossAgentGraphWatchdog, unwitnessed_agreement, shared_bottlenecks  # noqa: E402
from durable_watchdog import DurableGraphWatchdog  # noqa: E402


class IntegratedGraphSupervisor:
    """
    Combines OpenLine's authoritative `ProjectLedger` + `ExecutionSupervisor` with the
    verified hardened `DurableGraphWatchdog` (Google Drive ID `1P6tejwjy6EzYhspMPLu0qR_P5YbZ10V9`).

    Invariants enforced:
    1. `DurableGraphWatchdog` is strictly advisory (`receiver_authorization == 'NONE'`).
       It cannot grant authority, revoke authority, or modify accepted Git state.
    2. `IntegratedGraphSupervisor` persists cross-agent stagnation and uncertain-mutation
       HOLD states in SQLite (`db_path`) and enforces `STOP_STAGNATION` and
       `HOLD_RECONCILIATION` across worker rotations (`alice -> bob -> carol`) and restarts.
    3. Every supervisor enforcement decision emits an Ed25519-signed receipt (`openline.supervisor.decision.v1`)
       while preserving all previously accepted Git commits in `ProjectLedger`.
    """

    def __init__(
        self,
        *,
        db_path: str | _Path,
        project_id: str,
        owner_public_key: Ed25519PublicKey,
        supervisor_signing_key: Ed25519PrivateKey,
        threshold: int = 3,
        project_ledger: Any = None,
    ) -> None:
        self.db_path = str(db_path)
        self.project_id = project_id
        self.owner_public_key = owner_public_key
        self.supervisor_signing_key = supervisor_signing_key
        self.threshold = threshold
        self.project_ledger = project_ledger
        self.watchdog = DurableGraphWatchdog(self.db_path, threshold=threshold)
        self.receipts: List[Dict[str, Any]] = []

    def _emit_signed_receipt(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        body = {
            "schema": "openline.supervisor.graph_decision.v1",
            "project_id": self.project_id,
            "event_type": event_type,
            "threshold": self.threshold,
            "watchdog_advisory_only": True,
            "payload": payload,
        }
        raw = _canonical_json(body)
        sig = self.supervisor_signing_key.sign(raw).hex()
        receipt = {
            **body,
            "receipt_sha256": _sha256_hex(raw),
            "supervisor_signature": sig,
            "supervisor_pub_ed25519_hex": self.supervisor_signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
        }
        self.receipts.append(receipt)
        return receipt

    def supervise_verified_attempt(self, attempt: VerifiedAttempt, *, assignment_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Passes a receiver-verified attempt to `DurableGraphWatchdog.record(attempt)` and
        enforces the resulting advisory decision (`CONTINUE`, `DUPLICATE_IGNORED`,
        `STOP_STAGNATION`, or `HOLD_RECONCILIATION`).
        """
        # Check pre-existing terminal status before recording
        prior = self.watchdog.status(attempt.deliverable_id, attempt.basis)
        advisory = self.watchdog.record(attempt)
        assert advisory["receiver_authorization"] == "NONE", "Watchdog must never claim receiver authorization"

        decision = advisory["decision"]
        if decision == "DUPLICATE_IGNORED":
            return self._emit_signed_receipt(
                "SUPERVISOR_DUPLICATE_IGNORED",
                {
                    "attempt_id": attempt.attempt_id,
                    "worker_id": attempt.worker_id,
                    "advisory": advisory,
                    "enforced_action": "IGNORE_DUPLICATE_NO_BUDGET_BURN",
                },
            )

        if decision == "HOLD_RECONCILIATION":
            return self._emit_signed_receipt(
                "SUPERVISOR_ENFORCED_HOLD_RECONCILIATION",
                {
                    "attempt_id": attempt.attempt_id,
                    "worker_id": attempt.worker_id,
                    "pre_existing_hold": bool(prior and prior.get("terminal") == "HOLD_RECONCILIATION"),
                    "advisory": advisory,
                    "enforced_action": "HALT_AWAIT_OWNER_RECONCILIATION",
                },
            )

        if decision == "STOP_STAGNATION":
            quarantined_id = None
            if self.project_ledger is not None and not (prior and prior.get("terminal") == "STOP_STAGNATION"):
                try:
                    mem_id = f"mem-graph-wd-stop-{attempt.deliverable_id}-{attempt.basis}-{attempt.attempt_id}"
                    asgn = assignment_id or attempt.attempt_id
                    self.project_ledger.propose_memory(
                        mem_id,
                        attempt.deliverable_id,
                        attempt.worker_id,
                        attempt.basis,
                        _sha256_hex(attempt.fingerprint().encode("utf-8")),
                        f"Cross-agent graph watchdog reached threshold {self.threshold} across workers {advisory['workers']}",
                        f"CROSS_AGENT_STAGNATION_STOP on {attempt.deliverable_id}@{attempt.basis}",
                        assignment_id=asgn,
                    )
                    self.project_ledger.quarantine_memory(
                        asgn,
                        reason=f"GRAPH_WATCHDOG_STOP_STAGNATION ({advisory['stagnant_attempts']}/{self.threshold})",
                    )
                    quarantined_id = mem_id
                except Exception:
                    pass
            return self._emit_signed_receipt(
                "SUPERVISOR_ENFORCED_STOP_STAGNATION",
                {
                    "attempt_id": attempt.attempt_id,
                    "worker_id": attempt.worker_id,
                    "pre_existing_stop": bool(prior and prior.get("terminal") == "STOP_STAGNATION"),
                    "quarantined_memory_id": quarantined_id,
                    "advisory": advisory,
                    "enforced_action": "HALT_SCOPE_STAGNANT",
                },
            )

        return self._emit_signed_receipt(
            "SUPERVISOR_ALLOW_CONTINUE",
            {
                "attempt_id": attempt.attempt_id,
                "worker_id": attempt.worker_id,
                "advisory": advisory,
                "enforced_action": "CONTINUE",
            },
        )

    def owner_reconcile_hold(
        self,
        *,
        deliverable_id: str,
        basis: str,
        resolution: str,
        owner_signature_hex: str,
    ) -> Dict[str, Any]:
        payload = {
            "action": "RECONCILE_GRAPH_WATCHDOG_HOLD",
            "project_id": self.project_id,
            "deliverable_id": deliverable_id,
            "basis": basis,
            "resolution": resolution,
        }
        try:
            self.owner_public_key.verify(bytes.fromhex(owner_signature_hex), _canonical_json(payload))
        except (ValueError, InvalidSignature) as exc:
            return self._emit_signed_receipt(
                "REFUSED_INVALID_OWNER_RECONCILIATION_SIGNATURE",
                {
                    "deliverable_id": deliverable_id,
                    "basis": basis,
                    "error": str(exc),
                    "enforced_action": "REMAIN_HELD",
                },
            )
        self.watchdog.clear_hold_after_reconciliation(deliverable_id, basis)
        return self._emit_signed_receipt(
            "OWNER_RECONCILED_HOLD_CLEARED",
            {
                "deliverable_id": deliverable_id,
                "basis": basis,
                "resolution": resolution,
                "status_after": self.watchdog.status(deliverable_id, basis),
                "enforced_action": "HOLD_CLEARED",
            },
        )
