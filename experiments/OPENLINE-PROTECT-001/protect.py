"""OpenLine Protect 001: receiver-owned repair admission and inspectable receipts.

Private local proof of an actual Git ref gate, NOT an agent-facing service.
A trusted receiver calls existing ProjectLedger.promote_repair; this adapter
never gives a worker access to ProjectLedger, SafePromotion or a signing key.
It does not claim effects beyond the accepted Git ref and project ledger.
"""
from __future__ import annotations
from contextlib import closing
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
import time
import uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEMA = "openline.protect.incident.v1"


def canonical(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode()


def _sha(data):
    return hashlib.sha256(data).hexdigest()


class ProtectError(RuntimeError):
    pass


def _worker_group_ids(worker_uid: int) -> set[int]:
    """Group ids the worker belongs to (primary + supplementary).

    Raises ProtectError when group membership cannot be determined:
    on a non-POSIX host the boundary is unverifiable, so admission
    must fail closed rather than assume the worker cannot write.
    """
    try:
        import grp
        import pwd
    except ImportError as exc:
        raise ProtectError("worker_group_membership_unverifiable") from exc
    try:
        pw = pwd.getpwuid(worker_uid)
        groups = {pw.pw_gid}
        worker_name = pw.pw_name
    except KeyError as exc:
        raise ProtectError("worker_uid_unknown") from exc
    if hasattr(os, "getgrouplist"):
        try:
            groups.update(os.getgrouplist(worker_name, pw.pw_gid))
        except OSError:
            pass
    for entry in grp.getgrall():
        if worker_name in entry.gr_mem or worker_uid in entry.gr_mem:
            groups.add(entry.gr_gid)
    return groups


def check_receiver_boundary(paths, *, receiver_uid: int,
                            worker_uid: int | None) -> list[str]:
    """Fail-closed precondition audit for the receiver-owned boundary.

    Returns failure reasons; empty means the boundary holds. This
    check verifies that OS separation IS in place (distinct UIDs,
    receiver-owned paths, no worker write access, no symlinks). It
    does not substitute for the separation itself: the OS boundary
    does the protecting; this check refuses to proceed when that
    separation is absent or unverifiable. A non-empty result must
    block admission; it is never an advisory warning.
    """
    if worker_uid is None:
        return ["worker_uid_undeclared"]
    if worker_uid == receiver_uid:
        return ["worker_uid_equals_receiver_uid"]
    try:
        worker_groups = _worker_group_ids(worker_uid)
    except ProtectError as exc:
        return [str(exc)]
    reasons: list[str] = []
    def _check_one(label: str, path: Path):
        if path.is_symlink():
            reasons.append(f"{label}_symlink_forbidden")
            return
        if not path.exists():
            reasons.append(f"{label}_missing")
            return
        st = path.stat()
        if st.st_uid != receiver_uid:
            reasons.append(f"{label}_not_receiver_owned")
        if st.st_mode & 0o002:
            reasons.append(f"{label}_world_writable")
        if st.st_mode & 0o020 and st.st_gid in worker_groups:
            reasons.append(f"{label}_group_writable_by_worker")

    for label, raw_path in paths:
        path = Path(raw_path)
        _check_one(label, path)
        if label in ("project_db", "effects_db"):
            for sidecar_suffix in ("-wal", "-shm", "-journal", ".gate.lock", ".control.sqlite"):
                sc = Path(str(path) + sidecar_suffix)
                if sc.exists() or sc.is_symlink():
                    _check_one(label, sc)
        if label in ("promotion_state", "incidents") and path.is_dir() and not path.is_symlink():
            for sub in path.rglob("*"):
                _check_one(label, sub)
    return sorted(set(reasons))


class Protect:
    """A trusted receiver-side adapter around the EXISTING project gate.

    *Candidate staging/worker isolation are separate, mandatory production gates.*
    Receipts prove only that the receiver signed an observation; independent
    auditors must reobserve Git and validate provenance for effect truth.
    """

    def __init__(self, project, receiver_signer: Ed25519PrivateKey, receipts_dir: Path, *, acceptance_cmd: tuple[str, ...],
                 worker_uid: int | None = None, receiver_key_path: Path | None = None):
        if not isinstance(receiver_signer, Ed25519PrivateKey):
            raise ProtectError("receiver_signing_key_required")
        if project.promotion is None:
            raise ProtectError("receiver_owned_project_promotion_required")
        if not isinstance(acceptance_cmd, tuple) or not acceptance_cmd or not all(type(x) is str and x for x in acceptance_cmd):
            raise ProtectError("operator_pinned_acceptance_command_required")
        self.acceptance_cmd = acceptance_cmd
        self.project = project
        try:
            self.project.promotion._bound_project = self.project
            self.project.promotion.require_final_gate = True
        except Exception:
            pass
        self.signer = receiver_signer
        # worker_uid=None preserves legacy callers (boundary unaudited).
        # Production admission MUST pass the worker UID: without it the
        # receiver cannot prove OS separation is in place. See VERDICT.
        self.worker_uid = worker_uid
        self.receiver_key_path = Path(receiver_key_path) if receiver_key_path else None
        self.receipts = Path(receipts_dir)
        if self.receipts.is_symlink():
            raise ProtectError("receipt_directory_symlink_forbidden")
        self.receipts.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not self.receipts.is_dir() or self.receipts.stat().st_mode & 0o077:
            raise ProtectError("receipt_directory_not_private")
        self.cached_stop_state: dict = {"stopped": False, "epoch": 1, "stop_seq": 0, "clear_seq": 0}

    def sync_stop_cache(self) -> dict:
        """Refresh the receiver's local stop cache from authoritative ProjectLedger standing."""
        if hasattr(self.project, "read_stop_state"):
            st = self.project.read_stop_state()
            self.cached_stop_state = dict(st)
        return dict(self.cached_stop_state)

    def preliminary_admit(self, assignment_id: str, *, use_stale_cache: bool = False) -> dict:
        """Preliminary receiver admission check (never sufficient to authorize final Git CAS)."""
        self._validate_assignment_id(assignment_id)
        if use_stale_cache:
            if self.cached_stop_state.get("stopped"):
                return {
                    "admitted": False,
                    "decision": "REFUSE",
                    "reason": f"STOPPED_AT_EPOCH_{self.cached_stop_state.get('epoch', 1)}",
                    "cache_used": True,
                }
            return {
                "admitted": True,
                "decision": "PRELIMINARY_ADMIT",
                "reason": "CACHED_STANDING_OK_NOT_FINAL_AUTHORITY",
                "cache_used": True,
                "cached_stop_state": dict(self.cached_stop_state),
            }
        if hasattr(self.project, "preliminary_admit"):
            return self.project.preliminary_admit(assignment_id)
        return {"admitted": True, "decision": "PRELIMINARY_ADMIT", "reason": "STANDING_OK"}

    def receiver_paths(self) -> list[tuple[str, Path]]:
        """Receiver-owned paths the worker must never write, directly."""
        paths: list[tuple[str, Path]] = []
        promotion = getattr(self.project, "promotion", None)
        if promotion is not None:
            for label, value in (("accepted_git", getattr(promotion, "repo", None)),
                                 ("effects_db", getattr(promotion, "live_db", None)),
                                 ("promotion_state", getattr(promotion, "state_dir", None))):
                if value is not None:
                    paths.append((label, Path(value)))
        db_path = getattr(self.project, "db_path", None)
        if db_path is not None:
            paths.append(("project_db", Path(db_path)))
        paths.append(("incidents", self.receipts))
        if self.receiver_key_path is not None:
            paths.append(("receiver_key", self.receiver_key_path))
        return paths

    def _boundary_failure(self, assignment_id: str) -> dict | None:
        """Fail-closed boundary check. Returns a refusal receipt, or None.

        Runs before any candidate import, promotion, or decision. A
        failure means admission is refused without evaluating the
        candidate: no ACCEPT/STOP verdict is signed, and the accepted
        ref is untouched. The UNKNOWN receipt is itself a signed
        record that admission was refused for a missing boundary.
        """
        if self.worker_uid is None:
            return None
        reasons = check_receiver_boundary(
            self.receiver_paths(), receiver_uid=os.getuid(),
            worker_uid=self.worker_uid)
        if not reasons:
            return None
        try:
            current = self.project.promotion.accepted()
        except Exception:
            current = ""
        return self._emit_receipt(
            assignment_id=assignment_id,
            candidate_paths=[],
            candidate_inventory="RECEIVER_BOUNDARY_CHECK",
            verdict="UNKNOWN_RECONCILIATION_REQUIRED",
            explanation="receiver_boundary_unavailable:" + ";".join(reasons),
            start=current,
            now=current,
            worker_isolation_evaluated=False,
            cleanup=False,  # No admission decision ran; preserve candidate.
        )

    @property
    def receiver_public_hex(self):
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        return self.signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    @staticmethod
    def _validate_assignment_id(assignment_id: str):
        if not isinstance(assignment_id, str) or not assignment_id or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in assignment_id):
            raise ProtectError("invalid_assignment")

    def _cleanup_stopped_candidate(self, assignment_id: str, incident_id: str) -> bool:
        """Archive refused/stopped pre-CAS candidate state and free task slot for successor retry."""
        try:
            state_path, state = self.project.promotion._load(assignment_id)
            if state.get("stage") not in ("PREPARED", "REFUSED"):
                return False
            archive_dir = self.project.promotion.state_dir / "archived"
            archive_dir.mkdir(parents=True, exist_ok=True)
            archived_state = dict(state, archived_incident_id=incident_id, archived_at_unix=int(time.time()))
            (archive_dir / f"task-{assignment_id}-{incident_id}.json").write_text(
                json.dumps(archived_state, sort_keys=True, indent=2) + "\n", encoding="utf8")
            wd = Path(state.get("workspace", ""))
            repo = getattr(self.project.promotion, "repo", None)
            if repo and wd.exists():
                subprocess.run(["git", "--git-dir", str(repo), "worktree", "remove", "--force", str(wd)],
                               capture_output=True, timeout=10, check=False)
            task_dir = state_path.parent
            if task_dir.is_dir() and task_dir.name == f"task-{assignment_id}":
                shutil.rmtree(task_dir)
            return True
        except Exception:
            return False

    def _emit_receipt(self, *, assignment_id: str, candidate_paths: list[str], candidate_inventory: str,
                      verdict: str, explanation: str | None, start: str, now: str,
                      worker_isolation_evaluated: bool = False,
                      cleanup: bool = True) -> dict:
        """Sign and persist an incident receipt.

        cleanup: free a pre-CAS task slot ONLY when the receiver gate
        actually evaluated a candidate and refused/failed before the
        ref moved. Paths that execute no admission decision (an
        unverified worker report, a missing receiver boundary) must
        pass cleanup=False: their candidate is still authorized and
        deleting its worktree would destroy prepared work (V-03
        correction to the #156 cleanup scope, preserving #152).
        """
        incident_id = uuid.uuid4().hex
        if cleanup and verdict in ("STOPPED", "UNKNOWN_RECONCILIATION_REQUIRED") and start == now:
            self._cleanup_stopped_candidate(assignment_id, incident_id)
            if verdict == "STOPPED" and hasattr(self.project, "quarantine_memory"):
                try:
                    self.project.quarantine_memory(assignment_id, str(explanation or "stopped"))
                except Exception:
                    pass
        incident = {
            "schema": SCHEMA,
            "incident_id": incident_id,
            "at_unix": int(time.time()),
            "project_id": self.project.id,
            "assignment": assignment_id,
            "observed_candidate_paths": candidate_paths,
            "candidate_inventory_source": candidate_inventory,
            "verdict": verdict,
            "reason": explanation,
            "gate": "EXISTING_PROJECT_LEDGER_PROMOTE_REPAIR",
            "accepted_ref_before": start,
            "accepted_ref_after": now,
            "accepted_ref_unchanged": start == now,
            "authority": "RECEIVER_OWNED_SIGNED_ASSIGNMENT",
            "receipt_scope": "LOCAL_ACCEPTED_GIT_REF_AND_PROJECT_LEDGER_ONLY",
            "external_effect_truth": "UNKNOWN",
            "independent_git_observation_required": True,
            "worker_isolation_evaluated": bool(worker_isolation_evaluated),
            "model_inference_evaluated": False,
            "deployment_claim": "PRIVATE_DEMO_ONLY",
        }
        raw = canonical(incident)
        receipt = {"payload": incident, "payload_sha256": _sha(raw),
                   "signature_ed25519_hex": self.signer.sign(raw).hex(),
                   "receiver_pub_ed25519_hex": self.receiver_public_hex}
        output = self.receipts / (incident["incident_id"] + ".json")
        # Exclusive creation, no clobber or following a prior symlink.
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf8") as f:
                json.dump(receipt, f, sort_keys=True, indent=2)
                f.flush()
                os.fsync(f.fileno())
            dirfd = os.open(str(self.receipts), os.O_RDONLY)
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
        except BaseException:
            raise
        if hasattr(self.project, "db_path"):
            try:
                import sqlite3 as _sq
                with closing(_sq.connect(str(self.project.db_path))) as _db:
                    has_tbl = _db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='earned_memory'").fetchone()
                    if has_tbl:
                        _db.execute("UPDATE earned_memory SET receipt_sha256=? WHERE assignment_id=? AND receipt_sha256 IS NULL",
                                    (receipt["payload_sha256"], assignment_id))
                        _db.commit()
            except Exception:
                pass
        return {"receipt": receipt, "path": str(output), "verdict": verdict}

    def reconcile(self, assignment_id: str) -> dict:
        """Idempotently reconcile an interrupted post-CAS promotion from SafePromotion journal."""
        self._validate_assignment_id(assignment_id)
        refused = self._boundary_failure(assignment_id)
        if refused is not None:
            return refused
        start = self.project.promotion.accepted()
        expected_before = start
        try:
            _, state = self.project.promotion._load(assignment_id)
            if isinstance(state.get("expected_head"), str) and len(state["expected_head"]) == 40:
                expected_before = state["expected_head"]
        except Exception:
            state = {}
        error = None
        recovered = None
        try:
            recovered = self.project.promotion.recover(assignment_id)
        except Exception as exc:
            error = "promotion_recover_exception:" + type(exc).__name__
        now = self.project.promotion.accepted()
        explanation = None
        if error is not None or not isinstance(recovered, dict):
            verdict = "UNKNOWN_RECONCILIATION_REQUIRED"
            explanation = error or "unknown_promotion_recover_response"
        elif recovered.get("status") in ("PROMOTED", "PROMOTED_RECOVERED") and recovered.get("head") == now:
            try:
                recorded = self.project.resolve_repair(assignment_id, now)
                if recorded in ("RECORDED", "ALREADY_RECORDED"):
                    verdict = "ACCEPTED"
                    explanation = None
                else:
                    verdict = "UNKNOWN_RECONCILIATION_REQUIRED"
                    explanation = "unexpected_reconciliation_status"
            except Exception as exc:
                from project import ProjectRefused
                if isinstance(exc, ProjectRefused) and expected_before == now:
                    verdict = "STOPPED"
                    explanation = str(exc)
                else:
                    verdict = "UNKNOWN_RECONCILIATION_REQUIRED"
                    explanation = "project_reconciliation_exception:" + type(exc).__name__
        elif recovered.get("status") == "REFUSED" and expected_before == now:
            if hasattr(self.project, "reconcile_pending_cas"):
                try:
                    self.project.reconcile_pending_cas()
                except Exception:
                    pass
            verdict = "STOPPED"
            explanation = recovered.get("reason") or "cas_not_applied"
        else:
            verdict = "UNKNOWN_RECONCILIATION_REQUIRED"
            explanation = recovered.get("reason") or "promotion_journal_not_reconcilable"
        return self._emit_receipt(
            assignment_id=assignment_id,
            candidate_paths=[],
            candidate_inventory="PROMOTION_JOURNAL_RECOVERY",
            verdict=verdict,
            explanation=explanation,
            start=expected_before,
            now=now,
            worker_isolation_evaluated=False,
        )

    def intercept(self, assignment_id: str, *, timeout=20, worker_result=None):
        """Recheck the signed assignment at effect entry through ProjectLedger.

        acceptance_cmd must be a trusted operator-pinned verifier. No caller-
        controlled validator, path, executable, or policy is exposed to agents.
        """
        self._validate_assignment_id(assignment_id)
        refused = self._boundary_failure(assignment_id)
        if refused is not None:
            return refused
        try:
            _, pre_state = self.project.promotion._load(assignment_id)
            if pre_state.get("stage") in ("CAS_PENDING", "PROMOTED", "PROMOTED_RECOVERED"):
                return self.reconcile(assignment_id)
        except Exception:
            pass
        if worker_result is not None and getattr(worker_result, "outcome", None) != "CANDIDATE":
            start = self.project.promotion.accepted()
            now = self.project.promotion.accepted()
            outcome_name = str(getattr(worker_result, "outcome", "FAILED"))
            details = str(getattr(worker_result, "details", "") or outcome_name)
            candidate_paths = sorted(set(str(x) for x in getattr(worker_result, "changes", ())))[:256]
            # A caller-supplied object is NOT an independently verified sandbox
            # event. Never sign an isolation PASS or gate STOP merely because
            # worker_result says REFUSED_SCOPE, even if Git did not change.
            # No receiver admission decision was executed on this path.
            verdict = "UNKNOWN_RECONCILIATION_REQUIRED"
            explanation = "worker_refusal_unverified_no_receiver_gate:" + outcome_name.lower()
            return self._emit_receipt(
                assignment_id=assignment_id,
                candidate_paths=candidate_paths,
                candidate_inventory="UNVERIFIED_WORKER_REPORT",
                verdict=verdict,
                explanation=explanation,
                start=start,
                now=now,
                worker_isolation_evaluated=False,
                cleanup=False,  # No gate decision ran; preserve candidate.
            )
        # Diagnostic only: read candidate worktree status from trusted promotion
        # journal. The authoritative scope decision remains ProjectLedger + CAS.
        candidate_paths = []
        candidate_inventory = "UNAVAILABLE"
        worker_isolated = False
        if worker_result is not None and getattr(worker_result, "outcome", None) == "CANDIDATE":
            candidate_paths = sorted(set(str(x) for x in getattr(worker_result, "changes", ())))[:256]
            # Candidate still passes the real project gate. Its origin and
            # OS isolation are NOT established by the worker_result object.
            candidate_inventory = "UNVERIFIED_WORKER_REPORT"
            worker_isolated = False
        else:
            try:
                _, state = self.project.promotion._load(assignment_id)
                wd = Path(state['workspace'])
                p = subprocess.run(['git', '-C', str(wd), 'status', '--porcelain=v1', '-z',
                                    '--untracked-files=all'], capture_output=True, timeout=5)
                if p.returncode == 0 and len(p.stdout) <= 262144:
                    candidate_paths = sorted(set(x[3:].decode('utf8', 'replace') for x in p.stdout.split(b'\0')
                                                 if len(x) >= 4 and x[2:3] == b' '))[:256]
                    candidate_inventory = "UNTRUSTED_WORKTREE_STATUS_DIAGNOSTIC"
            except (OSError, ValueError, subprocess.TimeoutExpired, KeyError, AttributeError):
                pass
        start = self.project.promotion.accepted()
        result = None
        error = None
        try:
            result = self.project.promote_repair(assignment_id, acceptance_cmd=list(self.acceptance_cmd), timeout=timeout)
            if not isinstance(result, dict) or result.get("status") not in ("REFUSED", "PROMOTED"):
                error = "unknown_project_gate_response"
        except Exception as exc:
            # Only the exact existing receiver ProjectRefused type is a refusal.
            # Do not mark arbitrary runtime errors or post-CAS failures as STOP.
            from project import ProjectRefused
            if isinstance(exc, ProjectRefused):
                result = {"status": "REFUSED", "reason": str(exc)}
            else:
                error = "project_gate_exception:" + type(exc).__name__
        now = self.project.promotion.accepted()
        if error is not None:
            verdict = "UNKNOWN_RECONCILIATION_REQUIRED"
        elif result["status"] == "REFUSED" and start == now:
            verdict = "STOPPED"
        elif result["status"] == "REFUSED":
            verdict = "UNKNOWN_RECONCILIATION_REQUIRED"
        elif result["status"] == "PROMOTED" and result.get("head") == now:
            try:
                recorded = self.project.resolve_repair(assignment_id, now)
                verdict = "ACCEPTED" if recorded in ("RECORDED", "ALREADY_RECORDED") else "UNKNOWN_RECONCILIATION_REQUIRED"
            except Exception as exc:
                error = "project_reconciliation_exception:" + type(exc).__name__
                verdict = "UNKNOWN_RECONCILIATION_REQUIRED"
        else:
            verdict = "UNKNOWN_RECONCILIATION_REQUIRED"
        # A STOP receipt is based on an observed unchanged Git head, not a
        # model self-report. This still does not establish absence of external effects.
        explanation = error or (result.get("reason") if result and result.get("status") == "REFUSED" else None)
        return self._emit_receipt(
            assignment_id=assignment_id,
            candidate_paths=candidate_paths,
            candidate_inventory=candidate_inventory,
            verdict=verdict,
            explanation=explanation,
            start=start,
            now=now,
            worker_isolation_evaluated=worker_isolated,
        )


def verify_receipt(receipt: dict, trusted_receiver_pub_hex: str, *,
                   accepted_git: Path | None = None, project_db: Path | None = None) -> dict:
    """Offline cryptographic integrity check, with optional live Git + continuity verification."""
    if not isinstance(receipt, dict) or set(receipt) != {"payload", "payload_sha256", "signature_ed25519_hex", "receiver_pub_ed25519_hex"}:
        raise ProtectError("invalid_receipt_schema")
    if receipt["receiver_pub_ed25519_hex"] != trusted_receiver_pub_hex:
        raise ProtectError("untrusted_receiver_public_key")
    payload = receipt["payload"]
    if not isinstance(payload, dict) or payload.get("schema") != SCHEMA:
        raise ProtectError("invalid_payload_schema")
    raw = canonical(payload)
    if _sha(raw) != receipt["payload_sha256"]:
        raise ProtectError("receipt_digest_mismatch")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted_receiver_pub_hex)).verify(
            bytes.fromhex(receipt["signature_ed25519_hex"]), raw)
    except Exception as exc:
        raise ProtectError("receipt_signature_invalid") from exc
    if payload.get("verdict") == "STOPPED" and (payload.get("accepted_ref_unchanged") is not True or
                                                       payload.get("accepted_ref_after") != payload.get("accepted_ref_before")):
        raise ProtectError("stopped_receipt_inconsistent")
    out = {"crypto": "VERIFIED", "receiver": trusted_receiver_pub_hex,
           "verdict": payload["verdict"], "incident_id": payload["incident_id"],
           "effect_truth": "NOT_INFERRED_FROM_RECEIPT"}
    live_head = None
    if accepted_git is not None:
        git_dir = Path(accepted_git)
        if not git_dir.is_dir() or git_dir.is_symlink():
            raise ProtectError("accepted_git_invalid")
        p = subprocess.run(["git", "--git-dir", str(git_dir), "rev-parse", "--verify", "refs/heads/accepted^{commit}"],
                           capture_output=True, text=True, timeout=5)
        if p.returncode != 0:
            raise ProtectError("accepted_git_ref_unavailable")
        live_head = p.stdout.strip()
        ref_after = payload.get("accepted_ref_after")
        if not isinstance(ref_after, str) or len(ref_after) != 40:
            raise ProtectError("accepted_git_ref_mismatch")
        if live_head != ref_after:
            # Strict current-state verification fails closed unless project_db
            # proves both live_head and ref_after were receiver-admitted commits
            # and ref_after is a Git ancestor of live_head.
            historical_ok = False
            if project_db is not None and Path(project_db).is_file():
                anc = subprocess.run(["git", "--git-dir", str(git_dir), "merge-base", "--is-ancestor", ref_after, live_head],
                                     capture_output=True, timeout=5)
                if anc.returncode == 0:
                    import sqlite3 as _sq
                    with closing(_sq.connect(str(project_db))) as _conn:
                        _proj = _conn.execute("SELECT last_accepted FROM projects").fetchone()
                        _asgn = _conn.execute("SELECT state, promoted_head FROM assignments WHERE id=?",
                                              (payload.get("assignment"),)).fetchone()
                    if _proj and _proj[0] == live_head and _asgn and _asgn[0] == "COMMITTED" and _asgn[1] == ref_after:
                        historical_ok = True
            if not historical_ok:
                raise ProtectError("accepted_git_ref_mismatch")
            out["historical"] = True
        out["git_verified"] = True
        out["accepted_git_head"] = live_head
    if project_db is not None:
        import sys
        continuity_dir = Path(__file__).resolve().parents[1] / "OPENLINE-PROTECT-002"
        if not continuity_dir.is_dir():
            # Flat release layout: continuity.py sits next to protect.py.
            # The experiments layout above stays the first choice; this
            # fallback only removes a layout-dependent import failure.
            same_dir = Path(__file__).resolve().parent
            if (same_dir / "continuity.py").is_file():
                continuity_dir = same_dir
        if continuity_dir.is_dir() and str(continuity_dir) not in sys.path:
            sys.path.insert(0, str(continuity_dir))
        try:
            from continuity import audit as continuity_audit, ContinuityRefused
            report = continuity_audit(Path(project_db))
        except Exception as exc:
            raise ProtectError("project_continuity_audit_failed:" + str(exc)) from exc
        if report.get("assessment") != "NO_RECORDED_STALE_DEPENDENCY_FOUND" or report.get("flagged_current_deliverables") != 0:
            raise ProtectError("project_continuity_unproven")
        if live_head is not None and report.get("ledger_accepted_head") != live_head:
            raise ProtectError("project_ledger_git_head_drift")
        # Cryptographic validity does not establish this incident belongs to
        # the independently observed project or a real assignment.
        if payload.get("project_id") != report.get("project"):
            raise ProtectError("receipt_project_id_mismatch")
        import sqlite3
        with closing(sqlite3.connect(str(project_db))) as conn:
            row = conn.execute("SELECT state FROM assignments WHERE id=?",
                               (payload.get("assignment"),)).fetchone()
        if row is None:
            raise ProtectError("receipt_assignment_not_found")
        if payload.get("verdict") == "ACCEPTED" and row[0] != "COMMITTED":
            raise ProtectError("receipt_assignment_not_committed")
        if payload.get("verdict") == "STOPPED" and row[0] not in ("ASSIGNED", "COMMITTED"):
            raise ProtectError("receipt_assignment_status_invalid")
        out["continuity_verified"] = True
        out["continuity_assessment"] = report["assessment"]
    return out
