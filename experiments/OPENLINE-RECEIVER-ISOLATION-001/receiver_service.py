"""OpenLine Production Isolation — Dedicated Multi-Socket Receiver Daemon (`receiver_service.py`).

Implements Sections 2, 3, 4, 5, and 6 of Astra's Production Isolation Blueprint:
- Dedicated `worker.sock` and priority `control.sock` Unix domain socket listeners.
- Kernel `SO_PEERCRED` authentication + `openline.ipc.request.v1` Ed25519 signature verification.
- Durable `ipc_requests` idempotency/nonce ledger and wall-clock high-water mark in `project.sqlite`.
- Single promotion lane (`promotion_lane_lock`) with immediate `control.stop` / `control.revoke_member`
  preemption of in-flight validator process groups (`<50ms`).
- Byte-only `assignment.prepare` (`snapshot.chunk`) and `proposal.submit` (`candidate_transfer.py`).
- Isolated candidate validation (`IsolatedValidationRunner`) and `validation_context_sha256` recheck.
- Durable `ReceiptOutbox` and startup crash reconciliation across cut points `CUT-01` .. `CUT-06`.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = Path(__file__).resolve().parent
EXPERIMENTS = HERE.parent
for _rel in (
    "SELF-HEALING-ENGINE-001",
    "SELF-HEALING-PROJECTS-001",
    "OPENLINE-PROTECT-001",
    "OPENLINE-PROTECT-002",
    "LIVING-PROJECTS-001",
    "OPENLINE-RELEASE-001",
):
    _p = str(EXPERIMENTS / _rel)
    if _p not in sys.path:
        sys.path.insert(0, _p)
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from candidate_transfer import (  # noqa: E402
    CandidateTransferError,
    build_workspace_manifest,
    read_snapshot_chunk,
    validate_and_apply_candidate_files,
)
from durable_io import (  # noqa: E402
    OpenAt2Error,
    atomic_write_json,
    connect_durable_sqlite,
    fsync_directory,
    kernel_supports_native_openat2,
)
from git_runner import SanitizedGitRunner  # noqa: E402
from ipc_protocol import (  # noqa: E402
    IPCProtocolError,
    PerUIDRateLimiter,
    canonical_json_bytes,
    extract_peer_credentials,
    recv_frame,
    send_frame,
    sha256_hex,
    sign_ipc_response,
    strict_loads_json,
    verify_ipc_request_envelope,
)
from preflight import audit_production_preflight  # noqa: E402
from production_config import validate_production_config  # noqa: E402
from receipt_outbox import ReceiptOutbox  # noqa: E402
from validation_runner import (  # noqa: E402
    IsolatedValidationRunner,
    ValidationJob,
    compute_validation_context_sha256,
)

from foundation.promotion import PromotionRefused, SafePromotion  # noqa: E402
from project import ProjectLedger, ProjectRefused  # noqa: E402
from protect import Protect, ProtectError, check_receiver_boundary  # noqa: E402
from continuity import audit as continuity_audit  # noqa: E402
import living_project  # noqa: E402


def _load_ed25519_private_key(path: Path) -> Ed25519PrivateKey:
    if path.is_symlink() or not path.is_file():
        raise ProtectError(f"receiver_key_invalid:{path}")
    seed = bytes.fromhex(path.read_text(encoding="utf-8").strip())
    return Ed25519PrivateKey.from_private_bytes(seed)


def _pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


class OpenLineReceiverService:
    """Production-isolated receiver service managing accepted Git state, SQLite ledgers, and signing."""

    def __init__(
        self,
        config: dict[str, Any],
        *,
        validation_runner=None,
        require_distinct_uids: bool = False,
        require_systemd_hardening: bool = False,
        crash_cutpoint: str | None = None,
        crash_mode: str = "EXCEPTION",
    ):
        self.config = validate_production_config(config)
        self.deployment_id = self.config["deployment_id"]
        self.project_id = self.config["project_id"]
        self.receiver_id = self.config["receiver_id"]
        self.owner_pub = self.config["owner_pub"]
        self.paths = self.config["paths"]
        self.limits = self.config["limits"]
        self.require_distinct_uids = require_distinct_uids
        self.require_systemd_hardening = require_systemd_hardening
        self.crash_cutpoint = crash_cutpoint
        self.crash_mode = crash_mode

        # 1. Run preflight audit before opening keys or databases
        self.preflight_report = audit_production_preflight(
            self.config,
            require_distinct_uids=require_distinct_uids,
            require_systemd_hardening=require_systemd_hardening,
        )
        if not self.preflight_report.ok:
            raise ProtectError("receiver_preflight_failed:" + ";".join(self.preflight_report.reasons))

        # 2. Load receiver signing key and verify pinned receiver_pub
        self.receiver_key_path = Path(self.paths["receiver_key_file"])
        self.receiver_key = _load_ed25519_private_key(self.receiver_key_path)
        self.receiver_pub = _pub_hex(self.receiver_key)
        if self.receiver_pub != self.config["receiver_pub"]:
            raise ProtectError("receiver_key_mismatch_with_pinned_pub")

        # 3. Initialize SanitizedGitRunner and IsolatedValidationRunner
        self.git_runner = SanitizedGitRunner(self.paths["empty_hooks_dir"], home_dir=self.paths["root_dir"])
        if require_distinct_uids and (
            self.config.get("allow_single_uid_test_harness") or self.config.get("allow_enosys_openat2_fallback")
        ):
            raise ProtectError("production_forbids_test_harness_fallbacks")
        if require_distinct_uids and validation_runner is None:
            raise ProtectError("external_validator_required")
        self.require_native_openat2 = True if require_distinct_uids else bool(
            self.config.get(
                "require_native_openat2",
                kernel_supports_native_openat2() if self.config.get("allow_single_uid_test_harness") else True,
            )
        )
        self.worker_isolation_evaluated = bool(
            self.require_distinct_uids
            and not self.config.get("allow_single_uid_test_harness")
            and not getattr(validation_runner, "allow_single_uid_test_harness", False)
        )
        self.validation_runner = validation_runner or IsolatedValidationRunner(
            self.paths["validation_spool_dir"],
            validator_uid=self.config["validator_uid"],
            validator_gid=self.config["validator_gid"],
            abort_check=self._should_abort_validation,
        )

        # 4. Initialize SafePromotion, ProjectLedger, Protect, and ReceiptOutbox
        first_worker_uid = next(iter(self.config["worker_principals"].values()))["uid"]
        self.promotion = SafePromotion(
            Path(self.paths["accepted_git"]),
            Path(self.paths["effects_db"]),
            Path(self.paths["promotion_dir"]),
            require_final_gate=True,
            git_runner=self.git_runner,
            validation_runner=self.validation_runner,
        )
        self.project = ProjectLedger(
            Path(self.paths["project_db"]),
            self.project_id,
            self.config.get("objective", "OpenLine project"),
            self.owner_pub,
            promotion=self.promotion,
            world_verifier=lambda receipt, invitation: receipt.get("member") == invitation.get("member_id"),
            strict_production=True,
        )
        self.protect = Protect(
            self.project,
            self.receiver_key,
            Path(self.paths["incidents_dir"]),
            acceptance_cmd=(sys.executable, "-B", self.paths["validator_script"], self.paths["project_db"]),
            worker_uid=first_worker_uid if require_distinct_uids else 65534,
            receiver_key_path=self.receiver_key_path,
        )
        self.outbox = ReceiptOutbox(self.paths["project_db"], self.paths["incidents_dir"])
        self._init_ipc_tables()

        self.rate_limiter = PerUIDRateLimiter(
            burst=int(self.limits["rate_limit_burst"]),
            rate_per_sec=float(self.limits["rate_limit_per_sec"]),
        )
        self._promotion_lane_lock = threading.Lock()
        self._db_tx_lock = threading.RLock()
        self._shutdown_event = threading.Event()
        self._server_sockets: list[socket.socket] = []
        self._accept_threads: list[threading.Thread] = []

        # 5. Run startup crash recovery & receipt outbox reconciliation
        self.startup_reconciliation = self.reconcile_startup()

    def _trigger_cutpoint(self, name: str) -> None:
        if self.crash_cutpoint != name:
            return
        if self.crash_mode == "SIGKILL":
            os.kill(os.getpid(), 9)
        raise RuntimeError(f"injected_crash_{name}")

    def _init_ipc_tables(self) -> None:
        with closing(connect_durable_sqlite(self.paths["project_db"])) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS ipc_requests (
                    deployment_id TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    state TEXT NOT NULL,
                    response_json TEXT,
                    receipt_sha256 TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (deployment_id, principal_id, request_id),
                    UNIQUE (deployment_id, principal_id, nonce)
                );
                CREATE TABLE IF NOT EXISTS receiver_clock_state (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    high_water_unix INTEGER NOT NULL DEFAULT 0
                );
                INSERT OR IGNORE INTO receiver_clock_state VALUES (1, 0);
            """)
            db.commit()

    def _get_and_advance_high_water_clock(self) -> int:
        now = int(time.time())
        with self._db_tx_lock, closing(connect_durable_sqlite(self.paths["project_db"])) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT high_water_unix FROM receiver_clock_state WHERE id=1").fetchone()
            hw = int(row[0]) if row else 0
            effective = max(now, hw)
            if effective > hw:
                db.execute("UPDATE receiver_clock_state SET high_water_unix=? WHERE id=1", (effective,))
            db.commit()
            return effective

    def _should_abort_validation(self) -> bool:
        try:
            st = self.project.read_stop_state()
            return bool(st.get("stopped"))
        except Exception:
            return True

    def reconcile_startup(self) -> dict[str, Any]:
        """Reconcile any interrupted promotions, pending CAS reservations, and unpublished outbox receipts."""
        with self._db_tx_lock:
            flushed_before = self.outbox.flush_outbox()
            reconciled_assignments: list[dict[str, Any]] = []

            # Inspect any assignments with PENDING_CAS or CAS_PENDING journal state
            with closing(connect_durable_sqlite(self.paths["project_db"])) as db:
                pending_rows = db.execute(
                    "SELECT assignment_id, cas_state, cas_target_head, cas_expected_head FROM assignment_standing WHERE cas_state IN ('PENDING_CAS', 'HOLD_RECONCILIATION')"
                ).fetchall()
                assigned_rows = db.execute("SELECT id FROM assignments WHERE state='ASSIGNED'").fetchall()

            candidates = {r[0] for r in pending_rows} | {r[0] for r in assigned_rows}
            for asgn_id in sorted(candidates):
                promo_state_file = Path(self.paths["promotion_dir"]) / f"task-{asgn_id}" / "state.json"
                has_pending_cas = any(r[0] == asgn_id for r in pending_rows)
                stage = None
                if promo_state_file.is_file():
                    try:
                        stage = json.loads(promo_state_file.read_text(encoding="utf-8")).get("stage")
                    except Exception:
                        stage = "CORRUPT"
                if has_pending_cas or stage in ("CAS_PENDING", "TESTING", "PROMOTED", "PROMOTED_RECOVERED"):
                    if stage == "TESTING" and not has_pending_cas:
                        # CUT-01: interrupted during validation before final gate reservation
                        try:
                            st_path, st_obj = self.promotion._load(asgn_id)
                            merged = st_path.parent / "merged"
                            if merged.exists():
                                self.git_runner.run("--git-dir", str(self.promotion.repo), "worktree", "remove", "--force", str(merged), check=False)
                            st_obj["stage"] = "PREPARED"
                            atomic_write_json(st_path, st_obj)
                            reconciled_assignments.append({"assignment": asgn_id, "action": "RESET_INTERRUPTED_TESTING_TO_PREPARED"})
                        except Exception as exc:
                            reconciled_assignments.append({"assignment": asgn_id, "action": f"TESTING_CLEANUP_ERR:{exc}"})
                    else:
                        # CUT-02 / CUT-03 / CUT-05: reconcile via Protect + ReceiptOutbox
                        existing_outbox = self.outbox.get_by_assignment(asgn_id)
                        if existing_outbox and existing_outbox["verdict"] == "ACCEPTED":
                            try:
                                self.project.resolve_repair(asgn_id, existing_outbox["receipt"]["payload"]["accepted_ref_after"], receipt_sha256=existing_outbox["receipt_sha256"])
                            except Exception:
                                pass
                            reconciled_assignments.append({"assignment": asgn_id, "action": "OUTBOX_ALREADY_RECORDED", "verdict": existing_outbox["verdict"]})
                        else:
                            rec_out = self.protect.reconcile(asgn_id)
                            self.outbox.enqueue(
                                operation_id=f"reconcile:{asgn_id}:{rec_out['receipt']['payload']['accepted_ref_after']}",
                                assignment_id=asgn_id,
                                receipt=rec_out["receipt"],
                            )
                            reconciled_assignments.append({"assignment": asgn_id, "action": "RECONCILED", "verdict": rec_out["verdict"]})

            flushed_after = self.outbox.flush_outbox()
            return {
                "flushed_before": flushed_before,
                "reconciled_assignments": reconciled_assignments,
                "flushed_after": flushed_after,
            }

    def start_background(self) -> None:
        """Bind `worker.sock` and `control.sock` and start background accept loops."""
        for channel, sock_key in (("worker", "worker_socket"), ("control", "control_socket")):
            sock_path = Path(self.paths[sock_key])
            sock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o711)
            if sock_path.exists() or sock_path.is_symlink():
                sock_path.unlink()
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(str(sock_path))
            os.chmod(sock_path, 0o660)
            srv.listen(64)
            self._server_sockets.append(srv)
            t = threading.Thread(
                target=self._accept_loop,
                args=(srv, channel),
                name=f"openline-{channel}-listener",
                daemon=True,
            )
            t.start()
            self._accept_threads.append(t)

    def stop(self) -> None:
        self._shutdown_event.set()
        self.validation_runner.preempt_active_validations()
        for srv in self._server_sockets:
            try:
                srv.close()
            except OSError:
                pass
        for sock_key in ("worker_socket", "control_socket"):
            p = Path(self.paths[sock_key])
            if p.exists():
                try:
                    p.unlink()
                except OSError:
                    pass

    def _accept_loop(self, srv: socket.socket, channel: str) -> None:
        while not self._shutdown_event.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                break
            t = threading.Thread(
                target=self._handle_client_connection,
                args=(conn, channel),
                daemon=True,
            )
            t.start()

    def _resolve_peer_principal(self, peer_uid: int, channel: str, envelope: dict[str, Any]) -> tuple[str, str, str | None]:
        """Verify peer UID is authorized for `channel` and return `(principal_id, expected_signer_pub, member_id)`."""
        req_principal = envelope.get("principal_id", "")
        single_uid_ok = bool(self.config.get("allow_single_uid_test_harness", False) and not self.require_distinct_uids and peer_uid == self.config["receiver_uid"])
        if channel == "worker":
            w_entry = self.config["worker_principals"].get(str(peer_uid))
            if (w_entry is None or w_entry["principal_id"] != req_principal) and single_uid_ok:
                for cand in self.config["worker_principals"].values():
                    if cand["principal_id"] == req_principal or f"worker:{cand['member_id']}" == req_principal:
                        w_entry = cand
                        break
            if w_entry is None:
                raise IPCProtocolError(f"unauthorized_worker_uid:{peer_uid}", code="PEER_UID_UNAUTHORIZED")
            member_id = w_entry["member_id"]
            with closing(connect_durable_sqlite(self.paths["project_db"], read_only=True)) as db:
                row = db.execute(
                    "SELECT owner_pub, worker_pub, active FROM members WHERE project_id=? AND member_id=?",
                    (self.project_id, member_id),
                ).fetchone()
            if row is None or row[2] != 1:
                raise IPCProtocolError(f"worker_member_revoked_or_inactive:{member_id}", code="MEMBER_REVOKED")
            live_worker_pub = row[1]
            return w_entry["principal_id"], live_worker_pub, member_id

        c_entry = self.config["control_principals"].get(str(peer_uid))
        if (c_entry is None or c_entry["principal_id"] != req_principal) and single_uid_ok:
            for cand in self.config["control_principals"].values():
                if cand["principal_id"] == req_principal:
                    c_entry = cand
                    break
        if c_entry is None:
            raise IPCProtocolError(f"unauthorized_control_uid:{peer_uid}", code="PEER_UID_UNAUTHORIZED")
        if c_entry.get("role") == "owner":
            expected_pub = self.project.owner_pub
        else:
            expected_pub = c_entry.get("public_key") or self.project.owner_pub
        return c_entry["principal_id"], expected_pub, None

    def _handle_client_connection(self, conn: socket.socket, channel: str) -> None:
        with conn:
            conn.settimeout(60.0)
            req_id = "unknown"
            req_sha = "0" * 64
            try:
                _pid, peer_uid, _peer_gid = extract_peer_credentials(conn)
                if not self.rate_limiter.allow(peer_uid):
                    raise IPCProtocolError("rate_limit_exceeded", code="RATE_LIMITED")

                raw_frame = recv_frame(conn, max_frame_bytes=int(self.limits["max_frame_bytes"]))
                env = strict_loads_json(raw_frame)
                if isinstance(env.get("request_id"), str):
                    req_id = env["request_id"]
                req_sha = sha256_hex(env)

                principal_id, expected_pub, member_id = self._resolve_peer_principal(peer_uid, channel, env)
                hw_unix = self._get_and_advance_high_water_clock()
                verify_ipc_request_envelope(
                    env,
                    expected_deployment_id=self.deployment_id,
                    expected_project_id=self.project_id,
                    expected_receiver_id=self.receiver_id,
                    expected_channel=channel,
                    expected_principal_id=principal_id,
                    expected_signer_pub=expected_pub,
                    max_skew_s=int(self.limits["max_clock_skew_s"]),
                    high_water_unix=hw_unix,
                )

                resp = self._dispatch_authenticated_request(env, req_sha=req_sha, principal_id=principal_id, member_id=member_id)
                self._trigger_cutpoint("CUT-06")
                send_frame(conn, canonical_json_bytes(resp), max_frame_bytes=int(self.limits["max_frame_bytes"]))
            except IPCProtocolError as exc:
                err_resp = sign_ipc_response(
                    self.receiver_key,
                    deployment_id=self.deployment_id,
                    project_id=self.project_id,
                    receiver_id=self.receiver_id,
                    request_id=req_id,
                    request_sha256=req_sha,
                    status=exc.status,
                    code=exc.code,
                    result={"error": str(exc)},
                )
                try:
                    send_frame(conn, canonical_json_bytes(err_resp))
                except Exception:
                    pass
            except Exception as exc:
                if isinstance(exc, RuntimeError) and str(exc).startswith("injected_crash_"):
                    return
                err_resp = sign_ipc_response(
                    self.receiver_key,
                    deployment_id=self.deployment_id,
                    project_id=self.project_id,
                    receiver_id=self.receiver_id,
                    request_id=req_id,
                    request_sha256=req_sha,
                    status="ERROR",
                    code="INTERNAL_ERROR",
                    result={"error": f"{type(exc).__name__}:{exc}"},
                )
                try:
                    send_frame(conn, canonical_json_bytes(err_resp))
                except Exception:
                    pass

    def _check_or_reserve_idempotency(
        self,
        *,
        principal_id: str,
        request_id: str,
        nonce: str,
        operation: str,
        req_sha: str,
    ) -> dict[str, Any] | None:
        now = int(time.time())
        with self._db_tx_lock, closing(connect_durable_sqlite(self.paths["project_db"])) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT request_sha256, state, response_json, nonce FROM ipc_requests WHERE deployment_id=? AND principal_id=? AND request_id=?",
                (self.deployment_id, principal_id, request_id),
            ).fetchone()
            if row is not None:
                stored_sha, state, resp_json, stored_nonce = row
                if stored_sha != req_sha or stored_nonce != nonce:
                    db.rollback()
                    raise IPCProtocolError("idempotency_conflict_for_request_id", code="IDEMPOTENCY_CONFLICT")
                if resp_json is not None:
                    db.commit()
                    stored_resp = json.loads(resp_json)
                    # Re-sign with replayed=True so caller knows this is an idempotent replay
                    return sign_ipc_response(
                        self.receiver_key,
                        deployment_id=self.deployment_id,
                        project_id=self.project_id,
                        receiver_id=self.receiver_id,
                        request_id=request_id,
                        request_sha256=req_sha,
                        status=stored_resp["status"],
                        code=stored_resp["code"],
                        result=stored_resp["result"],
                        receipt_sha256=stored_resp.get("receipt_sha256"),
                        replayed=True,
                        at_unix=stored_resp["at_unix"],
                    )
                # Request was left IN_PROGRESS by a prior crash; allow recovery/re-execution
                db.commit()
                return None

            nonce_row = db.execute(
                "SELECT request_id FROM ipc_requests WHERE deployment_id=? AND principal_id=? AND nonce=?",
                (self.deployment_id, principal_id, nonce),
            ).fetchone()
            if nonce_row is not None:
                db.rollback()
                raise IPCProtocolError("nonce_replay_detected", code="NONCE_REPLAY")

            db.execute(
                """INSERT INTO ipc_requests(
                    deployment_id, principal_id, request_id, nonce, operation, request_sha256,
                    state, response_json, receipt_sha256, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'IN_PROGRESS', NULL, NULL, ?, ?)""",
                (self.deployment_id, principal_id, request_id, nonce, operation, req_sha, now, now),
            )
            db.commit()
            return None

    def _finalize_idempotency(
        self,
        *,
        principal_id: str,
        request_id: str,
        status: str,
        resp: dict[str, Any],
        receipt_sha256: str | None = None,
    ) -> None:
        now = int(time.time())
        with self._db_tx_lock, closing(connect_durable_sqlite(self.paths["project_db"])) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "UPDATE ipc_requests SET state=?, response_json=?, receipt_sha256=?, updated_at=? WHERE deployment_id=? AND principal_id=? AND request_id=?",
                (status, json.dumps(resp, sort_keys=True), receipt_sha256, now, self.deployment_id, principal_id, request_id),
            )
            db.commit()

    def _verify_worker_owns_assignment(self, assignment_id: str, member_id: str | None) -> tuple[str, str, list[str], str]:
        with closing(connect_durable_sqlite(self.paths["project_db"], read_only=True)) as db:
            row = db.execute(
                "SELECT deliverable_id, worker_member, basis, allowed_paths, state FROM assignments WHERE id=?",
                (assignment_id,),
            ).fetchone()
        if row is None:
            raise IPCProtocolError(f"assignment_not_found:{assignment_id}", code="ASSIGNMENT_NOT_FOUND")
        deliverable_id, assigned_worker, basis, raw_paths, state = row
        if member_id is not None and assigned_worker != member_id:
            raise IPCProtocolError(
                f"assignment_worker_mismatch:expected={assigned_worker},actual={member_id}",
                code="ASSIGNMENT_WORKER_MISMATCH",
            )
        return deliverable_id, assigned_worker, json.loads(raw_paths), state

    def _dispatch_authenticated_request(
        self,
        env: dict[str, Any],
        *,
        req_sha: str,
        principal_id: str,
        member_id: str | None,
    ) -> dict[str, Any]:
        request_id = env["request_id"]
        nonce = env["nonce"]
        op = env["operation"]
        payload = env["payload"]

        replayed_resp = self._check_or_reserve_idempotency(
            principal_id=principal_id,
            request_id=request_id,
            nonce=nonce,
            operation=op,
            req_sha=req_sha,
        )
        if replayed_resp is not None:
            return replayed_resp

        status = "OK"
        code = "OK"
        receipt_sha: str | None = None
        result: dict[str, Any] = {}

        try:
            if op == "project.status":
                with self._db_tx_lock:
                    snap = self.project.snapshot()
                    with closing(connect_durable_sqlite(self.paths["project_db"], read_only=True)) as db:
                        rows = db.execute("SELECT id, worker_member, basis, state, deliverable_id, allowed_paths FROM assignments ORDER BY id").fetchall()
                        dep_contracts = dict(db.execute("SELECT dep_key, contract FROM dependency_contracts WHERE project_id=?", (self.project.id,)).fetchall())
                        members = [{"member": r[0], "active": bool(r[1])} for r in db.execute("SELECT member_id, active FROM members WHERE project_id=? ORDER BY member_id", (self.project.id,))]
                    result = {
                        "status": "OK",
                        "project_id": self.project.id,
                        "head": self.promotion.accepted(),
                        "contract": snap["project"][2],
                        "dependency_contracts": dep_contracts,
                        "project_status": snap["project"][4],
                        "kill_switch": self.project.read_stop_state(),
                        "members": members,
                        "deliverables": [{"id": d[0], "member": d[1], "standing": d[2], "accepted_head": d[3]} for d in snap["deliverables"]],
                        "assignments": [
                            {
                                "id": r[0],
                                "worker": r[1],
                                "basis": r[2],
                                "state": r[3],
                                "deliverable": r[4],
                                "allowed_paths": json.loads(r[5]),
                            }
                            for r in rows
                        ],
                        "receiver_pub": self.receiver_pub,
                        "boundary": [],
                    }

            elif op == "assignment.prepare":
                assignment_id = str(payload.get("assignment_id") or "")
                self.protect._validate_assignment_id(assignment_id)
                deliverable_id, assigned_worker, allowed_paths, _state = self._verify_worker_owns_assignment(assignment_id, member_id)
                with self._promotion_lane_lock, self._db_tx_lock:
                    # Verify standing before preparing
                    self.project.preliminary_admit(assignment_id)
                    state_file = Path(self.paths["promotion_dir"]) / f"task-{assignment_id}" / "state.json"
                    if state_file.is_file():
                        _, state = self.promotion._load(assignment_id)
                    else:
                        state = self.promotion.prepare(assignment_id)
                    manifest = build_workspace_manifest(state["workspace"], state["snapshot_db"], require_native_openat2=self.require_native_openat2)
                    proposed_mem = None
                    if payload.get("propose_memory"):
                        proposed_mem = self.project.propose_memory(
                            str(payload["propose_memory"]),
                            deliverable_id,
                            assigned_worker,
                            str(payload.get("basis") or self.project.snapshot()["project"][2]),
                            hashlib.sha256(str(payload.get("lesson") or "candidate").encode("utf-8")).hexdigest(),
                            str(payload.get("diagnosis") or "candidate diagnosis"),
                            str(payload.get("lesson") or "candidate lesson"),
                            assignment_id=assignment_id,
                        )
                    result = {
                        "status": "PREPARED",
                        "assignment": assignment_id,
                        "base_head": state["base"],
                        "base_db_hash": state["base_db_hash"],
                        "allowed_paths": allowed_paths,
                        "manifest": manifest,
                        "proposed_memory": proposed_mem,
                    }

            elif op == "snapshot.chunk":
                assignment_id = str(payload.get("assignment_id") or "")
                self.protect._validate_assignment_id(assignment_id)
                self._verify_worker_owns_assignment(assignment_id, member_id)
                with self._db_tx_lock:
                    self.project.preliminary_admit(assignment_id)
                    _, state = self.promotion._load(assignment_id)
                raw_offset = payload.get("offset", 0)
                raw_length = payload.get("length", int(self.limits["snapshot_chunk_bytes"]))
                chunk = read_snapshot_chunk(
                    state["workspace"],
                    state["snapshot_db"],
                    target=str(payload.get("target") or ""),
                    offset=raw_offset,
                    length=raw_length,
                    max_chunk_bytes=int(self.limits["snapshot_chunk_bytes"]),
                    require_native_openat2=self.require_native_openat2,
                )
                result = {"status": "OK", **chunk}

            elif op == "proposal.submit":
                assignment_id = str(payload.get("assignment_id") or "")
                self.protect._validate_assignment_id(assignment_id)
                deliverable_id, assigned_worker, allowed_paths, asgn_state = self._verify_worker_owns_assignment(assignment_id, member_id)
                files = payload.get("files")

                with self._promotion_lane_lock:
                    self.validation_runner.clear_abort_flag()
                    # Check if already committed/recorded in outbox (crash recovery idempotence)
                    existing_outbox = self.outbox.get_by_assignment(assignment_id)
                    if asgn_state == "COMMITTED" and existing_outbox is not None:
                        self.outbox.flush_outbox()
                        rec = existing_outbox["receipt"]
                        receipt_sha = existing_outbox["receipt_sha256"]
                        status = existing_outbox["verdict"]
                        code = existing_outbox["verdict"]
                        result = {
                            "status": existing_outbox["verdict"],
                            "verdict": existing_outbox["verdict"],
                            "assignment": assignment_id,
                            "incident_id": rec["payload"]["incident_id"],
                            "receipt_path": existing_outbox["path"],
                            "reason": rec["payload"]["reason"],
                            "accepted_ref_before": rec["payload"]["accepted_ref_before"],
                            "accepted_ref_after": rec["payload"]["accepted_ref_after"],
                            "receipt": rec,
                        }
                    else:
                        # Ensure candidate worktree is prepared on receiver
                        state_file = Path(self.paths["promotion_dir"]) / f"task-{assignment_id}" / "state.json"
                        if not state_file.is_file():
                            with self._db_tx_lock:
                                self.promotion.prepare(assignment_id)
                        _, state = self.promotion._load(assignment_id)
                        if state.get("stage") in ("CAS_PENDING", "PROMOTED", "PROMOTED_RECOVERED"):
                            out = self.protect.reconcile(assignment_id)
                        else:
                            # Validate and apply candidate files into receiver's private worktree
                            try:
                                if files is not None:
                                    transfer_info = validate_and_apply_candidate_files(
                                        state["workspace"],
                                        files,
                                        allowed_paths=allowed_paths,
                                        max_files=int(self.limits["max_files"]),
                                        max_single_file_bytes=int(self.limits["max_single_file_bytes"]),
                                        max_total_bytes=int(self.limits["max_total_bytes"]),
                                        require_native_openat2=self.require_native_openat2,
                                    )
                                else:
                                    transfer_info = {"applied_paths": [], "candidate_manifest_sha256": "LOCAL_WORKTREE"}
                            except CandidateTransferError as exc:
                                # Emit signed STOPPED receipt for out-of-scope or forbidden candidate submission
                                head_now = self.promotion.accepted()
                                out = self.protect._emit_receipt(
                                    assignment_id=assignment_id,
                                    candidate_paths=[str(f.get("path", "")) for f in (files or []) if isinstance(f, dict)][:64],
                                    candidate_inventory="IPC_CANDIDATE_INTAKE_REJECTED",
                                    verdict="STOPPED",
                                    explanation=exc.reason,
                                    start=head_now,
                                    now=head_now,
                                    worker_isolation_evaluated=self.worker_isolation_evaluated,
                                    cleanup=True,
                                )
                            else:
                                # Run promotion with cutpoint hooks
                                out = self._execute_isolated_intercept(
                                    assignment_id,
                                    applied_paths=transfer_info["applied_paths"],
                                    candidate_manifest_sha256=transfer_info["candidate_manifest_sha256"],
                                )

                        rec = out["receipt"]
                        receipt_sha = rec["payload_sha256"]
                        with self._db_tx_lock:
                            self.outbox.enqueue(
                                operation_id=f"{principal_id}:{request_id}",
                                assignment_id=assignment_id,
                                receipt=rec,
                                companion={"request_sha256": req_sha},
                            )
                        self._trigger_cutpoint("CUT-04")
                        with self._db_tx_lock:
                            self.outbox.flush_outbox()
                        status = out["verdict"]
                        code = out["verdict"]
                        result = {
                            "status": out["verdict"],
                            "verdict": out["verdict"],
                            "assignment": assignment_id,
                            "incident_id": rec["payload"]["incident_id"],
                            "receipt_path": out["path"],
                            "reason": rec["payload"]["reason"],
                            "accepted_ref_before": rec["payload"]["accepted_ref_before"],
                            "accepted_ref_after": rec["payload"]["accepted_ref_after"],
                            "receipt": rec,
                        }

            elif op == "memory.propose":
                assignment_id = str(payload.get("assignment_id") or "")
                deliverable_id, assigned_worker, _allowed, _st = self._verify_worker_owns_assignment(assignment_id, member_id)
                with self._db_tx_lock:
                    mem = self.project.propose_memory(
                        str(payload["memory_id"]),
                        str(payload.get("deliverable_id") or deliverable_id),
                        assigned_worker,
                        str(payload.get("basis") or self.project.snapshot()["project"][2]),
                        str(payload.get("patch_sha256") or hashlib.sha256(str(payload.get("lesson") or "").encode("utf-8")).hexdigest()),
                        str(payload.get("diagnosis") or "worker diagnosis"),
                        str(payload.get("lesson") or "worker lesson"),
                        assignment_id=assignment_id,
                    )
                result = {"status": "MEMORY_CANDIDATE_PROPOSED", "memory": mem}

            elif op == "repair.reconcile":
                assignment_id = str(payload.get("assignment_id") or "")
                with self._promotion_lane_lock, self._db_tx_lock:
                    out = self.protect.reconcile(assignment_id)
                    rec = out["receipt"]
                    receipt_sha = rec["payload_sha256"]
                    self.outbox.enqueue(
                        operation_id=f"{principal_id}:{request_id}",
                        assignment_id=assignment_id,
                        receipt=rec,
                    )
                    self.outbox.flush_outbox()
                    status = out["verdict"]
                    code = out["verdict"]
                    result = {
                        "status": out["verdict"],
                        "verdict": out["verdict"],
                        "assignment": assignment_id,
                        "incident_id": rec["payload"]["incident_id"],
                        "receipt_path": out["path"],
                        "reason": rec["payload"]["reason"],
                        "receipt": rec,
                    }

            elif op == "receipt.get":
                ident = str(payload.get("incident_id") or payload.get("receipt_sha256") or payload.get("assignment_id") or "")
                found = self.outbox.get_by_incident_or_sha(ident) or self.outbox.get_by_assignment(ident)
                if found is None:
                    raise IPCProtocolError(f"receipt_not_found:{ident}", code="ASSIGNMENT_NOT_FOUND")
                receipt_sha = found["receipt_sha256"]
                result = {"status": "OK", **found}

            elif op == "request.get":
                target_req = str(payload.get("target_request_id") or "")
                with closing(connect_durable_sqlite(self.paths["project_db"], read_only=True)) as db:
                    row = db.execute(
                        "SELECT state, response_json, receipt_sha256 FROM ipc_requests WHERE deployment_id=? AND principal_id=? AND request_id=?",
                        (self.deployment_id, principal_id, target_req),
                    ).fetchone()
                if row is None:
                    raise IPCProtocolError(f"request_not_found:{target_req}", code="ASSIGNMENT_NOT_FOUND")
                result = {
                    "status": "OK",
                    "request_id": target_req,
                    "state": row[0],
                    "stored_response": json.loads(row[1]) if row[1] else None,
                    "receipt_sha256": row[2],
                }

            elif op == "control.stop":
                # Preempt active validations immediately before and after recording STOP!
                self.validation_runner.preempt_active_validations()
                with self._db_tx_lock:
                    st = self.project.issue_stop(
                        str(payload["reason"]),
                        str(payload["owner_signature"]),
                        actor_role="owner",
                        expected_epoch=int(payload["expected_epoch"]),
                    )
                killed = self.validation_runner.preempt_active_validations()
                result = {"status": "KILL_SWITCH_STOPPED", "project_id": self.project.id, "kill_switch": st, "preempted_validators": killed}

            elif op == "control.clear":
                with self._db_tx_lock:
                    st = self.project.clear_stop(
                        str(payload["reason"]),
                        str(payload["owner_signature"]),
                        actor_role="owner",
                        expected_epoch=int(payload["expected_epoch"]),
                    )
                self.validation_runner.clear_abort_flag()
                result = {"status": "KILL_SWITCH_CLEARED", "project_id": self.project.id, "kill_switch": st}

            elif op == "control.assign":
                with self._db_tx_lock:
                    self.project.assign_repair(
                        str(payload["assignment_id"]),
                        str(payload["deliverable_id"]),
                        str(payload["worker_member"]),
                        str(payload["basis"]),
                        str(payload["contributor_signature"]),
                        allowed_paths=list(payload["allowed_paths"]),
                        post_stop_owner_signature=payload.get("post_stop_owner_signature"),
                    )
                result = {
                    "status": "ASSIGNED",
                    "assignment": payload["assignment_id"],
                    "deliverable": payload["deliverable_id"],
                    "worker": payload["worker_member"],
                    "basis": payload["basis"],
                    "allowed_paths": sorted(payload["allowed_paths"]),
                }

            elif op == "control.change_dependency":
                with self._db_tx_lock:
                    affected = self.project.change_dependency(
                        str(payload["dependency"]),
                        str(payload["contract"]),
                        str(payload["owner_signature"]),
                    )
                result = {
                    "status": "CHANGED",
                    "dependency": payload["dependency"],
                    "contract": payload["contract"],
                    "affected": affected,
                }

            elif op == "control.revoke_member":
                with self._db_tx_lock:
                    self.project.revoke_member(
                        str(payload["member_id"]),
                        str(payload["owner_signature"]),
                    )
                self.validation_runner.preempt_active_validations()
                result = {"status": "REVOKED", "member": payload["member_id"]}

            elif op == "control.join":
                with self._db_tx_lock:
                    joined = self.project.join(
                        dict(payload["invitation"]),
                        str(payload["project_signature"]),
                        str(payload["participant_signature"]),
                        world_receipt=dict(payload["world_receipt"]),
                    )
                result = {"status": joined, "member": payload["invitation"]["member_id"]}

            elif op == "control.rotate_key":
                with self._db_tx_lock:
                    rot = self.project.rotate_owner_key(
                        str(payload["new_owner_pub"]),
                        str(payload["current_owner_signature"]),
                    )
                    self.owner_pub = str(payload["new_owner_pub"])
                result = {"status": rot, "new_owner_pub": self.owner_pub}

            elif op == "control.backup":
                backup_dir = Path(str(payload["backup_dir"])).resolve()
                with self._promotion_lane_lock, self._db_tx_lock:
                    manifest = self.create_consistent_backup(backup_dir)
                result = {"status": "BACKUP_CREATED", "manifest": manifest}

            else:
                raise IPCProtocolError(f"unsupported_operation:{op}", code="OPERATION_NOT_ALLOWED")

        except CandidateTransferError as exc:
            status = "REFUSED"
            code = exc.code
            result = {"status": "REFUSED", "error": exc.reason, "reason": exc.reason}
        except (ProjectRefused, ProtectError, PromotionRefused) as exc:
            status = "REFUSED"
            code = str(exc)
            result = {"status": "REFUSED", "error": str(exc), "reason": str(exc)}

        resp = sign_ipc_response(
            self.receiver_key,
            deployment_id=self.deployment_id,
            project_id=self.project_id,
            receiver_id=self.receiver_id,
            request_id=request_id,
            request_sha256=req_sha,
            status=status,
            code=code,
            result=result,
            receipt_sha256=receipt_sha,
            replayed=False,
        )
        self._finalize_idempotency(
            principal_id=principal_id,
            request_id=request_id,
            status=status,
            resp=resp,
            receipt_sha256=receipt_sha,
        )
        return resp

    def _execute_isolated_intercept(
        self,
        assignment_id: str,
        *,
        applied_paths: list[str],
        candidate_manifest_sha256: str,
    ) -> dict[str, Any]:
        """Run ProjectLedger.promote_repair with IsolatedValidationRunner, cutpoint hooks, and durable receipt."""
        start = self.promotion.accepted()
        result = None
        error = None

        def _pre_cas_hook():
            self._trigger_cutpoint("CUT-01")

        fail_before_ref = ("SIGKILL" if self.crash_mode == "SIGKILL" else True) if self.crash_cutpoint == "CUT-02" else False
        fail_after_ref = ("SIGKILL" if self.crash_mode == "SIGKILL" else True) if self.crash_cutpoint == "CUT-03" else False

        try:
            result = self.project.promote_repair(
                assignment_id,
                acceptance_cmd=list(self.protect.acceptance_cmd),
                timeout=float(self.limits["validation_timeout_s"]),
                pre_cas_hook=_pre_cas_hook,
                fail_before_ref=fail_before_ref,
                fail_after_ref=fail_after_ref,
            )
            if not isinstance(result, dict) or result.get("status") not in ("REFUSED", "PROMOTED"):
                error = "unknown_project_gate_response"
        except ProjectRefused as exc:
            result = {"status": "REFUSED", "reason": str(exc)}
        except Exception as exc:
            if isinstance(exc, RuntimeError) and str(exc).startswith("injected_crash_"):
                raise
            error = "project_gate_exception:" + type(exc).__name__

        now = self.promotion.accepted()
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

        explanation = error or (result.get("reason") if result and result.get("status") == "REFUSED" else None)
        return self.protect._emit_receipt(
            assignment_id=assignment_id,
            candidate_paths=applied_paths or [],
            candidate_inventory=f"IPC_CANDIDATE_MANIFEST:{candidate_manifest_sha256[:16]}",
            verdict=verdict,
            explanation=explanation,
            start=start,
            now=now,
            worker_isolation_evaluated=self.worker_isolation_evaluated,
        )

    def create_consistent_backup(self, backup_dir: Path) -> dict[str, Any]:
        """Create an atomic, hash-verified backup of `accepted.git`, `project.sqlite`, `effects.sqlite`, and `incidents/`."""
        if backup_dir.exists():
            shutil.rmtree(backup_dir)
        backup_dir.mkdir(parents=True, mode=0o700)

        # 1. Bare git clone/bundle + copy
        git_dst = backup_dir / "accepted.git"
        shutil.copytree(self.paths["accepted_git"], git_dst, symlinks=False)
        head_sha = self.promotion.accepted()

        # 2. Online SQLite backups
        proj_dst = backup_dir / "project.sqlite"
        eff_dst = backup_dir / "effects.sqlite"
        with closing(sqlite3.connect(self.paths["project_db"])) as sdb, closing(sqlite3.connect(str(proj_dst))) as ddb:
            sdb.backup(ddb)
        with closing(sqlite3.connect(self.paths["effects_db"])) as sdb, closing(sqlite3.connect(str(eff_dst))) as ddb:
            sdb.backup(ddb)

        # 3. Copy incidents receipts
        inc_dst = backup_dir / "incidents"
        shutil.copytree(self.paths["incidents_dir"], inc_dst, symlinks=False)

        manifest = {
            "schema": "openline.backup.manifest.v1",
            "deployment_id": self.deployment_id,
            "project_id": self.project_id,
            "receiver_id": self.receiver_id,
            "receiver_pub": self.receiver_pub,
            "owner_pub": self.owner_pub,
            "accepted_head": head_sha,
            "project_db_sha256": hashlib.sha256(proj_dst.read_bytes()).hexdigest(),
            "effects_db_sha256": hashlib.sha256(eff_dst.read_bytes()).hexdigest(),
            "incident_count": len(list(inc_dst.glob("*.json"))),
            "created_at_unix": int(time.time()),
        }
        manifest_sig = self.receiver_key.sign(canonical_json_bytes(manifest)).hex()
        signed_manifest = {"manifest": manifest, "signature_ed25519_hex": manifest_sig}
        atomic_write_json(backup_dir / "backup_manifest.json", signed_manifest, mode=0o600)
        return signed_manifest


def main(argv: list[str] | None = None) -> int:
    import argparse
    import signal
    from production_config import load_production_config

    parser = argparse.ArgumentParser(prog="openline-receiver-service")
    parser.add_argument("--config", required=True, help="Path to production_config.json")
    parser.add_argument("--require-distinct-uids", action="store_true")
    parser.add_argument("--require-systemd-hardening", action="store_true")
    parser.add_argument("--crash-cutpoint", default=None)
    parser.add_argument("--crash-mode", default="EXCEPTION", choices=("EXCEPTION", "SIGKILL"))
    args = parser.parse_args(argv)

    cfg = load_production_config(args.config)
    svc = OpenLineReceiverService(
        cfg,
        require_distinct_uids=args.require_distinct_uids,
        require_systemd_hardening=args.require_systemd_hardening,
        crash_cutpoint=args.crash_cutpoint,
        crash_mode=args.crash_mode,
    )
    svc.start_background()
    stop_ev = threading.Event()

    def _sig_handler(_signum, _frame):
        stop_ev.set()

    signal.signal(signal.SIGTERM, _sig_handler)
    signal.signal(signal.SIGINT, _sig_handler)
    print(json.dumps({"status": "LISTENING", "worker_socket": cfg["paths"]["worker_socket"], "control_socket": cfg["paths"]["control_socket"]}), flush=True)
    try:
        while not stop_ev.is_set():
            time.sleep(0.05)
    finally:
        svc.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
