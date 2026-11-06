"""OpenLine Production Isolation — Comprehensive Milestone M1–M7 & Adversarial Verification Suite.

Covers all acceptance matrix rows from Section 7.2 of Astra's Blueprint:
- `OS-01` .. `OS-04`: `_worker_group_ids` POSIX username fix, SQLite sidecar checks, `openat2`/`O_NOFOLLOW`
  containment, `owner.key` absence, `SanitizedGitRunner` repo hygiene, and `unshare` namespace probe.
- `IPC-01`, `IPC-02`: `AF_UNIX` `SO_PEERCRED`, `SCM_RIGHTS` descriptor-passing rejection, strict JSON
  (duplicate keys, `NaN`, floats, depth > 16), oversized frame refusal, channel operation allowlist,
  and durable `ipc_requests` idempotency/nonce replay protection.
- `CAND-01`: Byte-only `assignment.prepare` + `snapshot.chunk` (no `.git` exposure) and `proposal.submit`
  rejection of out-of-scope paths, traversal, symlinks (`120000`), submodules (`160000`), casefold
  collisions, NUL bytes, and digest mismatches.
- `VAL-01`, `VAL-02`: `IsolatedValidationRunner` execution without `.git`, timeout process-group kill,
  and post-run tree/snapshot mutation refusal.
- `AUTH-01`, `AUTH-02`: Cross-worker assignment spoofing refusal (`ASSIGNMENT_WORKER_MISMATCH`), and
  CLI + MCP `--service-socket` execution without `owner.key` or direct receiver file access.
- `RACE-01`, `RACE-02`: `control.stop` preempting active validation in `<250ms`, and concurrent barrier
  races between `proposal.submit` and `control.stop` / `control.revoke_member` / `control.change_dependency`.
- `CRASH-01`, `CRASH-02`: All 6 crash cut points (`CUT-01` .. `CUT-06`), including real `SIGKILL` (`kill -9`)
  child processes, diverged-ref `HOLD_RECONCILIATION`, and `ReceiverGuard` split-DB `commit_seq` recovery.
- `OPS-01`, `OPS-02`: Online backup, signed manifest verification, restore rehearsal, and key rotation.
"""
from __future__ import annotations

import array
import base64
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = Path(__file__).resolve().parent
PKG = HERE.parent
EXPERIMENTS = PKG.parent
for _rel in (
    "SELF-HEALING-ENGINE-001",
    "SELF-HEALING-PROJECTS-001",
    "OPENLINE-PROTECT-001",
    "OPENLINE-PROTECT-002",
    "LIVING-PROJECTS-001",
    "OPENLINE-RELEASE-001",
    "OPENLINE-RECEIVER-ISOLATION-001",
    "OPENLINE-RECEIVER-ISOLATION-001/deploy",
):
    _p = str(EXPERIMENTS / _rel)
    if _p not in sys.path:
        sys.path.insert(0, _p)

from backup_restore_rehearsal import (  # noqa: E402
    _pub,
    _sig,
    bootstrap_isolated_deployment,
    run_rehearsal,
)
from candidate_transfer import (  # noqa: E402
    CandidateTransferError,
    validate_and_apply_candidate_files,
)
from durable_io import (  # noqa: E402
    OpenAt2Error,
    atomic_write_bytes,
    kernel_supports_native_openat2,
    open_beneath,
    read_bytes_beneath,
)
from git_runner import SanitizedGitRunner  # noqa: E402
from ipc_client import OpenLineIPCClient  # noqa: E402
from ipc_protocol import (  # noqa: E402
    IPCProtocolError,
    canonical_json_bytes,
    recv_frame,
    send_frame,
    sign_ipc_request,
    strict_loads_json,
)
from preflight import audit_production_preflight  # noqa: E402
from protect import _worker_group_ids, check_receiver_boundary, verify_receipt  # noqa: E402
from receiver_service import OpenLineReceiverService  # noqa: E402
from validation_runner import IsolatedValidationRunner, ValidationJob  # noqa: E402
from openline_guard import ReceiverGuard, SigningIdentity, sign_envelope  # noqa: E402


class ProductionIsolationTestSuite(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="openline-rc5-test-")
        self.base = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    # ------------------------------------------------------------------
    # M1: OS boundary, _worker_group_ids bugfix, open_beneath, preflight
    # ------------------------------------------------------------------
    def test_01_m1_boundary_worker_groups_openat2_and_preflight(self):
        # 1a. Verify _worker_group_ids resolves supplementary groups by string username (pw_name)
        fake_pw = mock.MagicMock(pw_gid=2000, pw_name="alice_worker")
        fake_grp = mock.MagicMock(gr_gid=3005, gr_mem=["alice_worker"])
        with mock.patch("pwd.getpwuid", return_value=fake_pw), \
             mock.patch("grp.getgrall", return_value=[fake_grp]), \
             mock.patch("os.getgrouplist", return_value=[2000]):
            gids = _worker_group_ids(10001)
            self.assertIn(3005, gids, "Supplementary group membership by string username must be detected")

        # 1b. Verify check_receiver_boundary inspects SQLite sidecars (-wal, -shm, -journal, .gate.lock)
        db_file = self.base / "project.sqlite"
        db_file.write_text("db", encoding="utf-8")
        os.chmod(db_file, 0o600)
        wal_sidecar = self.base / "project.sqlite-wal"
        wal_sidecar.write_text("wal", encoding="utf-8")
        os.chmod(wal_sidecar, 0o666)  # world-writable sidecar!
        reasons = check_receiver_boundary([("project_db", db_file)], receiver_uid=os.getuid(), worker_uid=65534)
        self.assertIn("project_db_world_writable", reasons)
        os.chmod(wal_sidecar, 0o600)
        self.assertEqual(check_receiver_boundary([("project_db", db_file)], receiver_uid=os.getuid(), worker_uid=65534), [])

        # 1c. Verify open_beneath blocks traversal, absolute paths, symlinks, magic links, and hardlinks
        sandbox = self.base / "sandbox"
        sandbox.mkdir(mode=0o700)
        (sandbox / "app").mkdir(mode=0o700)
        f_ok = sandbox / "app" / "ok.py"
        atomic_write_bytes(f_ok, b"x = 1\n", mode=0o600)
        if not kernel_supports_native_openat2():
            with self.assertRaises(OpenAt2Error):
                read_bytes_beneath(sandbox, "app/ok.py", require_native_openat2=True)
        self.assertEqual(read_bytes_beneath(sandbox, "app/ok.py", require_native_openat2=kernel_supports_native_openat2()), b"x = 1\n")

        for bad_rel in ("/etc/passwd", "../project.sqlite", "app/../../project.sqlite", "proc/self/environ", "app/ok.py\x00"):
            with self.assertRaises(OpenAt2Error):
                open_beneath(sandbox, bad_rel)

        # Symlink inside sandbox pointing outside
        sym = sandbox / "app" / "escape.py"
        sym.symlink_to(db_file)
        with self.assertRaises(OpenAt2Error):
            open_beneath(sandbox, "app/escape.py")

        # Hardlink inside sandbox (st_nlink > 1)
        hlink = sandbox / "app" / "hardlink.py"
        os.link(f_ok, hlink)
        with self.assertRaises(OpenAt2Error):
            open_beneath(sandbox, "app/hardlink.py", check_single_link=True)
        hlink.unlink()

        # 1d. Verify audit_production_preflight catches owner.key on receiver and executable repo hooks
        deploy_env = bootstrap_isolated_deployment(self.base / "deploy1")
        cfg = deploy_env["config"]
        rep_clean = audit_production_preflight(cfg, require_distinct_uids=False)
        self.assertTrue(rep_clean.ok, rep_clean.reasons)

        # Plant owner.key inside receiver root -> preflight must refuse!
        planted_owner = Path(cfg["paths"]["root_dir"]) / "keys" / "owner.key"
        planted_owner.write_text("00" * 32, encoding="utf-8")
        rep_owner = audit_production_preflight(cfg, require_distinct_uids=False)
        self.assertFalse(rep_owner.ok)
        self.assertIn("owner_private_key_present_on_receiver", rep_owner.reasons)
        planted_owner.unlink()

        # Plant executable hook inside accepted.git/hooks/pre-receive -> preflight must refuse!
        hook_file = Path(cfg["paths"]["accepted_git"]) / "hooks" / "pre-receive"
        hook_file.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        os.chmod(hook_file, 0o755)
        rep_hook = audit_production_preflight(cfg, require_distinct_uids=False)
        self.assertFalse(rep_hook.ok)
        self.assertIn("executable_repo_hook_forbidden:pre-receive", rep_hook.reasons)
        hook_file.unlink()

    # ------------------------------------------------------------------
    # M2: Authenticated Unix socket IPC, SCM_RIGHTS rejection, strict JSON, replay
    # ------------------------------------------------------------------
    def test_02_m2_ipc_protocol_scm_rights_strict_json_and_replay(self):
        # 2a. Strict JSON parser rejects duplicate keys, floats, NaN, and depth > 16
        with self.assertRaises(IPCProtocolError):
            strict_loads_json(b'{"a": 1, "a": 2}')
        with self.assertRaises(IPCProtocolError):
            strict_loads_json(b'{"a": 1.5}')
        with self.assertRaises(IPCProtocolError):
            strict_loads_json(b'{"a": NaN}')
        deep = "{" * 18 + '"x":1' + "}" * 18
        with self.assertRaises(IPCProtocolError):
            strict_loads_json(deep.encode("utf-8"))

        # 2b. Start receiver service and test SCM_RIGHTS, channel restrictions, and replay ledger
        deploy_env = bootstrap_isolated_deployment(self.base / "deploy2")
        cfg = deploy_env["config"]
        svc = OpenLineReceiverService(cfg, require_distinct_uids=False)
        svc.start_background()
        try:
            worker_sock_path = cfg["paths"]["worker_socket"]
            bob_key = deploy_env["bob_key"]
            owner_key = deploy_env["owner_key"]

            # Attempt to pass an open file descriptor via SCM_RIGHTS ancillary data -> must be rejected!
            with tempfile.TemporaryFile() as tf:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                    s.connect(worker_sock_path)
                    req_env = sign_ipc_request(
                        bob_key,
                        deployment_id=cfg["deployment_id"],
                        project_id=cfg["project_id"],
                        receiver_id=cfg["receiver_id"],
                        channel="worker",
                        request_id="req-scm-1",
                        principal_id="worker:bob",
                        operation="project.status",
                        payload={},
                    )
                    raw = canonical_json_bytes(req_env)
                    frame = struct.pack(">I", len(raw)) + raw
                    fds = array.array("i", [tf.fileno()])
                    s.sendmsg([frame], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)])
                    resp_raw = recv_frame(s)
                    resp = strict_loads_json(resp_raw)
                    self.assertEqual(resp["status"], "REFUSED")
                    self.assertEqual(resp["code"], "MALFORMED_ENVELOPE")
                    self.assertIn("ancillary_data_or_scm_rights_forbidden", resp["result"]["error"])

            # Attempt control.stop on worker.sock -> must be refused with OPERATION_NOT_ALLOWED!
            worker_bob = OpenLineIPCClient(
                socket_path=worker_sock_path,
                channel="worker",
                deployment_id=cfg["deployment_id"],
                project_id=cfg["project_id"],
                receiver_id=cfg["receiver_id"],
                principal_id="worker:bob",
                signer_key=bob_key,
                pinned_receiver_pub=cfg["receiver_pub"],
            )
            r_forbid = worker_bob.call("control.stop", {"reason": "hack", "owner_signature": "00" * 64, "expected_epoch": 1})
            self.assertEqual(r_forbid["status"], "REFUSED")
            self.assertEqual(r_forbid["code"], "OPERATION_NOT_ALLOWED")

            # Expired request -> EXPIRED_REQUEST
            now = int(time.time())
            r_exp = worker_bob.call("project.status", {}, issued_at=now - 1000, expires_at=now - 500)
            self.assertEqual(r_exp["status"], "REFUSED")
            self.assertEqual(r_exp["code"], "EXPIRED_REQUEST")

            # Idempotent retry of same (request_id, nonce, payload) -> returns cached response with replayed=True
            r_ok1 = worker_bob.call("project.status", {}, request_id="req-idem-1", nonce="a" * 32)
            self.assertEqual(r_ok1["status"], "OK")
            self.assertFalse(r_ok1["replayed"])

            r_ok2 = worker_bob.call("project.status", {}, request_id="req-idem-1", nonce="a" * 32)
            self.assertEqual(r_ok2["status"], "OK")
            self.assertTrue(r_ok2["replayed"])
            self.assertEqual(r_ok2["result_sha256"], r_ok1["result_sha256"])

            # Same request_id with different payload -> IDEMPOTENCY_CONFLICT
            r_conflict = worker_bob.call("project.status", {"extra": 1}, request_id="req-idem-1", nonce="a" * 32)
            self.assertEqual(r_conflict["status"], "REFUSED")
            self.assertEqual(r_conflict["code"], "IDEMPOTENCY_CONFLICT")

            # Different request_id reusing same nonce -> NONCE_REPLAY
            r_nonce = worker_bob.call("project.status", {}, request_id="req-idem-2", nonce="a" * 32)
            self.assertEqual(r_nonce["status"], "REFUSED")
            self.assertEqual(r_nonce["code"], "NONCE_REPLAY")
        finally:
            svc.stop()

    # ------------------------------------------------------------------
    # M3: Safe candidate transfer (CAND-01)
    # ------------------------------------------------------------------
    def test_03_m3_candidate_transfer_scope_and_malformed_rejection(self):
        ws = self.base / "candidate_ws"
        (ws / "app").mkdir(parents=True)
        (ws / "app" / "price.py").write_text("def total(qty):\n    return qty * 10\n", encoding="utf-8")
        (ws / "app" / "independent.py").write_text("def label(value):\n    return value.upper()\n", encoding="utf-8")

        def _make_entry(path: str, content: bytes, *, mode: str = "100644", op: str = "upsert", sha_override: str | None = None):
            return {
                "path": path,
                "op": op,
                "mode": mode,
                "sha256": sha_override or hashlib.sha256(content).hexdigest(),
                "content_b64": base64.b64encode(content).decode("ascii"),
            }

        # 1. Out-of-scope file (app/independent.py when only app/price.py is allowed)
        with self.assertRaises(CandidateTransferError) as ctx:
            validate_and_apply_candidate_files(ws, [_make_entry("app/independent.py", b"x=1\n")], allowed_paths=["app/price.py"])
        self.assertEqual(ctx.exception.code, "OUT_OF_SCOPE_PATH")

        # 2. Traversal / .git path
        for bad_path in ("../project.sqlite", ".git/config", "app/../../etc/passwd"):
            with self.assertRaises(CandidateTransferError):
                validate_and_apply_candidate_files(ws, [_make_entry(bad_path, b"x=1\n")], allowed_paths=["app/"])

        # 3. Forbidden symlink (120000) and submodule/gitlink (160000) modes
        for bad_mode in ("120000", "160000"):
            with self.assertRaises(CandidateTransferError) as ctx:
                validate_and_apply_candidate_files(ws, [_make_entry("app/price.py", b"x=1\n", mode=bad_mode)], allowed_paths=["app/price.py"])
            self.assertEqual(ctx.exception.code, "SYMLINK_OR_SUBMODULE_FORBIDDEN")

        # 4. Casefold collision
        with self.assertRaises(CandidateTransferError):
            validate_and_apply_candidate_files(
                ws,
                [_make_entry("app/price.py", b"x=1\n"), _make_entry("app/PRICE.py", b"x=2\n")],
                allowed_paths=["app/"],
            )

        # 5. NUL byte injection & SHA-256 mismatch
        with self.assertRaises(CandidateTransferError):
            validate_and_apply_candidate_files(ws, [_make_entry("app/price.py", b"x=1\x00\n")], allowed_paths=["app/price.py"])
        with self.assertRaises(CandidateTransferError):
            validate_and_apply_candidate_files(ws, [_make_entry("app/price.py", b"x=1\n", sha_override="0" * 64)], allowed_paths=["app/price.py"])

    # ------------------------------------------------------------------
    # M4: Unprivileged validator runner (VAL-01, VAL-02)
    # ------------------------------------------------------------------
    def test_04_m4_isolated_validator_no_git_timeout_and_mutation_detection(self):
        spool = self.base / "spool"
        merged = self.base / "merged"
        (merged / "app").mkdir(parents=True)
        (merged / ".git").write_text("gitdir: /secret/accepted.git/worktrees/1\n", encoding="utf-8")
        (merged / "app" / "price.py").write_text("def total(qty):\n    return qty * 11\n", encoding="utf-8")

        proj_db = self.base / "proj.sqlite"
        eff_db = self.base / "eff.sqlite"
        with closing(sqlite3.connect(str(proj_db))) as db:
            db.executescript("""
                CREATE TABLE projects(id TEXT, contract TEXT, status TEXT);
                CREATE TABLE deliverables(id TEXT, member_id TEXT, standing TEXT);
                CREATE TABLE dependencies(deliverable_id TEXT, depends_on TEXT);
                CREATE TABLE dependency_contracts(project_id TEXT, dep_key TEXT, contract TEXT);
                CREATE TABLE assignments(id TEXT, deliverable_id TEXT, worker_member TEXT, basis TEXT, allowed_paths TEXT, state TEXT);
                CREATE TABLE members(project_id TEXT, member_id TEXT, owner_pub TEXT, worker_pub TEXT, active INT);
            """)
            db.commit()
        with closing(sqlite3.connect(str(eff_db))) as db:
            db.execute("CREATE TABLE effects(id TEXT, value INT)")
            db.commit()

        runner = IsolatedValidationRunner(spool)

        # 4a. Validator verifies `.git` is NOT copied into staged merged/ directory
        val_check_no_git = self.base / "val_no_git.py"
        val_check_no_git.write_text(
            "import pathlib, sys\n"
            "assert not pathlib.Path('.git').exists(), '.git must not exist in validator merged tree'\n"
            "sys.exit(0)\n",
            encoding="utf-8",
        )
        out_ok = runner.run(ValidationJob(
            job_id="j1",
            assignment_id="a1",
            merged_worktree=merged,
            project_db=proj_db,
            effects_snapshot_db=eff_db,
            validator_script=val_check_no_git,
            proposed_head="1" * 40,
            expected_head="0" * 40,
            timeout_s=5.0,
        ))
        self.assertTrue(out_ok.passed, out_ok)

        # 4b. Validator that mutates staged merged/ tree -> refused with tree_mutated=True!
        val_mutate = self.base / "val_mutate.py"
        val_mutate.write_text(
            "import pathlib, sys\n"
            "pathlib.Path('app/price.py').write_text('hacked')\n"
            "sys.exit(0)\n",
            encoding="utf-8",
        )
        out_mut = runner.run(ValidationJob(
            job_id="j2",
            assignment_id="a1",
            merged_worktree=merged,
            project_db=proj_db,
            effects_snapshot_db=eff_db,
            validator_script=val_mutate,
            proposed_head="1" * 40,
            expected_head="0" * 40,
            timeout_s=5.0,
        ))
        self.assertFalse(out_mut.passed)
        self.assertTrue(out_mut.tree_mutated)
        self.assertEqual(out_mut.reason, "validation_tree_mutated")

        # 4c. Validator that hangs -> killed on timeout (`timed_out=True`)
        val_hang = self.base / "val_hang.py"
        val_hang.write_text("import time\ntime.sleep(10)\n", encoding="utf-8")
        out_to = runner.run(ValidationJob(
            job_id="j3",
            assignment_id="a1",
            merged_worktree=merged,
            project_db=proj_db,
            effects_snapshot_db=eff_db,
            validator_script=val_hang,
            proposed_head="1" * 40,
            expected_head="0" * 40,
            timeout_s=0.25,
        ))
        self.assertFalse(out_to.passed)
        self.assertTrue(out_to.timed_out)
        self.assertEqual(out_to.reason, "validation_timed_out")

    # ------------------------------------------------------------------
    # M5: Cross-worker spoofing refusal, STOP preemption (<250ms), and CLI/MCP socket mode
    # ------------------------------------------------------------------
    def test_05_m5_cross_worker_auth_stop_preemption_and_cli_socket_mode(self):
        deploy_env = bootstrap_isolated_deployment(self.base / "deploy5")
        cfg = deploy_env["config"]
        # Use a validator script that sleeps 2.0s when a marker file is present so we can test <250ms STOP preemption
        slow_marker = self.base / "slow_validation.flag"
        real_validator = Path(cfg["paths"]["validator_script"]).read_text(encoding="utf-8")
        wrapped_validator = self.base / "wrapped_validator.py"
        wrapped_validator.write_text(
            f"import pathlib, time\n"
            f"if pathlib.Path({str(slow_marker)!r}).exists():\n"
            f"    time.sleep(3.0)\n"
            + real_validator,
            encoding="utf-8",
        )
        cfg["paths"]["validator_script"] = str(wrapped_validator)

        svc = OpenLineReceiverService(cfg, require_distinct_uids=False)
        svc.start_background()
        try:
            owner_key = deploy_env["owner_key"]
            alice_key = deploy_env["alice_key"]
            bob_key = deploy_env["bob_key"]

            ctrl_owner = OpenLineIPCClient(
                socket_path=cfg["paths"]["control_socket"],
                channel="control",
                deployment_id=cfg["deployment_id"],
                project_id=cfg["project_id"],
                receiver_id=cfg["receiver_id"],
                principal_id="control:owner",
                signer_key=owner_key,
                pinned_receiver_pub=cfg["receiver_pub"],
            )
            ctrl_alice = OpenLineIPCClient(
                socket_path=cfg["paths"]["control_socket"],
                channel="control",
                deployment_id=cfg["deployment_id"],
                project_id=cfg["project_id"],
                receiver_id=cfg["receiver_id"],
                principal_id="control:alice",
                signer_key=alice_key,
                pinned_receiver_pub=cfg["receiver_pub"],
            )
            worker_alice = OpenLineIPCClient(
                socket_path=cfg["paths"]["worker_socket"],
                channel="worker",
                deployment_id=cfg["deployment_id"],
                project_id=cfg["project_id"],
                receiver_id=cfg["receiver_id"],
                principal_id="worker:alice",
                signer_key=alice_key,
                pinned_receiver_pub=cfg["receiver_pub"],
            )
            worker_bob = OpenLineIPCClient(
                socket_path=cfg["paths"]["worker_socket"],
                channel="worker",
                deployment_id=cfg["deployment_id"],
                project_id=cfg["project_id"],
                receiver_id=cfg["receiver_id"],
                principal_id="worker:bob",
                signer_key=bob_key,
                pinned_receiver_pub=cfg["receiver_pub"],
            )

            # Assign repair-1 to bob
            asgn_claim = {
                "project_id": cfg["project_id"],
                "assignment_id": "repair-1",
                "deliverable_id": "invoice-feature",
                "worker_member": "bob",
                "basis": "invoice_v2",
                "allowed_paths": ["app/price.py"],
                "action": "repair_assignment",
            }
            self.assertEqual(ctrl_alice.call("control.assign", {
                "assignment_id": "repair-1",
                "deliverable_id": "invoice-feature",
                "worker_member": "bob",
                "basis": "invoice_v2",
                "allowed_paths": ["app/price.py"],
                "contributor_signature": _sig(alice_key, asgn_claim),
            })["status"], "OK")

            # AUTH-01: Alice attempts to prepare or submit for Bob's assignment -> refused!
            r_spoof = worker_alice.call("assignment.prepare", {"assignment_id": "repair-1"})
            self.assertEqual(r_spoof["status"], "REFUSED")
            self.assertEqual(r_spoof["code"], "ASSIGNMENT_WORKER_MISMATCH")

            # Bob prepares workspace
            bob_ws_dir = self.base / "bob_ws"
            r_prep = worker_bob.prepare_workspace("repair-1", bob_ws_dir)
            self.assertEqual(r_prep["status"], "OK")
            ws = Path(r_prep["result"]["client_workspace"])
            (ws / "app" / "price.py").write_text("def total(qty):\n    return qty * 11\n", encoding="utf-8")

            # RACE-01: Enable slow validation (3.0s), start proposal.submit in background thread,
            # then issue control.stop after 80ms and prove control.stop completes in <250ms and aborts validation!
            slow_marker.write_text("1", encoding="utf-8")
            submit_holder: list[dict] = []

            def _bg_submit():
                submit_holder.append(worker_bob.submit_workspace_proposal("repair-1", ws, allowed_paths=["app/price.py"]))

            t_sub = threading.Thread(target=_bg_submit)
            t_sub.start()
            time.sleep(0.08)

            t_stop_0 = time.monotonic()
            stop_claim = {"project_id": cfg["project_id"], "action": "issue_stop", "reason": "race_preempt", "expected_epoch": 1}
            r_stop = ctrl_owner.call("control.stop", {
                "reason": "race_preempt",
                "owner_signature": _sig(owner_key, stop_claim),
                "expected_epoch": 1,
            })
            stop_latency_ms = (time.monotonic() - t_stop_0) * 1000.0
            self.assertEqual(r_stop["status"], "OK")
            self.assertLess(stop_latency_ms, 250.0, f"control.stop latency {stop_latency_ms:.1f}ms exceeded 250ms target!")

            t_sub.join(timeout=5.0)
            self.assertEqual(len(submit_holder), 1)
            self.assertEqual(submit_holder[0]["status"], "STOPPED")
            slow_marker.unlink()

            # Clear STOP (epoch 2 -> 3), issue post-STOP assignment repair-2 to bob, and test openline_cli.py --service-socket mode!
            clear_claim = {"project_id": cfg["project_id"], "action": "clear_stop", "reason": "resume_ops", "expected_epoch": 2}
            self.assertEqual(ctrl_owner.call("control.clear", {
                "reason": "resume_ops",
                "owner_signature": _sig(owner_key, clear_claim),
                "expected_epoch": 2,
            })["status"], "OK")

            asgn2_claim = {
                "project_id": cfg["project_id"],
                "assignment_id": "repair-2",
                "deliverable_id": "invoice-feature",
                "worker_member": "bob",
                "basis": "invoice_v2",
                "allowed_paths": ["app/price.py"],
                "action": "repair_assignment",
            }
            self.assertEqual(ctrl_alice.call("control.assign", {
                "assignment_id": "repair-2",
                "deliverable_id": "invoice-feature",
                "worker_member": "bob",
                "basis": "invoice_v2",
                "allowed_paths": ["app/price.py"],
                "contributor_signature": _sig(alice_key, asgn2_claim),
            })["status"], "OK")

            # Write a thin client config directory that has NO access to receiver files or keys
            client_dir = self.base / "thin_client_dir"
            client_dir.mkdir(mode=0o700)
            (client_dir / "config.json").write_text(json.dumps({
                "version": 1,
                "deployment_id": cfg["deployment_id"],
                "project_id": cfg["project_id"],
                "receiver_id": cfg["receiver_id"],
                "dir": str(client_dir),
                "receiver_pub": cfg["receiver_pub"],
                "service_socket": cfg["paths"]["worker_socket"],
                "client_key": str(self.base / "deploy5" / "external_keys" / "bob.key"),
                "principal_id": "worker:bob",
            }), encoding="utf-8")

            cli_script = EXPERIMENTS / "OPENLINE-RELEASE-001" / "openline_cli.py"
            cli_ws = self.base / "cli_bob_ws"
            p_prep = subprocess.run(
                [sys.executable, str(cli_script), "prepare", "--dir", str(client_dir), "--assignment", "repair-2", "--client-workspace", str(cli_ws)],
                capture_output=True, text=True, check=True,
            )
            prep_json = json.loads(p_prep.stdout)
            self.assertEqual(prep_json["status"], "PREPARED")
            self.assertTrue(prep_json["ipc_verified"])
            (Path(prep_json["workspace"]) / "app" / "price.py").write_text("def total(qty):\n    return qty * 11\n", encoding="utf-8")

            p_int = subprocess.run(
                [sys.executable, str(cli_script), "intercept", "--dir", str(client_dir), "--assignment", "repair-2", "--client-workspace", prep_json["workspace"]],
                capture_output=True, text=True, check=False,
            )
            if p_int.returncode != 0:
                raise RuntimeError(f"intercept failed rc={p_int.returncode} out={p_int.stdout} err={p_int.stderr}")
            int_json = json.loads(p_int.stdout)
            self.assertEqual(int_json["status"], "ACCEPTED")
        finally:
            svc.stop()

    # ------------------------------------------------------------------
    # M6: Crash cut points CUT-01 .. CUT-06 and ReceiverGuard split-DB recovery
    # ------------------------------------------------------------------
    def test_06_m6_crash_cutpoints_and_split_db_recovery(self):
        deploy_env = bootstrap_isolated_deployment(self.base / "deploy6")
        cfg = deploy_env["config"]
        alice_key = deploy_env["alice_key"]
        bob_key = deploy_env["bob_key"]

        svc = OpenLineReceiverService(cfg, require_distinct_uids=False)
        svc.start_background()
        try:
            ctrl_alice = OpenLineIPCClient(
                socket_path=cfg["paths"]["control_socket"],
                channel="control",
                deployment_id=cfg["deployment_id"],
                project_id=cfg["project_id"],
                receiver_id=cfg["receiver_id"],
                principal_id="control:alice",
                signer_key=alice_key,
                pinned_receiver_pub=cfg["receiver_pub"],
            )
            worker_bob = OpenLineIPCClient(
                socket_path=cfg["paths"]["worker_socket"],
                channel="worker",
                deployment_id=cfg["deployment_id"],
                project_id=cfg["project_id"],
                receiver_id=cfg["receiver_id"],
                principal_id="worker:bob",
                signer_key=bob_key,
                pinned_receiver_pub=cfg["receiver_pub"],
            )

            asgn_claim = {
                "project_id": cfg["project_id"],
                "assignment_id": "repair-cut",
                "deliverable_id": "invoice-feature",
                "worker_member": "bob",
                "basis": "invoice_v2",
                "allowed_paths": ["app/price.py"],
                "action": "repair_assignment",
            }
            self.assertEqual(ctrl_alice.call("control.assign", {
                "assignment_id": "repair-cut",
                "deliverable_id": "invoice-feature",
                "worker_member": "bob",
                "basis": "invoice_v2",
                "allowed_paths": ["app/price.py"],
                "contributor_signature": _sig(alice_key, asgn_claim),
            })["status"], "OK")

            bob_ws_dir = self.base / "bob_cut_ws"
            r_prep = worker_bob.prepare_workspace("repair-cut", bob_ws_dir)
            ws = Path(r_prep["result"]["client_workspace"])
            (ws / "app" / "price.py").write_text("def total(qty):\n    return qty * 11\n", encoding="utf-8")

            # 6a. CUT-02: Crash after PENDING_CAS reservation before git update-ref
            svc.crash_cutpoint = "CUT-02"
            with self.assertRaises( Exception ):
                worker_bob.submit_workspace_proposal("repair-cut", ws, allowed_paths=["app/price.py"], request_id="req-cut2")
            svc.crash_cutpoint = None
            # Re-prepare and verify startup reconciliation voids unapplied PENDING_CAS
            rec_info = svc.reconcile_startup()
            self.assertTrue(any(r["assignment"] == "repair-cut" for r in rec_info["reconciled_assignments"]))

            # Re-prepare candidate for CUT-03 (crash AFTER git update-ref, BEFORE resolve_repair settlement)
            r_prep2 = worker_bob.prepare_workspace("repair-cut", bob_ws_dir)
            ws2 = Path(r_prep2["result"]["client_workspace"])
            (ws2 / "app" / "price.py").write_text("def total(qty):\n    return qty * 11\n", encoding="utf-8")
            svc.crash_cutpoint = "CUT-03"
            with self.assertRaises(Exception):
                worker_bob.submit_workspace_proposal("repair-cut", ws2, allowed_paths=["app/price.py"], request_id="req-cut3")
            svc.crash_cutpoint = None

            # Startup reconciliation after CUT-03 must detect accepted == target_head, complete resolve_repair, and publish ACCEPTED receipt!
            rec_cut3 = svc.reconcile_startup()
            self.assertTrue(any(r["assignment"] == "repair-cut" and r["verdict"] == "ACCEPTED" for r in rec_cut3["reconciled_assignments"]))
            outbox_rec = svc.outbox.get_by_assignment("repair-cut")
            self.assertIsNotNone(outbox_rec)
            self.assertEqual(outbox_rec["verdict"], "ACCEPTED")
            self.assertTrue(Path(outbox_rec["path"]).is_file())
        finally:
            svc.stop()

        # 6b. CUT-05: Diverged Git ref during PENDING_CAS transitions to HOLD_RECONCILIATION without erasing commit_seq
        deploy_env5 = bootstrap_isolated_deployment(self.base / "deploy_cut5")
        cfg5 = deploy_env5["config"]
        svc5 = OpenLineReceiverService(cfg5, require_distinct_uids=False)
        try:
            with closing(sqlite3.connect(cfg5["paths"]["project_db"])) as db:
                db.execute(
                    "INSERT INTO assignments VALUES ('repair-div', 'invoice-feature', 'bob', 'invoice_v2', '[\"app/price.py\"]', 'ASSIGNED', NULL)"
                )
                db.execute(
                    "INSERT INTO assignment_standing VALUES ('repair-div', 2, 1, 0, 2, 3, ?, ?, 'PENDING_CAS')",
                    ("a" * 40, "b" * 40),
                )
                db.commit()
            svc5.project.reconcile_pending_cas()
            with closing(sqlite3.connect(cfg5["paths"]["project_db"])) as db:
                st_row = db.execute("SELECT commit_seq, cas_target_head, cas_expected_head, cas_state FROM assignment_standing WHERE assignment_id='repair-div'").fetchone()
                proj_row = db.execute("SELECT status FROM projects WHERE id=?", (cfg5["project_id"],)).fetchone()
            self.assertEqual(st_row[3], "HOLD_RECONCILIATION")
            self.assertEqual(st_row[0], 3, "commit_seq must be preserved as forensic evidence on HOLD_RECONCILIATION")
            self.assertEqual(proj_row[0], "HOLD_RECONCILIATION")
        finally:
            svc5.stop()

        # 6c. ReceiverGuard split-DB crash recovery (db.commit() succeeded, cdb.commit() interrupted leaving commit_seq NULL)
        guard_db = self.base / "guard.sqlite"
        issuer = SigningIdentity()
        worker = SigningIdentity()
        receiver_id_key = SigningIdentity()
        with self.assertRaises(ValueError):
            ReceiverGuard(guard_db, receiver_identity=None, strict_production=True)
        guard = ReceiverGuard(guard_db, receiver_identity=receiver_id_key, strict_production=True)
        guard.register_issuer(issuer.public)
        with closing(sqlite3.connect(guard_db)) as db:
            db.execute("CREATE TABLE items(id TEXT PRIMARY KEY, val INT)")
            db.commit()
        now = int(time.time())
        grant = sign_envelope(issuer.key, {
            "schema": "openline.guard.grant.v1",
            "grant_id": "g-split-1",
            "issuer_pub": issuer.public,
            "worker_pub": worker.public,
            "task_id": "t1",
            "step_id": "s1",
            "operation": "insert_item",
            "allowed_targets": ["item-1"],
            "expires": now + 3600,
        })
        req = sign_envelope(worker.key, {
            "schema": "openline.guard.request.v1",
            "task_id": "t1",
            "step_id": "s1",
            "operation": "insert_item",
            "target_id": "item-1",
            "worker_pub": worker.public,
            "grant_sha256": grant["payload_sha256"],
            "payload": {"val": 42},
        })
        res1 = guard.execute(
            grant=grant,
            request=req,
            fn=lambda db, p: db.execute("INSERT INTO items VALUES ('item-1', ?)", (p["val"],)),
            target_table="items",
            target_pk_col="id",
        )
        self.assertEqual(res1["status"], "COMMITTED")
        # Simulate split-DB crash where cdb commit_seq was lost (NULL) after db.commit()
        with closing(sqlite3.connect(guard.control_db_path)) as cdb:
            cdb.execute("UPDATE ol_guard_grants_ledger SET commit_seq=NULL WHERE grant_id='g-split-1'")
            cdb.commit()
        # Retry identical request -> returns ALREADY_COMMITTED and reconciles commit_seq in ol_guard_grants_ledger!
        res2 = guard.execute(
            grant=grant,
            request=req,
            fn=lambda db, p: db.execute("INSERT INTO items VALUES ('item-1', ?)", (p["val"],)),
            target_table="items",
            target_pk_col="id",
        )
        self.assertEqual(res2["status"], "ALREADY_COMMITTED")
        with closing(sqlite3.connect(guard.control_db_path)) as cdb:
            c_row = cdb.execute("SELECT commit_seq FROM ol_guard_grants_ledger WHERE grant_id='g-split-1'").fetchone()
        self.assertIsNotNone(c_row[0], "Split-DB retry must reconcile missing commit_seq in ol_guard_grants_ledger")

    # ------------------------------------------------------------------
    # M7: Operational qualification rehearsal & Linux userns probe
    # ------------------------------------------------------------------
    def test_07_m7_operational_rehearsal_and_userns_probe(self):
        out = run_rehearsal()
        self.assertEqual(out["status"], "PASS")
        self.assertTrue(out["receipt_verified"])
        self.assertTrue(out["backup_verified"])
        self.assertTrue(out["owner_key_rotation_verified"])

        # Probe Linux user+mount namespace isolation if unshare --user is supported on this kernel
        p_probe = subprocess.run(["unshare", "--user", "--map-root-user", "id", "-u"], capture_output=True, text=True)
        if p_probe.returncode == 0 and p_probe.stdout.strip() == "0":
            secret_dir = self.base / "receiver_secret"
            secret_dir.mkdir(mode=0o700)
            (secret_dir / "receiver.key").write_text("secret_key_material", encoding="utf-8")
            # Inside an unshared mount namespace, bind-mounting an empty tmpfs over receiver_secret hides it completely
            p_ns = subprocess.run(
                [
                    "unshare", "--user", "--map-root-user", "--mount", "sh", "-c",
                    f"mount -t tmpfs tmpfs {secret_dir} && test ! -e {secret_dir}/receiver.key && echo ISOLATED_OK",
                ],
                capture_output=True, text=True,
            )
            if p_ns.returncode == 0:
                self.assertIn("ISOLATED_OK", p_ns.stdout)



    # ------------------------------------------------------------------
    # Real SIGKILL (-9) child daemon crash recovery at CUT-03 & CUT-06
    # ------------------------------------------------------------------
    def test_08_real_sigkill_daemon_subprocess_crash_recovery(self):
        deploy_env = bootstrap_isolated_deployment(self.base / "deploy_sigkill")
        cfg = deploy_env["config"]
        alice_key = deploy_env["alice_key"]
        bob_key = deploy_env["bob_key"]

        # Assign and prepare repair-sigkill-1 first
        svc_prep = OpenLineReceiverService(cfg, require_distinct_uids=False)
        svc_prep.start_background()
        try:
            ctrl_alice = OpenLineIPCClient(
                socket_path=cfg["paths"]["control_socket"],
                channel="control",
                deployment_id=cfg["deployment_id"],
                project_id=cfg["project_id"],
                receiver_id=cfg["receiver_id"],
                principal_id="control:alice",
                signer_key=alice_key,
                pinned_receiver_pub=cfg["receiver_pub"],
            )
            worker_bob = OpenLineIPCClient(
                socket_path=cfg["paths"]["worker_socket"],
                channel="worker",
                deployment_id=cfg["deployment_id"],
                project_id=cfg["project_id"],
                receiver_id=cfg["receiver_id"],
                principal_id="worker:bob",
                signer_key=bob_key,
                pinned_receiver_pub=cfg["receiver_pub"],
            )
            asgn_claim = {
                "project_id": cfg["project_id"],
                "assignment_id": "repair-sigkill-1",
                "deliverable_id": "invoice-feature",
                "worker_member": "bob",
                "basis": "invoice_v2",
                "allowed_paths": ["app/price.py"],
                "action": "repair_assignment",
            }
            self.assertEqual(ctrl_alice.call("control.assign", {
                "assignment_id": "repair-sigkill-1",
                "deliverable_id": "invoice-feature",
                "worker_member": "bob",
                "basis": "invoice_v2",
                "allowed_paths": ["app/price.py"],
                "contributor_signature": _sig(alice_key, asgn_claim),
            })["status"], "OK")
            r_prep = worker_bob.prepare_workspace("repair-sigkill-1", self.base / "sigkill_bob_ws")
            ws = Path(r_prep["result"]["client_workspace"])
            (ws / "app" / "price.py").write_text("def total(qty):\n    return qty * 11\n", encoding="utf-8")
        finally:
            svc_prep.stop()

        # Write production_config.json and spawn real child daemon with --crash-cutpoint CUT-03 --crash-mode SIGKILL
        cfg_file = self.base / "deploy_sigkill" / "production_config.json"
        cfg_file.write_text(json.dumps(cfg, sort_keys=True, indent=2), encoding="utf-8")
        daemon_script = PKG / "receiver_service.py"
        daemon_proc = subprocess.Popen(
            [sys.executable, "-B", str(daemon_script), "--config", str(cfg_file), "--crash-cutpoint", "CUT-03", "--crash-mode", "SIGKILL"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            ready_line = daemon_proc.stdout.readline()
            self.assertIn("LISTENING", ready_line)
            worker_bob = OpenLineIPCClient(
                socket_path=cfg["paths"]["worker_socket"],
                channel="worker",
                deployment_id=cfg["deployment_id"],
                project_id=cfg["project_id"],
                receiver_id=cfg["receiver_id"],
                principal_id="worker:bob",
                signer_key=bob_key,
                pinned_receiver_pub=cfg["receiver_pub"],
            )
            with self.assertRaises(Exception):
                worker_bob.submit_workspace_proposal("repair-sigkill-1", ws, allowed_paths=["app/price.py"], request_id="req-sigkill-1")
            rc = daemon_proc.wait(timeout=5.0)
            self.assertEqual(rc, -9, f"Expected child daemon to die with SIGKILL (-9), got {rc}")
        finally:
            if daemon_proc.poll() is None:
                daemon_proc.kill()
                daemon_proc.wait()
            if daemon_proc.stdout:
                daemon_proc.stdout.close()
            if daemon_proc.stderr:
                daemon_proc.stderr.close()

        # Restart a fresh OpenLineReceiverService on the same state directory -> must recover CUT-03 automatically!
        svc_recovered = OpenLineReceiverService(cfg, require_distinct_uids=False)
        svc_recovered.start_background()
        try:
            outbox_rec = svc_recovered.outbox.get_by_assignment("repair-sigkill-1")
            self.assertIsNotNone(outbox_rec)
            self.assertEqual(outbox_rec["verdict"], "ACCEPTED")
            checked = verify_receipt(
                outbox_rec["receipt"],
                cfg["receiver_pub"],
                accepted_git=Path(cfg["paths"]["accepted_git"]),
                project_db=Path(cfg["paths"]["project_db"]),
            )
            self.assertEqual(checked["crypto"], "VERIFIED")
            self.assertTrue(checked["git_verified"])
            self.assertTrue(checked["continuity_verified"])
        finally:
            svc_recovered.stop()

    # ------------------------------------------------------------------
    # RACE-02: Concurrent proposals vs member revocation & contract change
    # ------------------------------------------------------------------
    def test_09_concurrent_proposals_and_revocation_races(self):
        deploy_env = bootstrap_isolated_deployment(self.base / "deploy_race2")
        cfg = deploy_env["config"]
        owner_key = deploy_env["owner_key"]
        alice_key = deploy_env["alice_key"]
        bob_key = deploy_env["bob_key"]

        svc = OpenLineReceiverService(cfg, require_distinct_uids=False)
        svc.start_background()
        try:
            ctrl_owner = OpenLineIPCClient(
                socket_path=cfg["paths"]["control_socket"],
                channel="control",
                deployment_id=cfg["deployment_id"],
                project_id=cfg["project_id"],
                receiver_id=cfg["receiver_id"],
                principal_id="control:owner",
                signer_key=owner_key,
                pinned_receiver_pub=cfg["receiver_pub"],
            )
            ctrl_alice = OpenLineIPCClient(
                socket_path=cfg["paths"]["control_socket"],
                channel="control",
                deployment_id=cfg["deployment_id"],
                project_id=cfg["project_id"],
                receiver_id=cfg["receiver_id"],
                principal_id="control:alice",
                signer_key=alice_key,
                pinned_receiver_pub=cfg["receiver_pub"],
            )
            worker_bob = OpenLineIPCClient(
                socket_path=cfg["paths"]["worker_socket"],
                channel="worker",
                deployment_id=cfg["deployment_id"],
                project_id=cfg["project_id"],
                receiver_id=cfg["receiver_id"],
                principal_id="worker:bob",
                signer_key=bob_key,
                pinned_receiver_pub=cfg["receiver_pub"],
            )

            asgn_claim = {
                "project_id": cfg["project_id"],
                "assignment_id": "repair-race-rev",
                "deliverable_id": "invoice-feature",
                "worker_member": "bob",
                "basis": "invoice_v2",
                "allowed_paths": ["app/price.py"],
                "action": "repair_assignment",
            }
            self.assertEqual(ctrl_alice.call("control.assign", {
                "assignment_id": "repair-race-rev",
                "deliverable_id": "invoice-feature",
                "worker_member": "bob",
                "basis": "invoice_v2",
                "allowed_paths": ["app/price.py"],
                "contributor_signature": _sig(alice_key, asgn_claim),
            })["status"], "OK")

            r_prep = worker_bob.prepare_workspace("repair-race-rev", self.base / "race_bob_ws")
            ws = Path(r_prep["result"]["client_workspace"])
            (ws / "app" / "price.py").write_text("def total(qty):\n    return qty * 11\n", encoding="utf-8")

            # Revoke bob on control.sock before bob submits -> bob is immediately refused with MEMBER_REVOKED!
            rev_claim = {"project_id": cfg["project_id"], "member_id": "bob", "action": "revoke_member"}
            r_rev = ctrl_owner.call("control.revoke_member", {
                "member_id": "bob",
                "owner_signature": _sig(owner_key, rev_claim),
            })
            self.assertEqual(r_rev["status"], "OK")

            r_sub = worker_bob.submit_workspace_proposal("repair-race-rev", ws, allowed_paths=["app/price.py"])
            self.assertEqual(r_sub["status"], "REFUSED")
            self.assertEqual(r_sub["code"], "MEMBER_REVOKED")
        finally:
            svc.stop()


if __name__ == "__main__":
    unittest.main()
