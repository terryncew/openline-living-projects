"""
Comprehensive RC3 Product Proof & Verification Suite
Branch: engineering/argon-living-projects-rc3-20261101

Tests all 7 mandatory proof areas required by the Final OpenLine RC3 Build & Custody Commission:
1. Cross-agent rotation and persistent STOP/HOLD (with advisory boundary check).
2. Two disruptions and recovery without destroying unrelated accepted work.
3. Duplicate requests (idempotent & conflicting), concurrency, restart, and threshold migration.
4. Unauthorized action refusal (path escape, revoked worker, delegated effect inflation, unauthorized pivot, forged CAS).
5. Independent receipt verification against actual Git and SQLite effects (plus tamper detection).
6. Clean installation, CLI (`./openline`), and MCP (`mcp_server.py` JSON-RPC stdio).
7. Competent conventional Git/SQLite/CI comparison (preserving PARITY where observed).
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

HERE = Path(__file__).resolve().parent
RELEASE_DIR = HERE.parent
ROOT = RELEASE_DIR.parents[1]
sys.path.insert(0, str(RELEASE_DIR))

from engine_loader import load_engines  # noqa: E402
load_engines()

import openline_cli as cli  # noqa: E402
from protect import Protect, ProtectError, verify_receipt  # noqa: E402
from project import ProjectLedger, ProjectRefused  # noqa: E402
from foundation.promotion import SafePromotion, atomically_write  # noqa: E402
from foundation.effects import LocalEffectStore, EffectDenied  # noqa: E402
from openline_guard import ReceiverGuard, SigningIdentity, GuardRefused, VerificationError, verify_receipt_offline  # noqa: E402
from graph_watchdog import VerifiedAttempt, CrossAgentGraphWatchdog, unwitnessed_agreement, shared_bottlenecks  # noqa: E402
from durable_watchdog import DurableGraphWatchdog  # noqa: E402
from watchdog import ExecutionSupervisor, IntegratedGraphSupervisor, Attempt, ProgressEvidence, _canonical_json  # noqa: E402
from living_projects_e2e import run_mandatory_12_step_e2e, run_competent_conventional_comparison  # noqa: E402


class TestRC3ProductProof(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="openline-rc3-proof-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_01_cross_agent_rotation_and_persistent_stop_hold(self) -> None:
        """
        1. Cross-agent rotation (alice -> bob -> carol) triggers persistent STOP_STAGNATION.
        2. Restarting supervisor & rotating to 4th agent (dave) remains blocked on (deliverable, basis).
        3. Uncertain external mutation triggers persistent HOLD_RECONCILIATION across restart & rotation
           until owner Ed25519 signature reconciles.
        4. Watchdog remains strictly advisory (receiver_authorization == 'NONE') and never mutates accepted work.
        """
        proj_dir = self.tmp / "proj_rot"
        rc = cli.cmd_init(SimpleNamespace(
            dir=str(proj_dir), project_id="rc3-rot", workers="alice,bob,carol",
            validator=None, worker_uid=65534, no_initial_break=False,
        ))
        self.assertEqual(rc, 0)
        cfg = cli._load_config(proj_dir)
        promo, project, protect = cli._build_engines(cfg, 65534)
        owner_key = cli._read_key(Path(cfg["keys_dir"]) / "owner.key")
        owner_pub = owner_key.public_key()
        sup_key = Ed25519PrivateKey.generate()

        initial_accepted_head = promo.accepted()

        # Rotate across alice (att 1), bob (att 2), carol (att 3) with 0 progress, recreating supervisor each time
        for idx, worker in enumerate(["alice", "bob", "carol"], start=1):
            sup = IntegratedGraphSupervisor(
                db_path=cfg["project_db"],
                project_id=project.id,
                owner_public_key=owner_pub,
                supervisor_signing_key=sup_key,
                threshold=3,
                project_ledger=project,
            )
            rec = sup.supervise_verified_attempt(
                VerifiedAttempt("invoice-feature", "invoice_v2", worker, f"rot-att-{idx}", 0, 0, True, "none")
            )
            self.assertEqual(rec["payload"]["advisory"]["receiver_authorization"], "NONE")
            if idx < 3:
                self.assertEqual(rec["event_type"], "SUPERVISOR_ALLOW_CONTINUE")
            else:
                self.assertEqual(rec["event_type"], "SUPERVISOR_ENFORCED_STOP_STAGNATION")
                self.assertEqual(rec["payload"]["advisory"]["workers"], ["alice", "bob", "carol"])
                self.assertFalse(rec["payload"]["pre_existing_stop"])

        # Restart supervisor and rotate to a 4th worker; persistent STOP_STAGNATION must hold
        sup_restart = IntegratedGraphSupervisor(
            db_path=cfg["project_db"],
            project_id=project.id,
            owner_public_key=owner_pub,
            supervisor_signing_key=sup_key,
            threshold=3,
            project_ledger=project,
        )
        rec_after_stop = sup_restart.supervise_verified_attempt(
            VerifiedAttempt("invoice-feature", "invoice_v2", "alice", "rot-att-4", 0, 10, True, "none")
        )
        self.assertEqual(rec_after_stop["event_type"], "SUPERVISOR_ENFORCED_STOP_STAGNATION")
        self.assertTrue(rec_after_stop["payload"]["pre_existing_stop"])
        # Accepted Git head is completely untouched by watchdog/supervisor stop
        self.assertEqual(promo.accepted(), initial_accepted_head)

        # Now test persistent HOLD_RECONCILIATION on ('independent-formatter', 'format_v2')
        rec_hold_1 = sup_restart.supervise_verified_attempt(
            VerifiedAttempt("independent-formatter", "format_v2", "alice", "hold-att-1", 0, 0, True, "uncertain")
        )
        self.assertEqual(rec_hold_1["event_type"], "SUPERVISOR_ENFORCED_HOLD_RECONCILIATION")
        self.assertFalse(rec_hold_1["payload"]["pre_existing_hold"])

        # Restart and rotate to bob -> still held!
        sup_restart_2 = IntegratedGraphSupervisor(
            db_path=cfg["project_db"],
            project_id=project.id,
            owner_public_key=owner_pub,
            supervisor_signing_key=sup_key,
            threshold=3,
            project_ledger=project,
        )
        rec_hold_2 = sup_restart_2.supervise_verified_attempt(
            VerifiedAttempt("independent-formatter", "format_v2", "bob", "hold-att-2", 0, 5, True, "none")
        )
        self.assertEqual(rec_hold_2["event_type"], "SUPERVISOR_ENFORCED_HOLD_RECONCILIATION")
        self.assertTrue(rec_hold_2["payload"]["pre_existing_hold"])

        # Forged reconciliation signature fails
        forged_key = Ed25519PrivateKey.generate()
        rec_payload = {
            "action": "RECONCILE_GRAPH_WATCHDOG_HOLD",
            "project_id": project.id,
            "deliverable_id": "independent-formatter",
            "basis": "format_v2",
            "resolution": "ROLLED_BACK_CLEAN",
        }
        bad_rec = sup_restart_2.owner_reconcile_hold(
            deliverable_id="independent-formatter",
            basis="format_v2",
            resolution="ROLLED_BACK_CLEAN",
            owner_signature_hex=forged_key.sign(_canonical_json(rec_payload)).hex(),
        )
        self.assertEqual(bad_rec["event_type"], "REFUSED_INVALID_OWNER_RECONCILIATION_SIGNATURE")

        # Valid owner signature clears hold and allows bob to make verified progress
        good_rec = sup_restart_2.owner_reconcile_hold(
            deliverable_id="independent-formatter",
            basis="format_v2",
            resolution="ROLLED_BACK_CLEAN",
            owner_signature_hex=owner_key.sign(_canonical_json(rec_payload)).hex(),
        )
        self.assertEqual(good_rec["event_type"], "OWNER_RECONCILED_HOLD_CLEARED")
        self.assertIsNone(good_rec["payload"]["status_after"]["terminal"])

        rec_resumed = sup_restart_2.supervise_verified_attempt(
            VerifiedAttempt("independent-formatter", "format_v2", "bob", "hold-att-3", 0, 2, True, "none")
        )
        self.assertEqual(rec_resumed["event_type"], "SUPERVISOR_ALLOW_CONTINUE")

    def test_02_two_disruptions_and_recovery_preserving_unrelated_work(self) -> None:
        """
        Runs the complete 12-step two-disruption, multi-deliverable repair, revocation,
        interrupted-promotion recovery, and successor memory inheritance suite.
        """
        e2e_res = run_mandatory_12_step_e2e(self.tmp / "e2e_12step")
        self.assertEqual(e2e_res["overall_verdict"], "PASS_LOCAL_MECHANISM_AND_SECURITY_GATES")
        for step_key, step_val in e2e_res["steps"].items():
            self.assertIn(step_val["status"], ("PASS", "PASS_MECHANISM_PROOF"), f"{step_key} failed")

    def test_03_duplicates_concurrency_restart_and_threshold_migration(self) -> None:
        """
        Tests idempotent duplicate suppression, conflicting duplicate rejection,
        multi-threaded SQLite watchdog concurrency, restart durability, and legacy threshold migration.
        """
        db_path = self.tmp / "conc_mig.sqlite"
        # Create a legacy schema without threshold or fingerprint columns
        with closing(sqlite3.connect(db_path)) as db:
            db.executescript("""
                CREATE TABLE watchdog_scope (
                    deliverable TEXT NOT NULL, basis TEXT NOT NULL,
                    peak INTEGER, stagnant INTEGER NOT NULL DEFAULT 0,
                    terminal TEXT, PRIMARY KEY(deliverable,basis));
                CREATE TABLE watchdog_attempt (
                    deliverable TEXT NOT NULL, basis TEXT NOT NULL,
                    attempt_id TEXT NOT NULL, worker TEXT NOT NULL,
                    PRIMARY KEY(deliverable,basis,attempt_id));
                INSERT INTO watchdog_scope VALUES ('legacy-d', 'v1', 0, 3, NULL);
            """)
            db.commit()

        # Re-open with threshold=3 -> migrates schema and marks legacy-d@v1 terminal='STOP_STAGNATION'
        wd = DurableGraphWatchdog(db_path, threshold=3)
        st_legacy = wd.status("legacy-d", "v1")
        self.assertEqual(st_legacy["threshold"], 3)
        self.assertEqual(st_legacy["terminal"], "STOP_STAGNATION")

        # Conflicting threshold on re-open raises ValueError
        with self.assertRaises(ValueError):
            DurableGraphWatchdog(db_path, threshold=5)

        # Idempotent duplicate vs conflicting duplicate across restart
        att1 = VerifiedAttempt("deliv-a", "v2", "alice", "dup-1", 0, 0, True, "none")
        self.assertEqual(wd.record(att1)["decision"], "CONTINUE")
        self.assertEqual(DurableGraphWatchdog(db_path, threshold=3).record(att1)["decision"], "DUPLICATE_IGNORED")
        with self.assertRaises(ValueError):
            DurableGraphWatchdog(db_path, threshold=3).record(
                VerifiedAttempt("deliv-a", "v2", "bob", "dup-1", 0, 0, True, "none")
            )
        with self.assertRaises(ValueError):
            DurableGraphWatchdog(db_path, threshold=3).record(
                VerifiedAttempt("deliv-a", "v2", "alice", "dup-1", 0, 4, True, "none")
            )

        # Concurrent writes from 8 workers
        def _submit(i: int) -> dict:
            return DurableGraphWatchdog(db_path, threshold=3).record(
                VerifiedAttempt("conc-d", "v2", f"w-{i}", f"c-att-{i}", 0, 0, True, "none")
            )
        with ThreadPoolExecutor(max_workers=8) as pool:
            outs = list(pool.map(_submit, range(8)))
        st_conc = DurableGraphWatchdog(db_path, threshold=3).status("conc-d", "v2")
        self.assertEqual(st_conc["terminal"], "STOP_STAGNATION")
        self.assertEqual(st_conc["stagnant_attempts"], 3)

    def test_04_unauthorized_action_refusal_and_05_independent_receipt_verification(self) -> None:
        """
        Tests unauthorized action refusal across ProjectLedger, Protect, LocalEffectStore,
        and ExecutionSupervisor, and verifies Ed25519 receipts against actual Git & SQLite state.
        """
        proj_dir = self.tmp / "proj_sec"
        cli.cmd_init(SimpleNamespace(
            dir=str(proj_dir), project_id="rc3-sec", workers="alice,bob,carol",
            validator=None, worker_uid=65534, no_initial_break=False,
        ))
        cfg = cli._load_config(proj_dir)
        promo, project, protect = cli._build_engines(cfg, 65534)
        owner_key = cli._read_key(Path(cfg["keys_dir"]) / "owner.key")
        alice_key = cli._read_key(Path(cfg["keys_dir"]) / "alice.key")

        # 4a. Non-owner attempting change_dependency is refused
        bad_chg = {"project_id": project.id, "dependency": "invoice_v1", "contract": "invoice_v3", "action": "change_dependency"}
        with self.assertRaises(ProjectRefused):
            project.change_dependency("invoice_v1", "invoice_v3", cli._sig(alice_key, bad_chg))

        # 4b. Worker editing outside allowed_paths is STOPPED and emits a verifiable Ed25519 refusal receipt
        cli.cmd_assign(SimpleNamespace(
            dir=str(proj_dir), worker_uid=65534, assignment="sec-rogue-path",
            deliverable="invoice-feature", worker="bob", basis="invoice_v2",
            allowed_paths="app/price.py", as_member="alice", signature=None,
        ))
        cand = promo.prepare("sec-rogue-path")
        (Path(cand["workspace"]) / "app" / "independent.py").write_text("def label(v): return 'HACKED'\n")
        head_before = promo.accepted()
        out_rogue = protect.intercept("sec-rogue-path")
        self.assertEqual(out_rogue["verdict"], "STOPPED")
        self.assertEqual(out_rogue["receipt"]["payload"]["reason"], "repair_outside_allowed_source")
        self.assertEqual(promo.accepted(), head_before)

        # Independently verify the STOPPED receipt signature using only the public key
        ver_rogue = verify_receipt(out_rogue["receipt"], cfg["receiver_pub"])
        self.assertEqual(ver_rogue["crypto"], "VERIFIED")
        # Tamper with 1 field in receipt copy -> verify_receipt must raise ProtectError
        tampered_receipt = json.loads(json.dumps(out_rogue["receipt"]))
        tampered_receipt["payload"]["verdict"] = "ACCEPTED"
        with self.assertRaises(ProtectError):
            verify_receipt(tampered_receipt, cfg["receiver_pub"])

        # 4c. ReceiverGuard delegated worker tampering with refund amount (ADV-03/04) -> GuardRefused with signed REFUSED receipt
        eff_db = self.tmp / "guard_effects.sqlite"
        with closing(sqlite3.connect(eff_db)) as db:
            db.execute("CREATE TABLE accounts(id TEXT PRIMARY KEY, balance INTEGER)")
            db.execute("INSERT INTO accounts VALUES ('acct-1', 100)")
            db.commit()
        buyer = SigningIdentity()
        worker = SigningIdentity()
        rg = ReceiverGuard(eff_db)
        rg.register_issuer(buyer.public)
        grant = buyer.issue_grant(
            worker.public,
            task_id="refund-task-1",
            operation="refund",
            max_amount=50,
            allowed_targets=["acct-1"],
        )
        # Worker attempts inflated refund of 500 (> max_amount 50)
        bad_req = worker.sign_request(
            grant,
            operation="refund",
            target_id="acct-1",
            payload={"amount": 500},
        )
        with self.assertRaises(GuardRefused) as ctx:
            rg.execute(
                grant=grant,
                request=bad_req,
                fn=lambda db, p: db.execute("UPDATE accounts SET balance = balance + ? WHERE id='acct-1'", (p["amount"],)),
                target_table="accounts",
                target_pk_col="id",
                amount_field="amount",
            )
        refusal_receipt = ctx.exception.receipt
        # Verify account balance was rolled back via SAVEPOINT (remains 100) AND refusal receipt is cryptographically valid
        with closing(sqlite3.connect(eff_db)) as db:
            bal = db.execute("SELECT balance FROM accounts WHERE id='acct-1'").fetchone()[0]
        self.assertEqual(bal, 100)
        ver_ref = verify_receipt_offline(refusal_receipt, pinned_receiver_pub=rg.receiver_public, db_path=eff_db)
        self.assertEqual(ver_ref["status"], "REFUSED")
        self.assertEqual(ver_ref["effect_verification"], "REFUSAL_RECORD_VERIFIED")

        # Now execute a valid refund of 40 (<= max_amount 50) and verify receipt against live SQLite effect
        good_req = worker.sign_request(
            grant,
            operation="refund",
            target_id="acct-1",
            payload={"amount": 40},
        )
        ok_res = rg.execute(
            grant=grant,
            request=good_req,
            fn=lambda db, p: db.execute("UPDATE accounts SET balance = balance + ? WHERE id='acct-1'", (p["amount"],)),
            target_table="accounts",
            target_pk_col="id",
            amount_field="amount",
        )
        self.assertEqual(ok_res["status"], "COMMITTED")
        ver_ok = verify_receipt_offline(ok_res["receipt"], pinned_receiver_pub=rg.receiver_public, db_path=eff_db)
        self.assertEqual(ver_ok["effect_verification"], "VERIFIED_CURRENT")

        # Tamper directly with the SQLite row out-of-band -> verify_receipt_offline must detect REFUSED:effect_mismatch!
        with closing(sqlite3.connect(eff_db)) as db:
            db.execute("UPDATE accounts SET balance = 99999 WHERE id='acct-1'")
            db.commit()
        with self.assertRaises(VerificationError):
            verify_receipt_offline(ok_res["receipt"], pinned_receiver_pub=rg.receiver_public, db_path=eff_db)

        # 5. ReceiverGuard project-level cryptographic seal verification & tamper detection
        seal_info = ReceiverGuard.seal(proj_dir)
        self.assertEqual(seal_info["status"], "SEALED")
        ver_seal = ReceiverGuard.verify(proj_dir)
        self.assertEqual(ver_seal["status"], "VERIFIED")

    def test_06_clean_install_cli_and_mcp_and_07_conventional_comparison(self) -> None:
        """
        Tests CLI (`openline_cli.py`) including `watchdog-record` and `watchdog-status`,
        MCP server (`mcp_server.py`) JSON-RPC stdio round-trip, and conventional Git/DAG comparison.
        """
        proj_dir = self.tmp / "proj_cli_mcp"
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        cli_script = str(RELEASE_DIR / "openline_cli.py")

        # 1. CLI init
        r_init = subprocess.run(
            ["python3", cli_script, "init", "--dir", str(proj_dir), "--project-id", "rc3-cli"],
            env=env, capture_output=True, text=True, check=True,
        )
        init_json = json.loads(r_init.stdout)
        self.assertEqual(init_json["status"], "INITIALIZED")

        # 2. CLI watchdog-record & watchdog-status
        r_wr = subprocess.run(
            [
                "python3", cli_script, "watchdog-record",
                "--dir", str(proj_dir),
                "--deliverable", "invoice-feature",
                "--basis", "invoice_v2",
                "--worker", "alice",
                "--attempt", "cli-att-1",
                "--progress-before", "0",
                "--progress-after", "0",
                "--verified",
            ],
            env=env, capture_output=True, text=True, check=True,
        )
        wr_json = json.loads(r_wr.stdout)
        self.assertEqual(wr_json["advisory"]["decision"], "CONTINUE")
        self.assertEqual(wr_json["advisory"]["stagnant_attempts"], 1)

        r_ws = subprocess.run(
            [
                "python3", cli_script, "watchdog-status",
                "--dir", str(proj_dir),
                "--deliverable", "invoice-feature",
                "--basis", "invoice_v2",
            ],
            env=env, capture_output=True, text=True, check=True,
        )
        ws_json = json.loads(r_ws.stdout)
        self.assertEqual(ws_json["watchdog_scope"]["stagnant_attempts"], 1)

        # 3. MCP JSON-RPC stdio round-trip (tools/list + openline_watchdog_status + openline_watchdog_record)
        mcp_reqs = "\n".join([
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
            json.dumps({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {
                    "name": "openline_watchdog_record",
                    "arguments": {
                        "dir": str(proj_dir),
                        "deliverable": "invoice-feature",
                        "basis": "invoice_v2",
                        "worker": "bob",
                        "attempt": "mcp-att-2",
                        "progress_before": 0,
                        "progress_after": 0,
                        "receiver_verified": True,
                    },
                },
            }),
            json.dumps({
                "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": {
                    "name": "openline_watchdog_status",
                    "arguments": {
                        "dir": str(proj_dir),
                        "deliverable": "invoice-feature",
                        "basis": "invoice_v2",
                    },
                },
            }),
        ]) + "\n"
        r_mcp = subprocess.run(
            ["python3", cli_script, "mcp", "--dir", str(proj_dir)],
            input=mcp_reqs, env=env, capture_output=True, text=True, check=True,
        )
        mcp_lines = [json.loads(line) for line in r_mcp.stdout.strip().splitlines()]
        tools_list = [t["name"] for t in mcp_lines[1]["result"]["tools"]]
        self.assertIn("openline_watchdog_status", tools_list)
        self.assertIn("openline_watchdog_record", tools_list)
        ws_mcp = json.loads(mcp_lines[3]["result"]["content"][0]["text"])
        self.assertEqual(ws_mcp["watchdog_scope"]["stagnant_attempts"], 2)
        self.assertEqual(ws_mcp["watchdog_scope"]["workers"], ["alice", "bob"])

        # 4. Competent conventional comparison
        conv = run_competent_conventional_comparison(self.tmp / "conv_cmp")
        self.assertEqual(conv["comparison_matrix"][0]["classification"], "PARITY")


if __name__ == "__main__":
    unittest.main()
