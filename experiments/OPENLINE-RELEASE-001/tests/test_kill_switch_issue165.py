"""Adversarial dogfood & conformance test suite for OpenLine Issue #165:
Kill Switch integration into Living Projects (`ProjectLedger`, `SafePromotion`, `Protect`, `ReceiverGuard`, CLI, MCP).

Covers:
- `terryncew/openline-kill-switch` (`a303796745164e3c186d7a45cc090004afdc8e7f`, tag `v0.1.0`) 12 Gate Contract invariants
- Conformance paths `P1`..`P7`, controls `C1-PRE` & `C1-POST`, and 20 concurrent thread-barrier `STOP`-vs-`finalize` races
- Codex independent falsification vectors `ADV-KS-01`..`ADV-KS-10`
- Post-Release 002 dogfood fixes `H-01`..`H-05`
"""
from __future__ import annotations

from contextlib import closing
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

RELEASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RELEASE_DIR))

from engine_loader import load_engines  # noqa: E402

load_engines()

import openline_cli as cli  # noqa: E402
from project import ProjectLedger, ProjectRefused  # noqa: E402
from openline_guard import GuardRefused, ReceiverGuard, SigningIdentity, VerificationError  # noqa: E402
from kill_switch import KillSwitchEvidenceLog, run_kill_switch_conformance  # noqa: E402
from kill_switch_auditor import audit_evidence_file  # noqa: E402


class TestKillSwitchIssue165(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="openline-issue165-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_01_full_conformance_p1_to_p7_c1_and_20_barrier_races(self) -> None:
        """Verifies P1..P7, C1-PRE, C1-POST, and 20 concurrent thread-barrier STOP-vs-finalize races."""
        out_dir = self.tmp / "conformance"
        res = run_kill_switch_conformance(out_dir, race_iterations=20)
        self.assertEqual(res["status"], "PASS", res)
        audit = res["audit"]
        for p in ("P1", "P2", "P3", "P4", "P5", "P6", "P7"):
            self.assertEqual(audit["required_paths_stopped"][p], "STOPPED", f"{p} failed: {audit}")
        self.assertEqual(audit["controls"]["C1-PRE"], "PRE_STOP_COMMIT")
        self.assertEqual(audit["controls"]["C1-POST"], "FRESH_POST_STOP_COMMIT")
        self.assertEqual(audit["race_count"], 20)
        self.assertEqual(audit["forbidden_race_count"], 0)

    def test_02_adv_ks_01_and_04_owner_only_and_monotonic_clear_stop(self) -> None:
        """ADV-KS-01 & ADV-KS-04: Only owner can issue/clear STOP; clear_stop never resets stop_seq."""
        proj_dir = self.tmp / "proj_owner"
        cli.cmd_init(SimpleNamespace(dir=str(proj_dir), project_id="p-ks-owner", workers="alice,bob", validator=None, worker_uid=65534))
        cfg = cli._load_config(proj_dir)
        promo, project, protect = cli._build_engines(cfg, 65534)
        owner_key = cli._read_key(Path(cfg["keys_dir"]) / "owner.key")
        alice_key = cli._read_key(Path(cfg["keys_dir"]) / "alice.key")
        bob_key = cli._read_key(Path(cfg["keys_dir"]) / "bob.key")
        receiver_key = cli._read_key(Path(cfg["key_file"]))

        # Assign repair before STOP
        asgn_claim = {
            "project_id": project.id,
            "assignment_id": "rep-pre-stop",
            "deliverable_id": "invoice-feature",
            "worker_member": "bob",
            "basis": "invoice_v2",
            "allowed_paths": ["app/price.py"],
            "action": "repair_assignment",
        }
        project.assign_repair("rep-pre-stop", "invoice-feature", "bob", "invoice_v2", cli._sig(alice_key, asgn_claim), allowed_paths=["app/price.py"])
        st_prep = promo.prepare("rep-pre-stop")
        (Path(st_prep["workspace"]) / "app" / "price.py").write_text("def total(qty):\n    return qty * 11\n")

        # Worker and receiver keys cannot issue_stop
        stop_claim = {"project_id": project.id, "action": "issue_stop", "reason": "forged_stop", "expected_epoch": 1}
        with self.assertRaises(ProjectRefused) as ctx_w:
            project.issue_stop("forged_stop", cli._sig(bob_key, stop_claim), expected_epoch=1)
        self.assertEqual(str(ctx_w.exception), "invalid_owner_signature")

        with self.assertRaises(ProjectRefused) as ctx_r:
            project.issue_stop("forged_stop", cli._sig(receiver_key, stop_claim), expected_epoch=1)
        self.assertEqual(str(ctx_r.exception), "invalid_owner_signature")

        with self.assertRaises(ProjectRefused) as ctx_role:
            project.issue_stop("forged_stop", cli._sig(owner_key, stop_claim), actor_role="worker", expected_epoch=1)
        self.assertEqual(str(ctx_role.exception), "stop_authority_owner_only")

        # Owner issues STOP
        real_stop = {"project_id": project.id, "action": "issue_stop", "reason": "owner_stop_1", "expected_epoch": 1}
        st1 = project.issue_stop("owner_stop_1", cli._sig(owner_key, real_stop), expected_epoch=1)
        self.assertTrue(st1["stopped"])
        self.assertEqual(st1["epoch"], 2)
        self.assertGreater(st1["stop_seq"], 0)

        # Owner clears STOP
        clear_claim = {"project_id": project.id, "action": "clear_stop", "reason": "owner_clear_1", "expected_epoch": 2}
        st2 = project.clear_stop("owner_clear_1", cli._sig(owner_key, clear_claim), expected_epoch=2)
        self.assertFalse(st2["stopped"])
        self.assertEqual(st2["epoch"], 3)
        self.assertEqual(st2["stop_seq"], st1["stop_seq"])
        self.assertGreater(st2["clear_seq"], st2["stop_seq"])

        # Pre-STOP assignment 'rep-pre-stop' MUST still be refused as old_authority_dead even after clear_stop!
        out_dead = protect.intercept("rep-pre-stop")
        self.assertEqual(out_dead["verdict"], "STOPPED")
        self.assertEqual(out_dead["receipt"]["payload"]["reason"], "old_authority_dead")

        # Across restart (re-instantiating ProjectLedger), standing and old_authority_dead persist (ADV-KS-08)
        project_restarted = ProjectLedger(Path(cfg["project_db"]), promotion=promo)
        st_restart = project_restarted.read_stop_state()
        self.assertEqual(st_restart, st2)

    def test_03_adv_ks_05_fail_closed_on_corrupted_or_deleted_stop_state(self) -> None:
        """ADV-KS-05: Deleting or corrupting stop_state fails closed on both ProjectLedger and ReceiverGuard."""
        proj_dir = self.tmp / "proj_corrupt"
        cli.cmd_init(SimpleNamespace(dir=str(proj_dir), project_id="p-corrupt", workers="alice,bob", validator=None, worker_uid=65534))
        cfg = cli._load_config(proj_dir)
        promo, project, protect = cli._build_engines(cfg, 65534)
        alice_key = cli._read_key(Path(cfg["keys_dir"]) / "alice.key")

        asgn_claim = {
            "project_id": project.id,
            "assignment_id": "rep-corrupt",
            "deliverable_id": "invoice-feature",
            "worker_member": "bob",
            "basis": "invoice_v2",
            "allowed_paths": ["app/price.py"],
            "action": "repair_assignment",
        }
        project.assign_repair("rep-corrupt", "invoice-feature", "bob", "invoice_v2", cli._sig(alice_key, asgn_claim), allowed_paths=["app/price.py"])
        st_prep = promo.prepare("rep-corrupt")
        (Path(st_prep["workspace"]) / "app" / "price.py").write_text("def total(qty):\n    return qty * 11\n")

        # Corrupt stop_state by deleting the row
        with closing(sqlite3.connect(project.db_path)) as db:
            db.execute("DELETE FROM stop_state")
            db.commit()

        head_before = promo.accepted()
        out = protect.intercept("rep-corrupt")
        self.assertEqual(out["verdict"], "STOPPED")
        self.assertEqual(out["receipt"]["payload"]["reason"], "authority_unavailable_fail_closed")
        self.assertEqual(promo.accepted(), head_before)

        # Also test ReceiverGuard fail-closed when ol_guard_stop_state is deleted
        guard_db = self.tmp / "guard_corrupt.sqlite"
        with closing(sqlite3.connect(guard_db)) as db:
            db.execute("CREATE TABLE items(id TEXT PRIMARY KEY, val INTEGER)")
            db.commit()
        owner = SigningIdentity()
        worker = SigningIdentity()
        guard = ReceiverGuard(guard_db)
        guard.register_issuer(owner.public)
        grant = owner.issue_grant(worker.public, task_id="t1", operation="op1", allowed_targets=["k1"])
        req = worker.sign_request(grant, operation="op1", target_id="k1", payload={"v": 1})

        with closing(sqlite3.connect(guard.control_db_path)) as cdb:
            cdb.execute("DELETE FROM ol_guard_stop_state")
            cdb.commit()

        with self.assertRaises(GuardRefused) as ctx_g:
            guard.execute(
                grant=grant,
                request=req,
                fn=lambda db, p: db.execute("INSERT INTO items VALUES ('k1', 1)"),
                target_table="items",
                target_pk_col="id",
            )
        self.assertEqual(ctx_g.exception.reason, "authority_unavailable_fail_closed")
        with closing(sqlite3.connect(guard_db)) as db:
            self.assertIsNone(db.execute("SELECT * FROM items WHERE id='k1'").fetchone())

    def test_04_adv_ks_09_auditor_detects_tampering_escaped_and_unknown(self) -> None:
        """ADV-KS-09: Offline auditor detects hash-chain tampering, ESCAPED effects, and missing checks (UNKNOWN)."""
        ev_path = self.tmp / "ev_test.jsonl"
        ev = KillSwitchEvidenceLog(ev_path)
        ev.append("DECISION", "PATH-ESCAPED", {"decision": "REFUSE", "reason": "OLD_AUTHORITY_DEAD", "stop_seq": 5, "attempt_seq": 6})
        ev.append("EFFECT_STORE_CHECK", "PATH-ESCAPED", {"present": True})
        ev.append("DECISION", "PATH-MISSING-CHECK", {"decision": "REFUSE", "reason": "OLD_AUTHORITY_DEAD", "stop_seq": 5, "attempt_seq": 7})

        rep = audit_evidence_file(ev_path)
        self.assertTrue(rep["valid"])
        self.assertEqual(rep["verdicts"]["PATH-ESCAPED"], "ESCAPED")
        self.assertEqual(rep["verdicts"]["PATH-MISSING-CHECK"], "UNKNOWN")

        # Tamper with line 1 payload
        lines = ev_path.read_text().splitlines()
        rec0 = json.loads(lines[0])
        rec0["payload"]["decision"] = "COMMIT"
        lines[0] = json.dumps(rec0, sort_keys=True)
        ev_path.write_text("\n".join(lines) + "\n")

        rep_tampered = audit_evidence_file(ev_path)
        self.assertFalse(rep_tampered["valid"])
        self.assertEqual(rep_tampered["chain"], "CHAIN_TAMPERED")

    def test_05_adv_ks_10_post_release_002_dogfood_fixes_h01_to_h04(self) -> None:
        """ADV-KS-10: Verifies H-01 (memory assignment required), H-02 (forged claim signature refused),
        H-03 (collateral protected row mutation refused), and H-04 (single-execution grant reuse refused)."""
        proj_dir = self.tmp / "proj_h01_h02"
        cli.cmd_init(SimpleNamespace(dir=str(proj_dir), project_id="p-dogfood", workers="alice,bob", validator=None, worker_uid=65534))
        cfg = cli._load_config(proj_dir)
        _promo, project, _protect = cli._build_engines(cfg, 65534)

        # H-01: propose_memory with assignment_id=None or nonexistent assignment_id is refused
        with self.assertRaises(ProjectRefused) as ctx_h01a:
            project.propose_memory("mem-unscoped", "invoice-feature", "bob", "invoice_v2", "aa" * 32, "diag", "lesson", assignment_id=None)
        self.assertEqual(str(ctx_h01a.exception), "memory_assignment_required")

        with self.assertRaises(ProjectRefused) as ctx_h01b:
            project.propose_memory("mem-ghost", "invoice-feature", "bob", "invoice_v2", "aa" * 32, "diag", "lesson", assignment_id="nonexistent-asgn")
        self.assertEqual(str(ctx_h01b.exception), "memory_assignment_missing")

        # H-02: record_graph_claim with explicit signer_id + forged signature_hex is refused instead of silently downgraded
        with self.assertRaises(ProjectRefused) as ctx_h02:
            project.record_graph_claim("claim-forged", "invoice-feature", "verified", "true", signer_id="alice", signature_hex="00" * 64)
        self.assertEqual(str(ctx_h02.exception), "invalid_owner_signature")

        # H-03 & H-04: ReceiverGuard collateral protected record mutation and grant reuse after basis reopen
        guard_db = self.tmp / "guard_h03_h04.sqlite"
        with closing(sqlite3.connect(guard_db)) as db:
            db.execute("CREATE TABLE accounts(id TEXT PRIMARY KEY, balance INTEGER)")
            db.execute("INSERT INTO accounts VALUES ('protected-acct', 1000)")
            db.execute("INSERT INTO accounts VALUES ('target-1', 100)")
            db.execute("INSERT INTO accounts VALUES ('target-2', 100)")
            db.commit()
        owner = SigningIdentity()
        worker = SigningIdentity()
        guard = ReceiverGuard(guard_db, protected_targets={("accounts", "protected-acct")})
        guard.register_issuer(owner.public)
        guard.set_basis("policy", "v1")

        # H-03: Collateral UPDATE to 'protected-acct' while declaring target_id='target-1' is refused and rolled back
        g_col = owner.issue_grant(worker.public, task_id="t-col", operation="adjust", allowed_targets=["target-1", "target-2"], max_amount=50, required_basis={"policy": "v1"})
        r_col = worker.sign_request(g_col, operation="adjust", target_id="target-1", payload={"amount": 25})
        with self.assertRaises(GuardRefused) as ctx_h03:
            guard.execute(
                grant=g_col,
                request=r_col,
                fn=lambda db, p: (
                    db.execute("UPDATE accounts SET balance = balance + ? WHERE id='target-1'", (p["amount"],)),
                    db.execute("UPDATE accounts SET balance = 0 WHERE id='protected-acct'"),
                ),
                target_table="accounts",
                target_pk_col="id",
            )
        self.assertEqual(ctx_h03.exception.reason, "protected_record_collateral_mutation_refused")
        with closing(sqlite3.connect(guard_db)) as db:
            self.assertEqual(db.execute("SELECT balance FROM accounts WHERE id='protected-acct'").fetchone()[0], 1000)

        # H-04: Legitimate execution on 'target-1', then reusing the same grant_id on 'target-2' is refused
        res_ok = guard.execute(
            grant=g_col,
            request=r_col,
            fn=lambda db, p: db.execute("UPDATE accounts SET balance = balance + ? WHERE id='target-1'", (p["amount"],)),
            target_table="accounts",
            target_pk_col="id",
        )
        self.assertEqual(res_ok["status"], "COMMITTED")
        r_reuse = worker.sign_request(g_col, operation="adjust", target_id="target-2", payload={"amount": 50})
        with self.assertRaises(GuardRefused) as ctx_h04:
            guard.execute(
                grant=g_col,
                request=r_reuse,
                fn=lambda db, p: db.execute("UPDATE accounts SET balance = balance + ? WHERE id='target-2'", (p["amount"],)),
                target_table="accounts",
                target_pk_col="id",
            )
        self.assertEqual(ctx_h04.exception.reason, "grant_already_consumed")

    def test_06_cli_and_mcp_kill_switch_integration(self) -> None:
        """Verifies openline kill-switch CLI and MCP tools end-to-end."""
        proj_dir = self.tmp / "proj_cli_mcp"
        cli_script = str(RELEASE_DIR / "openline_cli.py")
        subprocess.run([sys.executable, cli_script, "init", "--dir", str(proj_dir)], check=True, capture_output=True)

        # CLI status, stop, clear
        st_out = json.loads(subprocess.run([sys.executable, cli_script, "kill-switch", "--dir", str(proj_dir), "--action", "status"], check=True, capture_output=True, text=True).stdout)
        self.assertFalse(st_out["kill_switch"]["stopped"])
        self.assertEqual(st_out["kill_switch"]["epoch"], 1)

        stop_out = json.loads(subprocess.run([sys.executable, cli_script, "kill-switch", "--dir", str(proj_dir), "--action", "stop", "--reason", "cli_test_stop"], check=True, capture_output=True, text=True).stdout)
        self.assertEqual(stop_out["status"], "KILL_SWITCH_STOPPED")
        self.assertTrue(stop_out["kill_switch"]["stopped"])
        self.assertEqual(stop_out["kill_switch"]["epoch"], 2)

        # Assigning without --post-stop-owner-sign fails during STOP
        assign_fail = subprocess.run([sys.executable, cli_script, "assign", "--dir", str(proj_dir), "--assignment", "r-blocked", "--worker", "bob", "--basis", "invoice_v2"], capture_output=True, text=True)
        self.assertEqual(assign_fail.returncode, 2)
        self.assertIn("stopped_at_epoch_2", assign_fail.stderr)

        # Assigning WITH --post-stop-owner-sign succeeds during STOP
        assign_ok = json.loads(subprocess.run([sys.executable, cli_script, "assign", "--dir", str(proj_dir), "--assignment", "r-override", "--worker", "bob", "--basis", "invoice_v2", "--post-stop-owner-sign"], check=True, capture_output=True, text=True).stdout)
        self.assertEqual(assign_ok["status"], "ASSIGNED")
        self.assertTrue(assign_ok["post_stop_override"])

        # MCP requires a separately signed, epoch-bound owner intent. A caller's
        # owner_confirm=true is only a boolean and MUST NOT authorize CLEAR.
        cfg = cli._load_config(proj_dir)
        owner_key = cli._read_key(Path(cfg["keys_dir"]) / "owner.key")
        signature = cli._sig(owner_key, {"project_id": cfg["project_id"], "action": "clear_stop", "reason": "mcp_signed_clear", "expected_epoch": 2})
        reqs = "\n".join([
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "openline_kill_switch_status", "arguments": {}}}),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "openline_kill_switch_clear", "arguments": {"reason": "mcp_unconfirmed_clear"}}}),
            json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "openline_kill_switch_clear", "arguments": {"reason": "mcp_untrusted_confirm", "owner_confirm": True}}}),
            json.dumps({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "openline_kill_switch_clear", "arguments": {"reason": "mcp_signed_clear", "signature": signature, "expected_epoch": 2}}}),
        ]) + "\n"
        proc = subprocess.run([sys.executable, "-W", "error::ResourceWarning", cli_script, "mcp", "--dir", str(proj_dir)], input=reqs, text=True, capture_output=True, check=True)
        lines = [json.loads(line) for line in proc.stdout.strip().splitlines()]
        ks_st = json.loads(lines[0]["result"]["content"][0]["text"])
        self.assertTrue(ks_st["kill_switch"]["stopped"])
        self.assertTrue(lines[1]["result"]["isError"])
        self.assertTrue(lines[2]["result"]["isError"])
        ks_clr = json.loads(lines[3]["result"]["content"][0]["text"])
        self.assertEqual(ks_clr["status"], "KILL_SWITCH_CLEARED")
        self.assertFalse(ks_clr["kill_switch"]["stopped"])
        self.assertEqual(ks_clr["kill_switch"]["epoch"], 3)


if __name__ == "__main__":
    unittest.main()
