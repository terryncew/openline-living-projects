"""
Regression suite for OPENLINE_ARGON_POST_RELEASE_002 (evaluated against
public v0.1.0, tag v0.1.0, commit 5ba070c):

- H-01: propose_memory requires a non-empty string assignment_id for a
  NEW memory (existing-memory settled/ownership checks still fire first).
- H-02: a fully presented signer+signature pair that fails verification
  (or names an inactive/unknown signer) refuses; it is NOT silently
  downgraded to UNTRUSTED_ADVISORY. Partial credentials (signer only or
  signature only) and fully unsigned claims remain advisory by design:
  no signer is recorded and no signature is stored.
- H-03: ReceiverGuard snapshots ALL protected rows before fn and refuses
  (with rollback + signed REFUSED receipt) if any protected row changed.
- GPT-6 A: a protected row whose table has no single declared PRIMARY
  KEY (and is not the execution target with target_pk_col) refuses
  BEFORE fn runs (protected_record_pk_unresolvable) instead of being
  silently skipped from the snapshot.
- H-04 + GPT-6 B: grants are single-execution. A second COMMIT under the
  same grant_id -- different target after REOPEN, or the IDENTICAL
  request after REOPEN -- refuses with grant_already_consumed, with no
  second effect. An identical retry while the receipt is CURRENT still
  returns ALREADY_COMMITTED without re-running fn. A redo after REOPEN
  requires a FRESH grant.
- H-05 (Argon patch hunk) is NOT applied here: protect.py already uses
  closing() at _emit_receipt in v0.1.0 (verified, not re-applied).
"""
from __future__ import annotations

from contextlib import closing
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
import unittest

HERE = Path(__file__).resolve().parent
RELEASE_DIR = HERE.parent
sys.path.insert(0, str(RELEASE_DIR))

from engine_loader import load_engines  # noqa: E402
load_engines()

import openline_cli as cli  # noqa: E402
from project import ProjectRefused  # noqa: E402
from openline_guard import ReceiverGuard, SigningIdentity, GuardRefused  # noqa: E402


def _guard_with_tables(tmp: Path, name: str):
    db_path = tmp / name
    with closing(sqlite3.connect(db_path)) as db:
        db.execute("CREATE TABLE swaps(swap_id TEXT PRIMARY KEY, bonus REAL)")
        db.execute("CREATE TABLE payroll(lock_id TEXT PRIMARY KEY, total REAL)")
        db.execute("INSERT INTO payroll VALUES ('LOCK-1', 4280.0)")
        db.execute("CREATE TABLE counters(id TEXT PRIMARY KEY, value INTEGER)")
        db.execute("INSERT INTO counters VALUES ('C1', 0)")
        db.execute("CREATE TABLE audit_notes(note_id TEXT UNIQUE NOT NULL, body TEXT NOT NULL)")
        db.execute("INSERT INTO audit_notes VALUES ('NOTE-1', 'original')")
        db.execute("CREATE TABLE nopk_rows(row_key TEXT, amount REAL)")
        db.execute("INSERT INTO nopk_rows VALUES ('R1', 100.0)")
        db.commit()
    issuer = SigningIdentity()
    worker = SigningIdentity()
    guard = ReceiverGuard(db_path, protected_targets={("payroll", "LOCK-1")})
    guard.register_issuer(issuer.public)
    guard.set_basis("labor_rule", "labor_rule_v1")
    return guard, issuer, worker


class TestPostRelease002(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="openline-post002-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---- H-01 ----
    def test_h01_memory_requires_assignment_for_new_memory(self) -> None:
        proj_dir = self.tmp / "proj_h01"
        cli.cmd_init(SimpleNamespace(dir=str(proj_dir), project_id="p-h01", workers="alice,bob", validator=None, worker_uid=65534))
        cfg = cli._load_config(proj_dir)
        _promo, project, _protect = cli._build_engines(cfg, 65534)
        for bad in (None, "", "   ", 123):
            with self.assertRaises(ProjectRefused) as ctx:
                project.propose_memory("mem-new", "invoice-feature", "alice", "invoice_v2",
                                       "ab" * 32, "diag", "lesson", assignment_id=bad)
            self.assertEqual(str(ctx.exception), "memory_assignment_required")

    def test_h01_existing_memory_checks_still_fire_first(self) -> None:
        # Locks Argon's placement: settled/ownership checks run before the
        # assignment-required check, so existing F-02 expectations are kept.
        proj_dir = self.tmp / "proj_h01b"
        cli.cmd_init(SimpleNamespace(dir=str(proj_dir), project_id="p-h01b", workers="alice,bob", validator=None, worker_uid=65534))
        cfg = cli._load_config(proj_dir)
        _promo, project, _protect = cli._build_engines(cfg, 65534)
        cli.cmd_assign(SimpleNamespace(
            dir=str(proj_dir), worker_uid=65534, assignment="rep-alice", deliverable="invoice-feature",
            worker="alice", basis="invoice_v2", allowed_paths="app/price.py", as_member=None, signature=None,
        ))
        cli.cmd_prepare(SimpleNamespace(
            dir=str(proj_dir), worker_uid=65534, assignment="rep-alice",
            propose_memory="mem-alice-1", diagnosis="alice diag", lesson="alice lesson",
        ))
        with self.assertRaises(ProjectRefused) as ctx:
            project.propose_memory("mem-alice-1", "invoice-feature", "bob", "invoice_v2",
                                   "ab" * 32, "overwrite", "overwrite", assignment_id=None)
        self.assertEqual(str(ctx.exception), "candidate_memory_owned_by_different_worker_or_assignment")

    # ---- H-02 ----
    def test_h02_forged_and_unknown_signer_refuse_partials_stay_advisory(self) -> None:
        proj_dir = self.tmp / "proj_h02"
        cli.cmd_init(SimpleNamespace(dir=str(proj_dir), project_id="p-h02", workers="alice,bob", validator=None, worker_uid=65534))
        cfg = cli._load_config(proj_dir)
        _promo, project, _protect = cli._build_engines(cfg, 65534)
        with self.assertRaises(ProjectRefused) as ctx:
            project.record_graph_claim("c-forged", "invoice-feature", "verified_by", "alice",
                                       signer_id="alice", signature_hex="ff" * 64)
        self.assertEqual(str(ctx.exception), "invalid_owner_signature")
        with self.assertRaises(ProjectRefused) as ctx2:
            project.record_graph_claim("c-unknown", "invoice-feature", "verified_by", "alice",
                                       signer_id="mallory", signature_hex="ff" * 64)
        self.assertEqual(str(ctx2.exception), "claim_signer_not_active_member")
        # Partial credentials: no full pair presented, so advisory, signer dropped.
        for cid, kw in [
            ("c-part-signer", dict(signer_id="alice", signature_hex=None)),
            ("c-part-sig", dict(signer_id=None, signature_hex="ff" * 64)),
            ("c-unsigned", dict(signer_id=None, signature_hex=None)),
        ]:
            r = project.record_graph_claim(cid, "invoice-feature", "verified_by", "alice", **kw)
            self.assertEqual(r["trust_status"], "UNTRUSTED_ADVISORY")
            self.assertIsNone(r["signer_id"])
        # A valid bound claim still works.
        alice_key = cli._read_key(Path(cfg["keys_dir"]) / "alice.key")
        env = {"project_id": project.id, "claim_id": "c-valid", "subject": "invoice-feature",
               "predicate": "verified_by", "object": "alice_v1", "signer_id": "alice", "action": "graph_claim"}
        r = project.record_graph_claim("c-valid", "invoice-feature", "verified_by", "alice_v1",
                                       signer_id="alice", signature_hex=cli._sig(alice_key, env))
        self.assertEqual(r["trust_status"], "CRYPTOGRAPHICALLY_BOUND")

    # ---- H-03 / GPT-6 A ----
    def test_h03_collateral_mutation_refused_and_rolled_back(self) -> None:
        guard, issuer, worker = _guard_with_tables(self.tmp, "h03.sqlite")
        grant = issuer.issue_grant(worker.public, task_id="t-h03", operation="approve",
                                   max_amount=40.0, allowed_targets=["SWAP-1"])
        req = worker.sign_request(grant, operation="approve", target_id="SWAP-1",
                                  payload={"bonus": 30.0})

        def collateral(db, p):
            db.execute("INSERT INTO swaps VALUES ('SWAP-1', 30.0)")
            db.execute("UPDATE payroll SET total=0.0 WHERE lock_id='LOCK-1'")

        with self.assertRaises(GuardRefused) as ctx:
            guard.execute(grant=grant, request=req, fn=collateral,
                          target_table="swaps", target_pk_col="swap_id", amount_field="bonus")
        self.assertEqual(ctx.exception.reason, "protected_record_collateral_mutation_refused")
        self.assertEqual(ctx.exception.receipt["payload"]["status"], "REFUSED")
        with closing(sqlite3.connect(guard.db_path)) as db:
            self.assertEqual(db.execute("SELECT total FROM payroll WHERE lock_id='LOCK-1'").fetchone()[0], 4280.0)
            self.assertIsNone(db.execute("SELECT 1 FROM swaps WHERE swap_id='SWAP-1'").fetchone())

    def test_gpt6a_unresolvable_protected_pk_refuses_before_fn(self) -> None:
        guard, issuer, worker = _guard_with_tables(self.tmp, "g6a.sqlite")
        guard.protect_record("audit_notes", "NOTE-1")
        grant = issuer.issue_grant(worker.public, task_id="t-g6a", operation="approve",
                                   max_amount=40.0, allowed_targets=["SWAP-1"])
        req = worker.sign_request(grant, operation="approve", target_id="SWAP-1",
                                  payload={"bonus": 30.0})

        def tamper(db, p):
            db.execute("INSERT INTO swaps VALUES ('SWAP-1', 30.0)")
            db.execute("UPDATE audit_notes SET body='tampered' WHERE note_id='NOTE-1'")

        with self.assertRaises(GuardRefused) as ctx:
            guard.execute(grant=grant, request=req, fn=tamper,
                          target_table="swaps", target_pk_col="swap_id", amount_field="bonus")
        self.assertEqual(ctx.exception.reason, "protected_record_pk_unresolvable")
        with closing(sqlite3.connect(guard.db_path)) as db:
            self.assertEqual(db.execute("SELECT body FROM audit_notes WHERE note_id='NOTE-1'").fetchone()[0], "original")
            self.assertIsNone(db.execute("SELECT 1 FROM swaps WHERE swap_id='SWAP-1'").fetchone())

    def test_gpt6a_target_table_fallback_still_protects(self) -> None:
        # The execution target table has no declared PK, but target_pk_col
        # is the configured identifier, so its protected row IS checked.
        guard, issuer, worker = _guard_with_tables(self.tmp, "g6a2.sqlite")
        guard.protect_record("nopk_rows", "R1")
        grant = issuer.issue_grant(worker.public, task_id="t-g6a2", operation="approve",
                                   max_amount=40.0, allowed_targets=["R2"])
        req = worker.sign_request(grant, operation="approve", target_id="R2",
                                  payload={"bonus": 30.0})

        def collateral(db, p):
            db.execute("INSERT INTO nopk_rows VALUES ('R2', 30.0)")
            db.execute("UPDATE nopk_rows SET amount=0.0 WHERE row_key='R1'")

        with self.assertRaises(GuardRefused) as ctx:
            guard.execute(grant=grant, request=req, fn=collateral,
                          target_table="nopk_rows", target_pk_col="row_key", amount_field="bonus")
        self.assertEqual(ctx.exception.reason, "protected_record_collateral_mutation_refused")
        with closing(sqlite3.connect(guard.db_path)) as db:
            self.assertEqual(db.execute("SELECT amount FROM nopk_rows WHERE row_key='R1'").fetchone()[0], 100.0)

    # ---- H-04 / GPT-6 B ----
    def test_h04_and_gpt6b_grant_is_single_execution(self) -> None:
        guard, issuer, worker = _guard_with_tables(self.tmp, "h04.sqlite")
        # H-04: different target after REOPEN
        grant = issuer.issue_grant(worker.public, task_id="t-h04", operation="approve",
                                   max_amount=40.0, allowed_targets=["SWAP-M1", "SWAP-M2"],
                                   required_basis={"labor_rule": "labor_rule_v1"})
        req1 = worker.sign_request(grant, operation="approve", target_id="SWAP-M1", payload={"bonus": 35.0})
        res1 = guard.execute(grant=grant, request=req1,
                             fn=lambda db, p: db.execute("INSERT INTO swaps VALUES ('SWAP-M1', 35.0)"),
                             target_table="swaps", target_pk_col="swap_id", amount_field="bonus")
        self.assertEqual(res1["status"], "COMMITTED")
        guard.set_basis("labor_rule", "labor_rule_v2")
        guard.set_basis("labor_rule", "labor_rule_v1")
        req2 = worker.sign_request(grant, operation="approve", target_id="SWAP-M2", payload={"bonus": 35.0})
        with self.assertRaises(GuardRefused) as ctx:
            guard.execute(grant=grant, request=req2,
                          fn=lambda db, p: db.execute("INSERT INTO swaps VALUES ('SWAP-M2', 35.0)"),
                          target_table="swaps", target_pk_col="swap_id", amount_field="bonus")
        self.assertEqual(ctx.exception.reason, "grant_already_consumed")
        with closing(sqlite3.connect(guard.db_path)) as db:
            total = db.execute("SELECT COALESCE(SUM(bonus),0) FROM swaps WHERE swap_id IN ('SWAP-M1','SWAP-M2')").fetchone()[0]
        self.assertEqual(total, 35.0)

        # GPT-6 B: identical request after REOPEN, non-idempotent increment
        grant_b = issuer.issue_grant(worker.public, task_id="t-g6b", operation="increment",
                                     allowed_targets=["C1"], required_basis={"labor_rule": "labor_rule_v1"})
        req_b = worker.sign_request(grant_b, operation="increment", target_id="C1", payload={"note": "tick"})
        res_b1 = guard.execute(grant=grant_b, request=req_b,
                               fn=lambda db, p: db.execute("UPDATE counters SET value=value+10 WHERE id='C1'"),
                               target_table="counters", target_pk_col="id")
        self.assertEqual(res_b1["status"], "COMMITTED")
        guard.set_basis("labor_rule", "labor_rule_v2")
        guard.set_basis("labor_rule", "labor_rule_v1")
        with self.assertRaises(GuardRefused) as ctx_b:
            guard.execute(grant=grant_b, request=req_b,
                          fn=lambda db, p: db.execute("UPDATE counters SET value=value+10 WHERE id='C1'"),
                          target_table="counters", target_pk_col="id")
        self.assertEqual(ctx_b.exception.reason, "grant_already_consumed")
        with closing(sqlite3.connect(guard.db_path)) as db:
            self.assertEqual(db.execute("SELECT value FROM counters WHERE id='C1'").fetchone()[0], 10)

    def test_idempotent_retry_while_current_and_fresh_grant_redo_after_reopen(self) -> None:
        guard, issuer, worker = _guard_with_tables(self.tmp, "redo.sqlite")
        grant = issuer.issue_grant(worker.public, task_id="t-redo", operation="increment",
                                   allowed_targets=["C1"], required_basis={"labor_rule": "labor_rule_v1"})
        req = worker.sign_request(grant, operation="increment", target_id="C1", payload={"note": "tick"})
        fn = lambda db, p: db.execute("UPDATE counters SET value=value+10 WHERE id='C1'")
        res1 = guard.execute(grant=grant, request=req, fn=fn, target_table="counters", target_pk_col="id")
        self.assertEqual(res1["status"], "COMMITTED")
        # Identical retry while CURRENT: no second effect.
        res2 = guard.execute(grant=grant, request=req, fn=fn, target_table="counters", target_pk_col="id")
        self.assertEqual(res2["status"], "ALREADY_COMMITTED")
        with closing(sqlite3.connect(guard.db_path)) as db:
            self.assertEqual(db.execute("SELECT value FROM counters WHERE id='C1'").fetchone()[0], 10)
        # After REOPEN, the old grant is spent, but a FRESH grant can redo.
        guard.set_basis("labor_rule", "labor_rule_v2")
        guard.set_basis("labor_rule", "labor_rule_v1")
        grant2 = issuer.issue_grant(worker.public, task_id="t-redo", operation="increment",
                                    allowed_targets=["C1"], required_basis={"labor_rule": "labor_rule_v1"})
        req2 = worker.sign_request(grant2, operation="increment", target_id="C1", payload={"note": "tick"})
        res3 = guard.execute(grant=grant2, request=req2, fn=fn, target_table="counters", target_pk_col="id")
        self.assertEqual(res3["status"], "COMMITTED")
        with closing(sqlite3.connect(guard.db_path)) as db:
            self.assertEqual(db.execute("SELECT value FROM counters WHERE id='C1'").fetchone()[0], 20)


if __name__ == "__main__":
    unittest.main()
