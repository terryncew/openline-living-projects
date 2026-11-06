"""Adversarial crash-consistency and SIGKILL fault-injection regression suite for Issue #165.

Proves that the two-phase write-ahead `PENDING_CAS` gate reservation and `_reconcile_pending_cas_tx`
protocol across `ProjectLedger`, `SafePromotion`, and `Protect` resolves the Git-CAS vs. SQLite
crash split-brain (`CRASH_GAP_REPRO.py`) across all crash boundaries:
1. Crash after `git update-ref` (`fail_after_ref=True`) followed by post-crash `STOP`:
   `commit_seq` is durably recorded (`commit_seq < stop_seq`), `resolve_repair` and `protect.reconcile`
   settle `project.sqlite` (`ACCEPTED` / `PRE_STOP_COMMIT`), and subsequent repairs remain `STOPPED`.
2. Crash after `PENDING_CAS` reservation but before `git update-ref` (`fail_before_ref=True`)
   followed by post-crash `STOP`: `issue_stop` and `protect.reconcile` observe `refs/heads/accepted`
   unchanged, void `commit_seq = NULL` (`CAS_ABORTED_PRE_REF`), and refuse resurrection (`old_authority_dead`).
3. Direct `SafePromotion.promote` bypass without pre-STOP `PENDING_CAS` reservation is refused by
   `resolve_repair` (`old_authority_dead`).
4. Post-crash `revoke_member` and `change_dependency` before `resolve_repair` settle the pre-crash
   repair at `commit_seq` without `assignment_basis_stale` split-brain while preserving `REOPEN`
   for the newer contract.
5. Real child-process `SIGKILL` (`kill -9`) at both `fail_before_ref='SIGKILL'` and `fail_after_ref='SIGKILL'`
   boundaries recovers deterministically without split-brain.
"""
from __future__ import annotations

import contextlib
from contextlib import closing
import functools
import io
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
from engine_loader import load_engines  # noqa: E402

load_engines()

import openline_cli as cli  # noqa: E402
from project import ProjectLedger, ProjectRefused  # noqa: E402
from protect import verify_receipt  # noqa: E402
from continuity import audit as continuity_audit  # noqa: E402


class CrashConsistencyHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="openline-crash-hardening-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _init_project(self, name: str = "crash-proj") -> tuple[Path, dict, object, object, object]:
        proj_dir = self.tmp / name
        with contextlib.redirect_stdout(io.StringIO()):
            rc = cli.cmd_init(SimpleNamespace(
                dir=str(proj_dir),
                project_id=name,
                workers="alice,bob,carol",
                validator=None,
                worker_uid=65534,
            ))
        self.assertEqual(rc, 0)
        cfg = cli._load_config(proj_dir)
        promo, project, protect = cli._build_engines(cfg, 65534)
        return proj_dir, cfg, promo, project, protect

    def test_01_crash_after_git_cas_reconciles_cleanly_after_post_crash_stop(self) -> None:
        """Exact CRASH_GAP_REPRO.py scenario: crash after git update-ref + post-crash STOP reconciles without split-brain."""
        proj_dir, cfg, promo, project, protect = self._init_project("crash-post-ref")
        alice = cli._read_key(Path(cfg["keys_dir"]) / "alice.key")
        owner = cli._read_key(Path(cfg["keys_dir"]) / "owner.key")

        claim = {
            "project_id": project.id,
            "assignment_id": "repair-crash",
            "deliverable_id": "invoice-feature",
            "worker_member": "bob",
            "basis": "invoice_v2",
            "allowed_paths": ["app/price.py"],
            "action": "repair_assignment",
        }
        project.assign_repair("repair-crash", "invoice-feature", "bob", "invoice_v2", cli._sig(alice, claim), allowed_paths=["app/price.py"])
        st = promo.prepare("repair-crash")
        (Path(st["workspace"]) / "app" / "price.py").write_text("def total(qty):\n    return qty * 11\n")

        orig_promote = promo.promote

        @functools.wraps(orig_promote)
        def crash_after_ref(*a, **kw):
            kw["fail_after_ref"] = True
            return orig_promote(*a, **kw)

        promo.promote = crash_after_ref
        old_head = promo.accepted()
        with self.assertRaisesRegex(RuntimeError, "injected_crash_after_ref_cas"):
            project.promote_repair("repair-crash", acceptance_cmd=[sys.executable, "-B", cfg["validator"], cfg["project_db"]])
        promo.promote = orig_promote

        new_head = promo.accepted()
        self.assertNotEqual(old_head, new_head)

        with closing(sqlite3.connect(cfg["project_db"])) as db:
            row = db.execute("SELECT commit_seq, cas_target_head, cas_state FROM assignment_standing WHERE assignment_id='repair-crash'").fetchone()
        self.assertIsNotNone(row[0])
        self.assertEqual(row[1], new_head)
        self.assertEqual(row[2], "PENDING_CAS")

        # Owner issues STOP after the crash
        stop_claim = {"project_id": project.id, "action": "issue_stop", "reason": "owner stop after crash", "expected_epoch": 1}
        stop_st = project.issue_stop("owner stop after crash", cli._sig(owner, stop_claim), expected_epoch=1)
        self.assertTrue(stop_st["stopped"])
        self.assertGreater(stop_st["stop_seq"], row[0])

        # Reconcile via Protect (which calls promo.recover + project.resolve_repair)
        rec_out = protect.reconcile("repair-crash")
        self.assertEqual(rec_out["verdict"], "ACCEPTED", rec_out)
        checked = verify_receipt(
            rec_out["receipt"],
            cfg["receiver_pub"],
            accepted_git=Path(cfg["accepted_git"]),
            project_db=Path(cfg["project_db"]),
        )
        self.assertEqual(checked["crypto"], "VERIFIED")
        self.assertTrue(checked["git_verified"])
        self.assertTrue(checked["continuity_verified"])

        # Repeated recovery is idempotent
        rec_again = protect.reconcile("repair-crash")
        self.assertEqual(rec_again["verdict"], "ACCEPTED")
        self.assertEqual(project.resolve_repair("repair-crash", new_head), "ALREADY_RECORDED")

        # STOP remains active and blocks any subsequent repair without post-STOP owner grant
        with self.assertRaisesRegex(ProjectRefused, "stopped_at_epoch_2"):
            project.assign_repair("repair-blocked", "invoice-feature", "bob", "invoice_v2", cli._sig(alice, dict(claim, assignment_id="repair-blocked")), allowed_paths=["app/price.py"])

    def test_02_crash_after_gate_commit_before_git_cas_aborts_and_cannot_resurrect(self) -> None:
        """Crash after PENDING_CAS reservation but BEFORE git update-ref voids commit_seq and refuses resurrection."""
        proj_dir, cfg, promo, project, protect = self._init_project("crash-pre-ref")
        alice = cli._read_key(Path(cfg["keys_dir"]) / "alice.key")
        owner = cli._read_key(Path(cfg["keys_dir"]) / "owner.key")

        claim = {
            "project_id": project.id,
            "assignment_id": "repair-pre-ref",
            "deliverable_id": "invoice-feature",
            "worker_member": "bob",
            "basis": "invoice_v2",
            "allowed_paths": ["app/price.py"],
            "action": "repair_assignment",
        }
        project.assign_repair("repair-pre-ref", "invoice-feature", "bob", "invoice_v2", cli._sig(alice, claim), allowed_paths=["app/price.py"])
        st = promo.prepare("repair-pre-ref")
        (Path(st["workspace"]) / "app" / "price.py").write_text("def total(qty):\n    return qty * 11\n")

        orig_promote = promo.promote

        @functools.wraps(orig_promote)
        def crash_before_ref(*a, **kw):
            kw["fail_before_ref"] = True
            return orig_promote(*a, **kw)

        promo.promote = crash_before_ref
        old_head = promo.accepted()
        with self.assertRaisesRegex(RuntimeError, "injected_crash_before_ref_cas"):
            project.promote_repair("repair-pre-ref", acceptance_cmd=[sys.executable, "-B", cfg["validator"], cfg["project_db"]])
        promo.promote = orig_promote

        # Git ref did NOT advance
        self.assertEqual(promo.accepted(), old_head)

        # Owner issues STOP after the pre-ref crash
        stop_claim = {"project_id": project.id, "action": "issue_stop", "reason": "stop after pre-ref crash", "expected_epoch": 1}
        project.issue_stop("stop after pre-ref crash", cli._sig(owner, stop_claim), expected_epoch=1)

        # Verify issue_stop voided the unapplied PENDING_CAS reservation
        with closing(sqlite3.connect(cfg["project_db"])) as db:
            row = db.execute("SELECT commit_seq, cas_state FROM assignment_standing WHERE assignment_id='repair-pre-ref'").fetchone()
        self.assertIsNone(row[0])
        self.assertEqual(row[1], "CAS_ABORTED_PRE_REF")

        # Reconcile reports STOPPED (cas_not_applied) and preserves unchanged Git head
        rec_out = protect.reconcile("repair-pre-ref")
        self.assertEqual(rec_out["verdict"], "STOPPED")
        self.assertEqual(rec_out["receipt"]["payload"]["reason"], "cas_not_applied")
        self.assertEqual(promo.accepted(), old_head)

        # Even after clear_stop, 'repair-pre-ref' remains permanently dead (old_authority_dead)
        clear_claim = {"project_id": project.id, "action": "clear_stop", "reason": "clear after pre-ref crash", "expected_epoch": 2}
        project.clear_stop("clear after pre-ref crash", cli._sig(owner, clear_claim), expected_epoch=2)
        with self.assertRaisesRegex(ProjectRefused, "old_authority_dead"):
            project.promote_repair("repair-pre-ref", acceptance_cmd=[sys.executable, "-B", cfg["validator"], cfg["project_db"]])

    def test_03_direct_promotion_refused_before_git_commit(self) -> None:
        """A direct promoter call cannot advance an integrated receiver's Git ref after STOP."""
        proj_dir, cfg, promo, project, _protect = self._init_project("crash-bypass")
        alice = cli._read_key(Path(cfg["keys_dir"]) / "alice.key")
        owner = cli._read_key(Path(cfg["keys_dir"]) / "owner.key")

        claim = {
            "project_id": project.id,
            "assignment_id": "repair-bypass",
            "deliverable_id": "invoice-feature",
            "worker_member": "bob",
            "basis": "invoice_v2",
            "allowed_paths": ["app/price.py"],
            "action": "repair_assignment",
        }
        project.assign_repair("repair-bypass", "invoice-feature", "bob", "invoice_v2", cli._sig(alice, claim), allowed_paths=["app/price.py"])
        st = promo.prepare("repair-bypass")
        (Path(st["workspace"]) / "app" / "price.py").write_text("def total(qty):\n    return qty * 11\n")

        # Owner issues STOP first
        stop_claim = {"project_id": project.id, "action": "issue_stop", "reason": "stop before bypass", "expected_epoch": 1}
        project.issue_stop("stop before bypass", cli._sig(owner, stop_claim), expected_epoch=1)

        prior = promo.accepted()
        from foundation.promotion import PromotionRefused
        with self.assertRaisesRegex(PromotionRefused, "final_gate_required"):
            promo.promote("repair-bypass", acceptance_cmd=[sys.executable, "-B", cfg["validator"], cfg["project_db"]], allow_prefixes=("app/price.py",))
        self.assertEqual(promo.accepted(), prior)
        with self.assertRaisesRegex(ProjectRefused, "old_authority_dead"):
            project.promote_repair("repair-bypass", acceptance_cmd=[sys.executable, "-B", cfg["validator"], cfg["project_db"]])

    def test_04_real_sigkill_child_processes_at_pre_and_post_cas_boundaries(self) -> None:
        """Spawns real child processes killed with SIGKILL (kill -9) at pre-ref and post-ref boundaries."""
        # Case A: Real SIGKILL after git update-ref
        proj_a, cfg_a, promo_a, project_a, protect_a = self._init_project("sigkill-post-ref")
        alice_a = cli._read_key(Path(cfg_a["keys_dir"]) / "alice.key")
        owner_a = cli._read_key(Path(cfg_a["keys_dir"]) / "owner.key")
        claim_a = {
            "project_id": project_a.id,
            "assignment_id": "repair-sigkill-post",
            "deliverable_id": "invoice-feature",
            "worker_member": "bob",
            "basis": "invoice_v2",
            "allowed_paths": ["app/price.py"],
            "action": "repair_assignment",
        }
        project_a.assign_repair("repair-sigkill-post", "invoice-feature", "bob", "invoice_v2", cli._sig(alice_a, claim_a), allowed_paths=["app/price.py"])
        st_a = promo_a.prepare("repair-sigkill-post")
        (Path(st_a["workspace"]) / "app" / "price.py").write_text("def total(qty):\n    return qty * 11\n")
        old_head_a = promo_a.accepted()

        child_code_post = (
            f"import sys, functools; from pathlib import Path; sys.path.insert(0, {str(BASE)!r}); "
            f"import openline_cli as cli; cfg = cli._load_config(Path({str(proj_a)!r})); "
            f"promo, project, _ = cli._build_engines(cfg, 65534); orig = promo.promote; "
            f"promo.promote = functools.partial(orig, fail_after_ref='SIGKILL'); "
            f"project.promote_repair('repair-sigkill-post', acceptance_cmd=[sys.executable, '-B', cfg['validator'], cfg['project_db']])"
        )
        proc_post = subprocess.run([sys.executable, "-c", child_code_post], capture_output=True, text=True)
        self.assertEqual(proc_post.returncode, -9)
        new_head_a = promo_a.accepted()
        self.assertNotEqual(old_head_a, new_head_a)

        # Issue STOP after real SIGKILL, then reconcile
        stop_claim_a = {"project_id": project_a.id, "action": "issue_stop", "reason": "stop after sigkill post", "expected_epoch": 1}
        project_a.issue_stop("stop after sigkill post", cli._sig(owner_a, stop_claim_a), expected_epoch=1)
        rec_a = protect_a.reconcile("repair-sigkill-post")
        self.assertEqual(rec_a["verdict"], "ACCEPTED")
        self.assertEqual(continuity_audit(Path(cfg_a["project_db"]))["assessment"], "NO_RECORDED_STALE_DEPENDENCY_FOUND")

        # Case B: Real SIGKILL before git update-ref
        proj_b, cfg_b, promo_b, project_b, protect_b = self._init_project("sigkill-pre-ref")
        alice_b = cli._read_key(Path(cfg_b["keys_dir"]) / "alice.key")
        owner_b = cli._read_key(Path(cfg_b["keys_dir"]) / "owner.key")
        claim_b = {
            "project_id": project_b.id,
            "assignment_id": "repair-sigkill-pre",
            "deliverable_id": "invoice-feature",
            "worker_member": "bob",
            "basis": "invoice_v2",
            "allowed_paths": ["app/price.py"],
            "action": "repair_assignment",
        }
        project_b.assign_repair("repair-sigkill-pre", "invoice-feature", "bob", "invoice_v2", cli._sig(alice_b, claim_b), allowed_paths=["app/price.py"])
        st_b = promo_b.prepare("repair-sigkill-pre")
        (Path(st_b["workspace"]) / "app" / "price.py").write_text("def total(qty):\n    return qty * 11\n")
        old_head_b = promo_b.accepted()

        child_code_pre = (
            f"import sys, functools; from pathlib import Path; sys.path.insert(0, {str(BASE)!r}); "
            f"import openline_cli as cli; cfg = cli._load_config(Path({str(proj_b)!r})); "
            f"promo, project, _ = cli._build_engines(cfg, 65534); orig = promo.promote; "
            f"promo.promote = functools.partial(orig, fail_before_ref='SIGKILL'); "
            f"project.promote_repair('repair-sigkill-pre', acceptance_cmd=[sys.executable, '-B', cfg['validator'], cfg['project_db']])"
        )
        proc_pre = subprocess.run([sys.executable, "-c", child_code_pre], capture_output=True, text=True)
        self.assertEqual(proc_pre.returncode, -9)
        self.assertEqual(promo_b.accepted(), old_head_b)

        stop_claim_b = {"project_id": project_b.id, "action": "issue_stop", "reason": "stop after sigkill pre", "expected_epoch": 1}
        project_b.issue_stop("stop after sigkill pre", cli._sig(owner_b, stop_claim_b), expected_epoch=1)
        rec_b = protect_b.reconcile("repair-sigkill-pre")
        self.assertEqual(rec_b["verdict"], "STOPPED")
        self.assertEqual(promo_b.accepted(), old_head_b)



    def test_05_post_crash_contract_change_and_member_revocation_reconcile_cleanly(self) -> None:
        """Post-crash member revocation + subsequent contract change (v2 -> v3) settle the v2 Git commit while keeping deliverable REOPEN for v3."""
        proj_dir, cfg, promo, project, protect = self._init_project("crash-post-contract")
        alice = cli._read_key(Path(cfg["keys_dir"]) / "alice.key")
        owner = cli._read_key(Path(cfg["keys_dir"]) / "owner.key")

        claim = {
            "project_id": project.id,
            "assignment_id": "repair-v2-crash",
            "deliverable_id": "invoice-feature",
            "worker_member": "bob",
            "basis": "invoice_v2",
            "allowed_paths": ["app/price.py"],
            "action": "repair_assignment",
        }
        project.assign_repair("repair-v2-crash", "invoice-feature", "bob", "invoice_v2", cli._sig(alice, claim), allowed_paths=["app/price.py"])
        project.propose_memory("mem-v2-crash", "invoice-feature", "bob", "invoice_v2", "a" * 64, "diag v2", "lesson v2", assignment_id="repair-v2-crash")
        st = promo.prepare("repair-v2-crash")
        (Path(st["workspace"]) / "app" / "price.py").write_text("def total(qty):\n    return qty * 11\n")

        orig_promote = promo.promote

        @functools.wraps(orig_promote)
        def crash_after_ref(*a, **kw):
            kw["fail_after_ref"] = True
            return orig_promote(*a, **kw)

        promo.promote = crash_after_ref
        with self.assertRaisesRegex(RuntimeError, "injected_crash_after_ref_cas"):
            project.promote_repair("repair-v2-crash", acceptance_cmd=[sys.executable, "-B", cfg["validator"], cfg["project_db"]])
        promo.promote = orig_promote

        # After the crash (where Git CAS for v2 already succeeded), owner revokes bob, changes contract to invoice_v3, and issues STOP
        rev_claim = {"project_id": project.id, "member_id": "bob", "action": "revoke_member"}
        project.revoke_member("bob", cli._sig(owner, rev_claim))
        chg_claim = {"project_id": project.id, "dependency": "invoice_v2", "contract": "invoice_v3", "action": "change_dependency"}
        project.change_dependency("invoice_v2", "invoice_v3", cli._sig(owner, chg_claim))
        stop_claim = {"project_id": project.id, "action": "issue_stop", "reason": "stop after contract v3", "expected_epoch": 1}
        project.issue_stop("stop after contract v3", cli._sig(owner, stop_claim), expected_epoch=1)

        # Reconcile settles repair-v2-crash as COMMITTED (since its Git CAS happened before revoke/v3/STOP),
        # rebinds invoice_v1 -> invoice_v2 as of commit_seq, and preserves standing='REOPEN' for invoice_v3!
        rec_out = protect.reconcile("repair-v2-crash")
        self.assertEqual(rec_out["verdict"], "ACCEPTED")
        self.assertEqual(project.resolve_repair("repair-v2-crash", promo.accepted()), "ALREADY_RECORDED")
        snap = project.snapshot()
        self.assertEqual(snap["assignments"], [("repair-v2-crash", "COMMITTED", promo.accepted())])
        deliverable_map = {d[0]: d for d in snap["deliverables"]}
        self.assertEqual(deliverable_map["invoice-feature"][2], "REOPEN")
        self.assertEqual(deliverable_map["invoice-feature"][3], promo.accepted())
        with closing(sqlite3.connect(cfg["project_db"])) as db:
            mem_status = db.execute("SELECT status, superseded_by FROM earned_memory WHERE memory_id='mem-v2-crash'").fetchone()
        self.assertEqual(mem_status, ("QUESTIONED", "invoice_v3"))


if __name__ == "__main__":
    unittest.main()
