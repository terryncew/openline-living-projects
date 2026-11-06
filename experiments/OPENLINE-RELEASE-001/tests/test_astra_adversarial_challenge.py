"""Astra Red-Team Challenge Regression Suite — Deep Adversarial Attacks Across OpenLine Engines.

Covers:
1. Forged or rolled-back stop_state in ProjectLedger and ReceiverGuard (S1).
2. Event-log payload rewriting, deletion, and forged assignment_standing.commit_seq (S2 & S3).
3. Malformed capabilities: boolean expires (isinstance(True, int) trap), string allowed_targets
   substring-match trap, non-dict request payloads, and omitted target in LocalEffectStore.
4. Contradictory, expired, reordered, duplicated, and missing evidence across ReceiverGuard,
   LocalEffectStore, and Agent Hunt simulation.
5. Multi-agent succession under mid-task revocation + pre-ref and post-ref crash recovery.
"""
from __future__ import annotations

import functools
import io
import json
import shutil
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing, redirect_stdout
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
RELEASE_DIR = HERE.parent
REPO_ROOT = RELEASE_DIR.parents[1]
if str(RELEASE_DIR) not in sys.path:
    sys.path.insert(0, str(RELEASE_DIR))
if str(REPO_ROOT / "experiments" / "AGENT-HUNT-001") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "experiments" / "AGENT-HUNT-001"))

from engine_loader import load_engines  # noqa: E402
load_engines()

import openline_cli as cli  # noqa: E402
from foundation.effects import EffectDenied, LocalEffectStore, Principal  # noqa: E402
from openline_guard import GuardRefused, ReceiverGuard, SigningIdentity, VerificationError  # noqa: E402
from project import ProjectRefused  # noqa: E402
from protect import ProtectError, verify_receipt  # noqa: E402
import hunt as agent_hunt  # noqa: E402


class TestAstraAdversarialChallenge(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="openline-astra-adv-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _init_project(self, name: str):
        proj_dir = self.tmp / name
        with redirect_stdout(io.StringIO()):
            rc = cli.cmd_init(SimpleNamespace(
                dir=str(proj_dir), project_id=f"p-{name}",
                workers="alice,bob,carol", validator=None, worker_uid=65534,
            ))
        self.assertEqual(rc, 0)
        cfg = cli._load_config(proj_dir)
        promo, project, protect = cli._build_engines(cfg, 65534)
        return proj_dir, cfg, promo, project, protect

    def test_01_unsigned_stop_state_forged_or_rolled_back_in_sqlite_fails_closed(self) -> None:
        """S1: Direct SQLite forgery or rollback of stop_state / ol_guard_stop_state fails closed."""
        _proj_dir, cfg, _promo, project, _protect = self._init_project("s1-stop-tamper")
        alice = cli._read_key(Path(cfg["keys_dir"]) / "alice.key")
        owner = cli._read_key(Path(cfg["keys_dir"]) / "owner.key")

        # 1a. Forge a STOP directly in stop_state without an owner-signed KILL_SWITCH_STOPPED event
        with closing(sqlite3.connect(cfg["project_db"])) as db:
            db.execute("UPDATE stop_state SET stopped=1, stop_seq=99, reason='forged' WHERE id=1")
            db.commit()
        with self.assertRaisesRegex(ProjectRefused, "authority_unavailable_fail_closed"):
            project.read_stop_state()
        claim = {
            "project_id": project.id, "assignment_id": "rep-1", "deliverable_id": "invoice-feature",
            "worker_member": "bob", "basis": "invoice_v2", "allowed_paths": ["app/price.py"],
            "action": "repair_assignment",
        }
        with self.assertRaisesRegex(ProjectRefused, "authority_unavailable_fail_closed"):
            project.assign_repair("rep-1", "invoice-feature", "bob", "invoice_v2", cli._sig(alice, claim), allowed_paths=["app/price.py"])

        # Restore initial stop_state, issue a legitimate owner-signed STOP, then attempt SQLite rollback to stopped=0, stop_seq=0
        with closing(sqlite3.connect(cfg["project_db"])) as db:
            db.execute("UPDATE stop_state SET stopped=0, epoch=1, stop_seq=0, clear_seq=0, reason='init' WHERE id=1")
            db.commit()
        stop_claim = {"project_id": project.id, "action": "issue_stop", "reason": "real_stop", "expected_epoch": 1}
        project.issue_stop("real_stop", cli._sig(owner, stop_claim), expected_epoch=1)
        self.assertTrue(project.read_stop_state()["stopped"])

        with closing(sqlite3.connect(cfg["project_db"])) as db:
            db.execute("UPDATE stop_state SET stopped=0, epoch=1, stop_seq=0, clear_seq=0, reason='init' WHERE id=1")
            db.commit()
        with self.assertRaisesRegex(ProjectRefused, "authority_unavailable_fail_closed"):
            project.read_stop_state()

        # 1b. Same check on ReceiverGuard.ol_guard_stop_state
        g_db = self.tmp / "guard_s1.sqlite"
        with closing(sqlite3.connect(g_db)) as db:
            db.execute("CREATE TABLE items(id TEXT PRIMARY KEY, val INTEGER)")
            db.commit()
        g_owner = SigningIdentity()
        g_worker = SigningIdentity()
        guard = ReceiverGuard(g_db)
        guard.register_issuer(g_owner.public)
        with closing(sqlite3.connect(guard.control_db_path)) as cdb:
            cdb.execute("UPDATE ol_guard_stop_state SET stopped=1, stop_seq=77, reason='forged' WHERE id=1")
            cdb.commit()
        with self.assertRaisesRegex(ValueError, "authority_unavailable_fail_closed"):
            guard.read_stop_state()

    def test_02_event_log_payload_rewrite_deletion_or_forged_commit_seq_detected(self) -> None:
        """S2 & S3: Event payload rewriting, event deletion, or forged commit_seq in assignment_standing are refused."""
        _proj_dir, cfg, promo, project, protect = self._init_project("s2-event-tamper")
        alice = cli._read_key(Path(cfg["keys_dir"]) / "alice.key")
        owner = cli._read_key(Path(cfg["keys_dir"]) / "owner.key")

        claim = {
            "project_id": project.id, "assignment_id": "rep-s2", "deliverable_id": "invoice-feature",
            "worker_member": "bob", "basis": "invoice_v2", "allowed_paths": ["app/price.py"],
            "action": "repair_assignment",
        }
        project.assign_repair("rep-s2", "invoice-feature", "bob", "invoice_v2", cli._sig(alice, claim), allowed_paths=["app/price.py"])
        st = promo.prepare("rep-s2")
        (Path(st["workspace"]) / "app" / "price.py").write_text("def total(qty):\n    return qty * 11\n")
        rec = protect.intercept("rep-s2")
        self.assertEqual(rec["verdict"], "ACCEPTED")

        # Baseline receipt verifies cleanly
        checked = verify_receipt(rec["receipt"], cfg["receiver_pub"], accepted_git=Path(cfg["accepted_git"]), project_db=Path(cfg["project_db"]))
        self.assertTrue(checked["continuity_verified"])

        # Tamper with the KILL_SWITCH_DECISION event payload in project.sqlite -> verify_receipt fails closed!
        with closing(sqlite3.connect(cfg["project_db"])) as db:
            seq = db.execute("SELECT seq FROM events WHERE kind='KILL_SWITCH_DECISION' ORDER BY seq DESC LIMIT 1").fetchone()[0]
            db.execute("UPDATE events SET payload='{\"tampered\": true}' WHERE seq=?", (seq,))
            db.commit()
        with self.assertRaisesRegex(ProtectError, "event_log_tampered"):
            verify_receipt(rec["receipt"], cfg["receiver_pub"], accepted_git=Path(cfg["accepted_git"]), project_db=Path(cfg["project_db"]))

        # S3: Forged commit_seq in assignment_standing without a matching FINAL_GATE commit event cannot bypass STOP
        _proj_dir2, cfg2, promo2, project2, _protect2 = self._init_project("s3-forged-commit-seq")
        alice2 = cli._read_key(Path(cfg2["keys_dir"]) / "alice.key")
        owner2 = cli._read_key(Path(cfg2["keys_dir"]) / "owner.key")
        claim2 = {**claim, "project_id": project2.id}
        project2.assign_repair("rep-s2", "invoice-feature", "bob", "invoice_v2", cli._sig(alice2, claim2), allowed_paths=["app/price.py"])
        st2 = promo2.prepare("rep-s2")
        (Path(st2["workspace"]) / "app" / "price.py").write_text("def total(qty):\n    return qty * 11\n")

        stop_claim2 = {"project_id": project2.id, "action": "issue_stop", "reason": "halt before cas", "expected_epoch": 1}
        project2.issue_stop("halt before cas", cli._sig(owner2, stop_claim2), expected_epoch=1)
        # The receiver API refuses the bypass; a hostile same-UID process can still edit
        # the raw Git ref itself, which is outside the software-only isolation claim.
        from foundation.promotion import PromotionRefused
        with self.assertRaisesRegex(PromotionRefused, "final_gate_required"):
            promo2.promote("rep-s2", acceptance_cmd=[sys.executable, "-B", cfg2["validator"], cfg2["project_db"]], allow_prefixes=("app/price.py",))
        old_head = promo2.accepted()
        import subprocess
        candidate_dir = Path(st2['workspace'])
        subprocess.run(['git', '-C', str(candidate_dir), 'add', '-A'], check=True, capture_output=True)
        subprocess.run(['git', '-C', str(candidate_dir), '-c', 'user.name=Untrusted', '-c', 'user.email=evil@localhost', 'commit', '-m', 'raw-bypass'], check=True, capture_output=True)
        target_head = subprocess.check_output(['git', '-C', str(candidate_dir), 'rev-parse', 'HEAD'], text=True).strip()
        # Deliberately illustrate the known same-UID OS permission breach, not a legitimate API.
        subprocess.run(['git', '--git-dir', str(cfg2['accepted_git']), 'update-ref', 'refs/heads/accepted', target_head, old_head], check=True)
        self.assertEqual(promo2.accepted(), target_head)

        # Attacker writes a fake commit_seq=1 and cas_state='CAS_CONFIRMED' into assignment_standing
        with closing(sqlite3.connect(cfg2["project_db"])) as db:
            db.execute(
                "UPDATE assignment_standing SET commit_seq=1, cas_target_head=?, cas_state='CAS_CONFIRMED' WHERE assignment_id='rep-s2'",
                (target_head,),
            )
            db.commit()
        with self.assertRaisesRegex(ProjectRefused, "promotion_journal_not_confirmed|old_authority_dead"):
            project2.resolve_repair("rep-s2", target_head)

    def test_03_malformed_capabilities_boolean_expires_string_targets_and_omitted_target(self) -> None:
        """Tests boolean expires, string allowed_targets substring trap, non-dict payload, and omitted target in LocalEffectStore."""
        g_db = self.tmp / "guard_caps.sqlite"
        with closing(sqlite3.connect(g_db)) as db:
            db.execute("CREATE TABLE swaps(swap_id TEXT PRIMARY KEY, amount REAL)")
            db.commit()
        issuer = SigningIdentity()
        worker = SigningIdentity()
        guard = ReceiverGuard(g_db)
        guard.register_issuer(issuer.public)

        # 3a. Boolean expires=True in grant must be rejected as grant_expired (not treated as int 1)
        g_bool_exp = issuer.issue_grant(worker.public, task_id="t-bexp", operation="approve", expires=True, allowed_targets=["SWAP-1"])
        r_bool_exp = worker.sign_request(g_bool_exp, operation="approve", target_id="SWAP-1", payload={"amount": 10.0})
        with self.assertRaises(GuardRefused) as ctx1:
            guard.execute(grant=g_bool_exp, request=r_bool_exp, fn=lambda db, p: db.execute("INSERT INTO swaps VALUES ('SWAP-1', 10.0)"), target_table="swaps", target_pk_col="swap_id")
        self.assertEqual(ctx1.exception.reason, "grant_expired")

        # 3b. String allowed_targets="SWAP-123" instead of list must not allow substring match "SWAP-1"
        from openline_guard import sign_envelope
        bad_grant_body = dict(issuer.issue_grant(worker.public, task_id="t-str", operation="approve", allowed_targets=["SWAP-123"])["payload"])
        bad_grant_body["allowed_targets"] = "SWAP-123"
        g_str_targets = sign_envelope(issuer.key, bad_grant_body)
        r_str_targets = worker.sign_request(g_str_targets, operation="approve", target_id="SWAP-1", payload={"amount": 10.0})
        with self.assertRaises(GuardRefused) as ctx2:
            guard.execute(grant=g_str_targets, request=r_str_targets, fn=lambda db, p: db.execute("INSERT INTO swaps VALUES ('SWAP-1', 10.0)"), target_table="swaps", target_pk_col="swap_id")
        self.assertEqual(ctx2.exception.reason, "invalid_allowed_targets")

        # 3c. LocalEffectStore: omitting 'target' from payload when delegation specifies allowed_targets must be refused
        e_db = self.tmp / "effects_caps.sqlite"
        with closing(sqlite3.connect(e_db)) as db:
            db.execute("CREATE TABLE items(id TEXT PRIMARY KEY, amount INTEGER)")
            db.commit()
        store = LocalEffectStore(e_db)
        buyer = Principal()
        w_prin = Principal()
        store.register_buyer(buyer.public)
        deleg = buyer.delegate(w_prin.public, task_id="t-eff-tgt", mode="execute", expires=9999999999, allowed_targets=["item-1"])
        payload_no_target = {"amount": 50}
        req_no_target = w_prin.request(deleg, task_id="t-eff-tgt", mode="execute", payload=payload_no_target)
        with self.assertRaises(EffectDenied) as ctx3:
            store.apply(delegation=deleg, request=req_no_target, task_id="t-eff-tgt", payload=payload_no_target, effect=lambda db: db.execute("INSERT INTO items VALUES ('item-999', 50)"), observe=lambda db: True)
        self.assertEqual(str(ctx3.exception), "delegation_target_not_allowed")

    def test_04_agent_succession_after_mid_task_revocation_and_pre_post_ref_crashes(self) -> None:
        """Multi-agent succession: bob crashes pre-ref + is revoked + STOP issued; carol receives post-STOP grant, crashes post-ref, and reconciles cleanly."""
        _proj_dir, cfg, promo, project, protect = self._init_project("succession-stress")
        alice = cli._read_key(Path(cfg["keys_dir"]) / "alice.key")
        owner = cli._read_key(Path(cfg["keys_dir"]) / "owner.key")

        # 1. Assign bob, inject pre-ref crash, then revoke bob and issue STOP
        c_bob = {
            "project_id": project.id, "assignment_id": "rep-bob", "deliverable_id": "invoice-feature",
            "worker_member": "bob", "basis": "invoice_v2", "allowed_paths": ["app/price.py"],
            "action": "repair_assignment",
        }
        project.assign_repair("rep-bob", "invoice-feature", "bob", "invoice_v2", cli._sig(alice, c_bob), allowed_paths=["app/price.py"])
        st_bob = promo.prepare("rep-bob")
        (Path(st_bob["workspace"]) / "app" / "price.py").write_text("def total(qty):\n    return qty * 11\n")

        orig_promote = promo.promote
        promo.promote = functools.partial(orig_promote, fail_before_ref=True)
        with self.assertRaisesRegex(RuntimeError, "injected_crash_before_ref_cas"):
            project.promote_repair("rep-bob", acceptance_cmd=[sys.executable, "-B", cfg["validator"], cfg["project_db"]])
        promo.promote = orig_promote

        rev_claim = {"project_id": project.id, "member_id": "bob", "action": "revoke_member"}
        project.revoke_member("bob", cli._sig(owner, rev_claim))
        stop_claim = {"project_id": project.id, "action": "issue_stop", "reason": "halt bob", "expected_epoch": 1}
        stop_st = project.issue_stop("halt bob", cli._sig(owner, stop_claim), expected_epoch=1)

        rec_bob = protect.reconcile("rep-bob")
        self.assertEqual(rec_bob["verdict"], "STOPPED")

        # 2. Assign successor carol with explicit post-STOP owner override, inject post-ref crash, then reconcile cleanly
        c_carol = {
            "project_id": project.id, "assignment_id": "rep-carol", "deliverable_id": "invoice-feature",
            "worker_member": "carol", "basis": "invoice_v2", "allowed_paths": ["app/price.py"],
            "action": "repair_assignment",
        }
        override_carol = {
            "project_id": project.id, "assignment_id": "rep-carol", "deliverable_id": "invoice-feature",
            "worker_member": "carol", "basis": "invoice_v2", "allowed_paths": ["app/price.py"],
            "epoch": stop_st["epoch"], "stop_seq": stop_st["stop_seq"], "action": "post_stop_grant",
        }
        project.assign_repair(
            "rep-carol", "invoice-feature", "carol", "invoice_v2",
            cli._sig(alice, c_carol), allowed_paths=["app/price.py"],
            post_stop_owner_signature=cli._sig(owner, override_carol),
        )
        st_carol = promo.prepare("rep-carol")
        (Path(st_carol["workspace"]) / "app" / "price.py").write_text("def total(qty):\n    return qty * 11\n")

        promo.promote = functools.partial(orig_promote, fail_after_ref=True)
        with self.assertRaisesRegex(RuntimeError, "injected_crash_after_ref_cas"):
            project.promote_repair("rep-carol", acceptance_cmd=[sys.executable, "-B", cfg["validator"], cfg["project_db"]])
        promo.promote = orig_promote

        rec_carol = protect.reconcile("rep-carol")
        self.assertEqual(rec_carol["verdict"], "ACCEPTED")
        checked = verify_receipt(rec_carol["receipt"], cfg["receiver_pub"], accepted_git=Path(cfg["accepted_git"]), project_db=Path(cfg["project_db"]))
        self.assertEqual(checked["crypto"], "VERIFIED")
        self.assertTrue(checked["git_verified"])
        self.assertTrue(checked["continuity_verified"])


    def test_05_astra01_legacy_and_unbound_safepromotion_final_gate_enforcement(self) -> None:
        "ASTRA-01: Legacy ProjectLedger/Protect setups, cross-instance unbound SafePromotion, and spoofed final_gate_context cannot bypass final gate."
        import contextlib as _ctx
        from foundation.promotion import SafePromotion, PromotionRefused
        _proj_dir, cfg, promo, project, _protect = self._init_project("astra01-legacy-gate")
        alice = cli._read_key(Path(cfg["keys_dir"]) / "alice.key")
        owner = cli._read_key(Path(cfg["keys_dir"]) / "owner.key")

        claim = {
            "project_id": project.id, "assignment_id": "rep-legacy", "deliverable_id": "invoice-feature",
            "worker_member": "bob", "basis": "invoice_v2", "allowed_paths": ["app/price.py"],
            "action": "repair_assignment",
        }
        project.assign_repair("rep-legacy", "invoice-feature", "bob", "invoice_v2", cli._sig(alice, claim), allowed_paths=["app/price.py"])
        st = promo.prepare("rep-legacy")
        (Path(st["workspace"]) / "app" / "price.py").write_text("def total(qty):\n    return qty * 11\n")

        stop_claim = {"project_id": project.id, "action": "issue_stop", "reason": "stop_legacy", "expected_epoch": 1}
        project.issue_stop("stop_legacy", cli._sig(owner, stop_claim), expected_epoch=1)
        head_before = promo.accepted()

        # 5a. Re-instantiating SafePromotion without require_final_gate=True (as in legacy scripts) still refuses!
        unbound_promo = SafePromotion(Path(cfg["accepted_git"]), Path(cfg["effects_db"]), Path(cfg["promotion_dir"]))
        with self.assertRaisesRegex(PromotionRefused, "final_gate_required"):
            unbound_promo.promote(
                "rep-legacy",
                acceptance_cmd=[sys.executable, "-B", cfg["validator"], cfg["project_db"]],
                allow_prefixes=("app/price.py",),
            )
        self.assertEqual(unbound_promo.accepted(), head_before)

        # 5b. Passing a spoofed dummy final_gate_context lambda without a real ProjectLedger PENDING_CAS reservation is refused before Git CAS!
        res_spoof = unbound_promo.promote(
            "rep-legacy",
            acceptance_cmd=[sys.executable, "-B", cfg["validator"], cfg["project_db"]],
            allow_prefixes=("app/price.py",),
            final_gate_context=lambda _t, _n: _ctx.nullcontext(),
        )
        self.assertEqual(res_spoof["status"], "REFUSED")
        self.assertEqual(res_spoof["reason"], "final_gate_required")
        self.assertEqual(unbound_promo.accepted(), head_before)

    def test_06_astra02_event_chain_tamper_refused_before_git_cas(self) -> None:
        "ASTRA-02: Tampering with events table or deleting KILL_SWITCH_STOPPED is caught at promote_repair ENTRY before Git CAS."
        _proj_dir, cfg, promo, project, _protect = self._init_project("astra02-pre-cas-chain")
        alice = cli._read_key(Path(cfg["keys_dir"]) / "alice.key")

        claim = {
            "project_id": project.id, "assignment_id": "rep-chain", "deliverable_id": "invoice-feature",
            "worker_member": "bob", "basis": "invoice_v2", "allowed_paths": ["app/price.py"],
            "action": "repair_assignment",
        }
        project.assign_repair("rep-chain", "invoice-feature", "bob", "invoice_v2", cli._sig(alice, claim), allowed_paths=["app/price.py"])
        st = promo.prepare("rep-chain")
        (Path(st["workspace"]) / "app" / "price.py").write_text("def total(qty):\n    return qty * 11\n")

        # Tamper with an earlier event in project.sqlite without updating event_hashes
        with closing(sqlite3.connect(cfg["project_db"])) as db:
            db.execute("UPDATE events SET payload='{\"forged\":true}' WHERE kind='MEMBER_JOINED'")
            db.commit()

        head_before = promo.accepted()
        with self.assertRaisesRegex(ProjectRefused, "authority_unavailable_fail_closed"):
            project.promote_repair("rep-chain", acceptance_cmd=[sys.executable, "-B", cfg["validator"], cfg["project_db"]])
        self.assertEqual(promo.accepted(), head_before)

    def test_07_astra03_propose_memory_accept_and_join_enforce_stop_and_revocation(self) -> None:
        "ASTRA-03: propose_memory, accept, and join enforce Kill Switch standing and member revocation."
        _proj_dir, cfg, promo, project, _protect = self._init_project("astra03-stop-mem")
        alice = cli._read_key(Path(cfg["keys_dir"]) / "alice.key")
        owner = cli._read_key(Path(cfg["keys_dir"]) / "owner.key")

        claim = {
            "project_id": project.id, "assignment_id": "rep-pre-stop", "deliverable_id": "invoice-feature",
            "worker_member": "bob", "basis": "invoice_v2", "allowed_paths": ["app/price.py"],
            "action": "repair_assignment",
        }
        project.assign_repair("rep-pre-stop", "invoice-feature", "bob", "invoice_v2", cli._sig(alice, claim), allowed_paths=["app/price.py"])

        # Issue STOP -> propose_memory and accept must fail closed
        stop_claim = {"project_id": project.id, "action": "issue_stop", "reason": "stop_mem", "expected_epoch": 1}
        project.issue_stop("stop_mem", cli._sig(owner, stop_claim), expected_epoch=1)

        with self.assertRaisesRegex(ProjectRefused, "old_authority_dead"):
            project.propose_memory("mem-dead-1", "invoice-feature", "bob", "invoice_v2", "ab" * 32, "diag", "lesson", assignment_id="rep-pre-stop")

        acc_claim = {
            "project_id": project.id, "deliverable_id": "sneak-deliv", "member_id": "alice",
            "accepted_head": promo.accepted(), "dependencies": ["sneak_v1"],
        }
        with self.assertRaisesRegex(ProjectRefused, "stopped_at_epoch_2"):
            project.accept("sneak-deliv", "alice", promo.accepted(), ["sneak_v1"], cli._sig(alice, acc_claim))

        # Even after clear_stop, pre-STOP assignment 'rep-pre-stop' remains old_authority_dead for propose_memory
        clr_claim = {"project_id": project.id, "action": "clear_stop", "reason": "clear_mem", "expected_epoch": 2}
        project.clear_stop("clear_mem", cli._sig(owner, clr_claim), expected_epoch=2)
        with self.assertRaisesRegex(ProjectRefused, "old_authority_dead"):
            project.propose_memory("mem-dead-2", "invoice-feature", "bob", "invoice_v2", "ab" * 32, "diag", "lesson", assignment_id="rep-pre-stop")

        # Revoke bob -> replaying bob's join invitation must fail as member_not_active
        rev_claim = {"project_id": project.id, "member_id": "bob", "action": "revoke_member"}
        project.revoke_member("bob", cli._sig(owner, rev_claim))
        bob_key = cli._read_key(Path(cfg["keys_dir"]) / "bob.key")
        from project import digest as _pdigest
        receipt = {"member": "bob", "environment": "local-init"}
        inv = {
            "project_id": project.id, "member_id": "bob",
            "owner_pub": cli._pub(bob_key), "worker_pub": cli._pub(bob_key),
            "scope": "contribute", "world_digest": _pdigest(receipt),
        }
        with self.assertRaisesRegex(ProjectRefused, "member_not_active"):
            project.join(inv, cli._sig(owner, inv), cli._sig(bob_key, inv), world_receipt=receipt)

    def test_08_astra04_local_effect_store_operation_omission_and_shadow_refused(self) -> None:
        "ASTRA-04: LocalEffectStore refuses omitted or conflicting action/operation fields when delegation scopes operation."
        e_db = self.tmp / "effects_op.sqlite"
        with closing(sqlite3.connect(e_db)) as db:
            db.execute("CREATE TABLE items(id TEXT PRIMARY KEY, amount INTEGER)")
            db.commit()
        store = LocalEffectStore(e_db)
        buyer = Principal()
        worker = Principal()
        store.register_buyer(buyer.public)
        deleg = buyer.delegate(worker.public, task_id="t-op", mode="execute", expires=9999999999, operation="refund_small")

        # Omitted action/operation must fail closed
        p_omit = {"amount": 25}
        r_omit = worker.request(deleg, task_id="t-op", mode="execute", payload=p_omit)
        with self.assertRaisesRegex(EffectDenied, "delegation_operation_mismatch"):
            store.apply(delegation=deleg, request=r_omit, task_id="t-op", payload=p_omit, effect=lambda db: db.execute("INSERT INTO items VALUES ('i1', 25)"), observe=lambda db: True)

        # Conflicting action vs operation keys must fail closed
        p_shadow = {"action": "refund_small", "operation": "wire_transfer", "amount": 25}
        r_shadow = worker.request(deleg, task_id="t-op", mode="execute", payload=p_shadow)
        with self.assertRaisesRegex(EffectDenied, "delegation_operation_mismatch"):
            store.apply(delegation=deleg, request=r_shadow, task_id="t-op", payload=p_shadow, effect=lambda db: db.execute("INSERT INTO items VALUES ('i1', 25)"), observe=lambda db: True)

        # Matching operation succeeds
        p_ok = {"operation": "refund_small", "amount": 25}
        r_ok = worker.request(deleg, task_id="t-op", mode="execute", payload=p_ok)
        out = store.apply(delegation=deleg, request=r_ok, task_id="t-op", payload=p_ok, effect=lambda db: db.execute("INSERT INTO items VALUES ('i1', 25)"), observe=lambda db: True)
        self.assertEqual(out["status"], "COMMITTED")

    def test_09_astra05_receiver_guard_idempotency_auth_and_receipt_chain_integrity(self) -> None:
        "ASTRA-05: ReceiverGuard authenticates grant/request/revocation/stop before ALREADY_COMMITTED and detects receipt/control log tampering."
        from openline_guard import sign_envelope, sha256_hex
        g_db = self.tmp / "guard_a05.sqlite"
        with closing(sqlite3.connect(g_db)) as db:
            db.execute("CREATE TABLE swaps(id TEXT PRIMARY KEY, val INTEGER)")
            db.commit()
        owner = SigningIdentity()
        alice = SigningIdentity()
        mallory = SigningIdentity()
        guard = ReceiverGuard(g_db)
        guard.register_issuer(owner.public)

        g1 = owner.issue_grant(alice.public, task_id="t1", operation="approve", allowed_targets=["S1", "S2"])
        r1 = alice.sign_request(g1, operation="approve", target_id="S1", payload={"v": 1})
        res1 = guard.execute(grant=g1, request=r1, fn=lambda db, p: db.execute("INSERT INTO swaps VALUES ('S1', 1)"), target_table="swaps", target_pk_col="id")
        self.assertEqual(res1["status"], "COMMITTED")

        # 9a. Mallory with unrelated grant g2 forging task_id='t1' in request must be refused as request_grant_binding_mismatch
        g2 = owner.issue_grant(mallory.public, task_id="t2", operation="approve", allowed_targets=["S1"])
        forged_req = sign_envelope(mallory.key, {
            "schema": "openline.guard.request.v1",
            "worker_pub": mallory.public,
            "grant_id": g2["payload"]["grant_id"],
            "grant_sha256": g2["payload_sha256"],
            "task_id": "t1",
            "step_id": "main",
            "operation": "approve",
            "target_id": "S1",
            "payload": {"v": 1},
            "payload_sha256": sha256_hex({"v": 1}),
            "upstream_receipt_sha256": None,
            "requested_at": 1000,
        })
        with self.assertRaises(GuardRefused) as ctx_m:
            guard.execute(grant=g2, request=forged_req, fn=lambda db, p: None, target_table="swaps", target_pk_col="id")
        self.assertEqual(ctx_m.exception.reason, "request_grant_binding_mismatch")

        # 9b. Deleting or tampering with ol_guard_receipts breaks the receipt hash chain and fails closed
        with closing(sqlite3.connect(g_db)) as db:
            db.execute("DELETE FROM ol_guard_receipts WHERE seq=1")
            db.commit()
        r1_second = alice.sign_request(g1, operation="approve", target_id="S2", payload={"v": 2})
        with self.assertRaises(GuardRefused) as ctx_tamper:
            guard.execute(grant=g1, request=r1_second, fn=lambda db, p: db.execute("INSERT INTO swaps VALUES ('S2', 2)"), target_table="swaps", target_pk_col="id")
        self.assertIn(ctx_tamper.exception.reason, ("receipt_log_tampered", "grant_already_consumed"))


if __name__ == "__main__":
    unittest.main()
