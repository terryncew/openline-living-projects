"""
Regression suite for Argon Outsider Experiment (OPENLINE_ARGON_OUTSIDER_001) Phase 3 improvements:
- F-01: ReceiverGuard & LocalEffectStore strict amount validation (reject bool True/False, NaN/Inf, and missing amount when max_amount is set).
- F-02: ProjectLedger.propose_memory assignment scope binding and settled-memory immutability (prevent cross-worker IDOR poisoning and overwriting INHERITED/QUARANTINED/QUESTIONED memories).
- F-03: ProjectLedger.record_graph_claim downgrade protection (prevent unsigned/advisory or other-member overwrites of CRYPTOGRAPHICALLY_BOUND claims).
- F-04: MCP server strict integer validation on `threshold` in `openline_watchdog_record` and `openline_watchdog_status`.
- F-05: Subprocess pipe cleanup in `mcp_test.py` under `-W error::ResourceWarning`.
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

HERE = Path(__file__).resolve().parent
RELEASE_DIR = HERE.parent
sys.path.insert(0, str(RELEASE_DIR))

from engine_loader import load_engines  # noqa: E402
load_engines()

import openline_cli as cli  # noqa: E402
from project import ProjectRefused  # noqa: E402
from foundation.effects import LocalEffectStore, Principal, EffectDenied  # noqa: E402
from openline_guard import ReceiverGuard, SigningIdentity, GuardRefused, verify_receipt_offline  # noqa: E402


class TestArgonOutsiderImprovements(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="openline-argon-fixes-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_f01_receiver_guard_and_effect_store_reject_bool_nan_and_missing_capped_amount(self) -> None:
        # 1. ReceiverGuard tests
        db_path = self.tmp / "guard.sqlite"
        with closing(sqlite3.connect(db_path)) as db:
            db.execute("CREATE TABLE ledger(id TEXT PRIMARY KEY, val INTEGER)")
            db.commit()
        issuer = SigningIdentity()
        worker = SigningIdentity()
        guard = ReceiverGuard(db_path)
        guard.register_issuer(issuer.public)
        grant = issuer.issue_grant(
            worker.public, task_id="t-amt", operation="disburse", max_amount=100, allowed_targets=["row-1"]
        )

        # 1a. Boolean True / False rejected
        for bad_val in (True, False, float("nan"), float("inf"), -10, 0):
            req = worker.sign_request(grant, operation="disburse", target_id="row-1", payload={"amount": bad_val})
            with self.assertRaises(GuardRefused) as ctx:
                guard.execute(
                    grant=grant, request=req,
                    fn=lambda db, p: db.execute("INSERT INTO ledger VALUES ('row-1', 1)"),
                    target_table="ledger", target_pk_col="id", amount_field="amount",
                )
            self.assertEqual(ctx.exception.reason, "invalid_amount")
            ver = verify_receipt_offline(ctx.exception.receipt, pinned_receiver_pub=guard.receiver_public)
            self.assertEqual(ver["status"], "REFUSED")

        # 1b. Missing amount key when grant specifies max_amount -> refused
        req_missing = worker.sign_request(grant, operation="disburse", target_id="row-1", payload={"other_amount": 99999})
        with self.assertRaises(GuardRefused) as ctx2:
            guard.execute(
                grant=grant, request=req_missing,
                fn=lambda db, p: db.execute("INSERT INTO ledger VALUES ('row-1', 99999)"),
                target_table="ledger", target_pk_col="id", amount_field="amount",
            )
        self.assertEqual(ctx2.exception.reason, "amount_required_for_capped_grant")

        # 2. LocalEffectStore tests
        eff_path = self.tmp / "effects.sqlite"
        with closing(sqlite3.connect(eff_path)) as db:
            db.execute("CREATE TABLE items(id TEXT PRIMARY KEY, v INTEGER)")
            db.commit()
        store = LocalEffectStore(eff_path)
        buyer = Principal()
        w_prin = Principal()
        store.register_buyer(buyer.public)

        # Boolean True rejected
        del_bool = buyer.delegate(w_prin.public, task_id="eff-bool", mode="execute", expires=9999999999, max_amount=50)
        req_bool = w_prin.request(del_bool, task_id="eff-bool", payload={"amount": True}, mode="execute")
        with self.assertRaises(EffectDenied) as ectx:
            store.apply(
                delegation=del_bool, request=req_bool, task_id="eff-bool", payload={"amount": True},
                effect=lambda db: db.execute("INSERT INTO items VALUES ('i1', 1)"), observe=lambda db: True,
            )
        self.assertEqual(str(ectx.exception), "invalid_amount")

        # Missing amount when max_amount is set -> rejected
        del_omit = buyer.delegate(w_prin.public, task_id="eff-omit", mode="execute", expires=9999999999, max_amount=50)
        req_omit = w_prin.request(del_omit, task_id="eff-omit", payload={" sneaky_amount": 5000}, mode="execute")
        with self.assertRaises(EffectDenied) as ectx2:
            store.apply(
                delegation=del_omit, request=req_omit, task_id="eff-omit", payload={" sneaky_amount": 5000},
                effect=lambda db: db.execute("INSERT INTO items VALUES ('i2', 5000)"), observe=lambda db: True,
            )
        self.assertEqual(str(ectx2.exception), "delegation_amount_required")

    def test_f02_propose_memory_prevents_cross_worker_poisoning_and_settled_overwrite(self) -> None:
        proj_dir = self.tmp / "proj_mem"
        cli.cmd_init(SimpleNamespace(dir=str(proj_dir), project_id="p-mem", workers="alice,bob", validator=None, worker_uid=65534))
        cfg = cli._load_config(proj_dir)
        promo, project, protect = cli._build_engines(cfg, 65534)

        cli.cmd_assign(SimpleNamespace(
            dir=str(proj_dir), worker_uid=65534, assignment="rep-alice", deliverable="invoice-feature",
            worker="alice", basis="invoice_v2", allowed_paths="app/price.py", as_member=None, signature=None,
        ))
        cli.cmd_prepare(SimpleNamespace(
            dir=str(proj_dir), worker_uid=65534, assignment="rep-alice",
            propose_memory="mem-alice-1", diagnosis="alice diag", lesson="alice lesson",
        ))

        # 1. Bob (different worker) cannot attach a poisoned memory to Alice's assignment 'rep-alice'
        with self.assertRaises(ProjectRefused) as ctx1:
            project.propose_memory(
                "mem-bob-poison", "invoice-feature", "bob", "invoice_v2",
                "ab" * 32, "poison", "poison", assignment_id="rep-alice",
            )
        self.assertEqual(str(ctx1.exception), "memory_assignment_scope_mismatch")

        # 2. Bob cannot overwrite Alice's candidate memory 'mem-alice-1'
        with self.assertRaises(ProjectRefused) as ctx2:
            project.propose_memory(
                "mem-alice-1", "invoice-feature", "bob", "invoice_v2",
                "ab" * 32, "overwrite", "overwrite", assignment_id=None,
            )
        self.assertEqual(str(ctx2.exception), "candidate_memory_owned_by_different_worker_or_assignment")

        # 3. Promote Alice's repair so 'mem-alice-1' becomes INHERITED
        ws = Path(cfg["promotion_dir"]) / "task-rep-alice" / "candidate" / "app" / "price.py"
        ws.write_text("def total(qty):\n    return qty * 11\n")
        out = protect.intercept("rep-alice")
        self.assertEqual(out["verdict"], "ACCEPTED")
        inherited = project.inherit_memory("invoice-feature")["inherited_verified"]
        self.assertEqual(len(inherited), 1)
        self.assertEqual(inherited[0]["memory_id"], "mem-alice-1")

        # 4. Neither Alice nor Bob can overwrite the settled INHERITED memory 'mem-alice-1' back to CANDIDATE
        with self.assertRaises(ProjectRefused) as ctx3:
            project.propose_memory(
                "mem-alice-1", "invoice-feature", "alice", "invoice_v2",
                "cd" * 32, "wipe", "wipe", assignment_id=None,
            )
        self.assertEqual(str(ctx3.exception), "settled_memory_cannot_be_overwritten")

    def test_f03_claim_graph_prevents_untrusted_or_cross_member_downgrade_of_bound_claim(self) -> None:
        proj_dir = self.tmp / "proj_claim"
        cli.cmd_init(SimpleNamespace(dir=str(proj_dir), project_id="p-claim", workers="alice,bob", validator=None, worker_uid=65534))
        cfg = cli._load_config(proj_dir)
        _promo, project, _protect = cli._build_engines(cfg, 65534)

        # Alice records a cryptographically bound claim 'c-bound'
        cli.cmd_graph(SimpleNamespace(
            dir=str(proj_dir), worker_uid=65534, add_claim="c-bound",
            subject="invoice-feature", predicate="verified_by", object="alice_v1",
            signer="alice", signature=None, sign_local=True, changed=[],
        ))

        # 1. Unsigned / advisory attempt to overwrite 'c-bound' is refused
        with self.assertRaises(ProjectRefused) as ctx1:
            project.record_graph_claim("c-bound", "invoice-feature", "verified_by", "spoofed", signer_id=None, signature_hex=None)
        self.assertEqual(str(ctx1.exception), "bound_claim_cannot_be_overwritten_by_untrusted_or_other_signer")

        # 2. Bob attempting to overwrite Alice's bound claim 'c-bound' is refused
        bob_key = cli._read_key(Path(cfg["keys_dir"]) / "bob.key")
        bob_env = {
            "project_id": project.id, "claim_id": "c-bound", "subject": "invoice-feature",
            "predicate": "verified_by", "object": "bob_takeover", "signer_id": "bob", "action": "graph_claim",
        }
        with self.assertRaises(ProjectRefused) as ctx2:
            project.record_graph_claim(
                "c-bound", "invoice-feature", "verified_by", "bob_takeover",
                signer_id="bob", signature_hex=cli._sig(bob_key, bob_env),
            )
        self.assertEqual(str(ctx2.exception), "bound_claim_cannot_be_overwritten_by_untrusted_or_other_signer")

        # 3. Alice (original signer) CAN legitimately update her own bound claim with a valid signature
        alice_key = cli._read_key(Path(cfg["keys_dir"]) / "alice.key")
        alice_env = {
            "project_id": project.id, "claim_id": "c-bound", "subject": "invoice-feature",
            "predicate": "verified_by", "object": "alice_v2", "signer_id": "alice", "action": "graph_claim",
        }
        updated = project.record_graph_claim(
            "c-bound", "invoice-feature", "verified_by", "alice_v2",
            signer_id="alice", signature_hex=cli._sig(alice_key, alice_env),
        )
        self.assertEqual(updated["trust_status"], "CRYPTOGRAPHICALLY_BOUND")
        self.assertEqual(updated["object"], "alice_v2")

    def test_f04_f05_mcp_threshold_strict_type_and_zero_resource_warnings(self) -> None:
        proj_dir = self.tmp / "proj_mcp"
        cli_script = str(RELEASE_DIR / "openline_cli.py")
        subprocess.run(["python3", cli_script, "init", "--dir", str(proj_dir)], check=True, capture_output=True)

        # Call openline_watchdog_record with boolean threshold=True and string threshold="3"
        reqs = "\n".join([
            json.dumps({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {
                    "name": "openline_watchdog_record",
                    "arguments": {
                        "deliverable": "invoice-feature", "basis": "invoice_v2",
                        "worker": "alice", "attempt": "a1", "threshold": True,
                    },
                },
            }),
            json.dumps({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {
                    "name": "openline_watchdog_status",
                    "arguments": {
                        "deliverable": "invoice-feature", "basis": "invoice_v2", "threshold": "3",
                    },
                },
            }),
        ]) + "\n"
        r = subprocess.run(
            ["python3", "-W", "error::ResourceWarning", cli_script, "mcp", "--dir", str(proj_dir)],
            input=reqs, text=True, capture_output=True, check=True,
        )
        lines = [json.loads(l) for l in r.stdout.strip().splitlines()]
        self.assertTrue(lines[0]["result"]["isError"])
        self.assertIn("threshold must be an integer", lines[0]["result"]["content"][0]["text"])
        self.assertTrue(lines[1]["result"]["isError"])
        self.assertIn("threshold must be an integer", lines[1]["result"]["content"][0]["text"])

        # Run mcp_test.py under -W error::ResourceWarning
        mcp_test_dir = self.tmp / "mcp_test_run"
        r_test = subprocess.run(
            ["python3", "-W", "error::ResourceWarning", str(RELEASE_DIR / "mcp_test.py"), "--dir", str(mcp_test_dir)],
            text=True, capture_output=True,
        )
        self.assertEqual(r_test.returncode, 0, r_test.stderr)


if __name__ == "__main__":
    unittest.main()
