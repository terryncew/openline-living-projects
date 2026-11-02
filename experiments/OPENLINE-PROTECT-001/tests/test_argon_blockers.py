"""Adversarial regression tests for Argon release blockers V-01..V-05.

Runs against the real engines (Protect, ProjectLedger, SafePromotion,
LocalEffectStore) with real Git + SQLite fixtures. Fixture keys are
generated fresh per test: a fixture signature must never be mistaken
for a trusted signature, and no fixed seed ships in this file.

Tests that need OS isolation are skipped unless running as root on
Linux with the sandbox utilities present. Skips are reported, never
silently passed.
"""
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

HERE = Path(__file__).resolve().parent
EXP = HERE.parents[1]  # tests/ -> OPENLINE-PROTECT-001 -> experiments/
for _extra in ("SELF-HEALING-ENGINE-001", "SELF-HEALING-PROJECTS-001",
               "OPENLINE-PROTECT-002", "CODEX-B-ISOLATED-REPAIR-001"):
    _path = EXP / _extra
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from protect import (  # noqa: E402
    Protect,
    ProtectError,
    check_receiver_boundary,
    verify_receipt,
)
from project import ProjectLedger, digest  # noqa: E402
from foundation.promotion import SafePromotion  # noqa: E402
from foundation.effects import (  # noqa: E402
    EffectDenied,
    LocalEffectStore,
    Principal,
)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode()


def _pub(key):
    return key.public_key().public_bytes(Encoding.Raw,
                                         PublicFormat.Raw).hex()


def _sig(key, obj):
    return key.sign(_canonical(obj)).hex()


def _git(*args, cwd=None):
    result = subprocess.run(["git", *map(str, args)], cwd=cwd,
                            capture_output=True, text=True)
    if result.returncode:
        raise AssertionError((result.args, result.stdout, result.stderr))
    return result.stdout.strip()


def _validator_script(path: Path, expected: int, needs_bob: bool) -> Path:
    """Trusted fixture-only AST validator (model output never executed)."""
    path.write_text(
        "import ast, sys\n"
        "from pathlib import Path\n"
        "tree = Path('.')\n"
        "price = ast.parse((tree / 'app' / 'price.py').read_text())\n"
        "label_src = (tree / 'app' / 'independent.py').read_text()\n"
        "ns = {}\n"
        "exec(compile(price, 'price.py', 'exec'), ns)\n"
        f"assert ns['total'](2) == {expected}, 'total mismatch'\n"
        "assert 'def label' in label_src\n"
        + ("assert 'upper' in label_src, 'bob contribution missing'\n"
           if needs_bob else "")
    )
    return path


class _Fixture:
    """Real-Git + SQLite project in the broken-v2 REOPEN state."""

    def __init__(self, root: Path, project_id: str = "argon-blockers"):
        self.root = root
        self.accepted = root / "accepted.git"
        _git("init", "--bare", str(self.accepted))
        setup = root / "bootstrap"
        _git("clone", str(self.accepted), str(setup))
        (setup / "app").mkdir()
        (setup / "app" / "price.py").write_text(
            "def total(qty):\n    return 0\n")
        (setup / "app" / "independent.py").write_text(
            "def label(value):\n    return value\n")
        _git("-C", str(setup), "config", "user.name", "Trusted Bootstrap")
        _git("-C", str(setup), "config", "user.email", "boot@local.test")
        _git("-C", str(setup), "add", "app")
        _git("-C", str(setup), "commit", "-qm", "Initial accepted project")
        _git("-C", str(setup), "push", "origin", "HEAD:refs/heads/accepted")
        live_db = root / "effects.sqlite"
        with closing(sqlite3.connect(live_db)) as db:
            db.execute("CREATE TABLE effects(id TEXT PRIMARY KEY, "
                       "value INTEGER)")
            db.commit()
        self.promo = SafePromotion(self.accepted, live_db,
                                   root / "promotion")
        self.owner = Ed25519PrivateKey.generate()
        self.alice = Ed25519PrivateKey.generate()
        self.bob = Ed25519PrivateKey.generate()
        self.project = ProjectLedger(
            root / "project.sqlite", project_id, "Argon blockers",
            _pub(self.owner), promotion=self.promo,
            world_verifier=lambda receipt, invitation:
                receipt.get("member") == invitation.get("member_id"))
        for member, key in (("alice", self.alice), ("bob", self.bob)):
            receipt = {"member": member, "environment": "TEST_ONLY_FAKE"}
            invitation = {"project_id": self.project.id,
                          "member_id": member,
                          "owner_pub": _pub(key), "worker_pub": _pub(key),
                          "scope": "contribute",
                          "world_digest": digest(receipt)}
            joined = self.project.join(invitation, _sig(self.owner, invitation),
                                       _sig(key, invitation),
                                       world_receipt=receipt)
            assert joined == "JOINED", joined
        self._propose("alice-initial",
                      {"app/price.py": "def total(qty):\n    return qty * 10\n"},
                      20, needs_bob=False)
        claim = {"project_id": self.project.id,
                 "deliverable_id": "invoice-feature", "member_id": "alice",
                 "accepted_head": self.promo.accepted(),
                 "dependencies": ["invoice_v1"]}
        self.project.accept("invoice-feature", "alice",
                            self.promo.accepted(), ["invoice_v1"],
                            _sig(self.alice, claim))
        self._propose("bob-initial",
                      {"app/independent.py":
                       "def label(value):\n    return value.upper()\n"},
                      20)
        claim = {"project_id": self.project.id,
                 "deliverable_id": "independent-formatter",
                 "member_id": "bob",
                 "accepted_head": self.promo.accepted(),
                 "dependencies": ["format_v1"]}
        self.project.accept("independent-formatter", "bob",
                            self.promo.accepted(), ["format_v1"],
                            _sig(self.bob, claim))
        change = {"project_id": self.project.id, "dependency": "invoice_v1",
                  "contract": "invoice_v2", "action": "change_dependency"}
        affected = self.project.change_dependency(
            "invoice_v1", "invoice_v2", _sig(self.owner, change))
        assert affected == ["invoice-feature"], affected
        self.validator = _validator_script(root / "validator_v2.py", 22, True)
        self.receiver_key = Ed25519PrivateKey.generate()
        self.protect = Protect(
            self.project, self.receiver_key, root / "incidents",
            acceptance_cmd=(sys.executable, "-B", str(self.validator)))
        self.receiver_pub = _pub(self.receiver_key)

    def _propose(self, identity, changes, amount, *, needs_bob=True):
        state = self.promo.prepare(identity)
        for file, text in changes.items():
            (Path(state["workspace"]) / file).write_text(text)
        validator = _validator_script(
            self.root / f"validator_{identity}.py", amount, needs_bob)
        result = self.promo.promote(
            identity,
            acceptance_cmd=(sys.executable, "-B", str(validator)))
        assert result["status"] == "PROMOTED", result
        return result

    def assign(self, task, worker="bob", basis="invoice_v2"):
        claim = {"project_id": self.project.id, "assignment_id": task,
                 "deliverable_id": "invoice-feature",
                 "worker_member": worker, "basis": basis,
                 "allowed_paths": ["app/price.py"],
                 "action": "repair_assignment"}
        self.project.assign_repair(task, "invoice-feature", worker, basis,
                                   _sig(self.alice, claim),
                                   allowed_paths=["app/price.py"])

    def head(self):
        return self.promo.accepted()

    def git_file(self, ref_path):
        return _git("--git-dir", str(self.accepted), "show",
                    f"refs/heads/accepted:{ref_path}")

    def assignment_state(self, task):
        with closing(sqlite3.connect(self.project.db_path)) as db:
            row = db.execute("SELECT state FROM assignments WHERE id=?",
                             (task,)).fetchone()
        return row[0] if row else None

    def set_assignment_state(self, task, state):
        with closing(sqlite3.connect(self.project.db_path)) as db:
            db.execute("UPDATE assignments SET state=? WHERE id=?",
                       (state, task))
            db.commit()


def _verify_err(receipt, pub, **kwargs):
    try:
        verify_receipt(receipt, pub, **kwargs)
    except ProtectError as exc:
        return str(exc)
    return None


class ArgonBlockerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.fix = _Fixture(Path(self._tmp.name) / "case")

    def tearDown(self):
        self._tmp.cleanup()

    # ---- V-01: strict live ref + project/assignment checks ----
    def test_v01_accept_verifies_at_exact_head(self):
        fix = self.fix
        fix.assign("repair-v2")
        state = fix.promo.prepare("repair-v2")
        (Path(state["workspace"]) / "app" / "price.py").write_text(
            "def total(qty):\n    return qty * 11\n")
        out = fix.protect.intercept("repair-v2")
        self.assertEqual(out["verdict"], "ACCEPTED")
        checked = verify_receipt(out["receipt"], fix.receiver_pub,
                                 accepted_git=fix.accepted,
                                 project_db=fix.project.db_path)
        self.assertEqual(checked["crypto"], "VERIFIED")
        self.assertTrue(checked["git_verified"])
        self.assertTrue(checked["continuity_verified"])

    def test_v01_later_commit_fails_strict_head_check(self):
        fix = self.fix
        fix.assign("repair-v2")
        state = fix.promo.prepare("repair-v2")
        (Path(state["workspace"]) / "app" / "price.py").write_text(
            "def total(qty):\n    return qty * 11\n")
        out = fix.protect.intercept("repair-v2")
        self.assertEqual(out["verdict"], "ACCEPTED")
        # Advance the ref WITHOUT the receiver (simulates a later,
        # non-admitted commit): strict verification must fail closed.
        clone = Path(self._tmp.name) / "later"
        _git("clone", "-b", "accepted", str(fix.accepted), str(clone))
        _git("-C", str(clone), "config", "user.name", "Later")
        _git("-C", str(clone), "config", "user.email", "later@local")
        (clone / "app" / "price.py").write_text(
            "def total(qty):\n    return qty * 11\n# later\n")
        _git("-C", str(clone), "add", "app")
        _git("-C", str(clone), "commit", "-qm", "later commit")
        _git("-C", str(clone), "push", "origin", "HEAD:refs/heads/accepted")
        self.assertNotEqual(fix.head(), out["receipt"]["payload"]
                            ["accepted_ref_after"])
        err = _verify_err(out["receipt"], fix.receiver_pub,
                          accepted_git=fix.accepted)
        self.assertEqual(err, "accepted_git_ref_mismatch")
        # Crypto-only verification still passes: strictness is opt-in
        # via the live arguments, not a signature break.
        checked = verify_receipt(out["receipt"], fix.receiver_pub)
        self.assertEqual(checked["crypto"], "VERIFIED")

    def test_v01_receipt_for_other_project_rejected(self):
        fix = self.fix
        # The target DB holds an ASSIGNED (not COMMITTED) repair-v2,
        # so the assignment exists and the checks below isolate the
        # project-identity and assignment-state rules.
        fix.assign("repair-v2")
        other_root = Path(self._tmp.name) / "other"
        other = _Fixture(other_root, project_id="other-project")
        # Same receiver key signs in the other project: the receipt is
        # cryptographically genuine but belongs to another project.
        other.protect.signer = fix.receiver_key
        other.assign("repair-v2")
        state = other.promo.prepare("repair-v2")
        (Path(state["workspace"]) / "app" / "price.py").write_text(
            "def total(qty):\n    return qty * 11\n")
        out = other.protect.intercept("repair-v2")
        self.assertEqual(out["verdict"], "ACCEPTED")
        checked = verify_receipt(out["receipt"], fix.receiver_pub,
                                 accepted_git=other.accepted,
                                 project_db=other.project.db_path)
        self.assertEqual(checked["crypto"], "VERIFIED")
        # Isolated project check (no live-git argument): the project
        # identity mismatch must fire even though the assignment id
        # exists in the target DB.
        err = _verify_err(out["receipt"], fix.receiver_pub,
                          project_db=fix.project.db_path)
        self.assertEqual(err, "receipt_project_id_mismatch")
        # Same project id, cross-fixture receipt: the assignment
        # exists but is not COMMITTED, so the state rule fires.
        same_root = Path(self._tmp.name) / "same"
        same = _Fixture(same_root)
        same.protect.signer = fix.receiver_key
        same.assign("repair-v2")
        state = same.promo.prepare("repair-v2")
        (Path(state["workspace"]) / "app" / "price.py").write_text(
            "def total(qty):\n    return qty * 11\n")
        out2 = same.protect.intercept("repair-v2")
        self.assertEqual(out2["verdict"], "ACCEPTED")
        err2 = _verify_err(out2["receipt"], fix.receiver_pub,
                           project_db=fix.project.db_path)
        self.assertEqual(err2, "receipt_assignment_not_committed")

    def test_v01_assignment_state_cross_check(self):
        fix = self.fix
        fix.assign("repair-v2")
        state = fix.promo.prepare("repair-v2")
        (Path(state["workspace"]) / "app" / "price.py").write_text(
            "def total(qty):\n    return qty * 11\n")
        out = fix.protect.intercept("repair-v2")
        self.assertEqual(out["verdict"], "ACCEPTED")
        self.assertEqual(fix.assignment_state("repair-v2"), "COMMITTED")
        # Corrupt the ledger state behind the receipt: verification
        # must catch the receipt/ledger disagreement.
        fix.set_assignment_state("repair-v2", "ASSIGNED")
        err = _verify_err(out["receipt"], fix.receiver_pub,
                          accepted_git=fix.accepted,
                          project_db=fix.project.db_path)
        self.assertEqual(err, "receipt_assignment_not_committed")
        fix.set_assignment_state("repair-v2", "COMMITTED")
        checked = verify_receipt(out["receipt"], fix.receiver_pub,
                                 accepted_git=fix.accepted,
                                 project_db=fix.project.db_path)
        self.assertEqual(checked["crypto"], "VERIFIED")

    def test_v01_stopped_receipt_state_rules(self):
        fix = self.fix
        fix.assign("rogue-v2")
        state = fix.promo.prepare("rogue-v2")
        (Path(state["workspace"]) / "app" / "independent.py").write_text(
            "def label(value):\n    return value.upper() + \"!\"\n")
        out = fix.protect.intercept("rogue-v2")
        self.assertEqual(out["verdict"], "STOPPED")
        self.assertEqual(fix.assignment_state("rogue-v2"), "ASSIGNED")
        checked = verify_receipt(out["receipt"], fix.receiver_pub,
                                 accepted_git=fix.accepted,
                                 project_db=fix.project.db_path)
        self.assertEqual(checked["crypto"], "VERIFIED")
        fix.set_assignment_state("rogue-v2", "BOGUS_STATE")
        err = _verify_err(out["receipt"], fix.receiver_pub,
                          accepted_git=fix.accepted,
                          project_db=fix.project.db_path)
        self.assertEqual(err, "receipt_assignment_status_invalid")

    def test_v01_ghost_unknown_receipt_needs_crypto_only(self):
        # A ghost UNKNOWN receipt is genuinely signed by the receiver
        # (falsifier path) but names no real assignment. Crypto-only
        # verification passes; the project cross-check fails closed.
        fix = self.fix
        from types import SimpleNamespace
        fake = SimpleNamespace(outcome="REFUSED_SCOPE",
                               changes=("app/independent.py",),
                               details="worker claims refusal")
        out = fix.protect.intercept("ghost-task", worker_result=fake)
        self.assertEqual(out["verdict"], "UNKNOWN_RECONCILIATION_REQUIRED")
        checked = verify_receipt(out["receipt"], fix.receiver_pub)
        self.assertEqual(checked["crypto"], "VERIFIED")
        err = _verify_err(out["receipt"], fix.receiver_pub,
                          project_db=fix.project.db_path)
        self.assertEqual(err, "receipt_assignment_not_found")

    # ---- V-03: pre-CAS UNKNOWN task cleanup ----
    def test_v03_gate_error_unknown_frees_prepared_slot_for_retry(self):
        # V-03, corrected scope: cleanup runs ONLY when the real gate
        # evaluated and failed pre-CAS. A gate exception is a genuine
        # pre-CAS UNKNOWN: the slot is freed and a successor retries.
        fix = self.fix
        fix.assign("stuck-v2")
        fix.promo.prepare("stuck-v2")
        task_dir = fix.promo.state_dir / "task-stuck-v2"
        self.assertTrue(task_dir.is_dir())
        real_gate = fix.project.promote_repair

        def _boom(*args, **kwargs):
            raise RuntimeError("injected_gate_exception")

        fix.project.promote_repair = _boom
        try:
            out = fix.protect.intercept("stuck-v2")
        finally:
            fix.project.promote_repair = real_gate
        self.assertEqual(out["verdict"], "UNKNOWN_RECONCILIATION_REQUIRED")
        self.assertIn("project_gate_exception", out["receipt"]["payload"]["reason"])
        self.assertFalse(task_dir.exists())
        # Successor retry on the same assignment now prepares cleanly.
        state = fix.promo.prepare("stuck-v2")
        (Path(state["workspace"]) / "app" / "price.py").write_text(
            "def total(qty):\n    return qty * 11\n")
        out = fix.protect.intercept("stuck-v2")
        self.assertEqual(out["verdict"], "ACCEPTED")

    def test_v03_falsifier_unknown_preserves_prepared_candidate(self):
        # #152 invariant, restored: an unverified worker report executes
        # no admission decision, so its UNKNOWN must NOT clear the
        # still-authorized prepared candidate.
        fix = self.fix
        fix.assign("stuck-v2")
        state = fix.promo.prepare("stuck-v2")
        workspace = Path(state["workspace"])
        from types import SimpleNamespace
        fake = SimpleNamespace(outcome="REFUSED_SCOPE",
                               changes=("app/price.py",), details="")
        out = fix.protect.intercept("stuck-v2", worker_result=fake)
        self.assertEqual(out["verdict"], "UNKNOWN_RECONCILIATION_REQUIRED")
        self.assertTrue(workspace.is_dir())
        # The same prepared candidate continues: a rogue edit through
        # the real gate is STOPPED, then a clean successor is ACCEPTED.
        (workspace / "app" / "price.py").write_text(
            "def total(qty):\n    return qty * 11\n")
        out = fix.protect.intercept("stuck-v2")
        self.assertEqual(out["verdict"], "ACCEPTED")

    def test_v03_post_cas_unknown_does_not_clean(self):
        # UNKNOWN with a moved ref (post-CAS) must NOT free the slot:
        # that state goes through reconcile, never cleanup.
        fix = self.fix
        fix.assign("repair-v2")
        state = fix.promo.prepare("repair-v2")
        (Path(state["workspace"]) / "app" / "price.py").write_text(
            "def total(qty):\n    return qty * 11\n")
        out = fix.protect.intercept("repair-v2")
        self.assertEqual(out["verdict"], "ACCEPTED")
        head_before = fix.head()
        receipt = fix.protect._emit_receipt(
            assignment_id="repair-v2", candidate_paths=[],
            candidate_inventory="TEST_POST_CAS",
            verdict="UNKNOWN_RECONCILIATION_REQUIRED",
            explanation="test-post-cas", start="0" * 40, now=head_before)
        self.assertEqual(receipt["verdict"],
                         "UNKNOWN_RECONCILIATION_REQUIRED")
        self.assertEqual(fix.head(), head_before)
        # The post-CAS state is undisturbed: reconcile still recovers
        # the original promotion instead of re-deciding it.
        recovered = fix.protect.reconcile("repair-v2")
        self.assertEqual(recovered["verdict"], "ACCEPTED")

    # ---- V-04: pinned private keyfile ----
    def _write_key_file(self, path: Path, key, mode: int):
        from cryptography.hazmat.primitives.serialization import (
            Encoding as _Enc,
            NoEncryption as _NoEnc,
            PrivateFormat as _Priv,
        )
        seed = key.private_bytes(_Enc.Raw, _Priv.Raw, _NoEnc())
        path.write_text(seed.hex() + "\n")
        os.chmod(path, mode)
        return path

    def test_v04_cli_reconcile_pinned_keyfile(self):
        import cli
        fix = self.fix
        fix.assign("repair-v2")
        state = fix.promo.prepare("repair-v2")
        (Path(state["workspace"]) / "app" / "price.py").write_text(
            "def total(qty):\n    return qty * 11\n")
        out = fix.protect.intercept("repair-v2")
        self.assertEqual(out["verdict"], "ACCEPTED")
        key_file = Path(self._tmp.name) / "receiver.key"
        self._write_key_file(key_file, fix.receiver_key, 0o600)
        result = cli.main(["reconcile",
                           "--project-dir", str(fix.root),
                           "--assignment", "repair-v2",
                           "--receiver-key-file", str(key_file),
                           "--pinned-receiver-public-key",
                           fix.receiver_pub])
        self.assertEqual(result, 0)

    def test_v04_cli_refuses_nonprivate_keyfile(self):
        import cli
        fix = self.fix
        for mode, name in ((0o644, "world_readable"), (0o640, "group_readable")):
            key_file = Path(self._tmp.name) / f"receiver_{name}.key"
            self._write_key_file(key_file, fix.receiver_key, mode)
            result = cli.main(["reconcile",
                               "--project-dir", str(fix.root),
                               "--assignment", "repair-v2",
                               "--receiver-key-file", str(key_file),
                               "--pinned-receiver-public-key",
                               fix.receiver_pub])
            self.assertEqual(result, 2, name)
        link = Path(self._tmp.name) / "receiver_link.key"
        good = Path(self._tmp.name) / "receiver_good.key"
        self._write_key_file(good, fix.receiver_key, 0o600)
        try:
            link.symlink_to(good)
        except OSError:
            self.skipTest("symlinks unavailable")
        result = cli.main(["reconcile",
                           "--project-dir", str(fix.root),
                           "--assignment", "repair-v2",
                           "--receiver-key-file", str(link),
                           "--pinned-receiver-public-key",
                           fix.receiver_pub])
        self.assertEqual(result, 2)

    def test_v04_cli_refuses_key_mismatch_and_old_arg(self):
        import cli
        fix = self.fix
        other_key = Ed25519PrivateKey.generate()
        key_file = Path(self._tmp.name) / "receiver_other.key"
        self._write_key_file(key_file, other_key, 0o600)
        result = cli.main(["reconcile",
                           "--project-dir", str(fix.root),
                           "--assignment", "repair-v2",
                           "--receiver-key-file", str(key_file),
                           "--pinned-receiver-public-key",
                           fix.receiver_pub])
        self.assertEqual(result, 2)
        with self.assertRaises(SystemExit) as ctx:
            cli.main(["reconcile",
                      "--project-dir", str(fix.root),
                      "--assignment", "repair-v2",
                      "--receiver-seed-hex", "00" * 32])
        self.assertEqual(ctx.exception.code, 2)

    # ---- V-02: receiver boundary ----
    def test_v02_boundary_unit_rules(self):
        root = Path(self._tmp.name) / "boundary"
        root.mkdir()
        receiver_uid = os.getuid()
        worker_uid = 65534
        good = root / "good.txt"
        good.write_text("x")
        os.chmod(good, 0o600)
        self.assertEqual(check_receiver_boundary(
            [("good", good)], receiver_uid=receiver_uid,
            worker_uid=worker_uid), [])
        self.assertEqual(check_receiver_boundary(
            [("good", good)], receiver_uid=receiver_uid,
            worker_uid=None), ["worker_uid_undeclared"])
        self.assertEqual(check_receiver_boundary(
            [("good", good)], receiver_uid=receiver_uid,
            worker_uid=receiver_uid), ["worker_uid_equals_receiver_uid"])
        world = root / "world.txt"
        world.write_text("x")
        os.chmod(world, 0o666)
        reasons = check_receiver_boundary(
            [("world", world)], receiver_uid=receiver_uid,
            worker_uid=worker_uid)
        self.assertIn("world_world_writable", reasons)
        link = root / "link.txt"
        link.symlink_to(good)
        reasons = check_receiver_boundary(
            [("link", link)], receiver_uid=receiver_uid,
            worker_uid=worker_uid)
        self.assertIn("link_symlink_forbidden", reasons)
        if receiver_uid == 0:
            grouped = root / "grouped.txt"
            grouped.write_text("x")
            os.chown(grouped, 0, 65534)
            os.chmod(grouped, 0o660)
            reasons = check_receiver_boundary(
                [("grouped", grouped)], receiver_uid=0,
                worker_uid=65534)
            self.assertIn("grouped_group_writable_by_worker", reasons)
            other_group = root / "other_group.txt"
            other_group.write_text("x")
            os.chown(other_group, 0, 0)
            os.chmod(other_group, 0o660)
            self.assertEqual(check_receiver_boundary(
                [("other_group", other_group)], receiver_uid=0,
                worker_uid=65534), [])

    def test_v02_intercept_refuses_without_boundary(self):
        fix = self.fix
        gated = Protect(fix.project, fix.receiver_key,
                        fix.root / "incidents_gated",
                        acceptance_cmd=(sys.executable, "-B",
                                        str(fix.validator)),
                        worker_uid=os.getuid())
        fix.assign("repair-v2")
        ref_before = fix.head()
        out = gated.intercept("repair-v2")
        self.assertEqual(out["verdict"], "UNKNOWN_RECONCILIATION_REQUIRED")
        self.assertIn("receiver_boundary_unavailable",
                      out["receipt"]["payload"]["reason"])
        self.assertEqual(fix.head(), ref_before)
        # Fixing the boundary (distinct worker UID) lets the same
        # assignment proceed: refusal does not poison the assignment.
        gated.worker_uid = 65534
        state = fix.promo.prepare("repair-v2")
        (Path(state["workspace"]) / "app" / "price.py").write_text(
            "def total(qty):\n    return qty * 11\n")
        out = gated.intercept("repair-v2")
        self.assertEqual(out["verdict"], "ACCEPTED")

    def test_v02_boundary_refusal_preserves_prepared_candidate(self):
        # Same rule as the falsifier path: a boundary failure executes
        # no admission decision, so a prepared candidate must survive
        # it and remain acceptable once the boundary is fixed.
        fix = self.fix
        gated = Protect(fix.project, fix.receiver_key,
                        fix.root / "incidents_gated3",
                        acceptance_cmd=(sys.executable, "-B",
                                        str(fix.validator)),
                        worker_uid=os.getuid())
        fix.assign("repair-v2")
        state = fix.promo.prepare("repair-v2")
        workspace = Path(state["workspace"])
        out = gated.intercept("repair-v2")
        self.assertEqual(out["verdict"], "UNKNOWN_RECONCILIATION_REQUIRED")
        self.assertTrue(workspace.is_dir())
        gated.worker_uid = 65534
        (workspace / "app" / "price.py").write_text(
            "def total(qty):\n    return qty * 11\n")
        out = gated.intercept("repair-v2")
        self.assertEqual(out["verdict"], "ACCEPTED")

    def test_v02_world_writable_receiver_path_refuses(self):
        fix = self.fix
        os.chmod(fix.project.db_path, 0o666)
        try:
            gated = Protect(fix.project, fix.receiver_key,
                            fix.root / "incidents_gated2",
                            acceptance_cmd=(sys.executable, "-B",
                                            str(fix.validator)),
                            worker_uid=65534)
            fix.assign("repair-v2")
            out = gated.intercept("repair-v2")
            self.assertEqual(out["verdict"],
                             "UNKNOWN_RECONCILIATION_REQUIRED")
            self.assertIn("project_db_world_writable",
                          out["receipt"]["payload"]["reason"])
        finally:
            os.chmod(fix.project.db_path, 0o600)

    @unittest.skipUnless(os.getuid() == 0 and shutil.which("setpriv")
                         and shutil.which("unshare"),
                         "OS isolation tests need root + setpriv/unshare")
    def test_v02_worker_cannot_write_receiver_paths(self):
        # The worker runs as nobody inside a chroot with no receiver
        # path mounted: every direct-write attempt must fail, while
        # the worker can still write its own tree (control).
        import hashlib
        import resource
        import signal
        import time as _time
        from isolated_agent import (
            IsolationRefused,
            RestrictedAgentWorkspace,
            WorkerResult,
            _files,
            path_allowed,
        )

        class _ContainerSandbox(RestrictedAgentWorkspace):
            """Container adaptation (see #155 driver, same finding).

            The vendor orders setpriv-then-unshare, which fails inside
            a nested container user namespace (uid_map write denied).
            This subclass unshares FIRST as root (map written by root
            via newuidmap), then drops to the worker UID inside the
            chroot. Vendor files are untouched; only launch order
            differs, and the worker ends up strictly less privileged.
            """

            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                os.chmod(self.root, 0o755)
                os.chmod(self.root / "tmp", 0o755)
                os.chmod(self.root / "usr", 0o755)

            def run(self, argv, *, timeout_s=60):
                if self._ran:
                    raise IsolationRefused("one_run_per_worker_context")
                self._ran = True
                if not argv or not all(isinstance(x, str) for x in argv):
                    raise IsolationRefused("agent_argv_required")
                if argv[0] not in ("/usr/bin/python3",) \
                        or not Path(argv[0]).is_file():
                    raise IsolationRefused("agent_runtime_not_reviewed")
                if not 1 <= timeout_s <= 120:
                    raise IsolationRefused("invalid_runtime_budget")
                shell = (
                    "root=\"$1\"; shift\n"
                    "mount --make-rprivate /\n"
                    "mount --bind /usr \"$root/usr\"\n"
                    "mount -o remount,bind,ro \"$root/usr\"\n"
                    "cd /\n"
                    f"exec chroot \"$root\" /usr/bin/setpriv "
                    f"--reuid={self.uid} --regid={self.gid} "
                    "--clear-groups --no-new-privs "
                    "/usr/bin/env -i PATH=/usr/bin:/bin HOME=/work "
                    "TMPDIR=/tmp PYTHONDONTWRITEBYTECODE=1 "
                    "PYTHONNOUSERSITE=1 /usr/bin/sh -c "
                    "'cd /work; exec \"$@\"' runner \"$@\"\n"
                )
                command = [shutil.which("unshare"),
                           "--user", "--map-users=0,0,65536",
                           "--map-groups=0,0,65536",
                           "--mount", "--net", "--pid", "--fork",
                           "/bin/sh", "-eu", "-c", shell, "sandbox",
                           str(self.root), *argv]
                started = _time.monotonic()

                def limits():
                    resource.setrlimit(
                        resource.RLIMIT_CPU,
                        (min(120, timeout_s + 3), min(120, timeout_s + 3)))
                    resource.setrlimit(resource.RLIMIT_FSIZE,
                                       (3_000_000, 3_000_000))

                proc = subprocess.Popen(
                    command, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                         "LANG": "C.UTF-8"},
                    preexec_fn=limits, start_new_session=True,
                    close_fds=True)
                try:
                    stdout, stderr = proc.communicate(timeout=timeout_s)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.communicate()
                    return WorkerResult("TIMEOUT", 124, (),
                                        round(_time.monotonic() - started, 3),
                                        "", "", "worker_process_group_killed")
                p = type("Completed", (),
                         {"returncode": proc.returncode,
                          "stdout": stdout, "stderr": stderr})()
                elapsed = round(_time.monotonic() - started, 3)
                try:
                    after = _files(self.root / "work")
                    changed = tuple(sorted(
                        k for k in set(self.before) | set(after)
                        if self.before.get(k) != after.get(k)))
                    if any(not path_allowed(k, self.allowed)
                           for k in changed):
                        return WorkerResult(
                            "REFUSED_SCOPE", p.returncode, changed, elapsed,
                            hashlib.sha256(p.stdout).hexdigest(),
                            hashlib.sha256(p.stderr).hexdigest(),
                            "not_owner_allowed")
                    if not changed:
                        outcome = "NO_CHANGE" if p.returncode == 0 \
                            else "WORKER_FAILED"
                    else:
                        outcome = "CANDIDATE" if p.returncode == 0 \
                            else "WORKER_FAILED"
                except IsolationRefused as exc:
                    return WorkerResult(
                        "REFUSED_CONTENT", p.returncode, (), elapsed,
                        hashlib.sha256(p.stdout).hexdigest(),
                        hashlib.sha256(p.stderr).hexdigest(), str(exc))
                return WorkerResult(
                    outcome, p.returncode, changed, elapsed,
                    hashlib.sha256(p.stdout).hexdigest(),
                    hashlib.sha256(p.stderr).hexdigest(),
                    p.stderr.decode("utf-8", "replace")[-300:]
                    if p.returncode else "",
                    tuple((k, after[k]) for k in changed if k in after))

        for _path, _entry in (("/etc/subuid", "root:0:65536"),
                              ("/etc/subgid", "root:0:65536")):
            try:
                _existing = Path(_path).read_text() \
                    if Path(_path).exists() else ""
            except OSError:
                _existing = ""
            if _entry not in _existing.splitlines():
                with open(_path, "a") as _handle:
                    _handle.write(_entry + "\n")
        fix = self.fix
        receiver_before = {
            label: Path(path).read_bytes() if Path(path).is_file() else None
            for label, path in (
                ("accepted_git_config", fix.accepted / "config"),
                ("project_db", fix.project.db_path),
                ("effects_db", fix.root / "effects.sqlite"))
        }
        probe_src = Path(self._tmp.name) / "probe_src" / "app"
        probe_src.mkdir(parents=True)
        targets = [str(fix.accepted), fix.project.db_path,
                   str(fix.root / "effects.sqlite")]
        (probe_src / "try_write.py").write_text(
            "import sys\n"
            "targets = sys.argv[1:]\n"
            "failed = 0\n"
            "for target in targets:\n"
            "    try:\n"
            "        open(target, 'a').write('rogue')\n"
            "        print('WRITE_UNEXPECTED:' + target)\n"
            "    except OSError:\n"
            "        failed += 1\n"
            "open('/work/app/result.txt', 'w').write(\n"
            "    f'WRITE_BLOCKED:{failed}/{len(targets)}')\n")
        sandbox = _ContainerSandbox(
            probe_src.parent,
            allowed_paths=("app/try_write.py", "app/result.txt"),
            task_note="v02 probe (scripted, not model)")
        try:
            run = sandbox.run(["/usr/bin/python3", "/work/app/try_write.py",
                               *targets], timeout_s=30)
            verdict = (sandbox.root / "work" / "app" / "result.txt"
                       ).read_text()
        finally:
            sandbox.close()
        self.assertEqual(run.outcome, "CANDIDATE")
        self.assertEqual(verdict, f"WRITE_BLOCKED:{len(targets)}/{len(targets)}")
        for label, before in receiver_before.items():
            path = {"accepted_git_config": fix.accepted / "config",
                    "project_db": fix.project.db_path,
                    "effects_db": fix.root / "effects.sqlite"}[label]
            self.assertEqual(Path(path).read_bytes(), before, label)

    def test_v04_cli_flat_layout_fallback(self):
        # The CLI reconcile path must work from a flat release layout
        # (promotion.py/project.py next to cli.py), not only from the
        # experiments/ tree.
        fix = self.fix
        fix.assign("repair-v2")
        state = fix.promo.prepare("repair-v2")
        (Path(state["workspace"]) / "app" / "price.py").write_text(
            "def total(qty):\n    return qty * 11\n")
        out = fix.protect.intercept("repair-v2")
        self.assertEqual(out["verdict"], "ACCEPTED")
        flat = Path(self._tmp.name) / "flat"
        flat.mkdir()
        for name, src in (("protect.py", HERE.parent / "protect.py"),
                          ("cli.py", HERE.parent / "cli.py"),
                          ("promotion.py",
                           EXP / "SELF-HEALING-ENGINE-001" / "foundation"
                           / "promotion.py"),
                          ("project.py",
                           EXP / "SELF-HEALING-PROJECTS-001" / "project.py"),
                          ("continuity.py",
                           EXP / "OPENLINE-PROTECT-002" / "continuity.py"),
                          ("effects.py",
                           EXP / "SELF-HEALING-ENGINE-001" / "foundation"
                           / "effects.py")):
            shutil.copy(src, flat / name)
        key_file = Path(self._tmp.name) / "flat_receiver.key"
        self._write_key_file(key_file, fix.receiver_key, 0o600)
        proc = subprocess.run(
            [sys.executable, str(flat / "cli.py"), "reconcile",
             "--project-dir", str(fix.root),
             "--assignment", "repair-v2",
             "--receiver-key-file", str(key_file),
             "--pinned-receiver-public-key", fix.receiver_pub],
            capture_output=True, text=True, cwd=flat, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr[-500:])
        self.assertIn('"verdict": "ACCEPTED"', proc.stdout)

    # ---- V-05: effect binding ----
    def _effect_fixture(self):
        store = LocalEffectStore(Path(self._tmp.name) / "eff.sqlite")
        buyer = Principal()
        worker = Principal()
        store.register_buyer(buyer.public)
        task_id = "effect-101"
        payload = {"invoice": "fixture-101", "amount": 22}
        delegation = buyer.delegate(worker.public, task_id=task_id,
                                    mode="execute",
                                    expires=int(__import__("time").time()) + 300)
        request = worker.request(delegation, task_id=task_id,
                                 payload=payload, mode="execute")
        return store, buyer, worker, task_id, payload, delegation, request

    def _apply(self, store, delegation, request, task_id, payload,
               bind=None, live_state=None):
        def effect(db):
            db.execute("INSERT INTO application_effects VALUES (?,?)",
                       ("fixture-101", 22))

        def observe(db):
            return db.execute(
                "SELECT value FROM application_effects WHERE id=?",
                ("fixture-101",)).fetchone() == (22,)
        with closing(sqlite3.connect(store.path)) as db:
            db.execute("CREATE TABLE IF NOT EXISTS application_effects"
                       "(id TEXT PRIMARY KEY, value INTEGER)")
            db.commit()
        return store.apply(delegation=delegation, request=request,
                           task_id=task_id, payload=payload, effect=effect,
                           observe=observe, bind=bind,
                           live_state=live_state)

    def test_v05_bound_apply_records_binding(self):
        store, buyer, worker, task_id, payload, delegation, request = \
            self._effect_fixture()
        bind = {"accepted_head": "a" * 40, "project": "p1",
                "dependency": "invoice_v2", "assignment_state": "COMMITTED"}
        live = {"accepted_head": "a" * 40, "project": "p1",
                "dependency": "invoice_v2", "assignment_state": "COMMITTED"}
        out = self._apply(store, delegation, request, task_id, payload,
                          bind=bind, live_state=lambda: dict(live))
        self.assertEqual(out["status"], "COMMITTED")
        claim = LocalEffectStore.verify_receipt(out["receipt"],
                                                store.receiver_public)
        self.assertEqual(claim["binding"], bind)

    def test_v05_stale_binding_refused(self):
        store, buyer, worker, task_id, payload, delegation, request = \
            self._effect_fixture()
        bind = {"accepted_head": "a" * 40, "project": "p1",
                "dependency": "invoice_v2"}
        live = {"accepted_head": "b" * 40, "project": "p1",
                "dependency": "invoice_v2"}
        with self.assertRaises(EffectDenied) as ctx:
            self._apply(store, delegation, request, task_id, payload,
                        bind=bind, live_state=lambda: dict(live))
        self.assertEqual(str(ctx.exception), "effect_binding_stale")
        with closing(sqlite3.connect(store.path)) as db:
            rows = db.execute("SELECT COUNT(*) FROM task_effects").fetchone()[0]
        self.assertEqual(rows, 0)

    def test_v05_revoked_delegation_refused(self):
        store, buyer, worker, task_id, payload, delegation, request = \
            self._effect_fixture()
        store.revoke(delegation)
        with self.assertRaises(EffectDenied) as ctx:
            self._apply(store, delegation, request, task_id, payload)
        self.assertEqual(str(ctx.exception), "grant_revoked")

    def test_v05_concurrent_double_apply_idempotent(self):
        store, buyer, worker, task_id, payload, delegation, request = \
            self._effect_fixture()
        first = self._apply(store, delegation, request, task_id, payload)
        second = self._apply(store, delegation, request, task_id, payload)
        self.assertEqual(first["status"], "COMMITTED")
        self.assertEqual(second["status"], "ALREADY_COMMITTED")
        self.assertEqual(second["receipt"], first["receipt"])
        with closing(sqlite3.connect(store.path)) as db:
            rows = db.execute("SELECT COUNT(*) FROM task_effects").fetchone()[0]
        self.assertEqual(rows, 1)

    def test_v05_recovery_returns_original_binding(self):
        store, buyer, worker, task_id, payload, delegation, request = \
            self._effect_fixture()
        bind = {"accepted_head": "a" * 40, "project": "p1"}
        live = {"accepted_head": "a" * 40, "project": "p1"}
        first = self._apply(store, delegation, request, task_id, payload,
                            bind=bind, live_state=lambda: dict(live))
        # Live state advances legitimately afterwards; recovery must
        # still return the ORIGINAL observation, not re-bind it.
        recover_delegation = buyer.delegate(
            worker.public, task_id=task_id, mode="recover",
            expires=int(__import__("time").time()) + 300)
        recover_request = worker.request(
            recover_delegation, task_id=task_id, payload=payload,
            mode="recover")
        out = store.recover(delegation=recover_delegation,
                            request=recover_request, task_id=task_id,
                            payload=payload)
        self.assertEqual(out["status"], "RECOVERED")
        self.assertEqual(out["receipt"], first["receipt"])
        self.assertEqual(out["receipt"]["body"]["binding"], bind)

    def test_v05_absent_binding_recorded_explicitly(self):
        store, buyer, worker, task_id, payload, delegation, request = \
            self._effect_fixture()
        out = self._apply(store, delegation, request, task_id, payload)
        self.assertEqual(out["status"], "COMMITTED")
        claim = LocalEffectStore.verify_receipt(out["receipt"],
                                                store.receiver_public)
        self.assertIsNone(claim["binding"])


if __name__ == "__main__":
    unittest.main()
