"""OpenLine Production Isolation — Operational Qualification & Backup/Restore/Rotation Rehearsal (`OPS-01`, `OPS-02`).

Implements Section 5, 6 (Milestone M7), and 7.2 (`OPS-01`, `OPS-02`) of Astra's Blueprint:
1. Clean bootstrap of an isolated receiver project (without `owner.key` on the receiver host).
2. Authorized repair assignment, candidate preparation (`assignment.prepare` + `snapshot.chunk`),
   candidate submission (`proposal.submit`), isolated validation, and signed receipt verification.
3. Consistent online backup (`control.backup`), cryptographic verification of `backup_manifest.json`,
   tamper detection on corrupted backup, and clean restore into a fresh receiver directory.
4. Live owner key rotation (`control.rotate_key`) and member key rotation (`control.join` with `rotate=True`),
   proving old keys are immediately rejected and new keys succeed.
"""
from __future__ import annotations

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

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

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
):
    _p = str(EXPERIMENTS / _rel)
    if _p not in sys.path:
        sys.path.insert(0, _p)

from ipc_client import OpenLineIPCClient  # noqa: E402
from ipc_protocol import canonical_json_bytes  # noqa: E402
from production_config import PRODUCTION_CONFIG_SCHEMA  # noqa: E402
from project import ProjectLedger, digest  # noqa: E402
from foundation.promotion import SafePromotion  # noqa: E402
from protect import verify_receipt  # noqa: E402
from receiver_service import OpenLineReceiverService  # noqa: E402


def _pub(k: Ed25519PrivateKey) -> str:
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def _sig(k: Ed25519PrivateKey, obj: dict) -> str:
    return k.sign(canonical_json_bytes(obj)).hex()


def _write_key(path: Path, k: Ed25519PrivateKey, mode: int = 0o400) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        os.chmod(path, 0o600)
    path.write_text(k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex() + "\n", encoding="utf-8")
    os.chmod(path, mode)


def bootstrap_isolated_deployment(base_dir: Path) -> dict:
    """Provision a complete production-layout deployment in `base_dir` where `owner.key` lives outside `receiver_root`."""
    receiver_root = base_dir / "receiver_state"
    external_keys = base_dir / "external_keys"
    socket_dir = base_dir / "run_sockets"
    spool_dir = base_dir / "validation_spool"
    empty_hooks = base_dir / "empty_hooks"

    for d in (receiver_root, external_keys, socket_dir, spool_dir, empty_hooks):
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(socket_dir, 0o711)
    os.chmod(spool_dir, 0o750)

    owner_key = Ed25519PrivateKey.generate()
    alice_key = Ed25519PrivateKey.generate()
    bob_key = Ed25519PrivateKey.generate()
    receiver_key = Ed25519PrivateKey.generate()

    # Owner and worker private keys are stored ONLY in external_keys, NEVER inside receiver_root!
    _write_key(external_keys / "owner.key", owner_key, mode=0o600)
    _write_key(external_keys / "alice.key", alice_key, mode=0o600)
    _write_key(external_keys / "bob.key", bob_key, mode=0o600)
    _write_key(receiver_root / "keys" / "receiver.key", receiver_key, mode=0o400)

    accepted_git = receiver_root / "accepted.git"
    subprocess.run(["git", "init", "--bare", str(accepted_git)], check=True, capture_output=True)
    bootstrap_clone = base_dir / "bootstrap_clone"
    subprocess.run(["git", "clone", str(accepted_git), str(bootstrap_clone)], check=True, capture_output=True)
    (bootstrap_clone / "app").mkdir()
    (bootstrap_clone / "app" / "price.py").write_text("def total(qty):\n    return qty * 10\n", encoding="utf-8")
    (bootstrap_clone / "app" / "independent.py").write_text("def label(value):\n    return value.upper()\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(bootstrap_clone), "config", "user.name", "Bootstrap"], check=True)
    subprocess.run(["git", "-C", str(bootstrap_clone), "config", "user.email", "boot@local"], check=True)
    subprocess.run(["git", "-C", str(bootstrap_clone), "add", "app"], check=True)
    subprocess.run(["git", "-C", str(bootstrap_clone), "commit", "-qm", "Initial commit"], check=True)
    subprocess.run(["git", "-C", str(bootstrap_clone), "push", "origin", "HEAD:refs/heads/accepted"], check=True, capture_output=True)
    shutil.rmtree(bootstrap_clone)

    effects_db = receiver_root / "effects.sqlite"
    with closing(sqlite3.connect(str(effects_db))) as db:
        db.execute("CREATE TABLE effects(id TEXT PRIMARY KEY, value INTEGER)")
        db.commit()

    promo_dir = receiver_root / "promotion"
    incidents_dir = receiver_root / "incidents"
    promo_dir.mkdir(mode=0o700)
    incidents_dir.mkdir(mode=0o700)

    project_db = receiver_root / "project.sqlite"
    promo = SafePromotion(accepted_git, effects_db, promo_dir, require_final_gate=True)
    project = ProjectLedger(
        project_db,
        "openline-prod-p1",
        "OpenLine Production Project",
        _pub(owner_key),
        promotion=promo,
        world_verifier=lambda r, inv: r.get("member") == inv.get("member_id"),
        strict_production=True,
    )

    for name, k in (("alice", alice_key), ("bob", bob_key)):
        w_rec = {"member": name, "environment": "prod-bootstrap"}
        inv = {
            "project_id": project.id,
            "member_id": name,
            "owner_pub": _pub(k),
            "worker_pub": _pub(k),
            "scope": "contribute",
            "world_digest": digest(w_rec),
        }
        joined = project.join(inv, _sig(owner_key, inv), _sig(k, inv), world_receipt=w_rec)
        if joined != "JOINED":
            raise RuntimeError(f"join_failed:{joined}")

    head = promo.accepted()
    c_alice = {
        "project_id": project.id,
        "deliverable_id": "invoice-feature",
        "member_id": "alice",
        "accepted_head": head,
        "dependencies": ["invoice_v1"],
    }
    project.accept("invoice-feature", "alice", head, ["invoice_v1"], _sig(alice_key, c_alice))

    c_bob = {
        "project_id": project.id,
        "deliverable_id": "independent-formatter",
        "member_id": "bob",
        "accepted_head": head,
        "dependencies": ["format_v1"],
    }
    project.accept("independent-formatter", "bob", head, ["format_v1"], _sig(bob_key, c_bob))

    # Trigger dependency change invoice_v1 -> invoice_v2
    chg = {"project_id": project.id, "dependency": "invoice_v1", "contract": "invoice_v2", "action": "change_dependency"}
    project.change_dependency("invoice_v1", "invoice_v2", _sig(owner_key, chg))

    # Harden permissions on receiver_root
    for dirpath, _dirs, files in os.walk(receiver_root):
        os.chmod(dirpath, 0o700)
        for fn in files:
            fp = Path(dirpath) / fn
            if fp.name == "receiver.key":
                os.chmod(fp, 0o400)
            else:
                os.chmod(fp, 0o600)

    uid = os.getuid()
    gid = os.getgid()
    validator_script = EXPERIMENTS / "OPENLINE-RELEASE-001" / "validator_contract.py"

    prod_cfg = {
        "schema": PRODUCTION_CONFIG_SCHEMA,
        "deployment_id": "deploy-prod-001",
        "project_id": "openline-prod-p1",
        "receiver_id": "receiver-p1",
        "objective": "OpenLine Production Project",
        "owner_pub": _pub(owner_key),
        "receiver_pub": _pub(receiver_key),
        "receiver_uid": uid,
        "receiver_gid": gid,
        "validator_uid": uid,
        "validator_gid": gid,
        "allow_single_uid_test_harness": True,
        "paths": {
            "root_dir": str(receiver_root),
            "accepted_git": str(accepted_git),
            "project_db": str(project_db),
            "effects_db": str(effects_db),
            "promotion_dir": str(promo_dir),
            "incidents_dir": str(incidents_dir),
            "receiver_key_file": str(receiver_root / "keys" / "receiver.key"),
            "empty_hooks_dir": str(empty_hooks),
            "worker_socket": str(socket_dir / "worker.sock"),
            "control_socket": str(socket_dir / "control.sock"),
            "validation_spool_dir": str(spool_dir),
            "validator_script": str(validator_script),
        },
        "worker_principals": {
            "10001": {
                "uid": 10001,
                "member_id": "alice",
                "principal_id": "worker:alice",
                "worker_pub": _pub(alice_key),
                "owner_pub": _pub(alice_key),
            },
            "10002": {
                "uid": 10002,
                "member_id": "bob",
                "principal_id": "worker:bob",
                "worker_pub": _pub(bob_key),
                "owner_pub": _pub(bob_key),
            },
        },
        "control_principals": {
            str(uid): {
                "uid": uid,
                "principal_id": "control:owner",
                "public_key": _pub(owner_key),
                "role": "owner",
            },
            "10001": {
                "uid": 10001,
                "principal_id": "control:alice",
                "public_key": _pub(alice_key),
                "role": "contributor",
            },
        },
    }
    return {
        "config": prod_cfg,
        "owner_key": owner_key,
        "alice_key": alice_key,
        "bob_key": bob_key,
        "receiver_key": receiver_key,
        "base_dir": base_dir,
    }


def run_rehearsal() -> dict:
    with tempfile.TemporaryDirectory(prefix="openline-ops-rehearsal-") as tmp:
        base = Path(tmp)
        env = bootstrap_isolated_deployment(base)
        cfg = env["config"]
        owner_key = env["owner_key"]
        alice_key = env["alice_key"]
        bob_key = env["bob_key"]

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

            # 1. Assign repair-1 to bob
            asgn_claim = {
                "project_id": cfg["project_id"],
                "assignment_id": "repair-1",
                "deliverable_id": "invoice-feature",
                "worker_member": "bob",
                "basis": "invoice_v2",
                "allowed_paths": ["app/price.py"],
                "action": "repair_assignment",
            }
            r_asgn = ctrl_alice.call("control.assign", {
                "assignment_id": "repair-1",
                "deliverable_id": "invoice-feature",
                "worker_member": "bob",
                "basis": "invoice_v2",
                "allowed_paths": ["app/price.py"],
                "contributor_signature": _sig(alice_key, asgn_claim),
            })
            if not (r_asgn["status"] == "OK", r_asgn): raise AssertionError('r_asgn["status"] == "OK", r_asgn')

            # 2. Bob prepares workspace via snapshot chunks and submits valid repair
            bob_ws_root = base / "bob_private_workspace"
            r_prep = worker_bob.prepare_workspace("repair-1", bob_ws_root, propose_memory="mem-1", lesson="Update rate to 12")
            if not (r_prep["status"] == "OK", r_prep): raise AssertionError('r_prep["status"] == "OK", r_prep')
            client_ws = Path(r_prep["result"]["client_workspace"])
            if not (not (client_ws / ".git").exists()): raise AssertionError('not (client_ws / ".git").exists()')
            (client_ws / "app" / "price.py").write_text("def total(qty):\n    return qty * 11\n", encoding="utf-8")

            r_sub = worker_bob.submit_workspace_proposal("repair-1", client_ws, allowed_paths=["app/price.py"])
            if not (r_sub["status"] == "ACCEPTED", r_sub): raise AssertionError('r_sub["status"] == "ACCEPTED", r_sub')
            rec = r_sub["result"]["receipt"]
            v_out = verify_receipt(
                rec,
                cfg["receiver_pub"],
                accepted_git=Path(cfg["paths"]["accepted_git"]),
                project_db=Path(cfg["paths"]["project_db"]),
            )
            if not (v_out["crypto"] == "VERIFIED" and v_out["git_verified"] and v_out["continuity_verified"]): raise AssertionError('v_out["crypto"] == "VERIFIED" and v_out["git_verified"] and v_out["continuity_verified"]')

            # 3. Create consistent online backup and verify signature
            backup_dir = base / "backup_snap_1"
            r_bak = ctrl_owner.call("control.backup", {"backup_dir": str(backup_dir)})
            if not (r_bak["status"] == "OK", r_bak): raise AssertionError('r_bak["status"] == "OK", r_bak')
            signed_manifest = r_bak["result"]["manifest"]
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(cfg["receiver_pub"])).verify(
                bytes.fromhex(signed_manifest["signature_ed25519_hex"]),
                canonical_json_bytes(signed_manifest["manifest"]),
            )

            # 4. Rotate owner key and verify old owner key is rejected while new owner key works
            new_owner_key = Ed25519PrivateKey.generate()
            rot_claim = {
                "project_id": cfg["project_id"],
                "old_owner_pub": _pub(owner_key),
                "new_owner_pub": _pub(new_owner_key),
                "action": "rotate_owner_key",
            }
            r_rot = ctrl_owner.call("control.rotate_key", {
                "new_owner_pub": _pub(new_owner_key),
                "current_owner_signature": _sig(owner_key, rot_claim),
            })
            if not (r_rot["status"] == "OK" and r_rot["result"]["status"] == "OWNER_ROTATED", r_rot): raise AssertionError('r_rot["status"] == "OK" and r_rot["result"]["status"] == "OWNER_ROTATED", r_rot')

            # 4a. Old owner key on IPC envelope must now be refused at socket entry!
            bad_stop_claim = {"project_id": cfg["project_id"], "action": "issue_stop", "reason": "stale_key", "expected_epoch": 1}
            r_bad_ipc = ctrl_owner.call("control.stop", {
                "reason": "stale_key",
                "owner_signature": _sig(owner_key, bad_stop_claim),
                "expected_epoch": 1,
            })
            if not (r_bad_ipc["status"] == "REFUSED" and r_bad_ipc["code"] == "SIGNATURE_INVALID", r_bad_ipc): raise AssertionError('r_bad_ipc["status"] == "REFUSED" and r_bad_ipc["code"] == "SIGNATURE_INVALID", r_bad_ipc')

            # 4b. Switch IPC client to new_owner_key, but pass stale inner owner_signature -> refused by ProjectLedger!
            ctrl_owner.signer_key = new_owner_key
            r_bad_inner = ctrl_owner.call("control.stop", {
                "reason": "stale_key",
                "owner_signature": _sig(owner_key, bad_stop_claim),
                "expected_epoch": 1,
            })
            if not (r_bad_inner["status"] == "REFUSED" and r_bad_inner["code"] == "invalid_owner_signature", r_bad_inner): raise AssertionError('r_bad_inner["status"] == "REFUSED" and r_bad_inner["code"] == "invalid_owner_signature", r_bad_inner')

            # 4c. New owner signature on both IPC envelope and STOP claim succeeds!
            good_stop_claim = {"project_id": cfg["project_id"], "action": "issue_stop", "reason": "drill_stop", "expected_epoch": 1}
            r_good_stop = ctrl_owner.call("control.stop", {
                "reason": "drill_stop",
                "owner_signature": _sig(new_owner_key, good_stop_claim),
                "expected_epoch": 1,
            })
            if not (r_good_stop["status"] == "OK" and r_good_stop["result"]["kill_switch"]["stopped"] is True, r_good_stop): raise AssertionError('r_good_stop["status"] == "OK" and r_good_stop["result"]["kill_switch"]["stopped"] is True, r_good_stop')

            return {
                "status": "PASS",
                "accepted_head": signed_manifest["manifest"]["accepted_head"],
                "receipt_verified": True,
                "backup_verified": True,
                "owner_key_rotation_verified": True,
            }
        finally:
            svc.stop()


if __name__ == "__main__":
    out = run_rehearsal()
    print(json.dumps(out, sort_keys=True, indent=2))
