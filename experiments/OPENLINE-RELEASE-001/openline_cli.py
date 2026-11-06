"""OpenLine Living Projects Release CLI — unified command surface over existing engines.

Every authorization decision is made by the existing receiver-owned engines
(Protect, ProjectLedger, SafePromotion, LocalEffectStore). This CLI connects:
  - Stage 1: Security foundation (ADV-01..ADV-10 defenses, ReceiverGuard, pinned keys)
  - Stage 2: One accepted project state (ProjectLedger + CRYPTOGRAPHICALLY_BOUND vs UNTRUSTED_ADVISORY Claim Graph)
  - Stage 3: Swarm, Coach & Verified Memory RSI loop (CANDIDATE -> INHERITED / QUARANTINED -> QUESTIONED)
  - Stage 4: Unified CLI/MCP experience (init, status, graph, change, assign, prepare, intercept,
             verify, recover, revoke, rotate-key, memory, history, doctor, guard, kill-switch, replay, mcp)

Exit codes: 0 ACCEPTED/success, 3 STOPPED, 4 UNKNOWN, 2 usage or engine refusal.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from engine_loader import load_engines  # noqa: E402

load_engines()

from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
)
from protect import Protect, ProtectError, verify_receipt, check_receiver_boundary  # noqa: E402
from project import ProjectLedger, ProjectRefused, digest  # noqa: E402
from foundation.promotion import SafePromotion  # noqa: E402
from continuity import audit as continuity_audit  # noqa: E402
import living_project  # noqa: E402


def _pub(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def _sig(key, obj):
    return key.sign(json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hex()


def _git(*args, cwd=None):
    result = subprocess.run(["git", *map(str, args)], cwd=cwd, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError((result.args, result.stdout, result.stderr))
    return result.stdout.strip()


def _write_key(path: Path, key) -> None:
    path.write_text(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex() + "\n")
    os.chmod(path, 0o600)


def _read_key(path: Path):
    seed = bytes.fromhex(Path(path).read_text().strip())
    return Ed25519PrivateKey.from_private_bytes(seed)


def _emit(obj: dict) -> None:
    print(json.dumps(obj, sort_keys=True, indent=2))


def _fail(message: str) -> int:
    print(json.dumps({"status": "ERROR", "error": message}, sort_keys=True), file=sys.stderr)
    return 2


def _load_config(project_dir: Path) -> dict:
    config_path = project_dir / "config.json"
    if not config_path.is_file():
        raise RuntimeError(f"not an OpenLine project dir: {project_dir} (missing config.json; run: openline init)")
    return json.loads(config_path.read_text())


def _save_config(project_dir: Path, config: dict) -> None:
    (project_dir / "config.json").write_text(json.dumps(config, sort_keys=True, indent=2) + "\n")



def _get_ipc_client(args, config: dict, *, channel: str = "worker"):
    sock_path = getattr(args, "service_socket", None) or os.environ.get("OPENLINE_SERVICE_SOCKET") or config.get("service_socket")
    if not sock_path:
        return None
    from ipc_client import OpenLineIPCClient
    key_path = getattr(args, "client_key", None) or os.environ.get("OPENLINE_CLIENT_KEY") or config.get("client_key")
    if not key_path:
        raise RuntimeError("--client-key or OPENLINE_CLIENT_KEY is required in --service-socket mode")
    signer_key = _read_key(Path(key_path))
    principal_id = (
        getattr(args, "principal_id", None)
        or os.environ.get("OPENLINE_PRINCIPAL_ID")
        or config.get("principal_id")
        or ("control:owner" if channel == "control" else "worker:bob")
    )
    pinned_pub = config.get("receiver_pub")
    if not pinned_pub:
        pinned_file = Path(config["dir"]) / "PINNED_RECEIVER_PUBLIC_KEY.hex"
        pinned_pub = pinned_file.read_text().strip()
    return OpenLineIPCClient(
        socket_path=Path(sock_path),
        channel=channel,
        deployment_id=config.get("deployment_id", "openline-prod-1"),
        project_id=config["project_id"],
        receiver_id=config.get("receiver_id", "receiver-p1"),
        principal_id=principal_id,
        signer_key=signer_key,
        pinned_receiver_pub=pinned_pub,
    )

def _build_engines(config: dict, worker_uid: int):
    key_file = Path(config["key_file"])
    receiver_key = _read_key(key_file)
    actual_pub = _pub(receiver_key)
    pinned_hex_file = Path(config["dir"]) / "PINNED_RECEIVER_PUBLIC_KEY.hex"
    if pinned_hex_file.is_file():
        pinned_pub = pinned_hex_file.read_text().strip()
        if actual_pub != pinned_pub:
            raise ProtectError("receiver_key_mismatch_with_pinned_pub")
    if config.get("receiver_pub") and actual_pub != config["receiver_pub"]:
        raise ProtectError("receiver_key_mismatch_with_pinned_pub")

    owner_key_path = Path(config.get("keys_dir", "")) / "owner.key" if config.get("keys_dir") else None
    if owner_key_path and owner_key_path.is_file():
        owner_pub = _pub(_read_key(owner_key_path))
    elif config.get("owner_pub"):
        owner_pub = config["owner_pub"]
    else:
        pinned_owner_file = Path(config["dir"]) / "PINNED_OWNER_PUBLIC_KEY.hex"
        owner_pub = pinned_owner_file.read_text().strip()
    promo = SafePromotion(Path(config["accepted_git"]), Path(config["effects_db"]), Path(config["promotion_dir"]), require_final_gate=True)
    project = ProjectLedger(
        Path(config["project_db"]),
        config["project_id"],
        config.get("objective", "OpenLine project"),
        owner_pub,
        promotion=promo,
        world_verifier=lambda receipt, invitation: receipt.get("member") == invitation.get("member_id"),
    )
    protect = Protect(
        project,
        receiver_key,
        Path(config["incidents_dir"]),
        acceptance_cmd=(sys.executable, "-B", config["validator"], config["project_db"]),
        worker_uid=worker_uid,
        receiver_key_path=key_file,
    )
    return promo, project, protect


def _harden_tree(root: Path, paths) -> None:
    for path in paths:
        p = Path(path)
        if p.is_dir():
            for dirpath, _dirs, files in os.walk(p):
                os.chmod(dirpath, 0o700)
                for name in files:
                    os.chmod(Path(dirpath) / name, 0o600)
        elif p.is_file():
            os.chmod(p, 0o600)


def cmd_init(args) -> int:
    project_dir = Path(args.dir).resolve()
    if project_dir.exists() and any(project_dir.iterdir()):
        return _fail(f"directory not empty: {project_dir}")
    project_dir.mkdir(parents=True, exist_ok=True)
    workers = [w.strip() for w in args.workers.split(",") if w.strip()]
    if not workers:
        return _fail("at least one worker member is required")
    validator = Path(args.validator).resolve() if args.validator else HERE / "validator_contract.py"
    if not validator.is_file():
        return _fail(f"validator not found: {validator}")
    accepted = project_dir / "accepted.git"
    _git("init", "--bare", str(accepted))
    setup = project_dir / ".bootstrap"
    _git("clone", str(accepted), str(setup))
    (setup / "app").mkdir()
    (setup / "app" / "price.py").write_text("def total(qty):\n    return qty * 10\n")
    (setup / "app" / "independent.py").write_text("def label(value):\n    return value.upper()\n")
    _git("-C", str(setup), "config", "user.name", "OpenLine Bootstrap")
    _git("-C", str(setup), "config", "user.email", "boot@local.test")
    _git("-C", str(setup), "add", "app")
    _git("-C", str(setup), "commit", "-qm", "Initial accepted project")
    _git("-C", str(setup), "push", "origin", "HEAD:refs/heads/accepted")
    live_db = project_dir / "effects.sqlite"
    with closing(sqlite3.connect(live_db)) as db:
        db.execute("CREATE TABLE effects(id TEXT PRIMARY KEY, value INTEGER)")
        db.commit()
    promo = SafePromotion(accepted, live_db, project_dir / "promotion", require_final_gate=True)
    keys_dir = project_dir / "keys"
    keys_dir.mkdir()
    owner = Ed25519PrivateKey.generate()
    _write_key(keys_dir / "owner.key", owner)
    member_keys = {}
    for name in workers:
        key = Ed25519PrivateKey.generate()
        _write_key(keys_dir / f"{name}.key", key)
        member_keys[name] = key
    project = ProjectLedger(
        project_dir / "project.sqlite",
        args.project_id,
        "OpenLine project",
        _pub(owner),
        promotion=promo,
        world_verifier=lambda receipt, invitation: receipt.get("member") == invitation.get("member_id"),
    )
    for name, key in member_keys.items():
        receipt = {"member": name, "environment": "local-init"}
        invitation = {
            "project_id": project.id,
            "member_id": name,
            "owner_pub": _pub(key),
            "worker_pub": _pub(key),
            "scope": "contribute",
            "world_digest": digest(receipt),
        }
        joined = project.join(invitation, _sig(owner, invitation), _sig(key, invitation), world_receipt=receipt)
        assert joined == "JOINED", joined
    head = promo.accepted()
    claim = {
        "project_id": project.id,
        "deliverable_id": "invoice-feature",
        "member_id": workers[0],
        "accepted_head": head,
        "dependencies": ["invoice_v1"],
    }
    project.accept("invoice-feature", workers[0], head, ["invoice_v1"], _sig(member_keys[workers[0]], claim))
    if len(workers) > 1:
        claim = {
            "project_id": project.id,
            "deliverable_id": "independent-formatter",
            "member_id": workers[1],
            "accepted_head": head,
            "dependencies": ["format_v1"],
        }
        project.accept("independent-formatter", workers[1], head, ["format_v1"], _sig(member_keys[workers[1]], claim))

    affected = []
    if not getattr(args, "no_initial_break", False):
        change = {"project_id": project.id, "dependency": "invoice_v1", "contract": "invoice_v2", "action": "change_dependency"}
        affected = project.change_dependency("invoice_v1", "invoice_v2", _sig(owner, change))

    receiver_key = Ed25519PrivateKey.generate()
    key_file = keys_dir / "receiver.key"
    _write_key(key_file, receiver_key)
    (project_dir / "PINNED_RECEIVER_PUBLIC_KEY.hex").write_text(_pub(receiver_key) + "\n")
    os.chmod(project_dir / "PINNED_RECEIVER_PUBLIC_KEY.hex", 0o600)

    protect = Protect(
        project,
        receiver_key,
        project_dir / "incidents",
        acceptance_cmd=(sys.executable, "-B", str(validator), str(project_dir / "project.sqlite")),
        worker_uid=args.worker_uid,
        receiver_key_path=key_file,
    )
    boundary_before = check_receiver_boundary(protect.receiver_paths(), receiver_uid=os.getuid(), worker_uid=args.worker_uid)
    _harden_tree(project_dir, [accepted, project_dir / "promotion", project_dir / "project.sqlite", live_db, project_dir / "incidents", keys_dir])
    boundary_after = check_receiver_boundary(protect.receiver_paths(), receiver_uid=os.getuid(), worker_uid=args.worker_uid)
    if boundary_after:
        return _fail("boundary not clean after hardening: " + ";".join(boundary_after))
    shutil.rmtree(setup)
    config = {
        "version": 1,
        "project_id": project.id,
        "objective": "OpenLine project",
        "dir": str(project_dir),
        "accepted_git": str(accepted),
        "project_db": str(project_dir / "project.sqlite"),
        "effects_db": str(live_db),
        "promotion_dir": str(project_dir / "promotion"),
        "incidents_dir": str(project_dir / "incidents"),
        "keys_dir": str(keys_dir),
        "key_file": str(key_file),
        "owner_pub": _pub(owner),
        "receiver_pub": _pub(receiver_key),
        "validator": str(validator),
        "members": workers,
        "contract": "v1" if getattr(args, "no_initial_break", False) else "invoice_v2",
        "boundary_before_hardening": boundary_before,
        "boundary_after_hardening": boundary_after,
    }
    _save_config(project_dir, config)
    _emit({
        "status": "INITIALIZED",
        "dir": str(project_dir),
        "project_id": project.id,
        "head": head,
        "members": workers,
        "affected_reopen": affected,
        "receiver_pub": _pub(receiver_key),
        "boundary_before_hardening": boundary_before,
        "next": "openline assign --dir DIR --assignment repair-1 --worker " + workers[0] + " --basis invoice_v2",
    })
    return 0


def cmd_assign(args) -> int:
    project_dir = Path(args.dir).resolve()
    config = _load_config(project_dir)
    _promo, project, _protect = _build_engines(config, args.worker_uid)
    snap = project.snapshot()
    deliverables = {d[0]: d[1] for d in snap["deliverables"]}
    target_deliv = getattr(args, "deliverable", None) or "invoice-feature"
    raw_paths = getattr(args, "allowed_paths", None)
    default_path = "app/independent.py" if target_deliv == "independent-formatter" else "app/price.py"
    allowed_paths = sorted([p.strip() for p in raw_paths.split(",") if p.strip()]) if raw_paths else [default_path]
    if target_deliv not in deliverables:
        return _fail(f"deliverable {target_deliv} not found")
    contributor = args.as_member or deliverables[target_deliv]
    claim = {
        "project_id": project.id,
        "assignment_id": args.assignment,
        "deliverable_id": target_deliv,
        "worker_member": args.worker,
        "basis": args.basis,
        "allowed_paths": allowed_paths,
        "action": "repair_assignment",
    }
    if args.signature:
        signature = args.signature
    else:
        key_path = Path(config["keys_dir"]) / f"{contributor}.key"
        if not key_path.is_file():
            return _fail(f"no local key for contributor {contributor}; pass --signature for out-of-band signing")
        signature = _sig(_read_key(key_path), claim)
    post_stop_sig = getattr(args, "post_stop_signature", None)
    if not post_stop_sig and getattr(args, "post_stop_owner_sign", False):
        st = project.read_stop_state()
        owner_key = _read_key(Path(config["keys_dir"]) / "owner.key")
        override_claim = {
            "project_id": project.id,
            "assignment_id": args.assignment,
            "deliverable_id": target_deliv,
            "worker_member": args.worker,
            "basis": args.basis,
            "allowed_paths": allowed_paths,
            "epoch": st["epoch"],
            "stop_seq": st["stop_seq"],
            "action": "post_stop_grant",
        }
        post_stop_sig = _sig(owner_key, override_claim)
    project.assign_repair(
        args.assignment,
        target_deliv,
        args.worker,
        args.basis,
        signature,
        allowed_paths=allowed_paths,
        post_stop_owner_signature=post_stop_sig,
    )
    _emit({
        "status": "ASSIGNED",
        "assignment": args.assignment,
        "deliverable": target_deliv,
        "worker": args.worker,
        "basis": args.basis,
        "allowed_paths": allowed_paths,
        "contributor": contributor,
        "post_stop_override": bool(post_stop_sig),
    })
    return 0


def cmd_prepare(args) -> int:
    project_dir = Path(args.dir).resolve()
    config = _load_config(project_dir)
    ipc = _get_ipc_client(args, config, channel="worker")
    if ipc is not None:
        dest_dir = Path(getattr(args, "client_workspace", None) or os.environ.get("OPENLINE_CLIENT_WORKSPACE") or (project_dir / f"client-{args.assignment}"))
        resp = ipc.prepare_workspace(
            args.assignment,
            dest_dir,
            propose_memory=getattr(args, "propose_memory", None),
            diagnosis=getattr(args, "diagnosis", None),
            lesson=getattr(args, "lesson", None),
        )
        if resp["status"] != "OK":
            return _fail(resp["result"].get("error", resp["code"]))
        _emit({
            "status": "PREPARED",
            "assignment": args.assignment,
            "workspace": resp["result"]["client_workspace"],
            "snapshot_db": resp["result"]["client_snapshot_db"],
            "proposed_memory": resp["result"].get("proposed_memory"),
            "ipc_verified": True,
        })
        return 0
    promo, project, _protect = _build_engines(config, args.worker_uid)
    state = promo.prepare(args.assignment)
    out = {"status": "PREPARED", "assignment": args.assignment, "workspace": state["workspace"]}
    if getattr(args, "propose_memory", None):
        with closing(sqlite3.connect(project.db_path)) as db:
            row = db.execute("SELECT deliverable_id, worker_member, basis FROM assignments WHERE id=?", (args.assignment,)).fetchone()
        if row:
            mem = project.propose_memory(
                args.propose_memory,
                row[0],
                row[1],
                row[2],
                hashlib.sha256((args.lesson or "candidate").encode()).hexdigest(),
                args.diagnosis or "candidate diagnosis",
                args.lesson or "candidate lesson",
                assignment_id=args.assignment,
            )
            out["proposed_memory"] = mem
    _emit(out)
    return 0


def cmd_intercept(args) -> int:
    project_dir = Path(args.dir).resolve()
    config = _load_config(project_dir)
    ipc = _get_ipc_client(args, config, channel="worker")
    if ipc is not None:
        ws_dir = Path(getattr(args, "client_workspace", None) or os.environ.get("OPENLINE_CLIENT_WORKSPACE") or (project_dir / f"client-{args.assignment}" / "workspace"))
        resp = ipc.submit_workspace_proposal(args.assignment, ws_dir)
        res = resp["result"]
        if "verdict" not in res:
            return _fail(res.get("error", resp["code"]))
        _emit({
            "status": res["verdict"],
            "assignment": args.assignment,
            "incident_id": res["incident_id"],
            "receipt_path": res["receipt_path"],
            "reason": res["reason"],
            "accepted_ref_before": res["accepted_ref_before"],
            "accepted_ref_after": res["accepted_ref_after"],
        })
        return {"ACCEPTED": 0, "STOPPED": 3, "UNKNOWN_RECONCILIATION_REQUIRED": 4}.get(res["verdict"], 2)
    _promo, _project, protect = _build_engines(config, args.worker_uid)
    out = protect.intercept(args.assignment)
    payload = out["receipt"]["payload"]
    _emit({
        "status": out["verdict"],
        "assignment": args.assignment,
        "incident_id": payload["incident_id"],
        "receipt_path": out["path"],
        "reason": payload["reason"],
        "accepted_ref_before": payload["accepted_ref_before"],
        "accepted_ref_after": payload["accepted_ref_after"],
    })
    return {"ACCEPTED": 0, "STOPPED": 3, "UNKNOWN_RECONCILIATION_REQUIRED": 4}.get(out["verdict"], 2)


def _assignment_state(project, assignment: str):
    with closing(sqlite3.connect(project.db_path)) as db:
        row = db.execute("SELECT state FROM assignments WHERE id=?", (assignment,)).fetchone()
    return row[0] if row else None


def cmd_verify(args) -> int:
    receipt = json.loads(Path(args.receipt).read_text())
    kwargs = {}
    if args.git:
        kwargs["accepted_git"] = Path(args.git)
    if args.project_db:
        kwargs["project_db"] = Path(args.project_db)
    try:
        checked = verify_receipt(receipt, args.pinned_key, **kwargs)
    except Exception as exc:
        return _fail(f"verification failed: {type(exc).__name__}: {exc}")
    _emit({"status": "VERIFIED" if checked.get("crypto") == "VERIFIED" else "REJECTED", "checked": checked})
    ok = checked.get("crypto") == "VERIFIED"
    if args.git:
        ok = ok and checked.get("git_verified") is True
    if args.project_db:
        ok = ok and checked.get("continuity_verified") is True
    return 0 if ok else 1


def cmd_status(args) -> int:
    project_dir = Path(args.dir).resolve()
    config = _load_config(project_dir)
    ipc = _get_ipc_client(args, config, channel="worker")
    if ipc is not None:
        resp = ipc.call("project.status", {})
        if resp["status"] != "OK":
            return _fail(resp["result"].get("error", resp["code"]))
        _emit(resp["result"])
        return 0
    promo, project, protect = _build_engines(config, args.worker_uid)
    snap = project.snapshot()
    with closing(sqlite3.connect(project.db_path)) as db:
        rows = db.execute("SELECT id, worker_member, basis, state, deliverable_id FROM assignments ORDER BY id").fetchall()
        dep_contracts = dict(db.execute("SELECT dep_key, contract FROM dependency_contracts WHERE project_id=?", (project.id,)).fetchall())
        members = [{"member": r[0], "active": bool(r[1])} for r in db.execute("SELECT member_id, active FROM members WHERE project_id=? ORDER BY member_id", (project.id,))]
    boundary = check_receiver_boundary(protect.receiver_paths(), receiver_uid=os.getuid(), worker_uid=args.worker_uid)
    _emit({
        "status": "OK",
        "project_id": project.id,
        "head": promo.accepted(),
        "contract": snap["project"][2],
        "dependency_contracts": dep_contracts,
        "project_status": snap["project"][4],
        "kill_switch": project.read_stop_state(),
        "members": members,
        "deliverables": [{"id": d[0], "member": d[1], "standing": d[2], "accepted_head": d[3]} for d in snap["deliverables"]],
        "assignments": [{"id": r[0], "worker": r[1], "basis": r[2], "state": r[3], "deliverable": r[4]} for r in rows],
        "receiver_pub": config["receiver_pub"],
        "boundary": boundary,
    })
    return 0


def cmd_graph(args) -> int:
    project_dir = Path(args.dir).resolve()
    config = _load_config(project_dir)
    _promo, project, _protect = _build_engines(config, args.worker_uid)
    if getattr(args, "add_claim", None):
        sig = args.signature
        if not sig and args.signer and getattr(args, "sign_local", False):
            key_file = Path(config["keys_dir"]) / ("owner.key" if args.signer == "owner" else f"{args.signer}.key")
            if key_file.is_file():
                envelope = {
                    "project_id": project.id,
                    "claim_id": args.add_claim,
                    "subject": args.subject,
                    "predicate": args.predicate,
                    "object": args.object,
                    "signer_id": args.signer,
                    "action": "graph_claim",
                }
                sig = _sig(_read_key(key_file), envelope)
        rec = project.record_graph_claim(
            args.add_claim,
            args.subject,
            args.predicate,
            args.object,
            signer_id=args.signer,
            signature_hex=sig,
        )
        _emit({"status": "GRAPH_CLAIM_RECORDED", "claim": rec})
        return 0

    changed = tuple(getattr(args, "changed", None) or ())
    obs = living_project.observe(Path(config["project_db"]), Path(config["accepted_git"]), changed=changed)
    with closing(sqlite3.connect(project.db_path)) as db:
        claims = [
            {
                "claim_id": r[0],
                "subject": r[1],
                "predicate": r[2],
                "object": r[3],
                "signer_id": r[4],
                "trust_status": r[5],
                "claim_sha256": r[6],
                "at": r[7],
                "authoritative_for_promotion": False,
            }
            for r in db.execute(
                "SELECT claim_id, subject, predicate, object, signer_id, trust_status, claim_sha256, at "
                "FROM claim_graph WHERE project_id=? ORDER BY at, claim_id",
                (project.id,),
            ).fetchall()
        ]
    obs["claim_graph"] = {
        "claims": claims,
        "cryptographically_bound_count": sum(1 for c in claims if c["trust_status"] == "CRYPTOGRAPHICALLY_BOUND"),
        "untrusted_advisory_count": sum(1 for c in claims if c["trust_status"] == "UNTRUSTED_ADVISORY"),
        "policy": "SEPARATE_CLAIM_GRAPH_NEVER_AUTHORITATIVE_FOR_GIT_PROMOTION",
    }
    _emit(obs)
    return 0


def cmd_recover(args) -> int:
    project_dir = Path(args.dir).resolve()
    config = _load_config(project_dir)
    _promo, _project, protect = _build_engines(config, args.worker_uid)
    out = protect.reconcile(args.assignment)
    payload = out["receipt"]["payload"]
    _emit({
        "status": out["verdict"],
        "assignment": args.assignment,
        "incident_id": payload["incident_id"],
        "receipt_path": out["path"],
        "reason": payload["reason"],
    })
    return {"ACCEPTED": 0, "STOPPED": 3, "UNKNOWN_RECONCILIATION_REQUIRED": 4}.get(out["verdict"], 2)


def cmd_change(args) -> int:
    project_dir = Path(args.dir).resolve()
    config = _load_config(project_dir)
    _promo, project, _protect = _build_engines(config, args.worker_uid)
    pairs = []
    if getattr(args, "dependency", None) and getattr(args, "contract", None):
        pairs.append((args.dependency, args.contract))
    for item in getattr(args, "changes", None) or []:
        if "=" not in item:
            return _fail(f"invalid --change format (expected DEP=CONTRACT): {item}")
        k, v = item.split("=", 1)
        pairs.append((k.strip(), v.strip()))
    if not pairs:
        return _fail("provide --dependency and --contract, or one or more --change DEP=CONTRACT pairs")

    owner_key = _read_key(Path(config["keys_dir"]) / "owner.key") if not args.signature else None
    all_affected = []
    applied = []
    for dep, contract in pairs:
        claim = {"project_id": project.id, "dependency": dep, "contract": contract, "action": "change_dependency"}
        sig = args.signature if args.signature else _sig(owner_key, claim)
        affected = project.change_dependency(dep, contract, sig)
        for a in affected:
            if a not in all_affected:
                all_affected.append(a)
        applied.append({"dependency": dep, "contract": contract, "affected": affected})
        config["contract"] = contract
    _save_config(project_dir, config)
    _emit({
        "status": "CHANGED",
        "dependency": pairs[-1][0],
        "contract": pairs[-1][1],
        "changes": applied,
        "affected": sorted(all_affected),
    })
    return 0


def cmd_revoke(args) -> int:
    project_dir = Path(args.dir).resolve()
    config = _load_config(project_dir)
    _promo, project, _protect = _build_engines(config, args.worker_uid)
    claim = {"project_id": project.id, "member_id": args.member, "action": "revoke_member"}
    if args.signature:
        signature = args.signature
    else:
        signature = _sig(_read_key(Path(config["keys_dir"]) / "owner.key"), claim)
    project.revoke_member(args.member, signature)
    _emit({"status": "REVOKED", "member": args.member})
    return 0


def cmd_rotate_key(args) -> int:
    project_dir = Path(args.dir).resolve()
    config = _load_config(project_dir)
    _promo, project, _protect = _build_engines(config, args.worker_uid)
    keys_dir = Path(config["keys_dir"])
    if args.role == "owner":
        old_owner = _read_key(keys_dir / "owner.key")
        new_owner = Ed25519PrivateKey.generate()
        new_pub = _pub(new_owner)
        claim = {
            "project_id": project.id,
            "old_owner_pub": _pub(old_owner),
            "new_owner_pub": new_pub,
            "action": "rotate_owner_key",
        }
        sig = args.signature or _sig(old_owner, claim)
        project.rotate_owner_key(new_pub, sig)
        _write_key(keys_dir / "owner.key", new_owner)
        config["owner_pub"] = new_pub
        _save_config(project_dir, config)
        _emit({"status": "OWNER_KEY_ROTATED", "new_owner_pub": new_pub})
        return 0
    else:
        member = args.member
        if not member:
            return _fail("--member is required when --role=member")
        owner_key = _read_key(keys_dir / "owner.key")
        new_member_key = Ed25519PrivateKey.generate()
        receipt = {"member": member, "environment": "key-rotation", "old_pub": _pub(_read_key(keys_dir / f"{member}.key"))}
        invitation = {
            "project_id": project.id,
            "member_id": member,
            "owner_pub": _pub(new_member_key),
            "worker_pub": _pub(new_member_key),
            "scope": "contribute",
            "world_digest": digest(receipt),
        }
        res = project.join(invitation, _sig(owner_key, invitation), _sig(new_member_key, invitation), world_receipt=receipt)
        _write_key(keys_dir / f"{member}.key", new_member_key)
        _emit({"status": res, "member": member, "new_member_pub": _pub(new_member_key)})
        return 0


def cmd_memory(args) -> int:
    project_dir = Path(args.dir).resolve()
    config = _load_config(project_dir)
    _promo, project, _protect = _build_engines(config, args.worker_uid)
    if getattr(args, "propose", None):
        patch_sha = args.patch_sha256 or hashlib.sha256((args.lesson or "").encode()).hexdigest()
        res = project.propose_memory(
            args.propose,
            args.deliverable or "invoice-feature",
            args.worker or "bob",
            args.basis or config.get("contract", "invoice_v2"),
            patch_sha,
            args.diagnosis or "worker diagnosis",
            args.lesson or "worker lesson",
            assignment_id=args.assignment,
        )
        _emit({"status": "MEMORY_CANDIDATE_PROPOSED", "memory": res})
        return 0
    mem = project.inherit_memory(getattr(args, "deliverable", None))
    _emit({"status": "OK", **mem})
    return 0


def cmd_history(args) -> int:
    project_dir = Path(args.dir).resolve()
    config = _load_config(project_dir)
    promo, project, _protect = _build_engines(config, args.worker_uid)
    snap = project.snapshot()
    git_log_raw = _git("--git-dir", config["accepted_git"], "log", "--format=%H|%ct|%s", "refs/heads/accepted")
    git_commits = []
    for line in git_log_raw.splitlines():
        if "|" in line:
            sha, ts, subj = line.split("|", 2)
            git_commits.append({"commit": sha, "at_unix": int(ts), "subject": subj})
    incidents_dir = Path(config["incidents_dir"])
    receipts = []
    if incidents_dir.is_dir():
        for f in sorted(incidents_dir.glob("*.json")):
            try:
                r = json.loads(f.read_text())
                p = r.get("payload", {})
                receipts.append({
                    "incident_id": p.get("incident_id"),
                    "assignment": p.get("assignment"),
                    "verdict": p.get("verdict"),
                    "reason": p.get("reason"),
                    "accepted_ref_before": p.get("accepted_ref_before"),
                    "accepted_ref_after": p.get("accepted_ref_after"),
                    "payload_sha256": r.get("payload_sha256"),
                    "at_unix": p.get("at_unix"),
                    "file": f.name,
                })
            except Exception:
                pass
    _emit({
        "status": "OK",
        "project_id": project.id,
        "current_accepted_head": promo.accepted(),
        "ledger_events": snap["events"],
        "accepted_git_commits": git_commits,
        "incident_receipts": receipts,
    })
    return 0


def cmd_doctor(args) -> int:
    project_dir = Path(args.dir).resolve()
    config = _load_config(project_dir)
    promo, project, protect = _build_engines(config, args.worker_uid)
    boundary = check_receiver_boundary(protect.receiver_paths(), receiver_uid=os.getuid(), worker_uid=args.worker_uid)
    cont = continuity_audit(Path(config["project_db"]))
    obs = living_project.observe(Path(config["project_db"]), Path(config["accepted_git"]))
    runtimes = {name: bool(shutil.which(name)) for name in ("codex", "claude", "aider", "opencode", "hermes")}
    seal_path = project_dir / "receiver_seal.json"
    guard_status = "UNSEALED"
    if seal_path.is_file():
        try:
            from openline_guard import ReceiverGuard
            g = ReceiverGuard.verify(project_dir, pinned_receiver_pub_hex=config["receiver_pub"])
            guard_status = g["status"]
        except Exception as exc:
            guard_status = f"SEAL_INVALID:{exc}"
    stop_st = project.read_stop_state()
    healthy = (
        not boundary
        and cont.get("assessment") == "NO_RECORDED_STALE_DEPENDENCY_FOUND"
        and obs["project"]["head_consistent"] is True
    )
    _emit({
        "status": "HEALTHY" if healthy else "ATTENTION_REQUIRED",
        "project_id": project.id,
        "head_consistent": obs["project"]["head_consistent"],
        "accepted_git_head": obs["project"]["accepted_git_head"],
        "ledger_last_accepted": obs["project"]["ledger_last_accepted"],
        "boundary_issues": boundary,
        "continuity_assessment": cont.get("assessment"),
        "flagged_current_deliverables": cont.get("flagged_current_deliverables"),
        "living_verdict": obs["verdict"],
        "kill_switch": stop_st,
        "receiver_guard_seal": guard_status,
        "coding_agent_clis_detected": runtimes,
    })
    return 0 if healthy else 1


def cmd_guard(args) -> int:
    from openline_guard import ReceiverGuard
    project_dir = Path(args.dir).resolve()
    config = _load_config(project_dir)
    if args.verify_only:
        res = ReceiverGuard.verify(project_dir, pinned_receiver_pub_hex=config["receiver_pub"])
    else:
        res = ReceiverGuard.seal(project_dir)
    _emit(res)
    return 0


def cmd_kill_switch(args) -> int:
    action = args.action
    if action == "conformance":
        from kill_switch import run_kill_switch_conformance
        import tempfile
        if getattr(args, "output_dir", None):
            res = run_kill_switch_conformance(Path(args.output_dir).resolve(), race_iterations=int(args.races))
        else:
            with tempfile.TemporaryDirectory(prefix="openline-ks-conformance-") as tmp:
                res = run_kill_switch_conformance(Path(tmp), race_iterations=int(args.races))
        _emit(res)
        return 0 if res.get("status") == "PASS" else 1
    if action == "audit":
        if not getattr(args, "evidence_path", None):
            return _fail("--evidence-path is required when --action=audit")
        from kill_switch_auditor import audit_directory, audit_evidence_file
        target = Path(args.evidence_path).resolve()
        res = audit_directory(target) if target.is_dir() else audit_evidence_file(target)
        _emit(res)
        ok = res.get("status") == "PASS" if target.is_dir() else res.get("valid") is True
        return 0 if ok else 1
    if not getattr(args, "dir", None):
        return _fail("--dir is required for kill-switch status/stop/clear")
    project_dir = Path(args.dir).resolve()
    config = _load_config(project_dir)
    _promo, project, _protect = _build_engines(config, args.worker_uid)
    if action == "status":
        st = project.read_stop_state()
        _emit({"status": "OK", "project_id": project.id, "kill_switch": st})
        return 0
    reason = getattr(args, "reason", None) or ("owner_emergency_stop" if action == "stop" else "owner_clear_stop")
    act_name = "issue_stop" if action == "stop" else "clear_stop"
    epoch_arg = getattr(args, "expected_epoch", None)
    sig = getattr(args, "signature", None)
    if sig and epoch_arg is None:
        return _fail("--expected-epoch is required with --signature")
    expected_epoch = epoch_arg if epoch_arg is not None else project.read_stop_state()["epoch"]
    claim = {"project_id": project.id, "action": act_name, "reason": reason, "expected_epoch": expected_epoch}
    if not sig:
        owner_key_file = Path(config["keys_dir"]) / "owner.key"
        if not owner_key_file.is_file():
            return _fail("no local owner.key found; pass --signature")
        sig = _sig(_read_key(owner_key_file), claim)
    actor_role = getattr(args, "role", "owner") or "owner"
    if action == "stop":
        st = project.issue_stop(reason, sig, actor_role=actor_role, expected_epoch=expected_epoch)
        _emit({"status": "KILL_SWITCH_STOPPED", "project_id": project.id, "kill_switch": st})
        return 0
    if action == "clear":
        st = project.clear_stop(reason, sig, actor_role=actor_role, expected_epoch=expected_epoch)
        _emit({"status": "KILL_SWITCH_CLEARED", "project_id": project.id, "kill_switch": st})
        return 0
    return _fail(f"unknown kill-switch action: {action}")


def cmd_replay(args) -> int:
    from living_projects_e2e import run_mandatory_12_step_e2e
    import tempfile
    if getattr(args, "output_dir", None):
        out_dir = Path(args.output_dir).resolve()
        if out_dir.exists():
            shutil.rmtree(out_dir)
        out_dir.mkdir(parents=True)
        res = run_mandatory_12_step_e2e(out_dir)
    else:
        with tempfile.TemporaryDirectory(prefix="openline-living-e2e-") as tmp:
            res = run_mandatory_12_step_e2e(Path(tmp))
    _emit(res)
    return 0 if res.get("overall_verdict") == "PASS_LOCAL_MECHANISM_AND_SECURITY_GATES" else 1


def cmd_effect_demo(args) -> int:
    from foundation.effects import EffectDenied, LocalEffectStore, Principal
    import time
    project_dir = Path(args.dir).resolve()
    config = _load_config(project_dir)
    promo, project, _protect = _build_engines(config, args.worker_uid)
    store_path = project_dir / "effect_store.sqlite"
    if store_path.exists():
        store_path.unlink()
    store = LocalEffectStore(str(store_path))
    buyer = Principal()
    worker = Principal()
    store.register_buyer(buyer.public)
    with closing(sqlite3.connect(store_path)) as db:
        db.execute("CREATE TABLE IF NOT EXISTS application_effects(id TEXT PRIMARY KEY, value INTEGER)")
        db.commit()

    def observe_binding(assignment):
        snap = project.snapshot()
        return {
            "accepted_head": promo.accepted(),
            "project": project.id,
            "dependency": snap["project"][2],
            "assignment_state": _assignment_state(project, assignment),
        }

    def effect(db):
        db.execute("INSERT INTO application_effects VALUES (?,?)", ("demo-effect-1", 1))

    def observe(db):
        row = db.execute("SELECT value FROM application_effects WHERE id=?", ("demo-effect-1",)).fetchone()
        return row is not None and row[0] == 1

    def standing(db):
        return project.snapshot()["project"][4] == "ACTIVE"

    now = int(time.time())
    bind = observe_binding(args.assignment)
    delegation = buyer.delegate(worker.public, task_id="demo-effect-1", mode="execute", expires=now + 3600)
    request = worker.request(delegation, task_id="demo-effect-1", payload={"effect": "demo-effect-1"}, mode="execute")
    out = store.apply(
        delegation=delegation,
        request=request,
        task_id="demo-effect-1",
        payload={"effect": "demo-effect-1"},
        effect=effect,
        observe=observe,
        standing=standing,
        bind=bind,
        live_state=lambda: observe_binding(args.assignment),
    )
    assert out["status"] == "COMMITTED", out
    assert out["receipt"]["body"]["binding"] == bind
    stale = dict(bind, accepted_head="0" * 40)
    delegation2 = buyer.delegate(worker.public, task_id="demo-effect-2", mode="execute", expires=now + 3600)
    request2 = worker.request(delegation2, task_id="demo-effect-2", payload={"effect": "demo-effect-2"}, mode="execute")
    try:
        store.apply(
            delegation=delegation2,
            request=request2,
            task_id="demo-effect-2",
            payload={"effect": "demo-effect-2"},
            effect=lambda db: db.execute("INSERT INTO application_effects VALUES (?,?)", ("demo-effect-2", 1)),
            observe=lambda db: True,
            standing=standing,
            bind=stale,
            live_state=lambda: observe_binding(args.assignment),
        )
        return _fail("stale binding must refuse")
    except EffectDenied as exc:
        assert str(exc) == "effect_binding_stale", exc
    delegation3 = buyer.delegate(worker.public, task_id="demo-effect-3", mode="execute", expires=now + 3600)
    request3 = worker.request(delegation3, task_id="demo-effect-3", payload={"effect": "demo-effect-3"}, mode="execute")
    store.revoke(delegation3)
    try:
        store.apply(
            delegation=delegation3,
            request=request3,
            task_id="demo-effect-3",
            payload={"effect": "demo-effect-3"},
            effect=lambda db: None,
            observe=lambda db: True,
            standing=standing,
            bind=bind,
            live_state=lambda: observe_binding(args.assignment),
        )
        return _fail("revoked delegation must refuse")
    except EffectDenied as exc:
        assert str(exc) == "grant_revoked", exc
    again = store.apply(
        delegation=delegation,
        request=request,
        task_id="demo-effect-1",
        payload={"effect": "demo-effect-1"},
        effect=effect,
        observe=observe,
        standing=standing,
        bind=bind,
        live_state=lambda: observe_binding(args.assignment),
    )
    assert again["status"] == "ALREADY_COMMITTED"
    assert again["receipt"] == out["receipt"]
    rec_delegation = buyer.delegate(worker.public, task_id="demo-effect-1", mode="recover", expires=now + 3600)
    rec_request = worker.request(rec_delegation, task_id="demo-effect-1", payload={"effect": "demo-effect-1"}, mode="recover")
    recovered = store.recover(delegation=rec_delegation, request=rec_request, task_id="demo-effect-1", payload={"effect": "demo-effect-1"})
    assert recovered["status"] == "RECOVERED"
    assert recovered["receipt"] == out["receipt"]
    _emit({
        "status": "EFFECT_BINDING_OK",
        "bound_apply": "COMMITTED",
        "stale": "effect_binding_stale",
        "revoked": "grant_revoked",
        "replay": "ALREADY_COMMITTED",
        "recovery": "RECOVERED",
    })
    return 0


def _add_common(parser):
    parser.add_argument("--dir", required=True)
    parser.add_argument("--worker-uid", type=int, default=65534)
    parser.add_argument("--service-socket", default=None)
    parser.add_argument("--client-key", default=None)
    parser.add_argument("--principal-id", default=None)
    parser.add_argument("--client-workspace", default=None)


def cmd_watchdog_record(args) -> int:
    config = _load_config(Path(args.dir).resolve())
    from graph_watchdog import VerifiedAttempt
    from durable_watchdog import DurableGraphWatchdog
    wd = DurableGraphWatchdog(config["project_db"], threshold=int(getattr(args, "threshold", 3)))
    att = VerifiedAttempt(
        deliverable_id=args.deliverable,
        basis=args.basis,
        worker_id=args.worker,
        attempt_id=args.attempt,
        progress_before=int(args.progress_before),
        progress_after=int(args.progress_after),
        receiver_verified=bool(args.verified),
        external_mutation=getattr(args, "mutation", "none"),
    )
    res = wd.record(att)
    _emit({"status": "WATCHDOG_RECORDED", "advisory": res})
    return 0


def cmd_watchdog_status(args) -> int:
    config = _load_config(Path(args.dir).resolve())
    from durable_watchdog import DurableGraphWatchdog
    wd = DurableGraphWatchdog(config["project_db"], threshold=int(getattr(args, "threshold", 3)))
    st = wd.status(args.deliverable, args.basis)
    _emit({"status": "OK", "watchdog_scope": st})
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="openline",
        description="OpenLine Living Projects CLI: receiver-owned authority, dependency graph, and verified memory for coding agents.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="create a Living Project")
    p.add_argument("--dir", required=True)
    p.add_argument("--project-id", default="openline-demo")
    p.add_argument("--workers", default="alice,bob")
    p.add_argument("--validator", default=None)
    p.add_argument("--worker-uid", type=int, default=65534)
    p.add_argument("--no-initial-break", action="store_true")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("assign", help="contributor-signed repair assignment")
    _add_common(p)
    p.add_argument("--assignment", required=True)
    p.add_argument("--deliverable", default=None)
    p.add_argument("--worker", required=True)
    p.add_argument("--basis", required=True)
    p.add_argument("--allowed-paths", default=None)
    p.add_argument("--as-member", default=None)
    p.add_argument("--signature", default=None)
    p.add_argument("--post-stop-signature", default=None)
    p.add_argument("--post-stop-owner-sign", action="store_true")
    p.set_defaults(func=cmd_assign)

    p = sub.add_parser("prepare", help="prepare a candidate worktree")
    _add_common(p)
    p.add_argument("--assignment", required=True)
    p.add_argument("--propose-memory", default=None)
    p.add_argument("--diagnosis", default=None)
    p.add_argument("--lesson", default=None)
    p.set_defaults(func=cmd_prepare)

    p = sub.add_parser("intercept", help="gate a prepared candidate")
    _add_common(p)
    p.add_argument("--assignment", required=True)
    p.set_defaults(func=cmd_intercept)

    p = sub.add_parser("verify", help="offline + live receipt verification")
    p.add_argument("--receipt", required=True)
    p.add_argument("--pinned-key", required=True)
    p.add_argument("--git", default=None)
    p.add_argument("--project-db", default=None)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("status", help="project head, standings, boundary")
    _add_common(p)
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("graph", help="inspect dependency graph, what-if impact, and Claim Graph")
    _add_common(p)
    p.add_argument("--changed", action="append", default=[])
    p.add_argument("--add-claim", default=None)
    p.add_argument("--subject", default=None)
    p.add_argument("--predicate", default=None)
    p.add_argument("--object", default=None)
    p.add_argument("--signer", default=None)
    p.add_argument("--signature", default=None)
    p.add_argument("--sign-local", action="store_true")
    p.set_defaults(func=cmd_graph)

    p = sub.add_parser("recover", help="reconcile an interrupted promotion")
    _add_common(p)
    p.add_argument("--assignment", required=True)
    p.set_defaults(func=cmd_recover)

    p = sub.add_parser("change", help="owner-signed dependency change (supports single or multiple --change DEP=CONTRACT)")
    _add_common(p)
    p.add_argument("--dependency", default=None)
    p.add_argument("--contract", default=None)
    p.add_argument("--change", dest="changes", action="append", default=[])
    p.add_argument("--signature", default=None)
    p.set_defaults(func=cmd_change)

    p = sub.add_parser("revoke", help="owner-signed member revocation")
    _add_common(p)
    p.add_argument("--member", required=True)
    p.add_argument("--signature", default=None)
    p.set_defaults(func=cmd_revoke)

    p = sub.add_parser("rotate-key", help="rotate owner or member Ed25519 key")
    _add_common(p)
    p.add_argument("--role", choices=("owner", "member"), default="member")
    p.add_argument("--member", default=None)
    p.add_argument("--signature", default=None)
    p.set_defaults(func=cmd_rotate_key)

    p = sub.add_parser("memory", help="inspect, propose, or inherit Verified Experience")
    _add_common(p)
    p.add_argument("--deliverable", default=None)
    p.add_argument("--propose", default=None)
    p.add_argument("--assignment", default=None)
    p.add_argument("--worker", default=None)
    p.add_argument("--basis", default=None)
    p.add_argument("--patch-sha256", default=None)
    p.add_argument("--diagnosis", default=None)
    p.add_argument("--lesson", default=None)
    p.set_defaults(func=cmd_memory)

    p = sub.add_parser("history", help="chronological ledger events, accepted Git commits, and signed receipts")
    _add_common(p)
    p.set_defaults(func=cmd_history)

    p = sub.add_parser("watchdog-record", help="record a receiver-verified attempt in DurableGraphWatchdog")
    _add_common(p)
    p.add_argument("--deliverable", required=True)
    p.add_argument("--basis", required=True)
    p.add_argument("--worker", required=True)
    p.add_argument("--attempt", required=True)
    p.add_argument("--progress-before", type=int, default=0)
    p.add_argument("--progress-after", type=int, default=0)
    p.add_argument("--verified", action="store_true", default=False)
    p.add_argument("--mutation", default="none", choices=("none", "confirmed", "uncertain"))
    p.add_argument("--threshold", type=int, default=3)
    p.set_defaults(func=cmd_watchdog_record)

    p = sub.add_parser("watchdog-status", help="read-only DurableGraphWatchdog scope status")
    _add_common(p)
    p.add_argument("--deliverable", required=True)
    p.add_argument("--basis", required=True)
    p.add_argument("--threshold", type=int, default=3)
    p.set_defaults(func=cmd_watchdog_status)

    p = sub.add_parser("doctor", help="diagnostics for boundary, keys, continuity, and agent runtimes")
    _add_common(p)
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("guard", help="seal or verify project directory with ReceiverGuard")
    _add_common(p)
    p.add_argument("--verify-only", action="store_true")
    p.set_defaults(func=cmd_guard)

    p = sub.add_parser("kill-switch", help="owner-controlled Kill Switch standing, stop, clear, conformance, and evidence audit")
    p.add_argument("--dir", default=None)
    p.add_argument("--worker-uid", type=int, default=65534)
    p.add_argument("--action", choices=("status", "stop", "clear", "conformance", "audit"), default="status")
    p.add_argument("--reason", default=None)
    p.add_argument("--signature", default=None)
    p.add_argument("--expected-epoch", type=int, default=None, help="epoch bound into detached owner signature")
    p.add_argument("--role", default="owner")
    p.add_argument("--output-dir", default=None)
    p.add_argument("--evidence-path", default=None)
    p.add_argument("--races", type=int, default=20)
    p.set_defaults(func=cmd_kill_switch)

    p = sub.add_parser("replay", help="run mandatory 12-step Living Projects end-to-end replay and comparison")
    p.add_argument("--output-dir", default=None)
    p.set_defaults(func=cmd_replay)

    p = sub.add_parser("effect-demo", help="V-05 binding sequence")
    _add_common(p)
    p.add_argument("--assignment", required=True)
    p.set_defaults(func=cmd_effect_demo)

    p = sub.add_parser("mcp", help="start the MCP stdio server")
    _add_common(p)
    p.set_defaults(func=lambda a: _run_mcp(a))

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ProjectRefused, ProtectError, RuntimeError) as exc:
        return _fail(f"{type(exc).__name__}: {exc}")


def _run_mcp(args) -> int:
    sys.path.insert(0, str(HERE))
    from mcp_server import run_server  # noqa: E402
    project_dir = Path(args.dir).resolve()
    config = _load_config(project_dir)
    return run_server(config, worker_uid=args.worker_uid)


if __name__ == "__main__":
    raise SystemExit(main())
