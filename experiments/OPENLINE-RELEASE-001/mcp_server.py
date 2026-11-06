"""OpenLine Living Projects MCP server -- stdio JSON-RPC, standard library only.

Tools (receiver-side inspection, gating, memory inheritance, diagnostics, and verification):
- openline_status: head, standings, assignments, dependency contracts, Kill Switch standing, boundary check.
- openline_graph: dependency graph, what-if impact analysis, and Claim Graph (CRYPTOGRAPHICALLY_BOUND vs UNTRUSTED_ADVISORY).
- openline_prepare: prepare a candidate worktree for an assignment (and optionally propose a CANDIDATE memory).
- openline_intercept: gate a prepared candidate (ACCEPTED / STOPPED / UNKNOWN) and ratchet Earned Memory.
- openline_verify_receipt: offline receipt verification against a pinned key, optionally against live Git head and project ledger.
- openline_recover: reconcile an interrupted promotion idempotently.
- openline_memory: inspect or inherit Verified Experience (INHERITED vs QUESTIONED vs QUARANTINED vs CANDIDATE).
- openline_history: chronological ledger events, accepted Git commits, and signed receipts.
- openline_kill_switch_status: read authoritative Kill Switch standing (stopped, epoch, stop_seq, clear_seq, reason).
- openline_kill_switch_stop: owner-signed emergency Kill Switch STOP (advances epoch and records monotonic stop_seq).
- openline_kill_switch_clear: owner-signed clear_stop (advances epoch while preserving stop_seq so pre-STOP authority stays dead).
- openline_kill_switch_audit: offline hash-chain and verdict audit over Kill Switch JSONL evidence.
- openline_doctor: boundary, key-pinning, continuity, Kill Switch, and runtime health check.
"""
from __future__ import annotations
from contextlib import closing
import hashlib
import json
import os
import shutil
import sqlite3
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from engine_loader import load_engines  # noqa: E402

load_engines()

from protect import check_receiver_boundary, verify_receipt  # noqa: E402
from continuity import audit as continuity_audit  # noqa: E402
import living_project  # noqa: E402

SUPPORTED_PROTOCOLS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
SERVER_VERSION = "0.3.0-rc3"


def _tool(name, description, properties, required):
    return {
        "name": name,
        "description": description,
        "inputSchema": {"type": "object", "properties": properties, "required": required},
    }


TOOLS = [
    _tool(
        "openline_status",
        "OpenLine project head, deliverable standings, assignments, Kill Switch standing, and receiver-boundary check.",
        {},
        [],
    ),
    _tool(
        "openline_graph",
        "Inspect project dependency graph, hypothetical impact (--changed), and Claim Graph (CRYPTOGRAPHICALLY_BOUND vs UNTRUSTED_ADVISORY).",
        {"changed": {"type": "array", "items": {"type": "string"}}},
        [],
    ),
    _tool(
        "openline_prepare",
        "Prepare a candidate worktree for a signed repair assignment. Optionally record a CANDIDATE memory hypothesis.",
        {
            "assignment": {"type": "string"},
            "memory_id": {"type": "string"},
            "diagnosis": {"type": "string"},
            "lesson": {"type": "string"},
        },
        ["assignment"],
    ),
    _tool(
        "openline_intercept",
        "Run the receiver gate on a prepared candidate. Returns the signed incident receipt and verdict.",
        {"assignment": {"type": "string"}},
        ["assignment"],
    ),
    _tool(
        "openline_verify_receipt",
        "Verify a signed receipt offline against a pinned receiver public key, optionally against live Git head and project ledger.",
        {
            "receipt_path": {"type": "string"},
            "pinned_key": {"type": "string"},
            "git_dir": {"type": "string"},
            "project_db": {"type": "string"},
        },
        ["receipt_path", "pinned_key"],
    ),
    _tool(
        "openline_recover",
        "Reconcile an interrupted (post-CAS) promotion idempotently.",
        {"assignment": {"type": "string"}},
        ["assignment"],
    ),
    _tool(
        "openline_memory",
        "Inspect or inherit Verified Experience (INHERITED vs QUESTIONED vs QUARANTINED vs CANDIDATE).",
        {"deliverable": {"type": "string"}},
        [],
    ),
    _tool(
        "openline_history",
        "Retrieve chronological project ledger events and signed incident receipts.",
        {},
        [],
    ),
    _tool(
        "openline_watchdog_status",
        "Inspect read-only DurableGraphWatchdog scope status (deliverable, basis).",
        {"deliverable": {"type": "string"}, "basis": {"type": "string"}, "threshold": {"type": "integer"}},
        ["deliverable", "basis"],
    ),
    _tool(
        "openline_watchdog_record",
        "Record a receiver-verified attempt in DurableGraphWatchdog (advisory only, receiver_authorization=NONE).",
        {
            "deliverable": {"type": "string"},
            "basis": {"type": "string"},
            "worker": {"type": "string"},
            "attempt": {"type": "string"},
            "progress_before": {"type": "integer"},
            "progress_after": {"type": "integer"},
            "receiver_verified": {"type": "boolean"},
            "external_mutation": {"type": "string"},
            "threshold": {"type": "integer"},
        },
        ["deliverable", "basis", "worker", "attempt"],
    ),
    _tool(
        "openline_kill_switch_status",
        "Inspect authoritative Kill Switch standing (stopped, epoch, stop_seq, clear_seq, reason).",
        {},
        [],
    ),
    _tool(
        "openline_kill_switch_stop",
        "Issue an owner-controlled emergency Kill Switch STOP (requires externally supplied owner signature bound to expected epoch).",
        {
            "reason": {"type": "string"},
            "signature": {"type": "string"},
            "actor_role": {"type": "string"},
            "expected_epoch": {"type": "integer"},
        },
        ["reason", "signature", "expected_epoch"],
    ),
    _tool(
        "openline_kill_switch_clear",
        "Clear an owner-controlled Kill Switch STOP while preserving monotonic stop_seq so pre-STOP authority stays dead.",
        {
            "reason": {"type": "string"},
            "signature": {"type": "string"},
            "actor_role": {"type": "string"},
            "expected_epoch": {"type": "integer"},
        },
        ["reason", "signature", "expected_epoch"],
    ),
    _tool(
        "openline_kill_switch_audit",
        "Verify hash-chained Kill Switch JSONL evidence offline.",
        {"evidence_path": {"type": "string"}},
        ["evidence_path"],
    ),
    _tool(
        "openline_doctor",
        "Run receiver boundary, continuity, Kill Switch, and Git-vs-SQLite health diagnostics.",
        {},
        [],
    ),
]


class Server:
    def __init__(self, config: dict, worker_uid: int):
        import openline_cli as cli  # noqa: E402
        self.cli = cli
        self.config = config
        self.worker_uid = worker_uid
        sock_path = os.environ.get("OPENLINE_SERVICE_SOCKET") or config.get("service_socket")
        if sock_path:
            from ipc_client import OpenLineIPCClient
            key_path = os.environ.get("OPENLINE_CLIENT_KEY") or config.get("client_key")
            signer_key = cli._read_key(Path(key_path))
            principal_id = os.environ.get("OPENLINE_PRINCIPAL_ID") or config.get("principal_id") or "worker:bob"
            self.ipc_client = OpenLineIPCClient(
                socket_path=Path(sock_path),
                channel=os.environ.get("OPENLINE_IPC_CHANNEL") or config.get("ipc_channel", "worker"),
                deployment_id=config.get("deployment_id", "openline-prod-1"),
                project_id=config["project_id"],
                receiver_id=config.get("receiver_id", "receiver-p1"),
                principal_id=principal_id,
                signer_key=signer_key,
                pinned_receiver_pub=config["receiver_pub"],
            )
            self.promo = None
            self.project = None
            self.protect = None
        else:
            self.ipc_client = None
            _promo, project, protect = cli._build_engines(config, worker_uid)
            self.promo = _promo
            self.project = project
            self.protect = protect

    def _text(self, obj, is_error=False):
        return {
            "content": [{"type": "text", "text": json.dumps(obj, sort_keys=True, indent=2)}],
            "isError": is_error,
        }

    def call(self, name, args):
        if self.ipc_client is not None:
            if name == "openline_status":
                resp = self.ipc_client.call("project.status", {})
                return self._text(resp["result"], is_error=(resp["status"] != "OK"))
            if name == "openline_prepare":
                dest = Path(args.get("client_workspace") or (Path(self.config["dir"]) / f"mcp-client-{args['assignment']}"))
                resp = self.ipc_client.prepare_workspace(
                    args["assignment"],
                    dest,
                    propose_memory=args.get("memory_id"),
                    diagnosis=args.get("diagnosis"),
                    lesson=args.get("lesson"),
                )
                if resp["status"] != "OK":
                    return self._text(resp["result"], is_error=True)
                return self._text({
                    "assignment": args["assignment"],
                    "workspace": resp["result"]["client_workspace"],
                    "snapshot_db": resp["result"]["client_snapshot_db"],
                    "proposed_memory": resp["result"].get("proposed_memory"),
                })
            if name == "openline_intercept":
                ws = Path(args.get("client_workspace") or (Path(self.config["dir"]) / f"mcp-client-{args['assignment']}" / "workspace"))
                resp = self.ipc_client.submit_workspace_proposal(args["assignment"], ws)
                return self._text(resp["result"], is_error=(resp["status"] not in ("ACCEPTED", "STOPPED", "UNKNOWN_RECONCILIATION_REQUIRED")))
            if name == "openline_recover":
                resp = self.ipc_client.call("repair.reconcile", {"assignment_id": args["assignment"]})
                return self._text(resp["result"], is_error=(resp["status"] not in ("ACCEPTED", "STOPPED", "UNKNOWN_RECONCILIATION_REQUIRED")))
            if name == "openline_kill_switch_stop":
                resp = self.ipc_client.call("control.stop", {
                    "reason": args["reason"],
                    "owner_signature": args["signature"],
                    "expected_epoch": args["expected_epoch"],
                })
                return self._text(resp["result"], is_error=(resp["status"] != "OK"))
            if name == "openline_kill_switch_clear":
                resp = self.ipc_client.call("control.clear", {
                    "reason": args["reason"],
                    "owner_signature": args["signature"],
                    "expected_epoch": args["expected_epoch"],
                })
                return self._text(resp["result"], is_error=(resp["status"] != "OK"))
            return self._text({"error": f"tool_not_available_on_worker_ipc:{name}"}, is_error=True)
        if name == "openline_status":
            snap = self.project.snapshot()
            return self._text({
                "project_id": self.project.id,
                "head": self.promo.accepted(),
                "contract": snap["project"][2],
                "project_status": snap["project"][4],
                "kill_switch": self.project.read_stop_state(),
                "deliverables": [{"id": d[0], "member": d[1], "standing": d[2]} for d in snap["deliverables"]],
                "boundary": check_receiver_boundary(
                    self.protect.receiver_paths(), receiver_uid=os.getuid(), worker_uid=self.worker_uid
                ),
            })
        if name == "openline_graph":
            changed = tuple(args.get("changed") or ())
            obs = living_project.observe(Path(self.config["project_db"]), Path(self.config["accepted_git"]), changed=changed)
            with closing(sqlite3.connect(self.project.db_path)) as db:
                claims = [
                    {
                        "claim_id": r[0], "subject": r[1], "predicate": r[2],
                        "object": r[3], "signer_id": r[4], "trust_status": r[5],
                    }
                    for r in db.execute(
                        "SELECT claim_id, subject, predicate, object, signer_id, trust_status FROM claim_graph WHERE project_id=?",
                        (self.project.id,),
                    ).fetchall()
                ]
            obs["claim_graph"] = claims
            return self._text(obs)
        if name == "openline_prepare":
            state = self.promo.prepare(args["assignment"])
            res = {"assignment": args["assignment"], "workspace": state["workspace"]}
            if args.get("memory_id"):
                with closing(sqlite3.connect(self.project.db_path)) as db:
                    row = db.execute(
                        "SELECT deliverable_id, worker_member, basis FROM assignments WHERE id=?",
                        (args["assignment"],),
                    ).fetchone()
                if row:
                    res["proposed_memory"] = self.project.propose_memory(
                        args["memory_id"],
                        row[0],
                        row[1],
                        row[2],
                        hashlib.sha256((args.get("lesson") or "candidate").encode()).hexdigest(),
                        args.get("diagnosis") or "candidate diagnosis",
                        args.get("lesson") or "candidate lesson",
                        assignment_id=args["assignment"],
                    )
            return self._text(res)
        if name == "openline_intercept":
            out = self.protect.intercept(args["assignment"])
            payload = out["receipt"]["payload"]
            return self._text({
                "verdict": out["verdict"],
                "assignment": args["assignment"],
                "incident_id": payload["incident_id"],
                "receipt_path": out["path"],
                "reason": payload["reason"],
                "accepted_ref_before": payload["accepted_ref_before"],
                "accepted_ref_after": payload["accepted_ref_after"],
                "receipt": out["receipt"],
            })
        if name == "openline_verify_receipt":
            receipt = json.loads(Path(args["receipt_path"]).read_text())
            kwargs = {}
            if args.get("git_dir"):
                kwargs["accepted_git"] = Path(args["git_dir"])
            if args.get("project_db"):
                kwargs["project_db"] = Path(args["project_db"])
            checked = verify_receipt(receipt, args["pinned_key"], **kwargs)
            return self._text({"checked": checked})
        if name == "openline_recover":
            out = self.protect.reconcile(args["assignment"])
            payload = out["receipt"]["payload"]
            return self._text({
                "verdict": out["verdict"],
                "assignment": args["assignment"],
                "incident_id": payload["incident_id"],
                "receipt_path": out["path"],
                "reason": payload["reason"],
                "receipt": out["receipt"],
            })
        if name == "openline_memory":
            return self._text(self.project.inherit_memory(args.get("deliverable")))
        if name == "openline_history":
            snap = self.project.snapshot()
            return self._text({
                "project_id": self.project.id,
                "current_accepted_head": self.promo.accepted(),
                "events": snap["events"],
            })
        if name == "openline_watchdog_status":
            from durable_watchdog import DurableGraphWatchdog
            if "threshold" in args and type(args["threshold"]) is not int:
                raise ValueError("threshold must be an integer")
            wd = DurableGraphWatchdog(self.project.db_path, threshold=args.get("threshold", 3))
            return self._text({"status": "OK", "watchdog_scope": wd.status(args["deliverable"], args["basis"])})
        if name == "openline_watchdog_record":
            from graph_watchdog import VerifiedAttempt
            from durable_watchdog import DurableGraphWatchdog
            for field in ("progress_before", "progress_after"):
                if field in args and (type(args[field]) is not int):
                    raise ValueError(f"{field} must be an integer")
            if "receiver_verified" in args and type(args["receiver_verified"]) is not bool:
                raise ValueError("receiver_verified must be a boolean")
            if "threshold" in args and type(args["threshold"]) is not int:
                raise ValueError("threshold must be an integer")
            wd = DurableGraphWatchdog(self.project.db_path, threshold=args.get("threshold", 3))
            att = VerifiedAttempt(
                deliverable_id=args["deliverable"],
                basis=args["basis"],
                worker_id=args["worker"],
                attempt_id=args["attempt"],
                progress_before=args.get("progress_before", 0),
                progress_after=args.get("progress_after", 0),
                receiver_verified=args.get("receiver_verified", True),
                external_mutation=args.get("external_mutation", "none"),
            )
            return self._text({"status": "WATCHDOG_RECORDED", "advisory": wd.record(att)})
        if name == "openline_kill_switch_status":
            return self._text({"status": "OK", "project_id": self.project.id, "kill_switch": self.project.read_stop_state()})
        if name in ("openline_kill_switch_stop", "openline_kill_switch_clear"):
            reason = args["reason"]
            actor_role = args.get("actor_role", "owner")
            act = "issue_stop" if name == "openline_kill_switch_stop" else "clear_stop"
            sig = args.get("signature")
            if not isinstance(sig, str) or not sig:
                raise ValueError("externally signed owner intent required; MCP never signs with owner keys")
            expected_epoch = args.get("expected_epoch")
            if type(expected_epoch) is not int or expected_epoch < 1:
                raise ValueError("expected_epoch required")
            if name == "openline_kill_switch_stop":
                st = self.project.issue_stop(reason, sig, actor_role=actor_role, expected_epoch=expected_epoch)
                return self._text({"status": "KILL_SWITCH_STOPPED", "project_id": self.project.id, "kill_switch": st})
            st = self.project.clear_stop(reason, sig, actor_role=actor_role, expected_epoch=expected_epoch)
            return self._text({"status": "KILL_SWITCH_CLEARED", "project_id": self.project.id, "kill_switch": st})
        if name == "openline_kill_switch_audit":
            from kill_switch_auditor import audit_directory, audit_evidence_file
            target = Path(args["evidence_path"]).resolve()
            rep = audit_directory(target) if target.is_dir() else audit_evidence_file(target)
            return self._text(rep)
        if name == "openline_doctor":
            cont = continuity_audit(Path(self.config["project_db"]))
            boundary = check_receiver_boundary(
                self.protect.receiver_paths(), receiver_uid=os.getuid(), worker_uid=self.worker_uid
            )
            return self._text({
                "project_id": self.project.id,
                "boundary_issues": boundary,
                "continuity": cont["assessment"],
                "kill_switch": self.project.read_stop_state(),
                "runtimes": {n: bool(shutil.which(n)) for n in ("codex", "claude", "aider", "opencode", "hermes")},
            })
        return self._text({"error": f"unknown tool: {name}"}, is_error=True)


def run_server(config: dict, worker_uid: int) -> int:
    server = Server(config, worker_uid)
    out = sys.stdout
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            out.write(json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}) + "\n")
            out.flush()
            continue
        msg_id = msg.get("id")
        method = msg.get("method")
        if msg_id is None:
            continue
        try:
            if method == "initialize":
                requested = (msg.get("params") or {}).get("protocolVersion")
                version = requested if requested in SUPPORTED_PROTOCOLS else "2025-06-18"
                result = {
                    "protocolVersion": version,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "openline-release", "version": SERVER_VERSION},
                }
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "tools/call":
                params = msg.get("params") or {}
                try:
                    result = server.call(params.get("name"), params.get("arguments") or {})
                except Exception as exc:
                    result = {"content": [{"type": "text", "text": json.dumps({"error": f"{type(exc).__name__}: {exc}"})}], "isError": True}
            else:
                out.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": "method not found"}}) + "\n")
                out.flush()
                continue
        except Exception as exc:
            out.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32603, "message": f"{type(exc).__name__}: {exc}"}}) + "\n")
            out.flush()
            continue
        out.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result}) + "\n")
        out.flush()
    return 0
