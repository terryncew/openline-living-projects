"""OpenLine Living Projects MCP server -- stdio JSON-RPC, standard library only.

Tools (receiver-side inspection, gating, memory inheritance, diagnostics, and verification):
- openline_status: head, standings, assignments, dependency contracts, boundary check.
- openline_graph: dependency graph, what-if impact analysis, and Claim Graph (CRYPTOGRAPHICALLY_BOUND vs UNTRUSTED_ADVISORY).
- openline_prepare: prepare a candidate worktree for an assignment (and optionally propose a CANDIDATE memory).
- openline_intercept: gate a prepared candidate (ACCEPTED / STOPPED / UNKNOWN) and ratchet Earned Memory.
- openline_verify_receipt: offline receipt verification against a pinned key, optionally against live Git head and project ledger.
- openline_recover: reconcile an interrupted promotion idempotently.
- openline_memory: inspect or inherit Verified Experience (INHERITED vs QUESTIONED vs QUARANTINED vs CANDIDATE).
- openline_history: chronological ledger events, accepted Git commits, and signed receipts.
- openline_doctor: boundary, key-pinning, continuity, and runtime health check.
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
        "OpenLine project head, deliverable standings, assignments, and receiver-boundary check.",
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
        "openline_doctor",
        "Run receiver boundary, continuity, and Git-vs-SQLite health diagnostics.",
        {},
        [],
    ),
]


class Server:
    def __init__(self, config: dict, worker_uid: int):
        import openline_cli as cli  # noqa: E402
        self.cli = cli
        self.config = config
        _promo, project, protect = cli._build_engines(config, worker_uid)
        self.promo = _promo
        self.project = project
        self.protect = protect
        self.worker_uid = worker_uid

    def _text(self, obj, is_error=False):
        return {
            "content": [{"type": "text", "text": json.dumps(obj, sort_keys=True, indent=2)}],
            "isError": is_error,
        }

    def call(self, name, args):
        if name == "openline_status":
            snap = self.project.snapshot()
            return self._text({
                "project_id": self.project.id,
                "head": self.promo.accepted(),
                "contract": snap["project"][2],
                "project_status": snap["project"][4],
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
            wd = DurableGraphWatchdog(self.project.db_path, threshold=int(args.get("threshold", 3)))
            return self._text({"status": "OK", "watchdog_scope": wd.status(args["deliverable"], args["basis"])})
        if name == "openline_watchdog_record":
            from graph_watchdog import VerifiedAttempt
            from durable_watchdog import DurableGraphWatchdog
            # JSON types must not be coerced into trusted progress evidence.
            for field in ("progress_before", "progress_after"):
                if field in args and (type(args[field]) is not int):
                    raise ValueError(f"{field} must be an integer")
            if "receiver_verified" in args and type(args["receiver_verified"]) is not bool:
                raise ValueError("receiver_verified must be a boolean")
            wd = DurableGraphWatchdog(self.project.db_path, threshold=int(args.get("threshold", 3)))
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
        if name == "openline_doctor":
            cont = continuity_audit(Path(self.config["project_db"]))
            boundary = check_receiver_boundary(
                self.protect.receiver_paths(), receiver_uid=os.getuid(), worker_uid=self.worker_uid
            )
            return self._text({
                "project_id": self.project.id,
                "boundary_issues": boundary,
                "continuity": cont["assessment"],
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
