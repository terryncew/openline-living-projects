"""MCP protocol test -- raw JSON-RPC, no official host needed.

Spawns the real `openline mcp` server as a subprocess, runs the full
flow (initialize, tools/list, status, prepare, intercept, verify,
recover, unknown tool, ping), and asserts every response. This proves
the MCP entry point speaks the protocol; it does NOT prove an
official host invocation (that is Gate A, BLOCKED, see
GATE_A_PROTOCOL.md).

Exit 0 only if every asserted step passes. Writes
<project_dir>/mcp_test_evidence.json.
"""
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from engine_loader import load_engines  # noqa: E402

load_engines()
import openline_cli as cli  # noqa: E402


class Client:
    def __init__(self, proc):
        self.proc = proc

    def send(self, obj):
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()

    def read_one(self, expected_id):
        line = self.proc.stdout.readline()
        assert line, "server closed stdout unexpectedly"
        msg = json.loads(line)
        assert msg.get("id") == expected_id, msg
        assert "error" not in msg, msg
        return msg["result"]

    def call(self, call_id, name, args):
        self.send({"jsonrpc": "2.0", "id": call_id, "method": "tools/call",
                   "params": {"name": name, "arguments": args}})
        result = self.read_one(call_id)
        text = result["content"][0]["text"]
        return result, json.loads(text)


def run_test(project_dir: Path):
    project_dir = project_dir.resolve()
    evidence = {}
    rc = cli.cmd_init(SimpleNamespace(
        dir=str(project_dir), project_id="openline-mcp-test",
        workers="alice,bob,carol", validator=None, worker_uid=65534))
    assert rc == 0, rc
    config = cli._load_config(project_dir)
    assert cli.cmd_assign(SimpleNamespace(
        dir=str(project_dir), worker_uid=65534, assignment="repair-mcp",
        worker="bob", basis="invoice_v2", as_member=None,
        signature=None)) == 0
    script = HERE / "openline"
    proc = subprocess.Popen(
        [sys.executable, str(script), "mcp", "--dir", str(project_dir)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True)
    try:
        client = Client(proc)
        client.send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                     "params": {"protocolVersion": "2025-06-18",
                                "capabilities": {},
                                "clientInfo": {"name": "mcp-protocol-test",
                                               "version": "0.1.0"}}})
        result = client.read_one(1)
        assert result["serverInfo"]["name"] == "openline-release", result
        assert result["protocolVersion"] == "2025-06-18", result
        # Notification must produce no response: the next read must be
        # the tools/list reply (id 2), not a notification reply.
        client.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        client.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        result = client.read_one(2)
        names = [t["name"] for t in result["tools"]]
        assert {"openline_status", "openline_prepare",
                "openline_intercept", "openline_verify_receipt",
                "openline_recover"} <= set(names), names
        evidence["tools"] = names
        print("MCP initialize + tools/list: 5 tools")
        _r, status = client.call(3, "openline_status", {})
        assert status["head"], status
        assert status["boundary"] == [], status
        print("MCP status: head + clean boundary")
        _r, prepared = client.call(4, "openline_prepare",
                                   {"assignment": "repair-mcp"})
        workspace = Path(prepared["workspace"])
        assert workspace.is_dir()
        (workspace / "app" / "price.py").write_text(
            "def total(qty):\n    return qty * 11\n")
        _r, intercepted = client.call(5, "openline_intercept",
                                      {"assignment": "repair-mcp"})
        assert intercepted["verdict"] == "ACCEPTED", intercepted
        receipt_path = intercepted["receipt_path"]
        print("MCP prepare + intercept: ACCEPTED")
        _r, verified = client.call(6, "openline_verify_receipt",
                                   {"receipt_path": receipt_path,
                                    "pinned_key": config["receiver_pub"],
                                    "git_dir": config["accepted_git"],
                                    "project_db": config["project_db"]})
        checked = verified["checked"]
        assert checked["crypto"] == "VERIFIED", checked
        assert checked["git_verified"] and checked["continuity_verified"]
        print("MCP verify: receipt VERIFIED (crypto + git + ledger)")
        _r, recovered = client.call(7, "openline_recover",
                                    {"assignment": "repair-mcp"})
        assert recovered["verdict"] == "ACCEPTED", recovered
        print("MCP recover: ACCEPTED (idempotent)")
        result, _body = client.call(8, "openline_nope", {})
        assert result.get("isError") is True, result
        client.send({"jsonrpc": "2.0", "id": 9, "method": "ping"})
        assert client.read_one(9) == {}
        print("MCP unknown tool -> isError, ping OK")
        evidence["flow"] = "initialize_list_status_prepare_intercept_" \
            "verify_recover_ping"
    finally:
        proc.stdin.close()
        proc.wait(timeout=30)
    assert proc.returncode == 0, proc.returncode
    (project_dir / "mcp_test_evidence.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print("MCP PROTOCOL TEST: ALL STEPS PASS")
    return 0


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", required=True)
    args = parser.parse_args()
    return run_test(Path(args.dir))


if __name__ == "__main__":
    raise SystemExit(main())
