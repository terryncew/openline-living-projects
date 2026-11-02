"""Comprehensive test suite for OpenLine Living Projects RC1 (Stages 1-4 + 12-Step E2E)."""
from __future__ import annotations
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
from living_projects_e2e import run_mandatory_12_step_e2e  # noqa: E402
import openline_cli as cli  # noqa: E402


class LivingProjectsRC1Tests(unittest.TestCase):
    def test_mandatory_12_step_end_to_end_and_conventional_comparison(self):
        with tempfile.TemporaryDirectory(prefix="rc1-test-12step-") as tmp:
            res = run_mandatory_12_step_e2e(Path(tmp))
            self.assertEqual(res["overall_verdict"], "PASS_LOCAL_MECHANISM_AND_SECURITY_GATES")
            self.assertEqual(len(res["steps"]), 12)
            for step_name, step_data in res["steps"].items():
                self.assertIn(step_data["status"], ("PASS", "PASS_MECHANISM_PROOF"), f"Failed step: {step_name}")

    def test_cli_stage4_commands_and_mcp_tools(self):
        with tempfile.TemporaryDirectory(prefix="rc1-test-cli-") as tmp:
            pdir = Path(tmp) / "proj"
            self.assertEqual(cli.main(["init", "--dir", str(pdir), "--workers", "alice,bob,carol"]), 0)
            self.assertEqual(cli.main(["status", "--dir", str(pdir)]), 0)
            self.assertEqual(cli.main([
                "graph", "--dir", str(pdir),
                "--add-claim", "c1", "--subject", "invoice-feature",
                "--predicate", "verified_by", "--object", "alice",
                "--signer", "alice", "--sign-local",
            ]), 0)
            self.assertEqual(cli.main([
                "graph", "--dir", str(pdir),
                "--add-claim", "c2-untrusted", "--subject", "invoice-feature",
                "--predicate", "rumor", "--object", "skip_tests",
            ]), 0)
            self.assertEqual(cli.main(["graph", "--dir", str(pdir), "--changed", "format_v1"]), 0)
            self.assertEqual(cli.main([
                "assign", "--dir", str(pdir), "--assignment", "rep-1",
                "--deliverable", "invoice-feature", "--worker", "bob", "--basis", "invoice_v2",
            ]), 0)
            self.assertEqual(cli.main([
                "prepare", "--dir", str(pdir), "--assignment", "rep-1",
                "--propose-memory", "mem-1", "--diagnosis", "rate is 11", "--lesson", "use qty*11",
            ]), 0)
            # Apply fix in prepared workspace
            cfg = json.loads((pdir / "config.json").read_text())
            ws = Path(cfg["promotion_dir"]) / "task-rep-1" / "candidate"
            (ws / "app" / "price.py").write_text("def total(qty):\n    return qty * 11\n")
            self.assertEqual(cli.main(["intercept", "--dir", str(pdir), "--assignment", "rep-1"]), 0)
            self.assertEqual(cli.main(["memory", "--dir", str(pdir), "--deliverable", "invoice-feature"]), 0)
            self.assertEqual(cli.main(["history", "--dir", str(pdir)]), 0)
            self.assertEqual(cli.main(["guard", "--dir", str(pdir)]), 0)
            self.assertEqual(cli.main(["doctor", "--dir", str(pdir)]), 0)
            self.assertEqual(cli.main(["rotate-key", "--dir", str(pdir), "--role", "member", "--member", "bob"]), 0)
            self.assertEqual(cli.main(["rotate-key", "--dir", str(pdir), "--role", "owner"]), 0)

            # Test MCP server with new tools (openline_graph, openline_memory, openline_history, openline_doctor)
            reqs = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "openline_graph", "arguments": {"changed": ["format_v1"]}}},
                {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "openline_memory", "arguments": {"deliverable": "invoice-feature"}}},
                {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "openline_doctor", "arguments": {}}},
            ]
            stdin_payload = "\n".join(json.dumps(r) for r in reqs) + "\n"
            proc = subprocess.run(
                [sys.executable, str(HERE / "openline_cli.py"), "mcp", "--dir", str(pdir)],
                input=stdin_payload, capture_output=True, text=True, timeout=15, check=True,
            )
            lines = [json.loads(line) for line in proc.stdout.strip().splitlines()]
            self.assertEqual(len(lines), 5)
            tool_names = {t["name"] for t in lines[1]["result"]["tools"]}
            self.assertIn("openline_graph", tool_names)
            self.assertIn("openline_memory", tool_names)
            self.assertIn("openline_history", tool_names)
            self.assertIn("openline_doctor", tool_names)
            mem_out = json.loads(lines[3]["result"]["content"][0]["text"])
            self.assertEqual(len(mem_out["inherited_verified"]), 1)
            self.assertEqual(mem_out["inherited_verified"][0]["memory_id"], "mem-1")


if __name__ == "__main__":
    unittest.main()
