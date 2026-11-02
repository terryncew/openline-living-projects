"""Real-engine acceptance, independently pinned receiver receipts, no mocked CLI.

Tests generate disposable signed samples with OpenLine Lite v0.6.0 at a pinned
source SHA, then run actual entrypoints through stdin/stdout and direct CLI.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from openline_mcp_entry.engine import ConfigurationError, OperatorConfig
try:
    from openline_mcp_entry.quickstart import bootstrap
except ModuleNotFoundError as _exc:
    raise unittest.SkipTest(f'external openline_lite package not installed offline: {_exc}')
from openline_mcp_entry.verify import verify_receipt

MESSAGE_BASE = {"jsonrpc": "2.0"}


def _rpc(config: Path, calls: list[dict]) -> tuple[list[dict], str]:
    env = {**os.environ, "OPENLINE_MCP_CONFIG": str(config)}
    proc = subprocess.run(
        [sys.executable, "-m", "openline_mcp_entry.server"],
        input="\n".join(json.dumps(x) for x in calls) + "\n", text=True,
        capture_output=True, timeout=30, env=env,
    )
    if proc.returncode:
        raise AssertionError("server process failed: " + proc.stderr[:2000])
    return [json.loads(x) for x in proc.stdout.splitlines()], proc.stderr


def _calls(*requested: tuple[str, str]) -> list[dict]:
    frames = [
        {**MESSAGE_BASE, "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "independent-integration-test", "version": "1"}}},
        {**MESSAGE_BASE, "method": "notifications/initialized"},
        {**MESSAGE_BASE, "id": 2, "method": "tools/list", "params": {}},
    ]
    for idx, (tool, profile) in enumerate(requested, start=3):
        frames.append({**MESSAGE_BASE, "id": idx, "method": "tools/call",
                       "params": {"name": tool, "arguments": {"profile": profile}}})
    return frames


class GenuineIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.home = cls.root / "receiver"
        bootstrap(cls.home)
        cls.config = cls.home / "operator-config.json"
        cls.trust = cls.home / "gate-trust.json"
        cls.results = {}

    @classmethod
    def tearDownClass(cls):
        if os.getenv("OPENLINE_MCP_EVIDENCE_OUTPUT"):
            p = Path(os.environ["OPENLINE_MCP_EVIDENCE_OUTPUT"])
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(cls.results, sort_keys=True, indent=2) + "\n")
            print("EVIDENCE_SHA256=" + hashlib.sha256(p.read_bytes()).hexdigest())
            print("EVIDENCE_PATH=" + str(p))
        cls.temp.cleanup()

    def test_01_real_mcp_and_receipts(self):
        requested = [
            ("openline_check", "commit"), ("openline_check", "deny"),
            ("openline_check", "quarantine"), ("openline_check", "tampered-evidence"),
            ("openline_impact", "changed-source"),
        ]
        replies, stderr = _rpc(self.config, _calls(*requested))
        self.assertEqual(len(replies), 7)
        self.assertEqual(replies[0]["result"]["protocolVersion"], "2025-11-25")
        self.assertEqual({x["name"] for x in replies[1]["result"]["tools"]},
                         {"openline_check", "openline_impact", "openline_capabilities"})
        decisions = {}
        for (tool, profile), message in zip(requested, replies[2:]):
            reply = message["result"]
            self.assertFalse(reply["isError"], (profile, reply))
            data = reply["structuredContent"]
            self.assertEqual(data["runtime_permission"], "NONE")
            self.assertEqual(data["engine"], "openline-lite")
            if tool == "openline_check":
                expected = {"commit": "COMMIT", "deny": "DENY",
                            "quarantine": "QUARANTINE", "tampered-evidence": "DENY"}[profile]
                payload = data["result"]
                self.assertEqual(payload["decision"], expected)
                self.assertEqual(payload["gate"]["key_mode"], "pinned_file")
                original = self.home / "records" / data["record_id"] / "decision.receipt.json"
                verified = verify_receipt(original, self.trust,
                    expected_sha256=payload["decision_receipt_sha256"],
                    expected_decision=expected)
                self.assertEqual(verified["signature"], "VALID")
                decisions[profile] = {"disposition": expected,
                    "original_receipt_sha256": verified["original_receipt_sha256"],
                    "record_id": data["record_id"]}
            else:
                result = data["result"]["result"]
                idx = data["result"]["index"]["decisions"]
                labels = {x["decision_id"]: x["label"] for x in idx}
                self.assertEqual({labels[x] for x in result["reopen"]}, {"code"})
                self.assertEqual({labels[x] for x in result["retain"]}, {"docs"})
                self.assertEqual({labels[x] for x in result["undetermined"]}, {"notes"})
                self.assertEqual(result["runtime_permission"], "NONE")
                self.assertEqual(len(result["invalidated_evidence_sha256"]), 1)
                self.__class__.results["impact_result_sha256"] = result["result_sha256"]
                for item in json.loads((self.home / "impact-pack.json").read_text())["decisions"]:
                    source = self.home / item["decision_receipt"]
                    self.assertEqual(verify_receipt(source, self.trust, expected_decision="COMMIT")["signature"], "VALID")
        key_text = (self.home / "gate.key").read_text().strip()
        self.assertNotIn(key_text, json.dumps(replies) + stderr)
        self.__class__.results["checks"] = decisions
        self.__class__.results["impact"] = {
            "REOPEN": ["code"], "RETAIN": ["docs"], "UNDETERMINED": ["notes"],
            "signed_decisions_independently_verified": 3,
        }
        self.__class__.results["real_engine"] = True
        self.__class__.results["original_gate_signature_independent_check"] = True

    def test_02_refusal_protocol_and_paths(self):
        msgs = _calls(("openline_check", "unknown-profile"),
                      ("openline_check", "../../etc/shadow"))
        msgs.extend([
            {**MESSAGE_BASE, "id": 5, "method": "tools/call",
             "params": {"name": "openline_check", "arguments": {
                "profile": "commit", "command": "sh -c id", "key": "untrusted"}}},
            {**MESSAGE_BASE, "id": 6, "method": "tools/call",
             "params": {"name": "openline_repair", "arguments": {}}},
            {**MESSAGE_BASE, "id": 7, "method": "tools/call",
             "params": {"name": "openline_check", "arguments": "bad"}},
            {**MESSAGE_BASE, "id": 8, "method": "inexistent/method", "params": {}},
        ])
        before = len(list((self.home / "records").iterdir())) if (self.home / "records").exists() else 0
        replies, _ = _rpc(self.config, msgs)
        for index in (2, 3, 4):
            self.assertTrue(replies[index]["result"]["isError"])
        self.assertEqual(replies[5]["error"]["code"], -32602)
        self.assertTrue(replies[6]["result"]["isError"])
        self.assertEqual(replies[7]["error"]["code"], -32601)
        self.assertEqual(len(list((self.home / "records").iterdir())), before)
        bad_pack = copy.deepcopy(json.loads(self.config.read_text()))
        bad_pack["records_dir"] = str(self.root / "outside")
        bad = self.home / "bad-operator.json"
        bad.write_text(json.dumps(bad_pack))
        with self.assertRaises(ConfigurationError):
            OperatorConfig.load(bad)
        self.__class__.results["profile_path_shell_refusal"] = "PASS"

    def test_03_tamper_impact_and_receipt(self):
        original_path = self.home / "packs/impact-code/accepted/decision.receipt.json"
        original = original_path.read_bytes()
        modified = json.loads(original)
        modified["payload"]["decision"] = "DENY"
        try:
            original_path.write_text(json.dumps(modified))
            response = _rpc(self.config, _calls(("openline_impact", "changed-source")))[0][-1]["result"]
            self.assertTrue(response["isError"], response)
            with self.assertRaises(ValueError):
                verify_receipt(original_path, self.trust)
        finally:
            original_path.write_bytes(original)
        wrong = self.home / "wrong-trust.json"
        wrong.write_text(json.dumps({"other-gate": "00" * 32}))
        with self.assertRaisesRegex(ValueError, "receiver_key_not_pinned"):
            verify_receipt(original_path, wrong)
        self.__class__.results["impact_tampering_and_wrong_key"] = "PASS"

    def test_04_malformed_frames(self):
        env = {**os.environ, "OPENLINE_MCP_CONFIG": str(self.config)}
        bad = subprocess.run(
            [sys.executable, "-m", "openline_mcp_entry.server"],
            input='{"jsonrpc": bad}\n' + "X" * 1_048_577 + "\n",
            text=True, capture_output=True, timeout=15, env=env,
        )
        self.assertEqual(bad.returncode, 0, bad.stderr)
        replies = [json.loads(x) for x in bad.stdout.splitlines()]
        self.assertEqual([x["error"]["code"] for x in replies], [-32700, -32700])
        self.__class__.results["malformed_and_oversize_protocol"] = "PASS"

    def test_05_cli_comparator_and_replay(self):
        config = json.loads(self.config.read_text())
        pack = config["check_profiles"]["commit"]
        def direct():
            return subprocess.run(
                [str(Path(sys.executable).parent / "openline-check"), pack,
                 "--json", "--gate-key", config["gate_key"],
                 "--gate-id", config["gate_id"],
                 "--output-dir", str(self.home / "comparison-cli")],
                text=True, capture_output=True, timeout=20,
            )
        cli = direct()
        self.assertEqual(cli.returncode, 0, cli.stderr)
        self.assertEqual(json.loads(cli.stdout)["decision"], "COMMIT")
        compare = []
        for i in range(3):
            t0 = time.perf_counter()
            a = direct()
            cli_ms = (time.perf_counter() - t0) * 1000
            t1 = time.perf_counter()
            resp = _rpc(self.config, _calls(("openline_check", "commit")))[0][-1]
            mcp_ms = (time.perf_counter() - t1) * 1000
            self.assertEqual(a.returncode, 0)
            self.assertEqual(resp["result"]["structuredContent"]["result"]["decision"], "COMMIT")
            compare.append({"cli_wall_ms": round(cli_ms, 2), "mcp_stdio_wall_ms": round(mcp_ms, 2)})
        one = _rpc(self.config, _calls(("openline_check", "commit"),
                                       ("openline_check", "commit")))[0]
        self.assertNotEqual(one[-2]["result"]["structuredContent"]["record_id"],
                            one[-1]["result"]["structuredContent"]["record_id"])
        self.__class__.results["benchmark"] = {"samples": compare,
            "measurement": "fresh subprocess for each CLI/MCP call, warm installed venv; MCP includes startup/JSON-RPC",
            "model_cost_usd": 0, "external_infrastructure_cost_usd": 0,
            "measured_host_cost": False}
        self.__class__.results["repeated_checks_distinct_records_not_one_use_authorizations"] = True


if __name__ == "__main__":
    unittest.main()
