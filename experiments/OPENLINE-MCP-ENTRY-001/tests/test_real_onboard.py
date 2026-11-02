"""Actual private-venv diagnostic and host snippet acceptance."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from openline_mcp_entry.onboard import generate, invoke, probe
try:
    from openline_mcp_entry.quickstart import bootstrap
except ModuleNotFoundError as _exc:
    raise unittest.SkipTest(f'external openline_lite package not installed offline: {_exc}')
from openline_mcp_entry.verify import verify_receipt

class RealOnboard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        cls.home=Path(cls.tmp.name)/"receiver"
        bootstrap(cls.home)
        cls.config=cls.home/"operator-config.json"

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_real_profile_invocation_and_signature(self):
        info=invoke(str(self.config),"check","commit")
        self.assertEqual(info["status"],"PASS")
        self.assertTrue(info["actual_openline_check"])
        self.assertFalse(info["external_host_tested"])
        d=info["data"]
        self.assertEqual(d["result"]["decision"],"COMMIT")
        receipt=self.home/"records"/d["record_id"]/"decision.receipt.json"
        verified=verify_receipt(receipt,self.home/"gate-trust.json",
             expected_sha256=d["result"]["decision_receipt_sha256"],expected_decision="COMMIT")
        self.assertEqual(verified["signature"],"VALID")
        self.assertEqual(invoke(str(self.config),"impact","changed-source")["status"],"PASS")
        denied=invoke(str(self.config),"check","not-a-profile")
        self.assertEqual(denied["status"],"REFUSED")

    def test_cli_first_use_and_host_via_actual_venv(self):
        cmd=[sys.executable,"-m","openline_mcp_entry.onboard",
             "--operator-config",str(self.config),"--check-profile","commit"]
        result=subprocess.run(cmd,capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(json.loads(result.stdout)["actual_openline_check"])
        generated=shlex.split(generate("codex",str(self.config)))
        self.assertEqual(generated[generated.index("--")+1],str(Path(sys.executable).absolute()))
        self.assertEqual(generated[-2:],["-m","openline_mcp_entry.server"])
        for host in ("cursor","claude-desktop"):
            d=json.loads(generate(host,str(self.config)))
            cfg=d["mcpServers"]["openline-local"]
            self.assertEqual(cfg["command"],str(Path(sys.executable).absolute()))
            self.assertNotIn((self.home/"gate.key").read_text().strip(),json.dumps(d))

    def test_genuine_dependency_probe_only(self):
        d=probe(str(self.config))
        self.assertEqual(d["status"],"PASS")
        self.assertFalse(d["real_signed_check_executed"])
        self.assertFalse(d["external_host_tested"])

if __name__=="__main__":
    unittest.main()
