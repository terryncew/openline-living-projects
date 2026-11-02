"""Real installation security path checks, separate from fake CLI stubs."""
from __future__ import annotations
import json
import os
from pathlib import Path
import tempfile
import unittest
from openline_mcp_entry.engine import ConfigurationError, EngineError, OperatorConfig, OpenLineTools
try:
    from openline_mcp_entry.quickstart import bootstrap
except ModuleNotFoundError as _exc:
    raise unittest.SkipTest(f'external openline_lite package not installed offline: {_exc}')

class RealOperatorFilesystem(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        cls.root=Path(cls.temp.name)
        cls.home=cls.root/"receiver"
        bootstrap(cls.home)
    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_symlinked_config_refused(self):
        alias=self.home/"config-alias"
        alias.symlink_to(self.home/"operator-config.json")
        with self.assertRaisesRegex(ConfigurationError, "operator_config_symlink"):
            OperatorConfig.load(alias)

    def test_symlinked_pack_refused(self):
        conf=json.loads((self.home/"operator-config.json").read_text())
        link=self.home/"linked-pack.json"
        link.symlink_to(Path(conf["check_profiles"]["commit"]))
        conf["check_profiles"]["commit"]=str(link)
        modified=self.home/"operator-symlink.json"
        modified.write_text(json.dumps(conf))
        with self.assertRaisesRegex(ConfigurationError, "operator_file_symlink"):
            OperatorConfig.load(modified)

    def test_world_writable_receiver_dir_refused(self):
        before=self.home.stat().st_mode & 0o777
        try:
            self.home.chmod(0o777)
            with self.assertRaisesRegex(ConfigurationError, "operator_config_directory"):
                OperatorConfig.load(self.home/"operator-config.json")
        finally:
            self.home.chmod(before)

    def test_world_writable_records_dir_refused(self):
        conf=OperatorConfig.load(self.home/"operator-config.json")
        conf.records_dir.mkdir(mode=0o700,exist_ok=True)
        before=conf.records_dir.stat().st_mode & 0o777
        try:
            conf.records_dir.chmod(0o777)
            with self.assertRaisesRegex(EngineError, "records_dir_writable"):
                OpenLineTools(conf).run("check",{"profile":"commit"})
        finally:
            conf.records_dir.chmod(before)

if __name__=="__main__":
    unittest.main()
