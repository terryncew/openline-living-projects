import sys as _sys; from pathlib import Path as _Path
_AUTO_BOOTSTRAP_PATHS = [
    _Path(__file__).resolve().parents[1],
    _Path(__file__).resolve().parents[2] / 'SELF-HEALING-ENGINE-001',
    _Path(__file__).resolve().parents[2] / 'SELF-HEALING-PROJECTS-001',
    _Path(__file__).resolve().parents[2] / 'OPENLINE-PROTECT-001',
]
for _p in reversed(_AUTO_BOOTSTRAP_PATHS):
    if _p.exists() and str(_p) not in _sys.path:
        _sys.path.insert(0, str(_p))
import tempfile,unittest,pathlib,os,subprocess,sys
from examples.make_task import create,CASES
from foundation.promotion import SafePromotion
from foundation.controller import RepairController
class PacketTests(unittest.TestCase):
    def test_real_multimodule_tasks_no_agent_not_misrepresented(self):
        for case in CASES:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as d:
                meta=create(pathlib.Path(d)/'task',case)
                out=RepairController(SafePromotion(meta['repo'],meta['db'],meta['state_dir']),trusted_validator=pathlib.Path(meta['oracle'])).run('real-case',None)
                self.assertEqual(out['status'],'AGENT_NOT_EXECUTED')
                self.assertTrue(pathlib.Path(meta['oracle']).is_file())
if __name__=='__main__':unittest.main()
