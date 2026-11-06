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
import sys, tempfile, pathlib, unittest
from test_promotion import PromotionTests
from foundation.controller import RepairController

class ControllerTests(unittest.TestCase):
    setUp=PromotionTests.setUp
    propose=PromotionTests.propose
    accept=PromotionTests.accept
    def test_missing_agent_is_not_autonomy(self):
        runner=RepairController(self.promoter,trusted_validator=self.validator)
        out=runner.run('agent-absent',None)
        self.assertEqual(out['status'],'AGENT_NOT_EXECUTED')

    def test_mock_agent_success_only_wiring_not_autonomy(self):
        fake=self.root/'mock_agent.py'
        fake.write_text('from pathlib import Path\nPath("app/calc.py").write_text("def price(n):\\n    return n * 3\\n")\n')
        runner=RepairController(self.promoter,trusted_validator=self.validator)
        out=runner.run('fake', [sys.executable,str(fake)])
        self.assertEqual(out['status'],'REPAIR_PROMOTED',out)
        self.assertTrue(out['autonomy_not_certified'])
        self.assertEqual(self.promoter.accepted(),out['head'])

    def test_broken_agent_proposal_stays_refused(self):
        fake=self.root/'mock_bad_agent.py'
        fake.write_text('from pathlib import Path\nPath("app/calc.py").write_text("def price(n):\\n    return n * 5\\n")\n')
        out=RepairController(self.promoter,trusted_validator=self.validator).run('fakebad',[sys.executable,str(fake)])
        self.assertEqual(out['status'],'REPAIR_REFUSED',out)
