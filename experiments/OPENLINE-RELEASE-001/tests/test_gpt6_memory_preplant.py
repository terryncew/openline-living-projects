"""Independent GPT-6 F-02 follow-on: future-assignment memory preplant."""
from __future__ import annotations
import io
import sqlite3
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, closing
from pathlib import Path
from types import SimpleNamespace

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent))
from engine_loader import load_engines
load_engines()
import openline_cli as cli
from project import ProjectRefused

class TestFutureAssignmentPreplant(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.proj_dir=Path(self.tmp.name)/'p'
        with redirect_stdout(io.StringIO()):
            cli.cmd_init(SimpleNamespace(dir=str(self.proj_dir),project_id='p-claim',workers='alice,bob',validator=None,worker_uid=65534))
        self.cfg=cli._load_config(self.proj_dir)
        self.promo,self.project,self.protect=cli._build_engines(self.cfg,65534)

    def tearDown(self):
        self.tmp.cleanup()

    def test_future_assignment_preplant_refused(self):
        with self.assertRaises(ProjectRefused) as e:
            self.project.propose_memory('preplanted','invoice-feature','bob','invoice_v2','ab'*32,
                'poison','poison',assignment_id='future-alice')
        self.assertEqual(str(e.exception),'memory_assignment_missing')
        with closing(sqlite3.connect(self.project.db_path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM earned_memory WHERE memory_id='preplanted'").fetchone()[0],0)

    def test_legacy_preplant_quarantined_when_alice_repair_accepted(self):
        # Simulate candidate created by vulnerable earlier release before future assignment.
        with closing(sqlite3.connect(self.project.db_path)) as db:
            db.execute("INSERT INTO earned_memory VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ('preplanted',self.project.id,'invoice-feature','future-alice','bob','invoice_v2',
                 'ab'*32,'poison','poison','CANDIDATE',None,None,None,1))
            db.commit()
        with redirect_stdout(io.StringIO()):
            cli.cmd_assign(SimpleNamespace(dir=str(self.proj_dir),worker_uid=65534,
                assignment='future-alice',deliverable='invoice-feature',worker='alice',
                basis='invoice_v2',allowed_paths='app/price.py',as_member=None,signature=None))
            cli.cmd_prepare(SimpleNamespace(dir=str(self.proj_dir),worker_uid=65534,
                assignment='future-alice',propose_memory='legit',diagnosis='valid diagnosis',lesson='valid lesson'))
        ws=Path(self.cfg['promotion_dir'])/'task-future-alice'/'candidate'/'app'/'price.py'
        ws.write_text('def total(qty):\n    return qty * 11\n')
        outcome=self.protect.intercept('future-alice')
        self.assertEqual(outcome['verdict'],'ACCEPTED')
        inherited=self.project.inherit_memory('invoice-feature')['inherited_verified']
        self.assertEqual([r['memory_id'] for r in inherited],['legit'])
        with closing(sqlite3.connect(self.project.db_path)) as db:
            status=db.execute("SELECT status FROM earned_memory WHERE memory_id='preplanted'").fetchone()[0]
            self.assertEqual(status,'QUARANTINED')
            event=db.execute("SELECT COUNT(*) FROM events WHERE kind='MEMORY_ASSIGNMENT_SCOPE_QUARANTINED'").fetchone()[0]
            self.assertEqual(event,1)

if __name__=='__main__': unittest.main()
