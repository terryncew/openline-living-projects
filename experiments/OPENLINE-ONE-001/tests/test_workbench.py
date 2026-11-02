"""Real local Git+SQLite interface tests, not real model or signed admission tests."""
from __future__ import annotations
from contextlib import closing
import importlib.util
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('openline_one_under_test', HERE / 'workbench.py')
w = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = w
spec.loader.exec_module(w)


def git(*args):
    return subprocess.run(['git', *map(str, args)], text=True, capture_output=True, check=True).stdout.strip()


class OneTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.project = self.root / 'project'
        self.project.mkdir()
        source_root = HERE.parents[1]  # checkout root from experiments/OPENLINE-ONE-001
        for name in ('living', 'coach'):
            source = source_root / w.SOURCES[name]
            target = self.repo / w.SOURCES[name]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        self.patcher = patch.object(w, 'ROOT', self.repo)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.bare = self.project / 'accepted.git'
        git('init', '--bare', self.bare)
        work = self.root / 'work'
        git('clone', self.bare, work)
        git('-C', work, 'config', 'user.name', 'Test')
        git('-C', work, 'config', 'user.email', 'test@localhost')
        (work / 'app').mkdir()
        (work / 'app' / 'a.py').write_text('x=1\n')
        git('-C', work, 'add', '.')
        git('-C', work, 'commit', '-m', 'fixture')
        git('-C', work, 'push', 'origin', 'HEAD:refs/heads/accepted')
        self.head = git('--git-dir', self.bare, 'rev-parse', 'refs/heads/accepted')
        db = self.project / 'project.sqlite'
        with closing(sqlite3.connect(db)) as conn:
            conn.executescript('''
            CREATE TABLE projects(id TEXT PRIMARY KEY, objective TEXT, owner_pub TEXT, contract TEXT, last_accepted TEXT, status TEXT);
            CREATE TABLE members(project_id TEXT, member_id TEXT, owner_pub TEXT, worker_pub TEXT, world_digest TEXT, active INTEGER);
            CREATE TABLE deliverables(id TEXT, project_id TEXT, member_id TEXT, accepted_head TEXT, standing TEXT);
            CREATE TABLE dependencies(deliverable_id TEXT, depends_on TEXT);
            CREATE TABLE assignments(id TEXT, deliverable_id TEXT, worker_member TEXT, basis TEXT, allowed_paths TEXT, state TEXT, promoted_head TEXT);
            CREATE TABLE events(seq INTEGER PRIMARY KEY,kind TEXT,payload TEXT,at INTEGER);
            ''')
            conn.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)', ('p1','Repair invoice','testkey','v2',self.head,'RECONSIDERATION'))
            conn.executemany('INSERT INTO members VALUES(?,?,?,?,?,?)', [('p1','alice','','','',1),('p1','bob','','','',1)])
            conn.executemany('INSERT INTO deliverables VALUES(?,?,?,?,?)', [('d1','p1','alice',self.head,'REOPEN'),('d2','p1','bob',self.head,'CURRENT')])
            conn.executemany('INSERT INTO dependencies VALUES(?,?)',[('d1','invoice-v1'),('d2','format-v1')])
            conn.execute('INSERT INTO assignments VALUES(?,?,?,?,?,?,?)', ('repair-1','d1','bob','v2','["app/a.py"]','ASSIGNED',None))
            conn.commit()
        self.catalog = self.root / 'catalog.json'
        self.catalog.write_text(json.dumps({
            'schema':'openline.one.operator-catalog.v1',
            'total_cap_micros':20_000_000,
            'provider_caps_micros':{'openai':10_000_000, 'anthropic':10_000_000},
            'models':[
                {'provider':'openai','name':'student','input_usd_per_million':'0.5',
                 'output_usd_per_million':'1','input_limit':1000,'output_limit':500},
                {'provider':'anthropic','name':'alternative','input_usd_per_million':'2',
                 'output_usd_per_million':'3','input_limit':1000,'output_limit':500}],
            'teacher':{'provider':'openai','name':'teacher','input_usd_per_million':'6',
                       'output_usd_per_million':'20','input_limit':1000,'output_limit':500}
        }))
        self.catalog.chmod(0o600)

    def test_reads_actual_git_and_db(self):
        o = w.inspect(self.project)
        self.assertEqual(o['verdict'],'REPAIR_ASSIGNMENTS_OBSERVED')
        self.assertEqual(o['project']['accepted_git_head'],self.head)
        self.assertEqual(o['deliverables'][1]['standing'],'CURRENT')

    def test_budgeted_task_packet_not_authorization(self):
        packet=w.prepare(self.project,self.catalog,'repair-1','Repair a bug','invoice')
        self.assertFalse(packet['authorized'])
        self.assertFalse(packet['model_called'])
        self.assertFalse(packet['repair_executed'])
        self.assertEqual(packet['student_suggested'],'openai/student')
        self.assertEqual(packet['allowed_paths'],['app/a.py'])
        self.assertEqual(packet['accepted_git_head'],self.head)
        self.assertEqual(len(packet['packet_sha256']),64)

    def test_git_ledger_drift_refused(self):
        with closing(sqlite3.connect(self.project/'project.sqlite')) as db:
            db.execute("UPDATE projects SET last_accepted='eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'")
            db.commit()
        with self.assertRaisesRegex(w.WorkbenchRefused,'reconciliation'):
            w.prepare(self.project,self.catalog,'repair-1','Fix','invoice')

    def test_revoked_worker_refused(self):
        with closing(sqlite3.connect(self.project/'project.sqlite')) as db:
            db.execute("UPDATE members SET active=0 WHERE member_id='bob'")
            db.commit()
        with self.assertRaisesRegex(w.WorkbenchRefused,'no_current_repair_assignment'):
            w.prepare(self.project,self.catalog,'repair-1','Fix','invoice')

    def test_stale_basis_refused(self):
        with closing(sqlite3.connect(self.project/'project.sqlite')) as db:
            db.execute("UPDATE assignments SET basis='v1'")
            db.commit()
        with self.assertRaises(w.WorkbenchRefused):
            w.prepare(self.project,self.catalog,'repair-1','Fix','invoice')

    def test_bad_path_refused(self):
        with closing(sqlite3.connect(self.project/'project.sqlite')) as db:
            db.execute('UPDATE assignments SET allowed_paths=?', ('["app/../secret.txt"]',))
            db.commit()
        with self.assertRaisesRegex(w.WorkbenchRefused,'scope_invalid'):
            w.prepare(self.project,self.catalog,'repair-1','Fix','invoice')

    def test_catalog_is_owner_controlled(self):
        self.catalog.chmod(0o666)
        with self.assertRaisesRegex(w.WorkbenchRefused,'writable_by_others'):
            w.prepare(self.project,self.catalog,'repair-1','Fix','invoice')

    def test_quote_can_stop_without_calling_model(self):
        x=json.loads(self.catalog.read_text())
        x['provider_caps_micros']={'openai':1,'anthropic':1}
        self.catalog.write_text(json.dumps(x))
        with self.assertRaisesRegex(w.WorkbenchRefused,'budget_quote_exceeds_remaining_caps'):
            w.prepare(self.project,self.catalog,'repair-1','Fix','invoice')

    def test_held_budget_reduces_remain(self):
        meter=self.root/'meter.sqlite'
        with closing(sqlite3.connect(meter)) as db:
            db.execute('CREATE TABLE calls(call_id TEXT,provider TEXT,model TEXT,reserved_micros INTEGER,metered_micros INTEGER,state TEXT)')
            db.execute('INSERT INTO calls VALUES(?,?,?,?,?,?)',('a','openai','x',9_999_999,9_999_999,'METERED'))
            db.commit()
        pkt=w.prepare(self.project,self.catalog,'repair-1','Fix','invoice',meter_path=meter)
        self.assertEqual(pkt['student_suggested'],'anthropic/alternative')
        self.assertEqual(pkt['metered_or_reserved_micro_usd']['openai'],9_999_999)

    def test_uncertain_provider_charge_blocks_every_route(self):
        meter=self.root/'meter.sqlite'
        with closing(sqlite3.connect(meter)) as db:
            db.execute('CREATE TABLE calls(call_id TEXT,provider TEXT,model TEXT,reserved_micros INTEGER,metered_micros INTEGER,state TEXT)')
            db.execute('INSERT INTO calls VALUES(?,?,?,?,?,?)',('a','openai','x',1_000_000,None,'UNCERTAIN'))
            db.commit()
        with self.assertRaisesRegex(w.WorkbenchRefused,'unreconciled_provider_charge_stop'):
            w.prepare(self.project,self.catalog,'repair-1','Fix','invoice',meter_path=meter)

    def test_no_assignment_refused(self):
        with self.assertRaisesRegex(w.WorkbenchRefused,'not_found'):
            w.prepare(self.project,self.catalog,'bogus','Fix','invoice')

    def test_doctor_never_claims_finish_line(self):
        d=w.doctor()
        self.assertFalse(d['ready_to_claim_product_finish_line'])
        self.assertTrue(d['components']['living']['present'])
        self.assertFalse(d['components']['mcp']['present'])

    def test_pretend_status_not_signed(self):
        out=w.inspect(self.project)
        self.assertEqual(out['claim_limits']['authorization'],'NONE')
        self.assertFalse(out['claim_limits']['source_signatures_verified'])

if __name__ == '__main__': unittest.main()
