"""Real bare Git and SQLite integration of read-only lens; not autonomous repair."""
from pathlib import Path
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from living_project import observe, report, main, ObservationError


def git(*args, cwd=None):
    r=subprocess.run(['git', *args], cwd=cwd, capture_output=True, text=True, check=True)
    return r.stdout.strip()


class LivingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.gitdir=self.root/'accepted.git'; self.dbpath=self.root/'project.sqlite'
        git('init', '--bare', str(self.gitdir))
        wd=self.root/'work'; git('clone', str(self.gitdir), str(wd))
        git('config','user.name','Test',cwd=wd);git('config','user.email','test@local',cwd=wd)
        (wd/'app').mkdir();(wd/'app'/'main.py').write_text('print(1)\n')
        git('add','.',cwd=wd);git('commit','-m','valid work',cwd=wd)
        git('push','origin','HEAD:refs/heads/accepted',cwd=wd)
        self.head=git('--git-dir',str(self.gitdir),'rev-parse','refs/heads/accepted')
        with sqlite3.connect(self.dbpath) as db:
            db.executescript('''
            CREATE TABLE projects (id TEXT,objective TEXT,owner_pub TEXT,contract TEXT,last_accepted TEXT,status TEXT);
            CREATE TABLE members (project_id TEXT,member_id TEXT,owner_pub TEXT,worker_pub TEXT,world_digest TEXT,active INTEGER);
            CREATE TABLE deliverables (id TEXT,project_id TEXT,member_id TEXT,accepted_head TEXT,standing TEXT);
            CREATE TABLE dependencies (deliverable_id TEXT,depends_on TEXT);
            CREATE TABLE assignments (id TEXT,deliverable_id TEXT,worker_member TEXT,basis TEXT,allowed_paths TEXT,state TEXT,promoted_head TEXT);
            CREATE TABLE events (seq INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT,payload TEXT,at INTEGER);
            ''')
            db.execute('INSERT INTO projects VALUES (?,?,?,?,?,?)',('p-1','Maintain inventory','pub','v1',self.head,'ACTIVE'))
            for member in ('alice','bob'):
                db.execute('INSERT INTO members VALUES (?,?,?,?,?,?)',('p-1',member,'key','worker','world',1))
            for ident, member, dependency in [('inventory','alice','inventory_v1'),('docs','bob','docs_v1')]:
                db.execute('INSERT INTO deliverables VALUES (?,?,?,?,?)',(ident,'p-1',member,self.head,'CURRENT'))
                db.execute('INSERT INTO dependencies VALUES (?,?)',(ident,dependency))
            db.execute('INSERT INTO events(kind,payload,at) VALUES (?,?,?)',('DELIVERABLE_ACCEPTED',json.dumps({'id':'inventory'}),0))
            db.commit()

    def mutate(self, sql, args=()):
        with sqlite3.connect(self.dbpath) as db:
            db.execute(sql, args);db.commit()

    def test_real_git_and_sqlite_current(self):
        v=observe(self.dbpath,self.gitdir)
        self.assertEqual(v['verdict'],'OBSERVED_CURRENT')
        self.assertEqual(v['project']['accepted_git_head'],self.head)
        self.assertEqual(v['members'],{'active':2,'total':2})
        self.assertIn('No declared work',v['next_step'])
        self.assertEqual(v['claim_limits']['authorization'],'NONE')

    def test_hypothetical_impact_does_not_mutate(self):
        a=observe(self.dbpath,self.gitdir,changed=('inventory_v1',))
        b=observe(self.dbpath,self.gitdir)
        self.assertEqual(a['hypothetical_change']['affected_declared_deliverables'],['inventory'])
        self.assertEqual(b['hypothetical_change']['affected_declared_deliverables'],[])
        self.assertEqual(a['hypothetical_change']['unlisted_dependencies'],'UNKNOWN')
        self.assertEqual(a['project'],b['project'])
        self.assertEqual([(x['id'],x['standing'],x['accepted_at']) for x in a['deliverables']], [(x['id'],x['standing'],x['accepted_at']) for x in b['deliverables']])

    def test_reopened_requires_assignment(self):
        self.mutate("UPDATE deliverables SET standing='REOPEN' WHERE id='inventory'")
        self.mutate("UPDATE projects SET status='RECONSIDERATION'")
        v=observe(self.dbpath,self.gitdir)
        self.assertEqual(v['verdict'],'REPAIR_ASSIGNMENT_NEEDED')
        self.assertEqual([x['id'] for x in v['deliverables'] if x['standing']=='CURRENT'],['docs'])

    def test_owner_signed_assignment_is_record_only(self):
        self.mutate("UPDATE deliverables SET standing='REOPEN' WHERE id='inventory'")
        self.mutate("INSERT INTO assignments VALUES (?,?,?,?,?,?,?)",('repair-1','inventory','bob','v1',json.dumps(['app/main.py']),'ASSIGNED',None))
        v=observe(self.dbpath,self.gitdir)
        self.assertEqual(v['verdict'],'REPAIR_ASSIGNMENTS_OBSERVED')
        self.assertEqual(v['claim_limits']['authorization'],'NONE')
        self.assertEqual(v['repair_assignments'][0]['allowed_paths'],['app/main.py'])

    def test_revoked_worker_cannot_trigger_ready(self):
        self.mutate("UPDATE deliverables SET standing='REOPEN' WHERE id='inventory'")
        self.mutate("UPDATE members SET active=0 WHERE member_id='bob'")
        self.mutate("INSERT INTO assignments VALUES (?,?,?,?,?,?,?)",('repair-1','inventory','bob','v1','["app/main.py"]','ASSIGNED',None))
        self.assertEqual(observe(self.dbpath,self.gitdir)['verdict'],'REPAIR_ASSIGNMENT_NEEDED')

    def test_stale_assignment_basis_not_eligible(self):
        self.mutate("UPDATE deliverables SET standing='REOPEN' WHERE id='inventory'")
        self.mutate("INSERT INTO assignments VALUES (?,?,?,?,?,?,?)",('repair-1','inventory','bob','v0','["app/main.py"]','ASSIGNED',None))
        self.assertEqual(observe(self.dbpath,self.gitdir)['verdict'],'REPAIR_ASSIGNMENT_NEEDED')

    def test_cross_resource_drift_requires_reconciliation(self):
        self.mutate('UPDATE projects SET last_accepted=?',('0'*40,))
        self.assertEqual(observe(self.dbpath,self.gitdir)['verdict'],'RECONCILIATION_REQUIRED')

    def test_ref_change_during_snapshot_denied(self):
        with patch('living_project._git_head',side_effect=[self.head,'f'*40]):
            with self.assertRaisesRegex(ObservationError,'accepted_ref_changed'):
                observe(self.dbpath,self.gitdir)

    def test_missing_db_refused_without_creating(self):
        p=self.root/'new.sqlite'
        with self.assertRaisesRegex(ObservationError,'project_database_missing'):
            observe(p,self.gitdir)
        self.assertFalse(p.exists())

    def test_bad_schema_refused(self):
        self.mutate('DROP TABLE assignments')
        with self.assertRaisesRegex(ObservationError,'project_schema_mismatch'):
            observe(self.dbpath,self.gitdir)

    def test_invalid_dependency_input_denied(self):
        with self.assertRaisesRegex(ObservationError,'invalid_changed_dependency'):
            observe(self.dbpath,self.gitdir,changed=('',))

    def test_corrupt_assignment_payload_refused(self):
        self.mutate("INSERT INTO assignments VALUES (?,?,?,?,?,?,?)",('r','inventory','bob','v1','not-json','ASSIGNED',None))
        with self.assertRaisesRegex(ObservationError,'invalid_assignment_scope'):
            observe(self.dbpath,self.gitdir)

    def test_deterministic_observation_hash(self):
        a=observe(self.dbpath,self.gitdir)
        b=observe(self.dbpath,self.gitdir)
        self.assertEqual(a['observation_sha256'],b['observation_sha256'])
        self.assertEqual(len(a['observation_sha256']),64)
        self.assertFalse(a['claim_limits']['source_signatures_verified'])

    def test_report_no_overclaim(self):
        s=report(observe(self.dbpath,self.gitdir))
        self.assertIn('READ',s.upper())
        self.assertIn('No signed authority',s)
        self.assertIn('inventory',s)

    def test_cli_json_and_exit_codes(self):
        with patch('sys.argv',['living','--db',str(self.dbpath),'--accepted-git',str(self.gitdir),'--json']):
            with patch('builtins.print') as p:
                self.assertEqual(main(),0)
                self.assertEqual(json.loads(p.call_args.args[0])['project']['id'],'p-1')
        self.mutate('UPDATE projects SET last_accepted=?',('0'*40,))
        with patch('sys.argv',['living','--db',str(self.dbpath),'--accepted-git',str(self.gitdir)]):
            with patch('builtins.print'):
                self.assertEqual(main(),1)

    def test_single_local_project_dir(self):
        with patch('sys.argv',['living','--project-dir',str(self.root),'--json']):
            with patch('builtins.print') as output:
                self.assertEqual(main(),0)
                self.assertEqual(json.loads(output.call_args.args[0])['project']['id'],'p-1')

    def test_source_is_read_only(self):
        with sqlite3.connect(self.dbpath) as db:
            before=db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        observe(self.dbpath,self.gitdir,changed=('inventory_v1',))
        with sqlite3.connect(self.dbpath) as db:
            after=db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        self.assertEqual(before,after)

if __name__ == '__main__':
    unittest.main()
