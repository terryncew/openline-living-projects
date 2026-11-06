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
import json
import sqlite3
import tempfile
from pathlib import Path
import subprocess
import sys
import unittest

from foundation.promotion import SafePromotion, PromotionRefused, cmd


class PromotionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name); self.repo=self.root/'repo.git'; self.working=self.root/'seed'
        cmd('git','init','--bare',str(self.repo)); cmd('git','clone',str(self.repo),str(self.working))
        (self.working/'app').mkdir(); (self.working/'app'/'calc.py').write_text('def price(n):\n    return n * 2\n')
        (self.working/'app'/'notes.txt').write_text('initial\n')
        (self.working/'checks').mkdir(); (self.working/'checks'/'README').write_text('immutable oracle')
        cmd('git','-C',str(self.working),'add','.')
        cmd('git','-C',str(self.working),'-c','user.name=Fixture','-c','user.email=fixture@localhost','commit','-m','baseline')
        base=cmd('git','-C',str(self.working),'rev-parse','HEAD').stdout.strip()
        cmd('git','-C',str(self.working),'push','origin','HEAD:refs/heads/seed')
        cmd('git','--git-dir',str(self.repo),'update-ref','refs/heads/accepted',base)
        self.db=self.root/'state.db'; conn=sqlite3.connect(self.db)
        conn.execute('CREATE TABLE ledger (id TEXT PRIMARY KEY, value INTEGER NOT NULL)')
        conn.execute('INSERT INTO ledger VALUES (?,?)',('original',5));conn.commit();conn.close()
        self.promoter=SafePromotion(self.repo,self.db,self.root/'journal')
        self.validator=self.root/'verify.py'
        self.validator.write_text("from pathlib import Path\nimport sqlite3,os\nfrom app.calc import price\nassert price(3)==9\nassert sqlite3.connect(os.environ['OPENLINE_TEST_DB']).execute('select sum(value) from ledger').fetchone()[0]>=5\n")

    def propose(self,task,code='def price(n):\n    return n * 3\n'):
        state=self.promoter.prepare(task)
        (Path(state['workspace'])/'app'/'calc.py').write_text(code)
        return state

    def accept(self,task,**kw):
        return self.promoter.promote(task,acceptance_cmd=[sys.executable,str(self.validator)],**kw)

    def independently_commit(self,path,content):
        (self.working/path).write_text(content)
        cmd('git','-C',str(self.working),'add','.')
        cmd('git','-C',str(self.working),'-c','user.name=Other','-c','user.email=other@localhost','commit','-m','other accepted work')
        sha=cmd('git','-C',str(self.working),'rev-parse','HEAD').stdout.strip()
        cmd('git','-C',str(self.working),'push','origin','HEAD:refs/heads/seed')
        previous=self.promoter.accepted();cmd('git','--git-dir',str(self.repo),'update-ref','refs/heads/accepted',sha,previous)
        return sha

    def test_success_conditional_git_repair(self):
        self.propose('A'); out=self.accept('A'); self.assertEqual(out['status'],'PROMOTED',out)
        self.assertEqual(cmd('git','--git-dir',str(self.repo),'show',out['head']+':app/calc.py').stdout,'def price(n):\n    return n * 3\n')
        with sqlite3.connect(self.db) as db: self.assertEqual(db.execute('select value from ledger').fetchall(),[(5,)])

    def test_unrelated_concurrent_git_commit_survives(self):
        self.propose('A'); self.independently_commit('app/notes.txt','other actor\n')
        out=self.accept('A'); self.assertEqual(out['status'],'PROMOTED',out)
        for name,expected in [('app/notes.txt','other actor\n'),('app/calc.py','def price(n):\n    return n * 3\n')]:
            self.assertEqual(cmd('git','--git-dir',str(self.repo),'show',out['head']+':'+name).stdout,expected)

    def test_conflicting_concurrent_git_edit_fails_closed(self):
        self.propose('A'); concurrent=self.independently_commit('app/calc.py','def price(n):\n    return n * 7\n')
        out=self.accept('A'); self.assertEqual(out['status'],'REFUSED',out); self.assertEqual(self.promoter.accepted(),concurrent)

    def test_database_change_during_candidate_refuses_without_losing_write(self):
        self.propose('A');db=sqlite3.connect(self.db);db.execute('INSERT INTO ledger VALUES (?,?)',('other',12));db.commit();db.close()
        out=self.accept('A');self.assertEqual(out['status'],'REFUSED');self.assertIn('live_database_changed',out['reason'])
        with sqlite3.connect(self.db) as db: self.assertEqual(sorted(db.execute('select * from ledger')),[('original',5),('other',12)])

    def test_failed_repair_not_promoted(self):
        self.propose('A','def price(n):\n    return n * 8\n')
        head=self.promoter.accepted();out=self.accept('A');self.assertEqual(out['status'],'REFUSED');self.assertEqual(self.promoter.accepted(),head)

    def test_no_modification_of_protected_verifier(self):
        s=self.propose('A'); (Path(s['workspace'])/'checks'/'README').write_text('skip tests')
        self.assertEqual(self.accept('A')['status'],'REFUSED')

    def test_exact_file_scope_cannot_accept_filename_prefix_collision(self):
        state=self.propose('prefix-collision')
        (Path(state['workspace'])/'app'/'calc.py.extra').write_text('side effect')
        out=self.accept('prefix-collision',allow_prefixes=('app/calc.py',))
        self.assertEqual(out['status'],'REFUSED',out)
        self.assertEqual(out['reason'],'repair_outside_allowed_source')

    def test_no_symlink_import(self):
        s=self.promoter.prepare('A'); wd=Path(s['workspace']); (wd/'app'/'outside').symlink_to('/etc/passwd')
        self.assertEqual(self.accept('A')['status'],'REFUSED')

    def test_crash_after_git_cas_recovers_not_reexecuted(self):
        self.propose('A');head=self.promoter.accepted()
        with self.assertRaisesRegex(RuntimeError,'injected_crash'):
            self.accept('A',fail_after_ref=True)
        self.assertNotEqual(self.promoter.accepted(),head)
        recovered=self.promoter.recover('A');self.assertEqual(recovered['status'],'PROMOTED_RECOVERED')
        self.assertEqual(self.promoter.recover('A')['status'],'PROMOTED_RECOVERED')

    def test_agent_tampering_with_test_snapshot_refuses(self):
        state=self.propose('snapshot')
        with sqlite3.connect(state['snapshot_db']) as db:
            db.execute('UPDATE ledger SET value=999 WHERE id="original"')
        out=self.accept('snapshot')
        self.assertEqual(out['status'],'REFUSED')
        self.assertIn('test_snapshot_modified',out['reason'])
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute('SELECT value FROM ledger WHERE id="original"').fetchone(),(5,))

    def test_deny_absolute_and_dotdot_paths(self):
        with self.assertRaises(PromotionRefused):self.promoter.prepare('../x')

if __name__=='__main__':unittest.main()
