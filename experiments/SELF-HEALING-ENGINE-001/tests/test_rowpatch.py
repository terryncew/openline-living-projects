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
import unittest,sqlite3,tempfile
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from foundation.promotion import snapshot
from foundation.rowpatch import RowDeltaPromotion
from foundation.effects import EffectDenied,verify,public

class RowTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name);self.live=root/'live.db';self.base=root/'base.db';self.candidate=root/'candidate.db'
        with sqlite3.connect(self.live) as db:
            db.execute('CREATE TABLE business (id TEXT PRIMARY KEY,rev INTEGER NOT NULL,value TEXT NOT NULL)')
            db.execute('INSERT INTO business VALUES (?,?,?)',('repair',0,'bad'))
            db.execute('INSERT INTO business VALUES (?,?,?)',('other',0,'accepted'))
        snapshot(self.live,self.base);snapshot(self.live,self.candidate)
        self.key=Ed25519PrivateKey.generate()
        self.p=RowDeltaPromotion(self.live,self.base,self.candidate,allowed_tables=['business'],receiver_key=self.key)
    def put(self,name,value,path=None):
        with sqlite3.connect(path or self.candidate) as db:db.execute('UPDATE business SET value=? WHERE id=?',(value,name))
    def get(self,name):
        with sqlite3.connect(self.live) as db:return db.execute('SELECT rev,value FROM business WHERE id=?',(name,)).fetchone()
    def test_unrelated_concurrent_row_preserved(self):
        self.put('repair','fixed');self.put('other','new accepted',self.live)
        r=self.p.promote('task',verify_current=lambda db:db.execute("SELECT value FROM business WHERE id='repair'").fetchone()==('fixed',))
        self.assertEqual(r['status'],'COMMITTED');self.assertEqual(self.get('other'),(0,'new accepted'))
        self.assertEqual(self.get('repair'),(1,'fixed'))
        self.assertEqual(verify(r['receipt'],public(self.key))['task_id'],'task')
        self.assertEqual(self.p.recover('task')['receipt'],r['receipt'])
        self.assertEqual(self.p.promote('task')['status'],'ALREADY_COMMITTED')
    def test_second_distinct_promotion_with_durable_receipts(self):
        self.put('repair','fixed')
        first=self.p.promote('first')
        self.assertEqual(first['status'],'COMMITTED')
        root=Path(self.tmp.name)
        newer_base=root/'next_base.db';newer_candidate=root/'next_candidate.db'
        snapshot(self.live,newer_base);snapshot(self.live,newer_candidate)
        with sqlite3.connect(newer_candidate) as db:
            db.execute('UPDATE business SET value=? WHERE id=?',('next accepted','other'))
        next_p=RowDeltaPromotion(self.live,newer_base,newer_candidate,allowed_tables=['business'],receiver_key=self.key)
        second=next_p.promote('second')
        self.assertEqual(second['status'],'COMMITTED')
        self.assertEqual(self.get('repair'),(1,'fixed'))
        self.assertEqual(self.get('other'),(1,'next accepted'))
        self.assertEqual(next_p.recover('first')['receipt'],first['receipt'])
        self.assertEqual(next_p.recover('second')['receipt'],second['receipt'])

    def test_same_row_concurrent_conflict(self):
        self.put('repair','fixed');self.put('repair','other change',self.live)
        with self.assertRaisesRegex(EffectDenied,'concurrent_row_conflict'):self.p.promote('task')
        self.assertEqual(self.get('repair'),(0,'other change'))
    def test_false_success_rolls_back(self):
        self.put('repair','fixed')
        with self.assertRaisesRegex(EffectDenied,'verification_failed'):self.p.promote('task',verify_current=lambda db:False)
        self.assertEqual(self.get('repair'),(0,'bad'))
        with self.assertRaisesRegex(EffectDenied,'not_found'):self.p.recover('task')
    def test_no_schema_mutation(self):
        with sqlite3.connect(self.candidate) as db:db.execute('CREATE TABLE secret (id TEXT)')
        with self.assertRaisesRegex(EffectDenied,'schema_changed'):self.p.promote('task')
    def test_no_offscope_change(self):
        with sqlite3.connect(self.live) as db:db.execute('CREATE TABLE extra (id TEXT)')
        with self.assertRaisesRegex(EffectDenied,'live_schema_changed'):
            self.put('repair','fixed');self.p.promote('task')

if __name__=='__main__':unittest.main()
