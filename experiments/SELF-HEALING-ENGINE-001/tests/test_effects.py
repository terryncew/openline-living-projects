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
import unittest, tempfile, sqlite3, time
from pathlib import Path
from foundation.effects import Principal,LocalEffectStore,EffectDenied
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

class EffectTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.db=Path(self.tmp.name)/'effect.sqlite';self.receiver=LocalEffectStore(self.db)
        self.A=Principal();self.B=Principal();self.A1=Principal();self.A2=Principal();self.B1=Principal()
        self.receiver.register_buyer(self.A.public);self.receiver.register_buyer(self.B.public)
        with sqlite3.connect(self.db) as c:c.execute('CREATE TABLE invoices (buyer TEXT, task TEXT, amount INT, PRIMARY KEY(buyer,task))')
        self.payload={'amount':1200};self.expires=int(time.time())+200
    def signed(self,buyer,worker,task,mode):
        delegation=buyer.delegate(worker.public,task_id=task,mode=mode,expires=self.expires)
        return {'delegation':delegation,'request':worker.request(delegation,task_id=task,payload=self.payload,mode=mode),'task_id':task,'payload':self.payload}
    def apply(self,buyer,worker,task='same-id',correct=True):
        req=self.signed(buyer,worker,task,'execute')
        return self.receiver.apply(**req,effect=lambda db:db.execute('INSERT INTO invoices VALUES (?,?,?)',(buyer.public,task,1200)),
          observe=lambda db: db.execute('SELECT amount FROM invoices WHERE buyer=? AND task=?',(buyer.public,task)).fetchone()==(1200,) if correct else False)
    def test_two_buyers_same_task_independent(self):
        a=self.apply(self.A,self.A1);b=self.apply(self.B,self.B1)
        self.assertEqual((a['status'],b['status']),('COMMITTED','COMMITTED'))
        with sqlite3.connect(self.db) as c:self.assertEqual(c.execute('SELECT count(*) FROM invoices').fetchone()[0],2)
    def test_successor_recovery_after_revocation_and_restart(self):
        original=self.apply(self.A,self.A1)
        grant=self.signed(self.A,self.A1,'same-id','execute')['delegation']
        self.receiver.revoke(grant)
        restart=LocalEffectStore(self.db,receiver_seed=self.receiver.key.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()))
        recovered=restart.recover(**self.signed(self.A,self.A2,'same-id','recover'))
        self.assertEqual(recovered['receipt'],original['receipt'])
        self.assertEqual(LocalEffectStore.verify_receipt(recovered['receipt'],restart.receiver_public)['buyer'],self.A.public)
        with sqlite3.connect(self.db) as c:self.assertEqual(c.execute('SELECT count(*) FROM invoices').fetchone()[0],1)
    def test_cross_buyer_recovery_refused(self):
        self.apply(self.A,self.A1)
        with self.assertRaisesRegex(EffectDenied,'not_found'):
            self.receiver.recover(**self.signed(self.B,self.B1,'same-id','recover'))
    def test_false_success_rollback(self):
        with self.assertRaisesRegex(EffectDenied,'effect_not_verified'):
            self.apply(self.A,self.A1,correct=False)
        with sqlite3.connect(self.db) as c:self.assertEqual(c.execute('SELECT count(*) FROM invoices').fetchone()[0],0)
    def test_handler_exception_rollback(self):
        req=self.signed(self.A,self.A1,'same-id','execute')
        def bad(db):
            db.execute('INSERT INTO invoices VALUES (?,?,?)',(self.A.public,'same-id',1));raise ValueError('failed')
        with self.assertRaises(ValueError):self.receiver.apply(**req,effect=bad,observe=lambda db:True)
        with sqlite3.connect(self.db) as c:self.assertEqual(c.execute('SELECT count(*) FROM invoices').fetchone()[0],0)
    def test_stale_evidence_refuses_effect(self):
        with self.assertRaisesRegex(EffectDenied,'evidence_not_current'):
            req=self.signed(self.A,self.A1,'same-id','execute')
            self.receiver.apply(**req,effect=lambda db:db.execute('INSERT INTO invoices VALUES (?,?,?)',(self.A.public,'same-id',1)),observe=lambda db:True,standing=lambda db:False)
        with sqlite3.connect(self.db) as c:self.assertEqual(c.execute('SELECT count(*) FROM invoices').fetchone()[0],0)
    def test_cross_worker_signature_tampered(self):
        req=self.signed(self.A,self.A1,'same-id','execute');req['request']=self.B1.request(req['delegation'],task_id='same-id',payload=self.payload,mode='execute')
        with self.assertRaises(EffectDenied):self.receiver.apply(**req,effect=lambda db:None,observe=lambda db:True)
    def test_expired_delegation_refused(self):
        self.expires=int(time.time())-1
        with self.assertRaisesRegex(EffectDenied,'grant_expired'):self.apply(self.A,self.A1)
    def test_repeat_apply_exactly_once(self):
        a=self.apply(self.A,self.A1); b=self.apply(self.A,self.A1)
        self.assertEqual(b['status'],'ALREADY_COMMITTED');self.assertEqual(a['receipt'],b['receipt'])
        with sqlite3.connect(self.db) as c:self.assertEqual(c.execute('SELECT count(*) FROM invoices').fetchone()[0],1)

if __name__=='__main__':unittest.main()
