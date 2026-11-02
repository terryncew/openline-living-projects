"""Receiver must refuse malformed signed caps, including an otherwise valid signature."""
from __future__ import annotations
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent))
from engine_loader import load_engines
load_engines()
from openline_guard import ReceiverGuard, SigningIdentity, GuardRefused
from foundation.effects import LocalEffectStore, Principal, EffectDenied

class TestMalformedSignedCaps(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.db_path=Path(self.temp.name)/'guard.sqlite'
        with closing(sqlite3.connect(self.db_path)) as db:
            db.execute('CREATE TABLE ledger(id TEXT PRIMARY KEY, amount INTEGER)')
            db.commit()
        self.issuer=SigningIdentity();self.worker=SigningIdentity()
        self.guard=ReceiverGuard(self.db_path)
        self.guard.register_issuer(self.issuer.public)

    def tearDown(self):
        self.temp.cleanup()

    def test_guard_signed_bad_caps_fail_closed_without_ledger_effect(self):
        for i,bad in enumerate((float('nan'),float('inf'),float('-inf'),True,'100',0,-1)):
            with self.subTest(cap=str(bad)):
                grant=self.issuer.issue_grant(self.worker.public,task_id=f'bad-{i}',operation='disburse',max_amount=bad,allowed_targets=[f'row-{i}'])
                request=self.worker.sign_request(grant,operation='disburse',target_id=f'row-{i}',payload={'amount':99999})
                with self.assertRaises(GuardRefused) as ctx:
                    self.guard.execute(grant=grant,request=request,fn=lambda db,p:db.execute('INSERT INTO ledger VALUES (?,?)',(f'row-{i}',p['amount'])),target_table='ledger',target_pk_col='id',amount_field='amount')
                self.assertEqual(ctx.exception.reason,'invalid_authorized_cap')
        with closing(sqlite3.connect(self.db_path)) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM ledger').fetchone()[0],0)

    def test_effect_store_signed_bad_caps_fail_closed(self):
        dbp=Path(self.temp.name)/'effects.sqlite'
        with closing(sqlite3.connect(dbp)) as db:
            db.execute('CREATE TABLE items (id TEXT PRIMARY KEY, amount INTEGER)');db.commit()
        store=LocalEffectStore(dbp); buyer=Principal();worker=Principal()
        store.register_buyer(buyer.public)
        for i,bad in enumerate((float('nan'),float('inf'),True,'100',0,-1)):
            with self.subTest(cap=str(bad)):
                delegation=buyer.delegate(worker.public,task_id=f'bad-{i}',mode='execute',expires=9999999999,max_amount=bad)
                payload={'amount':99999}
                request=worker.request(delegation,task_id=f'bad-{i}',mode='execute',payload=payload)
                with self.assertRaises(EffectDenied) as ctx:
                    store.apply(delegation=delegation,request=request,task_id=f'bad-{i}',payload=payload,effect=lambda db:db.execute('INSERT INTO items VALUES (?,?)',(f'row-{i}',99999)),observe=lambda db:True)
                self.assertEqual(str(ctx.exception),'invalid_delegation_cap')
        with closing(sqlite3.connect(dbp)) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM items').fetchone()[0],0)

if __name__=='__main__': unittest.main()
