"""SQLite-only conditional row promotion. Never copies a speculative DB snapshot.

Contract: the receiver explicitly admits tables with (id TEXT PRIMARY KEY,
rev INTEGER NOT NULL,value TEXT NOT NULL). Inserts and updates only. Structural
schema migrations, deletes, triggers, side effects, Git+DB atomicity unsupported.
"""
from __future__ import annotations
from contextlib import closing
import json
import sqlite3
import time
from .effects import seal,public,hash_of,EffectDenied
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def ident(table):
    if not table.isidentifier() or not table.isascii() or table.startswith('sqlite_'):
        raise EffectDenied('invalid_table_identifier')
    return '"'+table+'"'

class RowDeltaPromotion:
    def __init__(self,live_db,base_db,candidate_db, *, allowed_tables,receiver_key):
        self.live=str(live_db);self.base=str(base_db);self.candidate=str(candidate_db)
        self.tables=tuple(sorted(set(allowed_tables)))
        if not self.tables:raise EffectDenied('empty_allowed_scope')
        self.key=receiver_key
        for t in self.tables:ident(t)

    def _all_schema(self,db):
        return db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").fetchall()

    def _contents(self,db,table):
        return {str(row[0]):(int(row[1]),row[2]) for row in db.execute(f'SELECT id,rev,value FROM {ident(table)}')}

    def _delta(self):
        with closing(sqlite3.connect(self.base)) as base, closing(sqlite3.connect(self.candidate)) as fork:
            if self._all_schema(base)!=self._all_schema(fork):raise EffectDenied('candidate_schema_changed')
            changes=[]
            for table in self.tables:
                a=self._contents(base,table);b=self._contents(fork,table)
                if set(a)-set(b):raise EffectDenied('delete_requires_explicit_separate_authority')
                for k,(rev,v) in b.items():
                    if k not in a:
                        if rev!=0:raise EffectDenied('insert_must_have_zero_revision')
                        changes.append([table,k,None,None,v])
                    elif a[k]!=(rev,v):
                        if rev!=a[k][0] or v==a[k][1]:raise EffectDenied('candidate_version_mutation')
                        changes.append([table,k,a[k][0],a[k][1],v])
            # Ensure candidate did not modify off-scope tables.
            for _,table,_,_ in self._all_schema(base):
                if table in self.tables:continue
                if table.startswith('sqlite_'):continue
                if base.execute(f'SELECT * FROM {ident(table)}').fetchall()!=fork.execute(f'SELECT * FROM {ident(table)}').fetchall():
                    raise EffectDenied('off_scope_table_modified')
            return sorted(changes),[x for x in self._all_schema(base) if x[1]!='repair_promotions']

    def promote(self,task_id,*,verify_current=None):
        if not isinstance(task_id,str) or not 1<=len(task_id)<=96:raise EffectDenied('invalid_task')
        changes,base_schema=self._delta()
        if not changes:raise EffectDenied('empty_row_delta')
        with closing(sqlite3.connect(self.live,timeout=15)) as live:
            live.execute('BEGIN IMMEDIATE')
            try:
                live.execute('CREATE TABLE IF NOT EXISTS repair_promotions (task_id TEXT PRIMARY KEY, receipt TEXT NOT NULL)')
                existing=live.execute('SELECT receipt FROM repair_promotions WHERE task_id=?',(task_id,)).fetchone()
                if existing:
                    receipt=json.loads(existing[0]);live.rollback()
                    if receipt['body']['delta_sha256']!=hash_of(changes):raise EffectDenied('idempotency_mismatch')
                    return {'status':'ALREADY_COMMITTED','receipt':receipt}
                current_schema=[x for x in self._all_schema(live) if x[1]!='repair_promotions']
                if current_schema!=base_schema:raise EffectDenied('live_schema_changed')
                for table,key,base_rev,base_value,new_value in changes:
                    row=live.execute(f'SELECT rev,value FROM {ident(table)} WHERE id=?',(key,)).fetchone()
                    if base_rev is None:
                        if row is not None:raise EffectDenied('concurrent_insert_conflict')
                        live.execute(f'INSERT INTO {ident(table)} (id,rev,value) VALUES (?,?,?)',(key,0,new_value))
                    else:
                        if row!=(base_rev,base_value):raise EffectDenied('concurrent_row_conflict')
                        cur=live.execute(f'UPDATE {ident(table)} SET rev=?,value=? WHERE id=? AND rev=? AND value=?',
                                         (base_rev+1,new_value,key,base_rev,base_value))
                        if cur.rowcount!=1:raise EffectDenied('cas_conflict')
                if verify_current is not None and verify_current(live) is not True:
                    raise EffectDenied('verification_failed_rolled_back')
                receipt=seal(self.key,{'kind':'repair.sqlite_row_promotion.v1','task_id':task_id,
                      'delta_sha256':hash_of(changes),'changed_keys':[[t,k] for t,k,*_ in changes],
                      'status':'COMMITTED_LOCAL','at':int(time.time())})
                live.execute('INSERT INTO repair_promotions VALUES (?,?)',(task_id,json.dumps(receipt,sort_keys=True)))
                live.commit();return {'status':'COMMITTED','receipt':receipt}
            except BaseException:
                live.rollback();raise

    def recover(self,task_id):
        with closing(sqlite3.connect(self.live)) as live:
            try:
                row=live.execute('SELECT receipt FROM repair_promotions WHERE task_id=?',(task_id,)).fetchone()
            except sqlite3.OperationalError as exc:
                raise EffectDenied('not_found') from exc
            if row is None:raise EffectDenied('not_found')
            return {'status':'RECOVERED','receipt':json.loads(row[0])}
