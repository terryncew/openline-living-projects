"""Receiver-owned LOCAL SQLite effect admission, refusal receipts, and signed task recovery.

Supports scoped buyer delegations (operation, payload_hash, max_amount, allowed_targets),
out-of-rollback signed refusal receipts via SQLite SAVEPOINT, key rotation epochs, and
live effect-state tamper detection in verify_receipt.
"""
from __future__ import annotations
from contextlib import closing
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import base64
import hashlib
import json
import sqlite3
import time


class EffectDenied(Exception):
    def __init__(self, message: str, receipt: dict | None = None):
        super().__init__(message)
        self.receipt = receipt


def canonical(obj):
    return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()

def hash_of(obj): return hashlib.sha256(canonical(obj)).hexdigest()

def b64(raw): return base64.urlsafe_b64encode(raw).decode().rstrip('=')
def unb64(raw): return base64.urlsafe_b64decode(raw+'='*((-len(raw))%4))

def public(key):
    return b64(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))

def seal(key, body):
    return {'body':body,'signature':b64(key.sign(canonical(body)))}

def verify(signed, pub):
    if not isinstance(signed,dict) or set(signed)!={'body','signature'}: raise EffectDenied('invalid_envelope')
    try:
        Ed25519PublicKey.from_public_bytes(unb64(pub)).verify(unb64(signed['signature']),canonical(signed['body']))
    except (ValueError,TypeError,KeyError,Exception) as exc:
        raise EffectDenied('invalid_signature') from exc
    return signed['body']


_STORE_REGISTRY: dict[str, str] = {}


def _user_tables_hash(db: sqlite3.Connection) -> str:
    sys_tables = {'buyers', 'grants_revoked', 'task_effects', 'refusal_receipts', 'key_epochs'}
    rows = db.execute("SELECT name, type, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
    filtered_meta = [r for r in rows if r[0] not in sys_tables]
    payload = [filtered_meta]
    for name, kind, _ in filtered_meta:
        if kind != 'table':
            continue
        quoted = '"' + name.replace('"', '""') + '"'
        recs = [tuple(repr(v) for v in row) for row in db.execute(f'SELECT * FROM {quoted}')]
        payload.append([name, sorted(recs)])
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


class Principal:
    """Private key only in its own process/storage; not passed to receiver."""
    def __init__(self, seed: bytes | None = None):
        self.key=Ed25519PrivateKey.from_private_bytes(seed) if seed else Ed25519PrivateKey.generate()
        self.public=public(self.key)

    def delegate(self, worker_pub: str, *, task_id: str, mode: str, expires: int,
                 operation: str | None = None, payload: dict | None = None,
                 payload_hash: str | None = None, max_amount: int | float | None = None,
                 allowed_targets: list[str] | None = None):
        if mode not in ('execute','recover'): raise ValueError('invalid_mode')
        body = {'kind':'repair.delegation.v1','buyer':self.public,'worker':worker_pub,
                'task_id':task_id,'mode':mode,'expires':expires}
        if operation is not None:
            body['operation'] = operation
        if payload is not None:
            body['payload_hash'] = hash_of(payload)
        elif payload_hash is not None:
            body['payload_hash'] = payload_hash
        if max_amount is not None:
            body['max_amount'] = max_amount
        if allowed_targets is not None:
            body['allowed_targets'] = list(allowed_targets)
        return seal(self.key, body)

    def request(self, delegation, *, task_id: str, payload: dict, mode: str):
        return seal(self.key,{'kind':'repair.request.v1','worker':self.public,'task_id':task_id,
                              'mode':mode,'payload_hash':hash_of(payload),
                              'delegation_hash':hash_of(delegation)})


def _check_binding(bind, live_state):
    if bind is None:
        return
    if not isinstance(bind, dict) or not isinstance(bind.get("accepted_head"), str) or len(bind["accepted_head"]) != 40:
        raise EffectDenied("effect_binding_invalid")
    if live_state is None:
        return
    current = live_state()
    if not isinstance(current, dict):
        raise EffectDenied("effect_binding_unobserved")
    if current.get("accepted_head") != bind["accepted_head"]:
        raise EffectDenied("effect_binding_stale")
    for key in ("project", "dependency", "assignment_state"):
        if bind.get(key) is not None and current.get(key) != bind[key]:
            raise EffectDenied("effect_binding_stale")


class LocalEffectStore:
    def __init__(self, path, *, receiver_seed: bytes | None = None, clock=None):
        self.path=str(path);self.key=Ed25519PrivateKey.from_private_bytes(receiver_seed) if receiver_seed else Ed25519PrivateKey.generate()
        self.receiver_public=public(self.key);self.clock=clock or (lambda:int(time.time()))
        _STORE_REGISTRY[self.receiver_public] = self.path
        self.last_refusal_receipt = None
        with closing(sqlite3.connect(self.path)) as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS buyers(buyer TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS grants_revoked(digest TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS task_effects(
                buyer TEXT NOT NULL,task_id TEXT NOT NULL,payload_hash TEXT NOT NULL,
                receipt TEXT NOT NULL,PRIMARY KEY(buyer,task_id));
            CREATE TABLE IF NOT EXISTS refusal_receipts(
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL, reason TEXT NOT NULL,
                receipt TEXT NOT NULL, at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS key_epochs(
                epoch INTEGER PRIMARY KEY AUTOINCREMENT,
                public_key TEXT NOT NULL, rotated_at INTEGER NOT NULL,
                rotation_cert TEXT);
            ''')
            if not db.execute('SELECT 1 FROM key_epochs WHERE public_key=?', (self.receiver_public,)).fetchone():
                db.execute('INSERT INTO key_epochs(public_key, rotated_at, rotation_cert) VALUES (?, ?, NULL)',
                           (self.receiver_public, self.clock()))
            db.commit()

    def rotate_receiver_key(self, new_seed: bytes | None = None) -> dict:
        new_key = Ed25519PrivateKey.from_private_bytes(new_seed) if new_seed else Ed25519PrivateKey.generate()
        new_pub = public(new_key)
        cert = seal(self.key, {
            'kind': 'repair.key_rotation.v1',
            'old_receiver_pub': self.receiver_public,
            'new_receiver_pub': new_pub,
            'at': self.clock(),
        })
        with closing(sqlite3.connect(self.path)) as db:
            db.execute('INSERT INTO key_epochs(public_key, rotated_at, rotation_cert) VALUES (?, ?, ?)',
                       (new_pub, self.clock(), json.dumps(cert, sort_keys=True)))
            db.commit()
        self.key = new_key
        self.receiver_public = new_pub
        _STORE_REGISTRY[self.receiver_public] = self.path
        return cert

    def register_buyer(self,buyer_pub:str):
        Ed25519PublicKey.from_public_bytes(unb64(buyer_pub))
        with closing(sqlite3.connect(self.path)) as db:
            db.execute('INSERT OR IGNORE INTO buyers VALUES (?)',(buyer_pub,));db.commit()

    def revoke(self,delegation):
        with closing(sqlite3.connect(self.path)) as db:
            db.execute('INSERT OR IGNORE INTO grants_revoked VALUES (?)',(hash_of(delegation),));db.commit()

    def _authenticate(self,db,delegation,request,task_id,payload,mode):
        g=delegation.get('body',{});r=request.get('body',{})
        if g.get('kind')!='repair.delegation.v1' or r.get('kind')!='repair.request.v1': raise EffectDenied('invalid_profile')
        buyer=g['buyer'];worker=g['worker']
        verify(delegation,buyer);verify(request,worker)
        if not db.execute('SELECT 1 FROM buyers WHERE buyer=?',(buyer,)).fetchone(): raise EffectDenied('buyer_not_registered')
        if db.execute('SELECT 1 FROM grants_revoked WHERE digest=?',(hash_of(delegation),)).fetchone(): raise EffectDenied('grant_revoked')
        if not isinstance(g.get('expires'),int) or g['expires']<=self.clock(): raise EffectDenied('grant_expired')
        if g['task_id']!=task_id or g['mode']!=mode or r != {'kind':'repair.request.v1','worker':worker,
                'task_id':task_id,'mode':mode,'payload_hash':hash_of(payload),'delegation_hash':hash_of(delegation)}:
            raise EffectDenied('request_not_delegated')
        if 'payload_hash' in g and g['payload_hash'] != hash_of(payload):
            raise EffectDenied('delegation_payload_mismatch')
        if 'operation' in g and isinstance(payload, dict) and payload.get('action', payload.get('operation', g['operation'])) != g['operation']:
            raise EffectDenied('delegation_operation_mismatch')
        if 'max_amount' in g and isinstance(payload, dict) and isinstance(payload.get('amount'), (int, float)):
            if payload['amount'] > g['max_amount'] or payload['amount'] <= 0:
                raise EffectDenied('delegation_amount_exceeded')
        if 'allowed_targets' in g and isinstance(payload, dict) and 'target' in payload:
            if payload['target'] not in g['allowed_targets']:
                raise EffectDenied('delegation_target_not_allowed')
        # Guard against unscoped payload/amount forgery when buyer delegation omitted payload_hash/max_amount
        if isinstance(payload, dict) and 'payload_hash' not in g:
            if 'action' in payload and 'operation' not in g:
                raise EffectDenied('unscoped_action_payload_refused')
            if isinstance(payload.get('amount'), (int, float)) and payload['amount'] > 10000 and 'max_amount' not in g:
                raise EffectDenied('unscoped_high_amount_payload_refused')
        return buyer

    def _record_refusal(self, db, task_id: str, payload, reason: str, bind=None) -> dict:
        rec = seal(self.key, {
            'kind': 'repair.local_effect_refusal.v1',
            'task_id': str(task_id),
            'payload_hash': hash_of(payload) if isinstance(payload, (dict, list, str, int, float, bool)) or payload is None else '',
            'status': 'REFUSED',
            'reason': reason,
            'at': self.clock(),
            'binding': bind,
        })
        db.execute('INSERT INTO refusal_receipts(task_id, reason, receipt, at) VALUES (?, ?, ?, ?)',
                   (str(task_id), reason, json.dumps(rec, sort_keys=True), self.clock()))
        self.last_refusal_receipt = rec
        return rec

    def get_refusals(self, task_id: str | None = None) -> list[dict]:
        with closing(sqlite3.connect(self.path)) as db:
            if task_id is None:
                rows = db.execute('SELECT receipt FROM refusal_receipts ORDER BY seq').fetchall()
            else:
                rows = db.execute('SELECT receipt FROM refusal_receipts WHERE task_id=? ORDER BY seq', (task_id,)).fetchall()
        return [json.loads(r[0]) for r in rows]

    def apply(self, *, delegation, request, task_id, payload, effect, observe, standing=None, bind=None, live_state=None):
        if not isinstance(task_id,str) or not 1<=len(task_id)<=96:raise EffectDenied('bad_task_id')
        with closing(sqlite3.connect(self.path,timeout=15)) as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('SAVEPOINT openline_effect_attempt')
            try:
                buyer=self._authenticate(db,delegation,request,task_id,payload,'execute')
                existing=db.execute('SELECT payload_hash,receipt FROM task_effects WHERE buyer=? AND task_id=?',(buyer,task_id)).fetchone()
                if existing:
                    if existing[0]!=hash_of(payload): raise EffectDenied('idempotency_conflict')
                    db.execute('RELEASE SAVEPOINT openline_effect_attempt')
                    db.commit()
                    return {'status':'ALREADY_COMMITTED','receipt':json.loads(existing[1])}
                if standing is not None and standing(db) is not True:raise EffectDenied('evidence_not_current')
                _check_binding(bind, live_state)
                effect(db)
                if observe(db) is not True:raise EffectDenied('effect_not_verified_rolled_back')
                if standing is not None and standing(db) is not True:raise EffectDenied('evidence_changed_before_commit')
                _check_binding(bind, live_state)
                state_sha = _user_tables_hash(db)
                rec=seal(self.key,{'kind':'repair.local_effect.v1','buyer':buyer,'task_id':task_id,
                       'payload_hash':hash_of(payload),'status':'VERIFIED_LOCAL','at':self.clock(),
                       'binding':bind,'effect_state_sha256':state_sha})
                db.execute('INSERT INTO task_effects VALUES (?,?,?,?)',(buyer,task_id,hash_of(payload),json.dumps(rec,sort_keys=True)))
                db.execute('RELEASE SAVEPOINT openline_effect_attempt')
                db.commit()
                return {'status':'COMMITTED','receipt':rec}
            except EffectDenied as exc:
                db.execute('ROLLBACK TO SAVEPOINT openline_effect_attempt')
                db.execute('RELEASE SAVEPOINT openline_effect_attempt')
                ref_rec = self._record_refusal(db, task_id, payload, str(exc), bind=bind)
                db.commit()
                exc.receipt = ref_rec
                raise
            except BaseException:
                db.rollback()
                raise

    def recover(self, *, delegation, request, task_id, payload):
        with closing(sqlite3.connect(self.path)) as db:
            buyer=self._authenticate(db,delegation,request,task_id,payload,'recover')
            row=db.execute('SELECT payload_hash,receipt FROM task_effects WHERE buyer=? AND task_id=?',(buyer,task_id)).fetchone()
            if row is None:raise EffectDenied('not_found')
            if row[0]!=hash_of(payload):raise EffectDenied('idempotency_conflict')
            return {'status':'RECOVERED','receipt':json.loads(row[1])}

    @staticmethod
    def verify_receipt(receipt, receiver_pub, *, db_path: str | None = None):
        claim=verify(receipt,receiver_pub)
        if claim.get('kind') == 'repair.local_effect_refusal.v1' and claim.get('status') == 'REFUSED':
            return claim
        if claim.get('kind')!='repair.local_effect.v1' or claim.get('status')!='VERIFIED_LOCAL':
            raise EffectDenied('invalid_receipt_profile')
        resolved_db = db_path or _STORE_REGISTRY.get(receiver_pub)
        if resolved_db and 'effect_state_sha256' in claim and Path(resolved_db).is_file():
            with closing(sqlite3.connect(resolved_db)) as db:
                live_sha = _user_tables_hash(db)
                if live_sha != claim['effect_state_sha256']:
                    # Check if a later legitimate receipt in task_effects accounts for current live_sha
                    rows = db.execute('SELECT receipt FROM task_effects').fetchall()
                    known_hashes = {json.loads(r[0]).get('body', {}).get('effect_state_sha256') for r in rows}
                    if live_sha not in known_hashes:
                        raise EffectDenied('effect_state_tampered_or_deleted')
        return claim
