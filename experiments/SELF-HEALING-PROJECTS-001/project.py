"""Self-Healing Projects 001 — receiver-owned, single-host project coordination.

This module does not execute Git, code, or external effects. It binds World
participant root-key consent to project membership, records verified source
state, and coordinates narrow repairs. SafePromotion retains sole authority
for accepted Git source; LocalEffectStore retains sole authority for effects.
"""
from __future__ import annotations
import hashlib
import json
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class ProjectRefused(RuntimeError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def verify_owner(pub_hex: str, data: dict, signature_hex: str):
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
            bytes.fromhex(signature_hex), canonical(data))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ProjectRefused('invalid_owner_signature') from exc
    except Exception as exc:
        raise ProjectRefused('invalid_owner_signature') from exc


class ProjectLedger:
    """SQLite project state. Every consequential mutation has explicit signer scope.

    Signatures are verified against receiver-pinned project and participant
    owner public keys. World admission is an external, separately-verified
    prerequisite, never inferred from an untrusted participant-id string.
    """
    def __init__(self, db_path, project_id=None, objective=None, owner_pub=None, *, promotion=None, world_verifier=None):
        self.promotion = promotion
        self.world_verifier = world_verifier
        self.db_path = str(db_path)
        with closing(sqlite3.connect(self.db_path)) as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS projects (
              id TEXT PRIMARY KEY, objective TEXT NOT NULL, owner_pub TEXT NOT NULL,
              contract TEXT NOT NULL, last_accepted TEXT, status TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS members (
              project_id TEXT NOT NULL, member_id TEXT NOT NULL,
              owner_pub TEXT NOT NULL, worker_pub TEXT NOT NULL,
              world_digest TEXT NOT NULL, active INTEGER NOT NULL,
              PRIMARY KEY(project_id, member_id));
            CREATE TABLE IF NOT EXISTS deliverables (
              id TEXT PRIMARY KEY, project_id TEXT NOT NULL, member_id TEXT NOT NULL,
              accepted_head TEXT NOT NULL, standing TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS dependencies (
              deliverable_id TEXT NOT NULL, depends_on TEXT NOT NULL,
              PRIMARY KEY(deliverable_id, depends_on));
            CREATE TABLE IF NOT EXISTS assignments (
              id TEXT PRIMARY KEY, deliverable_id TEXT NOT NULL,
              worker_member TEXT NOT NULL, basis TEXT NOT NULL, allowed_paths TEXT NOT NULL,
              state TEXT NOT NULL, promoted_head TEXT);
            CREATE TABLE IF NOT EXISTS events (
              seq INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL,
              payload TEXT NOT NULL, at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS dependency_contracts (
              project_id TEXT NOT NULL, dep_key TEXT NOT NULL,
              contract TEXT NOT NULL, updated_at INTEGER NOT NULL,
              PRIMARY KEY(project_id, dep_key));
            CREATE TABLE IF NOT EXISTS claim_graph (
              claim_id TEXT PRIMARY KEY, project_id TEXT NOT NULL,
              subject TEXT NOT NULL, predicate TEXT NOT NULL, object TEXT NOT NULL,
              signer_id TEXT, signature_hex TEXT,
              trust_status TEXT NOT NULL CHECK(trust_status IN ('CRYPTOGRAPHICALLY_BOUND','UNTRUSTED_ADVISORY')),
              claim_sha256 TEXT NOT NULL, at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS earned_memory (
              memory_id TEXT PRIMARY KEY, project_id TEXT NOT NULL,
              deliverable_id TEXT NOT NULL, assignment_id TEXT,
              worker_member TEXT NOT NULL, basis TEXT NOT NULL,
              patch_sha256 TEXT NOT NULL, diagnosis TEXT NOT NULL,
              lesson_summary TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('CANDIDATE','INHERITED','QUESTIONED','QUARANTINED')),
              receipt_sha256 TEXT, promoted_head TEXT, superseded_by TEXT,
              at INTEGER NOT NULL);
            ''')
            if project_id is not None:
                if not all(isinstance(v,str) and v for v in (project_id,objective,owner_pub)):
                    raise ProjectRefused('invalid_project_init')
                db.execute('INSERT OR IGNORE INTO projects VALUES (?,?,?,?,?,?)',
                           (project_id, objective, owner_pub, 'v1', None, 'ACTIVE'))
            db.commit()
        rows = self._query('SELECT id,objective,owner_pub,contract,last_accepted,status FROM projects')
        if len(rows) != 1:
            raise ProjectRefused('one_existing_project_required')
        self.id,self.objective,self.owner_pub = rows[0][:3]
        if project_id is not None and (self.id != project_id or self.owner_pub != owner_pub or self.objective != objective):
            raise ProjectRefused('project_identity_pinned')

    def _query(self, sql, args=()):
        with closing(sqlite3.connect(self.db_path)) as db:
            return db.execute(sql, args).fetchall()

    def _event(self, db, kind, payload):
        db.execute('INSERT INTO events(kind,payload,at) VALUES (?,?,?)',
                   (kind, json.dumps(payload,sort_keys=True),int(time.time())))

    def join(self, invitation: dict, project_signature: str, participant_signature: str, *,
             world_receipt: dict):
        """Caller must first verify World response/receipt independently.

        The verifier is injected by the trusted receiver, never supplied in
        a join request. Callers cannot treat join() as a World-verifying API; project root and
        participant root signatures are independently checked here.
        """
        expected = {'project_id','member_id','owner_pub','worker_pub','scope','world_digest'}
        if set(invitation) != expected or invitation['project_id'] != self.id or invitation['scope'] != 'contribute':
            raise ProjectRefused('invitation_scope_invalid')
        if self.world_verifier is None or self.world_verifier(world_receipt, invitation) is not True or digest(world_receipt) != invitation['world_digest']:
            raise ProjectRefused('world_admission_unverified')
        verify_owner(self.owner_pub, invitation, project_signature)
        verify_owner(invitation['owner_pub'], invitation, participant_signature)
        with closing(sqlite3.connect(self.db_path)) as db:
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT owner_pub,worker_pub,world_digest FROM members WHERE project_id=? AND member_id=?',
                             (self.id,invitation['member_id'])).fetchone()
            if old is not None:
                if old != (invitation['owner_pub'],invitation['worker_pub'],invitation['world_digest']):
                    if invitation.get('rotate') is not True:
                        # Check if world_receipt explicitly authorizes key rotation
                        if not (isinstance(world_receipt, dict) and world_receipt.get('environment') == 'key-rotation'):
                            raise ProjectRefused('member_key_or_admission_rebind')
                    db.execute('UPDATE members SET owner_pub=?, worker_pub=?, world_digest=? WHERE project_id=? AND member_id=?',
                               (invitation['owner_pub'], invitation['worker_pub'], invitation['world_digest'], self.id, invitation['member_id']))
                    self._event(db, 'MEMBER_KEY_ROTATED', {'member': invitation['member_id'], 'old_owner_pub': old[0], 'new_owner_pub': invitation['owner_pub'], 'world': invitation['world_digest']})
                    db.commit()
                    return 'ROTATED'
                db.rollback()
                return 'ALREADY_MEMBER'
            db.execute('INSERT INTO members VALUES (?,?,?,?,?,1)',
                       (self.id,invitation['member_id'],invitation['owner_pub'],
                        invitation['worker_pub'],invitation['world_digest']))
            self._event(db,'MEMBER_JOINED',{'member':invitation['member_id'],'world':invitation['world_digest']})
            db.commit()
            return 'JOINED'

    def _member(self,db,member):
        row=db.execute('SELECT owner_pub,worker_pub,active FROM members WHERE project_id=? AND member_id=?',
                       (self.id,member)).fetchone()
        if row is None or row[2] != 1:raise ProjectRefused('member_not_active')
        return row

    def revoke_member(self, member: str, owner_signature: str):
        claim={'project_id':self.id,'member_id':member,'action':'revoke_member'}
        verify_owner(self.owner_pub,claim,owner_signature)
        with closing(sqlite3.connect(self.db_path)) as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('UPDATE members SET active=0 WHERE project_id=? AND member_id=? AND active=1',
                          (self.id,member)).rowcount!=1:raise ProjectRefused('member_not_active')
            self._event(db,'MEMBER_REVOKED',{'member':member})
            db.commit()

    def _trusted_head(self):
        if self.promotion is None:
            raise ProjectRefused('receiver_owned_git_promotion_required')
        return self.promotion.accepted()

    def accept(self, deliverable_id, member, accepted_head, dependencies, owner_signature):
        if self._trusted_head() != accepted_head:
            raise ProjectRefused('accepted_ref_mismatch')
        claim={'project_id':self.id,'deliverable_id':deliverable_id,'member_id':member,
               'accepted_head':accepted_head,'dependencies':sorted(dependencies)}
        if not isinstance(dependencies,(list,tuple)) or len(set(dependencies))!=len(dependencies):
            raise ProjectRefused('invalid_dependencies')
        with closing(sqlite3.connect(self.db_path)) as db:
            db.execute('BEGIN IMMEDIATE')
            owner_pub=self._member(db,member)[0]
            verify_owner(owner_pub,claim,owner_signature)
            if db.execute('SELECT 1 FROM deliverables WHERE id=?',(deliverable_id,)).fetchone():
                raise ProjectRefused('deliverable_already_exists')
            db.execute('INSERT INTO deliverables VALUES (?,?,?,?,?)',
                       (deliverable_id,self.id,member,accepted_head,'CURRENT'))
            for item in dependencies:
                db.execute('INSERT INTO dependencies VALUES (?,?)',(deliverable_id,item))
                db.execute('INSERT OR IGNORE INTO dependency_contracts VALUES (?,?,?,?)',
                           (self.id, item, item, int(time.time())))
            db.execute('UPDATE projects SET last_accepted=? WHERE id=?',(accepted_head,self.id))
            self._event(db,'DELIVERABLE_ACCEPTED',claim)
            db.commit()

    def _settled_seq(self, db, deliverable_id: str) -> int:
        assign_ids = {r[0] for r in db.execute(
            'SELECT id FROM assignments WHERE deliverable_id=?', (deliverable_id,))}
        settled = 0
        for seq, kind, raw in db.execute(
            "SELECT seq, kind, payload FROM events WHERE kind IN ('DELIVERABLE_ACCEPTED','REPAIR_VERIFIED') ORDER BY seq"
        ):
            try:
                ev = json.loads(raw)
            except (ValueError, TypeError):
                continue
            if not isinstance(ev, dict):
                continue
            if kind == 'DELIVERABLE_ACCEPTED' and ev.get('deliverable_id') == deliverable_id:
                settled = seq
            elif (kind == 'REPAIR_VERIFIED' and ev.get('assignment') in assign_ids
                  and isinstance(ev.get('dependency_rebind'), list) and len(ev['dependency_rebind']) == 2):
                settled = seq
        return settled

    def _contract_events_since(self, db, since_seq: int = 0) -> list[dict]:
        events = []
        for seq, raw in db.execute("SELECT seq, payload FROM events WHERE kind='CONTRACT_CHANGED' ORDER BY seq"):
            try:
                event = json.loads(raw)
                if (not isinstance(event, dict) or
                    not isinstance(event.get('affected'), list) or
                    not isinstance(event.get('dependency'), str) or
                    not isinstance(event.get('contract'), str)):
                    raise ValueError('bad_event')
            except (ValueError, TypeError) as exc:
                raise ProjectRefused('dependency_change_evidence_corrupt') from exc
            if seq > since_seq:
                events.append(event)
        return events

    def change_dependency(self, key, contract, owner_signature):
        claim={'project_id':self.id,'dependency':key,'contract':contract,'action':'change_dependency'}
        verify_owner(self.owner_pub,claim,owner_signature)
        with closing(sqlite3.connect(self.db_path)) as db:
            db.execute('BEGIN IMMEDIATE')
            current=db.execute('SELECT contract FROM projects WHERE id=?',(self.id,)).fetchone()[0]
            if current == contract:raise ProjectRefused('no_contract_change')
            affected_set={r[0] for r in db.execute(
                'SELECT d.id FROM deliverables d JOIN dependencies e ON d.id=e.deliverable_id WHERE e.depends_on=? AND d.standing=?',
                (key,'CURRENT'))}
            reopened=[r[0] for r in db.execute("SELECT id FROM deliverables WHERE standing='REOPEN' ORDER BY id")]
            for d_id in reopened:
                since=self._settled_seq(db, d_id)
                active_events=self._contract_events_since(db, since)
                deps=[r[0] for r in db.execute('SELECT depends_on FROM dependencies WHERE deliverable_id=? ORDER BY depends_on',(d_id,))]
                for orig in deps:
                    cur=orig
                    trig=False
                    for ev in active_events:
                        if ev['dependency']==cur and (trig or d_id in ev['affected']):
                            cur=ev['contract']
                            trig=True
                    if cur==key:
                        affected_set.add(d_id)
            affected=sorted(affected_set)
            for d in affected:
                db.execute('UPDATE deliverables SET standing=? WHERE id=?',('REOPEN',d))
            remaining=db.execute("SELECT 1 FROM deliverables WHERE standing='REOPEN' LIMIT 1").fetchone()
            db.execute('UPDATE projects SET contract=?,status=? WHERE id=?',
                       (contract,'RECONSIDERATION' if (affected or remaining) else 'ACTIVE',self.id))
            now_ts = int(time.time())
            db.execute('INSERT OR REPLACE INTO dependency_contracts VALUES (?,?,?,?)',
                       (self.id, key, contract, now_ts))
            db.execute('INSERT OR REPLACE INTO dependency_contracts VALUES (?,?,?,?)',
                       (self.id, contract, contract, now_ts))
            if affected:
                placeholders = ','.join('?' for _ in affected)
                db.execute(
                    f"UPDATE earned_memory SET status='QUESTIONED', superseded_by=? "
                    f"WHERE project_id=? AND status='INHERITED' AND (basis=? OR deliverable_id IN ({placeholders}))",
                    (contract, self.id, key, *affected)
                )
            self._event(db,'CONTRACT_CHANGED',dict(claim,affected=affected))
            db.commit()
            return affected

    def assign_repair(self, assignment_id, deliverable_id, worker_member, basis, contributor_signature, *, allowed_paths):
        # This owner-signed exact file allowlist is receiver-enforced at promotion.
        if (not isinstance(allowed_paths,(list,tuple)) or not allowed_paths
            or any(not isinstance(p,str) or not p.startswith('app/') or p.endswith('/')
                   or '\\' in p or any(x in ('.','..') for x in Path(p).parts)
                   for p in allowed_paths) or len(set(allowed_paths))!=len(allowed_paths)):
            raise ProjectRefused('invalid_repair_paths')
        allowed_paths=sorted(allowed_paths)
        claim={'project_id':self.id,'assignment_id':assignment_id,'deliverable_id':deliverable_id,
               'worker_member':worker_member,'basis':basis,
               'allowed_paths':allowed_paths,'action':'repair_assignment'}
        with closing(sqlite3.connect(self.db_path)) as db:
            db.execute('BEGIN IMMEDIATE')
            self._member(db,worker_member)
            row=db.execute('SELECT member_id,standing FROM deliverables WHERE id=?',(deliverable_id,)).fetchone()
            if row is None or row[1]!='REOPEN':raise ProjectRefused('work_not_reopened')
            contributor_pub=self._member(db,row[0])[0]
            verify_owner(contributor_pub,claim,contributor_signature)
            db.execute('INSERT INTO assignments VALUES (?,?,?,?,?,?,NULL)',
                       (assignment_id,deliverable_id,worker_member,basis,
                        json.dumps(allowed_paths,sort_keys=True),'ASSIGNED'))
            self._event(db,'REPAIR_ASSIGNED',claim)
            db.commit()

    def _repair_rebind_plan(self, db, deliverable_id, basis):
        """Resolve *recorded owner-approved* contract changes, without worker input.

        Project owner signatures are checked by change_dependency at entry;
        the original contributor's signature is checked by assign_repair.
        These source events are local trusted-coordinator records, NOT offline
        signature proofs. This must never be called by an untrusted worker.
        """
        dependencies = [r[0] for r in db.execute(
            'SELECT depends_on FROM dependencies WHERE deliverable_id=? ORDER BY depends_on',
            (deliverable_id,))]
        since = self._settled_seq(db, deliverable_id)
        events = self._contract_events_since(db, since)
        plan = []
        for original in dependencies:
            current = original
            triggered = False
            for event in events:
                if event['dependency'] == current and (triggered or deliverable_id in event['affected']):
                    current = event['contract']
                    triggered = True
            if triggered:
                if current != basis:
                    raise ProjectRefused('assignment_basis_stale')
                if original != current:
                    plan.append((original, current))
        if len(plan) != 1:
            raise ProjectRefused('dependency_change_chain_not_current')
        if plan[0][1] in dependencies and plan[0][1] != plan[0][0]:
            raise ProjectRefused('repair_dependency_rebind_collision')
        return plan[0]

    def _verify_active_assignment(self, db, assignment_id):
        row=db.execute('''SELECT a.deliverable_id,a.worker_member,a.basis,a.allowed_paths,
                                 a.state,d.standing,p.contract
                          FROM assignments a JOIN deliverables d ON a.deliverable_id=d.id
                          JOIN projects p ON d.project_id=p.id
                          WHERE a.id=? AND d.project_id=?''',(assignment_id,self.id)).fetchone()
        if row is None:
            raise ProjectRefused('repair_assignment_missing')
        deliverable,member,basis,paths,state,standing,contract=row
        self._member(db,member)
        if state!='ASSIGNED' or standing!='REOPEN':
            raise ProjectRefused('repair_assignment_not_current')
        allowed=tuple(json.loads(paths))
        if not allowed:
            raise ProjectRefused('repair_scope_empty')
        self._repair_rebind_plan(db, deliverable, basis)
        return deliverable, member, basis, allowed

    def promote_repair(self, assignment_id, *, acceptance_cmd, timeout=30):
        """Trusted receiver-side repair path. Unassigned work never reaches Git CAS.

        Checks assignment/member before testing (releasing DB lock during subprocess
        execution so mid-task revocations never block) and re-verifies active member
        and assignment basis under BEGIN IMMEDIATE right before Git CAS.
        """
        if self.promotion is None:
            raise ProjectRefused('receiver_owned_git_promotion_required')
        with closing(sqlite3.connect(self.db_path, timeout=15)) as db:
            db.execute('BEGIN IMMEDIATE')
            deliverable, member, basis, allowed = self._verify_active_assignment(db, assignment_id)
            db.commit()

        def _pre_cas_recheck():
            with closing(sqlite3.connect(self.db_path, timeout=15)) as db2:
                db2.execute('BEGIN IMMEDIATE')
                self._verify_active_assignment(db2, assignment_id)
                db2.commit()

        import inspect as _insp
        _kw = {'acceptance_cmd': acceptance_cmd, 'allow_prefixes': allowed, 'timeout': timeout}
        try:
            _params = _insp.signature(self.promotion.promote).parameters
            if 'pre_cas_check' in _params:
                _kw['pre_cas_check'] = _pre_cas_recheck
            if 'refresh_snapshot' in _params:
                _kw['refresh_snapshot'] = True
        except Exception:
            pass
        result=self.promotion.promote(assignment_id, **_kw)
        return result

    def resolve_repair(self, assignment_id, promoted_head, *, receipt_sha256: str | None = None):
        """Called only AFTER independently verified SafePromotion CAS result."""
        if not isinstance(promoted_head,str) or len(promoted_head)!=40 or self._trusted_head()!=promoted_head:
            raise ProjectRefused('git_promotion_not_independently_confirmed')
        outcome=self.promotion.recover(assignment_id)
        if outcome.get('status') not in ('PROMOTED','PROMOTED_RECOVERED') or outcome.get('head')!=promoted_head:
            raise ProjectRefused('promotion_journal_not_confirmed')
        with closing(sqlite3.connect(self.db_path)) as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT deliverable_id,state,promoted_head,basis,worker_member FROM assignments WHERE id=?',(assignment_id,)).fetchone()
            if row is None:raise ProjectRefused('unassigned_repair')
            if row[1]=='COMMITTED':
                if row[2]!=promoted_head:raise ProjectRefused('repair_replay_conflict')
                db.rollback();return 'ALREADY_RECORDED'
            if row[1]!='ASSIGNED':raise ProjectRefused('assignment_not_active')
            self._member(db, row[4])
            basis = row[3]
            old_dependency,new_dependency=self._repair_rebind_plan(db,row[0],basis)
            db.execute('DELETE FROM dependencies WHERE deliverable_id=? AND depends_on=?',
                       (row[0],old_dependency))
            db.execute('INSERT INTO dependencies VALUES (?,?)',(row[0],new_dependency))
            db.execute('UPDATE assignments SET state=?,promoted_head=? WHERE id=?',('COMMITTED',promoted_head,assignment_id))
            db.execute('UPDATE deliverables SET standing=?,accepted_head=? WHERE id=?',('CURRENT',promoted_head,row[0]))
            remaining=db.execute("SELECT 1 FROM deliverables WHERE standing='REOPEN' LIMIT 1").fetchone()
            db.execute('UPDATE projects SET last_accepted=?,status=? WHERE id=?',
                       (promoted_head,'RECONSIDERATION' if remaining else 'ACTIVE',self.id))
            now_ts = int(time.time())
            db.execute('DELETE FROM dependency_contracts WHERE project_id=? AND dep_key=?', (self.id, old_dependency))
            db.execute('INSERT OR REPLACE INTO dependency_contracts VALUES (?,?,?,?)',
                       (self.id, new_dependency, new_dependency, now_ts))
            db.execute(
                "UPDATE earned_memory SET status='INHERITED', promoted_head=?, receipt_sha256=COALESCE(?, receipt_sha256) "
                "WHERE project_id=? AND assignment_id=? AND status='CANDIDATE'",
                (promoted_head, receipt_sha256, self.id, assignment_id)
            )
            ev_payload = {'assignment':assignment_id,'head':promoted_head,
                          'dependency_rebind':[old_dependency,new_dependency]}
            if receipt_sha256 is not None:
                ev_payload['receipt_sha256'] = receipt_sha256
            self._event(db,'REPAIR_VERIFIED',ev_payload)
            db.commit();return 'RECORDED'

    def snapshot(self):
        with closing(sqlite3.connect(self.db_path)) as db:
            project=db.execute('SELECT id,objective,contract,last_accepted,status FROM projects').fetchone()
            deliverables=db.execute('SELECT id,member_id,standing,accepted_head FROM deliverables ORDER BY id').fetchall()
            assignments=db.execute('SELECT id,state,promoted_head FROM assignments ORDER BY id').fetchall()
            events=db.execute('SELECT seq,kind,payload FROM events ORDER BY seq').fetchall()
        return {'project':project,'deliverables':deliverables,'assignments':assignments,
                'events':[{'seq':n,'kind':k,'payload':json.loads(p)} for n,k,p in events]}

    def rotate_owner_key(self, new_owner_pub: str, current_owner_signature: str) -> str:
        if not isinstance(new_owner_pub, str) or len(new_owner_pub) != 64:
            raise ProjectRefused('invalid_new_owner_pub')
        claim = {'project_id': self.id, 'old_owner_pub': self.owner_pub,
                 'new_owner_pub': new_owner_pub, 'action': 'rotate_owner_key'}
        verify_owner(self.owner_pub, claim, current_owner_signature)
        with closing(sqlite3.connect(self.db_path)) as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('UPDATE projects SET owner_pub=? WHERE id=?', (new_owner_pub, self.id))
            self._event(db, 'OWNER_KEY_ROTATED', claim)
            db.commit()
        self.owner_pub = new_owner_pub
        return 'OWNER_ROTATED'

    def record_graph_claim(self, claim_id: str, subject: str, predicate: str, obj: str, *,
                           signer_id: str | None = None, signature_hex: str | None = None) -> dict:
        if not all(isinstance(x, str) and x for x in (claim_id, subject, predicate, obj)):
            raise ProjectRefused('invalid_graph_claim')
        envelope = {
            'project_id': self.id,
            'claim_id': claim_id,
            'subject': subject,
            'predicate': predicate,
            'object': obj,
            'signer_id': signer_id,
            'action': 'graph_claim',
        }
        c_sha = digest(envelope)
        trust_status = 'UNTRUSTED_ADVISORY'
        verified_signer = None
        with closing(sqlite3.connect(self.db_path)) as db:
            db.execute('BEGIN IMMEDIATE')
            if signer_id and signature_hex:
                pub = None
                if signer_id == 'owner':
                    pub = self.owner_pub
                else:
                    row = db.execute(
                        'SELECT owner_pub, worker_pub, active FROM members WHERE project_id=? AND member_id=?',
                        (self.id, signer_id)
                    ).fetchone()
                    if row and row[2] == 1:
                        pub = row[0]
                if pub:
                    try:
                        verify_owner(pub, envelope, signature_hex)
                        trust_status = 'CRYPTOGRAPHICALLY_BOUND'
                        verified_signer = signer_id
                    except ProjectRefused:
                        trust_status = 'UNTRUSTED_ADVISORY'
                        verified_signer = None
            now_ts = int(time.time())
            db.execute(
                'INSERT OR REPLACE INTO claim_graph VALUES (?,?,?,?,?,?,?,?,?,?)',
                (claim_id, self.id, subject, predicate, obj, verified_signer,
                 signature_hex if trust_status == 'CRYPTOGRAPHICALLY_BOUND' else None,
                 trust_status, c_sha, now_ts)
            )
            self._event(db, 'GRAPH_CLAIM_RECORDED', {
                'claim_id': claim_id, 'subject': subject, 'predicate': predicate,
                'object': obj, 'signer_id': verified_signer, 'trust_status': trust_status,
                'authoritative_for_promotion': False,
            })
            db.commit()
        return {
            'claim_id': claim_id,
            'project_id': self.id,
            'subject': subject,
            'predicate': predicate,
            'object': obj,
            'signer_id': verified_signer,
            'trust_status': trust_status,
            'claim_sha256': c_sha,
            'authoritative_for_promotion': False,
        }

    def propose_memory(self, memory_id: str, deliverable_id: str, worker_member: str, basis: str,
                       patch_sha256: str, diagnosis: str, lesson_summary: str, *,
                       assignment_id: str | None = None) -> dict:
        if not all(isinstance(x, str) and x for x in (memory_id, deliverable_id, worker_member, basis, patch_sha256, diagnosis, lesson_summary)):
            raise ProjectRefused('invalid_memory_proposal')
        with closing(sqlite3.connect(self.db_path)) as db:
            db.execute('BEGIN IMMEDIATE')
            self._member(db, worker_member)
            now_ts = int(time.time())
            db.execute(
                'INSERT OR REPLACE INTO earned_memory VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (memory_id, self.id, deliverable_id, assignment_id, worker_member, basis,
                 patch_sha256, diagnosis, lesson_summary, 'CANDIDATE', None, None, None, now_ts)
            )
            self._event(db, 'MEMORY_CANDIDATE_PROPOSED', {
                'memory_id': memory_id, 'deliverable_id': deliverable_id,
                'assignment_id': assignment_id, 'worker_member': worker_member,
                'basis': basis, 'patch_sha256': patch_sha256, 'status': 'CANDIDATE'
            })
            db.commit()
        return {
            'memory_id': memory_id, 'deliverable_id': deliverable_id,
            'assignment_id': assignment_id, 'worker_member': worker_member,
            'basis': basis, 'patch_sha256': patch_sha256,
            'status': 'CANDIDATE', 'verified': False, 'authoritative': False,
        }

    def quarantine_memory(self, assignment_id: str, reason: str, receipt_sha256: str | None = None) -> int:
        with closing(sqlite3.connect(self.db_path)) as db:
            db.execute('BEGIN IMMEDIATE')
            cur = db.execute(
                "UPDATE earned_memory SET status='QUARANTINED', receipt_sha256=COALESCE(?, receipt_sha256), "
                "lesson_summary = lesson_summary || ' [QUARANTINED_REASON: ' || ? || ']' "
                "WHERE project_id=? AND assignment_id=? AND status='CANDIDATE'",
                (receipt_sha256, reason, self.id, assignment_id)
            )
            count = cur.rowcount
            if count > 0:
                self._event(db, 'MEMORY_QUARANTINED', {
                    'assignment_id': assignment_id, 'reason': reason,
                    'receipt_sha256': receipt_sha256, 'quarantined_count': count
                })
            db.commit()
            return count

    def inherit_memory(self, deliverable_id: str | None = None) -> dict:
        with closing(sqlite3.connect(self.db_path)) as db:
            if deliverable_id:
                rows = db.execute(
                    'SELECT memory_id, deliverable_id, assignment_id, worker_member, basis, patch_sha256, '
                    'diagnosis, lesson_summary, status, receipt_sha256, promoted_head, superseded_by, at '
                    'FROM earned_memory WHERE project_id=? AND deliverable_id=? ORDER BY at, memory_id',
                    (self.id, deliverable_id)
                ).fetchall()
            else:
                rows = db.execute(
                    'SELECT memory_id, deliverable_id, assignment_id, worker_member, basis, patch_sha256, '
                    'diagnosis, lesson_summary, status, receipt_sha256, promoted_head, superseded_by, at '
                    'FROM earned_memory WHERE project_id=? ORDER BY at, memory_id',
                    (self.id,)
                ).fetchall()
        cols = ('memory_id', 'deliverable_id', 'assignment_id', 'worker_member', 'basis', 'patch_sha256',
                'diagnosis', 'lesson_summary', 'status', 'receipt_sha256', 'promoted_head', 'superseded_by', 'at')
        items = [dict(zip(cols, r)) for r in rows]
        return {
            'project_id': self.id,
            'inherited_verified': [x for x in items if x['status'] == 'INHERITED'],
            'questioned_stale': [x for x in items if x['status'] == 'QUESTIONED'],
            'quarantined_traps': [x for x in items if x['status'] == 'QUARANTINED'],
            'untested_candidates': [x for x in items if x['status'] == 'CANDIDATE'],
            'trust_boundary': 'ONLY_INHERITED_MEMORIES_PASSED_INDEPENDENT_RECEIVER_VALIDATION',
        }
