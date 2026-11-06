"""Self-Healing Projects 001 — receiver-owned, single-host project coordination.

This module does not execute Git, code, or external effects. It binds World
participant root-key consent to project membership, records verified source
state, and coordinates narrow repairs. SafePromotion retains sole authority
for accepted Git source; LocalEffectStore retains sole authority for effects.
"""
from __future__ import annotations
import fcntl
import hashlib
import json
import os
import sqlite3
import subprocess
import time
from contextlib import closing, contextmanager
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
    def __init__(self, db_path, project_id=None, objective=None, owner_pub=None, *, promotion=None, world_verifier=None, strict_production: bool = False):
        self.promotion = promotion
        self.world_verifier = world_verifier
        self.strict_production = bool(strict_production)
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
            CREATE TABLE IF NOT EXISTS stop_state (
              id INTEGER PRIMARY KEY CHECK (id = 1),
              stopped INTEGER NOT NULL DEFAULT 0,
              epoch INTEGER NOT NULL DEFAULT 1,
              stop_seq INTEGER NOT NULL DEFAULT 0,
              clear_seq INTEGER NOT NULL DEFAULT 0,
              reason TEXT NOT NULL DEFAULT 'init');
            CREATE TABLE IF NOT EXISTS assignment_standing (
              assignment_id TEXT PRIMARY KEY,
              issued_seq INTEGER NOT NULL,
              epoch INTEGER NOT NULL,
              post_stop_override INTEGER NOT NULL DEFAULT 0,
              admit_seq INTEGER,
              commit_seq INTEGER,
              cas_target_head TEXT,
              cas_expected_head TEXT,
              cas_state TEXT NOT NULL DEFAULT 'NONE');
            CREATE TABLE IF NOT EXISTS event_hashes (
              seq INTEGER PRIMARY KEY,
              prev_sha256 TEXT NOT NULL,
              event_sha256 TEXT NOT NULL);
            ''')
            cols = {r[1] for r in db.execute("PRAGMA table_info(assignment_standing)").fetchall()}
            if 'cas_target_head' not in cols:
                db.execute("ALTER TABLE assignment_standing ADD COLUMN cas_target_head TEXT")
            if 'cas_expected_head' not in cols:
                db.execute("ALTER TABLE assignment_standing ADD COLUMN cas_expected_head TEXT")
            if 'cas_state' not in cols:
                db.execute("ALTER TABLE assignment_standing ADD COLUMN cas_state TEXT NOT NULL DEFAULT 'NONE'")
            db.execute("INSERT OR IGNORE INTO stop_state VALUES (1, 0, 1, 0, 0, 'init')")
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
        if self.promotion is not None:
            try:
                self.promotion._bound_project = self
                with closing(sqlite3.connect(self.db_path)) as db:
                    s_row = db.execute('SELECT stopped, stop_seq, clear_seq FROM stop_state WHERE id=1').fetchone()
                    rev_row = db.execute("SELECT 1 FROM events WHERE kind='MEMBER_REVOKED' LIMIT 1").fetchone()
                    if (s_row and (s_row[0] != 0 or s_row[1] > 0 or s_row[2] > 0)) or rev_row:
                        self.promotion.require_final_gate = True
            except Exception:
                pass

    @contextmanager
    def _gate_lock(self):
        lock_path = self.db_path + '.gate.lock'
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            os.chmod(lock_path, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _is_git_ancestor_or_equal(self, commit_sha: str | None, live_head: str | None) -> bool:
        if not commit_sha or not live_head or not isinstance(commit_sha, str) or len(commit_sha) != 40:
            return False
        if commit_sha == live_head:
            return True
        if self.promotion is None or not getattr(self.promotion, 'repo', None):
            return False
        p = subprocess.run(
            ['git', '--git-dir', str(self.promotion.repo), 'merge-base', '--is-ancestor', commit_sha, live_head],
            capture_output=True, text=True, timeout=5, check=False,
        )
        return p.returncode == 0

    def _reconcile_pending_cas_tx(self, db) -> None:
        """Reconciles any interrupted write-ahead PENDING_CAS gate reservation against actual Git ref state."""
        try:
            rows = db.execute(
                "SELECT assignment_id, commit_seq, cas_target_head, cas_expected_head FROM assignment_standing WHERE cas_state='PENDING_CAS'"
            ).fetchall()
        except sqlite3.Error:
            return
        if not rows or self.promotion is None:
            return
        try:
            live_head = self._trusted_head()
        except Exception:
            return
        for asgn_id, c_seq, target_head, expected_head in rows:
            if self._is_git_ancestor_or_equal(target_head, live_head):
                db.execute(
                    "UPDATE assignment_standing SET cas_state='CAS_APPLIED_PRE_CRASH' WHERE assignment_id=?",
                    (asgn_id,),
                )
            elif isinstance(expected_head, str) and len(expected_head) == 40 and live_head != expected_head:
                db.execute(
                    "UPDATE assignment_standing SET cas_state='HOLD_RECONCILIATION' WHERE assignment_id=?",
                    (asgn_id,),
                )
                db.execute(
                    "UPDATE projects SET status='HOLD_RECONCILIATION' WHERE id=?",
                    (self.id,),
                )
                self._event(db, 'KILL_SWITCH_DECISION', {
                    'assignment': asgn_id,
                    'phase': 'CRASH_RECOVERY',
                    'decision': 'HOLD',
                    'reason': 'ACCEPTED_REF_DIVERGED_DURING_PENDING_CAS',
                    'preserved_commit_seq': c_seq,
                    'expected_head': expected_head,
                    'target_head': target_head,
                    'observed_head': live_head,
                })
            else:
                db.execute(
                    "UPDATE assignment_standing SET commit_seq=NULL, cas_target_head=NULL, cas_expected_head=NULL, cas_state='CAS_ABORTED_PRE_REF' WHERE assignment_id=?",
                    (asgn_id,),
                )
                self._event(db, 'KILL_SWITCH_DECISION', {
                    'assignment': asgn_id,
                    'phase': 'CRASH_RECOVERY',
                    'decision': 'REFUSE',
                    'reason': 'CAS_NOT_APPLIED_BEFORE_CRASH',
                    'voided_commit_seq': c_seq,
                    'expected_head': expected_head,
                    'target_head': target_head,
                    'observed_head': live_head,
                })
                try:
                    self.promotion.recover(asgn_id)
                except Exception:
                    pass

    def reconcile_pending_cas(self) -> None:
        with self._gate_lock():
            with closing(sqlite3.connect(self.db_path, timeout=15)) as db:
                db.execute('BEGIN IMMEDIATE')
                self._reconcile_pending_cas_tx(db)
                db.commit()

    def _query(self, sql, args=()):
        with closing(sqlite3.connect(self.db_path)) as db:
            return db.execute(sql, args).fetchall()

    def _event(self, db, kind, payload) -> int:
        raw_payload = json.dumps(payload, sort_keys=True)
        cur = db.execute('INSERT INTO events(kind,payload,at) VALUES (?,?,?)',
                         (kind, raw_payload, int(time.time())))
        seq = int(cur.lastrowid)
        prev_row = db.execute('SELECT event_sha256 FROM event_hashes WHERE seq < ? ORDER BY seq DESC LIMIT 1', (seq,)).fetchone()
        prev_sha = prev_row[0] if prev_row else ('0' * 64)
        ev_sha = digest({'seq': seq, 'prev_sha256': prev_sha, 'kind': kind, 'payload': raw_payload})
        db.execute('INSERT OR REPLACE INTO event_hashes VALUES (?, ?, ?)', (seq, prev_sha, ev_sha))
        return seq

    def _verify_event_chain_tx(self, db) -> None:
        try:
            ev_rows = db.execute('SELECT seq, kind, payload FROM events ORDER BY seq').fetchall()
            h_rows = db.execute('SELECT seq, prev_sha256, event_sha256 FROM event_hashes ORDER BY seq').fetchall()
        except sqlite3.Error as exc:
            raise ProjectRefused('authority_unavailable_fail_closed') from exc
        if not h_rows and not ev_rows:
            return
        if len(ev_rows) != len(h_rows):
            raise ProjectRefused('authority_unavailable_fail_closed')
        expected_prev = '0' * 64
        for (seq, kind, raw_payload), (h_seq, prev_sha, ev_sha) in zip(ev_rows, h_rows):
            if kind == 'CONTRACT_CHANGED':
                try:
                    ev_obj = json.loads(raw_payload)
                    if (not isinstance(ev_obj, dict) or
                        not isinstance(ev_obj.get('affected'), list) or
                        not isinstance(ev_obj.get('dependency'), str) or
                        not isinstance(ev_obj.get('contract'), str)):
                        raise ValueError('bad_contract_event')
                except (ValueError, TypeError) as exc:
                    raise ProjectRefused('dependency_change_evidence_corrupt') from exc
            if seq != h_seq or prev_sha != expected_prev:
                raise ProjectRefused('authority_unavailable_fail_closed')
            calc = digest({'seq': seq, 'prev_sha256': prev_sha, 'kind': kind, 'payload': raw_payload})
            if calc != ev_sha:
                raise ProjectRefused('authority_unavailable_fail_closed')
            expected_prev = ev_sha

    def _read_stop_state_tx(self, db) -> dict:
        self._verify_event_chain_tx(db)
        try:
            rows = db.execute('SELECT id, stopped, epoch, stop_seq, clear_seq, reason FROM stop_state').fetchall()
        except sqlite3.Error as exc:
            raise ProjectRefused('authority_unavailable_fail_closed') from exc
        if len(rows) != 1:
            raise ProjectRefused('authority_unavailable_fail_closed')
        row_id, stopped, epoch, stop_seq, clear_seq, reason = rows[0]
        if (row_id != 1
            or type(stopped) is not int or stopped not in (0, 1)
            or type(epoch) is not int or epoch < 1
            or type(stop_seq) is not int or stop_seq < 0
            or type(clear_seq) is not int or clear_seq < 0
            or not isinstance(reason, str) or not reason):
            raise ProjectRefused('authority_unavailable_fail_closed')
        if stopped == 0 and stop_seq > 0 and clear_seq <= stop_seq:
            raise ProjectRefused('authority_unavailable_fail_closed')
        if stop_seq == 0 and clear_seq == 0 and (stopped != 0 or epoch != 1 or reason != 'init'):
            raise ProjectRefused('authority_unavailable_fail_closed')
        max_ks_row = db.execute(
            "SELECT COALESCE(MAX(seq), 0) FROM events WHERE kind IN ('KILL_SWITCH_STOPPED', 'KILL_SWITCH_CLEARED')"
        ).fetchone()
        if max_ks_row and int(max_ks_row[0]) != max(stop_seq, clear_seq):
            raise ProjectRefused('authority_unavailable_fail_closed')
        if stop_seq > 0:
            s_ev = db.execute('SELECT kind, payload FROM events WHERE seq=?', (stop_seq,)).fetchone()
            if not s_ev or s_ev[0] != 'KILL_SWITCH_STOPPED':
                raise ProjectRefused('authority_unavailable_fail_closed')
            try:
                s_data = json.loads(s_ev[1])
                s_pub = s_data.get('owner_pub') or self.owner_pub
                s_claim = {
                    'project_id': self.id,
                    'action': 'issue_stop',
                    'reason': s_data.get('reason'),
                    'expected_epoch': s_data.get('expected_epoch'),
                }
                if clear_seq < stop_seq and (s_data.get('reason') != reason or s_data.get('epoch') != epoch):
                    raise ProjectRefused('authority_unavailable_fail_closed')
                verify_owner(s_pub, s_claim, str(s_data.get('owner_signature', '')))
            except Exception as exc:
                raise ProjectRefused('authority_unavailable_fail_closed') from exc
        if clear_seq > 0:
            c_ev = db.execute('SELECT kind, payload FROM events WHERE seq=?', (clear_seq,)).fetchone()
            if not c_ev or c_ev[0] != 'KILL_SWITCH_CLEARED':
                raise ProjectRefused('authority_unavailable_fail_closed')
            try:
                c_data = json.loads(c_ev[1])
                c_pub = c_data.get('owner_pub') or self.owner_pub
                c_claim = {
                    'project_id': self.id,
                    'action': 'clear_stop',
                    'reason': c_data.get('reason'),
                    'expected_epoch': c_data.get('expected_epoch'),
                }
                if clear_seq > stop_seq and (c_data.get('reason') != reason or c_data.get('epoch') != epoch):
                    raise ProjectRefused('authority_unavailable_fail_closed')
                verify_owner(c_pub, c_claim, str(c_data.get('owner_signature', '')))
            except Exception as exc:
                raise ProjectRefused('authority_unavailable_fail_closed') from exc
        return {
            'stopped': bool(stopped),
            'epoch': epoch,
            'stop_seq': stop_seq,
            'clear_seq': clear_seq,
            'reason': reason,
        }

    def read_stop_state(self) -> dict:
        try:
            with closing(sqlite3.connect(self.db_path, timeout=15)) as db:
                return self._read_stop_state_tx(db)
        except sqlite3.Error as exc:
            raise ProjectRefused('authority_unavailable_fail_closed') from exc

    def issue_stop(self, reason: str, owner_signature: str, *, actor_role: str = 'owner', expected_epoch: int | None = None) -> dict:
        """Owner-only emergency Kill Switch STOP. Advances epoch and records monotonic stop_seq."""
        if actor_role != 'owner':
            raise ProjectRefused('stop_authority_owner_only')
        if not isinstance(reason, str) or not reason.strip():
            raise ProjectRefused('invalid_stop_reason')
        if type(expected_epoch) is not int or expected_epoch < 1:
            raise ProjectRefused('expected_epoch_required')
        claim = {'project_id': self.id, 'action': 'issue_stop', 'reason': reason, 'expected_epoch': expected_epoch}
        verify_owner(self.owner_pub, claim, owner_signature)
        try:
            with self._gate_lock():
                with closing(sqlite3.connect(self.db_path, timeout=15)) as db:
                    db.execute('BEGIN IMMEDIATE')
                    self._reconcile_pending_cas_tx(db)
                    cur = self._read_stop_state_tx(db)
                    if cur['epoch'] != expected_epoch:
                        raise ProjectRefused('stale_owner_intent')
                    new_epoch = cur['epoch'] + 1
                    ev_seq = self._event(db, 'KILL_SWITCH_STOPPED', {
                        'project_id': self.id,
                        'epoch': new_epoch,
                        'expected_epoch': expected_epoch,
                        'prev_stop_seq': cur['stop_seq'],
                        'reason': reason,
                        'owner_pub': self.owner_pub,
                        'owner_signature': owner_signature,
                    })
                    db.execute(
                        'UPDATE stop_state SET stopped=1, epoch=?, stop_seq=?, reason=? WHERE id=1',
                        (new_epoch, ev_seq, reason),
                    )
                    st = self._read_stop_state_tx(db)
                    db.commit()
                    if self.promotion is not None:
                        self.promotion.require_final_gate = True
                    return st
        except sqlite3.Error as exc:
            raise ProjectRefused('authority_unavailable_fail_closed') from exc

    def clear_stop(self, reason: str, owner_signature: str, *, actor_role: str = 'owner', expected_epoch: int | None = None) -> dict:
        """Owner-only clear_stop. Advances epoch and clear_seq while preserving stop_seq so pre-STOP authority stays dead."""
        if actor_role != 'owner':
            raise ProjectRefused('stop_authority_owner_only')
        if not isinstance(reason, str) or not reason.strip():
            raise ProjectRefused('invalid_stop_reason')
        if type(expected_epoch) is not int or expected_epoch < 1:
            raise ProjectRefused('expected_epoch_required')
        claim = {'project_id': self.id, 'action': 'clear_stop', 'reason': reason, 'expected_epoch': expected_epoch}
        verify_owner(self.owner_pub, claim, owner_signature)
        try:
            with self._gate_lock():
                with closing(sqlite3.connect(self.db_path, timeout=15)) as db:
                    db.execute('BEGIN IMMEDIATE')
                    self._reconcile_pending_cas_tx(db)
                    cur = self._read_stop_state_tx(db)
                    if cur['epoch'] != expected_epoch:
                        raise ProjectRefused('stale_owner_intent')
                    if not cur['stopped']:
                        raise ProjectRefused('stop_not_active')
                    new_epoch = cur['epoch'] + 1
                    ev_seq = self._event(db, 'KILL_SWITCH_CLEARED', {
                        'project_id': self.id,
                        'epoch': new_epoch,
                        'expected_epoch': expected_epoch,
                        'stop_seq_preserved': cur['stop_seq'],
                        'reason': reason,
                        'owner_pub': self.owner_pub,
                        'owner_signature': owner_signature,
                    })
                    db.execute(
                        'UPDATE stop_state SET stopped=0, epoch=?, clear_seq=?, reason=? WHERE id=1',
                        (new_epoch, ev_seq, reason),
                    )
                    st = self._read_stop_state_tx(db)
                    db.commit()
                    if self.promotion is not None:
                        self.promotion.require_final_gate = True
                    return st
        except sqlite3.Error as exc:
            raise ProjectRefused('authority_unavailable_fail_closed') from exc

    def _verify_kill_switch_standing(self, db, assignment_id: str, *, phase: str) -> tuple[dict, int, int]:
        st = self._read_stop_state_tx(db)
        try:
            s_row = db.execute(
                'SELECT issued_seq, epoch, post_stop_override FROM assignment_standing WHERE assignment_id=?',
                (assignment_id,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise ProjectRefused('authority_unavailable_fail_closed') from exc
        if s_row is None:
            if st['stop_seq'] == 0 and not st['stopped']:
                issued_seq, asgn_epoch, post_stop_override = 1, 1, 0
            else:
                issued_seq, asgn_epoch, post_stop_override = 0, 1, 0
        else:
            if (type(s_row[0]) is not int or s_row[0] < 0
                or type(s_row[1]) is not int or s_row[1] < 1
                or type(s_row[2]) is not int or s_row[2] not in (0, 1)):
                raise ProjectRefused('authority_unavailable_fail_closed')
            issued_seq, asgn_epoch, post_stop_override = s_row[0], s_row[1], s_row[2]

        if st['stop_seq'] > 0 and issued_seq <= st['stop_seq']:
            self._event(db, 'KILL_SWITCH_DECISION', {
                'assignment': assignment_id,
                'phase': phase,
                'decision': 'REFUSE',
                'reason': 'OLD_AUTHORITY_DEAD',
                'epoch': st['epoch'],
                'stop_seq': st['stop_seq'],
                'issued_seq': issued_seq,
            })
            db.commit()
            raise ProjectRefused('old_authority_dead')

        if st['stopped'] and not (post_stop_override == 1 and asgn_epoch == st['epoch'] and issued_seq > st['stop_seq']):
            self._event(db, 'KILL_SWITCH_DECISION', {
                'assignment': assignment_id,
                'phase': phase,
                'decision': 'REFUSE',
                'reason': f"STOPPED_AT_EPOCH_{st['epoch']}",
                'epoch': st['epoch'],
                'stop_seq': st['stop_seq'],
                'issued_seq': issued_seq,
            })
            db.commit()
            raise ProjectRefused(f"stopped_at_epoch_{st['epoch']}")

        return st, issued_seq, post_stop_override

    def preliminary_admit(self, assignment_id: str) -> dict:
        """Preliminary admission check (recorded in events, never sufficient for finalization)."""
        try:
            with closing(sqlite3.connect(self.db_path, timeout=15)) as db:
                db.execute('BEGIN IMMEDIATE')
                st, issued_seq, _override = self._verify_kill_switch_standing(db, assignment_id, phase='PRELIMINARY_ADMIT')
                self._verify_active_assignment(db, assignment_id)
                admit_seq = self._event(db, 'PRELIMINARY_ADMIT', {
                    'assignment': assignment_id,
                    'decision': 'PRELIMINARY_ADMIT',
                    'reason': 'STANDING_OK_NOT_FINAL_AUTHORITY',
                    'epoch': st['epoch'],
                    'stop_seq': st['stop_seq'],
                    'issued_seq': issued_seq,
                })
                db.execute(
                    'UPDATE assignment_standing SET admit_seq=? WHERE assignment_id=?',
                    (admit_seq, assignment_id),
                )
                db.commit()
                return {
                    'admitted': True,
                    'decision': 'PRELIMINARY_ADMIT',
                    'reason': 'STANDING_OK_NOT_FINAL_AUTHORITY',
                    'admit_seq': admit_seq,
                    'issued_seq': issued_seq,
                    'epoch': st['epoch'],
                    'stop_seq': st['stop_seq'],
                }
        except sqlite3.Error as exc:
            raise ProjectRefused('authority_unavailable_fail_closed') from exc

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
            st = self._read_stop_state_tx(db)
            if st['stopped']:
                raise ProjectRefused(f"stopped_at_epoch_{st['epoch']}")
            old = db.execute('SELECT owner_pub,worker_pub,world_digest,active FROM members WHERE project_id=? AND member_id=?',
                             (self.id,invitation['member_id'])).fetchone()
            if old is not None:
                if old[3] != 1:
                    raise ProjectRefused('member_not_active')
                if old[:3] != (invitation['owner_pub'],invitation['worker_pub'],invitation['world_digest']):
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
        with self._gate_lock():
            with closing(sqlite3.connect(self.db_path)) as db:
                db.execute('BEGIN IMMEDIATE')
                self._reconcile_pending_cas_tx(db)
                if db.execute('UPDATE members SET active=0 WHERE project_id=? AND member_id=? AND active=1',
                              (self.id,member)).rowcount!=1:raise ProjectRefused('member_not_active')
                self._event(db,'MEMBER_REVOKED',{'member':member})
                db.commit()
                if self.promotion is not None:
                    self.promotion.require_final_gate = True

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
            st = self._read_stop_state_tx(db)
            if st['stopped']:
                raise ProjectRefused(f"stopped_at_epoch_{st['epoch']}")
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
                eff_seq = ev.get('effective_seq')
                settled = eff_seq if (type(eff_seq) is int and eff_seq > 0) else seq
        return settled

    def _contract_events_since(self, db, since_seq: int = 0, up_to_seq: int | None = None) -> list[dict]:
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
            if seq > since_seq and (up_to_seq is None or seq <= up_to_seq):
                events.append(event)
        return events

    def change_dependency(self, key, contract, owner_signature):
        claim={'project_id':self.id,'dependency':key,'contract':contract,'action':'change_dependency'}
        verify_owner(self.owner_pub,claim,owner_signature)
        with self._gate_lock():
            with closing(sqlite3.connect(self.db_path)) as db:
                db.execute('BEGIN IMMEDIATE')
                self._reconcile_pending_cas_tx(db)
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

    def assign_repair(self, assignment_id, deliverable_id, worker_member, basis, contributor_signature, *,
                      allowed_paths, post_stop_owner_signature: str | None = None):
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
        with self._gate_lock():
            with closing(sqlite3.connect(self.db_path)) as db:
                db.execute('BEGIN IMMEDIATE')
                self._reconcile_pending_cas_tx(db)
                st = self._read_stop_state_tx(db)
                post_stop_override = 0
                if st['stopped']:
                    if post_stop_owner_signature is None:
                        self._event(db, 'KILL_SWITCH_DECISION', {
                            'assignment': assignment_id,
                            'phase': 'ASSIGN_REPAIR',
                            'decision': 'REFUSE',
                            'reason': f"STOPPED_AT_EPOCH_{st['epoch']}",
                            'epoch': st['epoch'],
                            'stop_seq': st['stop_seq'],
                        })
                        db.commit()
                        raise ProjectRefused(f"stopped_at_epoch_{st['epoch']}")
                    override_claim = {
                        'project_id': self.id,
                        'assignment_id': assignment_id,
                        'deliverable_id': deliverable_id,
                        'worker_member': worker_member,
                        'basis': basis,
                        'allowed_paths': allowed_paths,
                        'epoch': st['epoch'],
                        'stop_seq': st['stop_seq'],
                        'action': 'post_stop_grant',
                    }
                    verify_owner(self.owner_pub, override_claim, post_stop_owner_signature)
                    post_stop_override = 1
                self._member(db,worker_member)
                row=db.execute('SELECT member_id,standing FROM deliverables WHERE id=?',(deliverable_id,)).fetchone()
                if row is None or row[1]!='REOPEN':raise ProjectRefused('work_not_reopened')
                contributor_pub=self._member(db,row[0])[0]
                verify_owner(contributor_pub,claim,contributor_signature)
                ev_seq = self._event(db,'REPAIR_ASSIGNED',claim)
                db.execute('INSERT INTO assignments VALUES (?,?,?,?,?,?,NULL)',
                           (assignment_id,deliverable_id,worker_member,basis,
                            json.dumps(allowed_paths,sort_keys=True),'ASSIGNED'))
                db.execute(
                    "INSERT OR REPLACE INTO assignment_standing(assignment_id, issued_seq, epoch, post_stop_override, admit_seq, commit_seq, cas_target_head, cas_expected_head, cas_state) "
                    "VALUES (?,?,?,?,NULL,NULL,NULL,NULL,'NONE')",
                    (assignment_id, ev_seq, st['epoch'], post_stop_override),
                )
                db.commit()

    def _repair_rebind_plan(self, db, deliverable_id, basis, *, up_to_seq: int | None = None):
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
        events = self._contract_events_since(db, since, up_to_seq=up_to_seq)
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

    def promote_repair(self, assignment_id, *, acceptance_cmd, timeout=30, pre_cas_hook=None, fail_before_ref=False, fail_after_ref=False):
        """Trusted receiver-side repair path. Unassigned work never reaches Git CAS.

        Checks Kill Switch standing and assignment/member before testing (releasing
        DB lock during subprocess execution so mid-task revocations/stops never block)
        and executes a write-ahead two-phase final gate reservation under _gate_lock()
        held across Git CAS so pre-crash Git commits are durably tied to commit_seq.
        """
        if self.promotion is None:
            raise ProjectRefused('receiver_owned_git_promotion_required')
        try:
            with self._gate_lock():
                with closing(sqlite3.connect(self.db_path, timeout=15)) as db:
                    db.execute('BEGIN IMMEDIATE')
                    self._reconcile_pending_cas_tx(db)
                    self._verify_kill_switch_standing(db, assignment_id, phase='ENTRY')
                    deliverable, member, basis, allowed = self._verify_active_assignment(db, assignment_id)
                    db.commit()
        except ProjectRefused:
            raise
        except sqlite3.Error as exc:
            raise ProjectRefused('authority_unavailable_fail_closed') from exc

        def _pre_cas_recheck():
            if pre_cas_hook is not None:
                pre_cas_hook()
            try:
                with self._gate_lock():
                    with closing(sqlite3.connect(self.db_path, timeout=15)) as db2:
                        db2.execute('BEGIN IMMEDIATE')
                        self._reconcile_pending_cas_tx(db2)
                        self._verify_kill_switch_standing(db2, assignment_id, phase='PRE_CAS')
                        self._verify_active_assignment(db2, assignment_id)
                        db2.commit()
            except ProjectRefused:
                raise
            except sqlite3.Error as exc:
                raise ProjectRefused('authority_unavailable_fail_closed') from exc

        @contextmanager
        def _final_gate_context(target_head, expected_head):
            with self._gate_lock():
                try:
                    db_gate = sqlite3.connect(self.db_path, timeout=15)
                except sqlite3.Error as exc:
                    raise ProjectRefused('authority_unavailable_fail_closed') from exc
                with closing(db_gate) as db2:
                    try:
                        db2.execute('BEGIN IMMEDIATE')
                        self._reconcile_pending_cas_tx(db2)
                        st, issued_seq, _override = self._verify_kill_switch_standing(db2, assignment_id, phase='FINAL_GATE')
                        self._verify_active_assignment(db2, assignment_id)
                        commit_seq = self._event(db2, 'KILL_SWITCH_DECISION', {
                            'assignment': assignment_id,
                            'phase': 'FINAL_GATE',
                            'decision': 'COMMIT',
                            'reason': 'STANDING_OK',
                            'epoch': st['epoch'],
                            'stop_seq': st['stop_seq'],
                            'issued_seq': issued_seq,
                            'head': target_head,
                            'expected_head': expected_head,
                        })
                        db2.execute(
                            "UPDATE assignment_standing SET commit_seq=?, cas_target_head=?, cas_expected_head=?, cas_state='PENDING_CAS' WHERE assignment_id=?",
                            (commit_seq, target_head, expected_head, assignment_id),
                        )
                        db2.commit()
                    except ProjectRefused:
                        raise
                    except sqlite3.Error as exc:
                        raise ProjectRefused('authority_unavailable_fail_closed') from exc
                try:
                    yield
                except Exception as exc:
                    if not (isinstance(exc, RuntimeError) and str(exc).startswith('injected_crash_')):
                        try:
                            with closing(sqlite3.connect(self.db_path, timeout=15)) as db_abort:
                                db_abort.execute('BEGIN IMMEDIATE')
                                self._reconcile_pending_cas_tx(db_abort)
                                db_abort.commit()
                        except Exception:
                            pass
                    raise
                try:
                    with closing(sqlite3.connect(self.db_path, timeout=15)) as db_ok:
                        db_ok.execute('BEGIN IMMEDIATE')
                        db_ok.execute(
                            "UPDATE assignment_standing SET cas_state='CAS_CONFIRMED' WHERE assignment_id=?",
                            (assignment_id,),
                        )
                        db_ok.commit()
                except Exception:
                    pass

        _final_gate_context._openline_project_ledger = self
        import inspect as _insp
        _kw = {'acceptance_cmd': acceptance_cmd, 'allow_prefixes': allowed, 'timeout': timeout}
        if fail_before_ref:
            _kw['fail_before_ref'] = fail_before_ref
        if fail_after_ref:
            # Trusted local fault injection for cross-store crash conformance.
            _kw['fail_after_ref'] = fail_after_ref
        try:
            _params = _insp.signature(self.promotion.promote).parameters
            if 'final_gate_context' in _params:
                _kw['final_gate_context'] = _final_gate_context
                if 'pre_cas_check' in _params and pre_cas_hook is not None:
                    _kw['pre_cas_check'] = pre_cas_hook
            elif 'pre_cas_check' in _params:
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
        with self._gate_lock():
            with closing(sqlite3.connect(self.db_path)) as db:
                db.execute('BEGIN IMMEDIATE')
                self._reconcile_pending_cas_tx(db)
                row=db.execute('SELECT deliverable_id,state,promoted_head,basis,worker_member FROM assignments WHERE id=?',(assignment_id,)).fetchone()
                if row is None:raise ProjectRefused('unassigned_repair')
                if row[1]=='COMMITTED':
                    if row[2]!=promoted_head:raise ProjectRefused('repair_replay_conflict')
                    db.rollback();return 'ALREADY_RECORDED'
                if row[1]!='ASSIGNED':raise ProjectRefused('assignment_not_active')
                c_row = db.execute(
                    'SELECT commit_seq, cas_target_head, cas_state FROM assignment_standing WHERE assignment_id=?',
                    (assignment_id,),
                ).fetchone()
                pre_committed_ok = False
                if (c_row is not None
                        and type(c_row[0]) is int
                        and c_row[0] > 0
                        and c_row[1] == promoted_head
                        and c_row[2] in ('CAS_CONFIRMED', 'CAS_APPLIED_PRE_CRASH')):
                    self._verify_event_chain_tx(db)
                    fg_ev = db.execute('SELECT kind, payload FROM events WHERE seq=?', (c_row[0],)).fetchone()
                    if fg_ev and fg_ev[0] == 'KILL_SWITCH_DECISION':
                        try:
                            fg_data = json.loads(fg_ev[1])
                            if (fg_data.get('assignment') == assignment_id
                                    and fg_data.get('phase') == 'FINAL_GATE'
                                    and fg_data.get('decision') == 'COMMIT'
                                    and fg_data.get('head') == promoted_head):
                                pre_committed_ok = True
                        except Exception:
                            pre_committed_ok = False
                if not pre_committed_ok:
                    self._verify_kill_switch_standing(db, assignment_id, phase='RESOLVE_REPAIR')
                    self._member(db, row[4])
                basis = row[3]
                up_to_seq = int(c_row[0]) if pre_committed_ok else None
                old_dependency,new_dependency=self._repair_rebind_plan(db,row[0],basis,up_to_seq=up_to_seq)
                post_commit_reopened = False
                post_commit_contract = None
                if pre_committed_ok:
                    cur_dep = new_dependency
                    for post_ev in self._contract_events_since(db, int(c_row[0])):
                        if post_ev['dependency'] == cur_dep or row[0] in post_ev['affected']:
                            cur_dep = post_ev['contract']
                            post_commit_reopened = True
                            post_commit_contract = cur_dep
                db.execute('DELETE FROM dependencies WHERE deliverable_id=? AND depends_on=?',
                           (row[0],old_dependency))
                db.execute('INSERT INTO dependencies VALUES (?,?)',(row[0],new_dependency))
                db.execute('UPDATE assignments SET state=?,promoted_head=? WHERE id=?',('COMMITTED',promoted_head,assignment_id))
                db.execute("UPDATE assignment_standing SET cas_state='RECONCILED' WHERE assignment_id=?", (assignment_id,))
                next_standing = 'REOPEN' if post_commit_reopened else 'CURRENT'
                db.execute('UPDATE deliverables SET standing=?,accepted_head=? WHERE id=?',(next_standing,promoted_head,row[0]))
                remaining=db.execute("SELECT 1 FROM deliverables WHERE standing='REOPEN' LIMIT 1").fetchone()
                db.execute('UPDATE projects SET last_accepted=?,status=? WHERE id=?',
                           (promoted_head,'RECONSIDERATION' if remaining else 'ACTIVE',self.id))
                now_ts = int(time.time())
                db.execute('DELETE FROM dependency_contracts WHERE project_id=? AND dep_key=?', (self.id, old_dependency))
                # Quarantine any preplanted or scope-mismatched candidate memory rows before inheriting legitimate memory
                poisoned = db.execute(
                    "SELECT memory_id FROM earned_memory WHERE project_id=? AND assignment_id=? "
                    "AND status='CANDIDATE' AND (worker_member!=? OR deliverable_id!=? OR basis!=?)",
                    (self.id, assignment_id, row[4], row[0], basis)
                ).fetchall()
                if poisoned:
                    db.execute(
                        "UPDATE earned_memory SET status='QUARANTINED' WHERE project_id=? AND assignment_id=? "
                        "AND status='CANDIDATE' AND (worker_member!=? OR deliverable_id!=? OR basis!=?)",
                        (self.id, assignment_id, row[4], row[0], basis)
                    )
                    self._event(db, 'MEMORY_ASSIGNMENT_SCOPE_QUARANTINED', {
                        'assignment': assignment_id, 'memory_ids': sorted(m[0] for m in poisoned)
                    })
                if not post_commit_reopened:
                    db.execute('INSERT OR REPLACE INTO dependency_contracts VALUES (?,?,?,?)',
                               (self.id, new_dependency, new_dependency, now_ts))
                    db.execute(
                        "UPDATE earned_memory SET status='INHERITED', promoted_head=?, receipt_sha256=COALESCE(?, receipt_sha256) "
                        "WHERE project_id=? AND assignment_id=? AND status='CANDIDATE' "
                        "AND worker_member=? AND deliverable_id=? AND basis=?",
                        (promoted_head, receipt_sha256, self.id, assignment_id, row[4], row[0], basis)
                    )
                else:
                    db.execute(
                        "UPDATE earned_memory SET status='QUESTIONED', superseded_by=?, promoted_head=?, receipt_sha256=COALESCE(?, receipt_sha256) "
                        "WHERE project_id=? AND assignment_id=? AND status='CANDIDATE' "
                        "AND worker_member=? AND deliverable_id=? AND basis=?",
                        (post_commit_contract, promoted_head, receipt_sha256, self.id, assignment_id, row[4], row[0], basis)
                    )
                ev_payload = {'assignment':assignment_id,'head':promoted_head,
                              'dependency_rebind':[old_dependency,new_dependency],
                              'effective_seq': int(c_row[0]) if pre_committed_ok else None}
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
        with self._gate_lock():
            with closing(sqlite3.connect(self.db_path)) as db:
                db.execute('BEGIN IMMEDIATE')
                self._reconcile_pending_cas_tx(db)
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
            if signer_id is not None and signature_hex is not None:
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
                if not pub:
                    raise ProjectRefused('claim_signer_not_active_member')
                verify_owner(pub, envelope, signature_hex)
                trust_status = 'CRYPTOGRAPHICALLY_BOUND'
                verified_signer = signer_id
            existing_claim = db.execute(
                'SELECT signer_id, trust_status FROM claim_graph WHERE claim_id=? AND project_id=?',
                (claim_id, self.id)
            ).fetchone()
            if existing_claim and existing_claim[1] == 'CRYPTOGRAPHICALLY_BOUND':
                if trust_status != 'CRYPTOGRAPHICALLY_BOUND' or verified_signer not in (existing_claim[0], 'owner'):
                    raise ProjectRefused('bound_claim_cannot_be_overwritten_by_untrusted_or_other_signer')
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
            ex_mem = db.execute(
                'SELECT status, worker_member, assignment_id FROM earned_memory WHERE memory_id=? AND project_id=?',
                (memory_id, self.id)
            ).fetchone()
            if ex_mem is not None:
                if ex_mem[0] in ('INHERITED', 'QUARANTINED', 'QUESTIONED'):
                    raise ProjectRefused('settled_memory_cannot_be_overwritten')
                if ex_mem[1] != worker_member or ex_mem[2] != assignment_id:
                    raise ProjectRefused('candidate_memory_owned_by_different_worker_or_assignment')
            if not isinstance(assignment_id, str) or not assignment_id.strip():
                raise ProjectRefused('memory_assignment_required')
            asgn_row = db.execute(
                'SELECT deliverable_id, worker_member, basis, state FROM assignments WHERE id=?',
                (assignment_id,)
            ).fetchone()
            if asgn_row is None:
                raise ProjectRefused('memory_assignment_missing')
            if asgn_row[0] != deliverable_id or asgn_row[1] != worker_member or asgn_row[2] != basis:
                raise ProjectRefused('memory_assignment_scope_mismatch')
            if asgn_row[3] != 'ASSIGNED':
                raise ProjectRefused('memory_assignment_not_active')
            self._verify_kill_switch_standing(db, assignment_id, phase='PROPOSE_MEMORY')
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
