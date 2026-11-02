"""SQLite-backed advisory cross-agent stagnation. NOT an authorization engine.

Only a trusted receiver may call record() with independently verified observations.
The caller must enforce STOP/HOLD and independently reconcile external effects.
"""
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from graph_watchdog import VerifiedAttempt


class DurableGraphWatchdog:
    def __init__(self, db_path, threshold=3):
        if type(threshold) is not int or threshold < 1:
            raise ValueError('threshold must be positive')
        self.db_path = str(Path(db_path))
        self.threshold = threshold
        with self._db() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS watchdog_scope (
                    deliverable TEXT NOT NULL, basis TEXT NOT NULL,
                    peak INTEGER, stagnant INTEGER NOT NULL DEFAULT 0,
                    threshold INTEGER,
                    terminal TEXT, PRIMARY KEY(deliverable,basis));
                CREATE TABLE IF NOT EXISTS watchdog_attempt (
                    deliverable TEXT NOT NULL, basis TEXT NOT NULL,
                    attempt_id TEXT NOT NULL, worker TEXT NOT NULL,
                    fingerprint TEXT,
                    PRIMARY KEY(deliverable,basis,attempt_id));
            ''')
            columns = {row[1] for row in db.execute('PRAGMA table_info(watchdog_scope)')}
            if 'threshold' not in columns:
                db.execute('ALTER TABLE watchdog_scope ADD COLUMN threshold INTEGER')
            att_columns = {row[1] for row in db.execute('PRAGMA table_info(watchdog_attempt)')}
            if 'fingerprint' not in att_columns:
                db.execute('ALTER TABLE watchdog_attempt ADD COLUMN fingerprint TEXT')
            db.execute('BEGIN IMMEDIATE')
            try:
                db.execute('UPDATE watchdog_scope SET threshold=? WHERE threshold IS NULL', (threshold,))
                db.execute(
                    "UPDATE watchdog_scope SET terminal='STOP_STAGNATION' "
                    "WHERE terminal IS NULL AND stagnant >= threshold"
                )
                mismatch = db.execute('SELECT 1 FROM watchdog_scope WHERE threshold != ? LIMIT 1', (threshold,)).fetchone()
                if mismatch:
                    raise ValueError('stored scope threshold differs from requested threshold')
                db.commit()
            except BaseException:
                db.rollback()
                raise

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        try:
            db.execute('PRAGMA busy_timeout=10000')
            yield db
        finally:
            db.close()

    def record(self, attempt: VerifiedAttempt):
        if not isinstance(attempt, VerifiedAttempt):
            raise TypeError('VerifiedAttempt required')
        fp = attempt.fingerprint()
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                d, b = attempt.deliverable_id, attempt.basis
                db.execute('INSERT OR IGNORE INTO watchdog_scope(deliverable,basis,threshold) VALUES(?,?,?)', (d,b,self.threshold))
                peak, stagnant, terminal, stored_threshold = db.execute(
                    'SELECT peak,stagnant,terminal,threshold FROM watchdog_scope WHERE deliverable=? AND basis=?', (d,b)).fetchone()
                if stored_threshold != self.threshold:
                    raise ValueError('stored scope threshold differs from requested threshold')
                existing = db.execute(
                    'SELECT worker, fingerprint FROM watchdog_attempt WHERE deliverable=? AND basis=? AND attempt_id=?',
                    (d,b,attempt.attempt_id)
                ).fetchone()
                if existing is not None:
                    ex_worker, ex_fp = existing
                    if ex_worker != attempt.worker_id or (ex_fp is not None and ex_fp != fp):
                        raise ValueError('conflicting duplicate attempt_id')
                    decision = 'DUPLICATE_IGNORED'
                elif terminal:
                    decision = terminal
                else:
                    db.execute(
                        'INSERT INTO watchdog_attempt(deliverable,basis,attempt_id,worker,fingerprint) VALUES(?,?,?,?,?)',
                        (d,b,attempt.attempt_id,attempt.worker_id,fp)
                    )
                    if attempt.external_mutation == 'uncertain':
                        terminal = decision = 'HOLD_RECONCILIATION'
                    else:
                        if attempt.receiver_verified and attempt.progress_after > attempt.progress_before and (peak is None or attempt.progress_after > peak):
                            peak = attempt.progress_after
                            stagnant = 0
                        else:
                            if attempt.receiver_verified and (peak is None or attempt.progress_before > peak):
                                peak = attempt.progress_before
                            stagnant += 1
                        if stagnant >= self.threshold:
                            terminal = decision = 'STOP_STAGNATION'
                        else:
                            decision = 'CONTINUE'
                    db.execute('UPDATE watchdog_scope SET peak=?,stagnant=?,terminal=? WHERE deliverable=? AND basis=?',
                               (peak,stagnant,terminal,d,b))
                workers = [x[0] for x in db.execute('SELECT DISTINCT worker FROM watchdog_attempt WHERE deliverable=? AND basis=? ORDER BY worker',(d,b))]
                db.commit()
                return {'deliverable_id':d,'basis':b,'decision':decision,
                        'stagnant_attempts':stagnant,'workers':workers,'receiver_authorization':'NONE'}
            except BaseException:
                db.rollback()
                raise

    def clear_hold_after_reconciliation(self, deliverable_id: str, basis: str):
        """Callable by the trusted ExecutionSupervisor after verifying an owner Ed25519 reconciliation signature."""
        if not all(isinstance(v, str) and v.strip() for v in (deliverable_id, basis)):
            raise ValueError('nonempty identifiers required')
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                row = db.execute(
                    'SELECT stagnant, threshold FROM watchdog_scope WHERE deliverable=? AND basis=?',
                    (deliverable_id, basis)
                ).fetchone()
                if row is not None:
                    stagnant, threshold = row
                    new_terminal = 'STOP_STAGNATION' if stagnant >= threshold else None
                    db.execute(
                        "UPDATE watchdog_scope SET terminal=? WHERE deliverable=? AND basis=? AND terminal='HOLD_RECONCILIATION'",
                        (new_terminal, deliverable_id, basis)
                    )
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def status(self, deliverable_id, basis):
        if not all(isinstance(v, str) and v.strip() for v in (deliverable_id, basis)):
            raise ValueError('nonempty identifiers required')
        with self._db() as db:
            row = db.execute(
                'SELECT peak,stagnant,terminal,threshold FROM watchdog_scope WHERE deliverable=? AND basis=?',
                (deliverable_id, basis)).fetchone()
            if row is None:
                return None
            peak, stagnant, terminal, threshold = row
            workers = [r[0] for r in db.execute(
                'SELECT DISTINCT worker FROM watchdog_attempt WHERE deliverable=? AND basis=? ORDER BY worker',
                (deliverable_id, basis))]
            return {'deliverable_id': deliverable_id, 'basis': basis,
                    'stagnant_attempts': stagnant, 'workers': workers,
                    'peak': peak, 'terminal': terminal, 'threshold': threshold,
                    'receiver_authorization': 'NONE'}
