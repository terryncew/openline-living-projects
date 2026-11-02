"""OpenLine Coach 001: budgeted teacher/student proposal experiment.

NO network clients, credentials, code execution, authorization, or promotion.
A trusted caller supplies a model runner and independent verifier. Proposed
source never becomes accepted work here. Intended as a bounded experiment that
can be plugged into Track B after its isolation gate and evaluated by Muse.
"""
from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
from decimal import Decimal, ROUND_CEILING
from hashlib import sha256
from pathlib import Path
import json
import sqlite3
from typing import Callable

CANON = (
    "OpenLine: owner authority is the floor; never override project scope. "
    "Separate proposed work from independently verified work. Preserve accepted "
    "contributions, disclose unknowns, record falsifiers, stay inside budget. "
    "A model never signs its own PASS or grants itself promotion authority."
)


class BudgetBlocked(RuntimeError):
    pass


class UncertainCharge(RuntimeError):
    pass


@dataclass(frozen=True)
class Model:
    provider: str
    name: str
    input_usd_per_million: str
    output_usd_per_million: str
    input_limit: int
    output_limit: int

    def __post_init__(self):
        if not self.provider or not self.name or any('/' in x for x in (self.provider, self.name)):
            raise ValueError('invalid_model_identity')
        if self.input_limit <= 0 or self.output_limit <= 0:
            raise ValueError('invalid_model_token_limits')
        for price in (self.input_usd_per_million, self.output_usd_per_million):
            p = Decimal(price)
            if not p.is_finite() or p < 0:
                raise ValueError('invalid_price')

    @property
    def key(self):
        return f'{self.provider}/{self.name}'

    def quote_micros(self, input_tokens: int | None = None, output_tokens: int | None = None) -> int:
        i = self.input_limit if input_tokens is None else input_tokens
        o = self.output_limit if output_tokens is None else output_tokens
        if not isinstance(i, int) or not isinstance(o, int) or min(i, o) < 0:
            raise ValueError('invalid_usage')
        if i > self.input_limit or o > self.output_limit:
            raise ValueError('usage_exceeds_reserved_limits')
        # USD/million * tokens gives micro-USD; ceil for conservative accounting.
        return int((Decimal(i) * Decimal(self.input_usd_per_million) +
                    Decimal(o) * Decimal(self.output_usd_per_million)).to_integral_value(rounding=ROUND_CEILING))


@dataclass(frozen=True)
class Task:
    project_id: str
    project_head: str
    family: str
    instruction: str
    contract_digest: str

    def __post_init__(self):
        if not all((self.project_id, self.project_head, self.family, self.instruction, self.contract_digest)):
            raise ValueError('unbound_task')

    @property
    def basis(self):
        payload = [self.project_id, self.project_head, self.family, self.contract_digest, self.instruction]
        return sha256(json.dumps(payload, separators=(',', ':')).encode()).hexdigest()


@dataclass(frozen=True)
class Completion:
    text: str
    input_tokens: int
    output_tokens: int


@dataclass(frozen=True)
class Check:
    passed: bool
    evidence_ref: str
    # Evidence is furnished by the independent receiver verifier, NOT model text.


class Meter:
    """Durable local reservation cap. Caller must separately pin provider billing caps.

    A timeout/unknown call is deliberately held UNCERTAIN against budget until
    a trusted operator reconciles it. Recorded cost is adapter-METERED, not billed.
    """
    def __init__(self, path: Path, total_micros: int, provider_caps: dict[str, int]):
        if not isinstance(total_micros, int) or total_micros <= 0 or not provider_caps or any(
                not isinstance(c, int) or c <= 0 for c in provider_caps.values()):
            raise ValueError('invalid_budget')
        self.path, self.total_cap, self.provider_caps = str(path), total_micros, dict(provider_caps)
        with closing(sqlite3.connect(self.path)) as db:
            db.execute('''CREATE TABLE IF NOT EXISTS calls(
              call_id TEXT PRIMARY KEY, provider TEXT NOT NULL, model TEXT NOT NULL,
              reserved_micros INTEGER NOT NULL, metered_micros INTEGER,
              state TEXT NOT NULL CHECK(state IN ('RESERVED','METERED','UNCERTAIN')))''')
            db.execute('''CREATE TABLE IF NOT EXISTS observations(
              seq INTEGER PRIMARY KEY, family TEXT NOT NULL, model TEXT NOT NULL,
              guided INTEGER NOT NULL, passed INTEGER NOT NULL, artifact_hash TEXT NOT NULL,
              evidence_ref TEXT NOT NULL)''')
            db.execute('''CREATE TABLE IF NOT EXISTS lessons(
              basis TEXT PRIMARY KEY, teacher TEXT NOT NULL, advice TEXT NOT NULL,
              passed_artifact_hash TEXT NOT NULL, verifier_evidence_ref TEXT NOT NULL)''')
            db.commit()

    def spent_or_held(self) -> dict[str, int]:
        with closing(sqlite3.connect(self.path)) as db:
            rows = db.execute('''SELECT provider, SUM(CASE WHEN state='METERED'
                          THEN metered_micros ELSE reserved_micros END)
                          FROM calls GROUP BY provider''').fetchall()
            return {p: n for p, n in rows}

    def reserve(self, call_id: str, model: Model) -> int:
        if not call_id or model.provider not in self.provider_caps:
            raise BudgetBlocked('provider_not_authorized')
        q = model.quote_micros()
        with closing(sqlite3.connect(self.path, timeout=15)) as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT 1 FROM calls WHERE call_id=?', (call_id,)).fetchone():
                raise BudgetBlocked('duplicate_call_id_no_replay')
            if db.execute("SELECT 1 FROM calls WHERE state='UNCERTAIN' LIMIT 1").fetchone():
                raise BudgetBlocked('unreconciled_charge_stop')
            rows = db.execute('''SELECT provider, SUM(CASE WHEN state='METERED'
                             THEN metered_micros ELSE reserved_micros END)
                             FROM calls GROUP BY provider''').fetchall()
            used = dict(rows)
            if sum(used.values()) + q > self.total_cap or used.get(model.provider, 0) + q > self.provider_caps[model.provider]:
                raise BudgetBlocked('cap_exceeded')
            db.execute('INSERT INTO calls VALUES (?,?,?,?,NULL,?)',
                       (call_id, model.provider, model.name, q, 'RESERVED'))
            db.commit()
        return q

    def meter(self, call_id: str, micros: int):
        with closing(sqlite3.connect(self.path, timeout=15)) as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT reserved_micros,state FROM calls WHERE call_id=?', (call_id,)).fetchone()
            if row is None or row[1] != 'RESERVED':
                raise UncertainCharge('call_not_open')
            if not isinstance(micros, int) or micros < 0 or micros > row[0]:
                db.execute("UPDATE calls SET state='UNCERTAIN' WHERE call_id=?", (call_id,))
                db.commit()
                raise UncertainCharge('usage_outside_reserved_bound_reconcile_billing')
            db.execute("UPDATE calls SET metered_micros=?,state='METERED' WHERE call_id=?", (micros, call_id))
            db.commit()

    def uncertain(self, call_id: str):
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("UPDATE calls SET state='UNCERTAIN' WHERE call_id=? AND state='RESERVED'", (call_id,))
            db.commit()

    def observe(self, task: Task, model: Model, guided: bool, passed: bool, artifact: str, proof: str):
        if not proof:
            raise ValueError('independent_verification_reference_required')
        with closing(sqlite3.connect(self.path)) as db:
            db.execute('INSERT INTO observations(family,model,guided,passed,artifact_hash,evidence_ref) VALUES (?,?,?,?,?,?)',
                       (task.family, model.key, int(guided), int(passed), sha256(artifact.encode()).hexdigest(), proof))
            db.commit()

    def unguided_score(self, family: str, model: Model) -> tuple[int, int]:
        with closing(sqlite3.connect(self.path)) as db:
            count, wins = db.execute('''SELECT COUNT(*), COALESCE(SUM(passed),0) FROM observations
                 WHERE family=? AND model=? AND guided=0''', (family, model.key)).fetchone()
            return count, wins

    def lesson(self, basis: str) -> str | None:
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute('SELECT advice FROM lessons WHERE basis=?', (basis,)).fetchone()
            return None if row is None else row[0]

    def keep_lesson(self, task: Task, teacher: Model, advice: str, artifact: str, check: Check):
        if not check.passed or not check.evidence_ref or not advice:
            raise ValueError('lesson_requires_independent_passing_evidence')
        with closing(sqlite3.connect(self.path)) as db:
            db.execute('''INSERT OR IGNORE INTO lessons VALUES (?,?,?,?,?)''',
                       (task.basis, teacher.key, advice, sha256(artifact.encode()).hexdigest(), check.evidence_ref))
            db.commit()


class Coach:
    """One-task, at-most-four calls: student -> teacher guide -> student -> teacher solve.

    This is a *proposal* router: no project authority, no source execution,
    no signed evidence generation, no promotion. Caller owns these boundaries.
    """
    def __init__(self, meter: Meter, students: list[Model], teacher: Model,
                 run_model: Callable[[Model, str, Task, str], Completion],
                 independent_verify: Callable[[Task, str], Check]):
        if not students or not callable(run_model) or not callable(independent_verify):
            raise ValueError('invalid_coach_configuration')
        self.meter, self.students, self.teacher = meter, list(students), teacher
        self.run_model, self.independent_verify = run_model, independent_verify

    def _student(self, task: Task) -> Model:
        # Smoothing is a routing heuristic, not a safety or capability claim.
        scored = []
        for m in self.students:
            attempts, wins = self.meter.unguided_score(task.family, m)
            base = m.quote_micros()
            estimated = base if attempts < 3 else base * (attempts + 2) / (wins + 1)
            scored.append((estimated, base, m.key, m))
        return min(scored, key=lambda r: r[:3])[3]

    def _call(self, session: str, ordinal: int, m: Model, mode: str, task: Task, context: str):
        call_id = f'{session}-{ordinal}'
        quoted = self.meter.reserve(call_id, m)
        try:
            result = self.run_model(m, mode, task, context)
            if not isinstance(result, Completion):
                raise TypeError('runner_returned_non_completion')
            usage = m.quote_micros(result.input_tokens, result.output_tokens)
        except BaseException:
            self.meter.uncertain(call_id)
            raise
        self.meter.meter(call_id, usage)
        return result, {'call': call_id, 'model': m.key, 'mode': mode,
                        'reserved_micro_usd': quoted, 'metered_estimate_micro_usd': usage}

    def _check(self, task: Task, m: Model, guided: bool, artifact: str):
        # Verifier is trusted by the host, never selected by a model response.
        check = self.independent_verify(task, artifact)
        if not isinstance(check, Check) or not isinstance(check.passed, bool) or not check.evidence_ref:
            raise ValueError('independent_verifier_result_missing')
        self.meter.observe(task, m, guided, check.passed, artifact, check.evidence_ref)
        return check

    def propose(self, task: Task, session_id: str) -> dict:
        if not session_id or any(x not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for x in session_id):
            raise ValueError('invalid_session_id')
        student = self._student(task)
        calls: list[dict] = []
        prior = self.meter.lesson(task.basis)
        # Only use a lesson if this exact project, accepted head, and contract basis match.
        context = CANON + '\n' + (('Previously verified task-local guidance: ' + prior) if prior else '')
        try:
            first, rec = self._call(session_id, 1, student, 'propose', task, context)
            calls.append(rec)
            checked = self._check(task, student, bool(prior), first.text)
            if checked.passed:
                return self._result('VERIFIED_PROPOSAL', first.text, checked.evidence_ref, calls, student.key)
            guidance, rec = self._call(session_id, 2, self.teacher, 'teach', task,
                                       CANON + '\nFailed artifact (UNVERIFIED): ' + first.text[:5000])
            calls.append(rec)
            # Teacher words are untrusted advice. They cannot grant authority.
            second, rec = self._call(session_id, 3, student, 'propose', task,
                                      CANON + '\nTeacher advice (UNVERIFIED): ' + guidance.text[:4000])
            calls.append(rec)
            checked = self._check(task, student, True, second.text)
            if checked.passed:
                self.meter.keep_lesson(task, self.teacher, guidance.text[:4000], second.text, checked)
                return self._result('VERIFIED_PROPOSAL', second.text, checked.evidence_ref, calls, student.key)
            final, rec = self._call(session_id, 4, self.teacher, 'solve', task,
                                    CANON + '\nStudent proposals did not pass independent tests.')
            calls.append(rec)
            checked = self._check(task, self.teacher, False, final.text)
            if checked.passed:
                return self._result('VERIFIED_PROPOSAL', final.text, checked.evidence_ref, calls, self.teacher.key)
            return self._result('NO_VERIFIED_REPAIR', None, checked.evidence_ref, calls, None)
        except (BudgetBlocked, UncertainCharge) as err:
            return {'status':'BUDGET_OR_RECONCILIATION_STOP','reason':str(err),'calls':calls,
                    'promotion_authorized':False}

    @staticmethod
    def _result(status, artifact, evidence_ref, calls, model_key):
        return {'status': status, 'artifact': artifact,
                'artifact_sha256': sha256(artifact.encode()).hexdigest() if artifact is not None else None,
                'verifier_evidence_ref': evidence_ref, 'model': model_key, 'calls':calls,
                'promotion_authorized':False, 'signed_receipt':False}
