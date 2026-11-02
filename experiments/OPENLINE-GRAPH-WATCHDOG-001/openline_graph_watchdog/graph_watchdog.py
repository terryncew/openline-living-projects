"""Advisory graph-wide stagnation detector; no authority or effects.

Receiver supplies independently verified observations. Persistence and enforcement
belong to the trusted ProjectLedger/supervisor integration, not this module.
"""
from dataclasses import dataclass
from collections import defaultdict
from typing import Iterable

@dataclass(frozen=True)
class VerifiedAttempt:
    deliverable_id: str
    basis: str
    worker_id: str
    attempt_id: str
    progress_before: int
    progress_after: int
    receiver_verified: bool
    external_mutation: str = 'none'

    def __post_init__(self):
        if not all(isinstance(v, str) and v.strip() for v in (self.deliverable_id, self.basis, self.worker_id, self.attempt_id)):
            raise ValueError('nonempty identifiers required')
        if type(self.progress_before) is not int or type(self.progress_after) is not int or min(self.progress_before, self.progress_after) < 0:
            raise ValueError('progress must be nonnegative integers')
        if self.external_mutation not in ('none', 'confirmed', 'uncertain'):
            raise ValueError('invalid mutation state')
        if type(self.receiver_verified) is not bool:
            raise ValueError('receiver_verified must be bool')

    def fingerprint(self) -> str:
        return f"{self.worker_id}|{self.progress_before}|{self.progress_after}|{int(self.receiver_verified)}|{self.external_mutation}"


class CrossAgentGraphWatchdog:
    """Replay-safe, scope-bound detector; missing evidence cannot reset progress.

    The trusted caller must serialize observations and persist this state atomically
    with its own attempt ledger. A new basis starts a distinct counter by design.
    """
    def __init__(self, max_stagnant_attempts=3):
        if type(max_stagnant_attempts) is not int or max_stagnant_attempts < 1:
            raise ValueError('invalid threshold')
        self.threshold = max_stagnant_attempts
        self._states = defaultdict(lambda: {'seen': {}, 'stagnant': 0, 'workers': set(), 'peak': None, 'terminal': None})

    def observe(self, attempt: VerifiedAttempt):
        if not isinstance(attempt, VerifiedAttempt):
            raise TypeError('VerifiedAttempt required')
        key = (attempt.deliverable_id, attempt.basis)
        state = self._states[key]
        if attempt.attempt_id in state['seen']:
            if state['seen'][attempt.attempt_id] != attempt.fingerprint():
                raise ValueError('conflicting duplicate attempt_id')
            return self._result(key, state, 'DUPLICATE_IGNORED')
        if state['terminal']:
            return self._result(key, state, state['terminal'])
        if attempt.external_mutation == 'uncertain':
            state['seen'][attempt.attempt_id] = attempt.fingerprint()
            state['workers'].add(attempt.worker_id)
            state['terminal'] = 'HOLD_RECONCILIATION'
            return self._result(key, state, 'HOLD_RECONCILIATION')
        state['seen'][attempt.attempt_id] = attempt.fingerprint()
        state['workers'].add(attempt.worker_id)
        if not attempt.receiver_verified:
            state['stagnant'] += 1
        elif state['peak'] is None:
            state['peak'] = attempt.progress_before
            if attempt.progress_after > attempt.progress_before and attempt.progress_after > state['peak']:
                state['peak'] = attempt.progress_after
                state['stagnant'] = 0
            else:
                state['stagnant'] += 1
        elif attempt.progress_after > attempt.progress_before and attempt.progress_after > state['peak']:
            state['peak'] = attempt.progress_after
            state['stagnant'] = 0
        else:
            if attempt.progress_before > state['peak']:
                state['peak'] = attempt.progress_before
            state['stagnant'] += 1
        if state['stagnant'] >= self.threshold:
            state['terminal'] = 'STOP_STAGNATION'
            return self._result(key, state, 'STOP_STAGNATION')
        return self._result(key, state, 'CONTINUE')

    def status(self, deliverable_id, basis):
        if not all(isinstance(v, str) and v.strip() for v in (deliverable_id, basis)):
            raise ValueError('nonempty identifiers required')
        key = (deliverable_id, basis)
        if key not in self._states:
            return None
        state = self._states[key]
        return {'deliverable_id': deliverable_id, 'basis': basis,
                'stagnant_attempts': state['stagnant'],
                'workers': sorted(state['workers']), 'peak': state['peak'],
                'terminal': state['terminal'], 'receiver_authorization': 'NONE'}

    @staticmethod
    def _result(key, state, decision):
        return {'deliverable_id': key[0], 'basis': key[1], 'decision': decision,
                'stagnant_attempts': state['stagnant'], 'workers': sorted(state['workers']),
                'receiver_authorization': 'NONE'}


def unwitnessed_agreement(claims: Iterable[dict], verified_receipt_ids: set[str]):
    """Diagnostic only. Claims cannot witness each other or grant authority."""
    by_target = defaultdict(set)
    for claim in claims:
        if not {'target', 'agent', 'receipt_id'} <= claim.keys():
            raise ValueError('malformed claim')
        if claim['receipt_id'] not in verified_receipt_ids:
            by_target[claim['target']].add(claim['agent'])
    return {target: sorted(agents) for target, agents in by_target.items() if len(agents) >= 2}


def shared_bottlenecks(dependencies: Iterable[tuple[str, str]], reopened: set[str]):
    """Conventional DAG fan-in baseline, deliberately not labeled TOE superiority."""
    by_dependency = defaultdict(set)
    for deliverable, dependency in dependencies:
        if deliverable in reopened:
            by_dependency[dependency].add(deliverable)
    return {dep: sorted(items) for dep, items in by_dependency.items() if len(items) >= 2}
