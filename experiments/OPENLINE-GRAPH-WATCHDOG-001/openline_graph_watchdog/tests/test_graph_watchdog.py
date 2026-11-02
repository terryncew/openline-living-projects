import unittest
from graph_watchdog import VerifiedAttempt, CrossAgentGraphWatchdog, unwitnessed_agreement, shared_bottlenecks

class GraphWatchdogTests(unittest.TestCase):
    def attempt(self, worker, i, before=0, after=0, verified=True, basis='v2', mutation='none'):
        return VerifiedAttempt('invoice', basis, worker, f'{basis}-{i}', before, after, verified, mutation)
    def test_cross_worker_loop(self):
        w = CrossAgentGraphWatchdog(3)
        self.assertEqual(w.observe(self.attempt('alice', 1))['decision'], 'CONTINUE')
        self.assertEqual(w.observe(self.attempt('alice', 2))['decision'], 'CONTINUE')
        result = w.observe(self.attempt('bob', 3))
        self.assertEqual(result['decision'], 'STOP_STAGNATION')
        self.assertEqual(result['workers'], ['alice', 'bob'])
    def test_duplicate_does_not_burn_budget(self):
        w = CrossAgentGraphWatchdog(2)
        a = self.attempt('a', 1)
        w.observe(a)
        self.assertEqual(w.observe(a)['decision'], 'DUPLICATE_IGNORED')
        self.assertEqual(w.observe(self.attempt('b', 2))['decision'], 'STOP_STAGNATION')
    def test_real_progress_resets(self):
        w = CrossAgentGraphWatchdog(2)
        w.observe(self.attempt('a', 1))
        self.assertEqual(w.observe(self.attempt('a', 2, 0, 1))['decision'], 'CONTINUE')
        self.assertEqual(w.observe(self.attempt('b', 3, 1, 1))['decision'], 'CONTINUE')
    def test_unverified_cannot_reset(self):
        w = CrossAgentGraphWatchdog(2)
        w.observe(self.attempt('a', 1, 0, 10, False))
        self.assertEqual(w.observe(self.attempt('b', 2, 0, 100, False))['decision'], 'STOP_STAGNATION')
    def test_basis_isolated(self):
        w = CrossAgentGraphWatchdog(1)
        self.assertEqual(w.observe(self.attempt('a', 1))['decision'], 'STOP_STAGNATION')
        self.assertEqual(w.observe(self.attempt('a', 1, basis='v3', before=0, after=1))['decision'], 'CONTINUE')
    def test_uncertain_mutation_halts(self):
        w = CrossAgentGraphWatchdog()
        self.assertEqual(w.observe(self.attempt('a', 1, mutation='uncertain'))['decision'], 'HOLD_RECONCILIATION')
        self.assertEqual(w.observe(self.attempt('b', 2))['decision'], 'HOLD_RECONCILIATION')
    def test_unwitnessed_agreement(self):
        claims = [{'target':'invoice','agent':x,'receipt_id':'fake'} for x in ('a','b')]
        self.assertEqual(unwitnessed_agreement(claims, set()), {'invoice':['a','b']})
        self.assertEqual(unwitnessed_agreement(claims, {'fake'}), {})
    def test_conventional_bottleneck(self):
        self.assertEqual(shared_bottlenecks([('a','contract'),('b','contract')], {'a','b'}), {'contract':['a','b']})

if __name__ == '__main__': unittest.main()
