import os
import tempfile
import unittest
from graph_watchdog import VerifiedAttempt
from durable_watchdog import DurableGraphWatchdog

class DurableTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name,'watchdog.sqlite')
    def tearDown(self): self.tmp.cleanup()
    def a(self,worker,n,after=0,verified=True,mutation='none',basis='v1'):
        return VerifiedAttempt('invoice',basis,worker,str(n),0,after,verified,mutation)
    def test_restart_and_cross_worker_stop(self):
        DurableGraphWatchdog(self.path).record(self.a('alice',1))
        DurableGraphWatchdog(self.path).record(self.a('bob',2))
        r=DurableGraphWatchdog(self.path).record(self.a('carol',3))
        self.assertEqual(r['decision'],'STOP_STAGNATION')
        self.assertEqual(r['workers'],['alice','bob','carol'])
    def test_duplicate_persists_across_restart(self):
        DurableGraphWatchdog(self.path,2).record(self.a('a',1))
        self.assertEqual(DurableGraphWatchdog(self.path,2).record(self.a('a',1))['decision'],'DUPLICATE_IGNORED')
        self.assertEqual(DurableGraphWatchdog(self.path,2).record(self.a('b',2))['decision'],'STOP_STAGNATION')
    def test_uncertain_hold_survives_restart(self):
        DurableGraphWatchdog(self.path).record(self.a('a',1,mutation='uncertain'))
        self.assertEqual(DurableGraphWatchdog(self.path).record(self.a('b',2))['decision'],'HOLD_RECONCILIATION')
    def test_verified_progress_resets(self):
        w=DurableGraphWatchdog(self.path,2)
        w.record(self.a('a',1))
        self.assertEqual(w.record(self.a('b',2,after=2))['decision'],'CONTINUE')
        self.assertEqual(w.record(self.a('c',3,after=2))['decision'],'CONTINUE')
    def test_unverified_progress_does_not_reset(self):
        w=DurableGraphWatchdog(self.path,2)
        w.record(self.a('a',1,after=50,verified=False))
        self.assertEqual(w.record(self.a('b',2,after=100,verified=False))['decision'],'STOP_STAGNATION')
    def test_basis_isolated(self):
        w=DurableGraphWatchdog(self.path,1)
        self.assertEqual(w.record(self.a('a',1))['decision'],'STOP_STAGNATION')
        self.assertEqual(w.record(self.a('a',1,after=2,basis='v2'))['decision'],'CONTINUE')
