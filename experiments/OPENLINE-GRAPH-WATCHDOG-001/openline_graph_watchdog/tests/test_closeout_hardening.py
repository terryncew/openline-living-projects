import os
import tempfile
import unittest
from graph_watchdog import VerifiedAttempt, CrossAgentGraphWatchdog
from durable_watchdog import DurableGraphWatchdog


def attempt(id, mutation='none'):
    return VerifiedAttempt('project', 'receiver-basis', 'alice', id, 0, 0, False, mutation)


class HardeningTests(unittest.TestCase):
    def test_verified_flag_is_strict(self):
        for invalid in (1, 0, 'yes', None, [], 2.0):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                VerifiedAttempt('project', 'basis', 'alice', 'a', 0, 1, invalid)
        for valid in (True, False):
            VerifiedAttempt('project', 'basis', 'alice', 'a', 0, 1, valid)

    def test_in_memory_status_is_read_only(self):
        w = CrossAgentGraphWatchdog(3)
        self.assertIsNone(w.status('project', 'receiver-basis'))
        w.observe(attempt('a'))
        first = w.status('project', 'receiver-basis')
        self.assertEqual(first['stagnant_attempts'], 1)
        self.assertEqual(w.status('project', 'receiver-basis'), first)

    def test_in_memory_hold_and_replay(self):
        w = CrossAgentGraphWatchdog()
        self.assertEqual(w.observe(attempt('a', 'uncertain'))['decision'], 'HOLD_RECONCILIATION')
        self.assertEqual(w.observe(attempt('a', 'uncertain'))['decision'], 'DUPLICATE_IGNORED')
        self.assertEqual(w.observe(attempt('b'))['decision'], 'HOLD_RECONCILIATION')
        self.assertEqual(w.status('project', 'receiver-basis')['terminal'], 'HOLD_RECONCILIATION')

    def test_durable_threshold_is_pinned(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'watchdog.db')
            w = DurableGraphWatchdog(path, threshold=3)
            w.record(attempt('a'))
            self.assertEqual(w.status('project', 'receiver-basis')['threshold'], 3)
            with self.assertRaises(ValueError):
                DurableGraphWatchdog(path, threshold=5)
            self.assertEqual(DurableGraphWatchdog(path, threshold=3).status('project', 'receiver-basis')['stagnant_attempts'], 1)

    def test_durable_status_does_not_mutate(self):
        with tempfile.TemporaryDirectory() as tmp:
            w = DurableGraphWatchdog(os.path.join(tmp, 'watchdog.db'))
            self.assertIsNone(w.status('project', 'receiver-basis'))
            w.record(attempt('a'))
            before = w.status('project', 'receiver-basis')
            self.assertEqual(before, w.status('project', 'receiver-basis'))
            self.assertEqual(before['workers'], ['alice'])


    def test_conflicting_duplicate_attempt_id_rejected(self):
        w_mem = CrossAgentGraphWatchdog(3)
        w_mem.observe(VerifiedAttempt('project', 'basis', 'alice', 'att-1', 0, 0, True, 'none'))
        # Identical duplicate is ignored
        self.assertEqual(
            w_mem.observe(VerifiedAttempt('project', 'basis', 'alice', 'att-1', 0, 0, True, 'none'))['decision'],
            'DUPLICATE_IGNORED'
        )
        # Conflicting duplicate with same attempt_id raises ValueError
        with self.assertRaises(ValueError):
            w_mem.observe(VerifiedAttempt('project', 'basis', 'bob', 'att-1', 0, 0, True, 'none'))
        with self.assertRaises(ValueError):
            w_mem.observe(VerifiedAttempt('project', 'basis', 'alice', 'att-1', 0, 5, True, 'none'))

        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, 'watchdog.db')
            w_dur = DurableGraphWatchdog(db_path, threshold=3)
            w_dur.record(VerifiedAttempt('project', 'basis', 'alice', 'att-1', 0, 0, True, 'none'))
            self.assertEqual(
                w_dur.record(VerifiedAttempt('project', 'basis', 'alice', 'att-1', 0, 0, True, 'none'))['decision'],
                'DUPLICATE_IGNORED'
            )
            with self.assertRaises(ValueError):
                w_dur.record(VerifiedAttempt('project', 'basis', 'bob', 'att-1', 0, 0, True, 'none'))
            with self.assertRaises(ValueError):
                w_dur.record(VerifiedAttempt('project', 'basis', 'alice', 'att-1', 0, 2, True, 'none'))

    def test_legacy_threshold_migration_and_concurrent_writes(self):
        import sqlite3
        from concurrent.futures import ThreadPoolExecutor
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, 'legacy.db')
            # Create a legacy schema without threshold column where stagnant is already 2
            conn = sqlite3.connect(db_path)
            conn.executescript("""
                CREATE TABLE watchdog_scope (
                    deliverable TEXT NOT NULL, basis TEXT NOT NULL,
                    peak INTEGER, stagnant INTEGER NOT NULL DEFAULT 0,
                    terminal TEXT, PRIMARY KEY(deliverable,basis));
                CREATE TABLE watchdog_attempt (
                    deliverable TEXT NOT NULL, basis TEXT NOT NULL,
                    attempt_id TEXT NOT NULL, worker TEXT NOT NULL,
                    PRIMARY KEY(deliverable,basis,attempt_id));
                INSERT INTO watchdog_scope VALUES ('legacy-deliv', 'v1', 0, 2, NULL);
            """)
            conn.commit()
            conn.close()

            # Migrate with threshold=2 -> must pin threshold=2 and set terminal='STOP_STAGNATION'
            w = DurableGraphWatchdog(db_path, threshold=2)
            st = w.status('legacy-deliv', 'v1')
            self.assertEqual(st['threshold'], 2)
            self.assertEqual(st['terminal'], 'STOP_STAGNATION')

            # Concurrent writes from 6 threads on a new scope ('conc-deliv', 'v1')
            w_conc = DurableGraphWatchdog(db_path, threshold=2)
            def _worker(i):
                return DurableGraphWatchdog(db_path, threshold=2).record(
                    VerifiedAttempt('conc-deliv', 'v1', f'worker-{i}', f'att-{i}', 0, 0, True, 'none')
                )
            with ThreadPoolExecutor(max_workers=6) as ex:
                results = list(ex.map(_worker, range(6)))
            st_conc = w.status('conc-deliv', 'v1')
            self.assertEqual(st_conc['terminal'], 'STOP_STAGNATION')
            self.assertEqual(st_conc['stagnant_attempts'], 2)

if __name__ == '__main__':
    unittest.main()
