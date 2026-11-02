"""Independent test that prevents false claims of Git concurrency advantage."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from compare_concurrent import execute

class ConventionalTests(unittest.TestCase):
    def test_competent_git_preserves_unrelated_concurrent_work(self):
        o=execute()
        self.assertEqual(o['verdict'],'CONVENTIONAL_CONCURRENT_PRESERVATION_PASS')
        self.assertEqual(o['scope_at_candidate_base'],['app/price.py'])
        self.assertTrue(o['both_contributors_preserved'])
        self.assertTrue(o['stale_cas_refused'])
        self.assertEqual(o['signed_receipts'],'NOT_TESTED')

if __name__=='__main__':unittest.main()
