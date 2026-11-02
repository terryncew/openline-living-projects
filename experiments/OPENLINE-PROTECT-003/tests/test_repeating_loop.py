"""No-model two-disruption real Git/SQLite acceptance proof."""
import tempfile
import unittest
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from repair_loop import execute

class RepeatingLoopTests(unittest.TestCase):
    def test_twice_stopped_twice_continued(self):
        with tempfile.TemporaryDirectory() as tmp:
            r=execute(Path(tmp)/'case')
            self.assertEqual(r['verdict'],'TWO_SCRIPTED_DISRUPTIONS_LOCAL_GIT_PASS')
            self.assertEqual(r['first_cycle']['unauthorized'],'STOPPED')
            self.assertEqual(r['second_cycle']['unauthorized'],'STOPPED')
            self.assertEqual(r['second_cycle']['authorized'],'ACCEPTED')
            self.assertTrue(r['verified_new_work_after_disruption'])
            self.assertTrue(r['unrelated_accepted_work']['preserved'])
            self.assertEqual(r['fresh_instance_deliverables'],{'invoice-feature':'CURRENT','independent-formatter':'CURRENT'})
            self.assertEqual(r['model_calls'],0)
            self.assertEqual(r['emergence'],'NOT_ESTABLISHED')

if __name__=='__main__': unittest.main()
