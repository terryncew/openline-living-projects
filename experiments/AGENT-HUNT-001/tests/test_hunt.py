import json
import unittest
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from hunt import hunt, build_html

ROOT=Path(__file__).resolve().parents[1]
class HuntTests(unittest.TestCase):
    def setUp(self):
        self.policy=json.loads((ROOT/'policy.json').read_text())
        self.events=[json.loads(x) for x in (ROOT/'events.jsonl').read_text().splitlines()]
    def test_sample_findings(self):
        r=hunt(self.policy,self.events)
        self.assertEqual(r['observed_events'],8)
        self.assertEqual(r['scope_alert_events'],5)
        self.assertEqual(r['flagged_agents'],['agent-blake'])
    def test_replay_and_revocation(self):
        findings=hunt(self.policy,self.events)['findings']
        self.assertIn('REPEATED_NONCE',findings[6]['reasons'])
        self.assertIn('REVOKED_IDENTITY',findings[7]['reasons'])
    def test_impact_boundaries(self):
        statuses=[r['status'] for r in hunt(self.policy,self.events)['impact']]
        self.assertEqual(statuses,['REOPEN','RETAIN','UNDETERMINED'])
    def test_no_proven_effects(self):
        r=hunt(self.policy,self.events)
        self.assertEqual(r['source_authenticity'],'UNVERIFIED')
        self.assertTrue(all('UNKNOWN' in x['effect_truth'] for x in r['findings']))
    def test_no_prefix_authority(self):
        fake=dict(self.events[0],id='bad-path',resource='src/docs/readme.md.evil',nonce='new')
        r=hunt(self.policy,[fake])
        self.assertIn('OUT_OF_SCOPE',r['findings'][0]['reasons'])
    def test_unknown_agent(self):
        fake=dict(self.events[0],id='unknown',agent='someone-else')
        self.assertIn('UNKNOWN_AGENT',hunt(self.policy,[fake])['findings'][0]['reasons'])
    def test_html_embedded_json_escape(self):
        r=hunt(self.policy,self.events)
        r['flagged_agents']=['</script><script>alert(1)</script>']
        result=build_html(r)
        self.assertNotIn('</script><script>alert(1)',result)
        self.assertIn('SIMULATION, NOT ACTIVE PROTECTION',result)

if __name__=='__main__': unittest.main()
