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
    def test_adversarial_malformed_missing_reordered_duplicated_expired_contradictory_evidence(self):
        pol = json.loads(json.dumps(self.policy))
        pol['evidence']['exp-ev'] = {'status': 'valid', 'expires_at': '2026-11-01T10:01:00Z'}
        pol['evidence']['contra-ev'] = {'status': 'contradictory'}
        # 1. Missing evidence on repo.promote & blank evidence
        ev_missing = {'id': 'e-miss', 'time': '2026-11-01T10:00:05Z', 'agent': 'agent-amelia', 'tool': 'repo.promote', 'resource': 'src/docs/readme.md', 'nonce': 'n1'}
        # 2. Expired evidence
        ev_expired = {'id': 'e-exp', 'time': '2026-11-01T10:02:00Z', 'agent': 'agent-amelia', 'tool': 'repo.read', 'resource': 'src/docs/readme.md', 'nonce': 'n2', 'evidence': 'exp-ev'}
        # 3. Contradictory evidence list (one valid, one invalidated)
        ev_contra = {'id': 'e-con', 'time': '2026-11-01T10:02:05Z', 'agent': 'agent-amelia', 'tool': 'repo.read', 'resource': 'src/docs/readme.md', 'nonce': 'n3', 'evidence': ['document-contract-v2', 'pricing-table-v1']}
        # 4. Duplicate event ID and missing nonce
        ev_dup = {'id': 'e-miss', 'time': '2026-11-01T10:02:10Z', 'agent': 'agent-amelia', 'tool': 'repo.read', 'resource': 'src/docs/readme.md', 'nonce': ''}
        # 5. Reordered timezone offset: 02:05:00-08:00 is 10:05:00Z (after agent-blake revocation at 10:04:00Z), even though '02:' < '10:' lexicographically
        ev_tz = {'id': 'e-tz', 'time': '2026-11-01T02:05:00-08:00', 'agent': 'agent-blake', 'tool': 'repo.read', 'resource': 'src/billing/tax.py', 'nonce': 'n-tz', 'evidence': 'pricing-table-v2'}
        # 6. Naive timestamp without timezone
        ev_naive = {'id': 'e-naive', 'time': '2026-11-01T10:00:00', 'agent': 'agent-amelia', 'tool': 'repo.read', 'resource': 'src/docs/readme.md', 'nonce': 'n-naive', 'evidence': 'document-contract-v2'}

        res = hunt(pol, [ev_tz, ev_missing, ev_expired, ev_contra, ev_dup, ev_naive])
        by_id = {f['id'] + ':' + f['time']: f for f in res['findings']}
        self.assertIn('STALE_OR_MISSING_EVIDENCE', by_id['e-miss:2026-11-01T10:00:05Z']['reasons'])
        self.assertIn('EXPIRED_EVIDENCE', by_id['e-exp:2026-11-01T10:02:00Z']['reasons'])
        self.assertIn('CONTRADICTORY_EVIDENCE', by_id['e-con:2026-11-01T10:02:05Z']['reasons'])
        self.assertIn('DUPLICATE_EVENT_ID', by_id['e-miss:2026-11-01T10:02:10Z']['reasons'])
        self.assertIn('MISSING_OR_MALFORMED_NONCE', by_id['e-miss:2026-11-01T10:02:10Z']['reasons'])
        self.assertIn('REVOKED_IDENTITY', by_id['e-tz:2026-11-01T02:05:00-08:00']['reasons'])
        self.assertIn('MALFORMED_TIMESTAMP', by_id['e-naive:2026-11-01T10:00:00']['reasons'])
        # Chronological sort places e-tz (10:05:00Z) last despite '02:05' string prefix
        self.assertEqual(res['findings'][-1]['id'], 'e-tz')

if __name__=='__main__': unittest.main()
