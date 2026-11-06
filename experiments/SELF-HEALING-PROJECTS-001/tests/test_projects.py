"""Deterministic project ledger tests. Stub Git/World interfaces are NOT integration evidence."""
import sys as _sys; from pathlib import Path as _Path
_AUTO_BOOTSTRAP_PATHS = [
    _Path(__file__).resolve().parents[1],
    _Path(__file__).resolve().parents[2] / 'SELF-HEALING-ENGINE-001',
    _Path(__file__).resolve().parents[2] / 'SELF-HEALING-PROJECTS-001',
    _Path(__file__).resolve().parents[2] / 'OPENLINE-PROTECT-001',
]
for _p in reversed(_AUTO_BOOTSTRAP_PATHS):
    if _p.exists() and str(_p) not in _sys.path:
        _sys.path.insert(0, str(_p))
import hashlib
import tempfile
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from project import ProjectLedger, ProjectRefused, canonical, digest


def pub(key):
    return key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()


def sign(key, claim):
    return key.sign(canonical(claim)).hex()


class FakePromotion:
    def __init__(self):
        self.head='a'*40
        self.outcomes={}
        self.promote_calls=0
        self.last_allow_prefixes=None
    def accepted(self): return self.head
    def recover(self, assignment_id): return self.outcomes.get(assignment_id,{'status':'NOT_FOUND'})
    def promote(self, assignment_id, *, acceptance_cmd, allow_prefixes, timeout):
        self.promote_calls+=1
        self.last_allow_prefixes=allow_prefixes
        self.head='b'*40
        self.outcomes[assignment_id]={'status':'PROMOTED','head':self.head}
        return self.outcomes[assignment_id]


class ProjectTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.owner=Ed25519PrivateKey.generate()
        self.alice=Ed25519PrivateKey.generate()
        self.bob=Ed25519PrivateKey.generate()
        self.promotion=FakePromotion()
        self.ledger=ProjectLedger(Path(self.temp.name)/'project.sqlite','proj-1','invoice repair',pub(self.owner),promotion=self.promotion,
                                  world_verifier=lambda rec,inv: rec.get('decision')=='ALLOWED' and rec.get('member')==inv['member_id'])
        self.join('alice',self.alice)
        self.join('bob',self.bob)

    def invitation(self,member,key, receipt=None):
        receipt=receipt or {'decision':'ALLOWED','member':member}
        return ({'project_id':'proj-1','member_id':member,'owner_pub':pub(key),
                 'worker_pub':pub(key),'scope':'contribute','world_digest':digest(receipt)},receipt)

    def join(self,member,key):
        claim,receipt=self.invitation(member,key)
        return self.ledger.join(claim,sign(self.owner,claim),sign(key,claim),world_receipt=receipt)

    def accept(self,id,member,key,deps):
        claim={'project_id':'proj-1','deliverable_id':id,'member_id':member,
               'accepted_head':self.promotion.head,'dependencies':sorted(deps)}
        self.ledger.accept(id,member,self.promotion.head,deps,sign(key,claim))

    def change(self):
        claim={'project_id':'proj-1','dependency':'invoice_v1','contract':'v2','action':'change_dependency'}
        return self.ledger.change_dependency('invoice_v1','v2',sign(self.owner,claim))

    def test_two_participants_and_selective_reconsideration(self):
        self.accept('feature','alice',self.alice,['invoice_v1'])
        self.accept('independent','bob',self.bob,['logging'])
        self.assertEqual(self.change(),['feature'])
        standing={v[0]:v[2] for v in self.ledger.snapshot()['deliverables']}
        self.assertEqual(standing,{'feature':'REOPEN','independent':'CURRENT'})
        claim={'project_id':'proj-1','assignment_id':'repair-1','deliverable_id':'feature',
               'worker_member':'bob','basis':'v2','allowed_paths':['app/price.py'],'action':'repair_assignment'}
        self.ledger.assign_repair('repair-1','feature','bob','v2',sign(self.alice,claim),allowed_paths=['app/price.py'])
        self.promotion.head='b'*40
        self.promotion.outcomes['repair-1']={'status':'PROMOTED','head':'b'*40}
        self.assertEqual(self.ledger.resolve_repair('repair-1','b'*40),'RECORDED')
        self.assertEqual(self.ledger.resolve_repair('repair-1','b'*40),'ALREADY_RECORDED')
        self.assertEqual({x[0]:x[2] for x in self.ledger.snapshot()['deliverables']},
                         {'feature':'CURRENT','independent':'CURRENT'})

    def test_cannot_invent_world_admission(self):
        k=Ed25519PrivateKey.generate(); claim,receipt=self.invitation('mallory',k)
        receipt['decision']='STOPPED'
        with self.assertRaises(ProjectRefused):
            self.ledger.join(claim,sign(self.owner,claim),sign(k,claim),world_receipt=receipt)

    def test_cannot_forge_invitation(self):
        k=Ed25519PrivateKey.generate(); claim,receipt=self.invitation('mallory',k)
        with self.assertRaises(ProjectRefused):
            self.ledger.join(claim,sign(self.bob,claim),sign(k,claim),world_receipt=receipt)

    def test_member_key_rebind_refused(self):
        k=Ed25519PrivateKey.generate();claim,receipt=self.invitation('alice',k)
        with self.assertRaisesRegex(ProjectRefused,'member_key_or_admission_rebind'):
            self.ledger.join(claim,sign(self.owner,claim),sign(k,claim),world_receipt=receipt)

    def test_promotion_cannot_be_self_reported(self):
        self.accept('feature','alice',self.alice,['invoice_v1'])
        self.change()
        claim={'project_id':'proj-1','assignment_id':'repair-1','deliverable_id':'feature',
               'worker_member':'bob','basis':'v2','allowed_paths':['app/price.py'],'action':'repair_assignment'}
        self.ledger.assign_repair('repair-1','feature','bob','v2',sign(self.alice,claim),allowed_paths=['app/price.py'])
        with self.assertRaises(ProjectRefused):self.ledger.resolve_repair('repair-1','b'*40)
        self.promotion.head='b'*40
        with self.assertRaisesRegex(ProjectRefused,'promotion_journal_not_confirmed'):
            self.ledger.resolve_repair('repair-1','b'*40)

    def test_revoked_participant_cannot_be_assigned(self):
        self.accept('feature','alice',self.alice,['invoice_v1'])
        self.change()
        claim={'project_id':'proj-1','member_id':'bob','action':'revoke_member'}
        self.ledger.revoke_member('bob',sign(self.owner,claim))
        repair={'project_id':'proj-1','assignment_id':'repair-1','deliverable_id':'feature',
                'worker_member':'bob','basis':'v2','allowed_paths':['app/price.py'],'action':'repair_assignment'}
        with self.assertRaisesRegex(ProjectRefused,'member_not_active'):
            self.ledger.assign_repair('repair-1','feature','bob','v2',sign(self.alice,repair),allowed_paths=['app/price.py'])

    def test_accept_requires_trusted_head(self):
        claim={'project_id':'proj-1','deliverable_id':'bad','member_id':'alice',
               'accepted_head':'b'*40,'dependencies':['invoice_v1']}
        with self.assertRaisesRegex(ProjectRefused,'accepted_ref_mismatch'):
            self.ledger.accept('bad','alice','b'*40,['invoice_v1'],sign(self.alice,claim))

    def test_reopen_requires_project_owner(self):
        self.accept('feature','alice',self.alice,['invoice_v1'])
        claim={'project_id':'proj-1','dependency':'invoice_v1','contract':'v2','action':'change_dependency'}
        with self.assertRaisesRegex(ProjectRefused,'invalid_owner_signature'):
            self.ledger.change_dependency('invoice_v1','v2',sign(self.bob,claim))

    def test_unassigned_correct_candidate_cannot_promote_through_project(self):
        before=self.promotion.head
        with self.assertRaisesRegex(ProjectRefused,'repair_assignment_missing'):
            self.ledger.promote_repair('unassigned',acceptance_cmd=['python','-V'])
        self.assertEqual(self.promotion.promote_calls,0)
        self.assertEqual(self.promotion.head,before)

    def test_receiver_uses_signed_path_allowlist_at_promotion(self):
        self.accept('feature','alice',self.alice,['invoice_v1'])
        self.change()
        claim={'project_id':'proj-1','assignment_id':'repair-1','deliverable_id':'feature',
               'worker_member':'bob','basis':'v2','allowed_paths':['app/price.py'],
               'action':'repair_assignment'}
        self.ledger.assign_repair('repair-1','feature','bob','v2',sign(self.alice,claim),
                                  allowed_paths=['app/price.py'])
        result=self.ledger.promote_repair('repair-1',acceptance_cmd=['python','-V'])
        self.assertEqual(result['status'],'PROMOTED')
        self.assertEqual(self.promotion.last_allow_prefixes,('app/price.py',))
        self.assertEqual(self.ledger.resolve_repair('repair-1','b'*40),'RECORDED')

    def test_revoked_member_cannot_reach_promotion(self):
        self.accept('feature','alice',self.alice,['invoice_v1'])
        self.change()
        claim={'project_id':'proj-1','assignment_id':'repair-1','deliverable_id':'feature',
               'worker_member':'bob','basis':'v2','allowed_paths':['app/price.py'],
               'action':'repair_assignment'}
        self.ledger.assign_repair('repair-1','feature','bob','v2',sign(self.alice,claim),
                                  allowed_paths=['app/price.py'])
        rev={'project_id':'proj-1','member_id':'bob','action':'revoke_member'}
        self.ledger.revoke_member('bob',sign(self.owner,rev))
        with self.assertRaisesRegex(ProjectRefused,'member_not_active'):
            self.ledger.promote_repair('repair-1',acceptance_cmd=['python','-V'])
        self.assertEqual(self.promotion.promote_calls,0)

    def test_invalid_assignment_paths_denied_before_signature(self):
        self.accept('feature','alice',self.alice,['invoice_v1'])
        self.change()
        claim={'project_id':'proj-1','assignment_id':'repair-1','deliverable_id':'feature',
               'worker_member':'bob','basis':'v2','allowed_paths':['app/price.py'],
               'action':'repair_assignment'}
        with self.assertRaisesRegex(ProjectRefused,'invalid_repair_paths'):
            self.ledger.assign_repair('repair-1','feature','bob','v2',sign(self.alice,claim),
                                      allowed_paths=['app/../checks/oracle.py'])
        self.assertEqual(self.promotion.promote_calls,0)

    def test_restart_durable(self):
        self.accept('feature','alice',self.alice,['invoice_v1'])
        restored=ProjectLedger(Path(self.temp.name)/'project.sqlite',promotion=self.promotion,
                 world_verifier=self.ledger.world_verifier)
        self.assertEqual(restored.snapshot()['deliverables'][0][0],'feature')
        self.assertEqual(restored.owner_pub,pub(self.owner))

    def test_unrelated_contract_change_preserves_reconsideration_status(self):
        self.accept('feature','alice',self.alice,['invoice_v1'])
        self.accept('independent','bob',self.bob,['logging'])
        self.assertEqual(self.change(),['feature'])
        self.assertEqual(self.ledger.snapshot()['project'][-1],'RECONSIDERATION')
        unrelated={'project_id':'proj-1','dependency':'unused_dep','contract':'unused_v2','action':'change_dependency'}
        affected=self.ledger.change_dependency('unused_dep','unused_v2',sign(self.owner,unrelated))
        self.assertEqual(affected,[])
        # Project status must stay RECONSIDERATION while 'feature' is still REOPEN.
        self.assertEqual(self.ledger.snapshot()['project'][-1],'RECONSIDERATION')

    def test_chained_unrepaired_contract_change_tracks_reopened_deliverable(self):
        self.accept('feature','alice',self.alice,['invoice_v1'])
        self.assertEqual(self.change(),['feature'])
        stale={'project_id':'proj-1','assignment_id':'repair-v2','deliverable_id':'feature',
               'worker_member':'bob','basis':'v2','allowed_paths':['app/price.py'],'action':'repair_assignment'}
        self.ledger.assign_repair('repair-v2','feature','bob','v2',sign(self.alice,stale),allowed_paths=['app/price.py'])
        # Supersede v2 -> v3 before repair-v2 runs.
        c3={'project_id':'proj-1','dependency':'v2','contract':'v3','action':'change_dependency'}
        self.assertEqual(self.ledger.change_dependency('v2','v3',sign(self.owner,c3)),['feature'])
        self.assertEqual(self.ledger.snapshot()['project'][-1],'RECONSIDERATION')
        with self.assertRaisesRegex(ProjectRefused,'assignment_basis_stale'):
            self.ledger.promote_repair('repair-v2',acceptance_cmd=['python','-V'])
        fresh={'project_id':'proj-1','assignment_id':'repair-v3','deliverable_id':'feature',
               'worker_member':'bob','basis':'v3','allowed_paths':['app/price.py'],'action':'repair_assignment'}
        self.ledger.assign_repair('repair-v3','feature','bob','v3',sign(self.alice,fresh),allowed_paths=['app/price.py'])
        res=self.ledger.promote_repair('repair-v3',acceptance_cmd=['python','-V'])
        self.assertEqual(res['status'],'PROMOTED')
        self.assertEqual(self.ledger.resolve_repair('repair-v3',res['head']),'RECORDED')
        self.assertEqual(self.ledger.snapshot()['project'][-1],'ACTIVE')

    def test_cyclic_rollback_rebind_across_multiple_repairs(self):
        self.accept('feature','alice',self.alice,['invoice_v1'])
        # Cycle 1: invoice_v1 -> v2
        self.assertEqual(self.change(),['feature'])
        a1={'project_id':'proj-1','assignment_id':'r1','deliverable_id':'feature',
            'worker_member':'bob','basis':'v2','allowed_paths':['app/price.py'],'action':'repair_assignment'}
        self.ledger.assign_repair('r1','feature','bob','v2',sign(self.alice,a1),allowed_paths=['app/price.py'])
        res1=self.ledger.promote_repair('r1',acceptance_cmd=['python','-V'])
        self.assertEqual(self.ledger.resolve_repair('r1',res1['head']),'RECORDED')
        # Cycle 2 (rollback): v2 -> invoice_v1
        c2={'project_id':'proj-1','dependency':'v2','contract':'invoice_v1','action':'change_dependency'}
        self.assertEqual(self.ledger.change_dependency('v2','invoice_v1',sign(self.owner,c2)),['feature'])
        a2={'project_id':'proj-1','assignment_id':'r2','deliverable_id':'feature',
            'worker_member':'bob','basis':'invoice_v1','allowed_paths':['app/price.py'],'action':'repair_assignment'}
        self.ledger.assign_repair('r2','feature','bob','invoice_v1',sign(self.alice,a2),allowed_paths=['app/price.py'])
        self.promotion.head='c'*40
        self.promotion.outcomes['r2']={'status':'PROMOTED','head':'c'*40}
        self.assertEqual(self.ledger.resolve_repair('r2','c'*40),'RECORDED')
        # Cycle 3: invoice_v1 -> v3
        c3={'project_id':'proj-1','dependency':'invoice_v1','contract':'v3','action':'change_dependency'}
        self.assertEqual(self.ledger.change_dependency('invoice_v1','v3',sign(self.owner,c3)),['feature'])
        a3={'project_id':'proj-1','assignment_id':'r3','deliverable_id':'feature',
            'worker_member':'bob','basis':'v3','allowed_paths':['app/price.py'],'action':'repair_assignment'}
        self.ledger.assign_repair('r3','feature','bob','v3',sign(self.alice,a3),allowed_paths=['app/price.py'])
        self.promotion.head='d'*40
        self.promotion.outcomes['r3']={'status':'PROMOTED','head':'d'*40}
        self.assertEqual(self.ledger.resolve_repair('r3','d'*40),'RECORDED')
        self.assertEqual(self.ledger.snapshot()['project'][-1],'ACTIVE')

if __name__=='__main__': unittest.main()
