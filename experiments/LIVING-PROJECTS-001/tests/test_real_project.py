"""Compatibility test against the ACTUAL PR139 ProjectLedger source, not schema-only mock.

World admission is a labelled fake in this test. A separate PR138 scripted
integration exercised the pinned real World receiver on loopback.
"""
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parents[1] / 'SELF-HEALING-PROJECTS-001'))
from living_project import observe
from project import ProjectLedger, canonical, digest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def git(*argv, cwd=None):
    return subprocess.run(['git', *argv], cwd=cwd, capture_output=True, text=True, check=True).stdout.strip()


def pub(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


class ReadActualProjectLedger(unittest.TestCase):
    def test_owner_signed_change_appears_in_living_projection(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); bare=root/'accepted.git'; wd=root/'work'; db=root/'project.sqlite'
            git('init', '--bare', str(bare)); git('clone', str(bare), str(wd))
            git('config','user.name','Test',cwd=wd);git('config','user.email','test@local',cwd=wd)
            (wd/'app').mkdir();(wd/'app'/'a.py').write_text('a=1\n')
            git('add','.',cwd=wd);git('commit','-m','valid',cwd=wd)
            git('push','origin','HEAD:refs/heads/accepted',cwd=wd)
            head=git('--git-dir',str(bare),'rev-parse','refs/heads/accepted')

            class TrustedHead:
                def accepted(self):return head
            owner=Ed25519PrivateKey.generate();a=Ed25519PrivateKey.generate();b=Ed25519PrivateKey.generate()
            ledger=ProjectLedger(db,'proj','keep work correct',pub(owner),promotion=TrustedHead(),
                world_verifier=lambda receipt, invitation: receipt['decision']=='ALLOWED' and receipt['member']==invitation['member_id'])
            for member,key in [('alice',a),('bob',b)]:
                receipt={'decision':'ALLOWED','member':member}  # fake World admission for compatibility only
                invitation={'project_id':'proj','member_id':member,'owner_pub':pub(key),'worker_pub':pub(key),
                            'scope':'contribute','world_digest':digest(receipt)}
                self.assertEqual(ledger.join(invitation,owner.sign(canonical(invitation)).hex(),
                    key.sign(canonical(invitation)).hex(),world_receipt=receipt),'JOINED')
            for did,member,key,dep in [('invoice','alice',a,'spec_v1'),('docs','bob',b,'format_v1')]:
                claim={'project_id':'proj','deliverable_id':did,'member_id':member,'accepted_head':head,'dependencies':[dep]}
                ledger.accept(did,member,head,[dep],key.sign(canonical(claim)).hex())
            initial=observe(db,bare)
            self.assertEqual(initial['verdict'],'OBSERVED_CURRENT')
            claim={'project_id':'proj','dependency':'spec_v1','contract':'spec_v2','action':'change_dependency'}
            self.assertEqual(ledger.change_dependency('spec_v1','spec_v2',owner.sign(canonical(claim)).hex()),['invoice'])
            next_state=observe(db,bare)
            self.assertEqual(next_state['verdict'],'REPAIR_ASSIGNMENT_NEEDED')
            self.assertEqual([(x['id'],x['standing']) for x in next_state['deliverables']],
                             [('docs','CURRENT'),('invoice','REOPEN')])
            self.assertEqual(next_state['project']['accepted_git_head'],head)
            self.assertEqual(next_state['claim_limits']['effect_truth'],'UNKNOWN')

if __name__=='__main__':unittest.main()
