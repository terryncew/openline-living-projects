"""Regression on real ProjectLedger + SafePromotion, not synthetic SQL only."""
import json
import sqlite3
from contextlib import closing
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
PROTECT=ROOT.parent/'OPENLINE-PROTECT-001'
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(PROTECT.parent/'SELF-HEALING-PROJECTS-001'))
sys.path.insert(0,str(PROTECT.parent/'SELF-HEALING-ENGINE-001'))
sys.path.insert(0,str(PROTECT))
from continuity import audit, ContinuityRefused
import demo
from project import ProjectLedger
from foundation.promotion import SafePromotion
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

class ContinuityTests(unittest.TestCase):
    def test_valid_repair_rebinds_dependency_without_touching_other_contribution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'fixture'
            evidence=demo.execute(root)
            self.assertEqual(evidence['authorized_repair']['decision'],'ACCEPTED')
            got=audit(root/'project.sqlite')
            self.assertEqual(got['assessment'],'NO_RECORDED_STALE_DEPENDENCY_FOUND')
            self.assertEqual(got['flagged_current_deliverables'],0)
            rows={r['deliverable']:r for r in got['deliverables']}
            self.assertEqual(rows['invoice-feature']['ledger_standing'],'CURRENT')
            self.assertEqual(rows['invoice-feature']['dependency_keys'],['invoice_v2'])
            self.assertEqual(rows['invoice-feature']['unresolved_changes'],[])
            self.assertEqual(rows['independent-formatter']['assessment'],'CURRENT_NOT_FALSIFIED_BY_RECORDED_CHANGES')
            self.assertEqual(got['mutation_authority'],'NONE')

    def test_second_owner_signed_contract_change_reopens_repaired_feature(self):
        generate=Ed25519PrivateKey.generate
        saved=[]
        def recorder():
            k=generate();saved.append(k);return k
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'fixture'
            with patch.object(demo.Ed25519PrivateKey,'generate',side_effect=recorder):
                demo.execute(root)
            self.assertGreaterEqual(len(saved),3)
            promotion=SafePromotion(root/'accepted.git',root/'effects.sqlite',root/'promotion')
            project=ProjectLedger(root/'project.sqlite',promotion=promotion)
            claim={'project_id':project.id,'dependency':'invoice_v2','contract':'invoice_v3','action':'change_dependency'}
            affected=project.change_dependency('invoice_v2','invoice_v3',demo.signed(saved[0],claim))
            self.assertEqual(affected,['invoice-feature'])
            self.assertEqual(project.snapshot()['deliverables'][1][2],'REOPEN')
            self.assertEqual(audit(root/'project.sqlite')['flagged_current_deliverables'],0)

    def test_corrupt_owner_change_event_fails_closed_before_git_promotion(self):
        generate=Ed25519PrivateKey.generate
        keys=[]
        def record():
            key=generate();keys.append(key);return key
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'fixture'
            with patch.object(demo.Ed25519PrivateKey,'generate',side_effect=record):
                demo.execute(root)
            promotion=SafePromotion(root/'accepted.git',root/'effects.sqlite',root/'promotion')
            project=ProjectLedger(root/'project.sqlite',promotion=promotion)
            change={'project_id':project.id,'dependency':'invoice_v2',
                    'contract':'invoice_v3','action':'change_dependency'}
            self.assertEqual(project.change_dependency('invoice_v2','invoice_v3',
                                                       demo.signed(keys[0],change)),['invoice-feature'])
            assignment={'project_id':project.id,'assignment_id':'repair-v3',
                        'deliverable_id':'invoice-feature','worker_member':'bob',
                        'basis':'invoice_v3','allowed_paths':['app/price.py'],
                        'action':'repair_assignment'}
            project.assign_repair('repair-v3','invoice-feature','bob','invoice_v3',
                                  demo.signed(keys[1],assignment),allowed_paths=['app/price.py'])
            candidate=promotion.prepare('repair-v3')
            (Path(candidate['workspace'])/'app'/'price.py').write_text('def total(qty):\n    return qty * 12\n')
            before=promotion.accepted()
            with closing(sqlite3.connect(root/'project.sqlite')) as db:
                db.execute("UPDATE events SET payload=? WHERE kind='CONTRACT_CHANGED' AND seq=(SELECT MAX(seq) FROM events WHERE kind='CONTRACT_CHANGED')", ('{bad',))
                db.commit()
            from project import ProjectRefused
            with self.assertRaisesRegex(ProjectRefused,'dependency_change_evidence_corrupt'):
                project.promote_repair('repair-v3',acceptance_cmd=demo._validator(24))
            self.assertEqual(promotion.accepted(),before)

    def test_missing_source_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ContinuityRefused,'missing_or_unsafe'):
                audit(Path(tmp)/'absent.db')

    def test_obsolete_v1_change_does_not_reopen_rebound_v2_or_clear_reconsideration(self):
        generate=Ed25519PrivateKey.generate
        keys=[]
        def record():
            k=generate();keys.append(k);return k
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'fixture'
            with patch.object(demo.Ed25519PrivateKey,'generate',side_effect=record):
                demo.execute(root)
            promotion=SafePromotion(root/'accepted.git',root/'effects.sqlite',root/'promotion')
            project=ProjectLedger(root/'project.sqlite',promotion=promotion)
            # Obsolete invoice_v1 change after invoice-feature rebound to invoice_v2 must affect nothing.
            obsolete={'project_id':project.id,'dependency':'invoice_v1','contract':'invoice_v1_legacy','action':'change_dependency'}
            self.assertEqual(project.change_dependency('invoice_v1','invoice_v1_legacy',demo.signed(keys[0],obsolete)),[])
            # Now reopen independent-formatter via format_v1 -> format_v2, then test another obsolete change.
            reopen_fmt={'project_id':project.id,'dependency':'format_v1','contract':'format_v2','action':'change_dependency'}
            self.assertEqual(project.change_dependency('format_v1','format_v2',demo.signed(keys[0],reopen_fmt)),['independent-formatter'])
            self.assertEqual(project.snapshot()['project'][-1],'RECONSIDERATION')
            obsolete2={'project_id':project.id,'dependency':'invoice_v1','contract':'invoice_v1_legacy2','action':'change_dependency'}
            self.assertEqual(project.change_dependency('invoice_v1','invoice_v1_legacy2',demo.signed(keys[0],obsolete2)),[])
            # Project status must remain RECONSIDERATION because independent-formatter is still REOPEN.
            self.assertEqual(project.snapshot()['project'][-1],'RECONSIDERATION')
            self.assertEqual(audit(root/'project.sqlite')['assessment'],'NO_RECORDED_STALE_DEPENDENCY_FOUND')

    def test_cyclic_rollback_repair_and_tampered_dependency_detection(self):
        generate=Ed25519PrivateKey.generate
        keys=[]
        def record():
            k=generate();keys.append(k);return k
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'fixture'
            with patch.object(demo.Ed25519PrivateKey,'generate',side_effect=record):
                demo.execute(root)
            promotion=SafePromotion(root/'accepted.git',root/'effects.sqlite',root/'promotion')
            project=ProjectLedger(root/'project.sqlite',promotion=promotion)
            # Rollback invoice_v2 -> invoice_v1 and repair back to qty * 10
            rollback={'project_id':project.id,'dependency':'invoice_v2','contract':'invoice_v1','action':'change_dependency'}
            self.assertEqual(project.change_dependency('invoice_v2','invoice_v1',demo.signed(keys[0],rollback)),['invoice-feature'])
            assign={'project_id':project.id,'assignment_id':'repair-rollback-v1','deliverable_id':'invoice-feature',
                    'worker_member':'bob','basis':'invoice_v1','allowed_paths':['app/price.py'],'action':'repair_assignment'}
            project.assign_repair('repair-rollback-v1','invoice-feature','bob','invoice_v1',
                                  demo.signed(keys[1],assign),allowed_paths=['app/price.py'])
            cand=promotion.prepare('repair-rollback-v1')
            (Path(cand['workspace'])/'app'/'price.py').write_text('def total(qty):\n    return qty * 10\n')
            res=project.promote_repair('repair-rollback-v1',acceptance_cmd=demo._validator(20))
            self.assertEqual(res['status'],'PROMOTED')
            self.assertEqual(project.resolve_repair('repair-rollback-v1',res['head']),'RECORDED')
            got=audit(root/'project.sqlite')
            self.assertEqual(got['assessment'],'NO_RECORDED_STALE_DEPENDENCY_FOUND')
            self.assertEqual(got['flagged_current_deliverables'],0)
            # If dependencies table is tampered back to an unverified key, continuity audit flags it.
            with closing(sqlite3.connect(root/'project.sqlite')) as db:
                db.execute("UPDATE dependencies SET depends_on='invoice_v2' WHERE deliverable_id='invoice-feature'")
                db.commit()
            flagged=audit(root/'project.sqlite')
            self.assertEqual(flagged['assessment'],'CONTINUITY_UNPROVEN')
            self.assertEqual(flagged['flagged_current_deliverables'],1)

if __name__=='__main__':unittest.main()
