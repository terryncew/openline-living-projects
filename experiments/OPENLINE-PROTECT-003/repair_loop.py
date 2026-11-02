"""Protect 003: TWO disturbances, two real local Git promotions, no model.

A genuine model/official host is deliberately NOT claimed. Owner/contributor
keys are transient fixture-only. Existing ProjectLedger and Protect enforce
refusal, authorization and reconciliation; this module adds no new gate.
"""
from __future__ import annotations
from contextlib import closing
from pathlib import Path
import hashlib
import json
import sqlite3
import sys
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent
EXP = HERE.parent
sys.path[:0] = [str(EXP/rel) for rel in ('OPENLINE-PROTECT-001', 'OPENLINE-PROTECT-002', 'SELF-HEALING-PROJECTS-001', 'SELF-HEALING-ENGINE-001')]
import demo
from foundation.promotion import SafePromotion, cmd
from project import ProjectLedger
from protect import Protect, verify_receipt
from continuity import audit


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise AssertionError(reason)


def head_file(repo: Path, file: str) -> bytes:
    return cmd('git', '--git-dir', str(repo), 'show', 'refs/heads/accepted:' + file).stdout.encode('utf8')


def assignment(project: ProjectLedger, alice, name: str, basis: str) -> None:
    obj = {'project_id': project.id, 'assignment_id': name, 'deliverable_id': 'invoice-feature',
           'worker_member': 'bob', 'basis': basis, 'allowed_paths': ['app/price.py'],
           'action': 'repair_assignment'}
    project.assign_repair(name, 'invoice-feature', 'bob', basis, demo.signed(alice, obj),
                          allowed_paths=['app/price.py'])


def execute(root: Path) -> dict:
    if root.exists() and any(root.iterdir()):
        raise ValueError('output_directory_not_empty')
    root.mkdir(parents=True, exist_ok=True)
    created = []
    create_key = Ed25519PrivateKey.generate
    def record_key():
        key = create_key()
        created.append(key)
        return key
    # Capture the three ephemeral fixture owners from the original demo.
    # The first demo already makes a v1->v2 change, refuses an out-of-scope
    # edit, and verifies a genuinely accepted in-scope repair.
    with patch.object(demo.Ed25519PrivateKey, 'generate', side_effect=record_key):
        first = demo.execute(root)
    require(len(created) >= 3, 'fixture_owner_keys_missing')
    founder, alice = created[:2]
    require(first['verdict'] == 'SCRIPTED_REAL_GIT_BOUNDARY_PASS', 'first_cycle_not_verified')
    require(first['unauthorized_attempt']['decision'] == 'STOPPED', 'first_rogue_not_refused')
    require(first['authorized_repair']['decision'] == 'ACCEPTED', 'first_repair_not_accepted')

    accepted = root/'accepted.git'
    promotion = SafePromotion(accepted, root/'effects.sqlite', root/'promotion')
    project = ProjectLedger(root/'project.sqlite', promotion=promotion)
    before = promotion.accepted()
    bob_before = head_file(accepted,'app/independent.py')
    first_consistent = audit(root/'project.sqlite')
    require(first_consistent['assessment'] == 'NO_RECORDED_STALE_DEPENDENCY_FOUND', 'first_continuity_not_verified')
    require({x['deliverable']:x['dependency_keys'] for x in first_consistent['deliverables']}['invoice-feature'] == ['invoice_v2'], 'first_rebind_missing')
    claim = {'project_id':project.id,'dependency':'invoice_v2','contract':'invoice_v3','action':'change_dependency'}
    affected = project.change_dependency('invoice_v2','invoice_v3',demo.signed(founder,claim))
    require(affected == ['invoice-feature'], 'second_change_not_selective')
    names = {r[0]:r[2] for r in project.snapshot()['deliverables']}
    require(names == {'independent-formatter':'CURRENT','invoice-feature':'REOPEN'}, 'second_change_wrong_standing')

    protect = Protect(project,Ed25519PrivateKey.generate(),root/'second_incidents',
                      acceptance_cmd=tuple(demo._validator(24)))
    # Explicitly wrong file, even though signed assignment is restricted to price.py.
    assignment(project,alice,'second-rogue','invoice_v3')
    r = promotion.prepare('second-rogue')
    Path(r['workspace'],'app','independent.py').write_text('def label(value):\n    return value.lower()\n')
    bad = protect.intercept('second-rogue')
    require(bad['verdict']=='STOPPED','second_rogue_not_stopped')
    require(promotion.accepted()==before,'second_rogue_modified_accepted_head')
    require(head_file(accepted,'app/independent.py')==bob_before,'second_rogue_modified_bob')

    # New *correct* work after the second disturbance (qty*12 for v3).
    assignment(project,alice,'second-authorized','invoice_v3')
    p = promotion.prepare('second-authorized')
    Path(p['workspace'],'app','price.py').write_text('def total(qty):\n    return qty * 12\n')
    accepted_result = protect.intercept('second-authorized')
    require(accepted_result['verdict']=='ACCEPTED','second_authorized_not_accepted')
    after = promotion.accepted()
    require(after != before,'no_new_verified_accepted_work')
    require(head_file(accepted,'app/independent.py')==bob_before,'unrelated_accepted_work_lost')
    require(b'return qty * 12' in head_file(accepted,'app/price.py'), 'wrong_repair_accepted')
    require(verify_receipt(bad['receipt'],protect.receiver_public_hex)['crypto']=='VERIFIED','stop_receipt_invalid')
    require(verify_receipt(accepted_result['receipt'],protect.receiver_public_hex)['crypto']=='VERIFIED','accept_receipt_invalid')
    current = audit(root/'project.sqlite')
    require(current['assessment']=='NO_RECORDED_STALE_DEPENDENCY_FOUND','second_continuity_audit_failed')
    require({x['deliverable']:x['dependency_keys'] for x in current['deliverables']}['invoice-feature']==['invoice_v3'], 'second_rebind_missing')
    fresh = ProjectLedger(root/'project.sqlite',promotion=promotion).snapshot()
    require(fresh['project'][-1]=='ACTIVE','project_not_active_after_restart')
    require({x[0]:x[2] for x in fresh['deliverables']}=={'invoice-feature':'CURRENT','independent-formatter':'CURRENT'}, 'not_current_after_restart')
    # A refusal does not certify absence of effects outside receiver.
    receipts=[bad['receipt'],accepted_result['receipt']]
    require(all(x['payload']['external_effect_truth']=='UNKNOWN' for x in receipts),'external_effect_overclaimed')
    record={
      'schema':'openline.protect.disruption-loop.v1','verdict':'TWO_SCRIPTED_DISRUPTIONS_LOCAL_GIT_PASS',
      'agent_type':'SCRIPTED_NOT_REAL_MODEL','official_coding_host':'NOT_AVAILABLE_OR_TESTED',
      'first_cycle':{'ref':before,'unauthorized':first['unauthorized_attempt']['decision'],
                     'authorized':first['authorized_repair']['decision'],'contract':'invoice_v2'},
      'second_cycle':{'pre':before,'post':after,'affected':affected,
                      'unauthorized':bad['verdict'],'unauthorized_reason':bad['receipt']['payload']['reason'],
                      'authorized':accepted_result['verdict'],'contract':'invoice_v3'},
      'unrelated_accepted_work':{'preserved':True,'sha256':hashlib.sha256(bob_before).hexdigest()},
      'fresh_instance_deliverables':{r[0]:r[2] for r in fresh['deliverables']},
      'verified_new_work_after_disruption':True,
      'verified_recoveries':2,
      'selective_reopens':2,
      'signed_incident_receipts_new_cycle':2,
      'external_effect_truth':'UNKNOWN','fair_conventional_comparison':'NOT_RUN',
      'owner_signed_reauthorization':'EXISTING_PROJECT_LEDGER',
      'model_calls':0,'model_spend_usd':0,
      'advantage_vs_conventional':'NOT_MEASURED','emergence':'NOT_ESTABLISHED',
      'release':'HOLD'}
    (root/'disruption-loop.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
    return record


def main() -> int:
    import argparse
    import tempfile
    p=argparse.ArgumentParser(description='Private two-disruption Protect evidence (scripted, never real model)')
    p.add_argument('--output-dir',type=Path)
    args=p.parse_args()
    if args.output_dir:
        obj=execute(args.output_dir)
    else:
        with tempfile.TemporaryDirectory(prefix='openline-loop-') as tmp:
            obj=execute(Path(tmp))
    print(json.dumps(obj,sort_keys=True,indent=2))
    return 0
if __name__=='__main__':raise SystemExit(main())
