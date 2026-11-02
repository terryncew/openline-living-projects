"""Real local Git + signed ProjectLedger demonstrations (SCRIPTED agent attempts).

No model calls. World verifier is a marked local fixture, not a real World check.
The trusted acceptance subprocess runs fixture-only Python, NOT hostile code.
"""
from __future__ import annotations
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = Path(__file__).resolve().parent
EXPERIMENTS = HERE.parent
sys.path.insert(0, str(EXPERIMENTS / 'SELF-HEALING-ENGINE-001'))
sys.path.insert(0, str(EXPERIMENTS / 'SELF-HEALING-PROJECTS-001'))
from foundation.promotion import SafePromotion, cmd
from project import ProjectLedger, canonical, digest
from protect import Protect, verify_receipt


def public(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def signed(key, payload):
    return key.sign(canonical(payload)).hex()


def _validator(amount, needs_bob=True):
    # Trusted, fixture-only AST check. Model output is never executed.
    command = [sys.executable, '-B', str(HERE / 'fixture_validator.py'), '--expected', str(amount)]
    if needs_bob:
        command.append('--needs-bob')
    return command


def _propose(promoter, identity, changes, amount, *, needs_bob=True):
    state = promoter.prepare(identity)
    for file, text in changes.items():
        path = Path(state['workspace']) / file
        path.write_text(text)
    check = _validator(amount, needs_bob)
    return promoter.promote(identity, acceptance_cmd=check)


def execute(root: Path):
    root.mkdir(parents=True, exist_ok=True)
    accepted = root / 'accepted.git'
    cmd('git', 'init', '--bare', str(accepted))
    setup = root / 'bootstrap'
    cmd('git', 'clone', str(accepted), str(setup))
    (setup / 'app').mkdir()
    (setup / 'app' / 'price.py').write_text('def total(qty):\n    return 0\n')
    (setup / 'app' / 'independent.py').write_text('def label(value):\n    return value\n')
    cmd('git', '-C', str(setup), 'add', 'app')
    cmd('git', '-C', str(setup), '-c', 'user.name=Trusted Bootstrap',
        '-c', 'user.email=boot@local.test', 'commit', '-m', 'Initial accepted project')
    cmd('git', '-C', str(setup), 'push', 'origin', 'HEAD:refs/heads/accepted')
    live_db = root / 'effects.sqlite'
    with closing(sqlite3.connect(live_db)) as db:
        db.execute('CREATE TABLE effects(id TEXT PRIMARY KEY, value INTEGER)')
        db.commit()
    promo = SafePromotion(accepted, live_db, root / 'promotion')
    owner, alice, bob = (Ed25519PrivateKey.generate() for _ in range(3))
    project = ProjectLedger(root / 'project.sqlite', 'protect-demo', 'Keep accepted work safe',
                            public(owner), promotion=promo,
                            world_verifier=lambda receipt, invitation: receipt.get('member') == invitation.get('member_id'))
    for member, key in (('alice', alice), ('bob', bob)):
        receipt = {'member': member, 'environment': 'DEMO_ONLY_FAKE_WORLD'}
        invitation = {'project_id': project.id, 'member_id': member,
                      'owner_pub': public(key), 'worker_pub': public(key),
                      'scope': 'contribute', 'world_digest': digest(receipt)}
        joined = project.join(invitation, signed(owner, invitation), signed(key, invitation),
                              world_receipt=receipt)
        if joined != 'JOINED':
            raise AssertionError('fixture_join_failed')
    a = _propose(promo, 'alice-initial', {'app/price.py': 'def total(qty):\n    return qty * 10\n'}, 20,
                 needs_bob=False)
    if not (a['status'] == 'PROMOTED'):
        raise AssertionError('expected_a_promotion')
    claim = {'project_id': project.id, 'deliverable_id': 'invoice-feature', 'member_id': 'alice',
             'accepted_head': promo.accepted(), 'dependencies': ['invoice_v1']}
    project.accept('invoice-feature', 'alice', promo.accepted(), ['invoice_v1'], signed(alice, claim))
    b = _propose(promo, 'bob-initial',
                 {'app/independent.py': 'def label(value):\n    return value.upper()\n'}, 20)
    if not (b['status'] == 'PROMOTED'):
        raise AssertionError('expected_b_promotion')
    claim = {'project_id': project.id, 'deliverable_id': 'independent-formatter', 'member_id': 'bob',
             'accepted_head': promo.accepted(), 'dependencies': ['format_v1']}
    project.accept('independent-formatter', 'bob', promo.accepted(), ['format_v1'], signed(bob, claim))
    independent = cmd('git', '--git-dir', str(accepted), 'show', 'refs/heads/accepted:app/independent.py').stdout
    change = {'project_id': project.id, 'dependency': 'invoice_v1',
              'contract': 'invoice_v2', 'action': 'change_dependency'}
    affected = project.change_dependency('invoice_v1', 'invoice_v2', signed(owner, change))
    if affected != ['invoice-feature']:
        raise AssertionError('dependency_change_not_selective')
    protect = Protect(project, Ed25519PrivateKey.generate(), root / 'incidents',
                      acceptance_cmd=tuple(_validator(22)))

    def assign(task):
        claim = {'project_id': project.id, 'assignment_id': task,
                 'deliverable_id': 'invoice-feature', 'worker_member': 'bob',
                 'basis': 'invoice_v2', 'allowed_paths': ['app/price.py'],
                 'action': 'repair_assignment'}
        project.assign_repair(task, 'invoice-feature', 'bob', 'invoice_v2',
                              signed(alice, claim), allowed_paths=['app/price.py'])

    # Actual unauthorized local Git candidate, not fictional alert text.
    assign('rogue-attempt')
    rogue = promo.prepare('rogue-attempt')
    Path(rogue['workspace'], 'app', 'independent.py').write_text(
        'def label(value):\n    return value.upper() + "!"\n')
    original_head = promo.accepted()
    stopped = protect.intercept('rogue-attempt')
    if not (stopped['verdict'] == 'STOPPED'):
        raise AssertionError('protect_invariant_failed')
    if not (promo.accepted() == original_head):
        raise AssertionError('protect_invariant_failed')
    if cmd('git', '--git-dir', str(accepted), 'show',
           'refs/heads/accepted:app/independent.py').stdout != independent:
        raise AssertionError('independent_contribution_modified')
    if not ('repair_outside_allowed_source' in stopped['receipt']['payload']['reason']):
        raise AssertionError('protect_invariant_failed')

    # A correct patch with NO owner-signed assignment must also be refused.
    unassigned = promo.prepare('unassigned-attempt')
    Path(unassigned['workspace'], 'app', 'price.py').write_text('def total(qty):\n    return qty * 11\n')
    unassigned_stop = protect.intercept('unassigned-attempt')
    if unassigned_stop['verdict'] != 'STOPPED' or promo.accepted() != original_head:
        raise AssertionError('unassigned_candidate_crossed_receiver_boundary')
    if unassigned_stop['receipt']['payload']['reason'] != 'repair_assignment_missing':
        raise AssertionError('wrong_unassigned_refusal')

    # Legitimate, scope-matched repair through same receiver gate.
    assign('authorized-repair')
    legitimate = promo.prepare('authorized-repair')
    Path(legitimate['workspace'], 'app', 'price.py').write_text('def total(qty):\n    return qty * 11\n')
    allowed = protect.intercept('authorized-repair')
    if not (allowed['verdict'] == 'ACCEPTED'):
        raise AssertionError('protect_invariant_failed')
    if not (promo.accepted() != original_head):
        raise AssertionError('protect_invariant_failed')
    if cmd('git', '--git-dir', str(accepted), 'show',
           'refs/heads/accepted:app/independent.py').stdout != independent:
        raise AssertionError('independent_contribution_modified')
    if not (project.snapshot()['project'][-1] == 'ACTIVE'):
        raise AssertionError('protect_invariant_failed')
    if {x[0]: x[2] for x in project.snapshot()['deliverables']} != {
        'independent-formatter': 'CURRENT', 'invoice-feature': 'CURRENT'}:
        raise AssertionError('deliverable_standing_not_current')
    verify_stop = verify_receipt(stopped['receipt'], protect.receiver_public_hex)
    verify_allow = verify_receipt(allowed['receipt'], protect.receiver_public_hex)
    (root / 'PINNED_RECEIVER_PUBLIC_KEY.hex').write_text(protect.receiver_public_hex + '\n')
    verify_unassigned = verify_receipt(unassigned_stop['receipt'], protect.receiver_public_hex)
    result = {'schema':'openline.protect.demo.v1',
              'verdict':'SCRIPTED_REAL_GIT_BOUNDARY_PASS',
              'unauthorized_attempt': {
                  'decision': stopped['verdict'], 'reason': stopped['receipt']['payload']['reason'],
                  'accepted_ref_unchanged': True, 'receipt_verified': verify_stop['crypto'],
                  'receipt_file': str(Path(stopped['path']).name)},
              'unassigned_correct_patch': {'decision': unassigned_stop['verdict'],
                                           'reason': unassigned_stop['receipt']['payload']['reason'],
                                           'receipt_verified': verify_unassigned['crypto']},
              'authorized_repair': {
                  'decision': allowed['verdict'], 'accepted_head': promo.accepted(),
                  'receipt_verified': verify_allow['crypto']},
              'independent_contribution_preserved': True,
              'two_independent_contributor_signatures': True,
              'worker_model': 'SCRIPTED_NOT_LLM',
              'worker_os_isolation': 'NOT_TESTED_HERE',
              'world_membership': 'STUB_DEMO_ONLY',
              'trusted_fixture_validator': 'STATIC_AST_NO_CANDIDATE_CODE_EXECUTION',
              'production_acceptance_runner': 'ISOLATED_GENERAL_ORACLE_NOT_TESTED',
              'dependencies_after_repair': 'OLD_DEPENDENCY_UNTIL_OWNER_AUTHORIZED_REBIND',
              'external_effect_truth': 'UNKNOWN',
              'release': 'HOLD'}
    (root / 'result.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return result


def main():
    import argparse
    cli = argparse.ArgumentParser(description='OpenLine Protect 001 real local Git gate demonstration')
    cli.add_argument('--output-dir', type=Path, help='Preserve private results and signed incident receipts')
    args = cli.parse_args()
    if args.output_dir:
        if args.output_dir.exists() and any(args.output_dir.iterdir()):
            raise SystemExit('output dir must be empty')
        data = execute(args.output_dir)
    else:
        with tempfile.TemporaryDirectory(prefix='openline-protect-') as d:
            data = execute(Path(d))
    print(json.dumps(data, indent=2, sort_keys=True))

if __name__ == '__main__':
    main()
