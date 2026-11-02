"""OpenLine One 001: read-only project + Coach coordination preview.

No model/API calls, key handling, assignment issuance, repair execution, or
promotion. An observation is never trusted as owner authority. This is the
single local discovery and handoff entry, NOT the Track C acceptance gate.
"""
from __future__ import annotations
import argparse
from contextlib import closing
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import sys
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[2]
SOURCES = {
    'living': 'experiments/LIVING-PROJECTS-001/living_project.py',
    'coach': 'experiments/OPENLINE-COACH-001/coach.py',
    'mcp': 'experiments/OPENLINE-MCP-ENTRY-001/openline_mcp_entry/server.py',
    'isolated_worker': 'experiments/CODEX-B-ISOLATED-REPAIR-001/isolated_agent.py',
    'bridge': 'experiments/CODEX-B-ISOLATED-REPAIR-001/project_bridge.py',
}
REQUIRED = ('living', 'coach')
ASSIGNMENT = re.compile(r'^[a-zA-Z0-9_-]{1,90}$')

class WorkbenchRefused(RuntimeError):
    pass


def _module(name):
    rel = SOURCES[name]
    path = ROOT / rel
    if not path.is_file():
        raise WorkbenchRefused('missing_component:' + name)
    spec = importlib.util.spec_from_file_location('openline_one_' + name, path)
    if spec is None or spec.loader is None:
        raise WorkbenchRefused('module_unavailable:' + name)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def doctor() -> dict:
    components = {name: {'present': (ROOT / path).is_file(), 'path': path}
                  for name, path in SOURCES.items()}
    runtimes = {name: bool(shutil.which(name))
                for name in ('codex', 'claude', 'aider', 'opencode', 'hermes')}
    return {
        'schema': 'openline.one.readiness.v1',
        'components': components,
        'coding_model_cli_detected': runtimes,
        'gates': {
            'real_signed_mcp': 'SEPARATELY_TESTED_IN_PR_142',
            'actual_coding_agent_host': 'NOT_VERIFIED_BY_THIS_COMMAND',
            'isolated_real_model_repair': 'NOT_VERIFIED_BY_THIS_COMMAND',
            'founder_approved_model_spend': 'NOT_GRANTED_BY_THIS_COMMAND',
            'trusted_project_promotion': 'NOT_EXPOSED',
            'cross_resource_atomicity': 'NOT_IMPLEMENTED',
            'third_party_effect_truth': 'UNKNOWN',
            'cost_superiority': 'UNMEASURED',
        },
        'ready_to_claim_product_finish_line': False,
    }


def inspect(project_dir: Path, changed=()) -> dict:
    living = _module('living')
    try:
        obs = living.observe(project_dir / 'project.sqlite',
                             project_dir / 'accepted.git', changed=tuple(changed))
    except living.ObservationError as exc:
        raise WorkbenchRefused('project_observation_refused:' + str(exc)) from exc
    if obs['project']['head_consistent'] is not True:
        raise WorkbenchRefused('git_ledger_reconciliation_required')
    return obs


def _model_spec(model_type, obj):
    try:
        return model_type(**obj)
    except (TypeError, ValueError, ArithmeticError) as exc:
        raise WorkbenchRefused('invalid_catalog_model') from exc


def _trusted_catalog(file: Path) -> dict:
    if not file.is_file() or file.is_symlink():
        raise WorkbenchRefused('owner_catalog_file_required')
    if file.stat().st_mode & 0o022 or file.parent.stat().st_mode & 0o022:
        raise WorkbenchRefused('catalog_writable_by_others')
    if file.stat().st_size > 40000:
        raise WorkbenchRefused('catalog_too_large')
    try:
        catalog = json.loads(file.read_text(encoding='utf8'))
    except (OSError, ValueError) as exc:
        raise WorkbenchRefused('catalog_not_json') from exc
    if not isinstance(catalog, dict) or set(catalog) != {'schema', 'models', 'teacher', 'total_cap_micros', 'provider_caps_micros'}:
        raise WorkbenchRefused('catalog_schema_invalid')
    if catalog['schema'] != 'openline.one.operator-catalog.v1' or not isinstance(catalog['models'], list) or not catalog['models']:
        raise WorkbenchRefused('catalog_schema_invalid')
    caps = catalog['provider_caps_micros']
    total = catalog['total_cap_micros']
    if type(total) is not int or not (0 < total <= 20_000_000) or not isinstance(caps, dict) or not caps or any(
        type(v) is not int or v <= 0 or v > 10_000_000 for v in caps.values()
    ):
        raise WorkbenchRefused('operator_budget_invalid')
    return catalog


def _held(db_path: Path) -> dict:
    # Existing Coach accounting only. Never open the DB in write/create mode.
    if not db_path.exists():
        return {}
    if not db_path.is_file() or db_path.is_symlink():
        raise WorkbenchRefused('meter_database_unsafe')
    uri = 'file:' + quote(str(db_path.resolve()), safe='/') + '?mode=ro'
    try:
        with closing(sqlite3.connect(uri, uri=True)) as db:
            db.execute('PRAGMA query_only=ON')
            if db.execute("SELECT 1 FROM calls WHERE state='UNCERTAIN' LIMIT 1").fetchone():
                raise WorkbenchRefused('unreconciled_provider_charge_stop')
            rows = db.execute("SELECT provider, SUM(CASE WHEN state='METERED' THEN metered_micros ELSE reserved_micros END) FROM calls GROUP BY provider").fetchall()
    except sqlite3.Error as exc:
        raise WorkbenchRefused('meter_database_unreadable') from exc
    return dict(rows)


def prepare(project_dir: Path, catalog_path: Path, assignment_id: str, instruction: str,
            family: str, *, meter_path: Path | None = None) -> dict:
    if not ASSIGNMENT.fullmatch(assignment_id) or not (0 < len(instruction) <= 20000) or not (0 < len(family) <= 128):
        raise WorkbenchRefused('invalid_task')
    observation = inspect(project_dir)
    if observation['verdict'] not in ('REPAIR_ASSIGNMENTS_OBSERVED', 'SOME_REPAIR_ASSIGNMENTS_OBSERVED'):
        raise WorkbenchRefused('no_current_repair_assignment_observed')
    matches = [a for a in observation['repair_assignments'] if a['id'] == assignment_id]
    if len(matches) != 1:
        raise WorkbenchRefused('repair_assignment_not_found')
    assignment = matches[0]
    if assignment['state'] != 'ASSIGNED' or not assignment['worker_active'] or assignment['basis'] != observation['project']['contract']:
        raise WorkbenchRefused('repair_assignment_not_current')
    if not any(d['id'] == assignment['deliverable'] and d['standing'] == 'REOPEN' for d in observation['deliverables']):
        raise WorkbenchRefused('deliverable_not_reopened')
    # This is only a preview of candidate boundaries. Signed assignment must be
    # revalidated by ProjectLedger.promote_repair at effect entry.
    paths = assignment['allowed_paths']
    if not paths or len(set(paths)) != len(paths) or any(
        not isinstance(p, str) or not p.startswith('app/') or '\\' in p or
        p.startswith('/') or any(segment in ('', '.', '..') for segment in p.split('/'))
        for p in paths
    ):
        raise WorkbenchRefused('assignment_scope_invalid')
    cat = _trusted_catalog(catalog_path)
    coach = _module('coach')
    models = [_model_spec(coach.Model, m) for m in cat['models']]
    teacher = _model_spec(coach.Model, cat['teacher'])
    if any(m.provider not in cat['provider_caps_micros'] for m in [*models, teacher]):
        raise WorkbenchRefused('model_provider_not_authorized')
    held = _held(meter_path) if meter_path else {}
    total_held = sum(held.values())
    affordable = [m for m in models if m.quote_micros() <= cat['provider_caps_micros'][m.provider] - held.get(m.provider, 0)
                  and m.quote_micros() <= cat['total_cap_micros'] - total_held]
    if not affordable:
        raise WorkbenchRefused('budget_quote_exceeds_remaining_caps')
    candidate = min(affordable, key=lambda m: (m.quote_micros(), m.key))
    task = coach.Task(project_id=observation['project']['id'],
                      project_head=observation['project']['accepted_git_head'],
                      family=family, instruction=instruction,
                      contract_digest=sha256(observation['project']['contract'].encode()).hexdigest())
    result = {
        'schema': 'openline.one.repair-preflight.v1', 'assignment_id': assignment_id,
        'project_id': task.project_id, 'accepted_git_head': task.project_head,
        'task_basis_sha256': task.basis, 'contract_sha256': task.contract_digest,
        'deliverable': assignment['deliverable'], 'allowed_paths': paths,
        'student_suggested': candidate.key, 'student_max_quote_micro_usd': candidate.quote_micros(),
        'teacher': teacher.key, 'teacher_max_quote_micro_usd': teacher.quote_micros(),
        'budget_total_cap_micro_usd': cat['total_cap_micros'],
        'budget_provider_caps_micro_usd': cat['provider_caps_micros'],
        'metered_or_reserved_micro_usd': held,
        'catalog_prices': 'OPERATOR_SUPPLIED_ESTIMATES_NOT_PROVIDER_BILLING',
        'project_observation_sha256': observation['observation_sha256'],
        'action': 'PROPOSAL_PREVIEW_ONLY', 'authorized': False,
        'model_called': False, 'repair_executed': False,
        'next': 'Trusted receiver must recheck signatures, assignment, sandbox, current project basis and live provider balance before execution.',
    }
    result['packet_sha256'] = sha256(json.dumps(result, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return result


def main(argv=None):
    p = argparse.ArgumentParser(prog='openline-one', description='Private OpenLine integrated discovery and repair preflight; never executes repairs.')
    sub = p.add_subparsers(dest='command', required=True)
    sub.add_parser('doctor')
    status = sub.add_parser('status')
    status.add_argument('--project-dir', type=Path, required=True)
    status.add_argument('--changed', action='append', default=[])
    plan = sub.add_parser('plan')
    plan.add_argument('--project-dir', type=Path, required=True)
    plan.add_argument('--catalog', type=Path, required=True)
    plan.add_argument('--assignment', required=True)
    plan.add_argument('--instruction', required=True)
    plan.add_argument('--family', required=True)
    plan.add_argument('--meter', type=Path)
    args = p.parse_args(argv)
    try:
        if args.command == 'doctor':
            outcome = doctor()
        elif args.command == 'status':
            outcome = inspect(args.project_dir, changed=args.changed)
        else:
            outcome = prepare(args.project_dir, args.catalog, args.assignment, args.instruction, args.family, meter_path=args.meter)
    except WorkbenchRefused as exc:
        print(json.dumps({'status': 'REFUSED', 'reason': str(exc), 'authorization': 'NONE'}, sort_keys=True))
        return 2
    print(json.dumps(outcome, sort_keys=True, indent=2))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
