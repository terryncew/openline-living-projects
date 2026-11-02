"""OpenLine Living Projects 001 — read-only view of existing ProjectLedger data.

A project *observation*, not authorization, signed evidence, comprehensive impact
analysis, a runnable repair agent, or proof of work correctness. No project writes.
"""
from __future__ import annotations
import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
from urllib.parse import quote

SCHEMA = 'openline.living-project.observation.v1'
REQUIRED = {
    'projects': {'id', 'objective', 'contract', 'last_accepted', 'status'},
    'members': {'project_id', 'member_id', 'active'},
    'deliverables': {'id', 'project_id', 'member_id', 'accepted_head', 'standing'},
    'dependencies': {'deliverable_id', 'depends_on'},
    'assignments': {'id', 'deliverable_id', 'worker_member', 'basis', 'allowed_paths', 'state', 'promoted_head'},
    'events': {'seq', 'kind', 'payload'},
}

class ObservationError(RuntimeError):
    pass


def _git_head(git_dir: Path) -> str:
    env = { 'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
            'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
            'GIT_NO_REPLACE_OBJECTS': '1', 'HOME': '/nonexistent'}
    def run(*args):
        try:
            r = subprocess.run(['git', '--git-dir', str(git_dir), *args], env=env,
                               capture_output=True, text=True, timeout=7, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ObservationError('git_head_unavailable') from exc
        if r.returncode:
            raise ObservationError('git_head_unavailable')
        return r.stdout.strip()
    if run('rev-parse', '--is-bare-repository') != 'true':
        raise ObservationError('bare_git_repository_required')
    head = run('rev-parse', '--verify', 'refs/heads/accepted^{commit}')
    if len(head) != 40 or any(c not in '0123456789abcdef' for c in head):
        raise ObservationError('invalid_accepted_git_head')
    return head


def _db_snapshot(db_path: Path):
    if not db_path.is_file():
        raise ObservationError('project_database_missing')
    uri = 'file:' + quote(str(db_path.resolve()), safe='/') + '?mode=ro'
    try:
        with closing(sqlite3.connect(uri, uri=True, timeout=3)) as db:
            db.execute('PRAGMA query_only=ON')
            db.execute('BEGIN')
            for table, columns in REQUIRED.items():
                present = {r[1] for r in db.execute(f'PRAGMA table_info({table})')}
                if not columns <= present:
                    raise ObservationError('project_schema_mismatch:' + table)
            projects = db.execute('SELECT id,objective,contract,last_accepted,status FROM projects').fetchall()
            if len(projects) != 1:
                raise ObservationError('one_project_required')
            project = dict(zip(('id','objective','contract','last_accepted','status'), projects[0]))
            deliveries = db.execute('SELECT id,member_id,standing,accepted_head FROM deliverables ORDER BY id').fetchall()
            members = db.execute('SELECT member_id,active FROM members WHERE project_id=? ORDER BY member_id', (project['id'],)).fetchall()
            deps = db.execute('SELECT deliverable_id,depends_on FROM dependencies ORDER BY deliverable_id,depends_on').fetchall()
            assignments = db.execute('SELECT id,deliverable_id,worker_member,basis,allowed_paths,state,promoted_head FROM assignments ORDER BY id').fetchall()
            events = db.execute('SELECT seq,kind,payload FROM events ORDER BY seq DESC LIMIT 6').fetchall()
            db.commit()
    except sqlite3.Error as exc:
        raise ObservationError('project_db_unreadable') from exc
    return project, deliveries, members, deps, assignments, events


def observe(db_path: Path, git_dir: Path, *, changed: tuple[str, ...] = ()) -> dict:
    """Conservative, non-authorizing observation of real project SQLite + accepted Git.

    Reads Git head before & after SQLite snapshot. A concurrent mutation without
    observable ref change is NOT excluded; DB/Git are not atomically linked.
    """
    if len(changed) > 100 or any(not isinstance(x, str) or not x or len(x) > 256 for x in changed):
        raise ObservationError('invalid_changed_dependency')
    before = _git_head(git_dir)
    project, deliverables, members, deps, assignments, events = _db_snapshot(db_path)
    after = _git_head(git_dir)
    if before != after:
        raise ObservationError('accepted_ref_changed_while_reading')
    active = {m for m, state in members if state == 1}
    known_members = {m for m, _ in members}
    dependency_map = {}
    for deliverable, dependency in deps:
        dependency_map.setdefault(deliverable, []).append(dependency)
    jobs = []
    for ident, member, standing, head in deliverables:
        if member not in known_members:
            raise ObservationError('orphan_deliverable_member')
        if standing not in ('CURRENT', 'REOPEN'):
            raise ObservationError('unknown_deliverable_standing')
        jobs.append({'id': ident, 'contributor': member, 'standing': standing,
                     'accepted_at': head, 'dependencies': dependency_map.get(ident, []),
                     'what_if_changed': sorted(set(dependency_map.get(ident, ())) & set(changed))})
    tasks = []
    for ident, deliverable, worker, basis, raw_paths, state, promoted in assignments:
        if state not in ('ASSIGNED', 'COMMITTED'):
            raise ObservationError('unknown_assignment_state')
        try:
            paths = json.loads(raw_paths)
        except (TypeError, ValueError) as exc:
            raise ObservationError('invalid_assignment_scope') from exc
        if not isinstance(paths, list) or not all(isinstance(x, str) for x in paths):
            raise ObservationError('invalid_assignment_scope')
        tasks.append({'id': ident, 'deliverable': deliverable,
                      'worker': worker, 'state': state, 'basis': basis,
                      'allowed_paths': paths, 'worker_active': worker in active,
                      'promoted_head': promoted})
    latest = []
    for seq, kind, payload in events:
        try:
            # Events are DB-owned history; payload is NOT an external signature.
            obj = json.loads(payload)
        except (ValueError, TypeError) as exc:
            raise ObservationError('event_json_invalid') from exc
        latest.append({'seq': seq, 'kind': kind, 'payload': obj})
    mismatched = project['last_accepted'] != after
    opened = [j for j in jobs if j['standing'] == 'REOPEN']
    valid_bases_by_deliv = {j['id']: {project['contract']} for j in opened}
    for ev in latest:
        if ev.get('kind') == 'CONTRACT_CHANGED' and isinstance(ev.get('payload'), dict):
            c_val = ev['payload'].get('contract')
            for aff in ev['payload'].get('affected', ()):
                if aff in valid_bases_by_deliv and isinstance(c_val, str):
                    valid_bases_by_deliv[aff].add(c_val)
    available = [t for t in tasks if t['state'] == 'ASSIGNED' and t['worker_active']
                 and any(j['id'] == t['deliverable'] and t['basis'] in valid_bases_by_deliv.get(j['id'], {project['contract']}) for j in opened)]
    predicted = [j['id'] for j in jobs if j['what_if_changed']]
    if mismatched:
        verdict, next_step = 'RECONCILIATION_REQUIRED', 'Trusted receiver must reconcile Git promotion journal and project SQLite; do not infer successful repair.'
    elif opened and len({t['deliverable'] for t in available}) == len(opened):
        verdict, next_step = 'REPAIR_ASSIGNMENTS_OBSERVED', 'Recorded assignments cover reopened work. Receiver MUST independently verify each signed assignment, current authority and isolation before attempting repair; this observation grants no permission.'
    elif opened and available:
        verdict, next_step = 'SOME_REPAIR_ASSIGNMENTS_OBSERVED', 'Some reopened work has recorded assignments; receiver must verify those and obtain owner-signed scope for the rest. No authority granted.'
    elif opened:
        verdict, next_step = 'REPAIR_ASSIGNMENT_NEEDED', 'Obtain current owner-signed repair scope before any proposal or promotion.'
    elif project['status'] != 'ACTIVE':
        verdict, next_step = 'PROJECT_STATE_UNRESOLVED', 'Trusted receiver must resolve the non-active project status.'
    else:
        verdict, next_step = 'OBSERVED_CURRENT', 'No declared work is reopened in this snapshot; correctness and complete dependency capture are not proved.'
    result = {'schema': SCHEMA, 'project': {'id': project['id'], 'objective': project['objective'],
              'contract': project['contract'], 'status': project['status'], 'accepted_git_head': after,
              'ledger_last_accepted': project['last_accepted'], 'head_consistent': not mismatched},
              'verdict': verdict, 'next_step': next_step,
              'members': {'total': len(members), 'active': len(active)},
              'deliverables': jobs, 'repair_assignments': tasks,
              'hypothetical_change': {'declared_roots': sorted(set(changed)),
                  'affected_declared_deliverables': predicted,
                  'unlisted_dependencies': 'UNKNOWN'},
              'recent_events': latest,
              'claim_limits': {'authorization': 'NONE', 'agent_execution': 'NONE',
                  'effect_truth': 'UNKNOWN', 'source_signatures_verified': False,
                  'cross_resource_atomicity': False, 'dependency_completeness': 'NOT_ESTABLISHED',
                  'total_cost_savings': 'NOT_MEASURED'},
              'source': {'project': 'operator-local ProjectLedger SQLite snapshot',
                         'accepted_ref': 'operator-local refs/heads/accepted',
                         'not_offline_proof': True}}
    # SHA256 makes this portable packet tamper-evident only against a separately
    # trusted digest; it is NOT a signature and does not grant authority.
    raw = json.dumps(result, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    result['observation_sha256'] = hashlib.sha256(raw).hexdigest()
    return result


def report(observation: dict) -> str:
    p = observation['project']
    lines = [f"OPENLINE LIVING PROJECT — {p['id']}",
             f"Objective: {p['objective']}",
             f"Contract: {p['contract']}",
             f"Status: {observation['verdict']}",
             f"Members: {observation['members']['active']} active / {observation['members']['total']}",
             f"Accepted Git: {p['accepted_git_head'][:12]}", '', 'WORK:']
    for d in observation['deliverables']:
        lines.append(f"  {d['standing']:7} {d['id']} (owner: {d['contributor']})")
    if not observation['deliverables']:
        lines.append('  No accepted deliverables recorded')
    lines.extend(['', 'NEXT:', observation['next_step'], '',
                  'BOUNDARY: Read-only observation. No signed authority, autonomous repair,',
                  'complete dependency discovery, external effect truth, or measured savings.'])
    return '\n'.join(lines) + '\n'


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog='openline-living', description='Inspect existing OpenLine Self-Healing Projects state without modifying it.')
    parser.add_argument('--project-dir', type=Path, help='operator-owned project directory containing project.sqlite and accepted.git')
    parser.add_argument('--db', type=Path, help='existing ProjectLedger SQLite database')
    parser.add_argument('--accepted-git', type=Path, help='existing bare Git repository with accepted ref')
    parser.add_argument('--changed', action='append', default=[], help='hypothetical dependency key; does not mutate state')
    parser.add_argument('--json', action='store_true', help='emit portable unsigned observation JSON')
    args = parser.parse_args(argv)
    if args.project_dir is not None and (args.db is not None or args.accepted_git is not None):
        parser.error('--project-dir cannot be combined with --db or --accepted-git')
    if args.project_dir is None and (args.db is None or args.accepted_git is None):
        parser.error('provide --project-dir or both --db and --accepted-git')
    db_path = args.project_dir / 'project.sqlite' if args.project_dir else args.db
    git_dir = args.project_dir / 'accepted.git' if args.project_dir else args.accepted_git
    try:
        value = observe(db_path, git_dir, changed=tuple(args.changed))
    except ObservationError as exc:
        print(json.dumps({'status': 'REFUSED', 'reason': str(exc), 'authorization': 'NONE'}, sort_keys=True))
        return 2
    print(json.dumps(value, indent=2, sort_keys=True) if args.json else report(value), end='\n' if args.json else '')
    return 0 if value['verdict'] not in ('RECONCILIATION_REQUIRED', 'PROJECT_STATE_UNRESOLVED') else 1

if __name__ == '__main__':
    raise SystemExit(main())
