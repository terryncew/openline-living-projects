"""Conditional local Git promotion with independently checked SQLite state.

Research boundary: trusted local code; candidate and verifier run with current OS
permissions. A Git worktree is NOT a security sandbox. No execution of arbitrary
untrusted model output is authorized by this implementation.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import time
import uuid

class PromotionRefused(RuntimeError):
    pass


def cmd(*args: str, cwd: Path | None = None, timeout: float = 60, check: bool = True) -> subprocess.CompletedProcess:
    p = subprocess.run([str(x) for x in args], cwd=cwd, text=True, capture_output=True, timeout=timeout,
                       env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"})
    if check and p.returncode:
        raise PromotionRefused(f"command exit={p.returncode}: {args[:3]}: {p.stderr[:450]}")
    return p


def atomically_write(path: Path, body: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    f = path.with_suffix('.tmp')
    with open(f, 'w', encoding='utf-8') as out:
        json.dump(body, out, sort_keys=True, indent=2)
        out.flush()
        os.fsync(out.fileno())
    os.replace(f, path)
    fd = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def snapshot(db_path: Path, output: Path) -> None:
    with contextlib.closing(sqlite3.connect(db_path)) as source, contextlib.closing(sqlite3.connect(output)) as target:
        source.backup(target)


def db_hash(db: sqlite3.Connection) -> str:
    """Stable logical DB fingerprint; check all user table schema and data."""
    rows = db.execute("SELECT name, type, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
    payload = [rows]
    for name, kind, _ in rows:
        if kind != 'table':
            continue
        quoted = '"' + name.replace('"', '""') + '"'
        recs = [tuple(repr(v) for v in row) for row in db.execute(f'SELECT * FROM {quoted}')]
        payload.append([name, sorted(recs)])
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


class SafePromotion:
    """Accepted ref is never checked out. Promotes source only; DB stays in place."""
    def __init__(self, bare_repo: Path, live_db: Path, state_dir: Path, *, ref: str = 'refs/heads/accepted', require_final_gate: bool = False, git_runner=None, validation_runner=None):
        self.repo, self.live_db, self.state_dir, self.ref = Path(bare_repo), Path(live_db), Path(state_dir), ref
        # Integrated receivers require owner/STOP ordering at the final Git CAS.
        self.require_final_gate = bool(require_final_gate)
        self.git_runner = git_runner
        self.validation_runner = validation_runner
        self._bound_project = None
        if not self.repo.exists() or not self.live_db.exists():
            raise ValueError('existing bare Git repository and SQLite DB are required')
        if cmd('git', '--git-dir', str(self.repo), 'rev-parse', '--is-bare-repository').stdout.strip() != 'true':
            raise ValueError('requires bare Git repository; no hidden working-tree mutation')
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def _candidate_project_dbs(self) -> list[Path]:
        candidates: list[Path] = []
        if self._bound_project is not None and getattr(self._bound_project, 'db_path', None):
            candidates.append(Path(self._bound_project.db_path))
        for base in (self.repo.parent, self.live_db.parent, self.state_dir.parent):
            pdb = base / 'project.sqlite'
            if pdb not in candidates:
                candidates.append(pdb)
            cfg_file = base / 'config.json'
            if cfg_file.is_file() and not cfg_file.is_symlink():
                try:
                    cfg_data = json.loads(cfg_file.read_text(encoding='utf-8'))
                    if isinstance(cfg_data, dict) and cfg_data.get('project_db'):
                        cp = Path(cfg_data['project_db'])
                        if cp not in candidates:
                            candidates.append(cp)
                except Exception:
                    pass
        return [p for p in candidates if p.is_file() and not p.is_symlink()]

    def _check_final_gate_required(self, task_id: str | None = None) -> tuple[bool, bool]:
        entry_req = bool(self.require_final_gate)
        cas_req = bool(self.require_final_gate)
        for base in (self.repo.parent, self.live_db.parent, self.state_dir.parent):
            if (base / 'config.json').is_file() or (base / 'PINNED_RECEIVER_PUBLIC_KEY.hex').is_file():
                entry_req = True
                cas_req = True
        for pdb in self._candidate_project_dbs():
            try:
                with contextlib.closing(sqlite3.connect(str(pdb), timeout=5)) as db:
                    tbls = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
                    if not {'projects', 'deliverables', 'assignments', 'events'}.issubset(tbls):
                        continue
                    if 'stop_state' in tbls:
                        s_rows = db.execute('SELECT stopped, stop_seq, clear_seq FROM stop_state').fetchall()
                        if len(s_rows) != 1 or s_rows[0][0] != 0 or s_rows[0][1] > 0 or s_rows[0][2] > 0:
                            entry_req = True
                            cas_req = True
                    if task_id is not None:
                        if db.execute('SELECT 1 FROM assignments WHERE id=?', (str(task_id),)).fetchone():
                            entry_req = True
                            cas_req = True
                    p_row = db.execute('SELECT status FROM projects LIMIT 1').fetchone()
                    if p_row and p_row[0] != 'ACTIVE':
                        cas_req = True
                    if db.execute("SELECT 1 FROM deliverables WHERE standing='REOPEN' LIMIT 1").fetchone():
                        cas_req = True
                    if db.execute('SELECT 1 FROM assignments LIMIT 1').fetchone():
                        cas_req = True
                    if db.execute(
                        "SELECT 1 FROM events WHERE kind IN ('KILL_SWITCH_STOPPED','KILL_SWITCH_CLEARED','MEMBER_REVOKED') LIMIT 1"
                    ).fetchone():
                        entry_req = True
                        cas_req = True
                    if db.execute(
                        "SELECT 1 FROM events WHERE kind IN ('CONTRACT_CHANGED','REPAIR_ASSIGNED') LIMIT 1"
                    ).fetchone():
                        cas_req = True
            except Exception:
                entry_req = True
                cas_req = True
        return entry_req, cas_req

    def _verify_active_final_gate_reservation(self, final_gate_context, task_id: str, target_head: str, expected_head: str) -> bool:
        ledger = getattr(final_gate_context, '_openline_project_ledger', None)
        if ledger is None or not getattr(ledger, 'db_path', None):
            return False
        try:
            with contextlib.closing(sqlite3.connect(str(ledger.db_path), timeout=5)) as db:
                row = db.execute(
                    'SELECT commit_seq, cas_target_head, cas_expected_head, cas_state FROM assignment_standing WHERE assignment_id=?',
                    (str(task_id),),
                ).fetchone()
                if not row or type(row[0]) is not int or row[0] <= 0:
                    return False
                if row[1] != target_head or row[2] != expected_head or row[3] != 'PENDING_CAS':
                    return False
                ev = db.execute('SELECT kind, payload FROM events WHERE seq=?', (row[0],)).fetchone()
                if not ev or ev[0] != 'KILL_SWITCH_DECISION':
                    return False
                data = json.loads(ev[1])
                return (
                    data.get('assignment') == task_id
                    and data.get('phase') == 'FINAL_GATE'
                    and data.get('decision') == 'COMMIT'
                    and data.get('head') == target_head
                )
        except Exception:
            return False

    def accepted(self) -> str:
        return cmd('git','--git-dir',str(self.repo),'rev-parse',self.ref).stdout.strip()

    @contextlib.contextmanager
    def lock(self):
        with open(self.state_dir / 'promotion.lock','a+b') as f:
            fcntl.flock(f,fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(f,fcntl.LOCK_UN)

    def prepare(self, task_id: str) -> dict:
        if not task_id or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in task_id):
            raise PromotionRefused('invalid_task_id')
        task = self.state_dir / ('task-' + task_id)
        if task.exists():
            raise PromotionRefused('task_already_exists')
        task.mkdir()
        base = self.accepted()
        workspace = task / 'candidate'
        cmd('git','--git-dir',str(self.repo),'worktree','add','--detach',str(workspace),base)
        dbcopy = task / 'candidate.sqlite'
        snapshot(self.live_db, dbcopy)
        with contextlib.closing(sqlite3.connect(dbcopy)) as db:
            fingerprint = db_hash(db)
        state = {'id':task_id,'stage':'PREPARED','base':base,'workspace':str(workspace),
                 'snapshot_db':str(dbcopy),'base_db_hash':fingerprint,'created':int(time.time())}
        atomically_write(task/'state.json',state)
        return state

    def _load(self,task_id: str) -> tuple[Path,dict]:
        p=self.state_dir/('task-'+task_id)/'state.json'
        if not p.is_file():
            raise PromotionRefused('unknown_task')
        return p,json.loads(p.read_text())

    def _candidate_commit(self, state: dict, allow_prefixes: tuple[str,...]) -> str:
        wd=Path(state['workspace'])
        cmd('git','-C',str(wd),'add','-A')
        entries=cmd('git','-C',str(wd),'diff','--cached','--name-only','--diff-filter=ACDMR').stdout.splitlines()
        if not entries:
            raise PromotionRefused('no_repair_proposed')
        if any(not any((e.startswith(prefix) if prefix.endswith('/') else e==prefix)
                       for prefix in allow_prefixes) or e.startswith('/') or '..' in Path(e).parts for e in entries):
            raise PromotionRefused('repair_outside_allowed_source')
        for e in entries:
            p=wd/e
            if p.is_symlink():
                raise PromotionRefused('symlink_not_allowed')
        cmd('git','-C',str(wd),'-c','user.name=Trusted Proposal','-c','user.email=proposal@localhost',
            '-c','core.hooksPath=/dev/null','commit','-m','candidate repair '+state['id'])
        return cmd('git','-C',str(wd),'rev-parse','HEAD').stdout.strip()

    def _merge(self, head: str, candidate: str) -> tuple[str,str]:
        if head == candidate:
            raise PromotionRefused('already_at_candidate')
        tree_command = cmd('git','--git-dir',str(self.repo),'merge-tree','--write-tree',head,candidate,check=False)
        if tree_command.returncode:
            raise PromotionRefused('merge_conflict_or_invalid_graph')
        tree=tree_command.stdout.splitlines()[0].strip()
        if not len(tree)==40:
            raise PromotionRefused('merge_tree_missing')
        # A candidate with identical head is handled upstream; merge-tree creates
        # a merge of the accepted head and the independently tested repair commit.
        p=subprocess.run(['git','--git-dir',str(self.repo),'-c','user.name=Trusted Promotion',
             '-c','user.email=promotion@localhost','commit-tree',tree,'-p',head,'-p',candidate],
             input='Merge independently validated repair with concurrent accepted edits\n',text=True,capture_output=True)
        if p.returncode:
            raise PromotionRefused('merge_commit_failed:'+p.stderr[:300])
        return p.stdout.strip(),tree

    def promote(self,task_id: str, *, acceptance_cmd: list[str], allow_prefixes: tuple[str,...]=('app/',),
                timeout: float=30, fail_before_ref: bool | str=False, fail_after_ref: bool | str=False,
                pre_cas_check=None, refresh_snapshot: bool=False, final_gate_context=None, validation_runner=None) -> dict:
        """Run external tests against merged current HEAD; CAS only on PASS.
        Refreshes DB snapshot against current live_db before running acceptance_cmd
        so concurrent committed DB writes between prepare() and promote() are tested
        cleanly, while failing closed if acceptance_cmd or an in-flight writer mutates DB.
        """
        entry_gate_req, cas_gate_req = self._check_final_gate_required(task_id)
        if entry_gate_req and final_gate_context is None:
            raise PromotionRefused('final_gate_required')
        path,state=self._load(task_id)
        if state['stage']!='PREPARED':
            raise PromotionRefused('task_not_prepared')
        if not acceptance_cmd or not all(type(x) is str for x in acceptance_cmd):
            raise PromotionRefused('acceptance_command_required')
        with self.lock():
            now=self.accepted()
            with contextlib.closing(sqlite3.connect(state['snapshot_db'])) as snap:
                if db_hash(snap)!=state['base_db_hash']:
                    state.update({'stage':'REFUSED','reason':'test_snapshot_modified'})
                    atomically_write(path,state)
                    return {'status':'REFUSED','reason':'test_snapshot_modified','task_id':task_id}
            if refresh_snapshot:
                snapshot(self.live_db, Path(state['snapshot_db']))
                with contextlib.closing(sqlite3.connect(state['snapshot_db'])) as snap:
                    promote_db_hash = db_hash(snap)
            else:
                promote_db_hash = state['base_db_hash']
            state['promote_db_hash'] = promote_db_hash
            try:
                candidate=self._candidate_commit(state,allow_prefixes)
                target,tree=self._merge(now,candidate)
            except PromotionRefused as e:
                state.update({'stage':'REFUSED','reason':str(e),'expected_head':now})
                atomically_write(path,state)
                return {'status':'REFUSED','task_id':task_id,'reason':str(e),'accepted':self.accepted()}
            state.update({'stage':'TESTING','candidate':candidate,'proposed_head':target,'expected_head':now,'tree':tree})
            atomically_write(path,state)
            merged=path.parent/'merged'
            cmd('git','--git-dir',str(self.repo),'worktree','add','--detach',str(merged),target)
            try:
                active_val_runner = validation_runner or self.validation_runner
                val_ctx_before = None
                if active_val_runner is not None:
                    from validation_runner import ValidationJob, compute_validation_context_sha256
                    proj_db_path = Path(self._bound_project.db_path) if (self._bound_project is not None and getattr(self._bound_project, 'db_path', None)) else Path(acceptance_cmd[-1])
                    val_script_path = Path(acceptance_cmd[-2]) if len(acceptance_cmd) >= 2 and Path(acceptance_cmd[-2]).is_file() else Path(acceptance_cmd[-1])
                    val_job = ValidationJob(
                        job_id=f"{task_id}-{uuid.uuid4().hex[:12]}",
                        assignment_id=task_id,
                        merged_worktree=merged,
                        project_db=proj_db_path,
                        effects_snapshot_db=Path(state['snapshot_db']),
                        validator_script=val_script_path,
                        proposed_head=target,
                        expected_head=now,
                        timeout_s=float(timeout),
                    )
                    outcome = active_val_runner.run(val_job)
                    val_ctx_before = outcome.validation_context_sha256
                    state['verification'] = outcome.to_verification_dict()
                    if not outcome.passed:
                        raise PromotionRefused(outcome.reason or 'independent_acceptance_failed')
                    if self._bound_project is not None and getattr(self._bound_project, 'db_path', None):
                        if compute_validation_context_sha256(self._bound_project.db_path) != val_ctx_before:
                            raise PromotionRefused('validation_context_changed_revalidation_required')
                else:
                    env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'HOME':str(path.parent),
                         'OPENLINE_TEST_DB':state['snapshot_db'],'PYTHONDONTWRITEBYTECODE':'1',
                         'PYTHONNOUSERSITE':'1','LANG':'C.UTF-8','PYTHONPATH':str(merged)}
                    started=time.monotonic()
                    p=subprocess.run(acceptance_cmd,cwd=merged,env=env,text=True,capture_output=True,timeout=timeout)
                    state['verification']={'exit':p.returncode,'elapsed_s':round(time.monotonic()-started,3),
                        'stdout_sha256':hashlib.sha256(p.stdout.encode()).hexdigest(),
                        'stderr_sha256':hashlib.sha256(p.stderr.encode()).hexdigest(),
                        'stdout_tail':p.stdout[-1600:],'stderr_tail':p.stderr[-1600:]}
                    if p.returncode:
                        raise PromotionRefused('independent_acceptance_failed')
                with contextlib.closing(sqlite3.connect(state['snapshot_db'])) as snap:
                    if db_hash(snap)!=promote_db_hash:
                        raise PromotionRefused('test_snapshot_modified')
                if pre_cas_check is not None:
                    pre_cas_check()
                entry_now, cas_now = self._check_final_gate_required(task_id)
                must_gate = bool(entry_gate_req or cas_gate_req or entry_now or cas_now)
                if must_gate and final_gate_context is None:
                    raise PromotionRefused('final_gate_required')
                gate_cm = final_gate_context(target, now) if final_gate_context is not None else contextlib.nullcontext()
                with gate_cm:
                    if must_gate and not self._verify_active_final_gate_reservation(final_gate_context, task_id, target, now):
                        raise PromotionRefused('final_gate_required')
                    with contextlib.closing(sqlite3.connect(self.live_db,timeout=15)) as live:
                        live.execute('BEGIN IMMEDIATE')
                        if db_hash(live)!=promote_db_hash:
                            raise PromotionRefused('live_database_changed_revalidation_required')
                        if self.accepted()!=now:
                            raise PromotionRefused('accepted_git_ref_changed_retry_required')
                        state['stage']='CAS_PENDING'
                        atomically_write(path,state)
                        if fail_before_ref == 'SIGKILL':
                            os.kill(os.getpid(), 9)
                        if fail_before_ref:
                            live.rollback()
                            raise RuntimeError('injected_crash_before_ref_cas')
                        cas=cmd('git','--git-dir',str(self.repo),'update-ref',self.ref,target,now,check=False)
                        if cas.returncode:
                            raise PromotionRefused('git_compare_and_swap_failed')
                        if fail_after_ref == 'SIGKILL':
                            os.kill(os.getpid(), 9)
                        if fail_after_ref:
                            live.rollback()
                            raise RuntimeError('injected_crash_after_ref_cas')
                        live.commit()
                state['stage']='PROMOTED'
                atomically_write(path,state)
                return {'status':'PROMOTED','task_id':task_id,'head':target,'parents':[now,candidate],
                        'db_unchanged':True,'verification':state['verification']}
            except PromotionRefused as e:
                state['stage']='REFUSED';state['reason']=str(e)
                atomically_write(path,state)
                return {'status':'REFUSED','task_id':task_id,'reason':str(e),'accepted':self.accepted(),
                        'verification':state.get('verification')}
            except Exception as e:
                if not (isinstance(e, RuntimeError) and str(e).startswith('injected_crash_')):
                    state['stage']='REFUSED';state['reason']=str(e)
                    atomically_write(path,state)
                raise
            finally:
                cmd('git','--git-dir',str(self.repo),'worktree','remove','--force',str(merged),check=False)

    def recover(self,task_id: str) -> dict:
        path,state=self._load(task_id)
        head=self.accepted()
        if state['stage']=='CAS_PENDING':
            proposed=state.get('proposed_head')
            expected=state.get('expected_head')
            ver=state.get('verification')
            if (not isinstance(proposed, str) or len(proposed) != 40 or
                not isinstance(expected, str) or len(expected) != 40 or
                proposed == expected or not isinstance(ver, dict) or ver.get('exit') != 0):
                state['stage']='REFUSED';state['reason']='cas_invalid_unverified_state'
                atomically_write(path,state)
                return {'status':'REFUSED','reason':'cas_invalid_unverified_state'}
            if head==proposed or cmd('git','--git-dir',str(self.repo),'merge-base','--is-ancestor',proposed,head,check=False).returncode==0:
                state['stage']='PROMOTED_RECOVERED'
                atomically_write(path,state)
                return {'status':'PROMOTED_RECOVERED','head':proposed,'accepted_head':head}
            if head==expected:
                state['stage']='REFUSED';state['reason']='cas_not_applied'
                atomically_write(path,state)
                return {'status':'REFUSED','reason':'cas_not_applied'}
            return {'status':'OUTCOME_UNCERTAIN','reason':'accepted_ref_diverged'}
        return {'status':state['stage'],'head':state.get('proposed_head')}
