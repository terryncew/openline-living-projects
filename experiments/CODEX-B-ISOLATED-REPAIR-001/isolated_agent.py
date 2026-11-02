"""Codex B: fail-closed local worker boundary; not an AI model or an authority engine.

Prerequisites: Linux, trusted root launcher, setpriv, unshare, mount, chroot,
non-root worker UID, user/mount/net/PID namespaces. No remote credentials or
paid agent calls are permitted in this profile. The worker receives only app/
source and a public task note, never a Git worktree or protected evaluator.
"""
from __future__ import annotations

import hashlib
import signal
import json
import os
from pathlib import Path, PurePosixPath
import resource
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass


class IsolationRefused(RuntimeError):
    pass


def path_allowed(path: str, allowed: tuple[str, ...]) -> bool:
    if (not isinstance(path, str) or not path.startswith('app/') or '\\' in path
        or path.startswith('/') or '\x00' in path or not path.isascii()
        or any(x in ('', '.', '..') for x in PurePosixPath(path).parts)):
        return False
    return any(path == a or (a.endswith('/') and path.startswith(a)) for a in allowed)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _files(root: Path, *, max_bytes: int = 2_000_000) -> dict[str, str]:
    """Reject symlinks/specials and all paths other than app/ source files."""
    result = {}
    base = root / 'app'
    if not base.is_dir() or base.is_symlink():
        raise IsolationRefused('app_directory_required')
    total = 0
    for dirpath, dirs, files in os.walk(base, followlinks=False):
        for name in dirs:
            if (Path(dirpath) / name).is_symlink():
                raise IsolationRefused('symlink_directory')
        for name in files:
            p = Path(dirpath) / name
            st = p.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise IsolationRefused('symlink_or_special_file')
            total += st.st_size
            if total > max_bytes:
                raise IsolationRefused('candidate_size_limit')
            relative = p.relative_to(root).as_posix()
            if not path_allowed(relative, ('app/',)):
                raise IsolationRefused('offscope_file')
            result[relative] = digest(p)
    return result


@dataclass(frozen=True)
class WorkerResult:
    outcome: str
    exit_code: int
    changes: tuple[str, ...]
    elapsed_s: float
    stdout_sha256: str
    stderr_sha256: str
    details: str
    files_sha256: tuple[tuple[str, str], ...] = ()


class RestrictedAgentWorkspace:
    """Root-owned coordinator, separate host UID and no-network chroot child.

    Trusted project coordinator must call ProjectLedger.promote_repair AFTER
    importing candidate files. This object never promotes, signs or accepts.
    """
    def __init__(self, source: Path, *, allowed_paths: tuple[str, ...], worker_uid: int = 65534,
                 worker_gid: int = 65534, task_note: str = ''):
        self.source = Path(source).resolve(strict=True)
        self.allowed = tuple(allowed_paths)
        if not self.allowed or any(not path_allowed(p, ('app/',)) for p in self.allowed):
            raise IsolationRefused('invalid_owner_pinned_scope')
        if os.name != 'posix' or os.geteuid() != 0:
            raise IsolationRefused('trusted_root_launcher_required')
        if worker_uid == 0 or worker_gid == 0:
            raise IsolationRefused('worker_must_have_separate_host_identity')
        if not all(shutil.which(x) for x in ('setpriv', 'unshare', 'mount', 'chroot')):
            raise IsolationRefused('namespace_utilities_missing')
        self.uid, self.gid = worker_uid, worker_gid
        self._tmp = tempfile.TemporaryDirectory(prefix='openline-b-agent-')
        os.chmod(self._tmp.name, 0o711)  # traverse to jailed root, no listing
        self.root = Path(self._tmp.name) / 'root'
        self.root.mkdir(mode=0o755)
        for name in ('usr','work','tmp'):
            (self.root / name).mkdir(mode=0o755)
        for alias,target in (('bin','usr/bin'),('lib','usr/lib'),('lib64','usr/lib64')):
            (self.root / alias).symlink_to(target)
        # Only the project app/ tree crosses from trusted to untrusted context.
        inventory = _files(self.source)
        for item in inventory:
            src = self.source / item
            dst = self.root / 'work' / item
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst, follow_symlinks=False)
        note = (self.root / 'work' / 'TASK.txt')
        if len(task_note) > 12000:
            raise IsolationRefused('task_note_too_long')
        note.write_text(task_note)
        # Trust root and copied public task remain immutable; app tree editable.
        for dirpath,dirs,files in os.walk(self.root/'work'):
            os.chown(dirpath, self.uid, self.gid)
            for file in files:
                p=Path(dirpath)/file
                os.chown(p,self.uid,self.gid)
                p.chmod(0o600 if p.name!='TASK.txt' else 0o400)
        (self.root/'work').chmod(0o700)
        (self.root/'work'/'app').chmod(0o700)
        self.before = inventory
        self._ran = False

    def __enter__(self):return self
    def __exit__(self,*_):self.close()
    def close(self): self._tmp.cleanup()

    def run(self, argv: list[str], *, timeout_s: int = 60) -> WorkerResult:
        if self._ran: raise IsolationRefused('one_run_per_worker_context')
        self._ran = True
        if not argv or not isinstance(argv, list) or not all(isinstance(x,str) for x in argv):
            raise IsolationRefused('agent_argv_required')
        # Current release provides an offline Python probe. Other runners
        # require a separately reviewed binary/dependency manifest.
        if argv[0] not in ('/usr/bin/python3', '/usr/bin/codex', '/usr/bin/claude', '/usr/bin/aider', '/usr/bin/opencode', '/usr/bin/hermes') or not Path(argv[0]).is_file():
            raise IsolationRefused('agent_runtime_not_reviewed_or_installed')
        if not 1 <= timeout_s <= 120:
            raise IsolationRefused('invalid_runtime_budget')
        # The command remains an untrusted process, including its arguments.
        # No shell constructs contain untrusted text; args passed after `sh`.
        shell = """
            root="$1"; shift
            mount --make-rprivate /
            mount --bind /usr "$root/usr"
            mount -o remount,bind,ro "$root/usr"
            cd /
            exec chroot "$root" /usr/bin/env -i PATH=/usr/bin:/bin HOME=/work TMPDIR=/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 /usr/bin/sh -c 'cd /work; exec "$@"' runner "$@"
        """
        command = [shutil.which('setpriv'), f'--reuid={self.uid}', f'--regid={self.gid}',
                   '--clear-groups', '--no-new-privs', shutil.which('unshare'),
                   '--user', '--map-root-user','--mount','--net','--pid','--fork',
                   '/bin/sh','-eu','-c',shell,'sandbox',str(self.root),*argv]
        import time
        started = time.monotonic()
        def limits():
            resource.setrlimit(resource.RLIMIT_CPU,(min(120,timeout_s+3),min(120,timeout_s+3)))
            resource.setrlimit(resource.RLIMIT_FSIZE,(3_000_000,3_000_000))
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'},
                            preexec_fn=limits, start_new_session=True, close_fds=True)
        try:
            stdout,stderr = proc.communicate(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            # Kill the ENTIRE namespace launcher group, not only setpriv.
            # A timeout must never leave an untrusted child editing files.
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()
            return WorkerResult('TIMEOUT',124,(),round(time.monotonic()-started,3),'','',
                                'worker_process_group_killed')
        p=type('Completed',(),{'returncode':proc.returncode,'stdout':stdout,'stderr':stderr})()
        elapsed=round(time.monotonic()-started,3)
        try:
            after=_files(self.root/'work')
            changed=tuple(sorted(k for k in set(self.before)|set(after) if self.before.get(k)!=after.get(k)))
            if any(not path_allowed(k,self.allowed) for k in changed):
                return WorkerResult('REFUSED_SCOPE',p.returncode,changed,elapsed,
                     hashlib.sha256(p.stdout).hexdigest(),hashlib.sha256(p.stderr).hexdigest(),'not_owner_allowed')
            if not changed:
                outcome='NO_CHANGE' if p.returncode==0 else 'WORKER_FAILED'
            else:
                outcome='CANDIDATE' if p.returncode==0 else 'WORKER_FAILED'
        except IsolationRefused as exc:
            return WorkerResult('REFUSED_CONTENT',p.returncode,(),elapsed,
                hashlib.sha256(p.stdout).hexdigest(),hashlib.sha256(p.stderr).hexdigest(),str(exc))
        return WorkerResult(outcome,p.returncode,changed,elapsed,
            hashlib.sha256(p.stdout).hexdigest(),hashlib.sha256(p.stderr).hexdigest(),
            p.stderr.decode('utf-8','replace')[-300:] if p.returncode else '',
            tuple((k, after[k]) for k in changed if k in after))

    def import_candidate(self, receiver_candidate: Path, result: WorkerResult):
        """Copy exact scoped source only to a receiver-owned PREPARED worktree.

        The receiver must independently validate accepted ref, assignment,
        current authority and hidden acceptance on the merged-current tree.
        """
        if result.outcome!='CANDIDATE':
            raise IsolationRefused('unaccepted_worker_result')
        destination=Path(receiver_candidate).resolve(strict=True)
        if not (destination / '.git').exists():
            raise IsolationRefused('prepared_git_worktree_required')
        # No direct copy of worker tree, links, tests, policy or metadata.
        inventory = _files(self.root/'work')
        if tuple(sorted(k for k in set(self.before)|set(inventory) if self.before.get(k)!=inventory.get(k))) != result.changes:
            raise IsolationRefused('candidate_changed_after_review')
        if dict(result.files_sha256) != {k: inventory[k] for k in result.changes if k in inventory}:
            raise IsolationRefused('candidate_bytes_changed_after_review')
        for path in result.changes:
            if not path_allowed(path,self.allowed):raise IsolationRefused('scope_changed')
            source=self.root/'work'/path
            target=destination/path
            if target.is_symlink() or not target.parent.is_dir() or target.parent.is_symlink():
                raise IsolationRefused('destination_path_unsafe')
            if path not in inventory:
                raise IsolationRefused('deletions_not_supported')
            target.write_bytes(source.read_bytes())
        return result.changes
