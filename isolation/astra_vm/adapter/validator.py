"""Independently launched validator. Only pinned static RC5 fixture checker is supported.

Receiver sends copies over a peer-credential authenticated socket. No shared spool,
receiver paths, descriptors, arbitrary commands or candidate execution are accepted.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import closing
from wire import canonical, digest, peer, recv, send, strict

PROFILE = 'rc5-static-contract-v1'
PROFILE_SHA = '509b5211fecb45e3a6912db25cdf8f7c66f73bd6b8d6f21782b500ac7c1baf29'
MAX_SNAPSHOT = 2 * 1024 * 1024
ALLOWED_FIXTURE_FILES = frozenset({'app/price.py', 'app/independent.py'})


def _unpack(text, maximum):
    if not isinstance(text, str) or len(text) > 4 * ((maximum + 2) // 3):
        raise ValueError('encoded input cap')
    value = base64.b64decode(text, validate=True)
    if len(value) > maximum:
        raise ValueError('input cap')
    return value


def _compute_snapshot_context_sha256(project_db):
    p = Path(project_db)
    if not p.is_file():
        return '0' * 64
    with closing(sqlite3.connect(f'file:{p.resolve()}?mode=ro', uri=True, timeout=15.0)) as db:
        proj = db.execute('SELECT id, contract, status FROM projects ORDER BY id').fetchall()
        delivs = db.execute('SELECT id, member_id, standing FROM deliverables ORDER BY id').fetchall()
        deps = db.execute('SELECT deliverable_id, depends_on FROM dependencies ORDER BY deliverable_id, depends_on').fetchall()
        contracts = db.execute('SELECT project_id, dep_key, contract FROM dependency_contracts ORDER BY project_id, dep_key').fetchall()
        asgns = db.execute('SELECT id, deliverable_id, worker_member, basis, allowed_paths, state FROM assignments ORDER BY id').fetchall()
        members = db.execute('SELECT project_id, member_id, owner_pub, worker_pub, active FROM members ORDER BY project_id, member_id').fetchall()
        has_events = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='events'").fetchone()
        events = db.execute("SELECT seq, payload FROM events WHERE kind='CONTRACT_CHANGED' ORDER BY seq").fetchall() if has_events else []
    payload = {
        'contract_changed_events': events,
        'projects': proj,
        'deliverables': delivs,
        'dependencies': deps,
        'dependency_contracts': contracts,
        'assignments': asgns,
        'members': members,
    }
    return digest(payload)


def _tree_state_digest(root):
    entries = []
    for p in sorted(Path(root).rglob('*')):
        rel = p.relative_to(root).as_posix()
        if p.is_symlink():
            entries.append(f'SYM:{rel}')
        elif p.is_file():
            entries.append(f'FILE:{rel}:{digest(p.read_bytes())}')
        elif p.is_dir():
            entries.append(f'DIR:{rel}')
    return digest('\n'.join(entries).encode('utf-8'))


def limits():
    resource.setrlimit(resource.RLIMIT_FSIZE, (32768, 32768))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (5, 5))


def run_static(request, checker, workdir, connection):
    required = {
        'schema',
        'job_id',
        'assignment',
        'expected_head',
        'proposed_head',
        'context_sha256',
        'profile',
        'files',
        'project_snapshot',
        'effects_snapshot',
    }
    if set(request) != required or request['schema'] != 'openline.vm.validation.v1' or request['profile'] != PROFILE:
        raise ValueError('validation schema/profile')
    for str_field in ('job_id', 'assignment', 'expected_head', 'proposed_head', 'context_sha256'):
        if not isinstance(request.get(str_field), str) or not request[str_field]:
            raise ValueError(f'invalid {str_field}')
    if not isinstance(request['files'], dict) or set(request['files']) != ALLOWED_FIXTURE_FILES:
        raise ValueError('only pinned two-file static fixture supported')
    checker_bytes = Path(checker).read_bytes()
    if hashlib.sha256(checker_bytes).hexdigest() != PROFILE_SHA:
        raise ValueError('checker hash mismatch')

    with tempfile.TemporaryDirectory(prefix='job-', dir=workdir) as tmp:
        tmp_root = Path(tmp)
        cand_dir = tmp_root / 'candidate'
        snap_dir = tmp_root / 'snapshots'
        io_dir = tmp_root / 'io'
        (cand_dir / 'app').mkdir(parents=True, mode=0o700)
        snap_dir.mkdir(mode=0o700)
        io_dir.mkdir(mode=0o700)

        try:
            for name, encoded in request['files'].items():
                f_path = cand_dir / name
                f_path.write_bytes(_unpack(encoded, 16384))
                os.chmod(f_path, 0o400)
            os.chmod(cand_dir / 'app', 0o500)
            os.chmod(cand_dir, 0o500)

            for field in ('project_snapshot', 'effects_snapshot'):
                s_path = snap_dir / (field + '.sqlite')
                s_path.write_bytes(_unpack(request[field], MAX_SNAPSHOT))
                os.chmod(s_path, 0o400)

            actual_ctx = _compute_snapshot_context_sha256(snap_dir / 'project_snapshot.sqlite')
            if actual_ctx != request['context_sha256']:
                raise ValueError('validation context_sha256 mismatch with snapshot')

            cand_before = _tree_state_digest(cand_dir)
            snap_before = (digest((snap_dir / "project_snapshot.sqlite").read_bytes()), digest((snap_dir / "effects_snapshot.sqlite").read_bytes()))

            pinned_checker = io_dir / 'checker.py'
            pinned_checker.write_bytes(checker_bytes)
            os.chmod(pinned_checker, 0o400)
            # Fixed parser and receiver-created SQLite snapshots; no exec/eval/import of candidate.
            with (io_dir / 'stdout').open('wb') as stdout, (io_dir / 'stderr').open('wb') as stderr:
                proc = subprocess.Popen(
                    [sys.executable, '-I', '-B', str(pinned_checker), str(snap_dir / 'project_snapshot.sqlite')],
                    cwd=cand_dir,
                    env={'PATH': '/usr/bin:/bin', 'HOME': str(io_dir), 'LANG': 'C.UTF-8'},
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    close_fds=True,
                    start_new_session=True,
                    preexec_fn=limits,
                )
                started = time.monotonic()
                try:
                    while proc.poll() is None:
                        if time.monotonic() - started > 6:
                            raise TimeoutError('validator deadline')
                        # Receiver closes its socket on STOP/cancel; terminate owned checker only.
                        if connection is not None:
                            connection.setblocking(False)
                            try:
                                peeked = connection.recv(1, socket.MSG_PEEK)
                                if peeked == b'':
                                    raise EOFError('receiver cancelled')
                                raise ValueError('unexpected pipelined data on validator socket')
                            except BlockingIOError:
                                pass
                            finally:
                                connection.setblocking(True)
                        time.sleep(0.01)
                finally:
                    if proc.poll() is None:
                        os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=2)

            tree_mutated = _tree_state_digest(cand_dir) != cand_before
            snapshot_mutated = (digest((snap_dir / "project_snapshot.sqlite").read_bytes()), digest((snap_dir / "effects_snapshot.sqlite").read_bytes())) != snap_before
            return {
                'schema': 'openline.vm.validation.result.v1',
                'request_sha256': digest(request),
                'job_id': request['job_id'],
                'context_sha256': actual_ctx,
                'exit_code': proc.returncode,
                'tree_mutated': tree_mutated,
                'snapshot_mutated': snapshot_mutated,
                'elapsed_ms': int((time.monotonic() - started) * 1000),
                'stdout_sha256': digest((io_dir / 'stdout').read_bytes()),
                'stderr_sha256': digest((io_dir / 'stderr').read_bytes()),
                'stdout_tail': (io_dir / 'stdout').read_text(errors='replace')[-1200:],
                'stderr_tail': (io_dir / 'stderr').read_text(errors='replace')[-1200:],
            }
        finally:
            for d in (cand_dir, cand_dir / 'app', snap_dir):
                try:
                    if d.exists():
                        os.chmod(d, 0o700)
                except OSError:
                    pass


def serve(path, receiver_uid, checker, workdir, *, allow_single_uid_test_harness=False):
    if os.getuid() == 0 or os.geteuid() == 0 or os.getgid() == 0 or os.getegid() == 0:
        raise PermissionError('validator must not run as root')
    if not allow_single_uid_test_harness and (os.getuid() == receiver_uid or os.geteuid() == receiver_uid):
        raise PermissionError('validator must have a distinct non-root OS identity')
    wdir = Path(workdir)
    if wdir.is_symlink() or not wdir.is_dir():
        raise PermissionError('invalid validator workdir')
    os.chmod(wdir, 0o700)
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise FileExistsError('remove stale socket only after checking prior service stopped')
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(str(path))
        os.chmod(path, 0o600 if os.getuid() == receiver_uid else 0o666)
        server.listen(4)
        while True:
            conn, _ = server.accept()
            with conn:
                if peer(conn)[1] != receiver_uid:
                    continue
                try:
                    request = strict(recv(conn, timeout=3))
                    result = run_static(request, checker, workdir, conn)
                    conn.settimeout(3)
                    send(conn, canonical(result))
                except (OSError, ValueError, EOFError, KeyError, RuntimeError, subprocess.SubprocessError):
                    continue


class SocketValidationRunner:
    def __init__(self, socket_path, validator_uid, checker, abort_check=None, *, allow_single_uid_test_harness=False, require_native_openat2=True):
        if type(validator_uid) is not int or validator_uid < 0 or (validator_uid == 0 and not allow_single_uid_test_harness):
            raise PermissionError('distinct non-root validator required')
        if not allow_single_uid_test_harness and (validator_uid == os.getuid() or validator_uid == os.geteuid()):
            raise PermissionError('distinct non-root validator required')
        self.path = str(socket_path)
        self.uid = validator_uid
        self.checker = Path(checker)
        self.abort_check = abort_check
        self.allow_single_uid_test_harness = bool(allow_single_uid_test_harness)
        self.require_native_openat2 = bool(require_native_openat2)
        self.abort = threading.Event()
        self.lock = threading.Lock()
        self.active = None

    def preempt_active_validations(self):
        self.abort.set()
        with self.lock:
            if self.active is not None:
                try:
                    self.active.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        return 1

    def clear_abort_flag(self):
        self.abort.clear()

    def _verify_worktree_inventory(self, merged_worktree):
        wt = Path(merged_worktree)
        if wt.is_symlink() or not wt.is_dir():
            raise PermissionError('invalid merged_worktree')
        found = set()
        for p in wt.rglob('*'):
            rel = p.relative_to(wt).as_posix()
            if rel == '.git' or rel.startswith('.git/'):
                continue
            if p.is_symlink():
                raise PermissionError(f'symlink forbidden in merged_worktree:{rel}')
            if p.is_file():
                found.add(rel)
        if found != ALLOWED_FIXTURE_FILES:
            raise PermissionError('unexpected files in merged_worktree')

    def run(self, job):
        from validation_runner import ValidationOutcome, compute_validation_context_sha256
        import durable_io

        started = time.monotonic()
        context = ''
        pid = -1
        result = {}
        reason = None
        tree_mutated = False
        snapshot_mutated = False
        try:
            if job.validator_script.resolve() != self.checker.resolve() or digest(self.checker.read_bytes()) != PROFILE_SHA:
                raise PermissionError('unapproved validation profile')
            self._verify_worktree_inventory(job.merged_worktree)
            # Capture DB copies after checking SQLite sidecars and read validation context from the same copy.
            with tempfile.TemporaryDirectory(prefix='vm-snap-') as tmp:
                snapshots = {}
                for name, src in [('project_snapshot', job.project_db), ('effects_snapshot', job.effects_snapshot_db)]:
                    sidecars = durable_io.check_sqlite_sidecars(src)
                    if sidecars:
                        raise PermissionError('sqlite_sidecar_violation:' + ';'.join(sidecars))
                    dst = Path(tmp) / (name + '.sqlite')
                    with closing(sqlite3.connect(f'file:{Path(src).resolve()}?mode=ro', uri=True)) as a, closing(sqlite3.connect(dst)) as b:
                        a.backup(b)
                    if dst.stat().st_size > MAX_SNAPSHOT:
                        raise ValueError('snapshot cap')
                    snapshots[name] = base64.b64encode(dst.read_bytes()).decode()
                context = compute_validation_context_sha256(Path(tmp) / 'project_snapshot.sqlite')
            files = {
                name: base64.b64encode(
                    durable_io.read_bytes_beneath(
                        job.merged_worktree,
                        name,
                        max_bytes=16384,
                        require_native_openat2=self.require_native_openat2,
                    )
                ).decode()
                for name in ('app/price.py', 'app/independent.py')
            }
            request = {
                'schema': 'openline.vm.validation.v1',
                'job_id': job.job_id,
                'assignment': job.assignment_id,
                'expected_head': job.expected_head,
                'proposed_head': job.proposed_head,
                'context_sha256': context,
                'profile': PROFILE,
                'files': files,
                **snapshots,
            }
            with socket.socket(socket.AF_UNIX) as sock:
                sock.settimeout(2)
                sock.connect(self.path)
                pid, actual_uid, _ = peer(sock)
                if actual_uid != self.uid:
                    raise PermissionError('validator peer uid mismatch')
                with self.lock:
                    self.active = sock
                if self.abort.is_set() or (self.abort_check and self.abort_check()):
                    raise PermissionError('validation cancelled')
                send(sock, canonical(request))
                result = strict(recv(sock, limit=16384, timeout=min(10, job.timeout_s)))
            if (
                result.get('schema') != 'openline.vm.validation.result.v1'
                or result.get('request_sha256') != digest(request)
                or result.get('job_id') != job.job_id
                or result.get('context_sha256') != context
            ):
                raise PermissionError('validation binding mismatch')
            tree_mutated = bool(result.get('tree_mutated', False))
            snapshot_mutated = bool(result.get('snapshot_mutated', False))
            if tree_mutated or snapshot_mutated:
                raise PermissionError('validator_mutated_readonly_inputs')
            if type(result.get('exit_code')) is not int or result['exit_code'] != 0:
                raise ValueError('independent_acceptance_failed')
            if self.abort.is_set() or (self.abort_check and self.abort_check()):
                raise PermissionError('validation cancelled')
        except Exception as exc:
            reason = type(exc).__name__ + ':' + str(exc)
        finally:
            with self.lock:
                self.active = None
        return ValidationOutcome(
            job_id=job.job_id,
            passed=reason is None,
            exit_code=result.get('exit_code', 125) if reason is None else 125,
            timed_out=bool(reason and 'Timeout' in reason),
            aborted_by_stop=self.abort.is_set(),
            tree_mutated=tree_mutated,
            snapshot_mutated=snapshot_mutated,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            stdout_sha256=result.get('stdout_sha256', digest(b'')),
            stderr_sha256=result.get('stderr_sha256', digest(b'')),
            stdout_tail=result.get('stdout_tail', ''),
            stderr_tail=result.get('stderr_tail', ''),
            validation_context_sha256=context,
            validator_uid=self.uid,
            validator_pid=pid,
            reason=reason,
        )


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--socket', required=True)
    p.add_argument('--receiver-uid', type=int, required=True)
    p.add_argument('--checker', required=True)
    p.add_argument('--workdir', required=True)
    p.add_argument('--allow-single-uid-test-harness', action='store_true')
    a = p.parse_args()
    serve(
        a.socket,
        a.receiver_uid,
        Path(a.checker).resolve(),
        a.workdir,
        allow_single_uid_test_harness=a.allow_single_uid_test_harness,
    )


if __name__ == '__main__':
    main()
