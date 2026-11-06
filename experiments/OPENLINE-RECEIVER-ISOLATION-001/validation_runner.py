"""OpenLine Production Isolation — Validation Job Packager & Isolated Validation Runner.

Implements Section 2.1, 3.2, 4.4, and 7.2 (`VAL-01`, `VAL-02`, `RACE-01`) of Astra's Blueprint:
- Packages an immutable candidate validation bundle in `<validation_spool_dir>/job-<uuid>`:
  - Plain regular-file copy of `merged/` (with `.git` completely stripped so the validator has zero
    link back to `accepted.git`).
  - Read-only SQLite `.backup()` snapshots of `project.sqlite` and `effects.sqlite`.
  - Canonical `validation_context_sha256` projection of `projects`, `deliverables`, `dependencies`,
    and `dependency_contracts`.
- Supports preemptible execution with a live `abort_event`: if `control.stop`, member revocation,
  or dependency change occurs while validation is in flight, the runner immediately sends `SIGKILL`
  to the validator process group (`os.killpg(pgid, signal.SIGKILL)`) within `<50ms` and refuses promotion.
- Verifies post-run immutability of the staged `merged/` tree and SQLite snapshots (`tree_mutated` check).
"""
from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from typing import Any, Callable

from durable_io import atomic_write_json
from validation_entry import VALIDATION_REQUEST_SCHEMA, VALIDATION_RESULT_SCHEMA


class ValidationRunnerError(RuntimeError):
    pass


@dataclass
class ValidationJob:
    job_id: str
    assignment_id: str
    merged_worktree: Path
    project_db: Path
    effects_snapshot_db: Path
    validator_script: Path
    proposed_head: str
    expected_head: str
    timeout_s: float = 30.0


@dataclass
class ValidationOutcome:
    job_id: str
    passed: bool
    exit_code: int
    timed_out: bool
    aborted_by_stop: bool
    tree_mutated: bool
    snapshot_mutated: bool
    elapsed_ms: int
    stdout_sha256: str
    stderr_sha256: str
    stdout_tail: str
    stderr_tail: str
    validation_context_sha256: str
    validator_uid: int
    validator_pid: int
    reason: str | None = None

    def to_verification_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "exit": self.exit_code,
            "timed_out": self.timed_out,
            "aborted_by_stop": self.aborted_by_stop,
            "tree_mutated": self.tree_mutated,
            "snapshot_mutated": self.snapshot_mutated,
            "elapsed_s": round(self.elapsed_ms / 1000.0, 3),
            "elapsed_ms": self.elapsed_ms,
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
            "stdout_tail": self.stdout_tail,
            "stderr_tail": self.stderr_tail,
            "validation_context_sha256": self.validation_context_sha256,
            "validator_uid": self.validator_uid,
            "validator_pid": self.validator_pid,
            "reason": self.reason,
        }


def compute_validation_context_sha256(project_db: Path | str) -> str:
    """Compute canonical SHA-256 over the authoritative contract and dependency state in `project.sqlite`."""
    p = Path(project_db)
    if not p.is_file():
        return "0" * 64
    with closing(sqlite3.connect(str(p), timeout=15.0)) as db:
        proj = db.execute("SELECT id, contract, status FROM projects ORDER BY id").fetchall()
        delivs = db.execute("SELECT id, member_id, standing FROM deliverables ORDER BY id").fetchall()
        deps = db.execute("SELECT deliverable_id, depends_on FROM dependencies ORDER BY deliverable_id, depends_on").fetchall()
        contracts = db.execute("SELECT project_id, dep_key, contract FROM dependency_contracts ORDER BY project_id, dep_key").fetchall()
        asgns = db.execute("SELECT id, deliverable_id, worker_member, basis, allowed_paths, state FROM assignments ORDER BY id").fetchall()
        members = db.execute("SELECT project_id, member_id, owner_pub, worker_pub, active FROM members ORDER BY project_id, member_id").fetchall()
        has_events = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='events'").fetchone()
        events = db.execute("SELECT seq, payload FROM events WHERE kind='CONTRACT_CHANGED' ORDER BY seq").fetchall() if has_events else []
    payload = {
        "contract_changed_events": events,
        "projects": proj,
        "deliverables": delivs,
        "dependencies": deps,
        "dependency_contracts": contracts,
        "assignments": asgns,
        "members": members,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _tree_digest(root: Path) -> str:
    items: list[str] = []
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        if p.is_symlink():
            items.append(f"SYMLINK:{rel}")
        elif p.is_file():
            h = hashlib.sha256(p.read_bytes()).hexdigest()
            st = p.stat()
            items.append(f"FILE:{rel}:{st.st_mode & 0o777}:{h}")
        elif p.is_dir():
            items.append(f"DIR:{rel}")
    return hashlib.sha256("\n".join(items).encode("utf-8")).hexdigest()


def _copy_merged_tree_without_git(src_merged: Path, dst_merged: Path) -> None:
    dst_merged.mkdir(parents=True, exist_ok=True, mode=0o750)
    for item in sorted(src_merged.rglob("*")):
        rel = item.relative_to(src_merged)
        if rel.parts[0] == ".git":
            continue
        target = dst_merged / rel
        if item.is_symlink():
            raise ValidationRunnerError(f"merged_worktree_contains_symlink:{rel}")
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True, mode=0o750)
        elif item.is_file():
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
            shutil.copyfile(item, target)
            os.chmod(target, 0o640)


def _sqlite_backup(src_db: Path, dst_db: Path, *, mode: int = 0o440) -> str:
    if dst_db.exists():
        dst_db.unlink()
    with closing(sqlite3.connect(str(src_db), timeout=15.0)) as sconn, closing(sqlite3.connect(str(dst_db), timeout=15.0)) as dconn:
        sconn.backup(dconn)
    os.chmod(dst_db, mode)
    return hashlib.sha256(dst_db.read_bytes()).hexdigest()


class IsolatedValidationRunner:
    """Runs candidate validation in an isolated spool directory without `.git` or live DB access."""

    def __init__(
        self,
        spool_dir: Path | str,
        *,
        validator_uid: int | None = None,
        validator_gid: int | None = None,
        abort_check: Callable[[], bool] | None = None,
        use_systemd_trigger: bool = False,
    ):
        self.spool_dir = Path(spool_dir).resolve()
        self.spool_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
        self.validator_uid = validator_uid
        self.validator_gid = validator_gid
        self.abort_check = abort_check
        self.use_systemd_trigger = use_systemd_trigger
        self._active_lock = threading.Lock()
        self._active_pgids: set[int] = set()
        self._abort_flag = threading.Event()

    def preempt_active_validations(self) -> int:
        """Immediately signal abort and SIGKILL any in-flight validator process groups."""
        self._abort_flag.set()
        killed = 0
        with self._active_lock:
            for pgid in list(self._active_pgids):
                try:
                    os.killpg(pgid, signal.SIGKILL)
                    killed += 1
                except OSError:
                    pass
        return killed

    def clear_abort_flag(self) -> None:
        self._abort_flag.clear()

    def run(self, job: ValidationJob) -> ValidationOutcome:
        job_dir = self.spool_dir / f"job-{job.job_id}"
        if job_dir.exists():
            shutil.rmtree(job_dir)
        job_dir.mkdir(parents=True, mode=0o750)

        try:
            merged_copy = job_dir / "merged"
            _copy_merged_tree_without_git(job.merged_worktree, merged_copy)
            tree_before = _tree_digest(merged_copy)

            proj_snap = job_dir / "project_snapshot.sqlite"
            eff_snap = job_dir / "effects_snapshot.sqlite"
            proj_sha_before = _sqlite_backup(job.project_db, proj_snap, mode=0o440)
            eff_sha_before = _sqlite_backup(job.effects_snapshot_db, eff_snap, mode=0o440)
            val_ctx_sha = compute_validation_context_sha256(proj_snap)

            req_obj = {
                "schema": VALIDATION_REQUEST_SCHEMA,
                "job_id": job.job_id,
                "assignment_id": job.assignment_id,
                "proposed_head": job.proposed_head,
                "expected_head": job.expected_head,
                "validation_context_sha256": val_ctx_sha,
                "validator_script": str(job.validator_script.resolve()),
                "timeout_s": float(job.timeout_s),
                "created_at_unix": int(time.time()),
            }
            atomic_write_json(job_dir / "request.json", req_obj, mode=0o640)

            entry_script = Path(__file__).resolve().parent / "validation_entry.py"
            cmd = [sys.executable, "-B", str(entry_script), "--job-dir", str(job_dir)]

            t0 = time.monotonic()
            timed_out = False
            aborted = False

            proc = subprocess.Popen(
                cmd,
                cwd=str(job_dir),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
                start_new_session=True,
            )
            pgid = proc.pid
            with self._active_lock:
                self._active_pgids.add(pgid)

            try:
                deadline = t0 + float(job.timeout_s) + 1.0
                while proc.poll() is None:
                    if self._abort_flag.is_set() or (self.abort_check is not None and self.abort_check()):
                        aborted = True
                        try:
                            os.killpg(pgid, signal.SIGKILL)
                        except OSError:
                            proc.kill()
                        break
                    if time.monotonic() >= deadline:
                        timed_out = True
                        try:
                            os.killpg(pgid, signal.SIGKILL)
                        except OSError:
                            proc.kill()
                        break
                    time.sleep(0.015)
                proc.wait(timeout=2.0)
            finally:
                with self._active_lock:
                    self._active_pgids.discard(pgid)

            elapsed_ms = int(round((time.monotonic() - t0) * 1000))
            tree_after = _tree_digest(merged_copy)
            tree_mutated = tree_after != tree_before
            proj_sha_after = hashlib.sha256(proj_snap.read_bytes()).hexdigest() if proj_snap.is_file() else "MISSING"
            eff_sha_after = hashlib.sha256(eff_snap.read_bytes()).hexdigest() if eff_snap.is_file() else "MISSING"
            snapshot_mutated = (proj_sha_after != proj_sha_before) or (eff_sha_after != eff_sha_before)

            res_path = job_dir / "result.json"
            if aborted:
                return ValidationOutcome(
                    job_id=job.job_id,
                    passed=False,
                    exit_code=137,
                    timed_out=False,
                    aborted_by_stop=True,
                    tree_mutated=tree_mutated,
                    snapshot_mutated=snapshot_mutated,
                    elapsed_ms=elapsed_ms,
                    stdout_sha256=hashlib.sha256(b"").hexdigest(),
                    stderr_sha256=hashlib.sha256(b"aborted_by_stop").hexdigest(),
                    stdout_tail="",
                    stderr_tail="aborted_by_stop",
                    validation_context_sha256=val_ctx_sha,
                    validator_uid=os.getuid(),
                    validator_pid=proc.pid,
                    reason="validation_aborted_by_stop",
                )

            if res_path.is_symlink() or not res_path.is_file():
                return ValidationOutcome(
                    job_id=job.job_id,
                    passed=False,
                    exit_code=124 if timed_out else (proc.returncode or 1),
                    timed_out=timed_out,
                    aborted_by_stop=False,
                    tree_mutated=tree_mutated,
                    snapshot_mutated=snapshot_mutated,
                    elapsed_ms=elapsed_ms,
                    stdout_sha256=hashlib.sha256(b"").hexdigest(),
                    stderr_sha256=hashlib.sha256(b"result_missing").hexdigest(),
                    stdout_tail="",
                    stderr_tail="validation_result_missing",
                    validation_context_sha256=val_ctx_sha,
                    validator_uid=os.getuid(),
                    validator_pid=proc.pid,
                    reason="validation_timed_out" if timed_out else "validation_result_missing",
                )

            res_data = json.loads(res_path.read_text(encoding="utf-8"))
            if res_data.get("schema") != VALIDATION_RESULT_SCHEMA or res_data.get("job_id") != job.job_id:
                raise ValidationRunnerError("invalid_validation_result_schema")

            exit_code = int(res_data["exit_code"])
            res_timed_out = bool(res_data.get("timed_out")) or timed_out
            passed = (
                exit_code == 0
                and not res_timed_out
                and not tree_mutated
                and not snapshot_mutated
                and not aborted
            )
            reason = None
            if not passed:
                if res_timed_out:
                    reason = "validation_timed_out"
                elif tree_mutated:
                    reason = "validation_tree_mutated"
                elif snapshot_mutated:
                    reason = "test_snapshot_modified"
                else:
                    reason = "independent_acceptance_failed"

            return ValidationOutcome(
                job_id=job.job_id,
                passed=passed,
                exit_code=exit_code,
                timed_out=res_timed_out,
                aborted_by_stop=False,
                tree_mutated=tree_mutated,
                snapshot_mutated=snapshot_mutated,
                elapsed_ms=int(res_data.get("elapsed_ms", elapsed_ms)),
                stdout_sha256=str(res_data["stdout_sha256"]),
                stderr_sha256=str(res_data["stderr_sha256"]),
                stdout_tail=str(res_data.get("stdout_tail", "")),
                stderr_tail=str(res_data.get("stderr_tail", "")),
                validation_context_sha256=val_ctx_sha,
                validator_uid=int(res_data.get("validator_uid", os.getuid())),
                validator_pid=int(res_data.get("validator_pid", proc.pid)),
                reason=reason,
            )
        finally:
            shutil.rmtree(job_dir, ignore_errors=True)
