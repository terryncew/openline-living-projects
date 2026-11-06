"""OpenLine Production Isolation — Unprivileged Validator Entrypoint (`ol-validate-p1`).

Implements Section 2.1, 3.2, and 4.4 of Astra's Production Isolation Blueprint:
- Executed under the dedicated unprivileged validator service (`openline-validate-p1.service`)
  or isolated subprocess runner with ZERO access to `accepted.git`, `project.sqlite`, `effects.sqlite`,
  `receiver.key`, or `/run/openline/p1/worker.sock`.
- Reads `<spool_job_dir>/request.json`, verifies staged `merged/` and read-only `project_snapshot.sqlite`
  / `effects_snapshot.sqlite`, executes the operator-pinned validator script against the read-only
  snapshots, and writes `<spool_job_dir>/result.json` (`openline.validation.result.v1`).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import time

from durable_io import atomic_write_json


VALIDATION_REQUEST_SCHEMA = "openline.validation.request.v1"
VALIDATION_RESULT_SCHEMA = "openline.validation.result.v1"


def _set_validator_rlimits() -> None:
    try:
        # Max 512 MiB file size, 256 open fds
        resource.setrlimit(resource.RLIMIT_FSIZE, (512 * 1024 * 1024, 512 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    except Exception:
        pass


def run_validation_job(job_dir: Path | str) -> dict:
    jdir = Path(job_dir).resolve()
    req_path = jdir / "request.json"
    if req_path.is_symlink() or not req_path.is_file():
        raise RuntimeError(f"validation_request_missing:{req_path}")
    req = json.loads(req_path.read_text(encoding="utf-8"))
    if req.get("schema") != VALIDATION_REQUEST_SCHEMA:
        raise RuntimeError("invalid_validation_request_schema")

    merged_dir = jdir / "merged"
    project_snap = jdir / "project_snapshot.sqlite"
    effects_snap = jdir / "effects_snapshot.sqlite"
    scratch_dir = jdir / "scratch"
    scratch_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    validator_script = Path(req["validator_script"]).resolve()
    if validator_script.is_symlink() or not validator_script.is_file():
        raise RuntimeError(f"validator_script_invalid:{validator_script}")

    timeout_s = float(req.get("timeout_s", 30.0))
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(scratch_dir),
        "TMPDIR": str(scratch_dir),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": str(merged_dir),
        "OPENLINE_TEST_DB": str(effects_snap),
        "OPENLINE_PROJECT_SNAPSHOT_DB": str(project_snap),
    }

    cmd = [sys.executable, "-B", "-I", str(validator_script), str(project_snap)]
    t0 = time.monotonic()
    timed_out = False
    try:
        p = subprocess.run(
            cmd,
            cwd=str(merged_dir),
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            preexec_fn=_set_validator_rlimits,
            check=False,
        )
        exit_code = int(p.returncode)
        stdout_text = p.stdout or ""
        stderr_text = p.stderr or ""
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        exit_code = 124
        stdout_text = (exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or ""))
        stderr_text = (exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or ""))

    elapsed_ms = int(round((time.monotonic() - t0) * 1000))
    result = {
        "schema": VALIDATION_RESULT_SCHEMA,
        "job_id": req["job_id"],
        "assignment_id": req["assignment_id"],
        "proposed_head": req["proposed_head"],
        "expected_head": req["expected_head"],
        "validation_context_sha256": req["validation_context_sha256"],
        "validator_uid": os.getuid(),
        "validator_gid": os.getgid(),
        "validator_pid": os.getpid(),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "elapsed_ms": elapsed_ms,
        "stdout_sha256": hashlib.sha256(stdout_text.encode("utf-8")).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr_text.encode("utf-8")).hexdigest(),
        "stdout_tail": stdout_text[-1600:],
        "stderr_tail": stderr_text[-1600:],
        "completed_at_unix": int(time.time()),
    }
    atomic_write_json(jdir / "result.json", result, mode=0o640)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="openline-validation-entry")
    parser.add_argument("--job-dir", required=True)
    args = parser.parse_args(argv)
    res = run_validation_job(Path(args.job_dir))
    return 0 if (res["exit_code"] == 0 and not res["timed_out"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
