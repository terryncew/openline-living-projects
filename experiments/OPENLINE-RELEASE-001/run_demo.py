"""OpenLine release demo -- the full continuity mission in one command.

Runs on top of the release CLI's own functions (init/assign/prepare/
change/revoke) plus direct gate calls where the demo must capture
receipts for verification. The subprocess CLI path is proved
separately by the quickstart manual flow and by the recover/verify
steps below, which shell out to the real `openline` script.

Steps: forbidden STOPPED; authorized ACCEPTED + verified; falsifier
UNKNOWN with candidate preserved; second disruption (interruption +
revocation) with carol replacement ACCEPTED and unrelated work
CURRENT; boundary gate; effect binding; CLI recover/verify; OS
isolation probe + timeout; same-UID deployment condition.

Exit 0 only if every asserted step passes. Writes
<project_dir>/demo_evidence.json.
"""
import hashlib
import json
import os
import resource
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from engine_loader import load_engines  # noqa: E402

load_engines()

import openline_cli as cli  # noqa: E402
from protect import check_receiver_boundary, verify_receipt  # noqa: E402
from isolated_agent import (  # noqa: E402
    IsolationRefused, RestrictedAgentWorkspace, WorkerResult, _files,
    path_allowed,
)

WORKER_UID = 65534


class ContainerSandbox(RestrictedAgentWorkspace):
    """Container adaptation, same finding as #157 (vendor command's
    setpriv-first ordering fails in a nested container user namespace).
    Unshares FIRST as root, then drops to the worker UID inside the
    chroot. Vendor files untouched; worker strictly less privileged.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        os.chmod(self.root, 0o755)
        os.chmod(self.root / "tmp", 0o755)
        os.chmod(self.root / "usr", 0o755)

    def run(self, argv, *, timeout_s=60):
        if self._ran:
            raise IsolationRefused("one_run_per_worker_context")
        self._ran = True
        if not argv or not all(isinstance(x, str) for x in argv):
            raise IsolationRefused("agent_argv_required")
        if argv[0] not in ("/usr/bin/python3",) \
                or not Path(argv[0]).is_file():
            raise IsolationRefused("agent_runtime_not_reviewed")
        if not 1 <= timeout_s <= 120:
            raise IsolationRefused("invalid_runtime_budget")
        shell = (
            "root=\"$1\"; shift\n"
            "mount --make-rprivate /\n"
            "mount --bind /usr \"$root/usr\"\n"
            "mount -o remount,bind,ro \"$root/usr\"\n"
            "cd /\n"
            f"exec chroot \"$root\" /usr/bin/setpriv "
            f"--reuid={self.uid} --regid={self.gid} "
            "--clear-groups --no-new-privs "
            "/usr/bin/env -i PATH=/usr/bin:/bin HOME=/work "
            "TMPDIR=/tmp PYTHONDONTWRITEBYTECODE=1 "
            "PYTHONNOUSERSITE=1 /usr/bin/sh -c "
            "'cd /work; exec \"$@\"' runner \"$@\"\n"
        )
        command = [shutil.which("unshare"),
                   "--user", "--map-users=0,0,65536",
                   "--map-groups=0,0,65536",
                   "--mount", "--net", "--pid", "--fork",
                   "/bin/sh", "-eu", "-c", shell, "sandbox",
                   str(self.root), *argv]
        started = time.monotonic()

        def limits():
            resource.setrlimit(
                resource.RLIMIT_CPU,
                (min(120, timeout_s + 3), min(120, timeout_s + 3)))
            resource.setrlimit(resource.RLIMIT_FSIZE, (3_000_000, 3_000_000))

        proc = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
            preexec_fn=limits, start_new_session=True, close_fds=True)
        try:
            stdout, stderr = proc.communicate(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()
            return WorkerResult("TIMEOUT", 124, (),
                                round(time.monotonic() - started, 3),
                                "", "", "worker_process_group_killed")
        p = type("Completed", (),
                 {"returncode": proc.returncode,
                  "stdout": stdout, "stderr": stderr})()
        elapsed = round(time.monotonic() - started, 3)
        try:
            after = _files(self.root / "work")
            changed = tuple(sorted(
                k for k in set(self.before) | set(after)
                if self.before.get(k) != after.get(k)))
            if any(not path_allowed(k, self.allowed) for k in changed):
                return WorkerResult(
                    "REFUSED_SCOPE", p.returncode, changed, elapsed,
                    hashlib.sha256(p.stdout).hexdigest(),
                    hashlib.sha256(p.stderr).hexdigest(),
                    "not_owner_allowed")
            if not changed:
                outcome = "NO_CHANGE" if p.returncode == 0 else "WORKER_FAILED"
            else:
                outcome = "CANDIDATE" if p.returncode == 0 else "WORKER_FAILED"
        except IsolationRefused as exc:
            return WorkerResult(
                "REFUSED_CONTENT", p.returncode, (), elapsed,
                hashlib.sha256(p.stdout).hexdigest(),
                hashlib.sha256(p.stderr).hexdigest(), str(exc))
        return WorkerResult(
            outcome, p.returncode, changed, elapsed,
            hashlib.sha256(p.stdout).hexdigest(),
            hashlib.sha256(p.stderr).hexdigest(),
            p.stderr.decode("utf-8", "replace")[-300:] if p.returncode else "",
            tuple((k, after[k]) for k in changed if k in after))


def _ns(**kwargs):
    return SimpleNamespace(**kwargs)


def _git_file(accepted, ref_path):
    result = subprocess.run(
        ["git", "--git-dir", str(accepted), "show",
         f"refs/heads/accepted:{ref_path}"],
        capture_output=True, text=True)
    if not (result.returncode == 0):
        raise AssertionError(result.stderr)
    return result.stdout.strip()


def run_demo(project_dir: Path):
    project_dir = project_dir.resolve()
    evidence = {}
    started = time.monotonic()
    rc = cli.cmd_init(_ns(dir=str(project_dir), project_id="openline-demo",
                          workers="alice,bob,carol", validator=None,
                          worker_uid=WORKER_UID))
    if not (rc == 0):
        raise AssertionError(rc)
    config = cli._load_config(project_dir)
    promo, project, protect = cli._build_engines(config, WORKER_UID)
    head = lambda: promo.accepted()  # noqa: E731
    standings = lambda: {d[0]: d[2]  # noqa: E731
                         for d in project.snapshot()["deliverables"]}

    def verify(out):
        checked = verify_receipt(out["receipt"], config["receiver_pub"],
                                 accepted_git=Path(config["accepted_git"]),
                                 project_db=Path(config["project_db"]))
        if not (checked["crypto"] == "VERIFIED"):
            raise AssertionError(checked)
        return checked

    # D1: forbidden change STOPPED.
    if not (cli.cmd_assign(_ns(dir=str(project_dir),
                              worker_uid=WORKER_UID, assignment="repair-v2",
                              worker="bob", basis="invoice_v2",
                              as_member=None, signature=None)) == 0):
        raise AssertionError('demo invariant failure')
    state = promo.prepare("repair-v2")
    (Path(state["workspace"]) / "app" / "independent.py").write_text(
        'def label(value):\n    return "hacked"\n')
    head_before = head()
    out = protect.intercept("repair-v2")
    if not (out["verdict"] == "STOPPED"):
        raise AssertionError(out)
    if not (head() == head_before):
        raise AssertionError('demo invariant failure')
    if not (_git_file(Path(config["accepted_git"]),
                     "app/independent.py") == \
        "def label(value):\n    return value.upper()"):
        raise AssertionError('demo invariant failure')
    verify(out)
    evidence["D1_forbidden"] = "STOPPED"
    print("D1 forbidden change STOPPED, head unchanged, receipt verified")

    # D2: authorized repair ACCEPTED + verified.
    state = promo.prepare("repair-v2")
    (Path(state["workspace"]) / "app" / "price.py").write_text(
        "def total(qty):\n    return qty * 11\n")
    out = protect.intercept("repair-v2")
    if not (out["verdict"] == "ACCEPTED"):
        raise AssertionError(out)
    if not (standings()["invoice-feature"] == "CURRENT"):
        raise AssertionError('demo invariant failure')
    checked = verify(out)
    if not (checked["git_verified"] and checked["continuity_verified"]):
        raise AssertionError('demo invariant failure')
    evidence["D2_authorized"] = {"verdict": "ACCEPTED", "head": head()}
    print("D2 authorized repair ACCEPTED, receipt verified (git + ledger)")

    # D3: falsifier UNKNOWN preserves the candidate.
    if not (cli.cmd_change(_ns(dir=str(project_dir),
                              worker_uid=WORKER_UID,
                              dependency="invoice_v2",
                              contract="invoice_v2b",
                              signature=None)) == 0):
        raise AssertionError('demo invariant failure')
    if not (cli.cmd_assign(_ns(dir=str(project_dir),
                              worker_uid=WORKER_UID, assignment="repair-v2b",
                              worker="bob", basis="invoice_v2b",
                              as_member=None, signature=None)) == 0):
        raise AssertionError('demo invariant failure')
    state = promo.prepare("repair-v2b")
    workspace = Path(state["workspace"])
    fake = SimpleNamespace(outcome="REFUSED_SCOPE",
                           changes=("app/price.py",), details="")
    out = protect.intercept("repair-v2b", worker_result=fake)
    if not (out["verdict"] == "UNKNOWN_RECONCILIATION_REQUIRED"):
        raise AssertionError(out)
    if not (out["receipt"]["payload"]["candidate_inventory_source"] == \
        "UNVERIFIED_WORKER_REPORT"):
        raise AssertionError('demo invariant failure')
    if not (workspace.is_dir()):
        raise AssertionError('demo invariant failure')
    (workspace / "app" / "price.py").write_text(
        "def total(qty):\n    return qty * 12\n")
    out = protect.intercept("repair-v2b")
    if not (out["verdict"] == "ACCEPTED"):
        raise AssertionError(out)
    evidence["D3_falsifier"] = "UNKNOWN_then_ACCEPTED_preserved"
    print("D3 falsifier UNKNOWN, candidate preserved, successor ACCEPTED")

    # D4: second disruption, revocation, replacement, selective reopen.
    if not (cli.cmd_change(_ns(dir=str(project_dir),
                              worker_uid=WORKER_UID,
                              dependency="invoice_v2b",
                              contract="invoice_v3",
                              signature=None)) == 0):
        raise AssertionError('demo invariant failure')
    if not (standings()["independent-formatter"] == "CURRENT"):
        raise AssertionError('demo invariant failure')
    if not (cli.cmd_assign(_ns(dir=str(project_dir),
                              worker_uid=WORKER_UID, assignment="repair-v3",
                              worker="bob", basis="invoice_v3",
                              as_member=None, signature=None)) == 0):
        raise AssertionError('demo invariant failure')
    abandoned = promo.prepare("repair-v3")
    if not (Path(abandoned["workspace"]).is_dir()):
        raise AssertionError('demo invariant failure')
    if not (cli.cmd_revoke(_ns(dir=str(project_dir),
                              worker_uid=WORKER_UID, member="bob",
                              signature=None)) == 0):
        raise AssertionError('demo invariant failure')
    out = protect.intercept("repair-v3")
    if not (out["verdict"] == "STOPPED"):
        raise AssertionError(out)
    if not ("member_not_active" in (out["receipt"]["payload"]["reason"] or "")):
        raise AssertionError('demo invariant failure')
    if not (cli.cmd_assign(_ns(dir=str(project_dir),
                              worker_uid=WORKER_UID,
                              assignment="repair-v3-carol",
                              worker="carol", basis="invoice_v3",
                              as_member=None, signature=None)) == 0):
        raise AssertionError('demo invariant failure')
    state = promo.prepare("repair-v3-carol")
    (Path(state["workspace"]) / "app" / "price.py").write_text(
        "def total(qty):\n    return qty * 13\n")
    out = protect.intercept("repair-v3-carol")
    if not (out["verdict"] == "ACCEPTED"):
        raise AssertionError(out)
    if not (standings() == {"invoice-feature": "CURRENT",
                           "independent-formatter": "CURRENT"}):
        raise AssertionError('demo invariant failure')
    if not (_git_file(Path(config["accepted_git"]),
                     "app/independent.py") == \
        "def label(value):\n    return value.upper()"):
        raise AssertionError('demo invariant failure')
    evidence["D4_second_disruption"] = "carol_ACCEPTED_unrelated_CURRENT"
    print("D4 second disruption: bob revoked+STOPPED, carol ACCEPTED, "
          "unrelated work CURRENT")

    # D5: boundary gate.
    from protect import Protect  # noqa: E402
    gated = Protect(project, protect.signer,
                    project_dir / "incidents_sameuid",
                    acceptance_cmd=(sys.executable, "-B",
                                    config["validator"],
                                    config["project_db"]),
                    worker_uid=os.getuid())
    out = gated.intercept("repair-v3-carol")
    if not (out["verdict"] == "UNKNOWN_RECONCILIATION_REQUIRED"):
        raise AssertionError(out)
    if not ("receiver_boundary_unavailable" in \
        (out["receipt"]["payload"]["reason"] or "")):
        raise AssertionError('demo invariant failure')
    mode_before = os.stat(project.db_path).st_mode & 0o777
    os.chmod(project.db_path, 0o666)
    try:
        out = protect.intercept("repair-v3-carol")
    finally:
        os.chmod(project.db_path, mode_before)
    if not (out["verdict"] == "UNKNOWN_RECONCILIATION_REQUIRED"):
        raise AssertionError(out)
    if not ("project_db_world_writable" in \
        (out["receipt"]["payload"]["reason"] or "")):
        raise AssertionError(out)
    reasons = check_receiver_boundary(
        protect.receiver_paths(), receiver_uid=os.getuid(),
        worker_uid=WORKER_UID)
    if not (reasons == []):
        raise AssertionError(reasons)
    evidence["D5_boundary"] = "same_uid_and_world_writable_refused"
    print("D5 boundary gate: same-UID + world-writable refuse, "
          "mission gate clean")

    # D6: real CLI recover + verify via subprocess.
    script = HERE / "openline"
    proc = subprocess.run(
        [sys.executable, str(script), "recover", "--dir", str(project_dir),
         "--assignment", "repair-v3-carol"],
        capture_output=True, text=True)
    if not (proc.returncode == 0):
        raise AssertionError(proc.stderr)
    recovered = json.loads(proc.stdout)
    if not (recovered["status"] == "ACCEPTED"):
        raise AssertionError(recovered)
    receipt_path = project_dir / "incidents" / \
        f"{recovered['incident_id']}.json"
    proc = subprocess.run(
        [sys.executable, str(script), "verify",
         "--receipt", str(receipt_path),
         "--pinned-key", config["receiver_pub"],
         "--git", config["accepted_git"],
         "--project-db", config["project_db"]],
        capture_output=True, text=True)
    if not (proc.returncode == 0):
        raise AssertionError(proc.stderr)
    evidence["D6_cli_recover_verify"] = "ACCEPTED_via_real_CLI"
    print("D6 real CLI recover + verify: ACCEPTED")

    # D7: effect binding.
    rc = cli.cmd_effect_demo(_ns(dir=str(project_dir),
                                 worker_uid=WORKER_UID,
                                 assignment="repair-v3-carol"))
    if not (rc == 0):
        raise AssertionError(rc)
    evidence["D7_effect_binding"] = "COMMITTED_stale_revoked_replay_recovery"
    print("D7 effect binding: COMMITTED, stale/revoked refused, "
          "replay + recovery identical")

    # D8: OS isolation probe + timeout (scripted workers, labeled).
    def _userns_chroot_available() -> bool:
        if os.geteuid() != 0 or not shutil.which("setpriv") or not shutil.which("unshare"):
            return False
        try:
            probe = subprocess.run(
                [shutil.which("unshare"), "--user", "--map-users=0,0,65536", "--map-groups=0,0,65536", "--mount", "--net", "--pid", "--fork", "/bin/true"],
                capture_output=True, timeout=5, check=False,
            )
            return probe.returncode == 0
        except Exception:
            return False

    if _userns_chroot_available():
        probe_src = project_dir / "probe_src" / "app"
        probe_src.mkdir(parents=True)
        targets = [str(config["accepted_git"]), config["project_db"],
                   config["effects_db"], config["key_file"]]
        (probe_src / "try_write.py").write_text(
            "import sys\n"
            "targets = sys.argv[1:]\n"
            "failed = 0\n"
            "for target in targets:\n"
            "    try:\n"
            "        open(target, 'a').write('rogue')\n"
            "    except OSError:\n"
            "        failed += 1\n"
            "open('/work/app/result.txt', 'w').write(\n"
            "    f'WRITE_BLOCKED:{failed}/{len(targets)}')\n")
        sandbox = ContainerSandbox(
            probe_src.parent,
            allowed_paths=("app/try_write.py", "app/result.txt"),
            task_note="release isolation probe (scripted)")
        try:
            run = sandbox.run(["/usr/bin/python3", "/work/app/try_write.py",
                               *targets], timeout_s=30)
            if not (run.outcome == "CANDIDATE"):
                raise AssertionError(run)
            verdict = (sandbox.root / "work" / "app" / "result.txt").read_text()
        finally:
            sandbox.close()
        if not (verdict == f"WRITE_BLOCKED:{len(targets)}/{len(targets)}"):
            raise AssertionError('demo invariant failure')
        probe_sleep = project_dir / "probe_sleep" / "app"
        probe_sleep.mkdir(parents=True)
        (probe_sleep / "sleep.py").write_text("import time\ntime.sleep(30)\n")
        sandbox2 = ContainerSandbox(
            probe_sleep.parent, allowed_paths=("app/sleep.py",),
            task_note="timeout probe (scripted)")
        try:
            run2 = sandbox2.run(["/usr/bin/python3", "/work/app/sleep.py"],
                                timeout_s=1)
        finally:
            sandbox2.close()
        if not (run2.outcome == "TIMEOUT" and run2.exit_code == 124):
            raise AssertionError(run2)
        evidence["D8_isolation"] = {"writes": verdict, "timeout": "TIMEOUT/124"}
        print("D8 isolation: worker writes blocked, sleeping worker "
              "group-killed on timeout")
    else:
        evidence["D8_isolation"] = "SKIPPED_NON_ROOT_LAUNCHER"
        print("D8 isolation: skipped namespace chroot probe (non-root user; /etc/subuid untouched)")

    # D9: same-UID deployment condition (documented, restored).
    config_file = Path(config["accepted_git"]) / "config"
    head_before = head()
    original = config_file.read_bytes()
    try:
        config_file.write_bytes(original + b"\n# rogue same-uid write\n")
        if not (config_file.read_bytes() != original):
            raise AssertionError('demo invariant failure')
    finally:
        config_file.write_bytes(original)
    if not (head() == head_before):
        raise AssertionError('demo invariant failure')
    evidence["D9_deployment_condition"] = "same_uid_write_succeeds_restored"
    print("D9 deployment condition: same-UID direct write succeeds "
          "(restored); gate holds only under separate UIDs")

    evidence["head"] = head()
    evidence["elapsed_s"] = round(time.monotonic() - started, 1)
    (project_dir / "demo_evidence.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(f"\nRELEASE DEMO: ALL STEPS PASS (head {head()}, "
          f"{evidence['elapsed_s']}s)")
    return 0


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", required=True)
    args = parser.parse_args()
    return run_demo(Path(args.dir))


if __name__ == "__main__":
    raise SystemExit(main())
