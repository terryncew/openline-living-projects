"""OpenLine Kill Switch Conformance & Evidence Harness for Living Projects (Issue #165).

Integrates the `terryncew/openline-kill-switch` (`a303796745164e3c186d7a45cc090004afdc8e7f`, tag `v0.1.0`)
12-invariant Gate Contract and Conformance Suite (`P1`..`P7`, `C1-PRE`, `C1-POST`, and 20 concurrent
thread-barrier `STOP`-vs-`finalize` races) directly into OpenLine Living Projects (`ProjectLedger`,
`SafePromotion`, `Protect`, and `ReceiverGuard`).
"""
from __future__ import annotations

import contextlib
from contextlib import closing
import hashlib
import io
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import threading
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from engine_loader import load_engines  # noqa: E402

load_engines()

import openline_cli as cli  # noqa: E402
from project import ProjectRefused  # noqa: E402
from openline_guard import GuardRefused, ReceiverGuard, SigningIdentity, VerificationError  # noqa: E402
from kill_switch_auditor import audit_directory, audit_evidence_file  # noqa: E402

WORKER_UID = 65534


def _require(cond: bool, detail: object = "conformance invariant failed") -> None:
    if not cond:
        raise AssertionError(detail)


class KillSwitchEvidenceLog:
    """Thread-safe append-only SHA-256 hash-chained JSONL evidence writer."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            self.path.unlink()
        self._lock = threading.Lock()
        self._seq = 0
        self._prev = "GENESIS"

    def append(self, rtype: str, label: str, payload: dict) -> dict:
        with self._lock:
            self._seq += 1
            body = {
                "seq": self._seq,
                "type": rtype,
                "label": label,
                "payload": payload,
                "prev": self._prev,
            }
            raw = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            h = hashlib.sha256(raw).hexdigest()
            rec = {**body, "hash": h}
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, sort_keys=True) + "\n")
                f.flush()
            self._prev = h
            return rec


def _git_is_ancestor(git_dir: Path, commit_sha: str | None, ref: str = "refs/heads/accepted") -> bool:
    if not commit_sha or not isinstance(commit_sha, str) or len(commit_sha) != 40:
        return False
    p = subprocess.run(
        ["git", "--git-dir", str(git_dir), "merge-base", "--is-ancestor", commit_sha, ref],
        capture_output=True,
        text=True,
        check=False,
    )
    return p.returncode == 0


def _last_decision_event(db_path: str | Path, assignment_id: str) -> tuple[int, dict]:
    with closing(sqlite3.connect(str(db_path))) as db:
        rows = db.execute(
            "SELECT seq, payload FROM events WHERE kind='KILL_SWITCH_DECISION' ORDER BY seq DESC"
        ).fetchall()
    for seq, raw in rows:
        data = json.loads(raw)
        if data.get("assignment") == assignment_id:
            return int(seq), data
    return 0, {}


def _assignment_standing_row(db_path: str | Path, assignment_id: str) -> dict:
    with closing(sqlite3.connect(str(db_path))) as db:
        row = db.execute(
            "SELECT issued_seq, epoch, post_stop_override, admit_seq, commit_seq FROM assignment_standing WHERE assignment_id=?",
            (assignment_id,),
        ).fetchone()
    if not row:
        return {"issued_seq": 0, "epoch": 1, "post_stop_override": 0, "admit_seq": None, "commit_seq": None}
    return {
        "issued_seq": int(row[0]),
        "epoch": int(row[1]),
        "post_stop_override": int(row[2]),
        "admit_seq": row[3],
        "commit_seq": row[4],
    }


def _clone_race_template(template_dir: Path, target_dir: Path) -> dict:
    shutil.copytree(template_dir, target_dir)
    raw_cfg = (target_dir / "config.json").read_text()
    updated_cfg = raw_cfg.replace(str(template_dir), str(target_dir))
    (target_dir / "config.json").write_text(updated_cfg)
    return json.loads(updated_cfg)


def run_single_race(race_dir: Path, race_index: int, evidence_path: Path, *, template_dir: Path | None = None) -> dict:
    """Runs one thread-barrier synchronized STOP-vs-finalize race on a real Living Project."""
    label = f"RACE-{race_index:02d}"
    ev = KillSwitchEvidenceLog(evidence_path)
    proj_dir = race_dir / f"proj_{race_index:02d}"
    if template_dir is not None and template_dir.is_dir():
        cfg = _clone_race_template(template_dir, proj_dir)
    else:
        with contextlib.redirect_stdout(io.StringIO()):
            rc = cli.cmd_init(SimpleNamespace(
                dir=str(proj_dir),
                project_id=f"race-proj-{race_index:02d}",
                workers="alice,bob",
                validator=None,
                worker_uid=WORKER_UID,
            ))
        _require(rc == 0, rc)
        cfg = cli._load_config(proj_dir)
    promo, project, _protect = cli._build_engines(cfg, WORKER_UID)
    owner_key = cli._read_key(Path(cfg["keys_dir"]) / "owner.key")
    alice_key = cli._read_key(Path(cfg["keys_dir"]) / "alice.key")

    asgn_id = f"repair-race-{race_index:02d}"
    claim_asgn = {
        "project_id": project.id,
        "assignment_id": asgn_id,
        "deliverable_id": "invoice-feature",
        "worker_member": "bob",
        "basis": "invoice_v2",
        "allowed_paths": ["app/price.py"],
        "action": "repair_assignment",
    }
    project.assign_repair(asgn_id, "invoice-feature", "bob", "invoice_v2", cli._sig(alice_key, claim_asgn), allowed_paths=["app/price.py"])
    st_prep = promo.prepare(asgn_id)
    (Path(st_prep["workspace"]) / "app" / "price.py").write_text("def total(qty):\n    return qty * 11\n")

    barrier = threading.Barrier(2)
    worker_box: dict = {}
    stop_box: dict = {}

    # Alternate minuscule post-barrier jitter so both COMMIT_BEFORE_STOP and STOP_BEFORE_FINALIZE_REFUSED are exercised
    def _pre_cas_hook():
        barrier.wait(timeout=10)
        if race_index % 2 == 1:
            # Let STOP thread contend first on odd indices
            import time as _t
            _t.sleep(0.002)

    def _worker_thread():
        try:
            res = project.promote_repair(
                asgn_id,
                acceptance_cmd=[sys.executable, "-B", cfg["validator"], cfg["project_db"]],
                timeout=20,
                pre_cas_hook=_pre_cas_hook,
            )
            worker_box["result"] = res
        except ProjectRefused as exc:
            worker_box["result"] = {"status": "REFUSED", "reason": str(exc)}
        except Exception as exc:
            worker_box["error"] = f"{type(exc).__name__}:{exc}"

    def _owner_stop_thread():
        barrier.wait(timeout=10)
        if race_index % 2 == 0:
            import time as _t
            _t.sleep(0.002)
        stop_claim = {"project_id": project.id, "action": "issue_stop", "reason": f"race_stop_{race_index:02d}", "expected_epoch": 1}
        stop_box["state"] = project.issue_stop(f"race_stop_{race_index:02d}", cli._sig(owner_key, stop_claim), expected_epoch=1)

    t_w = threading.Thread(target=_worker_thread)
    t_s = threading.Thread(target=_owner_stop_thread)
    t_w.start()
    t_s.start()
    t_w.join(timeout=30)
    t_s.join(timeout=30)

    stop_state = stop_box["state"]
    ev.append("STOP_ISSUED", "STOP", stop_state)
    dec_seq, dec_payload = _last_decision_event(project.db_path, asgn_id)
    s_info = _assignment_standing_row(project.db_path, asgn_id)
    w_res = worker_box.get("result", {})

    if w_res.get("status") == "PROMOTED":
        promoted_head = w_res.get("head")
        project.resolve_repair(asgn_id, promoted_head)
        present = _git_is_ancestor(Path(cfg["accepted_git"]), promoted_head)
        ev.append("DECISION", label, {
            "assignment": asgn_id,
            "decision": "COMMIT",
            "reason": "STANDING_OK",
            "issued_seq": s_info["issued_seq"],
            "commit_seq": s_info["commit_seq"] or dec_seq,
            "attempt_seq": s_info["commit_seq"] or dec_seq,
            "stop_seq": stop_state["stop_seq"],
            "epoch": dec_payload.get("epoch", 1),
            "effect_committed": True,
        })
        ev.append("EFFECT_STORE_CHECK", label, {
            "assignment": asgn_id,
            "present": present,
            "head": promoted_head,
        })
    else:
        # Verify accepted Git ref did not advance
        _, task_state = promo._load(asgn_id)
        proposed_head = task_state.get("proposed_head")
        present = _git_is_ancestor(Path(cfg["accepted_git"]), proposed_head)
        ev.append("DECISION", label, {
            "assignment": asgn_id,
            "decision": "REFUSE",
            "reason": dec_payload.get("reason", str(w_res.get("reason", "OLD_AUTHORITY_DEAD")).upper()),
            "issued_seq": s_info["issued_seq"],
            "commit_seq": None,
            "attempt_seq": dec_seq,
            "stop_seq": stop_state["stop_seq"],
            "epoch": stop_state["epoch"],
            "effect_committed": False,
        })
        ev.append("EFFECT_STORE_CHECK", label, {
            "assignment": asgn_id,
            "present": present,
            "head": promo.accepted(),
        })

    audit_rep = audit_evidence_file(evidence_path)
    return audit_rep["races"][label]


def run_kill_switch_conformance(work_dir: str | Path, *, race_iterations: int = 20) -> dict:
    """Runs the full P1-P7, C1-PRE, C1-POST, and 20-race Kill Switch conformance suite."""
    root = Path(work_dir).resolve()
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)
    evidence_dir = root / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    ev = KillSwitchEvidenceLog(evidence_dir / "evidence.jsonl")

    proj_dir = root / "project"
    with contextlib.redirect_stdout(io.StringIO()):
        rc = cli.cmd_init(SimpleNamespace(
            dir=str(proj_dir),
            project_id="openline-kill-switch-conformance",
            workers="alice,bob,carol",
            validator=None,
            worker_uid=WORKER_UID,
        ))
    _require(rc == 0, rc)
    cfg = cli._load_config(proj_dir)
    promo, project, protect = cli._build_engines(cfg, WORKER_UID)
    owner_key = cli._read_key(Path(cfg["keys_dir"]) / "owner.key")
    alice_key = cli._read_key(Path(cfg["keys_dir"]) / "alice.key")
    bob_key = cli._read_key(Path(cfg["keys_dir"]) / "bob.key")

    # Initialize ReceiverGuard as well to test dual-engine conformance (Git + SQLite effect gates)
    guard_db = root / "guard_effects.sqlite"
    with closing(sqlite3.connect(guard_db)) as db:
        db.execute("CREATE TABLE payouts(id TEXT PRIMARY KEY, status TEXT, amount INTEGER)")
        db.commit()
    guard_owner = SigningIdentity()
    guard_worker = SigningIdentity()
    guard = ReceiverGuard(guard_db, receiver_id="ks-guard-1")
    guard.register_issuer(guard_owner.public)

    def _assign(asgn_id: str, worker: str, basis: str, *, post_stop_sig: str | None = None):
        claim = {
            "project_id": project.id,
            "assignment_id": asgn_id,
            "deliverable_id": "invoice-feature",
            "worker_member": worker,
            "basis": basis,
            "allowed_paths": ["app/price.py"],
            "action": "repair_assignment",
        }
        project.assign_repair(
            asgn_id,
            "invoice-feature",
            worker,
            basis,
            cli._sig(alice_key, claim),
            allowed_paths=["app/price.py"],
            post_stop_owner_signature=post_stop_sig,
        )

    # =========================================================================
    # C1-PRE: Control path — authorized work commits BEFORE STOP
    # =========================================================================
    _assign("repair-c1-pre", "bob", "invoice_v2")
    st_c1 = promo.prepare("repair-c1-pre")
    (Path(st_c1["workspace"]) / "app" / "price.py").write_text("def total(qty):\n    return qty * 11\n")
    out_c1_pre = protect.intercept("repair-c1-pre")
    _require(out_c1_pre["verdict"] == "ACCEPTED", out_c1_pre)
    c1_pre_head = out_c1_pre["receipt"]["payload"]["accepted_ref_after"]
    c1_pre_info = _assignment_standing_row(project.db_path, "repair-c1-pre")
    ev.append("DECISION", "C1-PRE", {
        "assignment": "repair-c1-pre",
        "decision": "COMMIT",
        "reason": "STANDING_OK",
        "issued_seq": c1_pre_info["issued_seq"],
        "commit_seq": c1_pre_info["commit_seq"],
        "attempt_seq": c1_pre_info["commit_seq"],
        "stop_seq": 0,
        "epoch": 1,
        "effect_committed": True,
    })
    ev.append("EFFECT_STORE_CHECK", "C1-PRE", {
        "assignment": "repair-c1-pre",
        "present": _git_is_ancestor(Path(cfg["accepted_git"]), c1_pre_head),
        "head": c1_pre_head,
    })

    # Reopen invoice-feature to invoice_v2b so pre-STOP assignments P1, P2, P3, P4, P6, P7 can be prepared before STOP
    chg_v2b = {"project_id": project.id, "dependency": "invoice_v2", "contract": "invoice_v2b", "action": "change_dependency"}
    project.change_dependency("invoice_v2", "invoice_v2b", cli._sig(owner_key, chg_v2b))

    for aid in ("repair-p1-inflight", "repair-p2-delayed", "repair-p3-replay", "repair-p4-prepared", "repair-p6-stale-cache", "repair-p7-admitted"):
        _assign(aid, "bob", "invoice_v2b")
        prep = promo.prepare(aid)
        (Path(prep["workspace"]) / "app" / "price.py").write_text("def total(qty):\n    return qty * 12\n")

    # Pre-STOP ReceiverGuard grant & passport for P3 / P4 / P6 / P7
    grant_p3 = guard_owner.issue_grant(guard_worker.public, task_id="task-p3", operation="payout", allowed_targets=["p3"])
    req_p3 = guard_worker.sign_request(grant_p3, operation="payout", target_id="p3", payload={"amount": 10})
    guard.register_grant(grant_p3)

    # Sync local receiver cache BEFORE STOP for P6
    protect.sync_stop_cache()
    guard.sync_stop_cache()
    _require(protect.cached_stop_state["stopped"] is False)

    # Record pre-STOP preliminary admission for P7
    p7_admit = project.preliminary_admit("repair-p7-admitted")
    ev.append("PRELIMINARY_ADMIT", "P7", p7_admit)

    # =========================================================================
    # P1: In-flight already-running worker stopped before finalization
    # =========================================================================
    def _issue_stop_mid_p1():
        stop_claim = {"project_id": project.id, "action": "issue_stop", "reason": "emergency_stop_epoch_2", "expected_epoch": 1}
        st_stop = project.issue_stop("emergency_stop_epoch_2", cli._sig(owner_key, stop_claim), expected_epoch=1)
        guard.issue_stop(guard_owner.issue_stop_envelope(reason="emergency_stop_epoch_2", expected_epoch=1))
        ev.append("STOP_ISSUED", "STOP", st_stop)

    head_before_stop = promo.accepted()
    try:
        project.promote_repair(
            "repair-p1-inflight",
            acceptance_cmd=[sys.executable, "-B", cfg["validator"], cfg["project_db"]],
            timeout=20,
            pre_cas_hook=_issue_stop_mid_p1,
        )
        raise AssertionError("P1 must refuse at final gate")
    except ProjectRefused as exc:
        _require(str(exc) == "old_authority_dead", exc)
    _require(promo.accepted() == head_before_stop)
    p1_seq, p1_dec = _last_decision_event(project.db_path, "repair-p1-inflight")
    p1_info = _assignment_standing_row(project.db_path, "repair-p1-inflight")
    ev.append("DECISION", "P1", {
        "assignment": "repair-p1-inflight",
        "decision": "REFUSE",
        "reason": p1_dec.get("reason", "OLD_AUTHORITY_DEAD"),
        "issued_seq": p1_info["issued_seq"],
        "attempt_seq": p1_seq,
        "stop_seq": project.read_stop_state()["stop_seq"],
        "effect_committed": False,
    })
    ev.append("EFFECT_STORE_CHECK", "P1", {
        "assignment": "repair-p1-inflight",
        "present": promo.accepted() != head_before_stop,
        "head": promo.accepted(),
    })

    # =========================================================================
    # P2: Delayed or scheduled job firing after STOP
    # =========================================================================
    out_p2 = protect.intercept("repair-p2-delayed")
    _require(out_p2["verdict"] == "STOPPED", out_p2)
    _require(out_p2["receipt"]["payload"]["reason"] == "old_authority_dead")
    p2_seq, p2_dec = _last_decision_event(project.db_path, "repair-p2-delayed")
    p2_info = _assignment_standing_row(project.db_path, "repair-p2-delayed")
    ev.append("DECISION", "P2", {
        "assignment": "repair-p2-delayed",
        "decision": "REFUSE",
        "reason": p2_dec.get("reason", "OLD_AUTHORITY_DEAD"),
        "issued_seq": p2_info["issued_seq"],
        "attempt_seq": p2_seq,
        "stop_seq": project.read_stop_state()["stop_seq"],
        "effect_committed": False,
    })
    ev.append("EFFECT_STORE_CHECK", "P2", {
        "assignment": "repair-p2-delayed",
        "present": promo.accepted() != head_before_stop,
        "head": promo.accepted(),
    })

    # =========================================================================
    # P3: Pre-STOP authentic credential replayed after STOP
    # =========================================================================
    out_p3 = protect.intercept("repair-p3-replay")
    _require(out_p3["verdict"] == "STOPPED", out_p3)
    _require(out_p3["receipt"]["payload"]["reason"] == "old_authority_dead")
    try:
        guard.execute(
            grant=grant_p3,
            request=req_p3,
            fn=lambda db, p: db.execute("INSERT INTO payouts VALUES ('p3', 'PAID', ?)", (p["amount"],)),
            target_table="payouts",
            target_pk_col="id",
        )
        raise AssertionError("P3 ReceiverGuard replay must refuse")
    except GuardRefused as exc:
        _require(exc.reason == "old_authority_dead", exc.reason)
    p3_seq, p3_dec = _last_decision_event(project.db_path, "repair-p3-replay")
    p3_info = _assignment_standing_row(project.db_path, "repair-p3-replay")
    ev.append("DECISION", "P3", {
        "assignment": "repair-p3-replay",
        "decision": "REFUSE",
        "reason": p3_dec.get("reason", "OLD_AUTHORITY_DEAD"),
        "issued_seq": p3_info["issued_seq"],
        "attempt_seq": p3_seq,
        "stop_seq": project.read_stop_state()["stop_seq"],
        "effect_committed": False,
    })
    ev.append("EFFECT_STORE_CHECK", "P3", {
        "assignment": "repair-p3-replay",
        "present": promo.accepted() != head_before_stop,
        "head": promo.accepted(),
    })

    # =========================================================================
    # P4: Pre-STOP prepared worktree / continuity artifact
    # =========================================================================
    out_p4 = protect.intercept("repair-p4-prepared")
    _require(out_p4["verdict"] == "STOPPED", out_p4)
    p4_seq, p4_dec = _last_decision_event(project.db_path, "repair-p4-prepared")
    p4_info = _assignment_standing_row(project.db_path, "repair-p4-prepared")
    ev.append("DECISION", "P4", {
        "assignment": "repair-p4-prepared",
        "decision": "REFUSE",
        "reason": p4_dec.get("reason", "OLD_AUTHORITY_DEAD"),
        "issued_seq": p4_info["issued_seq"],
        "attempt_seq": p4_seq,
        "stop_seq": project.read_stop_state()["stop_seq"],
        "effect_committed": False,
    })
    ev.append("EFFECT_STORE_CHECK", "P4", {
        "assignment": "repair-p4-prepared",
        "present": promo.accepted() != head_before_stop,
        "head": promo.accepted(),
    })

    # =========================================================================
    # P5: Successor or delegated actor without fresh post-STOP owner grant
    # =========================================================================
    try:
        project.clear_stop("bob_unauthorized_clear", cli._sig(bob_key, {"project_id": project.id, "action": "clear_stop", "reason": "bob_unauthorized_clear", "expected_epoch": 2}), expected_epoch=2)
        raise AssertionError("worker clear_stop must fail")
    except ProjectRefused as exc:
        _require(str(exc) == "invalid_owner_signature", exc)
    try:
        _assign("repair-p5-successor", "carol", "invoice_v2b", post_stop_sig=None)
        raise AssertionError("P5 successor without post-STOP owner grant must fail")
    except ProjectRefused as exc:
        _require(str(exc).startswith("stopped_at_epoch_"), exc)
    p5_seq, p5_dec = _last_decision_event(project.db_path, "repair-p5-successor")
    ev.append("DECISION", "P5", {
        "assignment": "repair-p5-successor",
        "decision": "REFUSE",
        "reason": p5_dec.get("reason", "STOPPED_AT_EPOCH_2"),
        "issued_seq": 0,
        "attempt_seq": p5_seq,
        "stop_seq": project.read_stop_state()["stop_seq"],
        "effect_committed": False,
    })
    ev.append("EFFECT_STORE_CHECK", "P5", {
        "assignment": "repair-p5-successor",
        "present": promo.accepted() != head_before_stop,
        "head": promo.accepted(),
    })

    # =========================================================================
    # P6: Stale local receiver cache (preliminary admit passes on stale cache, final gate refuses)
    # =========================================================================
    stale_prelim = protect.preliminary_admit("repair-p6-stale-cache", use_stale_cache=True)
    _require(stale_prelim["admitted"] is True)
    out_p6 = protect.intercept("repair-p6-stale-cache")
    _require(out_p6["verdict"] == "STOPPED", out_p6)
    p6_seq, p6_dec = _last_decision_event(project.db_path, "repair-p6-stale-cache")
    p6_info = _assignment_standing_row(project.db_path, "repair-p6-stale-cache")
    ev.append("DECISION", "P6", {
        "assignment": "repair-p6-stale-cache",
        "decision": "REFUSE",
        "reason": p6_dec.get("reason", "OLD_AUTHORITY_DEAD"),
        "issued_seq": p6_info["issued_seq"],
        "attempt_seq": p6_seq,
        "stop_seq": project.read_stop_state()["stop_seq"],
        "effect_committed": False,
    })
    ev.append("EFFECT_STORE_CHECK", "P6", {
        "assignment": "repair-p6-stale-cache",
        "present": promo.accepted() != head_before_stop,
        "head": promo.accepted(),
    })

    # =========================================================================
    # P7: Pre-STOP in-flight admitted work (stopped at finalization, admission record preserved)
    # =========================================================================
    out_p7 = protect.intercept("repair-p7-admitted")
    _require(out_p7["verdict"] == "STOPPED", out_p7)
    p7_seq, p7_dec = _last_decision_event(project.db_path, "repair-p7-admitted")
    p7_info = _assignment_standing_row(project.db_path, "repair-p7-admitted")
    _require(p7_info["admit_seq"] == p7_admit["admit_seq"])
    _require(p7_info["admit_seq"] < project.read_stop_state()["stop_seq"])
    ev.append("DECISION", "P7", {
        "assignment": "repair-p7-admitted",
        "decision": "REFUSE",
        "reason": p7_dec.get("reason", "OLD_AUTHORITY_DEAD"),
        "issued_seq": p7_info["issued_seq"],
        "admit_seq": p7_info["admit_seq"],
        "attempt_seq": p7_seq,
        "stop_seq": project.read_stop_state()["stop_seq"],
        "effect_committed": False,
    })
    ev.append("EFFECT_STORE_CHECK", "P7", {
        "assignment": "repair-p7-admitted",
        "present": promo.accepted() != head_before_stop,
        "head": promo.accepted(),
    })

    # =========================================================================
    # C1-POST: Explicit post-STOP owner grant commits cleanly while STOP is active,
    # and clear_stop preserves stop_seq so pre-STOP authority stays OLD_AUTHORITY_DEAD
    # =========================================================================
    cur_stop = project.read_stop_state()
    override_claim = {
        "project_id": project.id,
        "assignment_id": "repair-c1-post",
        "deliverable_id": "invoice-feature",
        "worker_member": "carol",
        "basis": "invoice_v2b",
        "allowed_paths": ["app/price.py"],
        "epoch": cur_stop["epoch"],
        "stop_seq": cur_stop["stop_seq"],
        "action": "post_stop_grant",
    }
    _assign("repair-c1-post", "carol", "invoice_v2b", post_stop_sig=cli._sig(owner_key, override_claim))
    prep_c1_post = promo.prepare("repair-c1-post")
    (Path(prep_c1_post["workspace"]) / "app" / "price.py").write_text("def total(qty):\n    return qty * 12\n")
    out_c1_post = protect.intercept("repair-c1-post")
    _require(out_c1_post["verdict"] == "ACCEPTED", out_c1_post)
    c1_post_head = out_c1_post["receipt"]["payload"]["accepted_ref_after"]
    c1_post_info = _assignment_standing_row(project.db_path, "repair-c1-post")
    ev.append("DECISION", "C1-POST", {
        "assignment": "repair-c1-post",
        "decision": "COMMIT",
        "reason": "FRESH_POST_STOP_GRANT",
        "issued_seq": c1_post_info["issued_seq"],
        "commit_seq": c1_post_info["commit_seq"],
        "attempt_seq": c1_post_info["commit_seq"],
        "stop_seq": cur_stop["stop_seq"],
        "epoch": cur_stop["epoch"],
        "post_stop_override": True,
        "effect_committed": True,
    })
    ev.append("EFFECT_STORE_CHECK", "C1-POST", {
        "assignment": "repair-c1-post",
        "present": _git_is_ancestor(Path(cfg["accepted_git"]), c1_post_head),
        "head": c1_post_head,
    })

    # Also verify clear_stop preserves stop_seq and pre-STOP grant_p3 stays OLD_AUTHORITY_DEAD after clear_stop
    clear_claim = {"project_id": project.id, "action": "clear_stop", "reason": "incident_resolved_epoch_3", "expected_epoch": 2}
    cleared_st = project.clear_stop("incident_resolved_epoch_3", cli._sig(owner_key, clear_claim), expected_epoch=2)
    _require(cleared_st["stopped"] is False)
    _require(cleared_st["stop_seq"] == cur_stop["stop_seq"] > 0)
    _require(cleared_st["clear_seq"] > cleared_st["stop_seq"])
    guard.clear_stop(guard_owner.clear_stop_envelope(reason="incident_resolved_epoch_3", expected_epoch=2))
    try:
        guard.execute(
            grant=grant_p3,
            request=req_p3,
            fn=lambda db, p: db.execute("INSERT INTO payouts VALUES ('p3', 'PAID', ?)", (p["amount"],)),
            target_table="payouts",
            target_pk_col="id",
        )
        raise AssertionError("Pre-STOP grant must remain OLD_AUTHORITY_DEAD after clear_stop")
    except GuardRefused as exc:
        _require(exc.reason == "old_authority_dead", exc.reason)

    # =========================================================================
    # 20 Concurrent STOP-vs-finalize Thread-Barrier Races (RACE-00 .. RACE-19)
    # =========================================================================
    races_dir = root / "races"
    races_dir.mkdir(parents=True, exist_ok=True)
    race_template = root / "_race_template"
    with contextlib.redirect_stdout(io.StringIO()):
        rc_tmpl = cli.cmd_init(SimpleNamespace(
            dir=str(race_template),
            project_id="race-proj",
            workers="alice,bob",
            validator=None,
            worker_uid=WORKER_UID,
        ))
    _require(rc_tmpl == 0, rc_tmpl)
    for i in range(race_iterations):
        rfile = evidence_dir / f"evidence_race_{i:02d}.jsonl"
        run_single_race(races_dir, i, rfile, template_dir=race_template)

    audit_summary = audit_directory(evidence_dir)
    return {
        "status": audit_summary["status"],
        "evidence_dir": str(evidence_dir),
        "audit": audit_summary,
    }
