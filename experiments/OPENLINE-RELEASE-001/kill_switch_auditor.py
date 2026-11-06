"""Independent offline auditor for OpenLine Kill Switch hash-chained JSONL evidence.

Implements Invariant 12 of `terryncew/openline-kill-switch/portable/GATE_CONTRACT.md`:
- Verifies monotonic sequence numbers (`1..N`) and SHA-256 hash chain starting from `"GENESIS"`.
- Requires both `DECISION` and `EFFECT_STORE_CHECK` records to classify any path.
- Classifies each path as `STOPPED`, `ESCAPED`, `PRE_STOP_COMMIT`, `FRESH_POST_STOP_COMMIT`,
  `FORBIDDEN`, or `UNKNOWN`. Never labels `UNKNOWN` as `STOPPED`.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


def _canonical_bytes(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def audit_evidence_file(path: str | Path) -> dict:
    p = Path(path)
    if not p.is_file():
        return {"chain": "MISSING_FILE", "valid": False, "verdicts": {}, "races": {}}
    try:
        raw_text = p.read_text(encoding="utf-8").strip()
    except OSError:
        return {"chain": "UNREADABLE_FILE", "valid": False, "verdicts": {}, "races": {}}
    if not raw_text:
        return {"chain": "EMPTY_FILE", "valid": False, "verdicts": {}, "races": {}}

    lines = [line for line in raw_text.splitlines() if line.strip()]
    prev = "GENESIS"
    decisions: dict[str, dict] = {}
    checks: dict[str, dict] = {}
    prelim_admits: dict[str, dict] = {}
    stops: list[dict] = []

    for idx, line in enumerate(lines, start=1):
        try:
            rec = json.loads(line)
        except (ValueError, TypeError):
            return {"chain": "INVALID_JSON", "valid": False, "failed_line": idx, "verdicts": {}, "races": {}}
        if not isinstance(rec, dict):
            return {"chain": "INVALID_RECORD", "valid": False, "failed_line": idx, "verdicts": {}, "races": {}}
        claimed_hash = rec.get("hash")
        body = {k: v for k, v in rec.items() if k != "hash"}
        expected_hash = hashlib.sha256(_canonical_bytes(body)).hexdigest()
        if rec.get("seq") != idx or rec.get("prev") != prev or claimed_hash != expected_hash:
            return {
                "chain": "CHAIN_TAMPERED",
                "valid": False,
                "failed_seq": idx,
                "verdicts": {},
                "races": {},
            }
        prev = claimed_hash
        rtype = rec.get("type")
        label = str(rec.get("label", ""))
        payload = rec.get("payload") if isinstance(rec.get("payload"), dict) else {}
        if rtype == "DECISION":
            decisions[label] = rec
        elif rtype == "EFFECT_STORE_CHECK":
            checks[label] = rec
        elif rtype == "PRELIMINARY_ADMIT":
            prelim_admits[label] = rec
        elif rtype == "STOP_ISSUED":
            stops.append(rec)

    labels = sorted((set(decisions) | set(checks)) - {"STOP", "CLEAR", "INIT"})
    verdicts: dict[str, str] = {}
    races: dict[str, dict] = {}

    for label in labels:
        d_rec = decisions.get(label)
        c_rec = checks.get(label)
        if d_rec is None or c_rec is None:
            verdicts[label] = "UNKNOWN"
            continue
        dp = d_rec.get("payload", {})
        cp = c_rec.get("payload", {})
        decision = dp.get("decision")
        present = cp.get("present")
        stop_seq = dp.get("stop_seq", 0)
        commit_seq = dp.get("commit_seq")
        attempt_seq = dp.get("attempt_seq")
        issued_seq = dp.get("issued_seq", 0)
        post_stop_override = bool(dp.get("post_stop_override", False))

        if not isinstance(present, bool):
            verdicts[label] = "UNKNOWN"
        elif decision == "REFUSE" and present is False:
            verdicts[label] = "STOPPED"
        elif decision == "REFUSE" and present is True:
            verdicts[label] = "ESCAPED"
        elif decision == "COMMIT" and present is True:
            if type(stop_seq) is int and stop_seq > 0:
                if post_stop_override and type(issued_seq) is int and issued_seq > stop_seq:
                    verdicts[label] = "FRESH_POST_STOP_COMMIT"
                elif type(commit_seq) is int and commit_seq < stop_seq:
                    verdicts[label] = "PRE_STOP_COMMIT"
                else:
                    verdicts[label] = "FORBIDDEN"
            else:
                verdicts[label] = "PRE_STOP_COMMIT"
        else:
            verdicts[label] = "UNKNOWN"

        if label.startswith("RACE"):
            # Reconcile against the final STOP_ISSUED event in this race log if stop_seq was recorded after commit
            race_stop_seq = stop_seq
            if stops:
                last_stop_seq = stops[-1].get("payload", {}).get("stop_seq")
                if type(last_stop_seq) is int and last_stop_seq > 0:
                    race_stop_seq = last_stop_seq
            ordering = "UNKNOWN"
            if verdicts[label] == "STOPPED":
                if type(race_stop_seq) is int and type(attempt_seq) is int and race_stop_seq < attempt_seq:
                    ordering = "STOP_BEFORE_FINALIZE_REFUSED"
                else:
                    ordering = "FORBIDDEN"
            elif verdicts[label] == "PRE_STOP_COMMIT":
                if type(commit_seq) is int and type(race_stop_seq) is int and commit_seq < race_stop_seq:
                    ordering = "COMMIT_BEFORE_STOP"
                else:
                    ordering = "FORBIDDEN"
                    verdicts[label] = "FORBIDDEN"
            else:
                ordering = "FORBIDDEN"
            races[label] = {
                "verdict": verdicts[label],
                "ordering": ordering,
                "commit_seq": commit_seq,
                "attempt_seq": attempt_seq,
                "stop_seq": race_stop_seq,
                "present": present,
            }

    return {
        "chain": "VALID",
        "valid": True,
        "record_count": len(lines),
        "head_hash": prev,
        "verdicts": verdicts,
        "preliminary_admits_preserved": {
            k: v.get("payload", {}).get("admit_seq") for k, v in prelim_admits.items()
        },
        "races": races,
    }


def audit_directory(evidence_dir: str | Path) -> dict:
    d = Path(evidence_dir)
    main_file = d / "evidence.jsonl"
    main_report = audit_evidence_file(main_file)
    race_files = sorted(d.glob("evidence_race_*.jsonl"))
    race_reports = {}
    forbidden_races = 0
    for rf in race_files:
        rep = audit_evidence_file(rf)
        race_reports[rf.name] = rep
        if not rep.get("valid"):
            forbidden_races += 1
        for _rlabel, rinfo in rep.get("races", {}).items():
            if rinfo.get("ordering") == "FORBIDDEN" or rinfo.get("verdict") in ("FORBIDDEN", "ESCAPED", "UNKNOWN"):
                forbidden_races += 1

    required_stopped = ("P1", "P2", "P3", "P4", "P5", "P6", "P7")
    vmap = main_report.get("verdicts", {})
    all_stopped_ok = all(vmap.get(p) == "STOPPED" for p in required_stopped)
    c1_pre_ok = vmap.get("C1-PRE") == "PRE_STOP_COMMIT"
    c1_post_ok = vmap.get("C1-POST") == "FRESH_POST_STOP_COMMIT"
    overall_pass = (
        main_report.get("valid") is True
        and all_stopped_ok
        and c1_pre_ok
        and c1_post_ok
        and len(race_files) >= 20
        and forbidden_races == 0
    )
    return {
        "status": "PASS" if overall_pass else "FAIL",
        "main_evidence": main_report,
        "required_paths_stopped": {p: vmap.get(p) for p in required_stopped},
        "controls": {"C1-PRE": vmap.get("C1-PRE"), "C1-POST": vmap.get("C1-POST")},
        "race_count": len(race_files),
        "forbidden_race_count": forbidden_races,
        "races": {k: v.get("races") for k, v in race_reports.items()},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit OpenLine Kill Switch evidence JSONL files.")
    parser.add_argument("--path", required=True, help="Path to evidence.jsonl or evidence directory")
    args = parser.parse_args(argv)
    target = Path(args.path)
    if target.is_dir():
        res = audit_directory(target)
        print(json.dumps(res, indent=2, sort_keys=True))
        return 0 if res.get("status") == "PASS" else 1
    res = audit_evidence_file(target)
    print(json.dumps(res, indent=2, sort_keys=True))
    return 0 if res.get("valid") else 1


if __name__ == "__main__":
    raise SystemExit(main())
