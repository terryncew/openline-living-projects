"""Create disposable *real OpenLine Lite* signed sample packs, not trusted customer evidence.

No model/provider calls or effects. A fresh local receiver owns the signer, trust
file and policy; this is a demonstration issuer only. Never commit generated keys.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys

from openline_lite.canonical import pretty, sha256_hex
from openline_lite.crypto import generate_private_key_hex, public_key_hex
from openline_lite.wire import SOURCE_SCHEMA, issue_source_receipt


GATE_ID = "local-sample-receiver"
PRODUCER_ID = "local-sample-producer"


def _write(path: Path, value: object, private: bool = False) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    data = pretty(value) if not isinstance(value, str) else value
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600 if private else 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        out.write(data)


def bootstrap(home: Path) -> dict[str, str]:
    """Fail rather than reuse/overwrite an existing receiver configuration."""
    home = home.expanduser().absolute()
    home.mkdir(mode=0o700, parents=True, exist_ok=False)
    if home.is_symlink():
        raise ValueError("operator_home_symlink_forbidden")
    producer_private = generate_private_key_hex()
    gate_private = generate_private_key_hex()
    _write(home / "gate.key", gate_private + "\n", private=True)
    _write(home / "producer-trust.json", {PRODUCER_ID: public_key_hex(producer_private)})
    _write(home / "gate-trust.json", {GATE_ID: public_key_hex(gate_private)})
    issued = datetime.now(timezone.utc).replace(microsecond=0)
    issued_text = issued.isoformat().replace("+00:00", "Z")
    evaluation_time = (issued + timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
    check_profiles: dict[str, str] = {}

    def make_case(label: str, evidence_id: str, evidence: dict, *,
                  required: str | None = None, mismatch: bool = False,
                  missing: bool = False, tamper: bool = False) -> tuple[Path, str]:
        folder = home / "packs" / label
        folder.mkdir(mode=0o700, parents=True, exist_ok=False)
        evid_data = pretty(evidence).encode("utf-8")
        evidence_hash = sha256_hex(evid_data)
        eid = evidence_id
        (folder / "evidence").mkdir(mode=0o700)
        if not missing:
            (folder / "evidence" / (eid + ".json")).write_bytes(
                pretty({**evidence, "passed": False}).encode("utf-8") if tamper else evid_data
            )
        policy = {
            "policy_id": "sample-" + label, "version": "1",
            "allowed_actions": ["evaluate_only"],
            "required_evidence": [required or eid],
            "claim_rules": [{"id": "sample-pass", "evidence_id": eid,
                             "pointer": "/passed", "expected": not mismatch}],
            "max_age_seconds": 3600, "on_undecidable": "QUARANTINE",
            "rollback_supported": False,
        }
        payload = {
            "schema": SOURCE_SCHEMA, "issuer": PRODUCER_ID, "issued_at": issued_text,
            "run_id": "sample-" + label, "sequence": 0,
            "action": {"type": "evaluate_only", "name": "sample " + label},
            "claim": "Local illustrative sample, no external action",
            "evidence": [{"id": eid, "sha256": evidence_hash, "media_type": "application/json"}],
        }
        _write(folder / "source.receipt.json", issue_source_receipt(payload, producer_private, PRODUCER_ID))
        _write(folder / "producer-trust.json", {PRODUCER_ID: public_key_hex(producer_private)})
        _write(folder / "receiver-policy.json", policy)
        _write(folder / "check.json", {
            "schema": "openline.check.v1", "label": "SAMPLE " + label,
            "source": "source.receipt.json", "producer_trust": "producer-trust.json",
            "policy": "receiver-policy.json", "evidence": {eid: "evidence/" + eid + ".json"},
            "now": evaluation_time,
        })
        check_profiles[label] = str(folder / "check.json")
        return folder, evidence_hash

    make_case("commit", "tests", {"passed": True, "commit": "illustrative"})
    make_case("deny", "tests", {"passed": True}, mismatch=True)
    make_case("quarantine", "tests", {"passed": True}, missing=True)
    make_case("tampered-evidence", "tests", {"passed": True}, tamper=True)

    impact_entries = []
    invalidated_hash = None
    for name, completeness in (("code", "COMPLETE"), ("docs", "COMPLETE"), ("notes", "INCOMPLETE")):
        folder, digest = make_case("impact-" + name, name, {"passed": True, "sample": name})
        if name == "code":
            invalidated_hash = digest
        output = folder / "accepted"
        process = subprocess.run(
            [sys.executable, "-m", "openline_lite.check", str(folder / "check.json"),
             "--gate-id", GATE_ID, "--gate-key", str(home / "gate.key"),
             "--output-dir", str(output), "--json"],
            capture_output=True, text=True, timeout=20, check=False,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                 "HOME": str(home), "LANG": "C.UTF-8",
                 "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1"},
        )
        if process.returncode or json.loads(process.stdout).get("decision") != "COMMIT":
            raise RuntimeError("genuine_sample_decision_failed:" + name)
        impact_entries.append({
            "label": name, "binding_completeness": completeness,
            "decision_receipt": "packs/impact-" + name + "/accepted/decision.receipt.json",
            "source_receipt": "packs/impact-" + name + "/source.receipt.json",
        })

    _write(home / "impact-pack.json", {
        "schema": "openline.impact-pack.v1",
        "gate_trust": "gate-trust.json", "producer_trust": "producer-trust.json",
        "decisions": impact_entries, "invalidated_evidence_sha256": [invalidated_hash],
    })
    _write(home / "operator-config.json", {
        "schema": "openline.mcp-entry.operator.v1",
        "check_profiles": check_profiles, "impact_profiles": {"changed-source": str(home / "impact-pack.json")},
        "gate_key": str(home / "gate.key"), "gate_id": GATE_ID,
        "records_dir": str(home / "records"), "timeout_seconds": 20,
    }, private=True)
    return {
        "status": "SAMPLE_READY", "operator_config": str(home / "operator-config.json"),
        "pinned_gate_trust": str(home / "gate-trust.json"),
        "note": "Local generated evidence. Not production acceptance or permission for external effects.",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--home", required=True, help="fresh private directory; never overwritten")
    args = parser.parse_args()
    try:
        print(json.dumps(bootstrap(Path(args.home)), indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(json.dumps({"status": "REFUSED", "reason": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
