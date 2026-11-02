"""Independent pinned-key Ed25519 verification of original Lite receiver receipt.

Uses only cryptography + stdlib. Does not call Lite verifier, trust public keys
embedded in the response, or infer execution permission from COMMIT.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def verify_receipt(receipt_path: Path, trust_path: Path, *,
                   expected_sha256: str | None = None,
                   expected_decision: str | None = None) -> dict:
    raw = receipt_path.read_bytes()
    if expected_sha256 and hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("receipt_original_bytes_mismatch")
    receipt = json.loads(raw)
    if set(receipt) != {"payload", "payload_sha256", "proof"}:
        raise ValueError("receipt_envelope_invalid")
    payload, proof = receipt["payload"], receipt["proof"]
    trust = json.loads(trust_path.read_text())
    if not isinstance(trust, dict) or set(proof) != {"alg", "key_id", "public_key", "signature"}:
        raise ValueError("receipt_proof_invalid")
    key_id = proof["key_id"]
    if proof["alg"] != "Ed25519" or payload.get("gate_id") != key_id:
        raise ValueError("receipt_identity_invalid")
    if key_id not in trust or trust[key_id] != proof["public_key"]:
        raise ValueError("receiver_key_not_pinned")
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")
    if hashlib.sha256(body).hexdigest() != receipt["payload_sha256"]:
        raise ValueError("receipt_payload_hash_invalid")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(trust[key_id])).verify(
            bytes.fromhex(proof["signature"]), body
        )
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("receipt_signature_invalid") from exc
    if payload.get("schema") != "olp.decision.v1":
        raise ValueError("receipt_decision_schema_invalid")
    if expected_decision is not None and payload.get("decision") != expected_decision:
        raise ValueError("receipt_decision_mismatch")
    return {
        "status": "PASS", "signature": "VALID", "gate_id": key_id,
        "decision": payload["decision"], "verdict": payload["verdict"],
        "original_receipt_sha256": hashlib.sha256(raw).hexdigest(),
        "runtime_permission": "NONE",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--pinned-gate-trust", type=Path, required=True)
    parser.add_argument("--expected-sha256")
    args = parser.parse_args()
    try:
        print(json.dumps(verify_receipt(args.receipt, args.pinned_gate_trust,
                                        expected_sha256=args.expected_sha256), sort_keys=True))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "FAIL", "reason": str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
