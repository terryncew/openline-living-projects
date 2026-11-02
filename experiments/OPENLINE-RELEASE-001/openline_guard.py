"""OpenLine ReceiverGuard: Lightweight Effect-Bound Receiver Gate for Existing Applications.

Solves the Git-worktree integration mismatch identified in independent evaluation by
providing a zero-ceremony SQLite + file receiver gate that enforces:
1. Bound-First Scoped Grants (per-operation, max_amount, allowed_targets, required_basis, upstream_receipt).
2. Dual-Path Signed Receipts via SQLite SAVEPOINT (atomic effect-bound COMMITTED receipts + out-of-rollback REFUSED receipts).
3. Key Rotation Epoch Chaining (offline verification across historical key rotations without re-signing old records).
4. Falsifier-Driven Offline & Live Effect Verification (VERIFIED_CURRENT, VERIFIED_HISTORICAL, REFUSED:effect_missing, REFUSED:effect_mismatch).
5. Portable Task Continuity Passports (zero-redo worker/provider takeover + cross-receiver cryptographic effect chaining).
6. Per-Dependency Selective Reconsideration (reopens only transitively affected targets on contract change).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import time
import uuid
from contextlib import closing
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)


class GuardRefused(PermissionError):
    """Raised when ReceiverGuard refuses an operation; carries the signed refusal receipt."""
    def __init__(self, reason: str, receipt: dict):
        super().__init__(reason)
        self.reason = reason
        self.receipt = receipt


class VerificationError(RuntimeError):
    pass


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes | dict | list | str) -> str:
    if isinstance(data, bytes):
        raw = data
    elif isinstance(data, str):
        raw = data.encode("utf-8")
    else:
        raw = canonical(data)
    return hashlib.sha256(raw).hexdigest()


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * ((-len(text)) % 4))


def sign_envelope(priv: Ed25519PrivateKey, payload: dict) -> dict:
    pub_b64 = b64e(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    raw = canonical(payload)
    return {
        "payload": payload,
        "payload_sha256": hashlib.sha256(raw).hexdigest(),
        "signer_pub": pub_b64,
        "signature": b64e(priv.sign(raw)),
    }


def verify_envelope(env: dict, expected_pub: str | None = None) -> dict:
    if not isinstance(env, dict) or not {"payload", "payload_sha256", "signer_pub", "signature"} <= set(env):
        raise VerificationError("invalid_envelope_schema")
    pub = expected_pub or env["signer_pub"]
    if env["signer_pub"] != pub:
        raise VerificationError("signer_public_key_mismatch")
    raw = canonical(env["payload"])
    if hashlib.sha256(raw).hexdigest() != env["payload_sha256"]:
        raise VerificationError("payload_digest_mismatch")
    try:
        Ed25519PublicKey.from_public_bytes(b64d(pub)).verify(b64d(env["signature"]), raw)
    except Exception as exc:
        raise VerificationError("invalid_ed25519_signature") from exc
    return env["payload"]


class SigningIdentity:
    """Represents an Owner/Buyer, Worker/Agent, or Receiver cryptographic identity with rotation support."""
    def __init__(self, seed: bytes | None = None):
        self.key = Ed25519PrivateKey.from_private_bytes(seed) if seed else Ed25519PrivateKey.generate()
        self.public = b64e(self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        self.history: list[dict] = []

    def rotate(self, new_seed: bytes | None = None, *, now: int | None = None) -> dict:
        new_key = Ed25519PrivateKey.from_private_bytes(new_seed) if new_seed else Ed25519PrivateKey.generate()
        new_pub = b64e(new_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        cert = sign_envelope(self.key, {
            "schema": "openline.guard.key_rotation.v1",
            "old_pub": self.public,
            "new_pub": new_pub,
            "rotated_at": now if now is not None else int(time.time()),
        })
        self.history.append(cert)
        self.key = new_key
        self.public = new_pub
        return cert

    def issue_grant(
        self,
        worker_pub: str,
        *,
        task_id: str,
        operation: str,
        step_id: str = "main",
        max_amount: int | float | None = None,
        allowed_targets: list[str] | None = None,
        required_basis: dict[str, str] | None = None,
        upstream_receipt_sha256: str | None = None,
        expires: int | None = None,
        grant_id: str | None = None,
    ) -> dict:
        now = int(time.time())
        body = {
            "schema": "openline.guard.grant.v1",
            "grant_id": grant_id or uuid.uuid4().hex,
            "issuer_pub": self.public,
            "worker_pub": worker_pub,
            "task_id": task_id,
            "step_id": step_id,
            "operation": operation,
            "max_amount": max_amount,
            "allowed_targets": sorted(allowed_targets) if allowed_targets is not None else None,
            "required_basis": dict(required_basis) if required_basis is not None else None,
            "upstream_receipt_sha256": upstream_receipt_sha256,
            "issued_at": now,
            "expires": expires if expires is not None else now + 3600,
        }
        return sign_envelope(self.key, body)

    def sign_request(
        self,
        grant: dict,
        *,
        operation: str,
        target_id: str,
        payload: dict,
        step_id: str = "main",
        upstream_receipt: dict | None = None,
    ) -> dict:
        g_payload = grant.get("payload", {})
        body = {
            "schema": "openline.guard.request.v1",
            "worker_pub": self.public,
            "grant_id": g_payload.get("grant_id"),
            "grant_sha256": grant.get("payload_sha256"),
            "task_id": g_payload.get("task_id"),
            "step_id": step_id,
            "operation": operation,
            "target_id": str(target_id),
            "payload": payload,
            "payload_sha256": sha256_hex(payload),
            "upstream_receipt_sha256": upstream_receipt.get("payload_sha256") if isinstance(upstream_receipt, dict) else None,
            "requested_at": int(time.time()),
        }
        return sign_envelope(self.key, body)


class ReceiverGuard:
    """Lightweight receiver-owned enforcement & continuity engine over an existing SQLite DB and file set."""

    def __init__(
        self,
        db_path: str | Path,
        *,
        receiver_id: str = "default-receiver",
        receiver_identity: SigningIdentity | None = None,
        protected_files: list[str | Path] | None = None,
        protected_targets: set[tuple[str, str]] | None = None,
        clock: Callable[[], int] | None = None,
    ):
        self.db_path = str(Path(db_path).resolve())
        self.control_db_path = self.db_path + ".control.sqlite"
        self.receiver_id = receiver_id
        self.identity = receiver_identity or SigningIdentity()
        self.genesis_public = self.identity.public
        self.clock = clock or (lambda: int(time.time()))
        self.protected_files = {str(Path(p).resolve()): self._file_sha(Path(p)) for p in (protected_files or [])}
        self.protected_targets = set(protected_targets or set())
        self._init_schema()

    @staticmethod
    def _file_sha(path: Path) -> str:
        p = Path(path).resolve()
        return hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else "MISSING"

    def _init_schema(self) -> None:
        with closing(sqlite3.connect(self.db_path, timeout=15)) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS ol_guard_issuers (
                    issuer_pub TEXT PRIMARY KEY,
                    active INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS ol_guard_revocations (
                    kind TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    revoked_at INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    PRIMARY KEY (kind, target_id)
                );
                CREATE TABLE IF NOT EXISTS ol_guard_key_epochs (
                    epoch INTEGER PRIMARY KEY AUTOINCREMENT,
                    role TEXT NOT NULL,
                    old_pub TEXT,
                    new_pub TEXT NOT NULL,
                    rotated_at INTEGER NOT NULL,
                    cert_json TEXT
                );
                CREATE TABLE IF NOT EXISTS ol_guard_basis (
                    basis_key TEXT PRIMARY KEY,
                    version TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ol_guard_protected_records (
                    table_name TEXT NOT NULL,
                    pk_value TEXT NOT NULL,
                    PRIMARY KEY (table_name, pk_value)
                );
                CREATE TABLE IF NOT EXISTS ol_guard_receipts (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    receipt_id TEXT UNIQUE NOT NULL,
                    task_id TEXT NOT NULL,
                    step_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    target_table TEXT,
                    target_pk_col TEXT,
                    target_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    reason TEXT,
                    payload_sha256 TEXT NOT NULL,
                    effect_sha256 TEXT,
                    prev_receipt_sha256 TEXT NOT NULL,
                    receipt_sha256 TEXT NOT NULL,
                    signer_pub TEXT NOT NULL,
                    basis_json TEXT,
                    standing TEXT NOT NULL DEFAULT 'CURRENT',
                    receipt_json TEXT NOT NULL,
                    at_unix INTEGER NOT NULL
                );
            """)
            if not db.execute("SELECT 1 FROM ol_guard_key_epochs WHERE role='receiver' AND new_pub=?", (self.identity.public,)).fetchone():
                db.execute(
                    "INSERT INTO ol_guard_key_epochs(role, old_pub, new_pub, rotated_at, cert_json) VALUES ('receiver', NULL, ?, ?, NULL)",
                    (self.identity.public, self.clock()),
                )
            for tbl, pk in self.protected_targets:
                db.execute("INSERT OR IGNORE INTO ol_guard_protected_records VALUES (?, ?)", (tbl, str(pk)))
            db.commit()
        with closing(sqlite3.connect(self.control_db_path, timeout=15)) as cdb:
            cdb.execute("PRAGMA journal_mode=WAL")
            cdb.execute("""
                CREATE TABLE IF NOT EXISTS ol_guard_revocations (
                    kind TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    revoked_at INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    PRIMARY KEY (kind, target_id)
                )
            """)
            cdb.commit()

    @property
    def receiver_public(self) -> str:
        return self.identity.public

    def register_issuer(self, issuer_pub: str) -> None:
        with closing(sqlite3.connect(self.db_path, timeout=15)) as db:
            db.execute("INSERT OR REPLACE INTO ol_guard_issuers VALUES (?, 1)", (issuer_pub,))
            if not db.execute("SELECT 1 FROM ol_guard_key_epochs WHERE role='issuer' AND new_pub=?", (issuer_pub,)).fetchone():
                db.execute(
                    "INSERT INTO ol_guard_key_epochs(role, old_pub, new_pub, rotated_at, cert_json) VALUES ('issuer', NULL, ?, ?, NULL)",
                    (issuer_pub, self.clock()),
                )
            db.commit()

    def protect_record(self, table_name: str, pk_value: str) -> None:
        with closing(sqlite3.connect(self.db_path, timeout=15)) as db:
            db.execute("INSERT OR IGNORE INTO ol_guard_protected_records VALUES (?, ?)", (table_name, str(pk_value)))
            db.commit()

    def rotate_receiver_key(self, new_seed: bytes | None = None) -> dict:
        old_pub = self.identity.public
        cert = self.identity.rotate(new_seed, now=self.clock())
        with closing(sqlite3.connect(self.db_path, timeout=15)) as db:
            db.execute(
                "INSERT INTO ol_guard_key_epochs(role, old_pub, new_pub, rotated_at, cert_json) VALUES ('receiver', ?, ?, ?, ?)",
                (old_pub, self.identity.public, self.clock(), json.dumps(cert, sort_keys=True)),
            )
            db.commit()
        return cert

    def rotate_issuer_key(self, rotation_cert: dict) -> None:
        payload = verify_envelope(rotation_cert)
        if payload.get("schema") != "openline.guard.key_rotation.v1":
            raise VerificationError("invalid_rotation_cert_schema")
        old_pub = payload["old_pub"]
        new_pub = payload["new_pub"]
        with closing(sqlite3.connect(self.db_path, timeout=15)) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT active FROM ol_guard_issuers WHERE issuer_pub=?", (old_pub,)).fetchone()
            if not row or row[0] != 1:
                db.rollback()
                raise VerificationError("old_issuer_not_active")
            db.execute("UPDATE ol_guard_issuers SET active=0 WHERE issuer_pub=?", (old_pub,))
            db.execute("INSERT OR REPLACE INTO ol_guard_issuers VALUES (?, 1)", (new_pub,))
            db.execute(
                "INSERT INTO ol_guard_key_epochs(role, old_pub, new_pub, rotated_at, cert_json) VALUES ('issuer', ?, ?, ?, ?)",
                (old_pub, new_pub, self.clock(), json.dumps(rotation_cert, sort_keys=True)),
            )
            db.commit()

    def export_key_rotation_chain(self) -> list[dict]:
        with closing(sqlite3.connect(self.db_path, timeout=15)) as db:
            rows = db.execute(
                "SELECT cert_json FROM ol_guard_key_epochs WHERE role='receiver' AND cert_json IS NOT NULL ORDER BY epoch"
            ).fetchall()
        return [json.loads(r[0]) for r in rows]

    def revoke_worker(self, worker_pub: str, reason: str = "worker_revoked") -> None:
        with closing(sqlite3.connect(self.control_db_path, timeout=15)) as cdb:
            cdb.execute(
                "INSERT OR REPLACE INTO ol_guard_revocations VALUES ('worker', ?, ?, ?)",
                (worker_pub, self.clock(), reason),
            )
            cdb.commit()

    def revoke_grant(self, grant_or_id: dict | str, reason: str = "grant_revoked") -> None:
        gid = grant_or_id["payload"]["grant_id"] if isinstance(grant_or_id, dict) else str(grant_or_id)
        with closing(sqlite3.connect(self.control_db_path, timeout=15)) as cdb:
            cdb.execute(
                "INSERT OR REPLACE INTO ol_guard_revocations VALUES ('grant', ?, ?, ?)",
                (gid, self.clock(), reason),
            )
            cdb.commit()

    def _is_revoked(self, kind: str, target_id: str | None) -> bool:
        if not target_id:
            return False
        with closing(sqlite3.connect(self.control_db_path, timeout=15)) as cdb:
            return cdb.execute(
                "SELECT 1 FROM ol_guard_revocations WHERE kind=? AND target_id=?",
                (kind, str(target_id)),
            ).fetchone() is not None

    def set_basis(self, basis_key: str, version: str) -> list[str]:
        """Sets or updates a basis contract; selectively marks dependent COMMITTED steps as REOPEN."""
        with closing(sqlite3.connect(self.db_path, timeout=15)) as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT version FROM ol_guard_basis WHERE basis_key=?", (basis_key,)).fetchone()
            db.execute("INSERT OR REPLACE INTO ol_guard_basis VALUES (?, ?, ?)", (basis_key, version, self.clock()))
            reopened = []
            if old and old[0] != version:
                rows = db.execute(
                    "SELECT receipt_id, task_id, step_id, basis_json FROM ol_guard_receipts WHERE status='COMMITTED' AND standing='CURRENT'"
                ).fetchall()
                for rid, tid, sid, bjson in rows:
                    if not bjson:
                        continue
                    bmap = json.loads(bjson)
                    if bmap.get(basis_key) and bmap.get(basis_key) != version:
                        db.execute("UPDATE ol_guard_receipts SET standing='REOPEN' WHERE receipt_id=?", (rid,))
                        reopened.append(f"{tid}:{sid}")
            db.commit()
            return sorted(set(reopened))

    @staticmethod
    def _row_digest(db: sqlite3.Connection, table_name: str | None, pk_col: str | None, target_id: str) -> str | None:
        if not table_name or not pk_col:
            return None
        quoted_tbl = '"' + table_name.replace('"', '""') + '"'
        quoted_pk = '"' + pk_col.replace('"', '""') + '"'
        cur = db.execute(f"SELECT * FROM {quoted_tbl} WHERE {quoted_pk}=?", (target_id,))
        row = cur.fetchone()
        if row is None:
            return "ROW_MISSING"
        cols = [d[0] for d in cur.description]
        return sha256_hex({cols[i]: row[i] for i in range(len(cols))})

    def _emit_and_store_receipt(
        self,
        db: sqlite3.Connection,
        *,
        task_id: str,
        step_id: str,
        operation: str,
        target_table: str | None,
        target_pk_col: str | None,
        target_id: str,
        status: str,
        reason: str | None,
        payload_sha256: str,
        effect_sha256: str | None,
        grant_id: str | None,
        worker_pub: str | None,
        issuer_pub: str | None,
        basis: dict[str, str] | None,
        upstream_receipt_sha256: str | None,
    ) -> dict:
        last = db.execute("SELECT receipt_sha256 FROM ol_guard_receipts ORDER BY seq DESC LIMIT 1").fetchone()
        prev_sha = last[0] if last else "0" * 64
        receipt_id = uuid.uuid4().hex
        now = self.clock()
        body = {
            "schema": "openline.guard.receipt.v1",
            "receipt_id": receipt_id,
            "receiver_id": self.receiver_id,
            "task_id": str(task_id),
            "step_id": str(step_id),
            "operation": str(operation),
            "target": {
                "table": target_table,
                "pk_col": target_pk_col,
                "id": str(target_id),
            },
            "status": status,
            "reason": reason,
            "grant_id": grant_id,
            "issuer_pub": issuer_pub,
            "worker_pub": worker_pub,
            "payload_sha256": payload_sha256,
            "effect_sha256": effect_sha256,
            "basis": basis,
            "upstream_receipt_sha256": upstream_receipt_sha256,
            "prev_receipt_sha256": prev_sha,
            "at_unix": now,
        }
        signed = sign_envelope(self.identity.key, body)
        db.execute(
            """INSERT INTO ol_guard_receipts(
                receipt_id, task_id, step_id, operation, target_table, target_pk_col, target_id,
                status, reason, payload_sha256, effect_sha256, prev_receipt_sha256, receipt_sha256,
                signer_pub, basis_json, standing, receipt_json, at_unix
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                receipt_id,
                str(task_id),
                str(step_id),
                str(operation),
                target_table,
                target_pk_col,
                str(target_id),
                status,
                reason,
                payload_sha256,
                effect_sha256,
                prev_sha,
                signed["payload_sha256"],
                signed["signer_pub"],
                json.dumps(basis, sort_keys=True) if basis else None,
                "CURRENT" if status == "COMMITTED" else "REFUSED",
                json.dumps(signed, sort_keys=True),
                now,
            ),
        )
        return signed

    def execute(
        self,
        *,
        grant: dict,
        request: dict,
        fn: Callable[[sqlite3.Connection, dict], None],
        target_table: str | None = None,
        target_pk_col: str | None = None,
        target_file: str | Path | None = None,
        amount_field: str | None = None,
        upstream_receipt: dict | None = None,
        trusted_upstream_pub: str | None = None,
        pre_commit_hook: Callable[[], None] | None = None,
    ) -> dict:
        """Executes a receiver operation inside a guarded savepoint, emitting a signed receipt on both COMMIT and REFUSAL."""
        with closing(sqlite3.connect(self.db_path, timeout=15)) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("SAVEPOINT ol_guard_effect")
            g_body = grant.get("payload", {}) if isinstance(grant, dict) else {}
            r_body = request.get("payload", {}) if isinstance(request, dict) else {}
            task_id = str(r_body.get("task_id") or g_body.get("task_id") or "unknown")
            step_id = str(r_body.get("step_id") or g_body.get("step_id") or "main")
            operation = str(r_body.get("operation") or g_body.get("operation") or "unknown")
            target_id = str(r_body.get("target_id") or "unknown")
            req_payload = r_body.get("payload") if isinstance(r_body.get("payload"), dict) else {}
            payload_sha = sha256_hex(req_payload)
            grant_id = g_body.get("grant_id")
            issuer_pub = g_body.get("issuer_pub")
            worker_pub = r_body.get("worker_pub")
            req_basis = g_body.get("required_basis")
            up_sha = r_body.get("upstream_receipt_sha256")

            try:
                # 1. Verify cryptographic signatures on grant and request
                try:
                    verify_envelope(grant)
                    verify_envelope(request)
                except VerificationError as exc:
                    raise ValueError(f"signature_verification_failed:{exc}") from exc

                # 2. Check issuer registration
                issuer_row = db.execute("SELECT active FROM ol_guard_issuers WHERE issuer_pub=?", (issuer_pub,)).fetchone()
                if not issuer_row or issuer_row[0] != 1:
                    raise ValueError("issuer_not_authorized_or_rotated")

                # 3. Check idempotent completion BEFORE revocation/expiry if already committed with identical payload
                existing = db.execute(
                    "SELECT payload_sha256, receipt_json FROM ol_guard_receipts WHERE task_id=? AND step_id=? AND status='COMMITTED' AND standing='CURRENT'",
                    (task_id, step_id),
                ).fetchone()
                if existing:
                    if existing[0] != payload_sha:
                        raise ValueError("idempotency_payload_conflict")
                    db.execute("RELEASE SAVEPOINT ol_guard_effect")
                    db.commit()
                    return {"status": "ALREADY_COMMITTED", "receipt": json.loads(existing[1])}

                # 4. Check worker & grant revocations and expiry (via lock-free control plane DB)
                if self._is_revoked("worker", worker_pub):
                    raise ValueError("worker_revoked")
                if self._is_revoked("grant", grant_id):
                    raise ValueError("grant_revoked")
                if not isinstance(g_body.get("expires"), int) or g_body["expires"] <= self.clock():
                    raise ValueError("grant_expired")

                # 5. Check request-to-grant binding and operation/target/amount scope
                if (r_body.get("grant_sha256") != grant.get("payload_sha256") or
                        g_body.get("worker_pub") != worker_pub or
                        g_body.get("task_id") != task_id or
                        g_body.get("step_id") != step_id):
                    raise ValueError("request_grant_binding_mismatch")
                if g_body.get("operation") != operation:
                    raise ValueError("operation_scope_violation")
                if g_body.get("allowed_targets") is not None and target_id not in g_body["allowed_targets"]:
                    raise ValueError("target_scope_violation")
                # Verify the signed cap itself, not just the worker's amount.
                # A signed NaN cap defeats every `amount > max_amount` comparison.
                import math as _math
                cap = g_body.get("max_amount")
                if cap is not None:
                    if (type(cap) not in (int, float) or cap <= 0
                            or (isinstance(cap, float) and not _math.isfinite(cap))):
                        raise ValueError("invalid_authorized_cap")
                if amount_field is not None or cap is not None:
                    amt_key = amount_field or "amount"
                    val = req_payload.get(amt_key)
                    if cap is not None and val is None:
                        raise ValueError("amount_required_for_capped_grant")
                    if val is not None:
                        if isinstance(val, bool) or not isinstance(val, (int, float)) or not _math.isfinite(val) or val <= 0:
                            raise ValueError("invalid_amount")
                        if cap is not None and val > cap:
                            raise ValueError("amount_exceeds_authorized_cap")

                # 6. Check protected files and protected database records
                if target_file is not None:
                    resolved_file = str(Path(target_file).resolve())
                    if resolved_file in self.protected_files:
                        raise ValueError("protected_file_modification_refused")
                if target_table and db.execute(
                    "SELECT 1 FROM ol_guard_protected_records WHERE table_name=? AND pk_value=?",
                    (target_table, target_id),
                ).fetchone():
                    raise ValueError("protected_record_modification_refused")

                # 7. Check required basis contracts
                if req_basis:
                    for b_key, b_ver in req_basis.items():
                        live_b = db.execute("SELECT version FROM ol_guard_basis WHERE basis_key=?", (b_key,)).fetchone()
                        if not live_b or live_b[0] != b_ver:
                            raise ValueError(f"basis_stale_or_missing:{b_key}")

                # 8. Check cross-receiver upstream receipt binding when required
                if g_body.get("upstream_receipt_sha256") is not None:
                    if not isinstance(upstream_receipt, dict) or upstream_receipt.get("payload_sha256") != g_body["upstream_receipt_sha256"]:
                        raise ValueError("upstream_receipt_missing_or_mismatched")
                    up_body = verify_envelope(upstream_receipt, expected_pub=trusted_upstream_pub)
                    if up_body.get("status") != "COMMITTED":
                        raise ValueError("upstream_receipt_not_committed")

                # 9. Execute the operation inside savepoint
                fn(db, req_payload)

                # Optional hook to test mid-operation revocation/interruption before commit
                if pre_commit_hook is not None:
                    pre_commit_hook()
                # Always re-check lock-free control-plane revocations right before finalizing commit!
                if self._is_revoked("worker", worker_pub):
                    raise ValueError("worker_revoked_mid_task")
                if self._is_revoked("grant", grant_id):
                    raise ValueError("grant_revoked_mid_task")

                # Verify protected files remained byte-identical
                for p_file, expected_sha in self.protected_files.items():
                    if self._file_sha(Path(p_file)) != expected_sha:
                        raise ValueError("protected_file_bytes_altered")

                # 10. Compute post-mutation effect digest
                if target_file is not None:
                    effect_sha = self._file_sha(Path(target_file))
                else:
                    effect_sha = self._row_digest(db, target_table, target_pk_col, target_id)
                    if effect_sha == "ROW_MISSING":
                        raise ValueError("effect_row_missing_after_execution")

                receipt = self._emit_and_store_receipt(
                    db,
                    task_id=task_id,
                    step_id=step_id,
                    operation=operation,
                    target_table=target_table,
                    target_pk_col=target_pk_col,
                    target_id=target_id,
                    status="COMMITTED",
                    reason=None,
                    payload_sha256=payload_sha,
                    effect_sha256=effect_sha,
                    grant_id=grant_id,
                    worker_pub=worker_pub,
                    issuer_pub=issuer_pub,
                    basis=req_basis,
                    upstream_receipt_sha256=up_sha,
                )
                db.execute("RELEASE SAVEPOINT ol_guard_effect")
                db.commit()
                return {"status": "COMMITTED", "receipt": receipt}

            except Exception as exc:
                # Roll back any partial effect from the inner savepoint, then persist a signed refusal receipt!
                db.execute("ROLLBACK TO SAVEPOINT ol_guard_effect")
                db.execute("RELEASE SAVEPOINT ol_guard_effect")
                reason = str(exc)
                refusal_receipt = self._emit_and_store_receipt(
                    db,
                    task_id=task_id,
                    step_id=step_id,
                    operation=operation,
                    target_table=target_table,
                    target_pk_col=target_pk_col,
                    target_id=target_id,
                    status="REFUSED",
                    reason=reason,
                    payload_sha256=payload_sha,
                    effect_sha256=None,
                    grant_id=grant_id,
                    worker_pub=worker_pub,
                    issuer_pub=issuer_pub,
                    basis=req_basis,
                    upstream_receipt_sha256=up_sha,
                )
                db.commit()
                raise GuardRefused(reason, refusal_receipt) from exc

    def export_task_passport(self, task_id: str) -> dict:
        """Exports a receiver-signed Task Continuity Passport for cross-worker/provider takeover."""
        with closing(sqlite3.connect(self.db_path, timeout=15)) as db:
            rows = db.execute(
                """SELECT step_id, operation, target_table, target_pk_col, target_id,
                          status, standing, payload_sha256, effect_sha256, receipt_sha256
                   FROM ol_guard_receipts WHERE task_id=? ORDER BY seq""",
                (task_id,),
            ).fetchall()
            committed_steps = {}
            refused_steps = []
            reopen_steps = []
            for sid, op, tbl, pk, tid, st, standing, psha, esha, rsha in rows:
                if st == "COMMITTED" and standing == "CURRENT":
                    committed_steps[sid] = {
                        "operation": op,
                        "target": {"table": tbl, "pk_col": pk, "id": tid},
                        "payload_sha256": psha,
                        "effect_sha256": esha,
                        "receipt_sha256": rsha,
                    }
                elif st == "COMMITTED" and standing == "REOPEN":
                    reopen_steps.append(sid)
                elif st == "REFUSED":
                    refused_steps.append(sid)
            body = {
                "schema": "openline.guard.task_passport.v1",
                "receiver_id": self.receiver_id,
                "task_id": task_id,
                "committed_steps": committed_steps,
                "reopen_steps": sorted(set(reopen_steps)),
                "refused_step_attempts": len(refused_steps),
                "exported_at": self.clock(),
            }
            return sign_envelope(self.identity.key, body)

    def get_receipts(self, *, task_id: str | None = None, status: str | None = None) -> list[dict]:
        sql = "SELECT receipt_json FROM ol_guard_receipts WHERE 1=1"
        args = []
        if task_id is not None:
            sql += " AND task_id=?"
            args.append(task_id)
        if status is not None:
            sql += " AND status=?"
            args.append(status)
        sql += " ORDER BY seq"
        with closing(sqlite3.connect(self.db_path, timeout=15)) as db:
            return [json.loads(r[0]) for r in db.execute(sql, args).fetchall()]



    @classmethod
    def seal(cls, project_dir: str | Path) -> dict:
        pdir = Path(project_dir).resolve()
        cfg = json.loads((pdir / "config.json").read_text())
        key_seed = bytes.fromhex(Path(cfg["key_file"]).read_text().strip())
        priv = Ed25519PrivateKey.from_private_bytes(key_seed)
        pub_hex = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        import subprocess
        git_head = subprocess.run(
            ["git", "--git-dir", cfg["accepted_git"], "rev-parse", "refs/heads/accepted"],
            capture_output=True, text=True, check=True
        ).stdout.strip()
        payload = {
            "schema": "openline.receiver-guard.seal.v1",
            "project_id": cfg["project_id"],
            "accepted_git_head": git_head,
            "project_db_sha256": cls._file_sha(Path(cfg["project_db"])),
            "effects_db_sha256": cls._file_sha(Path(cfg["effects_db"])),
            "receiver_pub_hex": pub_hex,
            "at": int(time.time()),
        }
        raw = canonical(payload)
        env = {
            "status": "SEALED",
            "payload": payload,
            "payload_sha256": hashlib.sha256(raw).hexdigest(),
            "signature_hex": priv.sign(raw).hex(),
            "receiver_pub_hex": pub_hex,
        }
        seal_file = pdir / "receiver_seal.json"
        seal_file.write_text(json.dumps(env, sort_keys=True, indent=2) + "\n")
        os.chmod(seal_file, 0o600)
        return env

    @classmethod
    def verify(cls, project_dir: str | Path, *, pinned_receiver_pub_hex: str | None = None) -> dict:
        pdir = Path(project_dir).resolve()
        cfg = json.loads((pdir / "config.json").read_text())
        seal_file = pdir / "receiver_seal.json"
        if not seal_file.is_file():
            raise VerificationError("receiver_seal_missing")
        env = json.loads(seal_file.read_text())
        pub_hex = pinned_receiver_pub_hex or cfg.get("receiver_pub") or env.get("receiver_pub_hex")
        if env.get("receiver_pub_hex") != pub_hex:
            raise VerificationError("seal_receiver_pub_mismatch")
        raw = canonical(env["payload"])
        if hashlib.sha256(raw).hexdigest() != env.get("payload_sha256"):
            raise VerificationError("seal_digest_mismatch")
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
            bytes.fromhex(env["signature_hex"]), raw
        )
        import subprocess
        git_head = subprocess.run(
            ["git", "--git-dir", cfg["accepted_git"], "rev-parse", "refs/heads/accepted"],
            capture_output=True, text=True, check=True
        ).stdout.strip()
        p = env["payload"]
        if p["accepted_git_head"] != git_head:
            raise VerificationError("seal_git_head_drift")
        if p["project_db_sha256"] != cls._file_sha(Path(cfg["project_db"])):
            raise VerificationError("seal_project_db_tampered")
        if p["effects_db_sha256"] != cls._file_sha(Path(cfg["effects_db"])):
            raise VerificationError("seal_effects_db_tampered")
        return {"status": "VERIFIED", "project_id": p["project_id"], "accepted_git_head": git_head, "receiver_pub_hex": pub_hex}


def verify_receipt_offline(
    receipt: dict,
    *,
    pinned_receiver_pub: str,
    rotation_chain: list[dict] | None = None,
    db_path: str | Path | None = None,
    target_file: str | Path | None = None,
) -> dict:
    """Offline cryptographic + key-rotation chain + optional live effect-state verifier."""
    valid_keys = {pinned_receiver_pub}
    cur_pub = pinned_receiver_pub
    for cert in rotation_chain or []:
        c_body = verify_envelope(cert, expected_pub=cur_pub)
        if c_body.get("schema") != "openline.guard.key_rotation.v1" or c_body.get("old_pub") != cur_pub:
            raise VerificationError("invalid_key_rotation_chain")
        cur_pub = c_body["new_pub"]
        valid_keys.add(cur_pub)

    signer_pub = receipt.get("signer_pub")
    if signer_pub not in valid_keys:
        raise VerificationError("untrusted_receipt_signer_key")

    body = verify_envelope(receipt, expected_pub=signer_pub)
    if body.get("schema") != "openline.guard.receipt.v1":
        raise VerificationError("invalid_receipt_schema")

    result = {
        "crypto": "VERIFIED",
        "receipt_id": body["receipt_id"],
        "status": body["status"],
        "operation": body["operation"],
        "signer_pub": signer_pub,
        "effect_verification": "NOT_CHECKED_OFFLINE_ONLY",
    }

    if body["status"] == "REFUSED":
        result["effect_verification"] = "REFUSAL_RECORD_VERIFIED"
        return result

    if target_file is not None:
        live_sha = ReceiverGuard._file_sha(Path(target_file))
        if live_sha == "MISSING":
            raise VerificationError("REFUSED:effect_missing")
        if live_sha != body.get("effect_sha256"):
            raise VerificationError("REFUSED:effect_mismatch")
        result["effect_verification"] = "VERIFIED_CURRENT"
        return result

    if db_path is not None and body.get("effect_sha256"):
        target = body.get("target") or {}
        tbl, pk_col, tid = target.get("table"), target.get("pk_col"), target.get("id")
        if tbl and pk_col and tid is not None:
            uri = "file:" + str(Path(db_path).resolve()) + "?mode=ro"
            with closing(sqlite3.connect(uri, uri=True, timeout=5)) as db:
                live_sha = ReceiverGuard._row_digest(db, tbl, pk_col, str(tid))
                if live_sha == "ROW_MISSING":
                    raise VerificationError("REFUSED:effect_missing")
                if live_sha == body["effect_sha256"]:
                    result["effect_verification"] = "VERIFIED_CURRENT"
                else:
                    # Check if a later verified receipt in ol_guard_receipts superseded this row legitimately
                    later = db.execute(
                        """SELECT receipt_json FROM ol_guard_receipts
                           WHERE target_table=? AND target_id=? AND status='COMMITTED' AND effect_sha256=?""",
                        (tbl, str(tid), live_sha),
                    ).fetchall()
                    superseded_ok = False
                    for (rjson,) in later:
                        cand = json.loads(rjson)
                        if cand.get("signer_pub") in valid_keys:
                            verify_envelope(cand, expected_pub=cand["signer_pub"])
                            superseded_ok = True
                            break
                    if not superseded_ok:
                        raise VerificationError("REFUSED:effect_mismatch")
                    result["effect_verification"] = "VERIFIED_HISTORICAL"
    return result
