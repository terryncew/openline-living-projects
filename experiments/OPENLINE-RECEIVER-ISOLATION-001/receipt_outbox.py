"""OpenLine Production Isolation — Durable Receipt Outbox (`receipt_outbox`).

Implements Section 3.4, 4.4, and 7.2 (`CRASH-01`, `CRASH-02`) of Astra's Production Isolation Blueprint:
- Persists signed incident receipts inside `project.sqlite`'s `receipt_outbox` table before or alongside
  filesystem publication to `incidents/<incident_id>.json`.
- If the receiver crashes after Git CAS and/or SQLite settlement but before writing `incidents/<incident_id>.json`
  or before sending the socket response (`CUT-04`, `CUT-05`, `CUT-06`), `flush_outbox()` idempotently
  materializes any unpublished receipt files and returns the original signed receipt on retry without
  minting duplicate or conflicting receipts.
"""
from __future__ import annotations

from contextlib import closing
import json
from pathlib import Path
import sqlite3
import time
from typing import Any

from durable_io import atomic_write_json, fsync_directory


class ReceiptOutbox:
    """Manages durable receipt persistence in `project.sqlite` and idempotent file publication."""

    def __init__(self, db_path: Path | str, incidents_dir: Path | str):
        self.db_path = str(db_path)
        self.incidents_dir = Path(incidents_dir).resolve()
        self.incidents_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.ensure_schema()

    def ensure_schema(self) -> None:
        with closing(sqlite3.connect(self.db_path, timeout=15.0)) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS receipt_outbox (
                    operation_id TEXT NOT NULL,
                    observation_seq INTEGER NOT NULL DEFAULT 1,
                    assignment_id TEXT NOT NULL,
                    incident_id TEXT UNIQUE NOT NULL,
                    verdict TEXT NOT NULL,
                    receipt_sha256 TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    companion_json TEXT,
                    published_path TEXT,
                    published_at INTEGER,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY (operation_id, observation_seq)
                );
            """)
            db.commit()

    def record_in_tx(
        self,
        db: sqlite3.Connection,
        *,
        operation_id: str,
        assignment_id: str,
        receipt: dict[str, Any],
        observation_seq: int = 1,
        companion: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = receipt["payload"]
        incident_id = str(payload["incident_id"])
        verdict = str(payload["verdict"])
        receipt_sha = str(receipt["payload_sha256"])
        now = int(time.time())
        existing = db.execute(
            "SELECT incident_id, verdict, receipt_sha256, receipt_json, published_path FROM receipt_outbox WHERE operation_id=? AND observation_seq=?",
            (operation_id, int(observation_seq)),
        ).fetchone()
        if existing is not None:
            return {
                "incident_id": existing[0],
                "verdict": existing[1],
                "receipt_sha256": existing[2],
                "receipt": json.loads(existing[3]),
                "path": existing[4] or str(self.incidents_dir / f"{existing[0]}.json"),
                "already_enqueued": True,
            }
        db.execute(
            """INSERT INTO receipt_outbox(
                operation_id, observation_seq, assignment_id, incident_id, verdict,
                receipt_sha256, receipt_json, companion_json, published_path, published_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)""",
            (
                operation_id,
                int(observation_seq),
                assignment_id,
                incident_id,
                verdict,
                receipt_sha,
                json.dumps(receipt, sort_keys=True),
                json.dumps(companion, sort_keys=True) if companion else None,
                now,
            ),
        )
        return {
            "incident_id": incident_id,
            "verdict": verdict,
            "receipt_sha256": receipt_sha,
            "receipt": receipt,
            "path": str(self.incidents_dir / f"{incident_id}.json"),
            "already_enqueued": False,
        }

    def enqueue(
        self,
        *,
        operation_id: str,
        assignment_id: str,
        receipt: dict[str, Any],
        observation_seq: int = 1,
        companion: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        with closing(sqlite3.connect(self.db_path, timeout=15.0)) as db:
            db.execute("BEGIN IMMEDIATE")
            res = self.record_in_tx(
                db,
                operation_id=operation_id,
                assignment_id=assignment_id,
                receipt=receipt,
                observation_seq=observation_seq,
                companion=companion,
            )
            db.commit()
            return res

    def flush_outbox(self) -> list[dict[str, Any]]:
        """Materialize all unpublished outbox receipts to `incidents/<incident_id>.json` and mark published."""
        published: list[dict[str, Any]] = []
        with closing(sqlite3.connect(self.db_path, timeout=15.0)) as db:
            rows = db.execute(
                "SELECT operation_id, observation_seq, assignment_id, incident_id, verdict, receipt_sha256, receipt_json, published_path "
                "FROM receipt_outbox ORDER BY created_at, operation_id, observation_seq"
            ).fetchall()
            for op_id, obs_seq, asgn_id, inc_id, verdict, rec_sha, rec_json, pub_path in rows:
                target = self.incidents_dir / f"{inc_id}.json"
                rec_obj = json.loads(rec_json)
                need_write = not target.is_file()
                if not need_write:
                    try:
                        on_disk = json.loads(target.read_text(encoding="utf-8"))
                        if on_disk.get("payload_sha256") != rec_sha:
                            need_write = True
                    except Exception:
                        need_write = True
                if need_write:
                    atomic_write_json(target, rec_obj, mode=0o600, dir_mode=0o700)
                if pub_path != str(target):
                    db.execute(
                        "UPDATE receipt_outbox SET published_path=?, published_at=? WHERE operation_id=? AND observation_seq=?",
                        (str(target), int(time.time()), op_id, obs_seq),
                    )
                    published.append({
                        "operation_id": op_id,
                        "assignment_id": asgn_id,
                        "incident_id": inc_id,
                        "verdict": verdict,
                        "receipt_sha256": rec_sha,
                        "path": str(target),
                    })
            db.commit()
        return published

    def get_by_assignment(self, assignment_id: str) -> dict[str, Any] | None:
        with closing(sqlite3.connect(self.db_path, timeout=15.0)) as db:
            row = db.execute(
                "SELECT operation_id, observation_seq, incident_id, verdict, receipt_sha256, receipt_json, published_path "
                "FROM receipt_outbox WHERE assignment_id=? ORDER BY created_at DESC, observation_seq DESC LIMIT 1",
                (assignment_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "operation_id": row[0],
            "observation_seq": row[1],
            "incident_id": row[2],
            "verdict": row[3],
            "receipt_sha256": row[4],
            "receipt": json.loads(row[5]),
            "path": row[6] or str(self.incidents_dir / f"{row[2]}.json"),
        }

    def get_by_incident_or_sha(self, identifier: str) -> dict[str, Any] | None:
        with closing(sqlite3.connect(self.db_path, timeout=15.0)) as db:
            row = db.execute(
                "SELECT operation_id, observation_seq, assignment_id, incident_id, verdict, receipt_sha256, receipt_json, published_path "
                "FROM receipt_outbox WHERE incident_id=? OR receipt_sha256=? LIMIT 1",
                (identifier, identifier),
            ).fetchone()
        if row is None:
            return None
        return {
            "operation_id": row[0],
            "observation_seq": row[1],
            "assignment_id": row[2],
            "incident_id": row[3],
            "verdict": row[4],
            "receipt_sha256": row[5],
            "receipt": json.loads(row[6]),
            "path": row[7] or str(self.incidents_dir / f"{row[3]}.json"),
        }
