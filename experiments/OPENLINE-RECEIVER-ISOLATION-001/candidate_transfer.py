"""OpenLine Production Isolation — Byte-Only Snapshot Export & Immutable Candidate Intake.

Implements Section 3.1, 4.3, and 7.2 (`CAND-01`) of Astra's Production Isolation Blueprint:
- `assignment.prepare` exports a deterministic manifest of regular source files and read-only SQLite
  snapshot digests without exposing the receiver's private Git worktree path to workers.
- `snapshot.chunk` streams bounded byte chunks (`offset`, `length`) so workers can materialize
  an independent local workspace in their own private directory.
- `proposal.submit` accepts a bounded `files[]` array (`path`, `op`, `mode`, `sha256`, `content_b64`),
  enforces NFC normalization, casefold uniqueness, `allowed_paths` containment before disk writes,
  rejects symlinks (`120000`) and submodules/gitlinks (`160000`), enforces file count/size caps,
  and applies changes into the receiver's private candidate worktree via `open_beneath` / `atomic_write_bytes`.
"""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import stat
from typing import Any

from durable_io import (
    OpenAt2Error,
    atomic_write_bytes,
    open_beneath,
    read_bytes_beneath,
    validate_relative_subpath,
)


class CandidateTransferError(RuntimeError):
    def __init__(self, reason: str, *, code: str = "OUT_OF_SCOPE_PATH"):
        super().__init__(reason)
        self.reason = reason
        self.code = code


ALLOWED_FILE_MODES = frozenset({"100644", "100755"})
FORBIDDEN_GIT_MODES = frozenset({"120000", "160000", "040000"})
ALLOWED_FILE_OPS = frozenset({"upsert", "delete"})
CANDIDATE_ENTRY_FIELDS = frozenset({"path", "op", "mode", "sha256", "content_b64"})


def _is_path_allowed(relpath: str, allowed_paths: tuple[str, ...] | list[str]) -> bool:
    for prefix in allowed_paths:
        if prefix.endswith("/"):
            if relpath.startswith(prefix):
                return True
        else:
            if relpath == prefix:
                return True
    return False


def build_workspace_manifest(workspace_dir: Path | str, snapshot_db: Path | str, *, require_native_openat2: bool = True) -> dict[str, Any]:
    """Build a deterministic manifest of regular files in `workspace_dir` (excluding `.git`) and `snapshot_db`."""
    ws = Path(workspace_dir)
    if ws.is_symlink() or not ws.is_dir():
        raise CandidateTransferError("workspace_invalid", code="MALFORMED_ENVELOPE")

    files_manifest: list[dict[str, Any]] = []
    for p in sorted(ws.rglob("*")):
        rel = p.relative_to(ws).as_posix()
        if rel == ".git" or rel.startswith(".git/"):
            continue
        if p.is_symlink():
            raise CandidateTransferError(f"workspace_contains_symlink:{rel}", code="SYMLINK_OR_SUBMODULE_FORBIDDEN")
        if not p.is_file():
            continue
        raw = read_bytes_beneath(ws, rel, require_native_openat2=require_native_openat2)
        st = p.stat()
        mode_str = "100755" if (st.st_mode & 0o111) else "100644"
        files_manifest.append({
            "path": rel,
            "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "mode": mode_str,
        })

    snap_path = Path(snapshot_db)
    if snap_path.is_symlink() or not snap_path.is_file():
        raise CandidateTransferError("snapshot_db_invalid", code="MALFORMED_ENVELOPE")
    snap_bytes = snap_path.read_bytes()
    return {
        "files": files_manifest,
        "snapshot_db": {
            "size": len(snap_bytes),
            "sha256": hashlib.sha256(snap_bytes).hexdigest(),
        },
    }


def read_snapshot_chunk(
    workspace_dir: Path | str,
    snapshot_db: Path | str,
    *,
    target: str,
    offset: int,
    length: int,
    max_chunk_bytes: int = 262144,
    require_native_openat2: bool = True,
) -> dict[str, Any]:
    """Read a bounded byte chunk from either `@snapshot_db` or a relative file path in `workspace_dir`."""
    if type(offset) is not int or offset < 0:
        raise CandidateTransferError("invalid_chunk_offset", code="MALFORMED_ENVELOPE")
    if type(length) is not int or length <= 0 or length > max_chunk_bytes:
        raise CandidateTransferError("invalid_chunk_length", code="MALFORMED_ENVELOPE")

    if target == "@snapshot_db":
        snap_path = Path(snapshot_db)
        if snap_path.is_symlink() or not snap_path.is_file():
            raise CandidateTransferError("snapshot_db_missing", code="MALFORMED_ENVELOPE")
        raw = snap_path.read_bytes()
    else:
        if target == ".git" or target.startswith(".git/"):
            raise CandidateTransferError("git_metadata_chunk_forbidden", code="OUT_OF_SCOPE_PATH")
        try:
            raw = read_bytes_beneath(workspace_dir, target, require_native_openat2=require_native_openat2)
        except OpenAt2Error as exc:
            raise CandidateTransferError(f"chunk_read_rejected:{exc}", code="OUT_OF_SCOPE_PATH") from exc

    total_size = len(raw)
    slice_bytes = raw[offset : offset + length]
    return {
        "target": target,
        "offset": offset,
        "length": len(slice_bytes),
        "total_size": total_size,
        "eof": (offset + len(slice_bytes)) >= total_size,
        "chunk_sha256": hashlib.sha256(slice_bytes).hexdigest(),
        "data_b64": base64.b64encode(slice_bytes).decode("ascii"),
    }


def materialize_client_workspace(
    ipc_call_chunk,
    manifest: dict[str, Any],
    dest_dir: Path | str,
    *,
    assignment_id: str,
    chunk_size: int = 262144,
) -> dict[str, Any]:
    """Client-side helper: materialize an independent worker-owned directory from `assignment.prepare` + `snapshot.chunk`."""
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True, mode=0o700)
    ws_dir = dest / "workspace"
    ws_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    for fentry in manifest.get("files", []):
        rel = fentry["path"]
        expected_sha = fentry["sha256"]
        expected_size = int(fentry["size"])
        buf = bytearray()
        offset = 0
        while offset < expected_size or (expected_size == 0 and offset == 0):
            req_len = min(chunk_size, max(1, expected_size - offset))
            ch = ipc_call_chunk(assignment_id=assignment_id, target=rel, offset=offset, length=req_len)
            part = base64.b64decode(ch["data_b64"].encode("ascii"), validate=True)
            if hashlib.sha256(part).hexdigest() != ch["chunk_sha256"]:
                raise CandidateTransferError(f"chunk_sha256_mismatch:{rel}", code="MALFORMED_ENVELOPE")
            buf.extend(part)
            offset += len(part)
            if ch.get("eof") or expected_size == 0:
                break
        if hashlib.sha256(buf).hexdigest() != expected_sha:
            raise CandidateTransferError(f"file_sha256_mismatch:{rel}", code="MALFORMED_ENVELOPE")
        out_file = ws_dir / rel
        out_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        mode_int = 0o700 if fentry.get("mode") == "100755" else 0o600
        atomic_write_bytes(out_file, bytes(buf), mode=mode_int)

    snap_info = manifest.get("snapshot_db")
    snap_out = dest / "candidate.sqlite"
    if isinstance(snap_info, dict):
        expected_size = int(snap_info["size"])
        expected_sha = snap_info["sha256"]
        buf = bytearray()
        offset = 0
        while offset < expected_size or (expected_size == 0 and offset == 0):
            req_len = min(chunk_size, max(1, expected_size - offset))
            ch = ipc_call_chunk(assignment_id=assignment_id, target="@snapshot_db", offset=offset, length=req_len)
            part = base64.b64decode(ch["data_b64"].encode("ascii"), validate=True)
            buf.extend(part)
            offset += len(part)
            if ch.get("eof") or expected_size == 0:
                break
        if hashlib.sha256(buf).hexdigest() != expected_sha:
            raise CandidateTransferError("snapshot_db_sha256_mismatch", code="MALFORMED_ENVELOPE")
        atomic_write_bytes(snap_out, bytes(buf), mode=0o600)

    import json
    (dest / ".openline_base_manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return {"workspace": str(ws_dir), "snapshot_db": str(snap_out)}


def collect_client_candidate_files(
    client_workspace: Path | str,
    *,
    allowed_paths: list[str] | tuple[str, ...] | None = None,
) -> list[dict[str, Any]]:
    """Client-side helper: package modified/added regular files from a worker's local workspace into a `proposal.submit` `files[]` array."""
    import json
    ws = Path(client_workspace)
    if ws.is_symlink() or not ws.is_dir():
        raise CandidateTransferError("client_workspace_invalid", code="MALFORMED_ENVELOPE")
    base_hashes: dict[str, tuple[str, str]] = {}
    base_manifest_file = ws.parent / ".openline_base_manifest.json"
    if base_manifest_file.is_file():
        try:
            bman = json.loads(base_manifest_file.read_text(encoding="utf-8"))
            for fentry in bman.get("files", []):
                base_hashes[fentry["path"]] = (fentry["sha256"], fentry.get("mode", "100644"))
        except Exception:
            base_hashes = {}
    out: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for p in sorted(ws.rglob("*")):
        rel = p.relative_to(ws).as_posix()
        if rel == ".git" or rel.startswith(".git/"):
            continue
        if allowed_paths is not None and not _is_path_allowed(rel, allowed_paths):
            continue
        if p.is_symlink():
            raise CandidateTransferError(f"client_symlink_forbidden:{rel}", code="SYMLINK_OR_SUBMODULE_FORBIDDEN")
        if not p.is_file():
            continue
        raw = p.read_bytes()
        sha_hex = hashlib.sha256(raw).hexdigest()
        st = p.stat()
        mode_str = "100755" if (st.st_mode & 0o111) else "100644"
        seen_paths.add(rel)
        if rel in base_hashes and base_hashes[rel] == (sha_hex, mode_str):
            continue
        out.append({
            "path": rel,
            "op": "upsert",
            "mode": mode_str,
            "sha256": sha_hex,
            "content_b64": base64.b64encode(raw).decode("ascii"),
        })
    for old_rel in sorted(set(base_hashes.keys()) - seen_paths):
        if allowed_paths is not None and not _is_path_allowed(old_rel, allowed_paths):
            continue
        out.append({
            "path": old_rel,
            "op": "delete",
            "mode": "100644",
            "sha256": hashlib.sha256(b"").hexdigest(),
            "content_b64": "",
        })
    return out


def validate_and_apply_candidate_files(
    workspace_dir: Path | str,
    files: list[dict[str, Any]],
    *,
    allowed_paths: tuple[str, ...] | list[str],
    max_files: int = 512,
    max_single_file_bytes: int = 1 * 1024 * 1024,
    max_total_bytes: int = 4 * 1024 * 1024,
    reject_binary_nul: bool = True,
    require_native_openat2: bool = True,
) -> dict[str, Any]:
    """Validate an untrusted `files[]` candidate submission in memory first, then safely apply it to `workspace_dir`."""
    ws = Path(workspace_dir)
    if ws.is_symlink() or not ws.is_dir():
        raise CandidateTransferError("receiver_workspace_invalid", code="MALFORMED_ENVELOPE")
    if not isinstance(files, list) or not files:
        raise CandidateTransferError("empty_candidate_files", code="MALFORMED_ENVELOPE")
    if len(files) > max_files:
        raise CandidateTransferError(f"too_many_candidate_files:{len(files)}>{max_files}", code="OVERSIZED_FRAME")

    seen_exact: set[str] = set()
    seen_casefold: set[str] = set()
    total_bytes = 0
    staged_operations: list[tuple[str, str, str, bytes]] = []

    for idx, entry in enumerate(files):
        if not isinstance(entry, dict):
            raise CandidateTransferError(f"candidate_entry_not_dict:{idx}", code="MALFORMED_ENVELOPE")
        if set(entry.keys()) != CANDIDATE_ENTRY_FIELDS:
            raise CandidateTransferError(f"candidate_entry_fields_invalid:{idx}", code="MALFORMED_ENVELOPE")

        raw_path = entry["path"]
        op = entry["op"]
        mode = entry["mode"]
        sha_hex = entry["sha256"]
        b64_data = entry["content_b64"]

        if op not in ALLOWED_FILE_OPS:
            raise CandidateTransferError(f"invalid_file_op:{op}", code="MALFORMED_ENVELOPE")
        if mode in FORBIDDEN_GIT_MODES:
            raise CandidateTransferError(f"forbidden_git_mode:{mode}", code="SYMLINK_OR_SUBMODULE_FORBIDDEN")
        if mode not in ALLOWED_FILE_MODES:
            raise CandidateTransferError(f"invalid_file_mode:{mode}", code="SYMLINK_OR_SUBMODULE_FORBIDDEN")

        try:
            norm_path, parts = validate_relative_subpath(raw_path)
        except OpenAt2Error as exc:
            raise CandidateTransferError(f"invalid_candidate_path:{exc}", code="OUT_OF_SCOPE_PATH") from exc

        if ".git" in parts:
            raise CandidateTransferError("git_path_segment_forbidden", code="OUT_OF_SCOPE_PATH")
        if norm_path in seen_exact:
            raise CandidateTransferError(f"duplicate_candidate_path:{norm_path}", code="MALFORMED_ENVELOPE")
        cf = norm_path.casefold()
        if cf in seen_casefold:
            raise CandidateTransferError(f"casefold_path_collision:{norm_path}", code="OUT_OF_SCOPE_PATH")
        seen_exact.add(norm_path)
        seen_casefold.add(cf)

        if not _is_path_allowed(norm_path, allowed_paths):
            raise CandidateTransferError(f"repair_outside_allowed_source:{norm_path}", code="OUT_OF_SCOPE_PATH")

        if not isinstance(sha_hex, str) or len(sha_hex) != 64:
            raise CandidateTransferError(f"invalid_sha256_for_path:{norm_path}", code="MALFORMED_ENVELOPE")
        if not isinstance(b64_data, str):
            raise CandidateTransferError(f"invalid_content_b64_for_path:{norm_path}", code="MALFORMED_ENVELOPE")

        if op == "delete":
            if b64_data != "" or sha_hex != hashlib.sha256(b"").hexdigest():
                raise CandidateTransferError(f"delete_op_must_have_empty_content:{norm_path}", code="MALFORMED_ENVELOPE")
            decoded = b""
        else:
            try:
                decoded = base64.b64decode(b64_data.encode("ascii"), validate=True)
            except Exception as exc:
                raise CandidateTransferError(f"invalid_base64:{norm_path}", code="MALFORMED_ENVELOPE") from exc
            if len(decoded) > max_single_file_bytes:
                raise CandidateTransferError(
                    f"single_file_exceeds_limit:{norm_path}:{len(decoded)}>{max_single_file_bytes}",
                    code="OVERSIZED_FRAME",
                )
            total_bytes += len(decoded)
            if total_bytes > max_total_bytes:
                raise CandidateTransferError(
                    f"total_candidate_bytes_exceed_limit:{total_bytes}>{max_total_bytes}",
                    code="OVERSIZED_FRAME",
                )
            if hashlib.sha256(decoded).hexdigest() != sha_hex:
                raise CandidateTransferError(f"content_sha256_mismatch:{norm_path}", code="SIGNATURE_INVALID")
            if reject_binary_nul and b"\x00" in decoded:
                raise CandidateTransferError(f"binary_nul_byte_forbidden:{norm_path}", code="MALFORMED_ENVELOPE")

        staged_operations.append((norm_path, op, mode, decoded))

    # All validation passed in memory; now apply safely to receiver's private worktree
    applied_paths: list[str] = []
    for norm_path, op, mode, decoded in sorted(staged_operations, key=lambda x: x[0]):
        target = ws / norm_path
        # Verify no intermediate directory is a symlink
        cur = ws
        for seg in norm_path.split("/")[:-1]:
            cur = cur / seg
            if cur.is_symlink():
                raise CandidateTransferError(f"intermediate_symlink_in_worktree:{cur}", code="SYMLINK_OR_SUBMODULE_FORBIDDEN")
            cur.mkdir(parents=True, exist_ok=True, mode=0o700)
        if target.is_symlink():
            raise CandidateTransferError(f"target_symlink_in_worktree:{norm_path}", code="SYMLINK_OR_SUBMODULE_FORBIDDEN")

        if op == "delete":
            if target.exists():
                target.unlink()
        else:
            file_mode = 0o700 if mode == "100755" else 0o600
            atomic_write_bytes(target, decoded, mode=file_mode, dir_mode=0o700)
            # Re-verify via open_beneath that the written file is regular, single-link, and beneath ws
            fd = open_beneath(ws, norm_path, os.O_RDONLY, require_native_openat2=require_native_openat2, check_single_link=True, expect_regular=True)
            os.close(fd)
        applied_paths.append(norm_path)

    manifest_digest = hashlib.sha256(
        "\n".join(f"{p}:{op}:{m}:{hashlib.sha256(b).hexdigest()}" for p, op, m, b in sorted(staged_operations)).encode("utf-8")
    ).hexdigest()
    return {
        "applied_paths": applied_paths,
        "total_bytes": total_bytes,
        "candidate_manifest_sha256": manifest_digest,
    }
