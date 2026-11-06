"""OpenLine Production Isolation — Authenticated Unix Domain Socket IPC Protocol.

Implements Section 4.1, 4.2, and 7.2 (`IPC-01`, `IPC-02`, `AUTH-01`, `AUTH-02`) of Astra's Blueprint:
- `AF_UNIX` `SOCK_STREAM` framing with 4-byte big-endian length prefix (`MAX_FRAME_BYTES = 8 MiB`).
- Kernel peer credential extraction via `SO_PEERCRED` (`(pid, uid, gid)`).
- Strict `recvmsg` ancillary control message inspection: closes any `SCM_RIGHTS` descriptors immediately
  and rejects any message carrying ancillary data or `MSG_CTRUNC`.
- Strict JSON parser rejecting duplicate keys, `NaN`/`Infinity`, floats, and nesting depth > 16.
- Canonical Ed25519 request (`openline.ipc.request.v1`) and response (`openline.ipc.response.v1`) signing & verification.
- Per-UID token-bucket rate limiter and explicit worker vs control operation allowlists.
"""
from __future__ import annotations

import array
import json
import os
import socket
import struct
import threading
import time
from typing import Any
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import hashlib


IPC_REQUEST_SCHEMA = "openline.ipc.request.v1"
IPC_RESPONSE_SCHEMA = "openline.ipc.response.v1"
MAX_FRAME_BYTES = 8 * 1024 * 1024
MAX_JSON_DEPTH = 16

WORKER_ALLOWED_OPERATIONS = frozenset({
    "project.status",
    "assignment.prepare",
    "snapshot.chunk",
    "proposal.submit",
    "request.get",
    "receipt.get",
    "memory.propose",
    "repair.reconcile",
})

CONTROL_ALLOWED_OPERATIONS = frozenset({
    "control.stop",
    "control.clear",
    "control.assign",
    "control.change_dependency",
    "control.revoke_member",
    "control.join",
    "control.rotate_key",
    "control.backup",
    "project.status",
    "request.get",
    "receipt.get",
    "repair.reconcile",
})

REQUEST_ENVELOPE_FIELDS = frozenset({
    "schema",
    "deployment_id",
    "project_id",
    "receiver_id",
    "channel",
    "request_id",
    "principal_id",
    "operation",
    "issued_at",
    "expires_at",
    "nonce",
    "payload",
    "payload_sha256",
    "signer_pub",
    "signature",
})

RESPONSE_ENVELOPE_FIELDS = frozenset({
    "schema",
    "deployment_id",
    "project_id",
    "receiver_id",
    "request_id",
    "request_sha256",
    "status",
    "code",
    "replayed",
    "at_unix",
    "result",
    "result_sha256",
    "receipt_sha256",
    "receiver_pub",
    "signature",
})


class IPCProtocolError(RuntimeError):
    def __init__(self, message: str, *, code: str = "MALFORMED_ENVELOPE", status: str = "REFUSED"):
        super().__init__(message)
        self.code = code
        self.status = status


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(value: Any) -> str:
    if isinstance(value, (bytes, bytearray)):
        return hashlib.sha256(value).hexdigest()
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _check_depth(obj: Any, depth: int = 0, max_depth: int = MAX_JSON_DEPTH) -> None:
    if depth > max_depth:
        raise IPCProtocolError("json_max_depth_exceeded", code="MALFORMED_ENVELOPE")
    if isinstance(obj, dict):
        for v in obj.values():
            _check_depth(v, depth + 1, max_depth)
    elif isinstance(obj, list):
        for v in obj:
            _check_depth(v, depth + 1, max_depth)


def strict_loads_json(raw: bytes, *, max_depth: int = MAX_JSON_DEPTH) -> dict[str, Any]:
    """Parse UTF-8 JSON rejecting duplicate keys, floats, NaN/Infinity, and excessive depth."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IPCProtocolError("invalid_utf8_in_frame", code="MALFORMED_ENVELOPE") from exc

    def _no_dups(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in pairs:
            if k in out:
                raise IPCProtocolError(f"duplicate_json_key:{k}", code="MALFORMED_ENVELOPE")
            out[k] = v
        return out

    def _no_constants(val: str) -> Any:
        raise IPCProtocolError(f"forbidden_json_constant:{val}", code="MALFORMED_ENVELOPE")

    def _no_floats(val: str) -> Any:
        raise IPCProtocolError(f"float_forbidden_in_protocol:{val}", code="MALFORMED_ENVELOPE")

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_no_dups,
            parse_constant=_no_constants,
            parse_float=_no_floats,
        )
    except IPCProtocolError:
        raise
    except Exception as exc:
        raise IPCProtocolError(f"invalid_json:{exc}", code="MALFORMED_ENVELOPE") from exc

    if not isinstance(parsed, dict):
        raise IPCProtocolError("top_level_json_must_be_object", code="MALFORMED_ENVELOPE")
    _check_depth(parsed, 0, max_depth=max_depth)
    return parsed


def extract_peer_credentials(sock: socket.socket) -> tuple[int, int, int]:
    """Extract kernel-verified `(pid, uid, gid)` from an `AF_UNIX` `SOCK_STREAM` socket via `SO_PEERCRED`."""
    try:
        raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("iii"))
        pid, uid, gid = struct.unpack("iii", raw)
        return int(pid), int(uid), int(gid)
    except OSError as exc:
        raise IPCProtocolError(f"so_peercred_unavailable:{exc}", code="PEER_UID_UNAUTHORIZED") from exc


def _close_scm_rights_fds(cmsg_list: list[tuple[int, int, bytes]]) -> int:
    closed = 0
    scm_rights = getattr(socket, "SCM_RIGHTS", 1)
    for cmsg_level, cmsg_type, cmsg_data in cmsg_list:
        if cmsg_level == socket.SOL_SOCKET and cmsg_type == scm_rights:
            fds = array.array("i")
            fds.frombytes(cmsg_data[: len(cmsg_data) - (len(cmsg_data) % fds.itemsize)])
            for fd in fds:
                try:
                    os.close(fd)
                    closed += 1
                except OSError:
                    pass
    return closed


def _recv_exact_no_ancillary(sock: socket.socket, nbytes: int) -> bytes:
    chunks: list[bytes] = []
    remaining = nbytes
    while remaining > 0:
        if hasattr(sock, "recvmsg"):
            data, ancdata, msg_flags, _addr = sock.recvmsg(min(remaining, 65536), 1024)
            if ancdata or (msg_flags & getattr(socket, "MSG_CTRUNC", 0x08)):
                _close_scm_rights_fds(ancdata)
                raise IPCProtocolError("ancillary_data_or_scm_rights_forbidden", code="MALFORMED_ENVELOPE")
        else:
            data = sock.recv(min(remaining, 65536))
        if not data:
            raise IPCProtocolError("unexpected_eof_on_socket", code="MALFORMED_ENVELOPE")
        chunks.append(data)
        remaining -= len(data)
    return b"".join(chunks)


def recv_frame(sock: socket.socket, *, max_frame_bytes: int = MAX_FRAME_BYTES) -> bytes:
    """Read a length-prefixed frame while rejecting oversized frames and any `SCM_RIGHTS` ancillary fds."""
    hdr = _recv_exact_no_ancillary(sock, 4)
    (frame_len,) = struct.unpack(">I", hdr)
    if frame_len <= 0 or frame_len > max_frame_bytes:
        raise IPCProtocolError(f"invalid_frame_length:{frame_len}", code="OVERSIZED_FRAME")
    return _recv_exact_no_ancillary(sock, frame_len)


def send_frame(sock: socket.socket, payload_bytes: bytes, *, max_frame_bytes: int = MAX_FRAME_BYTES) -> None:
    if len(payload_bytes) <= 0 or len(payload_bytes) > max_frame_bytes:
        raise IPCProtocolError(f"invalid_outbound_frame_length:{len(payload_bytes)}", code="OVERSIZED_FRAME")
    hdr = struct.pack(">I", len(payload_bytes))
    sock.sendall(hdr + payload_bytes)


def sign_ipc_request(
    signer_key: Ed25519PrivateKey,
    *,
    deployment_id: str,
    project_id: str,
    receiver_id: str,
    channel: str,
    request_id: str,
    principal_id: str,
    operation: str,
    payload: dict[str, Any],
    issued_at: int | None = None,
    expires_at: int | None = None,
    nonce: str | None = None,
) -> dict[str, Any]:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    now = int(time.time()) if issued_at is None else int(issued_at)
    exp = (now + 120) if expires_at is None else int(expires_at)
    n_val = nonce or os.urandom(16).hex()
    pub_hex = signer_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    payload_sha = sha256_hex(payload)
    signable = {
        "schema": IPC_REQUEST_SCHEMA,
        "deployment_id": deployment_id,
        "project_id": project_id,
        "receiver_id": receiver_id,
        "channel": channel,
        "request_id": request_id,
        "principal_id": principal_id,
        "operation": operation,
        "issued_at": now,
        "expires_at": exp,
        "nonce": n_val,
        "payload_sha256": payload_sha,
        "signer_pub": pub_hex,
    }
    sig_hex = signer_key.sign(canonical_json_bytes(signable)).hex()
    return {
        **signable,
        "payload": payload,
        "signature": sig_hex,
    }


def verify_ipc_request_envelope(
    env: dict[str, Any],
    *,
    expected_deployment_id: str,
    expected_project_id: str,
    expected_receiver_id: str,
    expected_channel: str,
    expected_principal_id: str | None = None,
    expected_signer_pub: str | None = None,
    now_unix: int | None = None,
    max_skew_s: int = 300,
    high_water_unix: int = 0,
) -> dict[str, Any]:
    """Verify request envelope schema, fields, channel allowlist, freshness, and Ed25519 signature."""
    if not isinstance(env, dict):
        raise IPCProtocolError("request_envelope_not_dict", code="MALFORMED_ENVELOPE")
    unknown = set(env.keys()) - REQUEST_ENVELOPE_FIELDS
    missing = REQUEST_ENVELOPE_FIELDS - set(env.keys())
    if unknown or missing:
        raise IPCProtocolError(f"request_envelope_fields_invalid:unknown={sorted(unknown)},missing={sorted(missing)}", code="MALFORMED_ENVELOPE")
    if env["schema"] != IPC_REQUEST_SCHEMA:
        raise IPCProtocolError("invalid_request_schema", code="MALFORMED_ENVELOPE")
    if env["deployment_id"] != expected_deployment_id:
        raise IPCProtocolError("deployment_id_mismatch", code="SIGNATURE_INVALID")
    if env["project_id"] != expected_project_id:
        raise IPCProtocolError("project_id_mismatch", code="SIGNATURE_INVALID")
    if env["receiver_id"] != expected_receiver_id:
        raise IPCProtocolError("receiver_id_mismatch", code="SIGNATURE_INVALID")
    if env["channel"] != expected_channel:
        raise IPCProtocolError("channel_mismatch", code="OPERATION_NOT_ALLOWED")

    op = env["operation"]
    if not isinstance(op, str) or not op:
        raise IPCProtocolError("invalid_operation", code="OPERATION_NOT_ALLOWED")
    if expected_channel == "worker" and op not in WORKER_ALLOWED_OPERATIONS:
        raise IPCProtocolError(f"operation_not_allowed_on_worker_socket:{op}", code="OPERATION_NOT_ALLOWED")
    if expected_channel == "control" and op not in CONTROL_ALLOWED_OPERATIONS:
        raise IPCProtocolError(f"operation_not_allowed_on_control_socket:{op}", code="OPERATION_NOT_ALLOWED")

    for str_field in ("request_id", "principal_id", "nonce", "payload_sha256", "signer_pub", "signature"):
        if not isinstance(env[str_field], str) or not env[str_field].strip():
            raise IPCProtocolError(f"invalid_string_field:{str_field}", code="MALFORMED_ENVELOPE")
    if len(env["nonce"]) < 16:
        raise IPCProtocolError("nonce_too_short", code="MALFORMED_ENVELOPE")

    if expected_principal_id is not None and env["principal_id"] != expected_principal_id:
        raise IPCProtocolError("principal_id_mismatch_for_peer_uid", code="PEER_UID_UNAUTHORIZED")
    if expected_signer_pub is not None and env["signer_pub"] != expected_signer_pub:
        raise IPCProtocolError("signer_pub_mismatch_for_peer_uid", code="SIGNATURE_INVALID")

    issued_at = env["issued_at"]
    expires_at = env["expires_at"]
    if type(issued_at) is not int or type(expires_at) is not int or expires_at < issued_at:
        raise IPCProtocolError("invalid_timestamps", code="EXPIRED_REQUEST")

    now = max(int(time.time()) if now_unix is None else int(now_unix), int(high_water_unix))
    if issued_at > now + max_skew_s:
        raise IPCProtocolError("request_issued_in_future", code="EXPIRED_REQUEST")
    if expires_at < now - max_skew_s or expires_at < now:
        raise IPCProtocolError("request_expired", code="EXPIRED_REQUEST")

    payload = env["payload"]
    if not isinstance(payload, dict):
        raise IPCProtocolError("payload_must_be_object", code="MALFORMED_ENVELOPE")
    actual_payload_sha = sha256_hex(payload)
    if actual_payload_sha != env["payload_sha256"]:
        raise IPCProtocolError("payload_sha256_mismatch", code="SIGNATURE_INVALID")

    signable = {
        "schema": env["schema"],
        "deployment_id": env["deployment_id"],
        "project_id": env["project_id"],
        "receiver_id": env["receiver_id"],
        "channel": env["channel"],
        "request_id": env["request_id"],
        "principal_id": env["principal_id"],
        "operation": env["operation"],
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": env["nonce"],
        "payload_sha256": actual_payload_sha,
        "signer_pub": env["signer_pub"],
    }
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(env["signer_pub"]))
        pub.verify(bytes.fromhex(env["signature"]), canonical_json_bytes(signable))
    except Exception as exc:
        raise IPCProtocolError("ed25519_signature_invalid", code="SIGNATURE_INVALID") from exc

    return signable


def sign_ipc_response(
    receiver_key: Ed25519PrivateKey,
    *,
    deployment_id: str,
    project_id: str,
    receiver_id: str,
    request_id: str,
    request_sha256: str,
    status: str,
    code: str,
    result: dict[str, Any],
    receipt_sha256: str | None = None,
    replayed: bool = False,
    at_unix: int | None = None,
) -> dict[str, Any]:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    now = int(time.time()) if at_unix is None else int(at_unix)
    pub_hex = receiver_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    res_sha = sha256_hex(result)
    signable = {
        "schema": IPC_RESPONSE_SCHEMA,
        "deployment_id": deployment_id,
        "project_id": project_id,
        "receiver_id": receiver_id,
        "request_id": request_id,
        "request_sha256": request_sha256,
        "status": status,
        "code": code,
        "replayed": bool(replayed),
        "at_unix": now,
        "result_sha256": res_sha,
        "receipt_sha256": receipt_sha256,
        "receiver_pub": pub_hex,
    }
    sig_hex = receiver_key.sign(canonical_json_bytes(signable)).hex()
    return {
        **signable,
        "result": result,
        "signature": sig_hex,
    }


def verify_ipc_response_envelope(
    resp: dict[str, Any],
    *,
    pinned_receiver_pub: str,
    expected_request_id: str | None = None,
    expected_request_sha256: str | None = None,
) -> dict[str, Any]:
    if not isinstance(resp, dict):
        raise IPCProtocolError("response_not_dict", code="MALFORMED_ENVELOPE")
    unknown = set(resp.keys()) - RESPONSE_ENVELOPE_FIELDS
    missing = RESPONSE_ENVELOPE_FIELDS - set(resp.keys())
    if unknown or missing:
        raise IPCProtocolError("response_fields_invalid", code="MALFORMED_ENVELOPE")
    if resp["schema"] != IPC_RESPONSE_SCHEMA:
        raise IPCProtocolError("invalid_response_schema", code="MALFORMED_ENVELOPE")
    if resp["receiver_pub"] != pinned_receiver_pub:
        raise IPCProtocolError("untrusted_receiver_pub_in_response", code="SIGNATURE_INVALID")
    if expected_request_id is not None and resp["request_id"] != expected_request_id:
        raise IPCProtocolError("response_request_id_mismatch", code="SIGNATURE_INVALID")
    if expected_request_sha256 is not None and resp["request_sha256"] != expected_request_sha256:
        raise IPCProtocolError("response_request_sha256_mismatch", code="SIGNATURE_INVALID")
    if sha256_hex(resp["result"]) != resp["result_sha256"]:
        raise IPCProtocolError("response_result_sha256_mismatch", code="SIGNATURE_INVALID")

    signable = {
        "schema": resp["schema"],
        "deployment_id": resp["deployment_id"],
        "project_id": resp["project_id"],
        "receiver_id": resp["receiver_id"],
        "request_id": resp["request_id"],
        "request_sha256": resp["request_sha256"],
        "status": resp["status"],
        "code": resp["code"],
        "replayed": resp["replayed"],
        "at_unix": resp["at_unix"],
        "result_sha256": resp["result_sha256"],
        "receipt_sha256": resp["receipt_sha256"],
        "receiver_pub": resp["receiver_pub"],
    }
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pinned_receiver_pub))
        pub.verify(bytes.fromhex(resp["signature"]), canonical_json_bytes(signable))
    except Exception as exc:
        raise IPCProtocolError("response_signature_invalid", code="SIGNATURE_INVALID") from exc
    return resp


class PerUIDRateLimiter:
    """Thread-safe per-UID token bucket rate limiter."""

    def __init__(self, *, burst: int = 60, rate_per_sec: float = 30.0):
        self.burst = float(burst)
        self.rate = float(rate_per_sec)
        self._lock = threading.Lock()
        self._buckets: dict[int, tuple[float, float]] = {}

    def allow(self, uid: int) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, last_ts = self._buckets.get(uid, (self.burst, now))
            elapsed = max(0.0, now - last_ts)
            tokens = min(self.burst, tokens + elapsed * self.rate)
            if tokens < 1.0:
                self._buckets[uid] = (tokens, now)
                return False
            self._buckets[uid] = (tokens - 1.0, now)
            return True
