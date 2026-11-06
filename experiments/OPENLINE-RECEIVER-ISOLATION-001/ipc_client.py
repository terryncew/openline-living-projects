"""OpenLine Production Isolation — Unix Socket IPC Client (`ipc_client.py`).

Implements Section 4.1, 4.2, and 5 of Astra's Production Isolation Blueprint:
- Thin authenticated client communicating with `worker.sock` or `control.sock`.
- Signs outbound `openline.ipc.request.v1` envelopes with the caller's Ed25519 key.
- Verifies inbound `openline.ipc.response.v1` envelopes against `pinned_receiver_pub`.
- Provides high-level helpers for `prepare` (materializing an independent client-owned workspace
  via `snapshot.chunk`), `submit_proposal` (packaging regular files from the client workspace into
  `proposal.submit`), `status`, `stop`, `clear`, `assign`, `change_dependency`, `revoke_member`,
  and `reconcile`.
"""
from __future__ import annotations

from pathlib import Path
import socket
import uuid
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from candidate_transfer import (
    collect_client_candidate_files,
    materialize_client_workspace,
)
from ipc_protocol import (
    MAX_FRAME_BYTES,
    canonical_json_bytes,
    recv_frame,
    send_frame,
    sha256_hex,
    sign_ipc_request,
    strict_loads_json,
    verify_ipc_response_envelope,
)


class OpenLineIPCClient:
    """Authenticated Unix domain socket client for worker and control channels."""

    def __init__(
        self,
        *,
        socket_path: Path | str,
        channel: str,
        deployment_id: str,
        project_id: str,
        receiver_id: str,
        principal_id: str,
        signer_key: Ed25519PrivateKey,
        pinned_receiver_pub: str,
        timeout_s: float = 60.0,
    ):
        self.socket_path = Path(socket_path)
        self.channel = channel
        self.deployment_id = deployment_id
        self.project_id = project_id
        self.receiver_id = receiver_id
        self.principal_id = principal_id
        self.signer_key = signer_key
        self.pinned_receiver_pub = pinned_receiver_pub
        self.timeout_s = timeout_s

    def call(
        self,
        operation: str,
        payload: dict[str, Any] | None = None,
        *,
        request_id: str | None = None,
        nonce: str | None = None,
        issued_at: int | None = None,
        expires_at: int | None = None,
    ) -> dict[str, Any]:
        req_id = request_id or f"req-{uuid.uuid4().hex}"
        env = sign_ipc_request(
            self.signer_key,
            deployment_id=self.deployment_id,
            project_id=self.project_id,
            receiver_id=self.receiver_id,
            channel=self.channel,
            request_id=req_id,
            principal_id=self.principal_id,
            operation=operation,
            payload=payload or {},
            issued_at=issued_at,
            expires_at=expires_at,
            nonce=nonce,
        )
        req_sha = sha256_hex(env)
        return self.send_raw_envelope(env, expected_request_id=req_id, expected_request_sha256=req_sha)

    def send_raw_envelope(
        self,
        env: dict[str, Any],
        *,
        expected_request_id: str | None = None,
        expected_request_sha256: str | None = None,
    ) -> dict[str, Any]:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout_s)
            sock.connect(str(self.socket_path))
            send_frame(sock, canonical_json_bytes(env), max_frame_bytes=MAX_FRAME_BYTES)
            raw_resp = recv_frame(sock, max_frame_bytes=MAX_FRAME_BYTES)
        resp = strict_loads_json(raw_resp)
        verify_ipc_response_envelope(
            resp,
            pinned_receiver_pub=self.pinned_receiver_pub,
            expected_request_id=expected_request_id,
            expected_request_sha256=expected_request_sha256,
        )
        return resp

    def prepare_workspace(
        self,
        assignment_id: str,
        dest_dir: Path | str,
        *,
        propose_memory: str | None = None,
        diagnosis: str | None = None,
        lesson: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"assignment_id": assignment_id}
        if propose_memory:
            payload["propose_memory"] = propose_memory
            if diagnosis:
                payload["diagnosis"] = diagnosis
            if lesson:
                payload["lesson"] = lesson
        prep_resp = self.call("assignment.prepare", payload)
        if prep_resp["status"] != "OK":
            return prep_resp
        manifest = prep_resp["result"]["manifest"]

        def _fetch_chunk(*, assignment_id: str, target: str, offset: int, length: int) -> dict[str, Any]:
            c_resp = self.call(
                "snapshot.chunk",
                {"assignment_id": assignment_id, "target": target, "offset": offset, "length": length},
            )
            if c_resp["status"] != "OK":
                raise RuntimeError(f"snapshot_chunk_failed:{c_resp}")
            return c_resp["result"]

        local_paths = materialize_client_workspace(
            _fetch_chunk,
            manifest,
            dest_dir,
            assignment_id=assignment_id,
        )
        prep_resp["result"]["client_workspace"] = local_paths["workspace"]
        prep_resp["result"]["client_snapshot_db"] = local_paths["snapshot_db"]
        return prep_resp

    def submit_workspace_proposal(
        self,
        assignment_id: str,
        client_workspace: Path | str,
        *,
        allowed_paths: list[str] | tuple[str, ...] | None = None,
        request_id: str | None = None,
        nonce: str | None = None,
    ) -> dict[str, Any]:
        files = collect_client_candidate_files(client_workspace, allowed_paths=allowed_paths)
        return self.call(
            "proposal.submit",
            {"assignment_id": assignment_id, "files": files},
            request_id=request_id,
            nonce=nonce,
        )
