"""One worker per unprivileged gateway UID; mTLS plus unchanged RC5 signatures.

This gateway has no receiver/worker signing key and never connects control.sock.
The receiver independently authenticates the gateway's kernel UID and live worker key.
"""
import argparse
import hashlib
import hmac
import json
import socket
import ssl
import threading
import time
from pathlib import Path
from wire import canonical, digest, peer, recv, send, strict

ALLOWED = frozenset({
    'project.status',
    'assignment.prepare',
    'snapshot.chunk',
    'proposal.submit',
    'request.get',
    'receipt.get',
})

REQUIRED_ENVELOPE_FIELDS = frozenset({
    'schema',
    'deployment_id',
    'project_id',
    'receiver_id',
    'channel',
    'request_id',
    'principal_id',
    'operation',
    'issued_at',
    'expires_at',
    'nonce',
    'payload',
    'payload_sha256',
    'signer_pub',
    'signature',
})


def _is_hex(val, length):
    if not isinstance(val, str) or len(val) != length:
        return False
    try:
        bytes.fromhex(val)
        return True
    except ValueError:
        return False


class Gateway:
    def __init__(self, config):
        if not isinstance(config, dict):
            raise ValueError('gateway config must be dict')
        principal_id = config.get('principal_id')
        if not isinstance(principal_id, str) or not principal_id.startswith('worker:') or len(principal_id) <= len('worker:'):
            raise PermissionError('gateway principal_id must be worker:<member>')
        if not _is_hex(config.get('client_cert_sha256'), 64):
            raise ValueError('invalid client_cert_sha256 pin')
        if not _is_hex(config.get('receiver_pub'), 64):
            raise ValueError('invalid receiver_pub pin')
        if type(config.get('receiver_uid')) is not int or config['receiver_uid'] < 0:
            raise ValueError('invalid receiver_uid')
        self.cfg = dict(config)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.options |= getattr(ssl, 'OP_NO_TICKET', 0) | getattr(ssl, 'OP_NO_COMPRESSION', 0)
        ctx.load_cert_chain(config['cert'], config['key'])
        ctx.load_verify_locations(config['ca'])
        self.ctx = ctx
        self.stop_event = threading.Event()
        self.slots = threading.BoundedSemaphore(int(config.get('max_concurrent', 8)))
        self.rate_lock = threading.Lock()
        self.tokens, self.last = 20.0, time.monotonic()
        self.listener = None
        self.backend_forwards = 0

    def allow(self):
        with self.rate_lock:
            now = time.monotonic()
            self.tokens = min(20.0, self.tokens + (now - self.last) * 10.0)
            self.last = now
            if self.tokens < 1.0:
                return False
            self.tokens -= 1.0
            return True

    def _validate_worker_envelope(self, env):
        if set(env) != REQUIRED_ENVELOPE_FIELDS:
            raise PermissionError('envelope fields mismatch')
        if env.get('schema') != 'openline.ipc.request.v1':
            raise PermissionError('request schema mismatch')
        if env.get('channel') != 'worker' or env.get('principal_id') != self.cfg['principal_id'] or env.get('operation') not in ALLOWED:
            raise PermissionError('worker lane only')
        for bind_key in ('deployment_id', 'project_id', 'receiver_id'):
            val = env.get(bind_key)
            if not isinstance(val, str) or not val:
                raise PermissionError(f'invalid {bind_key}')
            if bind_key in self.cfg and val != self.cfg[bind_key]:
                raise PermissionError(f'{bind_key} pin mismatch')
        if 'worker_pub' in self.cfg and env.get('signer_pub') != self.cfg['worker_pub']:
            raise PermissionError('worker_pub pin mismatch')
        req_id = env.get('request_id')
        nonce = env.get('nonce')
        if not isinstance(req_id, str) or not (1 <= len(req_id) <= 128):
            raise PermissionError('invalid request_id')
        if not isinstance(nonce, str) or not (16 <= len(nonce) <= 128):
            raise PermissionError('invalid nonce')
        if type(env.get('issued_at')) is not int or type(env.get('expires_at')) is not int:
            raise PermissionError('invalid timestamps')
        if not _is_hex(env.get('signer_pub'), 64) or not _is_hex(env.get('signature'), 128):
            raise PermissionError('invalid signature fields')
        payload = env.get('payload')
        if not isinstance(payload, dict) or digest(payload) != env.get('payload_sha256'):
            raise PermissionError('payload digest mismatch')

    def handle(self, raw):
        try:
            raw.settimeout(3)
            with self.ctx.wrap_socket(raw, server_side=True) as tls:
                peer_der = tls.getpeercert(binary_form=True)
                if not peer_der or tls.version() != 'TLSv1.3':
                    raise PermissionError('tls1.3 client cert required')
                actual_pin = hashlib.sha256(peer_der).hexdigest()
                if not hmac.compare_digest(actual_pin, self.cfg['client_cert_sha256'].lower()):
                    raise PermissionError('client certificate pin')
                frame = recv(tls, timeout=5)
                env = strict(frame)
                self._validate_worker_envelope(env)
                canon_frame = canonical(env)
                with socket.socket(socket.AF_UNIX) as backend:
                    backend.settimeout(35)
                    backend.connect(self.cfg['worker_socket'])
                    # SO_PEERCRED is checked here too: never trust a replaced backend socket.
                    if peer(backend)[1] != self.cfg['receiver_uid']:
                        raise PermissionError('receiver uid')
                    self.backend_forwards += 1
                    send(backend, canon_frame)
                    response = recv(backend, timeout=35)
                # Reject forged/substituted responses even if Unix endpoint is misconfigured.
                from ipc_protocol import verify_ipc_response_envelope
                resp_obj = strict(response)
                verify_ipc_response_envelope(
                    resp_obj,
                    pinned_receiver_pub=self.cfg['receiver_pub'],
                    expected_request_id=env['request_id'],
                    expected_request_sha256=digest(env),
                )
                send(tls, canonical(resp_obj))
        except Exception:
            # No invented receiver signature on gateway errors. Client receives unknown/transport failure.
            pass
        finally:
            try:
                raw.close()
            except OSError:
                pass
            self.slots.release()

    def serve(self):
        with socket.socket() as listener:
            self.listener = listener
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self.cfg['bind'], self.cfg['port']))
            listener.listen(16)
            listener.settimeout(0.2)
            self.port = listener.getsockname()[1]
            while not self.stop_event.is_set():
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    continue
                if not self.allow():
                    conn.close()
                    continue
                if not self.slots.acquire(blocking=False):
                    conn.close()
                    continue
                threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def stop(self):
        self.stop_event.set()


def client_context(ca, cert, key):
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert, key)
    return ctx


def exchange(host, port, context, envelope, receiver_pub):
    from ipc_protocol import verify_ipc_response_envelope
    with socket.create_connection((host, port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname='openline.local') as sock:
            send(sock, canonical(envelope))
            response = strict(recv(sock, timeout=40))
    return verify_ipc_response_envelope(
        response,
        pinned_receiver_pub=receiver_pub,
        expected_request_id=envelope['request_id'],
        expected_request_sha256=digest(envelope),
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    parser.add_argument('--rc5', required=True)
    args = parser.parse_args()
    from rc5_paths import load
    load(args.rc5)
    Gateway(json.loads(Path(args.config).read_text())).serve()


if __name__ == '__main__':
    main()
