"""Small bounded stream framing; works on TLS sockets (which forbid recvmsg)."""
import hashlib
import json
import socket
import struct
import time

MAX_FRAME = 8 * 1024 * 1024


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def digest(data):
    return hashlib.sha256(data if isinstance(data, (bytes, bytearray)) else canonical(data)).hexdigest()


def strict(raw):
    if isinstance(raw, (bytes, bytearray)):
        try:
            text = bytes(raw).decode('utf-8')
        except UnicodeDecodeError as exc:
            raise ValueError('invalid utf-8') from exc
        if text.startswith('\ufeff'):
            raise ValueError('bom forbidden')
    elif isinstance(raw, str):
        text = raw
    else:
        raise ValueError('bytes or str required')

    def pairs(items):
        result = {}
        for k, v in items:
            if k in result:
                raise ValueError('duplicate key')
            result[k] = v
        return result

    def reject(_):
        raise ValueError('non-integer numeric value')

    try:
        obj = json.loads(text, object_pairs_hook=pairs, parse_float=reject, parse_constant=reject)
    except RecursionError as exc:
        raise ValueError('depth limit') from exc

    def depth(x, n=0):
        if n > 16:
            raise ValueError('depth limit')
        if isinstance(x, (dict, list)):
            for value in (x.values() if isinstance(x, dict) else x):
                depth(value, n + 1)

    try:
        depth(obj)
    except RecursionError as exc:
        raise ValueError('depth limit') from exc
    if not isinstance(obj, dict):
        raise ValueError('object required')
    return obj


def recv(sock, limit=MAX_FRAME, timeout=10):
    if type(limit) is not int or not 0 < limit <= MAX_FRAME:
        raise ValueError('invalid frame limit')
    deadline = time.monotonic() + timeout

    def exact(n):
        parts = []
        while n:
            remain = deadline - time.monotonic()
            if remain <= 0:
                raise TimeoutError('frame deadline')
            sock.settimeout(remain)
            chunk = sock.recv(min(n, 65536))
            if not chunk:
                raise EOFError('truncated frame')
            parts.append(chunk)
            n -= len(chunk)
        return b''.join(parts)

    n = struct.unpack('!I', exact(4))[0]
    if not 0 < n <= limit:
        raise ValueError('frame length')
    return exact(n)


def send(sock, raw, limit=MAX_FRAME):
    if not isinstance(raw, (bytes, bytearray)) or not 0 < len(raw) <= min(limit, MAX_FRAME):
        raise ValueError('frame length')
    sock.sendall(struct.pack('!I', len(raw)) + bytes(raw))


def peer(sock):
    return struct.unpack('3i', sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
