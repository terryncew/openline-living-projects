"""OpenLine Production Isolation — Durable I/O, openat2 / O_NOFOLLOW traversal, and SQLite WAL+FULL helpers.

Implements Section 4.1, 4.3.2, and 4.4 of Astra's Production Isolation Blueprint:
- Kernel-enforced `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV)`
  (syscall 437 on x86_64 Linux) with strict step-by-step `O_NOFOLLOW | O_CLOEXEC | O_DIRECTORY`
  descriptor-walk fallback when the host kernel / container returns `ENOSYS` (e.g. gVisor 4.19).
- Hardlink count (`st_nlink == 1`), regular-file mode, and cross-device (`st_dev`) verification.
- Crash-safe atomic file writes (`O_CREAT | O_EXCL | O_NOFOLLOW`, `fsync(file)`, `os.replace`, `fsync(parent_dir)`).
- Durable SQLite connection factory (`journal_mode=WAL`, `synchronous=FULL`, `foreign_keys=ON`, sidecar symlink checks).
"""
from __future__ import annotations

import ctypes
import errno
import json
import os
from pathlib import Path
import sqlite3
import stat
import unicodedata
import uuid


RESOLVE_NO_XDEV = 0x01
RESOLVE_NO_MAGICLINKS = 0x02
RESOLVE_NO_SYMLINKS = 0x04
RESOLVE_BENEATH = 0x08
SYS_OPENAT2_X86_64 = 437


class OpenAt2Error(PermissionError):
    """Raised when path resolution violates containment, symlink, magic-link, xdev, or hardlink rules."""


class _OpenHow(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]


_LIBC = None
try:
    _LIBC = ctypes.CDLL("libc.so.6", use_errno=True)
except Exception:
    _LIBC = None


def validate_relative_subpath(relpath: str) -> tuple[str, list[str]]:
    """Validate and NFC-normalize a relative subpath. Rejects absolute, traversal, NUL, or backslash paths."""
    if not isinstance(relpath, str) or not relpath:
        raise OpenAt2Error("invalid_empty_relpath")
    if "\x00" in relpath or "\\" in relpath:
        raise OpenAt2Error("invalid_relpath_characters")
    norm = unicodedata.normalize("NFC", relpath)
    if norm != relpath:
        raise OpenAt2Error("non_nfc_relpath_forbidden")
    if norm.startswith("/") or norm.endswith("/"):
        raise OpenAt2Error("absolute_or_trailing_slash_forbidden")
    parts = norm.split("/")
    if any(not p or p in (".", "..") for p in parts):
        raise OpenAt2Error("dot_or_empty_path_segment_forbidden")
    if parts[0] in ("proc", "sys", "dev"):
        raise OpenAt2Error("magic_namespace_prefix_forbidden")
    return norm, parts


def kernel_supports_native_openat2() -> bool:
    """Return True if the running kernel supports Linux 5.6+ openat2 (syscall 437)."""
    try:
        root_fd = os.open(".", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return False
    try:
        fd, err = _try_native_openat2(
            root_fd,
            b".",
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
            0,
            RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV,
        )
        if fd >= 0:
            os.close(fd)
            return True
        return err != errno.ENOSYS
    finally:
        os.close(root_fd)


def _try_native_openat2(root_fd: int, relpath_bytes: bytes, flags: int, mode: int, resolve: int) -> tuple[int, int]:
    import platform
    if platform.machine() not in ("x86_64", "aarch64"):
        return -1, errno.ENOSYS
    if _LIBC is None:
        return -1, errno.ENOSYS
    how = _OpenHow(
        flags=ctypes.c_uint64(flags),
        mode=ctypes.c_uint64(mode if (flags & os.O_CREAT) else 0),
        resolve=ctypes.c_uint64(resolve),
    )
    ctypes.set_errno(0)
    fd = int(_LIBC.syscall(SYS_OPENAT2_X86_64, int(root_fd), relpath_bytes, ctypes.byref(how), ctypes.sizeof(how)))
    if fd < 0:
        return -1, ctypes.get_errno() or errno.EPERM
    return fd, 0


def open_beneath(
    root_dir: Path | str,
    relpath: str,
    flags: int = os.O_RDONLY,
    mode: int = 0o600,
    *,
    require_native_openat2: bool = True,
    check_single_link: bool = True,
    expect_regular: bool = True,
) -> int:
    """Safely open a file strictly beneath `root_dir` without following symlinks or crossing filesystems.

    Returns an open file descriptor with `O_CLOEXEC`. Caller is responsible for closing the returned fd.
    """
    norm, parts = validate_relative_subpath(relpath)
    root_path = Path(root_dir)
    if root_path.is_symlink():
        raise OpenAt2Error("root_dir_symlink_forbidden")
    open_root_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        root_fd = os.open(str(root_path), open_root_flags)
    except OSError as exc:
        raise OpenAt2Error(f"root_dir_open_failed:{exc.errno}") from exc

    try:
        root_st = os.fstat(root_fd)
        if not stat.S_ISDIR(root_st.st_mode):
            raise OpenAt2Error("root_not_directory")

        leaf_flags = int(flags) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        resolve_mask = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV
        fd, err = _try_native_openat2(root_fd, norm.encode("utf-8"), leaf_flags, mode, resolve_mask)
        if fd >= 0:
            try:
                st = os.fstat(fd)
                if st.st_dev != root_st.st_dev:
                    raise OpenAt2Error("cross_device_resolution_forbidden")
                if expect_regular and not stat.S_ISREG(st.st_mode):
                    raise OpenAt2Error("not_a_regular_file")
                if check_single_link and stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
                    raise OpenAt2Error("hardlink_forbidden")
                return fd
            except BaseException:
                os.close(fd)
                raise

        if err != errno.ENOSYS or require_native_openat2:
            err_name = errno.errorcode.get(err, str(err))
            raise OpenAt2Error(f"openat2_rejected:{err_name}")

        # Fallback for kernels where syscall 437 returns ENOSYS (e.g. gVisor 4.19 container kernel):
        # Step-by-step directory descriptor walk with O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC and directory st_dev check.
        cur_fd = os.dup(root_fd)
        try:
            dir_step_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            for seg in parts[:-1]:
                try:
                    next_fd = os.open(seg, dir_step_flags, dir_fd=cur_fd)
                except OSError as exc:
                    ename = errno.errorcode.get(exc.errno, str(exc.errno))
                    raise OpenAt2Error(f"dir_walk_rejected:{seg}:{ename}") from exc
                os.close(cur_fd)
                cur_fd = next_fd
                st_dir = os.fstat(cur_fd)
                if not stat.S_ISDIR(st_dir.st_mode):
                    raise OpenAt2Error(f"intermediate_not_directory:{seg}")
                if st_dir.st_dev != root_st.st_dev:
                    raise OpenAt2Error(f"cross_device_resolution_forbidden:{seg}")

            leaf = parts[-1]
            try:
                leaf_fd = os.open(leaf, leaf_flags, mode, dir_fd=cur_fd)
            except OSError as exc:
                ename = errno.errorcode.get(exc.errno, str(exc.errno))
                raise OpenAt2Error(f"leaf_open_rejected:{leaf}:{ename}") from exc
            try:
                st = os.fstat(leaf_fd)
                if stat.S_ISDIR(st.st_mode) and st.st_dev != root_st.st_dev:
                    raise OpenAt2Error("cross_device_resolution_forbidden")
                if expect_regular and not stat.S_ISREG(st.st_mode):
                    raise OpenAt2Error("not_a_regular_file")
                if check_single_link and stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
                    raise OpenAt2Error("hardlink_forbidden")
                return leaf_fd
            except BaseException:
                os.close(leaf_fd)
                raise
        finally:
            os.close(cur_fd)
    finally:
        os.close(root_fd)


def read_bytes_beneath(
    root_dir: Path | str,
    relpath: str,
    *,
    max_bytes: int | None = None,
    check_single_link: bool = True,
    require_native_openat2: bool = True,
) -> bytes:
    """Safely read a regular file strictly beneath `root_dir` with optional size cap."""
    fd = open_beneath(
        root_dir,
        relpath,
        os.O_RDONLY,
        require_native_openat2=require_native_openat2,
        check_single_link=check_single_link,
        expect_regular=True,
    )
    try:
        st = os.fstat(fd)
        if max_bytes is not None and st.st_size > max_bytes:
            raise OpenAt2Error(f"file_exceeds_max_bytes:{st.st_size}>{max_bytes}")
        chunks: list[bytes] = []
        total = 0
        while True:
            buf = os.read(fd, 65536)
            if not buf:
                break
            total += len(buf)
            if max_bytes is not None and total > max_bytes:
                raise OpenAt2Error(f"file_exceeds_max_bytes_during_read:{total}>{max_bytes}")
            chunks.append(buf)
        return b"".join(chunks)
    finally:
        os.close(fd)


def fsync_directory(dir_path: Path | str) -> None:
    """Flush directory entries to durable storage."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(str(dir_path), flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write_bytes(target_path: Path | str, data: bytes, *, mode: int = 0o600, dir_mode: int = 0o700) -> None:
    """Durably write `data` to `target_path` via exclusive temp file + fsync(file) + os.replace + fsync(dir)."""
    target = Path(target_path)
    if target.is_symlink():
        raise OpenAt2Error(f"target_symlink_forbidden:{target}")
    parent = target.parent
    if parent.is_symlink():
        raise OpenAt2Error(f"parent_symlink_forbidden:{parent}")
    parent.mkdir(parents=True, exist_ok=True, mode=dir_mode)
    tmp_name = f".{target.name}.tmp.{os.getpid()}.{uuid.uuid4().hex}"
    tmp_path = parent / tmp_name
    open_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(str(tmp_path), open_flags, mode)
    try:
        os.fchmod(fd, mode)
        view = memoryview(data)
        written = 0
        while written < len(view):
            n = os.write(fd, view[written:])
            if n <= 0:
                raise OSError("short_write")
            written += n
        os.fsync(fd)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    os.close(fd)
    os.replace(str(tmp_path), str(target))
    fsync_directory(parent)


def atomic_write_json(target_path: Path | str, obj: dict, *, mode: int = 0o600, dir_mode: int = 0o700, indent: int | None = 2) -> bytes:
    """Durably write canonical JSON to `target_path` and return the exact bytes written."""
    if indent is None:
        raw = (json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    else:
        raw = (json.dumps(obj, sort_keys=True, indent=indent, ensure_ascii=False) + "\n").encode("utf-8")
    atomic_write_bytes(target_path, raw, mode=mode, dir_mode=dir_mode)
    return raw


def check_sqlite_sidecars(db_path: Path | str, *, expected_uid: int | None = None, forbidden_gids: set[int] | None = None) -> list[str]:
    """Verify SQLite database file and any existing sidecars (-wal, -shm, -journal, .gate.lock) are safe."""
    base = Path(db_path)
    reasons: list[str] = []
    candidates = [
        ("db", base),
        ("wal", Path(str(base) + "-wal")),
        ("shm", Path(str(base) + "-shm")),
        ("journal", Path(str(base) + "-journal")),
        ("gate_lock", Path(str(base) + ".gate.lock")),
        ("control_db", Path(str(base) + ".control.sqlite")),
        ("control_wal", Path(str(base) + ".control.sqlite-wal")),
        ("control_shm", Path(str(base) + ".control.sqlite-shm")),
    ]
    for suffix_label, p in candidates:
        if p.is_symlink():
            reasons.append(f"{suffix_label}_symlink_forbidden")
            continue
        if not p.exists():
            continue
        st = p.stat()
        if not stat.S_ISREG(st.st_mode):
            reasons.append(f"{suffix_label}_not_regular_file")
        if st.st_nlink > 1:
            reasons.append(f"{suffix_label}_hardlink_forbidden")
        if expected_uid is not None and st.st_uid != expected_uid:
            reasons.append(f"{suffix_label}_not_receiver_owned")
        if st.st_mode & 0o002:
            reasons.append(f"{suffix_label}_world_writable")
        if forbidden_gids and (st.st_mode & 0o020) and st.st_gid in forbidden_gids:
            reasons.append(f"{suffix_label}_group_writable_by_untrusted")
    return reasons


def connect_durable_sqlite(
    db_path: Path | str,
    *,
    read_only: bool = False,
    require_existing: bool = False,
    timeout: float = 15.0,
) -> sqlite3.Connection:
    """Open a SQLite database with production durability and sidecar safety checks."""
    p = Path(db_path)
    sidecar_issues = check_sqlite_sidecars(p)
    if sidecar_issues:
        raise OpenAt2Error("sqlite_sidecar_violation:" + ";".join(sidecar_issues))
    if read_only:
        if not p.is_file():
            raise FileNotFoundError(f"sqlite_db_missing:{p}")
        uri = f"file:{p.resolve()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=timeout)
        conn.execute("PRAGMA query_only = ON")
        return conn
    if require_existing and not p.is_file():
        raise FileNotFoundError(f"sqlite_db_missing:{p}")
    if require_existing:
        uri = f"file:{p.resolve()}?mode=rw"
        conn = sqlite3.connect(uri, uri=True, timeout=timeout)
    else:
        conn = sqlite3.connect(str(p), timeout=timeout)
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = FULL")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute(f"PRAGMA busy_timeout = {int(timeout * 1000)}")
    conn.execute("PRAGMA temp_store = MEMORY")
    return conn
