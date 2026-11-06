"""OpenLine Production Isolation — Startup Boundary & Process Hygiene Preflight Auditor.

Implements Section 2.1, 4.1, and 7.2 (`OS-01` .. `OS-04`, `AUTH-02`) of Astra's Production Isolation Blueprint:
- Verifies real/effective/saved UID and GID match configured `receiver_uid` / `receiver_gid`.
- Verifies supplementary groups do not overlap with any worker or validator group.
- Verifies `NoNewPrivs == 1` and `CapEff == 0` when systemd hardening enforcement is enabled.
- Verifies `owner.key` is completely absent from the receiver directory tree.
- Verifies `receiver.key` is a regular file with mode `0400` or `0600` owned by `receiver_uid`.
- Verifies all receiver state paths, SQLite sidecars (`-wal`, `-shm`, `-journal`, `.gate.lock`),
  parent directories, and socket directories have no symlinks, no world-writable bits,
  no worker/validator group write access, and no POSIX ACLs (`system.posix_acl_access`).
"""
from __future__ import annotations

from dataclasses import dataclass, field
import grp
import os
from pathlib import Path
import pwd
import stat
from typing import Any

from durable_io import check_sqlite_sidecars
from git_runner import SanitizedGitRunner


@dataclass
class PreflightReport:
    ok: bool
    reasons: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


def resolve_uid_groups(uid: int) -> set[int]:
    """Resolve primary + all supplementary GIDs for `uid` using pwd, os.getgrouplist, and grp.getgrall."""
    pw = pwd.getpwuid(uid)
    gids = {pw.pw_gid}
    uname = pw.pw_name
    if hasattr(os, "getgrouplist"):
        try:
            gids.update(os.getgrouplist(uname, pw.pw_gid))
        except OSError:
            pass
    for entry in grp.getgrall():
        if uname in entry.gr_mem or uid in entry.gr_mem:
            gids.add(entry.gr_gid)
    return gids


def _has_posix_acl(path: Path) -> bool:
    if not hasattr(os, "listxattr"):
        return False
    try:
        attrs = os.listxattr(str(path), follow_symlinks=False)
        return "system.posix_acl_access" in attrs or "system.posix_acl_default" in attrs
    except OSError:
        return False


def _read_proc_self_status() -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


def audit_production_preflight(
    config: dict[str, Any],
    *,
    require_distinct_uids: bool = True,
    require_systemd_hardening: bool = False,
) -> PreflightReport:
    reasons: list[str] = []
    details: dict[str, Any] = {}

    receiver_uid = int(config["receiver_uid"])
    receiver_gid = int(config["receiver_gid"])
    validator_uid = int(config["validator_uid"])
    validator_gid = int(config["validator_gid"])
    worker_uids = [int(w["uid"]) for w in config["worker_principals"].values()]

    # 1. Process credential checks
    ruid, euid, suid = os.getresuid()
    rgid, egid, sgid = os.getresgid()
    proc_groups = set(os.getgroups())
    details["process_credentials"] = {
        "ruid": ruid, "euid": euid, "suid": suid,
        "rgid": rgid, "egid": egid, "sgid": sgid,
        "groups": sorted(proc_groups),
    }
    if (ruid, euid, suid) != (receiver_uid, receiver_uid, receiver_uid):
        reasons.append("receiver_process_uid_mismatch")
    if (rgid, egid, sgid) != (receiver_gid, receiver_gid, receiver_gid):
        reasons.append("receiver_process_gid_mismatch")

    # 2. UID / GID separation checks
    untrusted_gids: set[int] = set()
    if require_distinct_uids:
        if receiver_uid == 0:
            reasons.append("receiver_must_not_run_as_root")
        if validator_uid == receiver_uid:
            reasons.append("validator_uid_equals_receiver_uid")
        for wuid in worker_uids:
            if wuid == receiver_uid:
                reasons.append(f"worker_uid_equals_receiver_uid:{wuid}")
            if wuid == validator_uid:
                reasons.append(f"worker_uid_equals_validator_uid:{wuid}")
            try:
                wgids = resolve_uid_groups(wuid)
                untrusted_gids.update(wgids)
            except KeyError:
                reasons.append(f"worker_uid_unknown:{wuid}")
        try:
            vgids = resolve_uid_groups(validator_uid)
            untrusted_gids.update(vgids)
        except KeyError:
            reasons.append(f"validator_uid_unknown:{validator_uid}")
        if validator_gid == receiver_gid:
            reasons.append("validator_gid_equals_receiver_gid")
        if proc_groups & untrusted_gids:
            reasons.append("receiver_shares_supplementary_group_with_untrusted")

    # 3. Kernel capability / NoNewPrivs checks
    proc_status = _read_proc_self_status()
    cap_eff = proc_status.get("CapEff", "")
    no_new_privs = proc_status.get("NoNewPrivs", "")
    details["proc_status"] = {"CapEff": cap_eff, "NoNewPrivs": no_new_privs}
    if cap_eff and cap_eff != "0000000000000000" and require_distinct_uids:
        reasons.append(f"nonzero_effective_capabilities:{cap_eff}")
    if require_systemd_hardening and no_new_privs != "1":
        reasons.append("no_new_privs_not_enabled")

    paths = config["paths"]
    root_dir = Path(paths["root_dir"])

    # 4. Verify owner.key is NOT present anywhere in receiver tree
    for forbidden_key in (
        root_dir / "owner.key",
        root_dir / "keys" / "owner.key",
        Path(paths["receiver_key_file"]).parent / "owner.key",
    ):
        if forbidden_key.exists() or forbidden_key.is_symlink():
            reasons.append("owner_private_key_present_on_receiver")
            break
    if root_dir.is_dir() and not root_dir.is_symlink():
        for p in root_dir.rglob("owner.key"):
            reasons.append("owner_private_key_present_on_receiver")
            break

    # 5. Verify receiver.key permissions (0400 or 0600, owned by receiver_uid, no symlink, nlink==1)
    key_path = Path(paths["receiver_key_file"])
    if key_path.is_symlink():
        reasons.append("receiver_key_symlink_forbidden")
    elif not key_path.is_file():
        reasons.append("receiver_key_missing")
    else:
        kst = key_path.stat()
        if kst.st_uid != receiver_uid:
            reasons.append("receiver_key_not_receiver_owned")
        if kst.st_mode & 0o077:
            reasons.append("receiver_key_group_or_world_accessible")
        if kst.st_nlink > 1:
            reasons.append("receiver_key_hardlink_forbidden")
        if _has_posix_acl(key_path):
            reasons.append("receiver_key_acl_forbidden")

    # 6. Check all protected state directories and files
    protected_items = [
        ("root_dir", Path(paths["root_dir"])),
        ("accepted_git", Path(paths["accepted_git"])),
        ("project_db", Path(paths["project_db"])),
        ("effects_db", Path(paths["effects_db"])),
        ("promotion_dir", Path(paths["promotion_dir"])),
        ("incidents_dir", Path(paths["incidents_dir"])),
        ("empty_hooks_dir", Path(paths["empty_hooks_dir"])),
    ]
    for label, p in protected_items:
        if p.is_symlink():
            reasons.append(f"{label}_symlink_forbidden")
            continue
        if not p.exists():
            reasons.append(f"{label}_missing")
            continue
        st = p.stat()
        if st.st_uid != receiver_uid:
            reasons.append(f"{label}_not_receiver_owned")
        if st.st_mode & 0o007:
            reasons.append(f"{label}_world_accessible")
        if st.st_mode & 0o020 and st.st_gid in untrusted_gids:
            reasons.append(f"{label}_group_writable_by_untrusted")
        if st.st_mode & 0o077 and label in ("root_dir", "accepted_git", "project_db", "effects_db", "promotion_dir", "incidents_dir"):
            reasons.append(f"{label}_not_mode_0700_or_0600")
        if _has_posix_acl(p):
            reasons.append(f"{label}_acl_forbidden")
        if p.is_dir():
            for sub in p.rglob("*"):
                if sub.is_symlink():
                    reasons.append(f"{label}_contains_symlink")
                    break
                sst = sub.stat()
                if sst.st_uid != receiver_uid:
                    reasons.append(f"{label}_child_not_receiver_owned")
                if sst.st_mode & 0o002:
                    reasons.append(f"{label}_child_world_writable")
                if sst.st_mode & 0o020 and sst.st_gid in untrusted_gids:
                    reasons.append(f"{label}_child_group_writable_by_untrusted")

    # 7. Check SQLite sidecars
    for db_label, db_key in (("project_db", "project_db"), ("effects_db", "effects_db")):
        sc_reasons = check_sqlite_sidecars(
            Path(paths[db_key]),
            expected_uid=receiver_uid,
            forbidden_gids=untrusted_gids,
        )
        for r in sc_reasons:
            reasons.append(f"{db_label}_{r}")

    # 8. Check parent directory chain up to / for world-writable without sticky bit or symlink
    for check_p in (root_dir, Path(paths["worker_socket"]).parent, Path(paths["control_socket"]).parent):
        cur = check_p
        while True:
            if cur.is_symlink():
                reasons.append(f"parent_dir_symlink_forbidden:{cur}")
                break
            if cur.exists():
                pst = cur.stat()
                if (pst.st_mode & 0o002) and not (pst.st_mode & stat.S_ISVTX):
                    reasons.append(f"parent_dir_world_writable_without_sticky:{cur}")
            if cur.parent == cur:
                break
            cur = cur.parent

    # 9. Verify bare Git repository hygiene
    git_runner = SanitizedGitRunner(paths["empty_hooks_dir"], home_dir=root_dir)
    reasons.extend(git_runner.verify_bare_repo_hygiene(paths["accepted_git"], expected_uid=receiver_uid))

    dedup = sorted(set(reasons))
    return PreflightReport(ok=len(dedup) == 0, reasons=dedup, details=details)
