"""OpenLine Production Isolation — Production Configuration Schema & Loader.

Implements Section 2.1, 4.1, and 5 of Astra's Production Isolation Blueprint:
- Strict validation of receiver configuration (`openline.production.config.v1`).
- Explicit UID-to-principal and UID-to-Ed25519-public-key bindings (`worker_principals`, `control_principals`).
- Pinned `owner_pub` and `receiver_pub` without requiring `owner.key` on the receiver host.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


PRODUCTION_CONFIG_SCHEMA = "openline.production.config.v1"

DEFAULT_LIMITS = {
    "max_frame_bytes": 8 * 1024 * 1024,      # 8 MiB
    "max_files": 512,
    "max_single_file_bytes": 1 * 1024 * 1024, # 1 MiB
    "max_total_bytes": 4 * 1024 * 1024,       # 4 MiB
    "snapshot_chunk_bytes": 256 * 1024,       # 256 KiB
    "validation_timeout_s": 30,
    "max_clock_skew_s": 300,
    "rate_limit_burst": 60,
    "rate_limit_per_sec": 30.0,
}


class ProductionConfigError(ValueError):
    """Raised when a production configuration violates schema or security constraints."""


def _is_hex64(val: Any) -> bool:
    if not isinstance(val, str) or len(val) != 64:
        return False
    try:
        bytes.fromhex(val)
        return True
    except ValueError:
        return False


def validate_production_config(cfg: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(cfg, dict):
        raise ProductionConfigError("config_must_be_dict")
    if cfg.get("schema") != PRODUCTION_CONFIG_SCHEMA:
        raise ProductionConfigError("invalid_production_config_schema")

    for req_str in ("deployment_id", "project_id", "receiver_id"):
        v = cfg.get(req_str)
        if not isinstance(v, str) or not v.strip():
            raise ProductionConfigError(f"missing_or_invalid_{req_str}")

    for req_hex in ("owner_pub", "receiver_pub"):
        if not _is_hex64(cfg.get(req_hex)):
            raise ProductionConfigError(f"invalid_{req_hex}")

    for req_uid in ("receiver_uid", "receiver_gid", "validator_uid", "validator_gid"):
        u = cfg.get(req_uid)
        if type(u) is not int or u < 0:
            raise ProductionConfigError(f"invalid_{req_uid}")

    if cfg["receiver_uid"] == cfg["validator_uid"] and not cfg.get("allow_single_uid_test_harness", False):
        raise ProductionConfigError("validator_uid_equals_receiver_uid")

    paths = cfg.get("paths")
    if not isinstance(paths, dict):
        raise ProductionConfigError("missing_paths_dict")
    required_paths = (
        "root_dir",
        "accepted_git",
        "project_db",
        "effects_db",
        "promotion_dir",
        "incidents_dir",
        "receiver_key_file",
        "empty_hooks_dir",
        "worker_socket",
        "control_socket",
        "validation_spool_dir",
        "validator_script",
    )
    for pk in required_paths:
        pv = paths.get(pk)
        if not isinstance(pv, str) or not pv.startswith("/"):
            raise ProductionConfigError(f"path_must_be_absolute:{pk}")

    # Ensure no owner.key is configured on receiver
    if "owner_key_file" in paths or "owner_key" in cfg:
        raise ProductionConfigError("owner_private_key_forbidden_in_production_config")

    worker_principals = cfg.get("worker_principals")
    if not isinstance(worker_principals, dict) or not worker_principals:
        raise ProductionConfigError("worker_principals_required")

    normalized_workers: dict[str, dict[str, Any]] = {}
    for uid_str, winfo in worker_principals.items():
        try:
            uid_int = int(uid_str)
        except (ValueError, TypeError) as exc:
            raise ProductionConfigError(f"invalid_worker_uid_key:{uid_str}") from exc
        if uid_int < 0:
            raise ProductionConfigError(f"negative_worker_uid:{uid_int}")
        if (uid_int == cfg["receiver_uid"] or uid_int == cfg["validator_uid"]) and not cfg.get("allow_single_uid_test_harness", False):
            raise ProductionConfigError(f"worker_uid_collides_with_service_uid:{uid_int}")
        if not isinstance(winfo, dict):
            raise ProductionConfigError(f"invalid_worker_entry:{uid_str}")
        member_id = winfo.get("member_id")
        worker_pub = winfo.get("worker_pub")
        owner_pub = winfo.get("owner_pub") or worker_pub
        if not isinstance(member_id, str) or not member_id.strip():
            raise ProductionConfigError(f"invalid_worker_member_id:{uid_str}")
        if not _is_hex64(worker_pub) or not _is_hex64(owner_pub):
            raise ProductionConfigError(f"invalid_worker_pub:{uid_str}")
        normalized_workers[str(uid_int)] = {
            "uid": uid_int,
            "member_id": member_id,
            "principal_id": winfo.get("principal_id") or f"worker:{member_id}",
            "worker_pub": worker_pub,
            "owner_pub": owner_pub,
            "role": "worker",
        }

    control_principals = cfg.get("control_principals") or {}
    if not isinstance(control_principals, dict):
        raise ProductionConfigError("invalid_control_principals")
    normalized_controls: dict[str, dict[str, Any]] = {}
    for uid_str, cinfo in control_principals.items():
        try:
            uid_int = int(uid_str)
        except (ValueError, TypeError) as exc:
            raise ProductionConfigError(f"invalid_control_uid_key:{uid_str}") from exc
        if not isinstance(cinfo, dict):
            raise ProductionConfigError(f"invalid_control_entry:{uid_str}")
        principal_id = cinfo.get("principal_id") or f"control:{uid_int}"
        pub = cinfo.get("public_key")
        if pub is not None and not _is_hex64(pub):
            raise ProductionConfigError(f"invalid_control_public_key:{uid_str}")
        normalized_controls[str(uid_int)] = {
            "uid": uid_int,
            "principal_id": principal_id,
            "public_key": pub,
            "role": cinfo.get("role", "control"),
        }

    limits = dict(DEFAULT_LIMITS)
    user_limits = cfg.get("limits") or {}
    if not isinstance(user_limits, dict):
        raise ProductionConfigError("invalid_limits")
    for lk, lv in user_limits.items():
        if lk not in DEFAULT_LIMITS:
            raise ProductionConfigError(f"unknown_limit_field:{lk}")
        if isinstance(lv, bool) or not isinstance(lv, (int, float)) or lv <= 0:
            raise ProductionConfigError(f"invalid_limit_value:{lk}")
        limits[lk] = lv

    out = dict(cfg)
    out["worker_principals"] = normalized_workers
    out["control_principals"] = normalized_controls
    out["limits"] = limits
    return out


def load_production_config(path: Path | str) -> dict[str, Any]:
    p = Path(path)
    if p.is_symlink():
        raise ProductionConfigError("production_config_symlink_forbidden")
    if not p.is_file():
        raise ProductionConfigError(f"production_config_missing:{p}")
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ProductionConfigError(f"production_config_invalid_json:{exc}") from exc
    return validate_production_config(raw)
