"""Small MCP interface to *existing* OpenLine Lite CLIs; no new authority engine.

All input files, policies and trust anchors are supplied by the local operator at
startup. The remote MCP caller can select a named profile but cannot provide a
path, shell command, signing key, trust anchor, or policy.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import sys
import subprocess
import uuid
from dataclasses import dataclass
from typing import Any

_PROFILE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_ALLOWED_CONFIG = {"schema", "check_profiles", "impact_profiles", "gate_key", "gate_id", "records_dir", "timeout_seconds", "check_binary", "impact_binary"}

class ConfigurationError(ValueError):
    pass

class EngineError(RuntimeError):
    pass


def _absolute_file(path: str, base: Path) -> Path:
    if not isinstance(path, str) or not path:
        raise ConfigurationError("operator_file_path_required")
    unresolved = base / path
    if unresolved.is_symlink():
        raise ConfigurationError("operator_file_symlink_forbidden")
    try:
        candidate = unresolved.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ConfigurationError("operator_file_missing") from exc
    if not candidate.is_file():
        raise ConfigurationError("operator_file_required")
    return candidate


def _profiles(raw: Any, base: Path) -> dict[str, Path]:
    if not isinstance(raw, dict):
        raise ConfigurationError("operator_profiles_must_be_object")
    out = {}
    for name, value in raw.items():
        if not isinstance(name, str) or not _PROFILE.fullmatch(name):
            raise ConfigurationError("operator_profile_name_invalid")
        out[name] = _absolute_file(value, base)
    return out


def _binary(value: Any, default: str) -> str:
    if not isinstance(value, str) or not value:
        raise ConfigurationError("operator_binary_invalid")
    # Prefer the installed commands beside the running interpreter (venv).
    # A host's ambient PATH need not activate that venv; do not load a
    # different global OpenLine binary accidentally.
    candidate = Path(sys.executable).parent / value
    found = str(candidate) if candidate.is_file() else shutil.which(value)
    if not found:
        raise ConfigurationError("required_engine_missing:" + default)
    resolved = Path(found).resolve(strict=True)
    if not resolved.is_file():
        raise ConfigurationError("required_engine_not_file:" + default)
    return str(resolved)


@dataclass(frozen=True)
class OperatorConfig:
    checks: dict[str, Path]
    impacts: dict[str, Path]
    key: Path | None
    gate_id: str
    records_dir: Path
    timeout: int
    binaries: dict[str, str]

    @classmethod
    def load(cls, config_file: Path) -> "OperatorConfig":
        if config_file.is_symlink():
            raise ConfigurationError("operator_config_symlink_forbidden")
        raw = json.loads(config_file.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or set(raw) - _ALLOWED_CONFIG:
            raise ConfigurationError("operator_config_invalid_fields")
        if raw.get("schema") != "openline.mcp-entry.operator.v1":
            raise ConfigurationError("operator_config_schema_invalid")
        base = config_file.resolve(strict=True).parent
        # Local threat boundary: receivers must keep config outside world/group
        # writable directories. This cannot isolate a same-UID malicious agent.
        if base.stat().st_mode & 0o022:
            raise ConfigurationError("operator_config_directory_writable_by_others")
        checks = _profiles(raw.get("check_profiles", {}), base)
        impacts = _profiles(raw.get("impact_profiles", {}), base)
        if not checks and not impacts:
            raise ConfigurationError("at_least_one_operator_profile_required")
        key = _absolute_file(raw["gate_key"], base) if raw.get("gate_key") else None
        if checks and key is None:
            raise ConfigurationError("durable_gate_key_required_for_check_profiles")
        gate_id = raw.get("gate_id", "openline-mcp-local")
        if not isinstance(gate_id, str) or not _PROFILE.fullmatch(gate_id):
            raise ConfigurationError("operator_gate_id_invalid")
        timeout = raw.get("timeout_seconds", 20)
        if type(timeout) is not int or not 1 <= timeout <= 60:
            raise ConfigurationError("operator_timeout_invalid")
        records_setting = raw.get("records_dir", ".openline-mcp-records")
        if not isinstance(records_setting, str) or not records_setting:
            raise ConfigurationError("records_dir_invalid")
        unresolved_records = base / records_setting
        if unresolved_records.is_symlink():
            raise ConfigurationError("records_dir_symlink_forbidden")
        records_dir = unresolved_records.resolve()
        if not records_dir.is_relative_to(base):
            raise ConfigurationError("records_dir_must_remain_under_operator_config_dir")
        # Prevent writing into an agent-controlled directory: the config directory itself
        # must be managed by the operator and not writable by workers.
        binaries = {}
        if checks:
            binaries["check"] = _binary(raw.get("check_binary", "openline-check"), "openline-check")
        if impacts:
            binaries["impact"] = _binary(raw.get("impact_binary", "openline-impact"), "openline-impact")
        return cls(checks, impacts, key, gate_id, records_dir, timeout, binaries)


class OpenLineTools:
    def __init__(self, config: OperatorConfig):
        self.config = config

    @staticmethod
    def _only_profile(arguments: Any) -> str:
        if not isinstance(arguments, dict) or set(arguments) != {"profile"}:
            raise EngineError("exact_profile_argument_required")
        name = arguments["profile"]
        if not isinstance(name, str) or not _PROFILE.fullmatch(name):
            raise EngineError("invalid_profile")
        return name

    def capabilities(self) -> dict[str, Any]:
        return {
            "status": "PRIVATE_LOCAL_PREVIEW",
            "check_profiles": sorted(self.config.checks),
            "impact_profiles": sorted(self.config.impacts),
            "protected_effect_permission": "NONE",
            "autonomous_repair": "NOT_AVAILABLE",
            "runtime": "local_stdio",
            "server_required": False,
            "remarks": "Uses existing OpenLine Lite checks. No code execution, provider calls, deployment, or effect authorization is exposed by this MCP surface.",
        }

    def run(self, kind: str, arguments: Any) -> dict[str, Any]:
        name = self._only_profile(arguments)
        profiles = self.config.checks if kind == "check" else self.config.impacts
        if name not in profiles:
            raise EngineError("unknown_operator_profile")
        # Unique owned output directory makes receipt records inspectable and stops
        # concurrent calls from clobbering each other's outputs.
        if self.config.records_dir.is_symlink():
            raise EngineError("records_dir_symlink_forbidden")
        self.config.records_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.config.records_dir.stat().st_mode & 0o022:
            raise EngineError("records_dir_writable_by_others")
        work = self.config.records_dir / (kind + "-" + uuid.uuid4().hex)
        work.mkdir(mode=0o700)
        argv = [self.config.binaries[kind], str(profiles[name]), "--json", "--output-dir", str(work)]
        if kind == "check":
            argv += ["--gate-key", str(self.config.key), "--gate-id", self.config.gate_id]
        # Do not forward provider tokens, SSH/GitHub credentials, arbitrary PYTHONPATH
        # or caller-controlled environment to the validator subprocess.
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
               "HOME": str(self.config.records_dir), "LANG": "C.UTF-8",
               "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"}
        try:
            proc = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, capture_output=True,
                                  text=True, timeout=self.config.timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise EngineError("verification_timeout") from exc
        except OSError as exc:
            raise EngineError("verification_subprocess_failed") from exc
        if len(proc.stdout) > 1_000_000 or len(proc.stderr) > 4096:
            raise EngineError("verification_output_too_large")
        # openline-check returns 1 for an ordinary DENY/QUARANTINE decision, not
        # an execution error. An exit code of 2 means malformed input/error.
        permitted = {0, 1} if kind == "check" else {0}
        if proc.returncode not in permitted:
            raise EngineError("verification_failed:exit_" + str(proc.returncode))
        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise EngineError("verification_result_not_json") from exc
        schema = "openline.check-result.v1" if kind == "check" else "openline.impact-pack-result.v1"
        if not isinstance(payload, dict) or payload.get("schema") != schema:
            raise EngineError("verification_result_schema_invalid")
        if kind == "check":
            decision = payload.get("decision")
            if decision not in ("COMMIT", "DENY", "QUARANTINE", "NO_BADGE", "ROLLBACK_REQUEST"):
                raise EngineError("verification_disposition_invalid")
            if (proc.returncode == 0) != (decision == "COMMIT"):
                raise EngineError("verification_disposition_exit_mismatch")
            if payload.get("gate", {}).get("key_mode") != "pinned_file":
                raise EngineError("verification_gate_key_not_pinned")
            if payload.get("decision_receipt_self_verified") is not True:
                raise EngineError("verification_receipt_not_self_verified")
        else:
            if not isinstance(payload.get("result"), dict):
                raise EngineError("impact_result_missing")
        return {"engine": "openline-lite", "profile": name,
                "record_id": work.name, "result": payload,
                "runtime_permission": "NONE"}
