"""Local MCP host setup instructions and a capability-only protocol probe.

No host settings are modified. No network requests, model calls, effects or
signing-key reads occur from this module. It only assembles a *local* command.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
from typing import Any

SERVER_MODULE = "openline_mcp_entry.server"
SERVER_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
HOSTS = ("codex", "cursor", "claude-desktop")


def _config_path(raw: str) -> str:
    path = Path(raw).expanduser().resolve(strict=True)
    if not path.is_file():
        raise ValueError("operator_config_must_be_file")
    return str(path)


def _interpreter(python: str | None) -> str:
    # Python virtual environments frequently use a symlink to the underlying
    # interpreter. Resolving it escapes the venv and loses installed scripts
    # and packages when an agent host starts the MCP server.
    candidate = Path(python or sys.executable).expanduser().absolute()
    if not candidate.is_file():
        raise ValueError("mcp_python_interpreter_missing")
    return str(candidate)


def generate(host: str, config_path: str, name: str = "openline-local", python: str | None = None) -> str:
    """Return a host-ready config/command without mutating host settings."""
    if host not in HOSTS:
        raise ValueError("host_not_supported")
    if not SERVER_NAME.fullmatch(name):
        raise ValueError("server_name_invalid")
    config = _config_path(config_path)
    interpreter = _interpreter(python)
    entry: dict[str, Any] = {
        "command": interpreter,
        "args": ["-m", SERVER_MODULE],
        "env": {"OPENLINE_MCP_CONFIG": config},
    }
    if host == "codex":
        return shlex.join(["codex", "mcp", "add", name, "--env", f"OPENLINE_MCP_CONFIG={config}",
                           "--", interpreter, "-m", SERVER_MODULE]) + "\n"
    return json.dumps({"mcpServers": {name: entry}}, indent=2) + "\n"


def probe(config_path: str, python: str | None = None) -> dict[str, Any]:
    """Verify local MCP handshake/discovery/capabilities only; no check pack executed."""
    config = _config_path(config_path)
    interpreter = _interpreter(python)
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "openline-local-probe", "version": "0.1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "openline_capabilities", "arguments": {}}},
    ]
    env = {"OPENLINE_MCP_CONFIG": config, "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
           "HOME": str(Path(config).parent), "LANG": "C.UTF-8",
           "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1"}
    try:
        process = subprocess.run(
            [interpreter, "-m", SERVER_MODULE],
            input="\n".join(json.dumps(x) for x in messages) + "\n",
            text=True, capture_output=True, timeout=8, env=env, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("mcp_probe_process_failed") from exc
    if process.returncode or len(process.stdout) > 100_000 or len(process.stderr) > 4096:
        raise ValueError("mcp_probe_server_failed")
    try:
        lines = [json.loads(line) for line in process.stdout.splitlines()]
    except json.JSONDecodeError as exc:
        raise ValueError("mcp_probe_invalid_json") from exc
    if [msg.get("id") for msg in lines] != [1, 2, 3]:
        raise ValueError("mcp_probe_protocol_failure")
    if "error" in lines[0] or "error" in lines[1] or "error" in lines[2]:
        raise ValueError("mcp_probe_rpc_error")
    tools = lines[1].get("result", {}).get("tools", [])
    names = [entry.get("name") for entry in tools]
    if not {"openline_capabilities", "openline_check", "openline_impact"}.issubset(set(names)):
        raise ValueError("mcp_probe_tools_missing")
    capabilities = lines[2].get("result", {}).get("structuredContent", {})
    if capabilities.get("protected_effect_permission") != "NONE" or capabilities.get("autonomous_repair") != "NOT_AVAILABLE":
        raise ValueError("mcp_probe_unexpected_authority")
    return {"status": "PASS", "scope": "LOCAL_CAPABILITY_ONLY", "tools": names,
            "real_signed_check_executed": False, "model_run_executed": False,
            "external_host_tested": False, "protected_effect_permission": "NONE"}


def invoke(config_path: str, kind: str, profile: str, python: str | None = None) -> dict[str, Any]:
    """Run a genuine named check/impact through the same MCP stdio interface.

    This is a local diagnostic client, not agent-host conformance or permission
    for external effects. The caller cannot supply policy, trust or file paths.
    """
    if kind not in ("check", "impact") or not SERVER_NAME.fullmatch(profile):
        raise ValueError("local_invocation_invalid_profile")
    config = _config_path(config_path)
    interpreter = _interpreter(python)
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "openline-local-diagnostic", "version": "0.1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "openline_" + kind, "arguments": {"profile": profile}}},
    ]
    env = {"OPENLINE_MCP_CONFIG": config, "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
           "HOME": str(Path(config).parent), "LANG": "C.UTF-8",
           "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1"}
    try:
        process = subprocess.run(
            [interpreter, "-m", SERVER_MODULE],
            input="\n".join(json.dumps(x) for x in messages) + "\n",
            text=True, capture_output=True, timeout=70, env=env, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("mcp_invocation_process_failed") from exc
    if process.returncode or len(process.stdout) > 1_100_000 or len(process.stderr) > 4096:
        raise ValueError("mcp_invocation_server_failed")
    try:
        replies = [json.loads(line) for line in process.stdout.splitlines()]
    except json.JSONDecodeError as exc:
        raise ValueError("mcp_invocation_invalid_json") from exc
    if len(replies) != 2 or [x.get("id") for x in replies] != [1, 2]:
        raise ValueError("mcp_invocation_protocol_failure")
    if "error" in replies[0] or "error" in replies[1]:
        raise ValueError("mcp_invocation_rpc_error")
    result = replies[1]["result"]
    data = result.get("structuredContent")
    if not isinstance(data, dict) or data.get("runtime_permission") != "NONE":
        raise ValueError("mcp_invocation_unexpected_authority")
    return {"status": "REFUSED" if result.get("isError") else "PASS",
            "mcp_tool": "openline_" + kind, "data": data,
            "actual_openline_check": kind == "check" and not result.get("isError"),
            "external_host_tested": False, "protected_effect_permission": "NONE"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate safe local MCP host settings or probe server discovery (no changes made)")
    parser.add_argument("--operator-config", required=True)
    parser.add_argument("--host", choices=HOSTS)
    parser.add_argument("--server-name", default="openline-local")
    parser.add_argument("--probe", action="store_true", help="Test local stdio protocol; no actual OpenLine check is invoked")
    parser.add_argument("--check-profile", help="Run a genuine named Lite check through local MCP stdio")
    parser.add_argument("--impact-profile", help="Run real signed evidence impact through local MCP stdio")
    args = parser.parse_args(argv)
    if sum([bool(args.probe), bool(args.host), bool(args.check_profile),
            bool(args.impact_profile)]) != 1:
        parser.error("select exactly one of --probe, --host, --check-profile, --impact-profile")
    try:
        if args.probe:
            print(json.dumps(probe(args.operator_config), sort_keys=True, indent=2))
        elif args.check_profile or args.impact_profile:
            kind = "check" if args.check_profile else "impact"
            result = invoke(args.operator_config, kind, args.check_profile or args.impact_profile)
            print(json.dumps(result, sort_keys=True, indent=2))
            return 0 if result["status"] == "PASS" else 2
        else:
            print(generate(args.host, args.operator_config, args.server_name), end="")
        return 0
    except (OSError, ValueError) as exc:
        print(json.dumps({"status": "REFUSED", "reason": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
