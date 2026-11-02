"""Dependency-free MCP stdio tool server backed by OpenLine Lite engines.

JSON-RPC 2.0 newline framing. Protocol stdout is never used for logs.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any
from .engine import ConfigurationError, EngineError, OpenLineTools, OperatorConfig

PROTOCOLS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
TOOLS = [
    {"name": "openline_check", "description": "Run a preconfigured receiver-owned OpenLine evidence check. Ordinary refusal is a successful tool result, not effect permission. No arbitrary paths, policies or keys.",
     "inputSchema": {"type": "object", "properties": {"profile": {"type": "string", "description": "Name of a receiver-preconfigured check pack"}},
                     "required": ["profile"], "additionalProperties": False}},
    {"name": "openline_impact", "description": "Verify signed decisions and determine REOPEN/RETAIN/UNDETERMINED under a receiver-preconfigured evidence invalidation. Does not authorize an effect.",
     "inputSchema": {"type": "object", "properties": {"profile": {"type": "string", "description": "Name of a receiver-preconfigured impact pack"}},
                     "required": ["profile"], "additionalProperties": False}},
    {"name": "openline_capabilities", "description": "List available OpenLine profiles and security limitations. No side effects.",
     "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
]


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _tool_result(data: dict[str, Any], error: bool = False) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(data, sort_keys=True, separators=(",", ":"))}],
            "structuredContent": data, "isError": error}


class MCPServer:
    def __init__(self, tools: OpenLineTools):
        self.tools = tools
        self.initialized = False

    def handle(self, request: Any) -> dict[str, Any] | None:
        if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
            return _error(None, -32600, "Invalid Request")
        # Valid JSON-RPC notifications have no id. Never reply to notifications.
        if "id" not in request:
            return None
        request_id = request["id"]
        if isinstance(request_id, (dict, list, bool)):
            return _error(None, -32600, "Invalid Request")
        method, params = request.get("method"), request.get("params", {})
        if not isinstance(params, dict):
            return _error(request_id, -32602, "Invalid params")
        if method == "initialize":
            requested = params.get("protocolVersion")
            version = requested if requested in PROTOCOLS else PROTOCOLS[0]
            self.initialized = True
            return {"jsonrpc": "2.0", "id": request_id, "result": {
                "protocolVersion": version, "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "openline-mcp-entry", "version": "0.1.0.dev0"}}}
        if method == "ping":
            return {"jsonrpc": "2.0", "id": request_id, "result": {}}
        if not self.initialized:
            return _error(request_id, -32002, "MCP not initialized")
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}}
        if method == "tools/call":
            name = params.get("name")
            args = params.get("arguments", {})
            try:
                if name == "openline_capabilities":
                    if args != {}:
                        raise EngineError("capabilities_takes_no_arguments")
                    result = self.tools.capabilities()
                elif name == "openline_check":
                    result = self.tools.run("check", args)
                elif name == "openline_impact":
                    result = self.tools.run("impact", args)
                else:
                    return _error(request_id, -32602, "Unknown tool")
                return {"jsonrpc": "2.0", "id": request_id, "result": _tool_result(result)}
            except (EngineError, ConfigurationError) as exc:
                return {"jsonrpc": "2.0", "id": request_id, "result":
                        _tool_result({"status": "REFUSED", "reason": str(exc), "runtime_permission": "NONE"}, True)}
        return _error(request_id, -32601, "Method not found")


def serve() -> int:
    location = os.environ.get("OPENLINE_MCP_CONFIG")
    if not location:
        print("OPENLINE_MCP_CONFIG is required", file=sys.stderr)
        return 2
    try:
        server = MCPServer(OpenLineTools(OperatorConfig.load(Path(location))))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("OpenLine MCP operator configuration invalid: " + str(exc), file=sys.stderr)
        return 2
    for line in sys.stdin.buffer:
        if len(line) > 1_048_576:
            response = _error(None, -32700, "MCP message too large")
        else:
            try:
                response = server.handle(json.loads(line))
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
                response = _error(None, -32700, "Parse error")
            except Exception:
                # Unexpected error is fail-closed. Details stay out of agent output.
                response = _error(None, -32603, "Internal error")
        if response is not None:
            sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
            sys.stdout.flush()
    return 0


def main() -> None:
    raise SystemExit(serve())

if __name__ == "__main__":
    main()
