"""Independent official Python MCP SDK client interoperability smoke.

No model, paid API, remote server, external effect, or invented Codex host.
Runs the genuine OpenLine Lite stdio subprocess as an SDK MCP server.
"""
from __future__ import annotations

import asyncio
import importlib.metadata
import json
import os
from pathlib import Path
import sys
import tempfile

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from openline_mcp_entry.quickstart import bootstrap
from openline_mcp_entry.verify import verify_receipt


async def run(home: Path) -> None:
    bootstrap(home)
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "openline_mcp_entry.server"],
        env={"OPENLINE_MCP_CONFIG": str(home / "operator-config.json"),
             "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
             "HOME": str(home), "PYTHONNOUSERSITE": "1"},
    )
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as client:
            init = await client.initialize()
            listed = await client.list_tools()
            assert {"openline_check", "openline_impact", "openline_capabilities"} <= {
                tool.name for tool in listed.tools}
            check = await client.call_tool("openline_check", {"profile": "commit"})
            assert not check.isError
            d = check.structuredContent
            assert d["result"]["decision"] == "COMMIT"
            assert d["runtime_permission"] == "NONE"
            path = home / "records" / d["record_id"] / "decision.receipt.json"
            verified = verify_receipt(path, home / "gate-trust.json",
                                      expected_sha256=d["result"]["decision_receipt_sha256"],
                                      expected_decision="COMMIT")
            assert verified["signature"] == "VALID"
            impact = await client.call_tool("openline_impact", {"profile": "changed-source"})
            assert not impact.isError
            payload = impact.structuredContent
            assert payload["runtime_permission"] == "NONE"
            result = payload["result"]["result"]
            assert all(len(result[k]) == 1 for k in ("reopen", "retain", "undetermined"))
            bad = await client.call_tool("openline_check", {"profile": "../evil"})
            assert bad.isError
            print(json.dumps({
                "status": "PASS", "scope": "OFFICIAL_PYTHON_MCP_SDK_CLIENT_ONLY",
                "sdk_version": importlib.metadata.version("mcp"),
                "negotiated_version": init.protocolVersion,
                "tools": [tool.name for tool in listed.tools],
                "actual_check_disposition": d["result"]["decision"],
                "original_signed_receipt_sha256": verified["original_receipt_sha256"],
                "impact_partitions": {"reopen": 1, "retain": 1, "undetermined": 1},
                "unauthorized_profile_refused": True, "agent_host_tested": False,
                "paid_model_calls": 0, "external_effects": 0,
            }, sort_keys=True))


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        asyncio.run(run(Path(temporary) / "operator"))


if __name__ == "__main__":
    main()
