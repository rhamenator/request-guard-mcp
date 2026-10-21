#!/usr/bin/env python3
"""Probe a candidate --stdio binary with official Python MCP SDK 2.3.0.

Install `mcp==2.3.0` in a disposable virtual environment first. This script
does not open a network listener or rely on configured backends.
"""

import argparse
import asyncio
import os
import tempfile
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


async def probe(binary, expected_version):
    with tempfile.TemporaryDirectory(prefix="request-guard-stdio-") as cwd:
        parameters = StdioServerParameters(
            command=str(binary),
            args=["--stdio"],
            cwd=cwd,
            env={"PATH": os.environ.get("PATH", ""), "HOME": cwd},
        )
        async with stdio_client(parameters) as (reader, writer):
            async with ClientSession(reader, writer) as session:
                initialized = await session.initialize()
                require(initialized.protocol_version == "2025-06-18", "unexpected protocol version")
                require(initialized.server_info.version == expected_version, "unexpected server version")
                listed = await session.list_tools()
                require({"classify", "explain"} <= {tool.name for tool in listed.tools}, "core tools missing")
                observed = {
                    "ip": "192.0.2.1", "user_agent": "GPTBot/1.0", "path": "/",
                }
                result = await session.call_tool("classify", observed)
                require(not result.is_error, "classify returned tool error")
                require(result.structured_content is not None, "classify omitted structured content")
                require(result.structured_content["verdict"] == "block", "unexpected verdict")
                explanation = await session.call_tool("explain", {"classification": observed})
                require(not explanation.is_error, "explain returned tool error")
                require(explanation.structured_content is not None, "explain omitted structured content")
                require(bool(explanation.structured_content["factors"]), "explain omitted factors")
                print("PASS Python MCP SDK stdio: initialize, tools/list, classify, explain")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--expected-version", default="0.1.5")
    args = parser.parse_args()
    asyncio.run(asyncio.wait_for(probe(args.binary.resolve(strict=True), args.expected_version), timeout=30))


if __name__ == "__main__":
    main()
