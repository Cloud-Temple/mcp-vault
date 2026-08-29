#!/usr/bin/env python3
"""Probe wire d'un serveur v0.20 avec le vrai SDK client mcp==1.26.0."""

import asyncio
import importlib.metadata
import json
import os

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


EXPECTED_SDK = "1.26.0"


async def main() -> None:
    installed = importlib.metadata.version("mcp")
    if installed != EXPECTED_SDK:
        raise RuntimeError(f"SDK client attendu={EXPECTED_SDK}, installé={installed}")

    base_url = os.getenv("MCP_URL", "http://localhost:8085").rstrip("/")
    token = os.getenv("MCP_TOKEN") or os.getenv("ADMIN_BOOTSTRAP_KEY")
    if not token:
        raise RuntimeError("MCP_TOKEN ou ADMIN_BOOTSTRAP_KEY est requis")

    async with streamablehttp_client(
        f"{base_url}/mcp",
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
        sse_read_timeout=60,
    ) as (read, write, _session_id):
        async with ClientSession(read, write) as session:
            initialized = await session.initialize()
            protocol = initialized.protocolVersion
            if protocol == "2026-07-28":
                raise AssertionError(f"le client v1 a négocié une ère moderne : {protocol}")

            listed = await session.list_tools()
            names = [tool.name for tool in listed.tools]
            if "system_about" not in names:
                raise AssertionError("system_about absent de tools/list")

            result = await session.call_tool("system_about", {})
            if result.isError:
                raise AssertionError(f"tools/call legacy refusé : {result!r}")
            payload = json.loads(result.content[0].text)

    print(json.dumps({
        "status": "ok",
        "target": base_url,
        "client_sdk": installed,
        "protocol": protocol,
        "tools_count": len(names),
        "server_version": payload.get("version"),
    }, ensure_ascii=False))


if __name__ == "__main__":
    asyncio.run(main())
