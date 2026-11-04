"""The public CLI must reject SDK redirects before forwarding its bearer."""
import json
from scripts.cli.client import MCPClient
from unittest.mock import patch

import httpx2
import pytest


def rpc_result(request, payload):
    if request.method != "POST":
        return httpx2.Response(405)
    body = json.loads(request.content)
    if "id" not in body:
        return httpx2.Response(202)
    if body["method"] == "initialize":
        result = {"protocolVersion": body["params"]["protocolVersion"],
                  "capabilities": {}, "serverInfo": {"name": "local-contract", "version": "1"}}
    elif body["method"] == "tools/list":
        result = {"tools": [{"name": name, "inputSchema": {"type": "object"}}
                            for name in ("system_health", "secret_read", "agent_status")]}
    else:
        result = {"content": [{"type": "text", "text": json.dumps(payload)}], "isError": False}
    return httpx2.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})



@pytest.mark.asyncio
@pytest.mark.parametrize("status", [None, 307, 308])
@pytest.mark.parametrize("location", ["https://pinned.invalid/next", "https://other.invalid/next"])
async def test_cli_pins_endpoint_with_real_sdk(status, location):
    seen = []
    def handle(request):
        seen.append((str(request.url), request.headers.get("authorization")))
        if status is not None:
            return httpx2.Response(status, headers={"Location": location})
        return rpc_result(request, {"status": "ok", "known": True})
    original = httpx2.AsyncClient
    def factory(**kwargs):
        return original(transport=httpx2.MockTransport(handle), **kwargs)
    with patch.object(httpx2, "AsyncClient", side_effect=factory):
        result = await MCPClient("https://pinned.invalid", "synthetic", timeout=1).call_tool("system_health", {})
    if status is None:
        assert result == {"status": "ok", "known": True}
    if status is not None:
        assert result["status"] == "error"
        assert len(seen) == 1
    assert seen
    assert set(seen) == {("https://pinned.invalid/mcp", "Bearer synthetic")}
