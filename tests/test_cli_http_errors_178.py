"""Erreurs HTTP réellement transformées par le SDK MCP, sans services simulés PG."""
import asyncio
import json
from pathlib import Path
import sys

import httpx2
import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from cli.client import MCPClient


def install_transport(monkeypatch, statuses, *, jsonrpc_error=False):
    posts = []

    def handler(request):
        if request.method != "POST":
            return httpx2.Response(405)
        message = json.loads(request.content)
        posts.append(message.get("method"))
        status = statuses[min(len(posts) - 1, len(statuses) - 1)]
        if jsonrpc_error:
            return httpx2.Response(status, json={"jsonrpc": "2.0", "id": message["id"],
                 "error": {"code": -32603, "message": "Server returned an error response"}})
        # Le texte ressemble à un refus d'auth, même à HTTP503 : seul le code fait foi.
        return httpx2.Response(status, json={"message": "401 token invalid"})

    original = httpx2.AsyncClient

    class LocalHttpClient(original):
        def __init__(self, **kwargs):
            kwargs.update(transport=httpx2.MockTransport(handler), trust_env=False)
            super().__init__(**kwargs)

    monkeypatch.setattr(httpx2, "AsyncClient", LocalHttpClient)
    return posts


@pytest.mark.parametrize(("statuses", "prefix"), [
    ((401, 401), "Authentification refusée (401)."),
    ((403, 403), "Accès interdit (403)."),
    ((503, 503), "Service indisponible ou réponse non confirmée (503)."),
    ((503, 401), "Réponse HTTP non confirmée"),
    ((400, 400), "Réponse HTTP non confirmée"),
    ((404, 404), "Réponse HTTP non confirmée"),
    ((502, 502), "Réponse HTTP non confirmée"),
])
def test_sdk_lost_status_classification(monkeypatch, statuses, prefix):
    posts = install_transport(monkeypatch, statuses)
    result = asyncio.run(MCPClient("http://fixture.test", "unit-test-token", timeout=3)
                         .call_tool("secret_read", {"vault_id": "unit", "path": "fixture"}))
    assert result["status"] == "error"
    assert result["message"].startswith(prefix)
    assert posts == ["server/discover", "initialize"]


def test_jsonrpc_error_at_http200_is_not_an_auth_denial(monkeypatch):
    posts = install_transport(monkeypatch, (200, 200), jsonrpc_error=True)
    result = asyncio.run(MCPClient("http://fixture.test", "unit-test-token", timeout=3)
                         .call_tool("secret_read", {"vault_id": "unit", "path": "fixture"}))
    assert result == {"status": "error", "message": "Server returned an error response"}
    assert posts == ["server/discover", "initialize"]


def test_transport_teardown_timeout_does_not_become_auth_denial(monkeypatch):
    posts = install_transport(monkeypatch, (401, 401))
    original = httpx2.AsyncClient

    class TimeoutHttpClient(original):
        async def __aexit__(self, exc_type, exc_value, traceback):
            await super().__aexit__(exc_type, exc_value, traceback)
            if isinstance(exc_value, Exception):
                raise ExceptionGroup("mixed", [exc_value, TimeoutError("call response unknown")])

    monkeypatch.setattr(httpx2, "AsyncClient", TimeoutHttpClient)
    result = asyncio.run(MCPClient("http://fixture.test", "unit-test-token", timeout=3)
                         .call_tool("secret_read", {"vault_id": "unit", "path": "fixture"}))
    assert result["status"] == "error"
    assert "call response unknown" in result["message"]
    assert "Authentification refusée" not in result["message"]
    assert posts == ["server/discover", "initialize"]


def test_cancellation_still_propagates(monkeypatch):
    entered = asyncio.Event()

    async def handler(request):
        entered.set()
        await asyncio.Event().wait()

    original = httpx2.AsyncClient

    class CancelHttpClient(original):
        def __init__(self, **kwargs):
            kwargs.update(transport=httpx2.MockTransport(handler), trust_env=False)
            super().__init__(**kwargs)

    monkeypatch.setattr(httpx2, "AsyncClient", CancelHttpClient)
    async def cancelled_call():
        task = asyncio.create_task(MCPClient("http://fixture.test", "unit-test-token", timeout=3)
                         .call_tool("secret_read", {"vault_id": "unit", "path": "fixture"}))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(cancelled_call())
