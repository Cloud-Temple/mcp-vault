# -*- coding: utf-8 -*-
"""Contrats du client MCP v2 livré avec le CLI."""

import asyncio
from unittest.mock import patch

import httpx2
import pytest

from scripts.cli.client import MCPClient


async def test_closed_200_sse_becomes_a_bounded_cli_error():
    """Un 200 SSE fermé sans réponse terminale ne doit jamais pendre le CLI."""
    requests = []

    async def closed_sse(scope, receive, send):
        assert scope["type"] == "http"
        headers = dict(scope["headers"])
        requests.append((scope["method"], scope["path"], headers.get(b"mcp-method")))
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/event-stream")],
        })
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    real_client = httpx2.AsyncClient

    def local_client(*args, **kwargs):
        kwargs["transport"] = httpx2.ASGITransport(app=closed_sse)
        return real_client(*args, **kwargs)

    with patch.object(httpx2, "AsyncClient", side_effect=local_client):
        started = asyncio.get_running_loop().time()
        result = await asyncio.wait_for(
            MCPClient("http://closed.test", timeout=5).call_tool("system_about", {}),
            timeout=2,
        )
        elapsed = asyncio.get_running_loop().time() - started

    assert result["status"] == "error", result
    assert requests, "le faux serveur n'a jamais été atteint"
    assert len(requests) <= 3, f"reprises non bornées détectées : {requests}"
    methods = [method for _verb, _path, method in requests if method is not None]
    assert len(methods) == len(set(methods)), f"méthode MCP réémise : {requests}"
    assert elapsed < 1, f"la fermeture n'a été rendue qu'après timeout : {elapsed:.3f}s"


async def test_cli_propagates_cancellation_instead_of_turning_it_into_a_result():
    class CancelledClient:
        async def __aenter__(self):
            raise asyncio.CancelledError

        async def __aexit__(self, *_args):
            return False

    with patch.object(httpx2, "AsyncClient", return_value=CancelledClient()):
        with pytest.raises(asyncio.CancelledError):
            await MCPClient("http://cancelled.test").call_tool("system_about", {})

    assert MCPClient._contains_control_flow(SystemExit())
    assert MCPClient._contains_control_flow(GeneratorExit())


async def test_cli_propagates_cancellation_from_an_inflight_sdk_task_group():
    request_started = asyncio.Event()

    async def hanging_server(scope, receive, send):
        assert scope["type"] == "http"
        request_started.set()
        await asyncio.Event().wait()

    real_client = httpx2.AsyncClient

    def local_client(*args, **kwargs):
        kwargs["transport"] = httpx2.ASGITransport(app=hanging_server)
        return real_client(*args, **kwargs)

    with patch.object(httpx2, "AsyncClient", side_effect=local_client):
        task = asyncio.create_task(
            MCPClient("http://cancelled.test").call_tool("system_about", {}),
        )
        await asyncio.wait_for(request_started.wait(), timeout=1)
        task.cancel()
        with pytest.raises(BaseException) as caught:
            await task

    assert MCPClient._contains_control_flow(caught.value)
