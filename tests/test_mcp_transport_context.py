# -*- coding: utf-8 -*-
"""Invariants transport/auth à conserver pendant la migration MCP SDK v2.

Ces tests traversent la vraie stack ``create_app()`` et le transport HTTP du
SDK v2. Le même banc exerce l'ère legacy et l'ère moderne sessionless sans
dupliquer la stack serveur ; le vrai client v1 vit dans un probe séparé.
"""

import asyncio
import json
import secrets
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, patch

import pytest


TRANSPORT_MODES = ("legacy", "modern")


def _token_info(token: str):
    suffix = token.removeprefix("token-")
    if suffix not in {"a", "b", "c"}:
        return None
    return {
        "auth_type": "bearer",
        "client_name": f"client-{suffix}",
        "permissions": ["read", "write"],
        "allowed_resources": [f"vault-{suffix}"],
        "policy_id": "",
    }


@asynccontextmanager
async def _run_lifespan(app):
    """Pilote le vrai protocole ASGI lifespan autour des requêtes HTTP."""
    startup_complete = asyncio.Event()
    shutdown_requested = asyncio.Event()
    startup_sent = False
    failure = []

    async def receive():
        nonlocal startup_sent
        if not startup_sent:
            startup_sent = True
            return {"type": "lifespan.startup"}
        await shutdown_requested.wait()
        return {"type": "lifespan.shutdown"}

    async def send(message):
        if message["type"] == "lifespan.startup.failed":
            failure.append(message.get("message", "startup failed"))
            startup_complete.set()
        elif message["type"] == "lifespan.startup.complete":
            startup_complete.set()

    task = asyncio.create_task(app(
        {"type": "lifespan", "asgi": {"version": "3.0"}}, receive, send,
    ))
    await asyncio.wait_for(startup_complete.wait(), timeout=5)
    if failure:
        await task
        raise AssertionError(failure[0])

    try:
        yield
    finally:
        shutdown_requested.set()
        await asyncio.wait_for(task, timeout=5)


@asynccontextmanager
async def _vault_app(list_spaces, create_space):
    """Construit la stack réelle avec seulement les backends externes neutralisés."""
    from mcp_vault import lifecycle, server
    from mcp_vault.auth.middleware import AuthMiddleware
    from mcp_vault.vault import spaces

    saved_key = server.settings.admin_bootstrap_key
    saved_mode = server.settings.mcp_auth_mode
    saved_hosts = server.settings.mcp_allowed_hosts
    startup = AsyncMock(return_value=True)
    shutdown = AsyncMock()

    def validate_token(_self, token):
        return _token_info(token)

    try:
        object.__setattr__(server.settings, "admin_bootstrap_key", secrets.token_urlsafe(48))
        object.__setattr__(server.settings, "mcp_auth_mode", "bearer")
        object.__setattr__(
            server.settings, "mcp_allowed_hosts",
            "vault.mcp.cloud-temple.app",
        )
        with patch.object(lifecycle, "vault_startup", startup), \
             patch.object(lifecycle, "vault_shutdown", shutdown), \
             patch.object(AuthMiddleware, "_validate_token", validate_token), \
             patch.object(spaces, "list_spaces", list_spaces), \
             patch.object(spaces, "create_space", create_space):
            app = server.create_app()
            async with _run_lifespan(app):
                yield app
    finally:
        object.__setattr__(server.settings, "admin_bootstrap_key", saved_key)
        object.__setattr__(server.settings, "mcp_auth_mode", saved_mode)
        object.__setattr__(server.settings, "mcp_allowed_hosts", saved_hosts)

    startup.assert_awaited_once()
    shutdown.assert_awaited_once_with(skip_upload=False)


@asynccontextmanager
async def _client(app, token: str, mode: str):
    """Client public v2, en transport moderne ou émulation d'un client legacy."""
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client
    import httpx2

    url = "http://localhost/mcp"
    headers = {"Authorization": f"Bearer {token}"}

    http = httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app),
        base_url="http://localhost",
        headers=headers,
        timeout=httpx2.Timeout(5),
    )

    async with http:
        transport = streamable_http_client(url, http_client=http)
        if mode == "legacy":
            async with transport as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    initialized = await session.initialize()
                    yield session, http, initialized.protocol_version
        else:
            from mcp import Client

            async with Client(transport, mode="auto", read_timeout_seconds=5) as client:
                yield client, http, client.protocol_version


def _vault_ids(result) -> list[str]:
    assert result.content, result
    payload = json.loads(result.content[0].text)
    assert payload["status"] == "ok", payload
    return [entry["vault_id"] for entry in payload["vaults"]]


async def test_auth_middleware_resets_context_in_the_calling_task():
    """Le ``finally`` doit restaurer le ContextVar, pas seulement le remplacer."""
    from mcp_vault.auth.context import current_token_info
    from mcp_vault.auth.middleware import AuthMiddleware

    captured = []
    events = []

    async def downstream(_scope, _receive, send):
        captured.append(current_token_info.get())
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(event):
        events.append(event)

    middleware = AuthMiddleware(downstream)
    scope = {
        "type": "http", "method": "POST", "path": "/mcp",
        "headers": [(b"authorization", b"Bearer token-a")],
        "query_string": b"",
    }
    assert current_token_info.get() is None
    settings = type("Settings", (), {"mcp_auth_mode": "bearer"})()
    with patch("mcp_vault.auth.middleware.get_settings", return_value=settings), \
         patch.object(AuthMiddleware, "_validate_token",
                      lambda _self, token: _token_info(token)):
        await middleware(scope, receive, send)

    assert captured == [_token_info("token-a")]
    assert current_token_info.get() is None


async def test_transport_context_invariants_on_the_real_app():
    """Identité par requête, entrelacement et nettoyage, sous un vrai lifespan.

    Le manager Streamable HTTP n'est lançable qu'une fois par instance : toutes
    les variantes partagent donc intentionnellement la même application réelle.
    """
    state = {"blocking": False, "a_entered": None, "b_entered": None,
             "release": None}
    from mcp_vault.auth.context import current_token_info

    async def list_spaces(*, allowed_vault_ids=None, owner_filter=None):
        assert owner_filter is None
        ids = allowed_vault_ids or []
        if state["blocking"]:
            if ids == ["vault-a"]:
                state["a_entered"].set()
            elif ids == ["vault-b"]:
                state["b_entered"].set()
            await asyncio.wait_for(state["release"].wait(), timeout=5)
        return {
            "status": "ok",
            "vaults": [{"vault_id": value} for value in ids],
            "count": len(ids),
        }

    async def create_space(vault_id, description=""):
        assert vault_id == "vault-b"
        assert description == "mutation pendant listen"
        return {"status": "created", "vault_id": vault_id}

    async with _vault_app(list_spaces, create_space) as app:
        for mode in TRANSPORT_MODES:
            # Une connexion initialisée par A ne doit jamais figer l'identité A.
            async with _client(app, "token-a", mode) as (client, http, protocol):
                first = await client.call_tool("vault_list", {})
                http.headers["Authorization"] = "Bearer token-b"
                second = await client.call_tool("vault_list", {})

            assert _vault_ids(first) == ["vault-a"]
            assert _vault_ids(second) == ["vault-b"]
            assert current_token_info.get() is None
            if mode == "legacy":
                assert protocol != "2026-07-28"
            else:
                assert protocol == "2026-07-28"

            # Deux handlers suspendus sur un await gardent chacun leur identité.
            state.update({
                "blocking": True,
                "a_entered": asyncio.Event(),
                "b_entered": asyncio.Event(),
                "release": asyncio.Event(),
            })
            async with _client(app, "token-a", mode) as (client_a, _http_a, _), \
                       _client(app, "token-b", mode) as (client_b, _http_b, _):
                call_a = asyncio.create_task(client_a.call_tool("vault_list", {}))
                await asyncio.wait_for(state["a_entered"].wait(), timeout=5)
                call_b = asyncio.create_task(client_b.call_tool("vault_list", {}))
                await asyncio.wait_for(state["b_entered"].wait(), timeout=5)
                state["release"].set()
                result_a, result_b = await asyncio.gather(call_a, call_b)
            state["blocking"] = False

            assert _vault_ids(result_a) == ["vault-a"]
            assert _vault_ids(result_b) == ["vault-b"]

            # Une erreur puis une fermeture ne contaminent pas la connexion suivante.
            async with _client(app, "token-a", mode) as (client_a, _http_a, _):
                error = await client_a.call_tool("outil_inexistant", {})
                assert error.is_error is True
            assert current_token_info.get() is None

            async with _client(app, "token-c", mode) as (client_c, _http_c, _):
                result_c = await client_c.call_tool("vault_list", {})
            assert _vault_ids(result_c) == ["vault-c"]

        # Preuve wire indépendante du client SDK : POST moderne brut.
        import httpx2

        envelope = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server/discover",
            "params": {"_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {
                    "name": "mcp-vault-wire-test", "version": "1",
                },
            }},
        }

        async def post_discover(host: str):
            async with httpx2.AsyncClient(
                transport=httpx2.ASGITransport(app=app),
                base_url=f"http://{host}",
                headers={"Authorization": "Bearer token-a"},
            ) as http:
                return await http.post(
                    "/mcp",
                    json=envelope,
                    headers={
                        "Accept": "application/json, text/event-stream",
                        "Mcp-Protocol-Version": "2026-07-28",
                        "Mcp-Method": "server/discover",
                    },
                )

        response = await post_discover("localhost")
        assert response.status_code == 200, response.text
        assert "mcp-session-id" not in response.headers
        if response.headers.get("content-type", "").startswith("application/json"):
            payload = response.json()
        else:
            data_lines = [
                line.removeprefix("data: ")
                for line in response.text.splitlines()
                if line.startswith("data: ")
            ]
            assert len(data_lines) == 1, response.text
            payload = json.loads(data_lines[0])
        assert "2026-07-28" in payload["result"]["supportedVersions"]

        # La sécurité transport est testée sur la vraie app, dans les deux sens.
        allowed = await post_discover("vault.mcp.cloud-temple.app")
        rejected = await post_discover("evil.example.com")
        assert allowed.status_code == 200, allowed.text
        assert rejected.status_code == 421, rejected.text

        # Le SDK v2 annonce ``subscriptions/listen`` automatiquement.
        # L'endpoint reste protégé par le bearer et inerte côté Vault.
        listen_envelope = {
            "jsonrpc": "2.0",
            "id": "listen-auth-check",
            "method": "subscriptions/listen",
            "params": {
                "_meta": envelope["params"]["_meta"],
                "notifications": {"resourcesListChanged": True},
            },
        }
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app),
            base_url="http://localhost",
        ) as anonymous_http:
            unauthorized = await anonymous_http.post(
                "/mcp",
                json=listen_envelope,
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Mcp-Protocol-Version": "2026-07-28",
                    "Mcp-Method": "subscriptions/listen",
                },
            )
        assert unauthorized.status_code in {401, 403}

        body = json.dumps(listen_envelope, separators=(",", ":")).encode()
        disconnected = asyncio.Event()
        response_started = asyncio.Event()
        response_body_seen = asyncio.Event()
        messages = []
        request_sent = False

        async def receive_listen():
            nonlocal request_sent
            if not request_sent:
                request_sent = True
                return {"type": "http.request", "body": body,
                        "more_body": False}
            await disconnected.wait()
            return {"type": "http.disconnect"}

        async def send_listen(message):
            messages.append(message)
            if message["type"] == "http.response.start":
                response_started.set()
            elif message["type"] == "http.response.body" and message.get("body"):
                response_body_seen.set()

        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/mcp",
            "raw_path": b"/mcp",
            "query_string": b"",
            "root_path": "",
            "server": ("localhost", 80),
            "client": ("127.0.0.1", 12345),
            "headers": [
                (b"host", b"localhost"),
                (b"authorization", b"Bearer token-a"),
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"accept", b"application/json, text/event-stream"),
                (b"mcp-protocol-version", b"2026-07-28"),
                (b"mcp-method", b"subscriptions/listen"),
            ],
        }
        listen_task = asyncio.create_task(
            app(scope, receive_listen, send_listen),
        )
        try:
            await asyncio.wait_for(response_started.wait(), timeout=3)
            start = next(
                message for message in messages
                if message["type"] == "http.response.start"
            )
            assert start["status"] == 200
            await asyncio.wait_for(response_body_seen.wait(), timeout=3)

            # Déclencher une vraie mutation sous une autre identité pendant
            # l'écoute : l'absence d'événement n'est plus testée au repos.
            async with _client(app, "token-b", "modern") as (client_b, _http, _):
                mutation = await client_b.call_tool("vault_create", {
                    "vault_id": "vault-b",
                    "description": "mutation pendant listen",
                })
            mutation_payload = json.loads(mutation.content[0].text)
            assert mutation_payload["status"] == "created"
            await asyncio.sleep(0.15)

            stream = b"".join(
                message.get("body", b"") for message in messages
                if message["type"] == "http.response.body"
            ).decode()
            frames = [
                json.loads(line.removeprefix("data: "))
                for line in stream.splitlines()
                if line.startswith("data: ")
            ]
            assert [frame.get("method") for frame in frames] == [
                "notifications/subscriptions/acknowledged",
            ]
        finally:
            disconnected.set()
            await asyncio.wait_for(listen_task, timeout=3)
