"""Closed retention-only HTTP surface for the 8031 operator process."""

import asyncio
import json
from contextlib import contextmanager
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import ValidationError

from mcp_vault.config import Settings
from mcp_vault.storage import operator, retention_proof as proof


BOOTSTRAP_KEY = "R488-test-bootstrap-key-that-is-long-and-random-enough-123456789"
RETENTION_PATHS = (
    "/admin/api/metadata-operator/audit-retention-close",
    "/admin/api/metadata-operator/audit-retention-status",
    "/admin/api/metadata-operator/audit-retention-inventory",
    "/admin/api/metadata-operator/audit-retention-retire",
    "/admin/api/metadata-operator/audit-retention-receipt",
)


def _scope(path, method="POST", *, raw_path=None, query=b""):
    return {
        "type": "http",
        "method": method,
        "path": path,
        "raw_path": raw_path if raw_path is not None else path.encode("ascii"),
        "query_string": query,
        "headers": [(b"authorization", ("Bearer " + BOOTSTRAP_KEY).encode())],
    }


async def _poison_receive():
    raise AssertionError("rejected retention-only request read its body")


async def _send_collect(messages):
    async def send(message):
        messages.append(message)

    return send


def test_retention_only_is_an_explicit_closed_setting():
    cfg = Settings(
        admin_bootstrap_key=BOOTSTRAP_KEY,
        metadata_backend="s3",
        metadata_operator_mode="retention-only",
    )
    assert cfg.metadata_operator_mode == "retention-only"
    with pytest.raises(ValidationError):
        Settings(
            admin_bootstrap_key=BOOTSTRAP_KEY,
            metadata_operator_mode="retention-only-custom-routes",
        )


@pytest.mark.parametrize("mode", ["disabled", "install", "restore", "retention-only"])
def test_operator_mode_enum_keeps_all_existing_modes(mode):
    cfg = Settings(
        admin_bootstrap_key=BOOTSTRAP_KEY,
        metadata_backend="s3",
        metadata_operator_mode=mode,
    )
    assert cfg.metadata_operator_mode == mode


@pytest.mark.parametrize(
    "scope",
    [
        _scope("/admin/api/metadata-operator/status", "GET"),
        _scope("/admin/api/metadata-operator/verify-connections"),
        _scope("/admin/api/metadata-operator/audit-expire"),
        _scope("/admin/api/metadata-operator/initial-admin"),
        _scope(
            "/admin/api/metadata-operator/installation-result/123e4567-e89b-42d3-a456-426614174000",
            "GET",
        ),
        _scope("/admin/api/metadata-operator/audit-retention-close", "GET"),
        _scope("/admin/api/metadata-operator/audit-retention-close/"),
        _scope("/admin/api/metadata-operator/audit-retention-close", query=b"x=1"),
    ],
)
def test_operator_handler_refuses_non_allowlisted_action_before_body_or_dispatch(scope):
    cfg = SimpleNamespace(
        admin_bootstrap_key=BOOTSTRAP_KEY,
        metadata_operator_mode="retention-only",
    )
    sent = []
    send = asyncio.run(_send_collect(sent))
    with patch.object(operator, "get_settings", return_value=cfg), patch.object(
        operator, "offload", new_callable=AsyncMock
    ) as dispatch, patch(
        "mcp_vault.openbao.manager.probe_openbao", new_callable=AsyncMock
    ) as probe:
        asyncio.run(operator.handle_operator(scope, _poison_receive, send))
    assert sent[0]["status"] == 403
    dispatch.assert_not_awaited()
    probe.assert_not_awaited()


@pytest.mark.parametrize("mode", ["install", "restore"])
def test_historical_install_result_prefix_remains_available_outside_retention_only(mode):
    cfg = SimpleNamespace(admin_bootstrap_key=BOOTSTRAP_KEY, metadata_operator_mode=mode)
    scope = _scope(
        "/admin/api/metadata-operator/installation-result/123e4567-e89b-42d3-a456-426614174000",
        "GET",
        query=b"token_hash=abc&client_name=test",
    )
    sent_messages = []
    send = asyncio.run(_send_collect(sent_messages))
    receive = AsyncMock(return_value={"type": "http.request", "body": b"", "more_body": False})
    with patch.object(operator, "get_settings", return_value=cfg), patch.object(
        operator, "offload", new_callable=AsyncMock,
        return_value={"status": "ok", "effect_observed": False},
    ) as dispatch:
        asyncio.run(operator.handle_operator(scope, receive, send))
    assert sent_messages[0]["status"] == 200
    assert receive.await_count == 1
    dispatch.assert_awaited_once()


@pytest.mark.parametrize("path", RETENTION_PATHS)
def test_five_retention_posts_pass_the_operator_gate_then_keep_existing_guards(path):
    cfg = SimpleNamespace(
        admin_bootstrap_key=BOOTSTRAP_KEY,
        metadata_operator_mode="retention-only",
    )
    scope = _scope(path)
    messages = []
    sent = asyncio.run(_send_collect(messages))
    receive = AsyncMock(return_value={"type": "http.request", "body": b"{}", "more_body": False})
    with patch.object(operator, "get_settings", return_value=cfg), patch.object(
        operator, "offload", new_callable=AsyncMock,
        return_value={"status": "ok", "observation_only": True},
    ) as dispatch:
        asyncio.run(operator.handle_operator(scope, receive, sent))
    assert receive.await_count == 1
    dispatch.assert_awaited_once()
    assert messages[0]["status"] == 200


@pytest.mark.parametrize(
    "path,body",
    [
        (RETENTION_PATHS[0], {"proof": "signed", "confirm": "audit-retention-close"}),
        (RETENTION_PATHS[1], {"proof": "signed"}),
        (RETENTION_PATHS[2], {"proof": "signed", "operation_id": "123e4567-e89b-42d3-a456-426614174000"}),
        (RETENTION_PATHS[3], {
            "proof": "signed", "operation_id": "123e4567-e89b-42d3-a456-426614174000",
            "confirm": "audit-retention-retire", "batch": 1,
        }),
        (RETENTION_PATHS[4], {"proof": "signed", "operation_id": "123e4567-e89b-42d3-a456-426614174000"}),
    ],
)
def test_allowed_handler_runs_real_mission_proof_and_stops_at_stubbed_sql_boundary(
    monkeypatch, path, body
):
    import httpx
    from mcp_vault.storage import retirement_maintenance as retirement
    from mcp_vault.storage import retention_maintenance as retention
    from mcp_vault.storage.postgres import MetadataUnavailable
    from tests.test_retention_owner_846 import settings as retention_settings, signed
    import tests.test_retention_owner_846 as retention_test

    monkeypatch.setattr(retention_test, "NOW", datetime.now(timezone.utc).replace(microsecond=0))
    token, cache = signed()
    body["proof"] = token
    cfg = retention_settings("retention-only")
    cfg.admin_bootstrap_key = BOOTSTRAP_KEY
    monkeypatch.setattr(operator, "get_settings", lambda: cfg)
    monkeypatch.setattr(retention, "get_settings", lambda: cfg)
    monkeypatch.setattr(retirement, "get_settings", lambda: cfg)
    monkeypatch.setattr(proof, "init_jwks_cache", lambda *unused: cache)
    requests = []
    original_client = httpx.Client

    def response(request):
        requests.append(request)
        return httpx.Response(200, json={"active": True})

    def client(**kwargs):
        assert kwargs["follow_redirects"] is False
        return original_client(transport=httpx.MockTransport(response), **kwargs)

    monkeypatch.setattr(proof.httpx, "Client", client)

    @contextmanager
    def app_connection():
        class App:
            def execute(self, query):
                assert query == "SELECT version FROM vault_metadata.schema_version"
                return SimpleNamespace(fetchall=lambda: [{"version": 4}])

        yield App()

    def no_real_sql():
        raise MetadataUnavailable("bounded SQL boundary stub")

    monkeypatch.setattr(retention, "connection", app_connection)
    monkeypatch.setattr(retirement, "connection", app_connection)
    monkeypatch.setattr(retention, "maintenance_connection", no_real_sql)
    monkeypatch.setattr(retirement, "maintenance_connection", no_real_sql)
    receive = AsyncMock(return_value={
        "type": "http.request", "body": json.dumps(body).encode(), "more_body": False,
    })
    messages = []
    send = asyncio.run(_send_collect(messages))
    asyncio.run(operator.handle_operator(_scope(path), receive, send))
    assert messages[0]["status"] == 503
    assert len(requests) == 1 and requests[0].method == "POST"
    assert receive.await_count == 1


@pytest.mark.parametrize(
    "path,method,raw_path,query",
    [
        (RETENTION_PATHS[0], "GET", None, b""),
        (RETENTION_PATHS[0], "POST", RETENTION_PATHS[0].replace("close", "%63lose").encode(), b""),
        (RETENTION_PATHS[0] + "/", "POST", None, b""),
        (RETENTION_PATHS[0], "POST", None, b"confirm=x"),
        ("/admin/api/vaults", "POST", None, b""),
        ("/acme/directory", "GET", None, b""),
        ("/v1/_sys_pki_int/roles/role/acme/directory", "GET", None, b""),
        ("/pki/ca/root.pem", "GET", None, b""),
        ("/api/health", "GET", None, b""),
        ("/mcp", "POST", None, b""),
    ],
)
def test_create_app_outer_gate_blocks_every_other_http_scope_before_inner_dispatch(
    monkeypatch, path, method, raw_path, query
):
    from mcp_vault import server
    from mcp_vault.admin.middleware import AdminMiddleware
    from mcp_vault.pki_middleware import PkiMiddleware
    from mcp_vault.auth.middleware import AuthMiddleware

    cfg = Settings(
        admin_bootstrap_key=BOOTSTRAP_KEY,
        metadata_backend="s3",
        metadata_operator_mode="retention-only",
    )
    monkeypatch.setattr(server, "settings", cfg)
    monkeypatch.setattr(server, "_install_vault_lifespan", lambda app: None)
    inner = []

    async def admin_call(self, scope, receive, send):
        inner.append("admin")

    async def auth_call(self, scope, receive, send):
        inner.append("auth")

    async def pki_proxy(self, scope, receive, send, *args):
        inner.append("pki")

    monkeypatch.setattr(AdminMiddleware, "__call__", admin_call)
    monkeypatch.setattr(AuthMiddleware, "__call__", auth_call)
    monkeypatch.setattr(PkiMiddleware, "_proxy_acme", pki_proxy)
    monkeypatch.setattr(PkiMiddleware, "_proxy_acme_long", pki_proxy)
    monkeypatch.setattr(PkiMiddleware, "_proxy_pki_ca", pki_proxy)
    app = server.create_app()
    messages = []
    send = asyncio.run(_send_collect(messages))
    actual_path = raw_path if isinstance(raw_path, bytes) else path.encode("ascii")
    scope = _scope(path, method, raw_path=actual_path, query=query)
    asyncio.run(app(scope, _poison_receive, send))
    assert messages[0]["status"] == 403
    assert inner == []


@pytest.mark.parametrize("path", RETENTION_PATHS)
def test_create_app_outer_gate_passes_the_five_exact_retention_posts(monkeypatch, path):
    from mcp_vault import server
    from mcp_vault.admin.middleware import AdminMiddleware

    cfg = Settings(
        admin_bootstrap_key=BOOTSTRAP_KEY,
        metadata_backend="s3",
        metadata_operator_mode="retention-only",
    )
    monkeypatch.setattr(server, "settings", cfg)
    monkeypatch.setattr(server, "_install_vault_lifespan", lambda app: None)
    passed = []

    async def admin_call(self, scope, receive, send):
        passed.append((scope["method"], scope["path"]))
        await send({"type": "http.response.start", "status": 209, "headers": []})
        await send({"type": "http.response.body", "body": b"passed"})

    monkeypatch.setattr(AdminMiddleware, "__call__", admin_call)
    app = server.create_app()
    messages = []
    send = asyncio.run(_send_collect(messages))
    asyncio.run(app(_scope(path), _poison_receive, send))
    assert passed == [("POST", path)]
    assert messages[0]["status"] == 209


def test_non_http_lifespan_scope_is_forwarded_in_retention_only(monkeypatch):
    from mcp_vault import server
    from mcp_vault.admin.middleware import AdminMiddleware

    cfg = Settings(
        admin_bootstrap_key=BOOTSTRAP_KEY,
        metadata_backend="s3",
        metadata_operator_mode="retention-only",
    )
    monkeypatch.setattr(server, "settings", cfg)
    monkeypatch.setattr(server, "_install_vault_lifespan", lambda app: None)
    seen = []

    async def admin_call(self, scope, receive, send):
        seen.append(scope["type"])

    monkeypatch.setattr(AdminMiddleware, "__call__", admin_call)
    app = server.create_app()
    asyncio.run(app({"type": "lifespan"}, _poison_receive, AsyncMock()))
    assert seen == ["lifespan"]
