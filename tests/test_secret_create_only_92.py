#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Régressions #92 : create-only KV v2 atomique et erreurs de lecture fiables."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


os.environ.setdefault("MCP_SERVER_NAME", "mcp-vault-test")
os.environ.setdefault("ADMIN_BOOTSTRAP_KEY", "Test-Bootstrap-Key-2026-Pour-Tests!!")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def run(coro):
    return asyncio.run(coro)


def response_collector():
    messages: list[dict] = []

    async def send(message: dict) -> None:
        messages.append(message)

    return messages, send


def request_body(payload):
    raw = json.dumps(payload).encode()
    delivered = False

    async def receive():
        nonlocal delivered
        if delivered:
            return {"type": "http.request", "body": b"", "more_body": False}
        delivered = True
        return {"type": "http.request", "body": raw, "more_body": False}

    return receive


def decoded_response(messages: list[dict]) -> tuple[int, dict]:
    status = next(message["status"] for message in messages if message["type"] == "http.response.start")
    raw = b"".join(message.get("body", b"") for message in messages if message["type"] == "http.response.body")
    return status, json.loads(raw)


def test_vault_layer_passes_cas_zero_only_for_create_only() -> None:
    from mcp_vault.vault import secrets

    writer = MagicMock(return_value={"data": {"version": 1}})
    client = SimpleNamespace(secrets=SimpleNamespace(kv=SimpleNamespace(v2=SimpleNamespace(create_or_update_secret=writer))))

    with patch.object(secrets, "get_hvac_client", return_value=client):
        result = run(
            secrets.write_secret(
                "agentic-platform",
                "platform/s3/mcp-agent",
                {"key": "test-key", "secret": "test-secret"},
                "api_key",
                create_only=True,
            )
        )

    assert result["status"] == "ok"
    assert result["version"] == 1
    writer.assert_called_once()
    assert writer.call_args.kwargs["cas"] == 0


def test_vault_layer_maps_cas_mismatch_to_conflict_without_retry() -> None:
    import hvac
    from mcp_vault.vault import secrets

    writer = MagicMock(
        side_effect=hvac.exceptions.InvalidRequest(
            errors=["check-and-set parameter did not match current version"]
        )
    )
    client = SimpleNamespace(secrets=SimpleNamespace(kv=SimpleNamespace(v2=SimpleNamespace(create_or_update_secret=writer))))

    with patch.object(secrets, "get_hvac_client", return_value=client):
        result = run(
            secrets.write_secret(
                "agentic-platform",
                "platform/s3/mcp-agent",
                {"key": "test-key", "secret": "test-secret"},
                "api_key",
                create_only=True,
            )
        )

    assert result == {
        "status": "conflict",
        "message": "Secret déjà présent",
    }
    writer.assert_called_once()


def test_vault_layer_does_not_map_an_unrelated_400_to_a_conflict() -> None:
    import hvac
    from mcp_vault.vault import secrets

    writer = MagicMock(side_effect=hvac.exceptions.InvalidRequest(errors=["invalid mount configuration"]))
    client = SimpleNamespace(secrets=SimpleNamespace(kv=SimpleNamespace(v2=SimpleNamespace(create_or_update_secret=writer))))

    with patch.object(secrets, "get_hvac_client", return_value=client):
        result = run(
            secrets.write_secret(
                "agentic-platform",
                "platform/s3/mcp-agent",
                {"key": "test-key", "secret": "test-secret"},
                "api_key",
                create_only=True,
            )
        )

    assert result == {
        "status": "error",
        "error_type": "backend",
        "message": "Écriture OpenBao refusée",
    }


def test_vault_layer_keeps_historical_upsert_without_cas() -> None:
    from mcp_vault.vault import secrets

    writer = MagicMock(return_value={"data": {"version": 2}})
    client = SimpleNamespace(secrets=SimpleNamespace(kv=SimpleNamespace(v2=SimpleNamespace(create_or_update_secret=writer))))

    with patch.object(secrets, "get_hvac_client", return_value=client):
        result = run(
            secrets.write_secret(
                "agentic-platform",
                "existing/path",
                {"key": "updated"},
                "api_key",
            )
        )

    assert result["status"] == "ok"
    assert "cas" not in writer.call_args.kwargs


def test_admin_route_requires_a_real_boolean_for_create_only() -> None:
    from mcp_vault.admin.api import _api_write_secret

    messages, send = response_collector()
    with patch("mcp_vault.vault.secrets.write_secret", new_callable=AsyncMock) as writer:
        run(
            _api_write_secret(
                send,
                "agentic-platform",
                json.dumps(
                    {
                        "path": "platform/s3/mcp-agent",
                        "type": "api_key",
                        "data": {"key": "test-key"},
                        "create_only": "true",
                    }
                ).encode(),
            )
        )

    status, body = decoded_response(messages)
    assert status == 400
    assert body == {"status": "error", "message": "create_only doit être booléen"}
    writer.assert_not_awaited()


def test_admin_route_returns_409_for_create_only_conflict() -> None:
    from mcp_vault.admin.api import _api_write_secret

    messages, send = response_collector()
    with patch(
        "mcp_vault.vault.secrets.write_secret",
        new=AsyncMock(return_value={"status": "conflict", "message": "Secret déjà présent"}),
    ) as writer:
        run(
            _api_write_secret(
                send,
                "agentic-platform",
                json.dumps(
                    {
                        "path": "platform/s3/mcp-agent",
                        "type": "api_key",
                        "data": {"key": "test-key"},
                        "create_only": True,
                    }
                ).encode(),
            )
        )

    status, body = decoded_response(messages)
    assert status == 409
    assert body["status"] == "conflict"
    assert writer.await_args.kwargs["create_only"] is True


def test_admin_route_returns_503_for_backend_write_error() -> None:
    from mcp_vault.admin.api import _api_write_secret

    messages, send = response_collector()
    domain_result = {
        "status": "error",
        "error_type": "backend",
        "message": "Écriture OpenBao impossible",
    }
    with patch(
        "mcp_vault.vault.secrets.write_secret",
        new=AsyncMock(return_value=domain_result),
    ):
        run(
            _api_write_secret(
                send,
                "agentic-platform",
                json.dumps(
                    {
                        "path": "platform/s3/mcp-agent",
                        "data": {"key": "test-key"},
                        "create_only": True,
                    }
                ).encode(),
            )
        )

    status, body = decoded_response(messages)
    assert status == 503
    assert body == domain_result


@pytest.mark.parametrize(
    ("payload", "expected_message"),
    [
        (["not", "an", "object"], "JSON objet requis"),
        ({"path": 42, "data": {"key": "value"}}, "path doit être une chaîne"),
        ({"path": "valid/path", "data": ["not", "an", "object"]}, "data requis"),
        ({"path": "valid/path", "data": {"key": "value"}, "type": []}, "type ou tags invalide"),
        ({"path": "valid/path", "data": {"key": "value"}, "tags": 42}, "type ou tags invalide"),
    ],
)
def test_admin_write_rejects_non_object_fields(payload, expected_message: str) -> None:
    from mcp_vault.admin.api import _api_write_secret

    messages, send = response_collector()
    with patch("mcp_vault.vault.secrets.write_secret", new_callable=AsyncMock) as writer:
        run(_api_write_secret(send, "agentic-platform", json.dumps(payload).encode()))

    status, body = decoded_response(messages)
    assert status == 400
    assert body == {"status": "error", "message": expected_message}
    writer.assert_not_awaited()


@pytest.mark.parametrize(
    "payload",
    [
        ["not", "an", "object"],
        {"path": 42, "data": {"key": "value"}},
    ],
)
def test_full_admin_route_rejects_invalid_top_level_secret_payload(payload) -> None:
    from mcp_vault.admin.api import _handle_admin_routes

    messages, send = response_collector()
    scope = {
        "path": "/admin/api/vaults/agentic-platform/secrets",
        "method": "POST",
        "query_string": b"",
    }
    token_info = {
        "client_name": "migration-test",
        "permissions": ["admin"],
        "allowed_resources": ["agentic-platform"],
    }
    with (
        patch("mcp_vault.admin.api._check_vault_access", return_value=None),
        patch("mcp_vault.admin.api.check_policy", return_value=None),
        patch("mcp_vault.admin.api.check_path_policy", return_value=None),
        patch("mcp_vault.vault.secrets.write_secret", new_callable=AsyncMock) as writer,
    ):
        run(_handle_admin_routes(scope, request_body(payload), send, None, token_info))

    status, _body = decoded_response(messages)
    assert status == 400
    writer.assert_not_awaited()


def test_vault_read_returns_not_found_only_when_kv_v2_mount_is_proven() -> None:
    import hvac
    from mcp_vault.vault import secrets

    reader = MagicMock(side_effect=hvac.exceptions.InvalidPath())
    client = SimpleNamespace(
        secrets=SimpleNamespace(kv=SimpleNamespace(v2=SimpleNamespace(read_secret_version=reader))),
        sys=SimpleNamespace(
            list_mounted_secrets_engines=MagicMock(
                return_value={
                    "data": {
                        "agentic-platform/": {
                            "type": "kv",
                            "options": {"version": "2"},
                        }
                    }
                }
            )
        ),
    )

    with patch.object(secrets, "get_hvac_client", return_value=client):
        result = run(secrets.read_secret("agentic-platform", "missing/path"))

    assert result == {
        "status": "error",
        "error_type": "not_found",
        "message": "Secret absent",
    }


@pytest.mark.parametrize(
    "mount_probe",
    [
        MagicMock(return_value={"data": {}}),
        MagicMock(side_effect=RuntimeError("SENSITIVE mount diagnostic")),
    ],
)
def test_vault_read_fails_closed_when_mount_cannot_be_proven(mount_probe, caplog) -> None:
    import hvac
    from mcp_vault.vault import secrets

    reader = MagicMock(side_effect=hvac.exceptions.InvalidPath())
    client = SimpleNamespace(
        secrets=SimpleNamespace(kv=SimpleNamespace(v2=SimpleNamespace(read_secret_version=reader))),
        sys=SimpleNamespace(list_mounted_secrets_engines=mount_probe),
    )

    with patch.object(secrets, "get_hvac_client", return_value=client):
        result = run(secrets.read_secret("agentic-platform", "missing/path"))

    assert result == {
        "status": "error",
        "error_type": "backend",
        "message": "Lecture OpenBao impossible",
    }
    assert "SENSITIVE" not in caplog.text


def test_backend_write_does_not_leak_exception_details(caplog) -> None:
    from mcp_vault.vault import secrets

    writer = MagicMock(side_effect=RuntimeError("SENSITIVE backend diagnostic"))
    client = SimpleNamespace(secrets=SimpleNamespace(kv=SimpleNamespace(v2=SimpleNamespace(create_or_update_secret=writer))))

    with patch.object(secrets, "get_hvac_client", return_value=client):
        result = run(
            secrets.write_secret(
                "agentic-platform",
                "platform/s3/mcp-agent",
                {"key": "test-key"},
                create_only=True,
            )
        )

    assert result["error_type"] == "backend"
    assert "SENSITIVE" not in caplog.text


def test_whoami_token_info_exposes_expiry_for_least_privilege_attestation() -> None:
    from mcp_vault.admin import api

    token_store = MagicMock()
    token_store.get_by_hash.return_value = {
        "client_name": "vault01-migration",
        "permissions": ["read"],
        "allowed_resources": ["agentic-plateform"],
        "policy_id": "migration-readonly",
        "expires_at": "2026-07-21T00:00:00+00:00",
        "revoked": False,
    }
    with (
        patch.object(api, "get_settings", return_value=SimpleNamespace(admin_bootstrap_key="different-token")),
        patch.object(api, "get_token_store", return_value=token_store),
    ):
        info = api._get_token_info("temporary-read-token")

    assert info == {
        "client_name": "vault01-migration",
        "permissions": ["read"],
        "allowed_resources": ["agentic-plateform"],
        "policy_id": "migration-readonly",
        "expires_at": "2026-07-21T00:00:00+00:00",
        "auth_type": "token",
    }


@pytest.mark.parametrize(
    ("domain_result", "expected_status"),
    [
        (
            {"status": "error", "error_type": "not_found", "message": "Secret absent"},
            404,
        ),
        ({"status": "error", "message": "Lecture OpenBao impossible"}, 503),
    ],
)
def test_admin_read_distinguishes_not_found_from_backend_error(domain_result: dict, expected_status: int) -> None:
    from mcp_vault.admin.api import _api_read_secret

    messages, send = response_collector()
    with patch("mcp_vault.vault.secrets.read_secret", new=AsyncMock(return_value=domain_result)):
        run(_api_read_secret(send, "agentic-platform", "platform/s3/mcp-agent"))

    status, body = decoded_response(messages)
    assert status == expected_status
    assert body == domain_result
