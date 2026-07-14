#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests admin API PKI — comportementaux, sans dépendances réseau.

Vérifie le routage et les permissions des routes /admin/api/pki/*.

Usage :
    PYTHONPATH=src python -m pytest tests/test_pki_admin.py -v
"""

import asyncio
import json
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

os.environ.setdefault("MCP_SERVER_NAME", "mcp-vault-test")
os.environ.setdefault("ADMIN_BOOTSTRAP_KEY", "Test-Bootstrap-Key-2026-Pour-Tests!!")

# hvac (dep Docker-only) est stubbé de façon DÉTERMINISTE et FAIL-CLOSE dans tests/conftest.py
# (issue #64) — plus d'injection sys.modules au niveau module ici (même anti-pattern que test_pki).


def _run(coro):
    """Run coroutine de façon défensive (issue #36).

    Les suites CLI (CliRunner + asyncio.run) peuvent fermer la boucle globale.
    On recrée une boucle si la courante est fermée ou absente, sans la fermer
    nous-mêmes. Pattern identique à test_jwt_validator._run.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


# ─── ASGI test helpers ────────────────────────────────────────────────────────

def _make_scope(path: str, method: str = "GET", token: str = "admin-token") -> dict:
    return {
        "type": "http",
        "method": method,
        "path": path,
        "headers": [(b"authorization", f"Bearer {token}".encode())],
        "query_string": b"",
    }


def _make_receive(body: bytes = b"") -> callable:
    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}
    return receive


def _make_send():
    events = []
    async def send(event): events.append(event)
    return send, events


def _get_response(events):
    start = next(e for e in events if e["type"] == "http.response.start")
    body_event = next(e for e in events if e["type"] == "http.response.body")
    return start["status"], json.loads(body_event["body"])


_ADMIN_TOKEN_INFO = {
    "client_name": "test-admin",
    "permissions": ["read", "write", "admin"],
    "allowed_resources": [],
    "token_hash": "test",
}

_READ_TOKEN_INFO = {
    "client_name": "test-reader",
    "permissions": ["read"],
    "allowed_resources": [],
    "token_hash": "test",
}


# ─── Tests routage PKI dans admin API ────────────────────────────────────────

class TestPkiAdminRoutes:
    """Vérifie que les routes /admin/api/pki/* sont correctement routées."""

    def _call_admin(self, path, method="GET", body=b"", token_info=None):
        from mcp_vault.admin.api import handle_admin_api
        if token_info is None:
            token_info = _ADMIN_TOKEN_INFO
        scope = _make_scope(path, method)
        send_fn, events = _make_send()

        with patch("mcp_vault.admin.api._get_token_info", return_value=token_info):
            _run(handle_admin_api(scope, _make_receive(body), send_fn, None))

        return _get_response(events)

    def test_pki_status_returns_200(self):
        """GET /admin/api/pki/status → 200 (PKI non init = not_initialized)."""
        with patch("mcp_vault.vault.pki_ca.is_pki_initialized", return_value=False), \
             patch("mcp_vault.vault.pki_ca._get_hvac_client", return_value=None):
            code, body = self._call_admin("/admin/api/pki/status")
        assert code == 200
        assert body["status"] in ("ok", "not_initialized", "error")

    def test_pki_status_accessible_to_read_token(self):
        """GET /admin/api/pki/status est accessible à tout token valide."""
        with patch("mcp_vault.vault.pki_ca.is_pki_initialized", return_value=False), \
             patch("mcp_vault.vault.pki_ca._get_hvac_client", return_value=None):
            code, _ = self._call_admin("/admin/api/pki/status", token_info=_READ_TOKEN_INFO)
        assert code == 200

    def test_pki_setup_requires_admin(self):
        """POST /admin/api/pki/setup → 403 si non-admin."""
        code, body = self._call_admin(
            "/admin/api/pki/setup", "POST", b'{"lab_mode":true}',
            token_info=_READ_TOKEN_INFO
        )
        assert code == 403
        assert body["status"] == "error"

    def test_pki_setup_allowed_for_admin(self):
        """POST /admin/api/pki/setup → 200 ou 500 (pas 403) si admin."""
        mock_result = {"status": "ok", "lab_mode": True, "root_mount": "_sys_pki_root"}
        with patch("mcp_vault.vault.pki_ca.setup_pki_ca", new_callable=AsyncMock, return_value=mock_result):
            code, body = self._call_admin(
                "/admin/api/pki/setup", "POST",
                b'{"lab_mode":true,"allowed_domains":"*.lesur.lan,lesur.lan"}'
            )
        assert code == 200
        assert body["status"] == "ok"

    def test_pki_certs_requires_admin(self):
        """GET /admin/api/pki/certs → 403 si non-admin (inventaire = données sensibles)."""
        code, body = self._call_admin("/admin/api/pki/certs", token_info=_READ_TOKEN_INFO)
        assert code == 403

    def test_pki_certs_returns_list_for_admin(self):
        """GET /admin/api/pki/certs → 200 avec liste pour admin."""
        mock_result = {"status": "ok", "total": 0, "certs": []}
        with patch("mcp_vault.vault.pki_ca.list_issued_certs", new_callable=AsyncMock, return_value=mock_result):
            code, body = self._call_admin("/admin/api/pki/certs")
        assert code == 200
        assert "certs" in body

    def test_pki_revoke_rejects_invalid_serial_in_router(self):
        """POST /admin/api/pki/certs/{serial_invalide}/revoke → 400 avant même revoke_cert."""
        code, body = self._call_admin(
            "/admin/api/pki/certs/../../evil/revoke", "POST", b"{}"
        )
        assert code == 400
        assert body["status"] == "error"

    def test_pki_revoke_requires_admin(self):
        """POST /admin/api/pki/certs/{serial}/revoke → 403 si non-admin."""
        code, body = self._call_admin(
            "/admin/api/pki/certs/12:34:ab:cd/revoke", "POST", b"{}",
            token_info=_READ_TOKEN_INFO
        )
        assert code == 403

    def test_pki_revoke_calls_revoke_cert(self):
        """POST /admin/api/pki/certs/{serial}/revoke → appelle revoke_cert."""
        mock_result = {"status": "ok", "serial_number": "12:34:ab:cd", "crl_updated": True}
        with patch("mcp_vault.vault.pki_ca.revoke_cert", new_callable=AsyncMock, return_value=mock_result) as mock_revoke:
            code, body = self._call_admin(
                "/admin/api/pki/certs/12:34:ab:cd/revoke", "POST", b"{}"
            )
        assert code == 200
        mock_revoke.assert_called_once_with("12:34:ab:cd")

    def test_pki_rotate_requires_admin(self):
        """POST /admin/api/pki/ca/rotate → 403 si non-admin."""
        code, body = self._call_admin(
            "/admin/api/pki/ca/rotate", "POST", b"{}",
            token_info=_READ_TOKEN_INFO
        )
        assert code == 403

    def test_pki_rotate_calls_rotate_intermediate(self):
        """POST /admin/api/pki/ca/rotate → appelle rotate_intermediate."""
        mock_result = {"status": "ok", "new_issuer_id": "uuid-new", "new_expires": "2028-01-01"}
        with patch("mcp_vault.vault.pki_ca.rotate_intermediate", new_callable=AsyncMock, return_value=mock_result):
            code, body = self._call_admin(
                "/admin/api/pki/ca/rotate", "POST",
                b'{"keep_old_issuer":true}'
            )
        assert code == 200
        assert body["status"] == "ok"

    def test_unknown_pki_route_returns_404(self):
        """GET /admin/api/pki/unknown → 404."""
        code, body = self._call_admin("/admin/api/pki/unknown")
        assert code == 404
