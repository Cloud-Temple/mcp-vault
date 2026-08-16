#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests du fix admin API ContextVar — Bug "created_by: anonymous".

Vérifie que handle_admin_api() injecte correctement le token_info
dans le ContextVar current_token_info, pour que les fonctions downstream
(create_space, update_space, etc.) résolvent le bon client_name.

Ces tests sont 100% locaux — aucune dépendance S3, OpenBao, ou réseau.

Usage :
    PYTHONPATH=src python -m pytest tests/test_admin_context.py -v
"""

import os
import sys
from unittest.mock import patch

from tests.doubles_magasins import DoubleMagasin

import pytest

# S'assurer que le module est importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Fixer les env vars minimales pour que Settings() ne plante pas
os.environ.setdefault("MCP_SERVER_NAME", "mcp-vault-test")
os.environ.setdefault("ADMIN_BOOTSTRAP_KEY", "Test-Bootstrap-Key-2026-Pour-Tests!!")


def _loop():
    """Boucle d'événements valide même si une suite antérieure l'a fermée (issue #36)."""
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop


# =============================================================================
# Tests ContextVar injection (fix du bug "created_by: anonymous")
# =============================================================================

class TestAdminApiContextVar:
    """
    Tests de l'injection du ContextVar dans l'API admin.

    Vérifie le fix du bug "created_by: anonymous" :
    handle_admin_api() doit injecter token_info dans current_token_info
    pour que get_current_client_name() retourne le vrai client_name
    (et non "anonymous") lors des appels downstream (create_space, etc.).
    """

    def test_admin_api_injects_contextvar(self):
        """
        handle_admin_api() doit injecter token_info dans le ContextVar AVANT d'appeler
        la route downstream. Test comportemental : si l'injection était supprimée,
        get_current_client_name() retournerait "anonymous".
        
        On appelle GET /admin/api/whoami qui retourne {**token_info} inline
        après que handle_admin_api a injecté le ContextVar. On capture
        get_current_client_name() via un patch de _json_response.
        """
        import asyncio
        from mcp_vault.admin.api import handle_admin_api
        from mcp_vault.auth.context import get_current_client_name
        from unittest.mock import patch, AsyncMock

        seen_during_response = []

        async def spy_json_response(send, status, body):
            seen_during_response.append(get_current_client_name())
            await send({"type": "http.response.start", "status": status, "headers": []})
            import json
            await send({"type": "http.response.body", "body": json.dumps(body).encode()})

        token_info = {
            "client_name": "CEY",
            "permissions": ["read", "write"],
            "allowed_resources": [],
            "auth_type": "token",
        }

        scope = {
            "type": "http", "method": "GET", "path": "/admin/api/whoami",
            "query_string": b"",
            "headers": [(b"authorization", b"Bearer test-token")],
        }

        async def receive(): return {"type": "http.request", "body": b"", "more_body": False}
        responses = []
        async def send_fn(msg): responses.append(msg)

        with patch("mcp_vault.admin.api._get_token_info", return_value=token_info), \
             patch("mcp_vault.admin.api._json_response", side_effect=spy_json_response):
            _loop().run_until_complete(
                handle_admin_api(scope, receive, send_fn, mcp=None)
            )

        assert seen_during_response, "La route /admin/api/whoami n'a pas été appelée"
        assert seen_during_response[0] == "CEY", \
            f"handle_admin_api doit injecter le ContextVar avant la route, obtenu '{seen_during_response[0]}'"

    def test_admin_api_bootstrap_token_contextvar(self):
        """
        Le bootstrap token (admin) propage aussi le ContextVar via handle_admin_api().
        Test comportemental : si l'injection était supprimée, on obtiendrait "anonymous".
        """
        import asyncio
        from mcp_vault.admin.api import handle_admin_api
        from mcp_vault.auth.context import get_current_client_name
        from unittest.mock import patch

        seen_during_response = []

        async def spy_json_response(send, status, body):
            seen_during_response.append(get_current_client_name())
            await send({"type": "http.response.start", "status": status, "headers": []})
            import json
            await send({"type": "http.response.body", "body": json.dumps(body).encode()})

        token_info = {
            "client_name": "admin",
            "permissions": ["read", "write", "admin"],
            "allowed_resources": [],
            "auth_type": "bootstrap",
        }

        scope = {
            "type": "http", "method": "GET", "path": "/admin/api/whoami",
            "query_string": b"",
            "headers": [(b"authorization", b"Bearer bootstrap-key")],
        }

        async def receive(): return {"type": "http.request", "body": b"", "more_body": False}
        async def send_fn(msg): pass

        with patch("mcp_vault.admin.api._get_token_info", return_value=token_info), \
             patch("mcp_vault.admin.api._json_response", side_effect=spy_json_response):
            _loop().run_until_complete(
                handle_admin_api(scope, receive, send_fn, mcp=None)
            )

        assert seen_during_response, "La route /admin/api/whoami n'a pas été appelée"
        assert seen_during_response[0] == "admin", \
            f"Bootstrap token doit propager client_name='admin' via ContextVar : obtenu '{seen_during_response[0]}'"

    def test_without_fix_would_be_anonymous(self):
        """
        Confirme que SANS injection du ContextVar (le bug d'origine),
        get_current_client_name() retourne 'anonymous'.
        C'est le test de non-régression du bug.
        """
        from mcp_vault.auth.context import current_token_info, get_current_client_name

        # Simule l'ancien comportement : pas d'injection ContextVar
        tok = current_token_info.set(None)
        try:
            name = get_current_client_name()
            assert name == "anonymous", f"Expected 'anonymous', got '{name}'"
        finally:
            current_token_info.reset(tok)

    def test_contextvar_isolation_between_requests(self):
        """
        Vérifie que le ContextVar est bien isolé entre deux requêtes
        simulées (le reset empêche les fuites de contexte).
        """
        from mcp_vault.auth.context import current_token_info, get_current_client_name

        # Requête 1 : client CEY
        tok1 = current_token_info.set({"client_name": "CEY", "permissions": ["write"]})
        try:
            assert get_current_client_name() == "CEY"
        finally:
            current_token_info.reset(tok1)

        # Entre les requêtes : pas de fuite
        assert get_current_client_name() == "anonymous"

        # Requête 2 : client agent-sre
        tok2 = current_token_info.set({"client_name": "agent-sre", "permissions": ["read"]})
        try:
            assert get_current_client_name() == "agent-sre"
        finally:
            current_token_info.reset(tok2)

        # Après tout : propre
        assert get_current_client_name() == "anonymous"


# =============================================================================
# Tests check_access / check_write / check_admin (contexte auth)
# =============================================================================

class TestAuthContextPermissions:
    """
    Tests de la logique d'autorisation via ContextVar.
    Vérifie que check_access, check_write_permission, check_admin_permission
    fonctionnent correctement selon le token injecté.
    """

    def test_no_token_access_denied(self):
        """Sans token → check_access refusé."""
        from mcp_vault.auth.context import current_token_info, check_access

        tok = current_token_info.set(None)
        try:
            result = check_access("any-vault")
            assert result is not None
            assert result["status"] == "error"
            assert "Authentification" in result["message"]
        finally:
            current_token_info.reset(tok)

    def test_admin_access_total(self):
        """Token admin → accès total à tout vault."""
        from mcp_vault.auth.context import current_token_info, check_access

        tok = current_token_info.set({
            "client_name": "admin",
            "permissions": ["admin", "read", "write"],
            "allowed_resources": [],
        })
        try:
            for vault in ["vault-a", "vault-b", "nonexistent", ""]:
                result = check_access(vault)
                assert result is None, f"Admin should access '{vault}', got {result}"
        finally:
            current_token_info.reset(tok)

    def test_allowed_resources_filter(self):
        """Token avec allowed_resources → seuls ceux-ci sont accessibles."""
        from mcp_vault.auth.context import current_token_info, check_access

        tok = current_token_info.set({
            "client_name": "agent-1",
            "permissions": ["read"],
            "allowed_resources": ["vault-a", "vault-b"],
        })
        try:
            assert check_access("vault-a") is None
            assert check_access("vault-b") is None
            result = check_access("vault-c")
            assert result is not None
            assert result["status"] == "error"
        finally:
            current_token_info.reset(tok)

    def test_write_permission_readonly_denied(self):
        """Token read-only → écriture refusée."""
        from mcp_vault.auth.context import current_token_info, check_write_permission

        tok = current_token_info.set({"client_name": "reader", "permissions": ["read"]})
        try:
            result = check_write_permission()
            assert result is not None
            assert "écriture" in result["message"].lower() or "write" in result["message"].lower()
        finally:
            current_token_info.reset(tok)

    def test_write_permission_writer_ok(self):
        """Token write → écriture autorisée."""
        from mcp_vault.auth.context import current_token_info, check_write_permission

        tok = current_token_info.set({"client_name": "writer", "permissions": ["read", "write"]})
        try:
            assert check_write_permission() is None
        finally:
            current_token_info.reset(tok)

    def test_admin_permission_non_admin_denied(self):
        """Token non-admin → permission admin refusée."""
        from mcp_vault.auth.context import current_token_info, check_admin_permission

        tok = current_token_info.set({"client_name": "user", "permissions": ["read", "write"]})
        try:
            result = check_admin_permission()
            assert result is not None
            assert "admin" in result["message"].lower()
        finally:
            current_token_info.reset(tok)

    def test_admin_permission_admin_ok(self):
        """Token admin → permission admin OK."""
        from mcp_vault.auth.context import current_token_info, check_admin_permission

        tok = current_token_info.set({"client_name": "admin", "permissions": ["admin"]})
        try:
            assert check_admin_permission() is None
        finally:
            current_token_info.reset(tok)

    def test_get_current_client_name_various(self):
        """get_current_client_name() retourne le bon nom selon le contexte."""
        from mcp_vault.auth.context import current_token_info, get_current_client_name

        # Sans token
        assert get_current_client_name() == "anonymous"

        # Avec token
        tok = current_token_info.set({"client_name": "my-agent"})
        try:
            assert get_current_client_name() == "my-agent"
        finally:
            current_token_info.reset(tok)

        # Token sans client_name → "unknown"
        tok = current_token_info.set({"permissions": ["read"]})
        try:
            assert get_current_client_name() == "unknown"
        finally:
            current_token_info.reset(tok)


# =============================================================================
# Test structurel : vérifier que api.py importe et utilise le ContextVar
# =============================================================================

class TestAdminApiCodeStructure:
    """
    Tests comportementaux — vérifie les invariants d'api.py à l'exécution,
    sans inspection de code source ni recherche textuelle.
    """

    def _call_admin(self, path, method="GET", body=b"", token_info=None):
        """Helper ASGI : appelle handle_admin_api et retourne (status, body_dict)."""
        import asyncio, json
        from mcp_vault.admin.api import handle_admin_api

        if token_info is None:
            token_info = {"client_name": "test-admin", "permissions": ["admin"], "allowed_resources": []}

        scope = {
            "type": "http", "method": method, "path": path,
            "headers": [(b"authorization", b"Bearer test-tok")],
            "query_string": b"",
        }
        events = []

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(event):
            events.append(event)

        with patch("mcp_vault.admin.api._get_token_info", return_value=token_info):
            _loop().run_until_complete(
                handle_admin_api(scope, receive, send, None)
            )

        start = next(e for e in events if e["type"] == "http.response.start")
        body_ev = next(e for e in events if e["type"] == "http.response.body")
        return start["status"], json.loads(body_ev["body"])

    def test_whoami_returns_injected_client_name(self):
        """
        GET /admin/api/whoami retourne le client_name du token injecté dans le ContextVar.

        Prouve que handle_admin_api injecte bien current_token_info avant de router :
        si le ContextVar n'était pas injecté, whoami retournerait "anonymous".
        """
        token_info = {"client_name": "agent-xyz", "permissions": ["read"], "allowed_resources": []}
        code, body = self._call_admin("/admin/api/whoami", token_info=token_info)
        assert code == 200
        assert body.get("client_name") == "agent-xyz", (
            "whoami doit retourner le client_name du token injecté dans le ContextVar, "
            f"obtenu : {body.get('client_name')!r}"
        )

    def test_contextvar_reset_after_request(self):
        """
        Le ContextVar current_token_info est resetté après chaque requête (finally).

        Prouve que handle_admin_api utilise un finally pour reset — sinon le ContextVar
        d'une requête contaminerait les requêtes suivantes dans le même thread.
        """
        from mcp_vault.auth.context import current_token_info, get_current_client_name

        # Avant la requête : ContextVar non défini → "anonymous"
        assert get_current_client_name() == "anonymous"

        token_info = {"client_name": "requete-test", "permissions": ["read"], "allowed_resources": []}
        self._call_admin("/admin/api/whoami", token_info=token_info)

        # Après la requête : ContextVar doit être resetté → retour à "anonymous"
        assert get_current_client_name() == "anonymous", (
            "Le ContextVar doit être resetté après la requête (finally dans handle_admin_api)"
        )

    def test_create_policy_created_by_uses_token_client_name(self):
        """
        POST /admin/api/policies crée la policy avec created_by = client_name du token.

        Prouve que _api_create_policy appelle get_current_client_name() et non "admin"
        hardcodé : si le client s'appelle "agent-creator", la policy doit avoir
        created_by="agent-creator".
        """
        from unittest.mock import MagicMock, patch

        mock_store = DoubleMagasin()
        mock_store.create.return_value = {"status": "created", "policy_id": "test-pol"}

        token_info = {"client_name": "agent-creator", "permissions": ["admin"], "allowed_resources": []}
        body = b'{"policy_id": "test-pol", "description": "test"}'

        with patch("mcp_vault.auth.policies.get_policy_store", return_value=mock_store):
            code, resp = self._call_admin("/admin/api/policies", "POST", body, token_info)

        assert code == 201
        call_kwargs = mock_store.create.call_args[1]
        assert call_kwargs.get("created_by") == "agent-creator", (
            f"created_by doit être 'agent-creator', obtenu : {call_kwargs.get('created_by')!r} — "
            "vérifier que _api_create_policy utilise get_current_client_name()"
        )
