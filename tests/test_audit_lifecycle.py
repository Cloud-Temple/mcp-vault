#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests — traçabilité d'audit du plan de contrôle d'accès (issue #49).

Conformité SecNumCloud / HDS : toute opération mutante sur les tokens et les
policies via l'API REST admin doit émettre une entrée d'audit persistante
(log_audit -> audit-mcp.jsonl), aujourd'hui absente.

Non-complaisant :
- on vérifie que log_audit est appelé avec le bon (tool, status) pour CHAQUE
  mutation (create/update/revoke token, create/delete policy) ;
- on vérifie que le DÉTAIL d'audit ne contient JAMAIS le token brut (raw_token) ;
- on vérifie la NON-RÉGRESSION du code HTTP (l'ajout d'audit ne change pas le
  status retourné) ;
- on vérifie l'événement critique : une révocation NON persistée (S3 down) est
  auditée en 'error' (le token reste valide — doit laisser une trace).

Offline : stores et log_audit mockés ; aucune dépendance S3 / Docker.
"""

import os
import sys
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp_vault.admin import api
import mcp_vault.server as server
from mcp_vault.auth.context import current_token_info


def _asgi_statuses(send_mock):
    """Status HTTP des messages ASGI http.response.start capturés."""
    return [
        c.args[0].get("status")
        for c in send_mock.call_args_list
        if c.args and isinstance(c.args[0], dict)
        and c.args[0].get("type") == "http.response.start"
    ]


def _audit_call(mock_audit):
    """(tool, status, detail) du dernier appel à log_audit."""
    assert mock_audit.call_count >= 1, "log_audit n'a pas été appelé"
    args, kwargs = mock_audit.call_args
    tool = args[0] if args else kwargs.get("tool_name")
    status = args[1] if len(args) > 1 else kwargs.get("status")
    detail = kwargs.get("detail", args[3] if len(args) > 3 else "")
    return tool, status, detail


class _Ctx:
    """Pose/retire le contextvar opérateur admin (comme AdminMiddleware)."""
    def __enter__(self):
        self._tok = current_token_info.set(
            {"client_name": "admin-op", "permissions": ["admin"], "allowed_resources": []}
        )
        return self

    def __exit__(self, *a):
        current_token_info.reset(self._tok)


# ── Révocation de token ───────────────────────────────────────────────────

async def test_revoke_token_audite_succes():
    send = AsyncMock()
    store = MagicMock()
    store.revoke.return_value = {"status": "ok", "message": "révoqué"}
    with _Ctx(), patch.object(api, "get_token_store", return_value=store), \
            patch.object(api, "log_audit") as mock_audit:
        await api._api_revoke_token(send, "abc123def456")
    tool, status, _ = _audit_call(mock_audit)
    assert (tool, status) == ("token_revoke", "ok")
    assert 200 in _asgi_statuses(send)  # non-régression HTTP


async def test_revoke_token_non_persistee_auditee_en_error():
    """Événement critique : S3 down -> révocation perdue -> token reste valide.
    Doit être tracé en 'error', pas silencieux."""
    send = AsyncMock()
    store = MagicMock()
    store.revoke.return_value = {"status": "storage_unavailable", "message": "S3 down"}
    with _Ctx(), patch.object(api, "get_token_store", return_value=store), \
            patch.object(api, "log_audit") as mock_audit:
        await api._api_revoke_token(send, "abc123def456")
    tool, status, _ = _audit_call(mock_audit)
    assert (tool, status) == ("token_revoke", "error")
    assert 503 in _asgi_statuses(send)


async def test_revoke_token_not_found_pas_d_audit_de_succes():
    """Un not_found n'est pas une mutation : on ne loggue pas un faux succès."""
    send = AsyncMock()
    store = MagicMock()
    store.revoke.return_value = {"status": "not_found", "message": "absent"}
    with _Ctx(), patch.object(api, "get_token_store", return_value=store), \
            patch.object(api, "log_audit") as mock_audit:
        await api._api_revoke_token(send, "abc123def456")
    # aucune entrée 'ok' ne doit être émise pour un not_found
    assert all(c.args[:2] != ("token_revoke", "ok") for c in mock_audit.call_args_list)
    assert 404 in _asgi_statuses(send)


# ── Création / mise à jour de token ─────────────────────────────────────────

async def test_create_token_audite_sans_exposer_le_token_brut():
    send = AsyncMock()
    store = MagicMock()
    store.create.return_value = {
        "raw_token": "sk-vault-SECRET-XYZ", "hash": "h" * 64,
        "client_name": "agent", "permissions": ["read"], "allowed_resources": ["v1"],
    }
    body = json.dumps({"client_name": "agent", "permissions": ["read"],
                       "allowed_resources": ["v1"]})
    with _Ctx(), patch.object(api, "get_token_store", return_value=store), \
            patch.object(api, "log_audit") as mock_audit:
        await api._api_create_token(send, body)
    tool, status, detail = _audit_call(mock_audit)
    assert (tool, status) == ("token_create", "created")
    # INVARIANT SÉCURITÉ : le token brut ne doit JAMAIS fuiter dans l'audit
    assert "sk-vault-SECRET-XYZ" not in detail
    assert 201 in _asgi_statuses(send)


async def test_update_token_audite():
    send = AsyncMock()
    store = MagicMock()
    store.update.return_value = {"status": "updated", "updated_fields": ["permissions"],
                                 "client_name": "agent"}
    body = json.dumps({"permissions": ["read", "write"]})
    with _Ctx(), patch.object(api, "get_token_store", return_value=store), \
            patch.object(api, "log_audit") as mock_audit:
        await api._api_update_token(send, "abc123def456", body)
    tool, status, _ = _audit_call(mock_audit)
    assert (tool, status) == ("token_update", "updated")
    assert 200 in _asgi_statuses(send)


# ── Cycle de vie policy ─────────────────────────────────────────────────────

async def test_create_policy_audite():
    send = AsyncMock()
    pstore = MagicMock()
    pstore.create.return_value = {"status": "created", "policy_id": "p1"}
    body = json.dumps({"policy_id": "p1", "description": "x"})
    with _Ctx(), patch("mcp_vault.auth.policies.get_policy_store", return_value=pstore), \
            patch.object(api, "log_audit") as mock_audit:
        await api._api_create_policy(send, body)
    tool, status, detail = _audit_call(mock_audit)
    assert (tool, status) == ("policy_create", "created")
    assert "p1" in detail
    assert 201 in _asgi_statuses(send)


async def test_delete_policy_audite():
    send = AsyncMock()
    pstore = MagicMock()
    pstore.delete.return_value = True
    with _Ctx(), patch("mcp_vault.auth.policies.get_policy_store", return_value=pstore), \
            patch.object(api, "log_audit") as mock_audit:
        await api._api_delete_policy(send, "p1")
    tool, status, _ = _audit_call(mock_audit)
    assert (tool, status) == ("policy_delete", "deleted")
    assert 200 in _asgi_statuses(send)


# ── Outils MCP : wrap _r() préserve le résultat ET audite ───────────────────

async def test_mcp_policy_create_preserve_resultat_et_audite():
    """policy_create (MCP) doit retourner le résultat du store INCHANGÉ et auditer."""
    store_result = {"status": "created", "policy_id": "p1"}
    expected = dict(store_result)  # snapshot indépendant (détecte une mutation en place)
    pstore = MagicMock()
    pstore.create.return_value = store_result
    with _Ctx(), patch("mcp_vault.auth.policies.get_policy_store", return_value=pstore), \
            patch("mcp_vault.audit.log_audit") as mock_audit:
        out = await server.policy_create("p1", description="x")
    assert out is store_result, "_r() doit retourner le MÊME objet (pas de substitution)"
    assert out == expected, "_r() ne doit pas muter le résultat du store"
    assert mock_audit.call_count == 1
    assert mock_audit.call_args.args[0] == "policy_create"


async def test_mcp_token_update_preserve_resultat_et_audite():
    """token_update (MCP) doit retourner le résultat du store INCHANGÉ et auditer."""
    store_result = {"status": "updated", "updated_fields": ["permissions"]}
    expected = dict(store_result)  # snapshot indépendant (détecte une mutation en place)
    tstore = MagicMock()
    tstore.update.return_value = store_result
    with _Ctx(), patch("mcp_vault.auth.token_store.get_token_store", return_value=tstore), \
            patch("mcp_vault.audit.log_audit") as mock_audit:
        out = await server.token_update("abc123def456", permissions="read,write")
    assert out is store_result, "_r() doit retourner le MÊME objet (pas de substitution)"
    assert out == expected, "_r() ne doit pas muter le résultat du store"
    assert mock_audit.call_args.args[0] == "token_update"


async def test_mcp_policy_delete_storage_error_audite():
    """Régression du fix MOYEN : une suppression de policy NON persistée (S3 down)
    via MCP doit être auditée en 'error', pas silencieuse."""
    pstore = MagicMock()
    pstore.delete.return_value = "storage_error"
    with _Ctx(), patch("mcp_vault.auth.policies.get_policy_store", return_value=pstore), \
            patch("mcp_vault.audit.log_audit") as mock_audit:
        out = await server.policy_delete("p1", confirm=True)
    assert out["status"] == "error"
    assert (mock_audit.call_args.args[0], mock_audit.call_args.args[1]) == ("policy_delete", "error")
