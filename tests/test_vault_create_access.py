#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests — Asymétrie MCP/REST vault_create check_access (issue #58).

Prouve que POST /admin/api/vaults applique désormais le même contrôle
d'accès vault-level que le chemin MCP vault_create.

Appelle _api_create_vault directement pour isoler le comportement :
- mock create_space via sys.modules (vault.spaces dépend de hvac non dispo hors Docker)
- token_info passé explicitement (nouveau style REST cohérent)

Non-complaisant :
- test RED sur ancien code : _api_create_vault(send, body) sans token_info
  → TypeError (signature changée) prouve que le check n'existait pas
- test GREEN avec fix : 403 retourné ET create_space non appelé pour vault non autorisé
- test admin → toujours autorisé (pas de régression)
- test allowed vault → 201 (happy path non-admin)
- test vault_id vide → 400 avant le check d'accès
"""

import sys
import os
import json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from mcp_vault.admin import api


def _statuses(send_mock):
    return [
        c.args[0]["status"]
        for c in send_mock.call_args_list
        if c.args and isinstance(c.args[0], dict)
        and c.args[0].get("type") == "http.response.start"
    ]


def _mock_vault_spaces(create_result=None):
    """Injecte un module mcp_vault.vault.spaces mocké dans sys.modules."""
    mock = MagicMock()
    mock.create_space = AsyncMock(return_value=create_result or {"status": "created"})
    mock.check_vault_owner = MagicMock(return_value=True)
    return mock


# ── Accès refusé : vault hors allowed_resources ───────────────────────────────

async def test_create_vault_acces_refuse_vault_non_autorise():
    """
    Token avec allowed_resources=["vault-a"] essaie de créer "vault-b".

    Ce test est RED sur le code original :
    - ancienne signature _api_create_vault(send, body) → TypeError (3 args passés)
    GREEN après fix : 403, create_space non appelé.
    """
    token_info = {
        "client_name": "agent",
        "permissions": ["read", "write"],
        "allowed_resources": ["vault-a"],
    }
    body = json.dumps({"vault_id": "vault-b", "description": "test"}).encode()
    send = AsyncMock()
    mock_spaces = _mock_vault_spaces()

    with patch.dict(sys.modules, {"mcp_vault.vault.spaces": mock_spaces}):
        await api._api_create_vault(send, body, token_info)

    assert 403 in _statuses(send), f"Attendu 403, obtenu {_statuses(send)}"
    mock_spaces.create_space.assert_not_called()


# ── Accès autorisé : vault dans allowed_resources ────────────────────────────

async def test_create_vault_acces_autorise_vault_dans_liste():
    """Token avec allowed_resources=["vault-a"] crée "vault-a" → 201."""
    token_info = {
        "client_name": "agent",
        "permissions": ["read", "write"],
        "allowed_resources": ["vault-a"],
    }
    body = json.dumps({"vault_id": "vault-a", "description": "test"}).encode()
    send = AsyncMock()
    mock_spaces = _mock_vault_spaces()

    with patch.dict(sys.modules, {"mcp_vault.vault.spaces": mock_spaces}):
        await api._api_create_vault(send, body, token_info)

    assert 201 in _statuses(send), f"Attendu 201, obtenu {_statuses(send)}"
    mock_spaces.create_space.assert_called_once()


# ── Accès admin : toujours autorisé ──────────────────────────────────────────

async def test_create_vault_admin_toujours_autorise():
    """Token admin peut créer n'importe quel vault (pas de régression)."""
    token_info = {
        "client_name": "admin",
        "permissions": ["admin"],
        "allowed_resources": [],
    }
    body = json.dumps({"vault_id": "vault-z", "description": "test"}).encode()
    send = AsyncMock()
    mock_spaces = _mock_vault_spaces()

    with patch.dict(sys.modules, {"mcp_vault.vault.spaces": mock_spaces}):
        await api._api_create_vault(send, body, token_info)

    assert 201 in _statuses(send), f"Admin doit obtenir 201, obtenu {_statuses(send)}"
    mock_spaces.create_space.assert_called_once()


# ── vault_id vide : 400 avant le check d'accès ───────────────────────────────

async def test_create_vault_sans_vault_id_retourne_400():
    """vault_id absent → 400 avant même d'appliquer check_access."""
    token_info = {
        "client_name": "agent",
        "permissions": ["read", "write"],
        "allowed_resources": ["vault-a"],
    }
    body = json.dumps({"description": "test"}).encode()
    send = AsyncMock()
    mock_spaces = _mock_vault_spaces()

    with patch.dict(sys.modules, {"mcp_vault.vault.spaces": mock_spaces}):
        await api._api_create_vault(send, body, token_info)

    assert 400 in _statuses(send), f"Attendu 400, obtenu {_statuses(send)}"
    mock_spaces.create_space.assert_not_called()


# ── Owner-based : vault existant dont on n'est pas owner ─────────────────────

async def test_create_vault_owner_based_vault_existant_non_owner():
    """
    Token sans allowed_resources (owner-based isolation), vault déjà existant
    dont il n'est pas le créateur → 403.
    """
    token_info = {
        "client_name": "agent-b",
        "permissions": ["read", "write"],
        "allowed_resources": [],
    }
    body = json.dumps({"vault_id": "vault-owned-by-agent-a"}).encode()
    send = AsyncMock()
    mock_spaces = _mock_vault_spaces()
    mock_spaces.check_vault_owner.return_value = False  # vault existe, wrong owner

    with patch.dict(sys.modules, {"mcp_vault.vault.spaces": mock_spaces}):
        await api._api_create_vault(send, body, token_info)

    assert 403 in _statuses(send), f"Attendu 403, obtenu {_statuses(send)}"
    mock_spaces.create_space.assert_not_called()
