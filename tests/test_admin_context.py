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

import pytest

# S'assurer que le module est importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Fixer les env vars minimales pour que Settings() ne plante pas
os.environ.setdefault("MCP_SERVER_NAME", "mcp-vault-test")
os.environ.setdefault("ADMIN_BOOTSTRAP_KEY", "test-bootstrap-key-for-unit-tests")


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
        Simule le flux handle_admin_api : après injection du ContextVar,
        get_current_client_name() doit retourner le client du token.
        """
        from mcp_vault.auth.context import current_token_info, get_current_client_name

        # Simule ce que handle_admin_api fait maintenant après le fix
        token_info = {
            "client_name": "CEY",
            "permissions": ["read", "write"],
            "allowed_resources": [],
            "auth_type": "token",
        }
        ctx_token = current_token_info.set(token_info)
        try:
            name = get_current_client_name()
            assert name == "CEY", f"Expected 'CEY', got '{name}'"
        finally:
            current_token_info.reset(ctx_token)

        # Après reset, on doit revenir à "anonymous"
        name_after = get_current_client_name()
        assert name_after == "anonymous", f"Expected 'anonymous' after reset, got '{name_after}'"

    def test_admin_api_bootstrap_token_contextvar(self):
        """
        Vérifie que le bootstrap token (admin) propage aussi le ContextVar.
        """
        from mcp_vault.auth.context import current_token_info, get_current_client_name

        token_info = {
            "client_name": "admin",
            "permissions": ["read", "write", "admin"],
            "allowed_resources": [],
            "auth_type": "bootstrap",
        }
        ctx_token = current_token_info.set(token_info)
        try:
            name = get_current_client_name()
            assert name == "admin", f"Expected 'admin', got '{name}'"
        finally:
            current_token_info.reset(ctx_token)

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
    Tests structurels — vérifie que le fix est bien présent dans le code source.
    Pas de dépendance runtime, juste de l'inspection AST/texte.
    """

    def test_api_imports_contextvar(self):
        """api.py doit importer current_token_info depuis auth.context."""
        import ast
        from pathlib import Path

        api_path = Path(__file__).parent.parent / "src" / "mcp_vault" / "admin" / "api.py"
        source = api_path.read_text()
        tree = ast.parse(source)

        # Chercher l'import de current_token_info
        found = False
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module and "context" in node.module:
                    names = [alias.name for alias in node.names]
                    if "current_token_info" in names:
                        found = True
                        break
        assert found, "api.py doit importer current_token_info depuis auth.context"

    def test_api_sets_contextvar_in_handler(self):
        """handle_admin_api doit appeler current_token_info.set()."""
        from pathlib import Path

        api_path = Path(__file__).parent.parent / "src" / "mcp_vault" / "admin" / "api.py"
        source = api_path.read_text()

        assert "current_token_info.set(" in source, \
            "handle_admin_api doit injecter le ContextVar via .set()"
        assert "current_token_info.reset(" in source, \
            "handle_admin_api doit reset le ContextVar dans un finally"

    def test_api_create_policy_uses_get_current_client_name(self):
        """_api_create_policy doit utiliser get_current_client_name() et non 'admin' hardcodé."""
        from pathlib import Path

        api_path = Path(__file__).parent.parent / "src" / "mcp_vault" / "admin" / "api.py"
        source = api_path.read_text()

        assert 'created_by="admin"' not in source, \
            "_api_create_policy ne doit plus avoir created_by='admin' hardcodé"
        assert "get_current_client_name()" in source, \
            "_api_create_policy doit appeler get_current_client_name()"
