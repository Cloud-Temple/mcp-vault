#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests — contournement de l'isolation owner-based par vault_id non canonique.

Découvert en revue adversariale (round 3, PR #97/issue #96), SANS RAPPORT
avec le code de cette PR : bug pré-existant dans le cœur du produit.

check_vault_owner() (vault/spaces.py) teste l'existence du mount OpenBao via
`f"{vault_id}/" not in mounts` puis AUTORISE si absent (cas "vault pas encore
créé"). Un vault_id non canonique (ex. slash final, "agentic-platform/")
construit une clé de recherche ("agentic-platform//") qui ne matche JAMAIS un
mount réel ("agentic-platform/") : le vault EXISTANT est alors traité comme
absent, et l'appelant — même non propriétaire, même sans allowed_resources —
se voit autorisé. Correctif : valider/canoniser resource_id dans
check_access() (auth/context.py), AVANT tout branchement liste/owner-based —
le seul point de passage commun à tous les outils vault-scoped.

Ces tests sont 100% locaux. `vault.spaces` dépend de hvac (absent hors
Docker) : injecté dans sys.modules AVANT tout import, comme
test_vault_create_access.py.
"""

import asyncio
import json
import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

os.environ.setdefault("MCP_SERVER_NAME", "mcp-vault-test")
os.environ.setdefault("ADMIN_BOOTSTRAP_KEY", "Test-Bootstrap-Key-2026-Pour-Tests!!")


def _run(coro):
    return asyncio.run(coro)


def _mock_vault_spaces_module(check_vault_owner_return=True):
    """Injecte un mcp_vault.vault.spaces mocké dans sys.modules (hvac absent hors Docker)."""
    mock = MagicMock()
    mock.check_vault_owner = MagicMock(return_value=check_vault_owner_return)
    return mock


def _owner_based_token(client_name="attacker"):
    return {
        "client_name": client_name,
        "auth_type": "token",
        "permissions": ["read", "write"],
        "allowed_resources": [],
    }


class TestOwnerBasedBypassViaNonCanonicalVaultId:
    """Reproduit puis ferme le contournement démontré en revue round 3."""

    def test_trailing_slash_vault_id_is_rejected_before_reaching_owner_check(self):
        """Le POC exact de la revue : vault_id="agentic-platform/" ne doit
        JAMAIS atteindre check_vault_owner() — reproduction indépendante,
        sans dépendre du mock retournant True ou False pour être significatif."""
        from mcp_vault.auth.context import check_access, current_token_info

        fake_spaces = _mock_vault_spaces_module(check_vault_owner_return=True)
        ctx = current_token_info.set(_owner_based_token())
        try:
            with patch.dict(sys.modules, {"mcp_vault.vault.spaces": fake_spaces}):
                result = check_access("agentic-platform/")
        finally:
            current_token_info.reset(ctx)

        assert result is not None
        assert result["status"] == "error"
        assert not fake_spaces.check_vault_owner.called

    def test_double_slash_and_other_non_canonical_ids_are_rejected(self):
        from mcp_vault.auth.context import check_access, current_token_info

        malformed = [
            "agentic-platform/", "agentic-platform//", "/agentic-platform",
            "../agentic-platform", "agentic-platform\n", "agentic platform",
            "", "a" * 65,
        ]
        for vault_id in malformed:
            fake_spaces = _mock_vault_spaces_module(check_vault_owner_return=True)
            ctx = current_token_info.set(_owner_based_token())
            try:
                with patch.dict(sys.modules, {"mcp_vault.vault.spaces": fake_spaces}):
                    result = check_access(vault_id)
            finally:
                current_token_info.reset(ctx)
            assert result is not None, f"'{vault_id}' aurait dû être refusé"
            assert result["status"] == "error"
            assert not fake_spaces.check_vault_owner.called, (
                f"'{vault_id}' a atteint check_vault_owner()"
            )

    def test_canonical_vault_id_still_reaches_owner_check_unchanged(self):
        """Non-régression : un vault_id bien formé continue de passer par
        check_vault_owner() — le comportement owner-based normal n'est pas
        cassé par la validation ajoutée."""
        from mcp_vault.auth.context import check_access, current_token_info

        fake_spaces = _mock_vault_spaces_module(check_vault_owner_return=True)
        ctx = current_token_info.set(_owner_based_token())
        try:
            with patch.dict(sys.modules, {"mcp_vault.vault.spaces": fake_spaces}):
                result = check_access("agentic-platform")
        finally:
            current_token_info.reset(ctx)

        assert result is None
        fake_spaces.check_vault_owner.assert_called_once_with("agentic-platform", "attacker")

    def test_canonical_vault_id_owner_check_can_still_deny(self):
        """Non-régression symétrique : un non-propriétaire reste refusé sur
        un vault_id bien formé (le check_vault_owner mocké répond False)."""
        from mcp_vault.auth.context import check_access, current_token_info

        fake_spaces = _mock_vault_spaces_module(check_vault_owner_return=False)
        ctx = current_token_info.set(_owner_based_token())
        try:
            with patch.dict(sys.modules, {"mcp_vault.vault.spaces": fake_spaces}):
                result = check_access("agentic-platform")
        finally:
            current_token_info.reset(ctx)

        assert result is not None
        assert result["status"] == "error"

    def test_non_canonical_vault_id_is_also_rejected_on_the_allow_list_path(self):
        """Défense en profondeur : le branchement allowed_resources non-vide
        est protégé aussi, pas seulement l'owner-based."""
        from mcp_vault.auth.context import check_access, current_token_info

        token_info = {
            "client_name": "agent",
            "auth_type": "token",
            "permissions": ["read", "write"],
            "allowed_resources": ["agentic-platform"],
        }
        ctx = current_token_info.set(token_info)
        try:
            result = check_access("agentic-platform/")
        finally:
            current_token_info.reset(ctx)

        assert result is not None
        assert result["status"] == "error"

    def test_admin_bypasses_validation_unaffected(self):
        """Non-régression : un bearer admin garde l'accès total, la nouvelle
        validation ne s'applique qu'après le court-circuit admin existant."""
        from mcp_vault.auth.context import check_access, current_token_info

        token_info = {
            "client_name": "admin", "auth_type": "bootstrap",
            "permissions": ["admin", "read", "write"], "allowed_resources": [],
        }
        ctx = current_token_info.set(token_info)
        try:
            result = check_access("agentic-platform/")
        finally:
            current_token_info.reset(ctx)

        assert result is None


class TestValidateVaultIdFullmatch:
    """_validate_vault_id() (création de vault) durci de `match` à `fullmatch` :
    `match` + `$` accepte aussi une position juste avant un `\\n` final."""

    def test_trailing_newline_is_now_rejected(self):
        from mcp_vault.vault.spaces import _validate_vault_id

        assert _validate_vault_id("agentic-platform\n") is not None

    def test_well_formed_vault_id_still_accepted(self):
        from mcp_vault.vault.spaces import _validate_vault_id

        assert _validate_vault_id("agentic-platform") is None
        assert _validate_vault_id("agentic-plateform") is None


class TestAdminApiCheckVaultAccessDuplicateWasAlsoVulnerable:
    """_check_vault_access() (admin/api.py) DUPLIQUE la logique de
    check_access() en Python natif — y compris l'appel direct à
    check_vault_owner() — SANS jamais bénéficier de la validation ajoutée
    dans check_access(). Découvert en continuant l'investigation après le
    premier correctif : la surface REST Admin (vault_info, secrets,
    vault_create — au moins 4 sites d'appel) restait exploitable par le même
    slash final tant que cette fonction n'était pas corrigée séparément."""

    def test_trailing_slash_vault_id_is_rejected_before_reaching_owner_check(self):
        from mcp_vault.admin.api import _check_vault_access

        fake_spaces = _mock_vault_spaces_module(check_vault_owner_return=True)
        token_info = _owner_based_token()
        with patch.dict(sys.modules, {"mcp_vault.vault.spaces": fake_spaces}):
            result = _check_vault_access(token_info, "agentic-platform/")

        assert result is not None
        assert result["status"] == "error"
        assert not fake_spaces.check_vault_owner.called

    def test_canonical_vault_id_still_reaches_owner_check_unchanged(self):
        from mcp_vault.admin.api import _check_vault_access

        fake_spaces = _mock_vault_spaces_module(check_vault_owner_return=True)
        token_info = _owner_based_token()
        with patch.dict(sys.modules, {"mcp_vault.vault.spaces": fake_spaces}):
            result = _check_vault_access(token_info, "agentic-platform")

        assert result is None
        fake_spaces.check_vault_owner.assert_called_once_with("agentic-platform", "attacker")

    def test_admin_bypasses_validation_unaffected(self):
        from mcp_vault.admin.api import _check_vault_access

        token_info = {"client_name": "admin", "permissions": ["admin", "read", "write"]}
        assert _check_vault_access(token_info, "agentic-platform/") is None

    def test_asgi_level_rest_bypass_is_closed(self):
        """Round 2 (revue Codex) : test permanent au niveau ROUTEUR ASGI, pas
        seulement du helper _check_vault_access() — reproduit exactement
        POST /admin/api/vaults/victim//ssh/sign avec un bearer owner-based
        non propriétaire (client_name="attacker"). Un futur changement du
        routeur qui casserait l'appel au garde serait détecté ici, pas
        seulement un changement du helper lui-même.

        check_vault_owner() est mocké à True (simule le comportement
        qu'aurait un OpenBao réel confondu par le vault_id non canonique,
        cf. round 1) : SANS ce mock, le stub hvac fail-close de
        tests/conftest.py masquerait la disparition du garde et ferait
        passer ce test à tort même si le correctif était retiré (piège
        identifié en sabotageant ce test manuellement avant de le committer)."""
        from mcp_vault.admin.api import handle_admin_api

        token_info = _owner_based_token(client_name="attacker")
        body = json.dumps({"public_key": "ssh-ed25519 AAAA", "role_name": "any-role"}).encode()
        messages = []

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message):
            messages.append(message)

        scope = {
            "type": "http", "method": "POST",
            "path": "/admin/api/vaults/victim//ssh/sign",
            "headers": [(b"authorization", b"Bearer attacker-token")],
            "query_string": b"",
        }
        fake_spaces = _mock_vault_spaces_module(check_vault_owner_return=True)
        signer = AsyncMock()
        with patch("mcp_vault.admin.api._get_token_info", return_value=token_info), \
             patch.dict(sys.modules, {"mcp_vault.vault.spaces": fake_spaces}), \
             patch("mcp_vault.vault.ssh_ca.sign_ssh_key", signer):
            _run(handle_admin_api(scope, receive, send, mcp=None))

        start = next(item for item in messages if item["type"] == "http.response.start")
        assert start["status"] == 403
        assert not signer.called
        assert not fake_spaces.check_vault_owner.called


class TestMissionBindingsThirdDuplicateAlsoConsolidated:
    """auth/mission_bindings.py avait une 3e copie du pattern, en `.match()`
    (accepte un `\\n` final) — découverte par la revue Codex sur le premier
    correctif. Consolidée dans vault_ids.is_valid_vault_id()."""

    def test_trailing_newline_in_allowed_resources_is_rejected(self):
        from mcp_vault.auth.mission_bindings import validate_allowed_resources

        result, message = validate_allowed_resources(["agentic-platform\n"])
        assert result is None
        assert "invalide" in message

    def test_well_formed_allowed_resources_still_accepted(self):
        from mcp_vault.auth.mission_bindings import validate_allowed_resources

        result, message = validate_allowed_resources(["agentic-platform", "another-vault"])
        assert result == ["agentic-platform", "another-vault"]
        assert message == ""


class TestWrappingPyFourthDuplicateAlsoConsolidated:
    """vault/wrapping.py (_validate_inputs, chemin critique secret_wrap/C18)
    avait une 4e copie divergente : plus stricte que la canonique (refusait
    les underscores et un tiret final). Pas un bypass actif (secret_wrap
    passe par check_access() en amont), mais une source de dérive
    fonctionnelle et sécurité réelle — découverte revue round 2."""

    def test_underscore_vault_id_now_accepted_like_the_canonical_rule(self):
        from mcp_vault.vault.wrapping import _validate_inputs

        err = _validate_inputs("tenant_1", "some/path", "mission-1", "op-1")
        assert err is None

    def test_trailing_newline_still_rejected(self):
        from mcp_vault.vault.wrapping import _validate_inputs

        err = _validate_inputs("tenant\n", "some/path", "mission-1", "op-1")
        assert err is not None


class TestVaultIdsLeafModuleHasNoInternalDependency(unittest.TestCase):
    """vault_ids.py doit rester un module feuille : aucun import interne à
    mcp_vault, pour rester safe à importer depuis n'importe quel module sans
    risque de cycle (raison d'être de la consolidation)."""

    def test_vault_ids_module_imports_nothing_from_mcp_vault(self):
        """Round 2 (revue Codex) : le premier test ne vérifiait ni les imports
        relatifs (ImportFrom.level > 0, ex. `from .auth import context` a
        `module="auth"` SANS point initial — le level porte l'information de
        relativité, pas le nom du module) ni `ast.Import` (`import
        mcp_vault.x`). Corrigé pour couvrir les deux."""
        import ast
        import inspect

        import mcp_vault.vault_ids as vault_ids_module

        source = inspect.getsource(vault_ids_module)
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                self.assertEqual(
                    node.level, 0,
                    f"vault_ids.py a un import relatif ({node.module!r}, level="
                    f"{node.level}) — casse son statut de module feuille",
                )
                if node.module:
                    self.assertFalse(
                        node.module == "mcp_vault" or node.module.startswith("mcp_vault."),
                        f"vault_ids.py importe {node.module} — casse son statut de module feuille",
                    )
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertFalse(
                        alias.name == "mcp_vault" or alias.name.startswith("mcp_vault."),
                        f"vault_ids.py importe {alias.name} — casse son statut de module feuille",
                    )
