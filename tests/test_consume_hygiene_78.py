# -*- coding: utf-8 -*-
"""
Tests Lot A #78 — Hygiène / anti-injection de secret_consume & voisins.

Périmètre (revue Codex, décisions D5/D6 + annexes) :
- D6 : validation stricte des identifiants par fullmatch (le `$` de _SAFE_ID_RE
  acceptait une fin de ligne `op\\n`), centralisée et appliquée AVANT tout audit,
  y compris dans secret_consume (qui ne validait pas operation_id du tout).
- D5 : les reason à valeur variable (unsupported_algorithm:{alg}, mission_status:{state})
  ne doivent jamais être reflétés vers le client ni dans un champ d'audit humain.
- Annexe : secret_revoke_wrap reflétait un préfixe de lease_id non validé.

Ces tests sont RED sur le code d'origine (662aa8e) et GREEN après le Lot A.

Tests mockés (pas de conteneur Docker). sys.path/stub hvac : tests/conftest.py.
"""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest


def run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# =============================================================================
# D6 — is_safe_id : fullmatch strict (ferme l'injection de fin de ligne)
# =============================================================================

class TestIsSafeId:
    """Le validateur centralisé doit rejeter tout ce qui n'est pas intégralement sûr."""

    def test_accepts_legit_ids(self):
        from mcp_vault.vault.wrapping import is_safe_id
        for good in ("op-valid-001", "mission_42", "a", "a" * 256,
                     "uuid:1a2b.3c", "hvs.CAESabcd"):
            assert is_safe_id(good) is True, f"{good!r} aurait dû être accepté"

    def test_rejects_trailing_newline(self):
        """CŒUR D6 : 'op\\n' passait avec .match ($ avant \\n final) — doit être rejeté."""
        from mcp_vault.vault.wrapping import is_safe_id
        assert is_safe_id("op-1\n") is False
        assert is_safe_id("op-1\r\n") is False
        assert is_safe_id("op-1\n\n") is False

    def test_rejects_injection_and_bounds(self):
        from mcp_vault.vault.wrapping import is_safe_id
        for bad in ("op with spaces", "op\ninjection", "a" * 257, "op#bad",
                    "", "op\ttab", "op/../evil"):
            assert is_safe_id(bad) is False, f"{bad!r} aurait dû être rejeté"

    def test_rejects_non_str(self):
        from mcp_vault.vault.wrapping import is_safe_id
        for bad in (None, 123, ["op"], b"op"):
            assert is_safe_id(bad) is False, f"{bad!r} (non-str) aurait dû être rejeté"


# =============================================================================
# D6 — secret_consume valide operation_id AVANT toute logique (et tout audit)
# =============================================================================

class TestConsumeValidatesOperationId:
    def _import_consume(self):
        try:
            from mcp_vault.server import secret_consume
            return secret_consume
        except Exception as e:  # pragma: no cover
            pytest.skip(f"server.py import échoue: {type(e).__name__}")

    def test_trailing_newline_operation_id_rejected_before_core(self):
        """operation_id 'op\\n' → rejeté SANS appeler consume_wrap_secret (anti-injection audit)."""
        secret_consume = self._import_consume()
        mock_core = AsyncMock(return_value={"status": "ok", "data": {}})
        with patch("mcp_vault.vault.wrapping.consume_wrap_secret", new=mock_core):
            r = run(secret_consume(wrap_token="wt", operation_id="op-1\n",
                                   mission_token="mtok"))
        assert r["status"] == "error", f"op\\n aurait dû être rejeté: {r}"
        assert r.get("error_type") == "invalid_input", r
        mock_core.assert_not_called()

    def test_various_invalid_operation_ids_rejected(self):
        secret_consume = self._import_consume()
        mock_core = AsyncMock(return_value={"status": "ok", "data": {}})
        with patch("mcp_vault.vault.wrapping.consume_wrap_secret", new=mock_core):
            for bad in ("op with spaces", "a" * 300, "op#bad", "op\ninjection"):
                mock_core.reset_mock()
                r = run(secret_consume(wrap_token="wt", operation_id=bad,
                                       mission_token="mtok"))
                assert r["status"] == "error" and r.get("error_type") == "invalid_input", \
                    f"{bad[:20]!r} aurait dû être rejeté: {r}"
                mock_core.assert_not_called()

    def test_valid_operation_id_reaches_core(self):
        """Non-complaisance : un operation_id valide NE doit PAS être bloqué par la garde."""
        secret_consume = self._import_consume()
        sentinel = {"status": "ok", "data": {"data": {"k": "v"}, "metadata": {}},
                    "operation_id": "op-ok", "mission_id": "", "vault_id": "v",
                    "secret_path": "p"}
        mock_core = AsyncMock(return_value=sentinel)
        with patch("mcp_vault.vault.wrapping.consume_wrap_secret", new=mock_core):
            r = run(secret_consume(wrap_token="wt", operation_id="op-ok",
                                   mission_token="mtok"))
        mock_core.assert_called_once()
        assert r["status"] == "ok", r


# =============================================================================
# D5 — secret_consume ne reflète pas le reason brut (valeur non vérifiée) au client
# =============================================================================

class TestConsumeDoesNotReflectReason:
    def _import_consume(self):
        try:
            from mcp_vault.server import secret_consume
            return secret_consume
        except Exception as e:  # pragma: no cover
            pytest.skip(f"server.py import échoue: {type(e).__name__}")

    def test_jwt_invalid_message_is_generic(self):
        """En enforce, un reason JWT porteur d'une valeur (alg) NE doit PAS finir dans le message client."""
        secret_consume = self._import_consume()

        class _Err(Exception):
            reason = "unsupported_algorithm:INJECT_ME"

        fake_validator = AsyncMock()
        fake_validator.validate = lambda tok: (_ for _ in ()).throw(_Err())

        from mcp_vault import server as srv
        with patch.object(srv.settings, "enforce_mission_token_validation", True), \
             patch.object(srv.settings, "mission_jwks_url", "https://jwks.example/keys"), \
             patch("mcp_vault.auth.jwt_validator.get_mission_token_validator",
                   return_value=fake_validator):
            r = run(secret_consume(wrap_token="wt", operation_id="op-ok",
                                   mission_token="mtok"))

        assert r["status"] == "error" and r.get("error_type") == "jwt_invalid", r
        assert "INJECT_ME" not in r.get("message", ""), \
            f"valeur non vérifiée reflétée au client: {r.get('message')!r}"


# =============================================================================
# Annexe D5 — secret_revoke_wrap valide lease_id avant de le refléter
# =============================================================================

class TestRevokeWrapValidatesLeaseId:
    def _import_revoke(self):
        try:
            from mcp_vault.server import secret_revoke_wrap
            return secret_revoke_wrap
        except Exception as e:  # pragma: no cover
            pytest.skip(f"server.py import échoue: {type(e).__name__}")

    def test_lease_id_with_newline_rejected(self):
        # Admin patché pour ISOLER la validation lease_id (sinon "Authentification
        # requise" masquerait le test → complaisance).
        secret_revoke = self._import_revoke()
        mock_core = AsyncMock(return_value={"status": "ok", "state": "not_found"})
        with patch("mcp_vault.auth.context.check_admin_permission", return_value=None), \
             patch("mcp_vault.vault.wrapping.revoke_wrap", new=mock_core):
            r = run(secret_revoke(lease_id="ACC-1\ninjected"))
        assert r["status"] == "error" and r.get("error_type") == "invalid_input", r
        mock_core.assert_not_called()

    def test_realistic_accessor_accepted(self):
        """Non-complaisance : un accessor OpenBao réaliste doit passer la validation."""
        secret_revoke = self._import_revoke()
        mock_core = AsyncMock(return_value={"status": "ok", "state": "not_found"})
        with patch("mcp_vault.auth.context.check_admin_permission", return_value=None), \
             patch("mcp_vault.vault.wrapping.revoke_wrap", new=mock_core):
            r = run(secret_revoke(lease_id="hvs.CAESIFooBar-1234.5678"))
        assert r["status"] == "ok", f"accessor réaliste rejeté à tort: {r}"
        mock_core.assert_called_once()
