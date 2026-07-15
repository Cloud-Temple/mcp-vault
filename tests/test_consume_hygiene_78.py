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


# =============================================================================
# Défense CENTRALE — l'audit neutralise les caractères de contrôle (tous champs)
# =============================================================================

def _has_control_char(s) -> bool:
    """True si s contient un C0/DEL/C1 ou un séparateur de ligne/paragraphe Unicode."""
    return any(
        ord(ch) < 0x20 or ord(ch) == 0x7f or 0x80 <= ord(ch) <= 0x9f
        or ord(ch) in (0x2028, 0x2029)
        for ch in s
    )


class TestAuditFieldSanitization:
    """Filet central : quel que soit l'appelant, aucun caractère de contrôle (C0, DEL,
    C1, séparateurs Unicode) ne survit dans une entrée d'audit — buffer ET fichier,
    à l'écriture ET au rechargement."""

    def test_control_chars_neutralized_all_fields(self, tmp_path):
        from mcp_vault.audit import AuditStore
        store = AuditStore(tmp_path / "audit.jsonl")
        store.log(tool_name="secret_wrap", status="error",
                  vault_id="prod\nFAKE 2026 admin ok",
                  detail="op=x\r\ninjected\x85nel sep",  # C0 + C1 (NEL) + U+2028
                  client_name="cli\x7fent")
        entry = store._buffer[-1]
        for field in ("vault_id", "detail", "client", "tool", "status"):
            assert not _has_control_char(entry[field]), \
                f"caractère de contrôle résiduel dans {field}: {entry[field]!r}"

    def test_file_entry_clean_after_json_reload(self, tmp_path):
        """Non-complaisant : recharger la ligne via json.loads et vérifier l'ABSENCE de
        contrôle dans chaque champ (json.dumps échappe \\n → un simple comptage de lignes
        physiques serait complaisant et resterait vert sans le correctif)."""
        import json as _json
        from mcp_vault.audit import AuditStore
        path = tmp_path / "audit.jsonl"
        store = AuditStore(path)
        store.log(tool_name="secret_wrap", status="ok",
                  vault_id="v\nADMIN GRANT", detail="d\r\nfake\x85nel")
        entry = _json.loads(path.read_text().splitlines()[0])
        for field in ("vault_id", "detail"):
            assert not _has_control_char(entry[field]), \
                f"contrôle dans le champ fichier {field}: {entry[field]!r}"

    def test_load_recent_re_sanitizes_historical_entries(self, tmp_path):
        """Une entrée historique (écrite avant le durcissement) est re-nettoyée au
        rechargement dans le buffer (load_recent), pas seulement à l'écriture."""
        import json as _json
        from mcp_vault.audit import AuditStore
        path = tmp_path / "audit.jsonl"
        path.write_text(_json.dumps({
            "ts": "2026-01-01T00:00:00+00:00", "client": "x", "tool": "t",
            "category": "c", "vault_id": "prod\nFORGED 2026 admin",
            "status": "ok", "detail": "d\x85nel", "duration_ms": 0,
        }) + "\n")
        store = AuditStore(path)
        store.load_recent()
        entry = store._buffer[-1]
        for field in ("vault_id", "detail"):
            assert not _has_control_char(entry[field]), \
                f"contrôle non nettoyé au rechargement dans {field}: {entry[field]!r}"

    def test_non_str_field_failclose(self, tmp_path):
        """Un champ non-str ne casse pas l'audit (fail-close via str())."""
        from mcp_vault.audit import AuditStore
        store = AuditStore(tmp_path / "audit.jsonl")
        store.log(tool_name="secret_wrap", status="ok", vault_id=None, detail=12345)
        entry = store._buffer[-1]
        assert isinstance(entry["vault_id"], str) and isinstance(entry["detail"], str)


# =============================================================================
# D6 (cœur) — _validate_inputs : fullmatch sur vault_id / secret_path, sans echo
# =============================================================================

class TestValidateInputsFullmatch:
    def test_vault_id_trailing_newline_rejected(self):
        from mcp_vault.vault.wrapping import _validate_inputs
        assert _validate_inputs("prod\n", "db/p", "m-1", "op-1") is not None

    def test_secret_path_trailing_newline_rejected(self):
        from mcp_vault.vault.wrapping import _validate_inputs
        assert _validate_inputs("prod", "db/p\n", "m-1", "op-1") is not None

    def test_valid_inputs_pass(self):
        """Non-complaisance : des entrées valides passent toujours (fullmatch ne sur-bloque pas)."""
        from mcp_vault.vault.wrapping import _validate_inputs
        assert _validate_inputs("prod", "db/pass", "m-1", "op-1") is None

    def test_secret_path_error_message_no_raw_echo(self):
        """Le message d'erreur ne reflète PAS la valeur brute (anti-reflection client + audit)."""
        from mcp_vault.vault.wrapping import _validate_inputs
        err = _validate_inputs("prod", "db/p\ninjected-token", "m-1", "op-1")
        assert err is not None and "injected-token" not in err and "\n" not in err


# =============================================================================
# D5 — reason JWKS fermé (le code HTTP externe ne fuit pas dans l'audit PEP)
# =============================================================================

class TestJwksReasonClosed:
    def test_jwks_http_error_reason_is_closed(self):
        """Un code HTTP non-200 du serveur JWKS → reason fermé `jwks_http_error`.

        Vecteur réel d'exposition : `force_reload()` (endpoint admin
        POST /admin/api/auth/jwks/reload) propage le reason TEL QUEL. (Le chemin
        `get_key` normal le remap déjà en `jwks_unavailable` générique.) Le reason ne
        doit jamais contenir la valeur externe (l'ancien `jwks_http_{status}`).
        """
        from mcp_vault.auth.mission_jwt import JWKSCache, JWKSUnavailable

        def http_500_fetch(url, etag, timeout):
            return 500, None, None  # (status, etag, body) — non-200, fail-close

        cache = JWKSCache("http://mock-jwks/x", ttl_seconds=60, fetch=http_500_fetch)
        with pytest.raises(JWKSUnavailable) as exc_info:
            cache.force_reload()
        assert exc_info.value.reason == "jwks_http_error", \
            f"code HTTP reflété dans le reason: {exc_info.value.reason!r}"
        assert "500" not in exc_info.value.reason


# =============================================================================
# Annexe — le refus PEP ne forge pas de lignes stderr via des claims CR/LF
# =============================================================================

class TestPepDenyStderrSanitized:
    """`_audit_pep_deny` journalise sur stderr : des claims forgés (CR/LF/NEL) ne
    doivent PAS y forger de lignes supplémentaires (le JSONL était déjà couvert par
    AuditStore ; ici c'est le print stderr)."""

    def test_forged_claims_do_not_forge_stderr_lines(self, capsys):
        from mcp_vault.auth.middleware import AuthMiddleware
        mw = AuthMiddleware(app=lambda *a, **k: None)
        claims_ctx = {"mission_id": "m\nFORGED-LINE", "tenant_id": "t\r\nEVIL-TENANT",
                      "jti": "j\x85nel", "issuer_decision_id": ""}
        mw._audit_pep_deny("some_reason", claims_ctx)
        err = capsys.readouterr().err
        deny_lines = [ln for ln in err.splitlines() if "PEP deny" in ln]
        assert len(deny_lines) == 1, \
            f"le refus PEP occupe {len(deny_lines)} lignes stderr: {err!r}"
        # Valeurs neutralisées (espaces) et maintenues sur la ligne deny, pas coupées.
        residual = err.replace(deny_lines[0], "")
        for forged in ("FORGED-LINE", "EVIL-TENANT"):
            assert forged not in residual, f"'{forged}' a forgé une ligne stderr séparée"
