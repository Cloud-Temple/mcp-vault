#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests PKI Certificate Authority — comportementaux, sans dépendances réseau.

Vérifie :
  - Protection vault_delete contre les mounts _sys_pki_*  (T9)
  - Proxy ACME non-authentifié dans PkiMiddleware
  - Proxy /pki/ca/*.pem dans PkiMiddleware
  - Appels upload_to_s3 après mutations critiques (setup, revoke, rotate)
  - Fonctions utilitaires (is_reserved_mount, _sha256_fingerprint, _cert_expiry_iso)

Usage :
    PYTHONPATH=src python -m pytest tests/test_pki.py -v
"""

import asyncio
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

os.environ.setdefault("MCP_SERVER_NAME", "mcp-vault-test")
os.environ.setdefault("ADMIN_BOOTSTRAP_KEY", "Test-Bootstrap-Key-2026-Pour-Tests!!")

# hvac (dep Docker-only) est stubbé de façon DÉTERMINISTE et centralisée dans
# tests/conftest.py (issue #64). Auparavant, l'injection sys.modules se faisait ICI au
# niveau module : elle fuyait vers toute la session et rendait d'autres tests dépendants
# de l'ordre de collecte (test_06_permissions vert/rouge selon que test_pki passait avant).


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _run(coro):
    """Run coroutine de façon défensive (issue #36).

    Les suites CLI (CliRunner + asyncio.run) peuvent fermer la boucle globale.
    On recrée une boucle si la courante est fermée ou absente, sans la fermer
    nous-mêmes — sinon on casse les tests suivants. Pattern identique à
    test_jwt_validator._run.
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


# ─────────────────────────────────────────────────────────────────────────────
# Tests utilitaires (synchrones, pas de réseau)
# ─────────────────────────────────────────────────────────────────────────────

class TestIsReservedMount:
    """is_reserved_mount() doit identifier les mounts PKI protégés."""

    def test_reserved_root(self):
        from mcp_vault.vault.pki_ca import is_reserved_mount
        assert is_reserved_mount("_sys_pki_root") is True

    def test_reserved_int(self):
        from mcp_vault.vault.pki_ca import is_reserved_mount
        assert is_reserved_mount("_sys_pki_int") is True

    def test_not_reserved_normal_vault(self):
        from mcp_vault.vault.pki_ca import is_reserved_mount
        assert is_reserved_mount("my-vault") is False

    def test_not_reserved_empty(self):
        from mcp_vault.vault.pki_ca import is_reserved_mount
        assert is_reserved_mount("") is False

    def test_not_reserved_similar_prefix(self):
        from mcp_vault.vault.pki_ca import is_reserved_mount
        assert is_reserved_mount("sys_pki_root") is False  # sans underscore initial
        assert is_reserved_mount("pki_root") is False


# ─────────────────────────────────────────────────────────────────────────────
# Tests T9 — Protection vault_delete (défense en profondeur)
# ─────────────────────────────────────────────────────────────────────────────

class TestVaultDeleteProtection:
    """
    T9 : vault_delete sur un mount _sys_pki_* doit être refusé.

    Deux couches :
      - spaces.py:delete_space() retourne {status: error, error: reserved_mount}
      - server.py:vault_delete (tool MCP) retourne idem avant d'appeler delete_space
    """

    def test_delete_space_refuses_pki_root(self):
        """spaces.delete_space('_sys_pki_root') → error reserved_mount."""
        result = _run(_delete_space_call("_sys_pki_root"))
        assert result["status"] == "error"
        assert result.get("error") == "reserved_mount"

    def test_delete_space_refuses_pki_int(self):
        """spaces.delete_space('_sys_pki_int') → error reserved_mount."""
        result = _run(_delete_space_call("_sys_pki_int"))
        assert result["status"] == "error"
        assert result.get("error") == "reserved_mount"

    def test_delete_space_allows_normal_vault(self):
        """spaces.delete_space('my-vault') n'est PAS bloqué par le guard PKI."""
        mock_client = MagicMock()
        mock_client.sys.disable_secrets_engine = MagicMock()

        with patch("mcp_vault.vault.spaces.get_hvac_client", return_value=mock_client), \
             patch("mcp_vault.vault.ssh_ca.cleanup_ssh_ca", new_callable=AsyncMock, return_value=True):
            result = _run(_delete_space_call("my-vault"))

        # Le guard PKI ne bloque pas → on arrive à disable_secrets_engine
        assert result.get("error") != "reserved_mount"


def _delete_space_call(vault_id: str):
    from mcp_vault.vault.spaces import delete_space
    return delete_space(vault_id)


# ─────────────────────────────────────────────────────────────────────────────
# Tests PkiMiddleware — proxy ACME non-authentifié
# ─────────────────────────────────────────────────────────────────────────────

class TestPkiMiddleware:
    """Vérifie que PkiMiddleware proxy /acme/* et /pki/ca/* vers OpenBao."""

    def _make_scope(self, path: str, method: str = "GET") -> dict:
        return {
            "type": "http",
            "method": method,
            "path": path,
            "headers": [],
            "query_string": b"",
        }

    def _make_receive(self, body: bytes = b"") -> callable:
        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}
        return receive

    def _make_send(self) -> tuple:
        events = []

        async def send(event):
            events.append(event)

        return send, events

    def _fake_httpx_response(self, status=200, content=b"pem-data",
                              headers=None):
        mock_resp = MagicMock()
        mock_resp.status_code = status
        mock_resp.content = content
        mock_resp.headers = headers or {"content-type": "application/pem-certificate-chain"}
        return mock_resp

    def test_acme_directory_proxied_without_auth(self):
        """GET /acme/directory → proxy vers OpenBao, aucun header Bearer requis."""
        from mcp_vault.pki_middleware import PkiMiddleware

        inner_called = []

        async def inner_app(scope, receive, send):
            inner_called.append(True)

        middleware = PkiMiddleware(inner_app)
        scope = self._make_scope("/acme/directory")
        send_fn, events = self._make_send()

        fake_resp = self._fake_httpx_response(
            200, b'{"newNonce":"https://..."}',
            headers={"content-type": "application/json", "replay-nonce": "abc123"}
        )

        with patch("mcp_vault.pki_middleware.httpx.AsyncClient") as mock_cls:
            mock_instance = AsyncMock()
            mock_instance.request = AsyncMock(return_value=fake_resp)
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)

            _run(middleware(scope, self._make_receive(), send_fn))

        assert not inner_called, "Le middleware interne NE doit PAS être appelé pour /acme/*"
        start_event = next(e for e in events if e["type"] == "http.response.start")
        assert start_event["status"] == 200

    def test_pki_root_pem_proxied(self):
        """GET /pki/ca/root.pem → proxy vers _sys_pki_root/ca/pem."""
        from mcp_vault.pki_middleware import PkiMiddleware

        middleware = PkiMiddleware(MagicMock())
        scope = self._make_scope("/pki/ca/root.pem")
        send_fn, events = self._make_send()

        pem_content = b"-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----"
        fake_resp = self._fake_httpx_response(200, pem_content)

        with patch("mcp_vault.pki_middleware.httpx.AsyncClient") as mock_cls:
            mock_instance = AsyncMock()
            mock_instance.request = AsyncMock(return_value=fake_resp)
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)

            _run(middleware(scope, self._make_receive(), send_fn))

        start_event = next(e for e in events if e["type"] == "http.response.start")
        body_event = next(e for e in events if e["type"] == "http.response.body")
        assert start_event["status"] == 200
        assert body_event["body"] == pem_content

    def test_pki_unknown_path_passes_through(self):
        """GET /api/health ne doit PAS être intercepté par PkiMiddleware."""
        from mcp_vault.pki_middleware import PkiMiddleware

        inner_called = []

        async def inner_app(scope, receive, send):
            inner_called.append(True)
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        middleware = PkiMiddleware(inner_app)
        scope = self._make_scope("/api/health")
        send_fn, _ = self._make_send()

        _run(middleware(scope, self._make_receive(), send_fn))

        assert inner_called, "Les routes non-PKI doivent passer au middleware suivant"

    def test_acme_path_traversal_rejected(self):
        """GET /acme/../../admin → rejeté 400 (CRITIQUE anti-traversal)."""
        from mcp_vault.pki_middleware import PkiMiddleware

        middleware = PkiMiddleware(MagicMock())
        scope = self._make_scope("/acme/../../admin/creds")
        send_fn, events = self._make_send()

        _run(middleware(scope, self._make_receive(), send_fn))

        start_event = next(e for e in events if e["type"] == "http.response.start")
        assert start_event["status"] == 400

    def test_acme_double_slash_rejected(self):
        """GET /acme//bypass → rejeté 400."""
        from mcp_vault.pki_middleware import PkiMiddleware

        middleware = PkiMiddleware(MagicMock())
        scope = self._make_scope("/acme//bypass")
        send_fn, events = self._make_send()

        _run(middleware(scope, self._make_receive(), send_fn))

        start_event = next(e for e in events if e["type"] == "http.response.start")
        assert start_event["status"] == 400

    def test_acme_proxy_returns_502_on_openbao_down(self):
        """Si OpenBao est injoignable, le middleware retourne 502."""
        from mcp_vault.pki_middleware import PkiMiddleware

        middleware = PkiMiddleware(MagicMock())
        scope = self._make_scope("/acme/directory")
        send_fn, events = self._make_send()

        with patch("mcp_vault.pki_middleware.httpx.AsyncClient") as mock_cls:
            mock_instance = AsyncMock()
            mock_instance.request = AsyncMock(side_effect=Exception("Connection refused"))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)

            _run(middleware(scope, self._make_receive(), send_fn))

        start_event = next(e for e in events if e["type"] == "http.response.start")
        assert start_event["status"] == 502

    def test_websocket_passes_through(self):
        """Les connexions non-HTTP (WebSocket) passent sans modification."""
        from mcp_vault.pki_middleware import PkiMiddleware

        inner_called = []

        async def inner_app(scope, receive, send):
            inner_called.append(True)

        middleware = PkiMiddleware(inner_app)
        scope = {"type": "websocket", "path": "/acme/directory"}

        _run(middleware(scope, self._make_receive(), MagicMock()))

        assert inner_called


# ─────────────────────────────────────────────────────────────────────────────
# Tests upload_to_s3 forcée après mutations critiques
# ─────────────────────────────────────────────────────────────────────────────

class TestS3SyncAfterMutations:
    """
    T10 partiel : upload_to_s3 doit être appelé après setup, revoke, rotate.
    Vérifie que la durabilité S3 est garantie même en cas de crash post-mutation.
    """

    def _mock_hvac(self):
        """Crée un mock hvac minimal pour les tests PKI."""
        client = MagicMock()
        client.sys.enable_secrets_engine = MagicMock()
        client.sys.list_mounted_secrets_engines = MagicMock(return_value={
            "data": {"_sys_pki_root/": {}, "_sys_pki_int/": {}}
        })
        # certificate vide → _cert_expiry_iso / _sha256_fingerprint ne sont pas appelés
        client.write = MagicMock(return_value={
            "data": {
                "certificate": "",
                "csr": "-----BEGIN CERTIFICATE REQUEST-----\nMOCK\n-----END CERTIFICATE REQUEST-----",
                "imported_issuers": ["issuer-uuid-new"],
                "default": "issuer-uuid-old",
            }
        })
        client.read = MagicMock(return_value={
            "data": {"default": "issuer-uuid-old"}
        })
        client.list = MagicMock(return_value={"data": {"keys": []}})
        client.delete = MagicMock()
        return client

    def test_setup_calls_upload_to_s3(self):
        """setup_pki_ca() doit appeler upload_to_s3() avant de retourner."""
        from mcp_vault.vault.pki_ca import setup_pki_ca

        mock_client = self._mock_hvac()

        with patch("mcp_vault.vault.pki_ca._get_hvac_client", return_value=mock_client), \
             patch("mcp_vault.s3_sync.upload_to_s3", new_callable=AsyncMock) as mock_s3, \
             patch("mcp_vault.vault.pki_ca._read_pem_url", new_callable=AsyncMock, return_value=_MOCK_CERT_PEM):

            result = _run(setup_pki_ca(lab_mode=True, allowed_domains=["test.lan"]))

        assert result["status"] == "ok", f"Inattendu : {result}"
        mock_s3.assert_called_once()

    def test_revoke_calls_upload_to_s3(self):
        """revoke_cert() doit appeler upload_to_s3() après révocation."""
        from mcp_vault.vault.pki_ca import revoke_cert

        mock_client = self._mock_hvac()

        with patch("mcp_vault.vault.pki_ca._get_hvac_client", return_value=mock_client), \
             patch("mcp_vault.s3_sync.upload_to_s3", new_callable=AsyncMock) as mock_s3, \
             patch("mcp_vault.vault.pki_ca.is_pki_initialized", return_value=True):

            result = _run(revoke_cert("12:34:ab:cd"))

        assert result["status"] == "ok"
        mock_s3.assert_called_once()

    def test_rotate_calls_upload_to_s3(self):
        """rotate_intermediate() doit appeler upload_to_s3() après rotation."""
        from mcp_vault.vault.pki_ca import rotate_intermediate

        mock_client = self._mock_hvac()

        with patch("mcp_vault.vault.pki_ca._get_hvac_client", return_value=mock_client), \
             patch("mcp_vault.s3_sync.upload_to_s3", new_callable=AsyncMock) as mock_s3, \
             patch("mcp_vault.vault.pki_ca.is_pki_initialized", return_value=True), \
             patch("mcp_vault.vault.pki_ca._read_pem_url", new_callable=AsyncMock, return_value=_MOCK_CERT_PEM):

            result = _run(rotate_intermediate(keep_old_issuer=True))

        assert result["status"] == "ok"
        mock_s3.assert_called_once()

    def test_setup_fails_if_openbao_disconnected(self):
        """setup_pki_ca() retourne error si OpenBao non connecté."""
        from mcp_vault.vault.pki_ca import setup_pki_ca

        with patch("mcp_vault.vault.pki_ca._get_hvac_client", return_value=None):
            result = _run(setup_pki_ca(lab_mode=True, allowed_domains=["test.lan"]))

        assert result["status"] == "error"
        assert "non connecté" in result["message"]

    def test_revoke_requires_serial_number(self):
        """revoke_cert() sans serial_number retourne error immédiatement."""
        from mcp_vault.vault.pki_ca import revoke_cert
        result = _run(revoke_cert(""))
        assert result["status"] == "error"

    def test_revoke_rejects_invalid_serial_format(self):
        """revoke_cert() avec serial_number invalide (injection possible) retourne error."""
        from mcp_vault.vault.pki_ca import revoke_cert
        for bad_serial in ["../../admin", "12:34:ab:cd; evil", "GGGG", "12345"]:
            result = _run(revoke_cert(bad_serial))
            assert result["status"] == "error", f"Attendu error pour {bad_serial!r}"

    def test_revoke_accepts_valid_serial(self):
        """revoke_cert() avec serial valide (hex:hex:...) passe la validation."""
        from mcp_vault.vault.pki_ca import revoke_cert

        mock_client = MagicMock()
        mock_client.write = MagicMock(return_value={"data": {"revocation_time": 1234567890}})

        with patch("mcp_vault.vault.pki_ca._get_hvac_client", return_value=mock_client), \
             patch("mcp_vault.s3_sync.upload_to_s3", new_callable=AsyncMock, return_value=True), \
             patch("mcp_vault.vault.pki_ca.is_pki_initialized", return_value=True):
            result = _run(revoke_cert("12:34:ab:cd:ef:12"))

        assert result["status"] == "ok"


# ─────────────────────────────────────────────────────────────────────────────
# Tests inventaire vide — hvac list() retourne None (issue #38)
# ─────────────────────────────────────────────────────────────────────────────

class TestEmptyInventoryNoneSafe:
    """
    Issue #38 : client.list() retourne None sur un chemin vide (PKI/SSH vierge,
    état nominal). Les fonctions de listing doivent retourner ok/total=0, pas
    une AttributeError affichée comme erreur.
    """

    def test_safe_list_keys_helper(self):
        """_hvac_utils.safe_list_keys gère None, dict vide, et structure valide."""
        from mcp_vault.vault._hvac_utils import safe_list_keys
        assert safe_list_keys(None) == []
        assert safe_list_keys({}) == []
        assert safe_list_keys({"data": None}) == []
        assert safe_list_keys({"data": {}}) == []
        assert safe_list_keys({"data": {"keys": None}}) == []
        assert safe_list_keys({"data": {"keys": ["a", "b"]}}) == ["a", "b"]

    def test_list_certs_empty_pki_returns_ok(self):
        """
        list_issued_certs sur PKI vierge (client.list → None) → ok/total=0,
        PAS d'AttributeError. C'est le bug prod #38.
        """
        from mcp_vault.vault.pki_ca import list_issued_certs

        client = MagicMock()
        client.list = MagicMock(return_value=None)  # PKI vierge
        with patch("mcp_vault.vault.pki_ca._get_hvac_client", return_value=client), \
             patch("mcp_vault.vault.pki_ca.is_pki_initialized", return_value=True):
            result = _run(list_issued_certs())

        assert result["status"] == "ok", f"PKI vierge doit être ok : {result}"
        assert result.get("total") == 0
        assert result.get("certs") == []

    def test_list_roles_empty_pki_returns_ok(self):
        """list_pki_roles sur PKI sans rôle (client.list → None) → ok/count=0."""
        from mcp_vault.vault.pki_ca import list_pki_roles

        client = MagicMock()
        client.list = MagicMock(return_value=None)
        with patch("mcp_vault.vault.pki_ca._get_hvac_client", return_value=client), \
             patch("mcp_vault.vault.pki_ca.is_pki_initialized", return_value=True):
            result = _run(list_pki_roles())

        assert result["status"] == "ok", f"Doit être ok : {result}"
        assert result.get("count") == 0
        assert result.get("roles") == []

    def test_list_ssh_roles_empty_returns_ok(self):
        """list_ssh_roles sur vault SSH vierge (client.list → None) → ok/count=0."""
        from mcp_vault.vault import ssh_ca

        client = MagicMock()
        client.list = MagicMock(return_value=None)
        with patch("mcp_vault.vault.ssh_ca.get_hvac_client", return_value=client):
            result = _run(ssh_ca.list_ssh_roles("mon-vault"))

        assert result["status"] == "ok", f"Vault SSH vierge doit être ok : {result}"
        assert result.get("count") == 0
        assert result.get("roles") == []


# ─────────────────────────────────────────────────────────────────────────────
# Tests émission manuelle de certificat (issue #41)
# ─────────────────────────────────────────────────────────────────────────────

class TestIssueCertificate:
    """
    pki_issue_cert : validation locale (CN/SAN vs allowed_domains, IP, TTL,
    wildcard refusé) + émission + clé privée jamais loggée/auditée.
    """

    def _client_with_role(self, allowed_domains=None):
        """Client mock : rôle ACME avec allowed_domains, émission renvoie cert+clé."""
        allowed_domains = allowed_domains if allowed_domains is not None else ["*.cloud-temple.app", "cloud-temple.app"]
        client = MagicMock()
        client.read = MagicMock(return_value={
            "data": {"allowed_domains": allowed_domains, "max_ttl": "8760h"}
        })
        client.write = MagicMock(return_value={
            "data": {
                "serial_number": "12:34:ab:cd",
                "certificate": "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----",
                "private_key": "-----BEGIN PRIVATE KEY-----\nSENSITIVE\n-----END PRIVATE KEY-----",
                "ca_chain": ["-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----"],
                "expiration": 1800000000,
            }
        })
        return client

    def test_acme_role_accepts_ec_and_bare_domains(self):
        """
        Le rôle ACME doit accepter les clés EC (Caddy génère EC par défaut) et
        les domaines exacts (bare) — sinon l'enrollment ACME réel échoue
        (badCSR 'requires rsa' / rejectedIdentifier). Régression E2E #41.
        """
        from mcp_vault.vault.pki_ca import setup_pki_ca, _ACME_ROLE_NAME
        mock_client = MagicMock()
        mock_client.write = MagicMock(return_value={"data": {
            "certificate": "", "csr": "-----BEGIN CERTIFICATE REQUEST-----\nM\n-----END CERTIFICATE REQUEST-----",
            "imported_issuers": ["i"], "default": "i",
        }})
        with patch("mcp_vault.vault.pki_ca._get_hvac_client", return_value=mock_client), \
             patch("mcp_vault.s3_sync.upload_to_s3", new_callable=AsyncMock, return_value=True), \
             patch("mcp_vault.vault.pki_ca._read_pem_url", new_callable=AsyncMock, return_value=_MOCK_CERT_PEM):
            _run(setup_pki_ca(lab_mode=True, allowed_domains=["test.lan"]))

        role_calls = [c for c in mock_client.write.call_args_list
                      if c.args and str(c.args[0]).endswith(f"roles/{_ACME_ROLE_NAME}")]
        assert role_calls, "Rôle ACME non configuré"
        kw = role_calls[-1].kwargs
        assert kw.get("key_type") == "any", f"key_type doit être 'any' (clés EC) : {kw.get('key_type')}"
        assert kw.get("allow_bare_domains") is True, "allow_bare_domains doit être True"
        assert kw.get("allow_glob_domains") is True, "allow_glob_domains doit être True"

    def test_issue_ok_nominal(self):
        """CN dans le domaine autorisé → émission ok + clé privée retournée."""
        from mcp_vault.vault.pki_ca import issue_certificate
        client = self._client_with_role()
        with patch("mcp_vault.vault.pki_ca._get_hvac_client", return_value=client), \
             patch("mcp_vault.vault.pki_ca.is_pki_initialized", return_value=True), \
             patch("mcp_vault.s3_sync.upload_to_s3", new_callable=AsyncMock, return_value=True):
            r = _run(issue_certificate("www.cloud-temple.app", ttl="720h"))
        assert r["status"] == "ok", f"{r}"
        assert r["private_key"].startswith("-----BEGIN PRIVATE KEY")
        assert r["serial_number"] == "12:34:ab:cd"
        # émission via le rôle manual-servers (pas acme-servers)
        issue_calls = [c for c in client.write.call_args_list if "issue/manual-servers" in str(c.args[0])]
        assert issue_calls, "Émission doit passer par le rôle manual-servers"

    def test_issue_domain_not_allowed(self):
        """CN hors domaines autorisés → rejet AVANT émission (validation locale)."""
        from mcp_vault.vault.pki_ca import issue_certificate
        client = self._client_with_role(allowed_domains=["cloud-temple.app"])
        with patch("mcp_vault.vault.pki_ca._get_hvac_client", return_value=client), \
             patch("mcp_vault.vault.pki_ca.is_pki_initialized", return_value=True):
            r = _run(issue_certificate("evil.attacker.com"))
        assert r["status"] == "error"
        assert r["error_type"] == "domain_not_allowed"
        # OpenBao /issue ne doit PAS avoir été appelé
        assert not any("issue/manual-servers" in str(c.args[0]) for c in client.write.call_args_list)

    def test_issue_wildcard_refused(self):
        """Wildcard interdit en émission manuelle."""
        from mcp_vault.vault.pki_ca import issue_certificate
        client = self._client_with_role()
        with patch("mcp_vault.vault.pki_ca._get_hvac_client", return_value=client), \
             patch("mcp_vault.vault.pki_ca.is_pki_initialized", return_value=True):
            r = _run(issue_certificate("*.cloud-temple.app"))
        assert r["status"] == "error" and r["error_type"] == "invalid_input"

    def test_issue_bad_ttl(self):
        """TTL au mauvais format → rejet."""
        from mcp_vault.vault.pki_ca import issue_certificate
        client = self._client_with_role()
        with patch("mcp_vault.vault.pki_ca._get_hvac_client", return_value=client), \
             patch("mcp_vault.vault.pki_ca.is_pki_initialized", return_value=True):
            r = _run(issue_certificate("www.cloud-temple.app", ttl="forever"))
        assert r["status"] == "error" and r["error_type"] == "invalid_input"

    def test_issue_ttl_exceeds_max(self):
        """TTL > max_ttl du rôle → rejet local (pas délégué à OpenBao)."""
        from mcp_vault.vault.pki_ca import issue_certificate
        client = self._client_with_role()  # max_ttl 8760h
        with patch("mcp_vault.vault.pki_ca._get_hvac_client", return_value=client), \
             patch("mcp_vault.vault.pki_ca.is_pki_initialized", return_value=True):
            r = _run(issue_certificate("www.cloud-temple.app", ttl="99999h"))
        assert r["status"] == "error" and r["error_type"] == "invalid_input"
        assert not any("issue/manual-servers" in str(c.args[0]) for c in client.write.call_args_list)

    def test_issue_allowed_domains_as_csv_string(self):
        """allowed_domains renvoyé en CSV par OpenBao → normalisé en liste (pas d'itération char)."""
        from mcp_vault.vault.pki_ca import issue_certificate
        client = MagicMock()
        client.read = MagicMock(return_value={"data": {"allowed_domains": "cloud-temple.app", "max_ttl": "8760h"}})
        client.write = MagicMock(return_value={"data": {
            "serial_number": "aa:bb", "certificate": "C", "private_key": "K", "ca_chain": "CH", "expiration": 1,
        }})
        with patch("mcp_vault.vault.pki_ca._get_hvac_client", return_value=client), \
             patch("mcp_vault.vault.pki_ca.is_pki_initialized", return_value=True), \
             patch("mcp_vault.s3_sync.upload_to_s3", new_callable=AsyncMock, return_value=True):
            ok = _run(issue_certificate("api.cloud-temple.app"))
            ko = _run(issue_certificate("evil.com"))
        assert ok["status"] == "ok", f"sous-domaine valide doit passer: {ok}"
        assert ko["status"] == "error" and ko["error_type"] == "domain_not_allowed"

    def test_issue_bad_ip_san(self):
        """IP SAN invalide → rejet AVANT émission."""
        from mcp_vault.vault.pki_ca import issue_certificate
        client = self._client_with_role()
        with patch("mcp_vault.vault.pki_ca._get_hvac_client", return_value=client), \
             patch("mcp_vault.vault.pki_ca.is_pki_initialized", return_value=True):
            r = _run(issue_certificate("www.cloud-temple.app", ip_sans="999.999.0.1"))
        assert r["status"] == "error" and r["error_type"] == "invalid_input"

    def test_issue_alt_name_validated(self):
        """Un alt_name hors domaine → rejet (pas seulement le CN)."""
        from mcp_vault.vault.pki_ca import issue_certificate
        client = self._client_with_role()
        with patch("mcp_vault.vault.pki_ca._get_hvac_client", return_value=client), \
             patch("mcp_vault.vault.pki_ca.is_pki_initialized", return_value=True):
            r = _run(issue_certificate("www.cloud-temple.app", alt_names="evil.com"))
        assert r["status"] == "error" and r["error_type"] == "domain_not_allowed"

    def test_issue_private_key_not_in_audit(self):
        """server.pki_issue_cert : la clé privée ne doit jamais entrer dans l'audit."""
        audited = []

        def mock_r(tool, result, vault_id="", detail=""):
            audited.append(result)
            return result

        from unittest.mock import AsyncMock as _AM
        mock_issue = _AM(return_value={
            "status": "ok", "common_name": "www.cloud-temple.app",
            "serial_number": "aa:bb", "certificate": "CERTPEM",
            "private_key": "SUPERSECRETKEY", "ca_chain": "CHAIN", "expiration": 1,
        })
        with patch("mcp_vault.server._r", side_effect=mock_r), \
             patch("mcp_vault.auth.context.check_admin_permission", return_value=None), \
             patch("mcp_vault.auth.context.check_policy", return_value=None), \
             patch("mcp_vault.vault.pki_ca.issue_certificate", new=mock_issue):
            from mcp_vault.server import pki_issue_cert
            r = _run(pki_issue_cert("www.cloud-temple.app"))
        # le retour à l'appelant contient la clé (one-shot)
        assert r["private_key"] == "SUPERSECRETKEY"
        # mais l'audit ne doit JAMAIS la contenir
        for a in audited:
            assert "SUPERSECRETKEY" not in str(a), "Clé privée divulguée dans l'audit !"
            assert "CERTPEM" not in str(a), "Certificat complet dans l'audit (inutile)"


# ─────────────────────────────────────────────────────────────────────────────
# Tests EAB policy — bug bloquant prod (issue #32)
# ─────────────────────────────────────────────────────────────────────────────

class TestEabPolicyProd:
    """
    Issue #32 : eab_policy="required" était invalide pour OpenBao (mode Prod KO).
    Tests non-complaisant : inspectent le payload RÉEL envoyé à config/acme,
    pas seulement le dict de retour.
    """

    def _mock_hvac(self):
        client = MagicMock()
        client.sys.enable_secrets_engine = MagicMock()
        client.sys.tune_mount_configuration = MagicMock()
        client.write = MagicMock(return_value={
            "data": {
                "certificate": "",
                "csr": "-----BEGIN CERTIFICATE REQUEST-----\nMOCK\n-----END CERTIFICATE REQUEST-----",
            }
        })
        client.read = MagicMock(return_value={"data": {}})
        return client

    def _acme_write_kwargs(self, mock_client):
        """Retourne les kwargs du write vers config/acme (ou None)."""
        for call in mock_client.write.call_args_list:
            args, kwargs = call
            if args and str(args[0]).endswith("config/acme"):
                return kwargs
        return None

    def test_prod_mode_sends_valid_eab_policy(self):
        """
        BLOQUANT — en lab_mode=False, config/acme reçoit "new-account-required"
        et JAMAIS "required" (valeur rejetée par OpenBao).
        """
        from mcp_vault.vault.pki_ca import setup_pki_ca

        mock_client = self._mock_hvac()
        with patch("mcp_vault.vault.pki_ca._get_hvac_client", return_value=mock_client), \
             patch("mcp_vault.s3_sync.upload_to_s3", new_callable=AsyncMock, return_value=True), \
             patch("mcp_vault.vault.pki_ca._read_pem_url", new_callable=AsyncMock, return_value=_MOCK_CERT_PEM):
            result = _run(setup_pki_ca(lab_mode=False, allowed_domains=["prod.example.com"]))

        assert result["status"] == "ok", f"Setup prod KO : {result}"
        acme_kwargs = self._acme_write_kwargs(mock_client)
        assert acme_kwargs is not None, "Aucun write vers config/acme"
        assert acme_kwargs["eab_policy"] == "new-account-required", (
            f"eab_policy invalide : {acme_kwargs['eab_policy']!r}"
        )
        assert acme_kwargs["eab_policy"] != "required", "Régression : 'required' rejeté par OpenBao !"

    def test_lab_mode_sends_not_required(self):
        """lab_mode=True → config/acme reçoit 'not-required'."""
        from mcp_vault.vault.pki_ca import setup_pki_ca

        mock_client = self._mock_hvac()
        with patch("mcp_vault.vault.pki_ca._get_hvac_client", return_value=mock_client), \
             patch("mcp_vault.s3_sync.upload_to_s3", new_callable=AsyncMock, return_value=True), \
             patch("mcp_vault.vault.pki_ca._read_pem_url", new_callable=AsyncMock, return_value=_MOCK_CERT_PEM):
            result = _run(setup_pki_ca(lab_mode=True, allowed_domains=["test.lan"]))

        acme_kwargs = self._acme_write_kwargs(mock_client)
        assert acme_kwargs["eab_policy"] == "not-required"
        assert result["eab_required"] is False
        assert result["eab_policy"] == "not-required"

    def test_prod_mode_result_eab_required_true(self):
        """lab_mode=False → retour setup expose eab_required=True + eab_policy."""
        from mcp_vault.vault.pki_ca import setup_pki_ca

        mock_client = self._mock_hvac()
        with patch("mcp_vault.vault.pki_ca._get_hvac_client", return_value=mock_client), \
             patch("mcp_vault.s3_sync.upload_to_s3", new_callable=AsyncMock, return_value=True), \
             patch("mcp_vault.vault.pki_ca._read_pem_url", new_callable=AsyncMock, return_value=_MOCK_CERT_PEM):
            result = _run(setup_pki_ca(lab_mode=False, allowed_domains=["prod.example.com"]))

        assert result["eab_required"] is True, "eab_required doit être True en prod"
        assert result["eab_policy"] == "new-account-required"

    def test_eab_required_helper(self):
        """_eab_required : True pour new-account/always-required, False sinon."""
        from mcp_vault.vault.pki_ca import _eab_required
        assert _eab_required("new-account-required") is True
        assert _eab_required("always-required") is True
        assert _eab_required("not-required") is False
        assert _eab_required("required") is False, "'required' n'existe pas → ne doit pas activer EAB"
        assert _eab_required("unknown") is False

    def test_allowed_response_headers_tuned(self):
        """
        Réserve #1 — le mount intermédiaire est tuné pour autoriser les
        headers ACME (Replay-Nonce, Link, Location).
        """
        from mcp_vault.vault.pki_ca import setup_pki_ca, _ACME_RESPONSE_HEADERS

        mock_client = self._mock_hvac()
        with patch("mcp_vault.vault.pki_ca._get_hvac_client", return_value=mock_client), \
             patch("mcp_vault.s3_sync.upload_to_s3", new_callable=AsyncMock, return_value=True), \
             patch("mcp_vault.vault.pki_ca._read_pem_url", new_callable=AsyncMock, return_value=_MOCK_CERT_PEM):
            _run(setup_pki_ca(lab_mode=False, allowed_domains=["prod.example.com"]))

        tune_calls = mock_client.sys.tune_mount_configuration.call_args_list
        assert tune_calls, "tune_mount_configuration jamais appelé"
        found = any(
            c.kwargs.get("allowed_response_headers") == _ACME_RESPONSE_HEADERS
            for c in tune_calls
        )
        assert found, f"allowed_response_headers ACME non tunés : {tune_calls}"

    def test_sign_intermediate_uses_issuer_path(self):
        """
        Réserve #2 — sign-intermediate via /issuer/:ref/sign-intermediate
        (path), pas issuer_ref dans le body.
        """
        from mcp_vault.vault.pki_ca import setup_pki_ca

        mock_client = self._mock_hvac()
        with patch("mcp_vault.vault.pki_ca._get_hvac_client", return_value=mock_client), \
             patch("mcp_vault.s3_sync.upload_to_s3", new_callable=AsyncMock, return_value=True), \
             patch("mcp_vault.vault.pki_ca._read_pem_url", new_callable=AsyncMock, return_value=_MOCK_CERT_PEM):
            _run(setup_pki_ca(lab_mode=False, allowed_domains=["prod.example.com"]))

        sign_calls = [
            c for c in mock_client.write.call_args_list
            if c.args and "sign-intermediate" in str(c.args[0])
        ]
        assert sign_calls, "Aucun appel sign-intermediate"
        for c in sign_calls:
            assert "/issuer/mcp-vault-root/sign-intermediate" in str(c.args[0]), (
                f"Path sign-intermediate incorrect : {c.args[0]}"
            )
            assert "issuer_ref" not in c.kwargs, "issuer_ref ne doit plus être dans le body"

    def test_setup_fails_if_acme_header_tuning_fails(self):
        """
        ÉLEVÉ — si le tuning allowed_response_headers échoue, le setup doit
        échouer (pas annoncer une PKI ACME opérationnelle qui ne l'est pas).
        """
        from mcp_vault.vault.pki_ca import setup_pki_ca

        mock_client = self._mock_hvac()
        mock_client.sys.tune_mount_configuration = MagicMock(
            side_effect=Exception("tune refused")
        )
        with patch("mcp_vault.vault.pki_ca._get_hvac_client", return_value=mock_client), \
             patch("mcp_vault.s3_sync.upload_to_s3", new_callable=AsyncMock, return_value=True), \
             patch("mcp_vault.vault.pki_ca._read_pem_url", new_callable=AsyncMock, return_value=_MOCK_CERT_PEM):
            result = _run(setup_pki_ca(lab_mode=False, allowed_domains=["prod.example.com"]))

        assert result["status"] == "error", "Setup doit échouer si tuning ACME KO"

    def test_rotate_uses_issuer_path(self):
        """
        Réserve #2 (rotation) — rotate_intermediate signe via
        /issuer/:ref/sign-intermediate, pas issuer_ref dans le body.
        """
        from mcp_vault.vault.pki_ca import rotate_intermediate

        mock_client = self._mock_hvac()
        mock_client.write = MagicMock(return_value={
            "data": {
                "certificate": "",
                "csr": "-----BEGIN CERTIFICATE REQUEST-----\nMOCK\n-----END CERTIFICATE REQUEST-----",
                "imported_issuers": ["issuer-uuid-new"],
                "default": "issuer-uuid-old",
            }
        })
        with patch("mcp_vault.vault.pki_ca._get_hvac_client", return_value=mock_client), \
             patch("mcp_vault.s3_sync.upload_to_s3", new_callable=AsyncMock, return_value=True), \
             patch("mcp_vault.vault.pki_ca.is_pki_initialized", return_value=True), \
             patch("mcp_vault.vault.pki_ca._read_pem_url", new_callable=AsyncMock, return_value=_MOCK_CERT_PEM):
            result = _run(rotate_intermediate(keep_old_issuer=True))

        assert result["status"] == "ok", f"Rotation KO : {result}"
        sign_calls = [
            c for c in mock_client.write.call_args_list
            if c.args and "sign-intermediate" in str(c.args[0])
        ]
        assert sign_calls, "Aucun appel sign-intermediate dans la rotation"
        for c in sign_calls:
            assert "/issuer/mcp-vault-root/sign-intermediate" in str(c.args[0]), (
                f"Path rotation incorrect : {c.args[0]}"
            )
            assert "issuer_ref" not in c.kwargs, "issuer_ref ne doit plus être dans le body (rotation)"


# ─────────────────────────────────────────────────────────────────────────────
# Mock certificat PEM pour les tests (auto-signé, expiré acceptable)
# ─────────────────────────────────────────────────────────────────────────────

# Cert PEM minimaliste généré pour les tests (RSA 2048, 1 jour, CN=test)
_MOCK_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU6pQ4pHnSSDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlt
Y3AtdGVzdDAeFw0yNjA2MTAwMDAwMDBaFw0zNjA2MDgwMDAwMDBaMBQxEjAQBgNV
BAMMCm1jcC10ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2a5v
xkjH6Q3vqz7L5DnfO8s9P1+YmRnRaF3WvkAjpBKtQZkBqSzlYOcR1HKJr4i8Nq
Z5X9fOt+vJ/Vvs3H8H3YcH7M2t5oFJVHJhPDdgWHUEu9RgF3KZ4GvVHRSJTPJv
Lq7nFOZ8CtCyBpqC5BHiSZ9m9TDmVG7b7VJpuJwOZT5PpXEqQd0u7K8GZ1fR5V
mT8sJHU6bFkY4gZD3cQ5BXt2Z8KcOhHxfYXv7nM9sEFqT3vWDzLpK8Q2O9bT6j
SHmP5vZzL7bP3X2wN+M0c8fZkQ1TXfJqhV8KL3pFgDs4nQ0Q2L5Y7P8cR6W2A1
YGjNtHF2KwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCq9f7MnkHJ4Zs3RbVp5N1
xR2v8L0F4vMsOPqt3HZ5B8WnYcVkQhXTJpLvD7Z9M3fAG5Np4cK7RHiMvQ2xJ
-----END CERTIFICATE-----"""
