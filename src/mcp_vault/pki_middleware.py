# -*- coding: utf-8 -*-
"""
PkiMiddleware ASGI — Proxy non-authentifié pour les endpoints PKI/ACME.

Intercepte AVANT le middleware d'auth MCP (couche la plus externe dans create_app).
Ces routes sont délibérément non-authentifiées : c'est le standard PKI/ACME.

SÉCURITÉ :
  - Les endpoints ACME utilisent JWS (RFC 8555) pour l'authentification des clients.
    Il n'y a PAS de CSRF car l'API ACME n'est pas appelée par des navigateurs avec
    des cookies/sessions. La protection réseau est assurée par le WAF en amont.
  - Les paths ACME sont validés anti-traversal (pas de /../..) avant forwarding.
  - Les query strings sont validés avant forwarding.
  - follow_redirects=False : pas de SSRF via redirections OpenBao.

Routes interceptées :
    /acme/*        → proxy vers OpenBao /v1/_sys_pki_int/acme/*
    /pki/ca/root.pem  → OpenBao /v1/_sys_pki_root/ca/pem
    /pki/ca/chain.pem → OpenBao /v1/_sys_pki_int/ca_chain
    /pki/ca/crl.pem   → OpenBao /v1/_sys_pki_int/crl
"""

import json
import logging
import re

import httpx

from .config import get_settings
from .vault.pki_ca import _INT_MOUNT as _PKI_INT_MOUNT, _ROOT_MOUNT as _PKI_ROOT_MOUNT

logger = logging.getLogger("mcp-vault.pki-middleware")

# Headers de réponse ACME à propager vers le client
_ACME_RESPONSE_HEADERS = frozenset({
    "content-type",
    "replay-nonce",
    "location",
    "link",
    "retry-after",
    "cache-control",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
})

# Validation anti-injection de path : caractères autorisés dans les segments ACME
# Pas de ../ ni // ni caractères de contrôle
_SAFE_ACME_SUFFIX = re.compile(r'^(/[a-zA-Z0-9/_\-\.~%]*)?$')

# Validation des query strings : caractères URL-safe seulement, pas de traversal
_SAFE_QUERY_STRING = re.compile(r'^[a-zA-Z0-9=&%+\-_.~!*\'(,):@/?#\[\]]*$')


class PkiMiddleware:
    """
    Middleware ASGI outermost — proxy transparent ACME + distribution CA.

    Monté après AdminMiddleware dans create_app() (couche la plus externe).
    Les requêtes /acme/* et /pki/ca/* ne traversent JAMAIS AuthMiddleware.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        path = scope.get("path", "")

        if path.startswith("/acme/") or path in ("/acme", "/acme/"):
            return await self._proxy_acme(scope, receive, send, path)

        # URL longue générée par OpenBao dans les réponses ACME directory
        # (ex: {base}/v1/_sys_pki_int/acme/new-nonce) — proxy direct vers OpenBao
        if path.startswith(f"/v1/{_PKI_INT_MOUNT}/acme/") or path == f"/v1/{_PKI_INT_MOUNT}/acme":
            return await self._proxy_acme_long(scope, receive, send, path)

        if path in ("/pki/ca/root.pem", "/pki/ca/chain.pem", "/pki/ca/crl.pem"):
            return await self._proxy_pki_ca(scope, receive, send, path)

        return await self.app(scope, receive, send)

    async def _proxy_acme(self, scope, receive, send, path: str) -> None:
        settings = get_settings()
        acme_suffix = path[len("/acme"):]  # /directory, /new-nonce, ...

        # SÉCURITÉ CRITIQUE : validation anti-traversal du path ACME
        if ".." in acme_suffix or "//" in acme_suffix or not _SAFE_ACME_SUFFIX.fullmatch(acme_suffix):
            logger.warning(f"⚠️ PkiMiddleware : path ACME rejeté (traversal) : {acme_suffix!r}")
            return await self._error(send, 400, "Invalid ACME path")

        target = f"{settings.openbao_addr}/v1/{_PKI_INT_MOUNT}/acme{acme_suffix}"

        # SÉCURITÉ CRITIQUE : validation de la query string
        query_bytes = scope.get("query_string", b"")
        if query_bytes:
            query_str = query_bytes.decode(errors="replace")
            if ".." in query_str or not _SAFE_QUERY_STRING.fullmatch(query_str):
                logger.warning(f"⚠️ PkiMiddleware : query string ACME rejetée : {query_str!r}")
                return await self._error(send, 400, "Invalid query parameters")
            target += f"?{query_str}"

        await self._proxy_request(scope, receive, send, target)

    async def _proxy_acme_long(self, scope, receive, send, path: str) -> None:
        """Proxy pour le path long /v1/_sys_pki_int/acme/* (généré par OpenBao)."""
        settings = get_settings()
        prefix = f"/v1/{_PKI_INT_MOUNT}"
        acme_suffix = path[len(prefix):]  # /acme/new-nonce, /acme/directory, etc.

        if ".." in acme_suffix or "//" in acme_suffix or not _SAFE_ACME_SUFFIX.fullmatch(acme_suffix):
            logger.warning(f"⚠️ PkiMiddleware (long path) : path ACME rejeté : {acme_suffix!r}")
            return await self._error(send, 400, "Invalid ACME path")

        target = f"{settings.openbao_addr}/v1/{_PKI_INT_MOUNT}{acme_suffix}"
        query = scope.get("query_string", b"")
        if query:
            query_str = query.decode(errors="replace")
            if ".." in query_str or not _SAFE_QUERY_STRING.fullmatch(query_str):
                return await self._error(send, 400, "Invalid query parameters")
            target += f"?{query_str}"

        await self._proxy_request(scope, receive, send, target)

    async def _proxy_pki_ca(self, scope, receive, send, path: str) -> None:
        settings = get_settings()
        # Whitelist stricte — les paths /pki/ca/* sont fixes, pas d'injection possible
        path_map = {
            "/pki/ca/root.pem":  f"{settings.openbao_addr}/v1/{_PKI_ROOT_MOUNT}/ca/pem",
            "/pki/ca/chain.pem": f"{settings.openbao_addr}/v1/{_PKI_INT_MOUNT}/ca_chain",
            "/pki/ca/crl.pem":   f"{settings.openbao_addr}/v1/{_PKI_INT_MOUNT}/crl/pem",  # /crl/pem = PEM, /crl = DER
        }
        target = path_map.get(path)
        if not target:
            return await self._error(send, 404, "Not found")
        await self._proxy_request(scope, receive, send, target)

    async def _proxy_request(self, scope, receive, send, target: str) -> None:
        method = scope.get("method", "GET")

        body = b""
        more = True
        while more:
            event = await receive()
            body += event.get("body", b"")
            more = event.get("more_body", False)

        req_headers = {}
        for name_b, value_b in scope.get("headers", []):
            name = name_b.decode().lower()
            if name in ("content-type", "accept", "user-agent"):
                req_headers[name] = value_b.decode()

        try:
            async with httpx.AsyncClient(timeout=30.0) as http_client:
                resp = await http_client.request(
                    method=method,
                    url=target,
                    content=body,
                    headers=req_headers,
                    follow_redirects=False,  # SÉCURITÉ : pas de SSRF via redirections
                )
        except (httpx.InvalidURL, httpx.UnsupportedProtocol) as e:
            # #160 : une URL que NOTRE client refuse est un défaut de la requête
            # entrante, pas une panne d'OpenBao — qui n'a jamais été contacté.
            # L'ancien `except Exception` unique répondait « PKI backend
            # unavailable » et journalisait « connexion OpenBao échouée » : un
            # appelant NON AUTHENTIFIÉ pouvait donc faire émettre à notre service
            # une fausse panne de tiers, et toute supervision branchée sur ce
            # signal devenait un générateur d'alarme déclenchable de l'extérieur.
            # Même faute que #86/#152/#154 : ne jamais présenter un fait sur
            # l'appelant comme une indisponibilité d'un tiers.
            logger.warning("⚠️ PkiMiddleware : requête invalide (%s) — %s",
                           type(e).__name__, e)
            return await self._error(send, 400, "Invalid ACME request")
        except Exception as e:
            logger.error(f"❌ PkiMiddleware : connexion OpenBao échouée ({target}) : {e}")
            return await self._error(send, 502, "PKI backend unavailable")

        resp_headers = []
        for name, value in resp.headers.items():
            if name.lower() in _ACME_RESPONSE_HEADERS:
                resp_headers.append((name.lower().encode(), value.encode()))

        content = resp.content
        resp_headers.append((b"content-length", str(len(content)).encode()))

        await send({
            "type": "http.response.start",
            "status": resp.status_code,
            "headers": resp_headers,
        })
        await send({"type": "http.response.body", "body": content})

    async def _error(self, send, status: int, message: str) -> None:
        # MOYEN : json.dumps évite les injections JSON via message
        body = json.dumps({"status": "error", "message": message}).encode()
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        })
        await send({"type": "http.response.body", "body": body})
