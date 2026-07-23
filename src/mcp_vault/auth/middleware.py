# -*- coding: utf-8 -*-
"""
Middlewares ASGI : authentification, logging, health check.

Pile d'exécution (ordre) :
    AdminMiddleware → HealthCheckMiddleware → AuthMiddleware → LoggingMiddleware → FastMCP
"""

import hmac
import json
import sys
import time
import hashlib
import collections
from typing import Optional
from .context import current_token_info
from .token_store import get_token_store
from ..config import get_settings


# =============================================================================
# Ring buffer pour l'activité (utilisé par la console admin)
# =============================================================================

_activity_log = collections.deque(maxlen=200)


def get_activity_log() -> list:
    """Retourne les N dernières entrées du ring buffer d'activité."""
    return list(_activity_log)


# =============================================================================
# HealthCheckMiddleware
# =============================================================================

class HealthCheckMiddleware:
    """
    Middleware ASGI pour les health checks.

    Intercepte /health, /healthz, /ready et retourne 200 OK directement.
    """

    HEALTH_PATHS = {"/health", "/healthz", "/ready"}

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope.get("path", "") == "/":
            return await self._root_response(send)

        if scope["type"] == "http" and scope.get("path", "") in self.HEALTH_PATHS:
            return await self._health_response(send)


        await self.app(scope, receive, send)

    async def _root_response(self, send):
        """GET / → status du service MCP Vault (public, sans auth)."""
        from pathlib import Path
        import platform

        settings = get_settings()
        version = "dev"
        vf = Path("VERSION")
        if vf.exists():
            version = vf.read_text().strip()

        body = json.dumps({
            "status": "ok",
            "service": settings.mcp_server_name,
            "version": version,
            "description": "MCP Vault — Gestion sécurisée des secrets pour agents IA (OpenBao embedded)",
            "endpoints": {
                "mcp": "/mcp",
                "admin": "/admin",
                "health": "/health",
            },
        }, ensure_ascii=False).encode()

        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [
                [b"content-type", b"application/json"],
                [b"access-control-allow-origin", b"*"],
            ],
        })
        await send({"type": "http.response.body", "body": body})

    async def _health_response(self, send):
        """GET /health → format aligné sur les autres services MCP Cloud Temple."""
        from pathlib import Path

        settings = get_settings()
        version = "dev"
        vf = Path("VERSION")
        if vf.exists():
            version = vf.read_text().strip()

        body = json.dumps({
            "status": "healthy",
            "service": settings.mcp_server_name,
            "version": version,
            "transport": "streamable-http",
        }).encode()

        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [[b"content-type", b"application/json"]],
        })
        await send({"type": "http.response.body", "body": body})


# =============================================================================
# AuthMiddleware
# =============================================================================

class AuthMiddleware:
    """
    Middleware ASGI d'authentification par Bearer token — et PEP mission JWT (issue #47).

    Unique lecteur du header Authorization et unique writer de current_token_info
    sur la surface /mcp (l'Admin API /admin/* est une surface d'auth séparée,
    bearer/bootstrap-only, qui ne dispatch JAMAIS les JWT).

    Modes (settings.mcp_auth_mode) :
      - "bearer" (défaut)  : comportement historique STRICTEMENT inchangé —
        bearer opaque validé (bootstrap key / Token Store), token_info ou None
        injecté, les outils vérifient.
      - "jwt"        : mission_token JWT ES256 OBLIGATOIRE. Refus ACTIF au
        middleware : 401 (token absent/opaque/JWT invalide), 403 (token authentique
        mais aud/component_id ≠ instance, mission inactive), 503 (JWKS indisponible,
        fail-close). Exception : la bootstrap key admin reste acceptée (break-glass —
        testée en constant-time AVANT tout dispatch JWT).
      - "dual-stack" : mode de MIGRATION. Un JWT structurel est validé comme en
        mode jwt (un JWT invalide → 401, ne retombe JAMAIS sur le chemin bearer) ;
        un bearer opaque suit le chemin historique.

    SÉCURITÉ : seul le header Authorization est accepté.
    L'auth par query string (?token=) a été supprimée (risque de fuite dans les logs).
    Le token (bearer ou JWT compact) n'apparaît JAMAIS dans les logs, l'audit ni
    les réponses — seuls des codes de raison sont loggés côté serveur.
    """

    PUBLIC_PATHS = {"/health", "/healthz", "/ready", "/favicon.ico"}

    def __init__(self, app, mcp=None):
        self.app = app
        self.mcp = mcp

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)

        path = scope.get("path", "")

        # Routes publiques → pas d'auth
        if path in self.PUBLIC_PATHS:
            return await self.app(scope, receive, send)

        # Extraire le Bearer token
        token = self._extract_token(scope)
        settings = get_settings()

        if settings.mcp_auth_mode == "bearer":
            # ── Comportement historique (inchangé) ─────────────────────────
            token_info = self._validate_token(token) if token else None
        else:
            # ── PEP mission JWT (modes jwt / dual-stack) ───────────────────
            token_info, deny = await self._resolve_pep(token, settings)
            if deny is not None:
                status, reason, claims_ctx = deny
                self._audit_pep_deny(reason, claims_ctx)
                return await self._deny_response(scope, send, status)

        # Injecter dans le contextvar (même si None → les outils vérifieront)
        tok = current_token_info.set(token_info)
        try:
            await self.app(scope, receive, send)
        finally:
            current_token_info.reset(tok)

    # ── PEP mission JWT (issue #47) ─────────────────────────────────────────

    async def _resolve_pep(self, token, settings):
        """Résout le token entrant en modes jwt/dual-stack.

        Returns:
            (token_info, None)                    → injecter et continuer.
            (None, (status, reason, claims_ctx))  → refus actif au middleware.
        """
        from .mission_jwt import looks_like_jwt

        mode = settings.mcp_auth_mode

        # Modes jwt ET dual-stack sont des modes de DURCISSEMENT : une requête /mcp
        # doit présenter une auth VALIDE. Pas de passthrough anonyme (qui, via
        # get_listing_filter(None), rendrait tous les vaults visibles).
        if not token:
            return None, (401, "missing_token", {})

        # Bootstrap key admin : testée en constant-time AVANT tout dispatch JWT
        # (break-glass — jamais routée vers la validation JWT).
        if hmac.compare_digest(token, settings.admin_bootstrap_key):
            return {
                "auth_type": "bootstrap",
                "client_name": "admin",
                "permissions": ["admin", "read", "write"],
                "allowed_resources": [],
            }, None

        if looks_like_jwt(token):
            return await self._validate_mission_jwt(token, settings)

        # Bearer opaque.
        if mode == "jwt":
            return None, (401, "opaque_token_not_allowed", {})
        # dual-stack : chemin bearer historique (Token Store). Un bearer invalide
        # est refusé ACTIVEMENT (401) — jamais de passthrough silencieux avec None.
        info = self._validate_token(token)
        if info is None:
            return None, (401, "invalid_bearer", {})
        return info, None

    async def _validate_mission_jwt(self, token, settings):
        """Valide un mission_token JWT et construit le token_info synthétique.

        Le mission_token ne porte AUCUNE autz vault : mcp-vault (PDP local) authentifie
        l'identité + la lie à l'instance (PR #47), puis résout le périmètre provisionné
        pour ce tenant dans le MissionBindingStore (#69). Absent/désactivé/expiré →
        allowed_resources=[] + auth_type="mission_jwt" → deny-by-default (check_access,
        jamais owner-based). Store configuré mais indisponible → 503 (jamais deny silencieux).
        """
        from .mission_jwt import (
            JWKSUnavailable,
            MissionTokenForbidden,
            MissionTokenInvalid,
            check_mission_active,
            get_jwks_cache,
            validate_mission_token,
        )

        jwks_cache = get_jwks_cache()
        if jwks_cache is None:
            # Lifecycle non passé / JWKS non initialisé → fail-close.
            return None, (503, "jwks_not_initialized", {})

        try:
            claims = validate_mission_token(
                token,
                jwks_cache,
                instance_id=settings.resolved_mission_aud,
                component_kind=settings.mcp_component_kind,
                iat_leeway=settings.mission_token_leeway_seconds,
            )
        except MissionTokenInvalid as e:
            return None, (401, e.reason, {})
        except MissionTokenForbidden as e:
            # Refus d'un token AUTHENTIFIÉ (signature/exp OK) : l'audit doit tracer
            # l'identité. e.claims porte les claims vérifiés.
            fclaims = getattr(e, "claims", {}) or {}
            forbidden_ctx = {
                "mission_id": fclaims.get("mission_id", ""),
                "tenant_id": fclaims.get("tenant_id", ""),
                "jti": fclaims.get("jti", ""),
                "issuer_decision_id": self._extract_issuer_decision_id(fclaims),
            }
            return None, (403, e.reason, forbidden_ctx)
        except JWKSUnavailable as e:
            return None, (503, e.reason, {})

        claims_ctx = {
            "mission_id": claims.get("mission_id", ""),
            "tenant_id": claims.get("tenant_id", ""),
            "jti": claims.get("jti", ""),
            "issuer_decision_id": self._extract_issuer_decision_id(claims),
        }

        # Mission active (allow-list {RUNNING, WAITING_HUMAN, PAUSED}, fail-close).
        if settings.mission_status_url:
            active, why = await check_mission_active(
                claims["mission_id"],
                status_url_template=settings.mission_status_url,
                cache_ttl=settings.mission_status_cache_ttl,
            )
            if not active:
                status = 503 if why == "service_unavailable" else 403
                return None, (status, f"mission_inactive:{why}", claims_ctx)

        tenant_id = claims["tenant_id"]

        # ── Résolution du périmètre vault local (MissionBindingStore, #69) ──────
        # deny-all par défaut : sans binding, allowed_resources=[] → check_access refuse.
        allowed_resources: list = []
        permissions: list = ["read"]
        policy_id: str = ""
        from .mission_bindings import (
            MissionBindingStoreUnavailable,
            get_mission_binding_store,
        )
        binding_store = get_mission_binding_store()
        if binding_store is not None:
            try:
                binding = binding_store.resolve(tenant_id)
            except MissionBindingStoreUnavailable:
                # Store configuré mais indisponible/corrompu → refus OBSERVABLE (audité
                # via _audit_pep_deny), jamais un deny silencieux masquant la panne du PDP.
                return None, (503, "binding_store_unavailable", claims_ctx)
            if binding is not None:
                allowed_resources = list(binding.get("allowed_resources", []))
                permissions = list(binding.get("permissions", ["read"]))
                policy_id = binding.get("policy_id", "") or ""

        return {
            "auth_type": "mission_jwt",
            "client_name": f"mission:{tenant_id}",
            "permissions": permissions,
            "allowed_resources": allowed_resources,
            "policy_id": policy_id,
            "tenant_id": tenant_id,
            "mission_id": claims["mission_id"],
            "jti": claims["jti"],
        }, None

    @staticmethod
    def _extract_issuer_decision_id(claims) -> str:
        """decision_id de l'émetteur : claims["provenance"][i]["decision_id"]."""
        prov = claims.get("provenance")
        if isinstance(prov, list):
            for entry in prov:
                if isinstance(entry, dict) and entry.get("decision_id"):
                    return str(entry["decision_id"])
        return ""

    def _audit_pep_deny(self, reason, claims_ctx):
        """Audit immuable d'un refus PEP (jamais le token ni un secret).

        decision_id local (uuid4) + decision_id émetteur (provenance) pour la
        corrélation d'audit E2E avec mcp-mission.
        """
        import uuid
        from ..audit import sanitize_audit_field as _san
        decision_id = uuid.uuid4().hex
        # #78 : claims issus du JWT (tenant_id/mission_id/jti) = valeurs potentiellement
        # forgées → sanitisées AVANT log_audit ET print stderr (anti-injection de ligne).
        detail_parts = [f"decision_id={decision_id}", f"reason={_san(reason)}"]
        for key in ("mission_id", "tenant_id", "jti", "issuer_decision_id"):
            if claims_ctx.get(key):
                detail_parts.append(f"{key}={_san(str(claims_ctx[key]))}")
        client = (f"mission:{_san(str(claims_ctx['tenant_id']))}"
                  if claims_ctx.get("tenant_id") else "?")
        try:
            from ..audit import log_audit
            log_audit("mission_pep", "denied", detail=" ".join(detail_parts),
                      client_name=client)
        except Exception:
            pass
        print(f"🛡️  PEP deny: {' '.join(detail_parts)}", file=sys.stderr)

    @staticmethod
    async def _deny_response(scope, send, status):
        """Refus actif : réponse HTTP générique (le motif précis reste côté serveur).

        WebSocket : fermeture 1008 (policy violation) / 1011 (erreur serveur).
        """
        if scope["type"] == "websocket":
            await send({"type": "websocket.close",
                        "code": 1011 if status == 503 else 1008})
            return

        messages = {401: "invalid_token", 403: "forbidden", 503: "service_unavailable"}
        body = json.dumps({
            "status": "error",
            "message": messages.get(status, "denied"),
        }).encode()
        headers = [(b"content-type", b"application/json"),
                   (b"content-length", str(len(body)).encode())]
        if status == 401:
            headers.append((b"www-authenticate", b"Bearer"))
        await send({"type": "http.response.start", "status": status,
                    "headers": headers})
        await send({"type": "http.response.body", "body": body})

    def _extract_token(self, scope) -> Optional[str]:
        """Extrait le token depuis le header Authorization uniquement.

        SÉCURITÉ : l'authentification par query string (?token=) a été
        supprimée pour éviter les fuites de tokens dans les logs HTTP,
        l'historique navigateur, les proxies et les outils de monitoring.
        Seul le header Authorization: Bearer <token> est accepté.
        """
        headers = dict(scope.get("headers", []))
        auth = headers.get(b"authorization", b"").decode()
        if auth.startswith("Bearer "):
            return auth[7:]
        return None

    def _validate_token(self, token: str) -> Optional[dict]:
        """
        Valide un token et retourne ses infos.

        Ordre de validation :
        1. Bootstrap key → admin total
        2. Token Store S3 (si configuré) → lookup par hash SHA-256
        """
        settings = get_settings()

        # Bootstrap key → admin total (comparaison constant-time contre timing attacks)
        if hmac.compare_digest(token, settings.admin_bootstrap_key):
            return {
                "auth_type": "bootstrap",
                "client_name": "admin",
                "permissions": ["admin", "read", "write"],
                "allowed_resources": [],
            }

        # Token Store S3 (si configuré)
        store = get_token_store()
        if store:
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            token_info = store.get_by_hash(token_hash)
            if token_info and not token_info.get("revoked", False):
                resolved = dict(token_info)
                resolved["auth_type"] = "token"
                return resolved

        return None


# =============================================================================
# LoggingMiddleware (avec ring buffer pour la console admin)
# =============================================================================

class LoggingMiddleware:
    """
    Middleware ASGI de logging des requêtes HTTP.

    - Log sur stderr : méthode, path, status, durée
    - Stocke dans un ring buffer mémoire (200 entrées) pour la console admin
    """

    QUIET_PATHS = {"/health", "/healthz", "/ready"}

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        path = scope.get("path", "")
        method = scope.get("method", "?")
        t0 = time.monotonic()
        status_code = 0

        async def send_wrapper(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message.get("status", 0)
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            elapsed = round((time.monotonic() - t0) * 1000, 1)

            # Stocker dans le ring buffer (toutes les requêtes)
            _activity_log.append({
                "method": method,
                "path": path,
                "status": status_code,
                "duration_ms": elapsed,
                "timestamp": time.time(),
            })

            # Log stderr (sauf health checks pour éviter le bruit)
            if path not in self.QUIET_PATHS:
                print(
                    f"📡 {method} {path} → {status_code} ({elapsed}ms)",
                    file=sys.stderr,
                )
