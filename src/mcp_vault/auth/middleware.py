# -*- coding: utf-8 -*-
"""
Middlewares ASGI : authentification, logging, health check.

Pile d'exécution (ordre) :
    AdminMiddleware → HealthCheckMiddleware → AuthMiddleware → LoggingMiddleware → FastMCP
"""

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
        if scope["type"] == "http" and scope.get("path", "") in self.HEALTH_PATHS:
            body = json.dumps({"status": "ok"}).encode()
            await send({
                "type": "http.response.start",
                "status": 200,
                "headers": [[b"content-type", b"application/json"]],
            })
            await send({
                "type": "http.response.body",
                "body": body,
            })
            return

        await self.app(scope, receive, send)


# =============================================================================
# AuthMiddleware
# =============================================================================

class AuthMiddleware:
    """
    Middleware ASGI d'authentification par Bearer token.

    - Extrait le token du header Authorization ou query string ?token=
    - Valide via bootstrap key ou Token Store S3
    - Injecte les infos du token dans les contextvars
    - Les routes publiques passent sans token
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
        token_info = None

        if token:
            token_info = self._validate_token(token)

        # Injecter dans le contextvar (même si None → les outils vérifieront)
        tok = current_token_info.set(token_info)
        try:
            await self.app(scope, receive, send)
        finally:
            current_token_info.reset(tok)

    def _extract_token(self, scope) -> Optional[str]:
        """Extrait le token depuis le header Authorization ou query string."""
        headers = dict(scope.get("headers", []))
        auth = headers.get(b"authorization", b"").decode()
        if auth.startswith("Bearer "):
            return auth[7:]

        # Fallback: query string ?token=xxx
        qs = scope.get("query_string", b"").decode()
        for param in qs.split("&"):
            if param.startswith("token="):
                return param[6:]
        return None

    def _validate_token(self, token: str) -> Optional[dict]:
        """
        Valide un token et retourne ses infos.

        Ordre de validation :
        1. Bootstrap key → admin total
        2. Token Store S3 (si configuré) → lookup par hash SHA-256
        """
        settings = get_settings()

        # Bootstrap key → admin total
        if token == settings.admin_bootstrap_key:
            return {
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
                return token_info

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
