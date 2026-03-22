# -*- coding: utf-8 -*-
"""
AdminMiddleware ASGI — Console d'administration web (/admin).

Intercepte les routes /admin, /admin/static/*, /admin/api/*
AVANT l'auth MCP (l'admin gère sa propre auth Bearer admin).
"""

import json
import mimetypes
from pathlib import Path


class AdminMiddleware:
    """
    Middleware ASGI outermost — sert la console admin et l'API REST.

    Routes interceptées :
        GET  /admin             → SPA HTML (admin.html)
        GET  /admin/static/*    → Fichiers statiques (CSS, JS, images)
        *    /admin/api/*       → API REST admin (délègue à api.py)
        Tout le reste           → Passe au middleware suivant (MCP)
    """

    def __init__(self, app, mcp_instance=None):
        self.app = app
        self.mcp = mcp_instance
        self.static_dir = Path(__file__).parent.parent / "static"

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        path = scope.get("path", "")
        method = scope.get("method", "GET")

        # --- CORS preflight ---
        if method == "OPTIONS" and path.startswith("/admin/api/"):
            return await self._cors_response(send)

        # --- SPA HTML ---
        if path in ("/admin", "/admin/"):
            return await self._serve_file(send, "admin.html", "text/html")

        # --- Fichiers statiques ---
        if path.startswith("/admin/static/"):
            rel = path[len("/admin/static/"):]
            if ".." in rel:
                return await self._error(send, 403, "Forbidden")
            return await self._serve_file(send, rel)

        # --- API REST admin ---
        if path.startswith("/admin/api/"):
            from .api import handle_admin_api
            return await handle_admin_api(scope, receive, send, self.mcp)

        # --- Tout le reste → middleware suivant ---
        return await self.app(scope, receive, send)

    async def _serve_file(self, send, filename, content_type=None):
        """Sert un fichier statique depuis le répertoire static/."""
        filepath = self.static_dir / filename
        if not filepath.exists():
            return await self._error(send, 404, f"Not found: {filename}")

        if content_type is None:
            content_type = mimetypes.guess_type(str(filepath))[0] or "application/octet-stream"

        body = filepath.read_bytes()
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [
                (b"content-type", content_type.encode()),
                (b"content-length", str(len(body)).encode()),
                (b"cache-control", b"no-cache"),
            ],
        })
        await send({"type": "http.response.body", "body": body})

    async def _cors_response(self, send):
        """Répond aux preflight CORS OPTIONS."""
        await send({
            "type": "http.response.start",
            "status": 204,
            "headers": [
                (b"access-control-allow-origin", b"*"),
                (b"access-control-allow-methods", b"GET, POST, DELETE, OPTIONS"),
                (b"access-control-allow-headers", b"Authorization, Content-Type"),
                (b"access-control-max-age", b"3600"),
            ],
        })
        await send({"type": "http.response.body", "body": b""})

    async def _error(self, send, status, message):
        """Retourne une erreur JSON."""
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
