# -*- coding: utf-8 -*-
"""
API REST admin — Endpoints pour la console d'administration.

Tous les endpoints requièrent un Bearer token admin.
Routage depuis AdminMiddleware pour /admin/api/*.
"""

import json
import platform
from pathlib import Path

from ..config import get_settings
from ..auth.token_store import get_token_store
from ..auth.middleware import get_activity_log


async def handle_admin_api(scope, receive, send, mcp):
    """Routeur principal de l'API admin."""
    path = scope.get("path", "")
    method = scope.get("method", "GET")

    # --- Auth admin requise ---
    token = _extract_admin_token(scope)
    if not _is_admin(token):
        return await _json_response(send, 401, {"status": "error", "message": "Admin token required"})

    # --- Routes ---
    if path == "/admin/api/health" and method == "GET":
        return await _api_health(send, mcp)

    if path == "/admin/api/tokens" and method == "GET":
        return await _api_list_tokens(send)

    if path == "/admin/api/tokens" and method == "POST":
        body = await _read_body(receive)
        return await _api_create_token(send, body)

    if path.startswith("/admin/api/tokens/") and method == "DELETE":
        name = path.split("/")[-1]
        return await _api_revoke_token(send, name)

    if path == "/admin/api/logs" and method == "GET":
        return await _api_logs(send)

    return await _json_response(send, 404, {"status": "error", "message": f"Unknown admin route: {path}"})


# =============================================================================
# Endpoints
# =============================================================================

async def _api_health(send, mcp):
    """GET /admin/api/health — État du serveur."""
    settings = get_settings()
    version = "dev"
    vf = Path(__file__).parent.parent.parent.parent / "VERSION"
    if vf.exists():
        version = vf.read_text().strip()

    tools = [t.name for t in mcp._tool_manager.list_tools()] if mcp else []

    await _json_response(send, 200, {
        "status": "ok",
        "service_name": settings.mcp_server_name,
        "version": version,
        "python_version": platform.python_version(),
        "tools_count": len(tools),
        "tools": tools,
        "s3_configured": bool(settings.s3_endpoint_url),
    })


async def _api_list_tokens(send):
    """GET /admin/api/tokens — Liste des tokens."""
    store = get_token_store()
    if not store:
        return await _json_response(send, 200, {"status": "ok", "tokens": [], "message": "S3 non configuré"})
    await _json_response(send, 200, {"status": "ok", "tokens": store.list_all()})


async def _api_create_token(send, body):
    """POST /admin/api/tokens — Créer un token."""
    store = get_token_store()
    if not store:
        return await _json_response(send, 400, {"status": "error", "message": "S3 non configuré"})

    data = json.loads(body) if body else {}
    client_name = data.get("client_name", "")
    permissions = data.get("permissions", ["read"])
    allowed_resources = data.get("allowed_resources", [])
    email = data.get("email", "")
    expires_in_days = data.get("expires_in_days", 90)

    if not client_name:
        return await _json_response(send, 400, {"status": "error", "message": "client_name requis"})

    result = store.create(client_name, permissions, allowed_resources,
                          expires_in_days=expires_in_days, email=email)
    await _json_response(send, 201, {"status": "created", **result})


async def _api_revoke_token(send, hash_prefix):
    """DELETE /admin/api/tokens/{hash_prefix} — Révoquer un token."""
    store = get_token_store()
    if not store:
        return await _json_response(send, 400, {"status": "error", "message": "S3 non configuré"})

    if store.revoke(hash_prefix):
        await _json_response(send, 200, {"status": "ok", "message": f"Token {hash_prefix}... révoqué"})
    else:
        await _json_response(send, 404, {"status": "error", "message": f"Token {hash_prefix}... non trouvé"})


async def _api_logs(send):
    """GET /admin/api/logs — Activité récente (ring buffer)."""
    logs = get_activity_log()
    await _json_response(send, 200, {"status": "ok", "count": len(logs), "logs": logs[-50:]})


# =============================================================================
# Helpers
# =============================================================================

def _extract_admin_token(scope) -> str:
    """Extrait le Bearer token depuis les headers."""
    headers = dict(scope.get("headers", []))
    auth = headers.get(b"authorization", b"").decode()
    if auth.startswith("Bearer "):
        return auth[7:]
    return ""


def _is_admin(token: str) -> bool:
    """Vérifie si le token est admin (bootstrap key ou token admin S3)."""
    if not token:
        return False
    settings = get_settings()
    if token == settings.admin_bootstrap_key:
        return True
    store = get_token_store()
    if store:
        import hashlib
        h = hashlib.sha256(token.encode()).hexdigest()
        info = store.get_by_hash(h)
        if info and "admin" in info.get("permissions", []) and not info.get("revoked"):
            return True
    return False


async def _read_body(receive) -> bytes:
    """Lit le body complet d'une requête ASGI."""
    body = b""
    while True:
        message = await receive()
        body += message.get("body", b"")
        if not message.get("more_body", False):
            break
    return body


async def _json_response(send, status, data):
    """Envoie une réponse JSON avec headers CORS."""
    body = json.dumps(data, default=str).encode()
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
            (b"access-control-allow-origin", b"*"),
        ],
    })
    await send({"type": "http.response.body", "body": body})
