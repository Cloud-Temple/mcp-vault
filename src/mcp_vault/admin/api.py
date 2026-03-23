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

    # --- Auth : token valide requis ---
    token = _extract_admin_token(scope)
    token_info = _get_token_info(token)
    if not token_info:
        return await _json_response(send, 401, {"status": "error", "message": "Valid token required"})

    perms = token_info.get("permissions", [])
    is_admin = "admin" in perms
    can_write = is_admin or "write" in perms
    allowed_vaults = token_info.get("allowed_resources", [])

    # --- Routes système (tout token) ---
    if path == "/admin/api/health" and method == "GET":
        return await _api_health(send, mcp)

    if path == "/admin/api/whoami" and method == "GET":
        return await _json_response(send, 200, {"status": "ok", **token_info})

    if path == "/admin/api/logs" and method == "GET":
        return await _api_logs(send)

    if path == "/admin/api/audit" and method == "GET":
        return await _api_audit(send, scope)

    if path == "/admin/api/generate-password" and method == "GET":
        return await _api_generate_password(send)

    # --- Routes vaults (read = list/detail, write = create/update, admin = delete) ---
    if path == "/admin/api/vaults" and method == "GET":
        if is_admin:
            return await _api_list_vaults(send)
        elif allowed_vaults:
            return await _api_list_vaults(send, allowed_vault_ids=allowed_vaults)
        else:
            # Owner-based isolation : ne voir que ses propres vaults
            client_name = token_info.get("client_name", "")
            return await _api_list_vaults(send, owner_filter=client_name)

    if path == "/admin/api/vaults" and method == "POST":
        if not can_write:
            return await _json_response(send, 403, {"status": "error", "message": "Permission write requise"})
        body = await _read_body(receive)
        return await _api_create_vault(send, body)

    if path.startswith("/admin/api/vaults/") and not "/secrets" in path:
        vault_id = path[len("/admin/api/vaults/"):]
        if "/" not in vault_id and vault_id:
            if method == "GET":
                return await _api_vault_detail(send, vault_id)
            if method == "PUT":
                if not can_write:
                    return await _json_response(send, 403, {"status": "error", "message": "Permission write requise"})
                body = await _read_body(receive)
                return await _api_update_vault(send, vault_id, body)
            if method == "DELETE":
                if not is_admin:
                    return await _json_response(send, 403, {"status": "error", "message": "Permission admin requise"})
                return await _api_delete_vault(send, vault_id)

    # --- Routes secrets (read = list/get, write = create, admin = delete) ---
    if path.startswith("/admin/api/vaults/") and "/secrets" in path:
        parts = path[len("/admin/api/vaults/"):].split("/secrets", 1)
        vault_id = parts[0]
        secret_path = parts[1].lstrip("/") if len(parts) > 1 else ""

        if method == "GET" and not secret_path:
            return await _api_list_secrets(send, vault_id)
        if method == "GET" and secret_path:
            return await _api_read_secret(send, vault_id, secret_path)
        if method == "POST":
            if not can_write:
                return await _json_response(send, 403, {"status": "error", "message": "Permission write requise"})
            body = await _read_body(receive)
            return await _api_write_secret(send, vault_id, body)
        if method == "DELETE" and secret_path:
            if not can_write:
                return await _json_response(send, 403, {"status": "error", "message": "Permission write requise"})
            return await _api_delete_secret(send, vault_id, secret_path)

    # --- Routes policies (admin only) ---
    if path == "/admin/api/policies" and method == "GET":
        if not is_admin:
            return await _json_response(send, 403, {"status": "error", "message": "Permission admin requise"})
        return await _api_list_policies(send)

    if path == "/admin/api/policies" and method == "POST":
        if not is_admin:
            return await _json_response(send, 403, {"status": "error", "message": "Permission admin requise"})
        body = await _read_body(receive)
        return await _api_create_policy(send, body)

    if path.startswith("/admin/api/policies/") and method == "GET":
        policy_id = path[len("/admin/api/policies/"):]
        if policy_id and "/" not in policy_id:
            if not is_admin:
                return await _json_response(send, 403, {"status": "error", "message": "Permission admin requise"})
            return await _api_get_policy(send, policy_id)

    if path.startswith("/admin/api/policies/") and method == "DELETE":
        policy_id = path[len("/admin/api/policies/"):]
        if policy_id and "/" not in policy_id:
            if not is_admin:
                return await _json_response(send, 403, {"status": "error", "message": "Permission admin requise"})
            return await _api_delete_policy(send, policy_id)

    # --- Routes tokens (admin only) ---
    if path == "/admin/api/tokens" and method == "GET":
        if not is_admin:
            return await _json_response(send, 403, {"status": "error", "message": "Permission admin requise"})
        return await _api_list_tokens(send)

    if path == "/admin/api/tokens" and method == "POST":
        if not is_admin:
            return await _json_response(send, 403, {"status": "error", "message": "Permission admin requise"})
        body = await _read_body(receive)
        return await _api_create_token(send, body)

    if path.startswith("/admin/api/tokens/") and method == "PUT":
        if not is_admin:
            return await _json_response(send, 403, {"status": "error", "message": "Permission admin requise"})
        hash_prefix = path.split("/")[-1]
        body = await _read_body(receive)
        return await _api_update_token(send, hash_prefix, body)

    if path.startswith("/admin/api/tokens/") and method == "DELETE":
        if not is_admin:
            return await _json_response(send, 403, {"status": "error", "message": "Permission admin requise"})
        name = path.split("/")[-1]
        return await _api_revoke_token(send, name)

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
    policy_id = data.get("policy_id", "")

    if not client_name:
        return await _json_response(send, 400, {"status": "error", "message": "client_name requis"})

    result = store.create(client_name, permissions, allowed_resources,
                          expires_in_days=expires_in_days, email=email,
                          policy_id=policy_id)
    await _json_response(send, 201, {"status": "created", **result})


async def _api_update_token(send, hash_prefix, body):
    """PUT /admin/api/tokens/{hash_prefix} — Modifier un token."""
    store = get_token_store()
    if not store:
        return await _json_response(send, 400, {"status": "error", "message": "S3 non configuré"})

    data = json.loads(body) if body else {}

    # Préparer les champs (None = pas de changement)
    policy_id = data.get("policy_id")  # None si absent
    permissions = data.get("permissions")  # None si absent
    allowed_resources = data.get("allowed_resources")  # None si absent

    result = store.update(
        hash_prefix=hash_prefix,
        policy_id=policy_id,
        permissions=permissions,
        allowed_resources=allowed_resources,
    )
    status_code = 200 if result.get("status") == "updated" else 400
    await _json_response(send, status_code, result)


async def _api_revoke_token(send, hash_prefix):
    """DELETE /admin/api/tokens/{hash_prefix} — Révoquer un token."""
    store = get_token_store()
    if not store:
        return await _json_response(send, 400, {"status": "error", "message": "S3 non configuré"})

    if store.revoke(hash_prefix):
        await _json_response(send, 200, {"status": "ok", "message": f"Token {hash_prefix}... révoqué"})
    else:
        await _json_response(send, 404, {"status": "error", "message": f"Token {hash_prefix}... non trouvé"})


async def _api_create_vault(send, body):
    """POST /admin/api/vaults — Créer un vault."""
    from ..vault.spaces import create_space
    data = json.loads(body) if body else {}
    vault_id = data.get("vault_id", "").strip()
    description = data.get("description", "")
    if not vault_id:
        return await _json_response(send, 400, {"status": "error", "message": "vault_id requis"})
    result = await create_space(vault_id, description)
    status = 201 if result.get("status") == "created" else 400
    await _json_response(send, status, result)


async def _api_update_vault(send, vault_id, body):
    """PUT /admin/api/vaults/{vault_id} — Modifier un vault."""
    from ..vault.spaces import update_space
    data = json.loads(body) if body else {}
    description = data.get("description", "")
    result = await update_space(vault_id, description)
    status = 200 if result.get("status") != "error" else 400
    await _json_response(send, status, result)


async def _api_delete_vault(send, vault_id):
    """DELETE /admin/api/vaults/{vault_id} — Supprimer un vault."""
    from ..vault.spaces import delete_space
    result = await delete_space(vault_id)
    status = 200 if result.get("status") == "deleted" else 400
    await _json_response(send, status, result)


async def _api_list_secrets(send, vault_id):
    """GET /admin/api/vaults/{vault_id}/secrets — Lister les secrets."""
    from ..vault.secrets import list_secrets
    result = await list_secrets(vault_id)
    await _json_response(send, 200, result)


async def _api_read_secret(send, vault_id, secret_path):
    """GET /admin/api/vaults/{vault_id}/secrets/{path} — Lire un secret."""
    from ..vault.secrets import read_secret
    result = await read_secret(vault_id, secret_path)
    status = 200 if result.get("status") == "ok" else 404
    await _json_response(send, status, result)


async def _api_write_secret(send, vault_id, body):
    """POST /admin/api/vaults/{vault_id}/secrets — Écrire un secret."""
    from ..vault.secrets import write_secret
    data = json.loads(body) if body else {}
    path = data.get("path", "").strip()
    secret_data = data.get("data", {})
    secret_type = data.get("type", "custom")
    tags = data.get("tags", "")
    if not path:
        return await _json_response(send, 400, {"status": "error", "message": "path requis"})
    if not secret_data:
        return await _json_response(send, 400, {"status": "error", "message": "data requis"})
    result = await write_secret(vault_id, path, secret_data, secret_type, tags)
    status = 200 if result.get("status") == "ok" else 400
    await _json_response(send, status, result)


async def _api_delete_secret(send, vault_id, secret_path):
    """DELETE /admin/api/vaults/{vault_id}/secrets/{path} — Supprimer un secret."""
    from ..vault.secrets import delete_secret
    result = await delete_secret(vault_id, secret_path)
    status = 200 if result.get("status") == "deleted" else 400
    await _json_response(send, status, result)


async def _api_list_vaults(send, allowed_vault_ids=None, owner_filter=None):
    """GET /admin/api/vaults — Liste des vaults avec métadonnées."""
    from ..vault.spaces import list_spaces, get_space_info

    result = await list_spaces(allowed_vault_ids, owner_filter=owner_filter)
    if result.get("status") != "ok":
        return await _json_response(send, 500, result)

    # Enrichir chaque vault avec ses métadonnées (secrets_count, dates)
    enriched = []
    for vault in result.get("vaults", []):
        try:
            info = await get_space_info(vault["vault_id"])
            enriched.append({
                "vault_id": vault["vault_id"],
                "description": info.get("description", vault.get("description", "")),
                "secrets_count": info.get("secrets_count", 0),
                "created_at": info.get("created_at", ""),
                "created_by": info.get("created_by", ""),
                "updated_at": info.get("updated_at", ""),
            })
        except Exception:
            enriched.append({
                "vault_id": vault["vault_id"],
                "description": vault.get("description", ""),
                "secrets_count": 0,
            })

    await _json_response(send, 200, {
        "status": "ok",
        "vaults": enriched,
        "count": len(enriched),
    })


async def _api_vault_detail(send, vault_id):
    """GET /admin/api/vaults/{vault_id} — Détail d'un vault."""
    from ..vault.spaces import get_space_info
    from ..vault.secrets import list_secrets
    from ..vault.ssh_ca import list_ssh_roles

    # Infos de base
    info = await get_space_info(vault_id)
    if info.get("status") == "error":
        return await _json_response(send, 404, info)

    # Liste des clés de secrets (pas les valeurs !)
    secrets = await list_secrets(vault_id)
    keys = secrets.get("keys", [])

    # SSH CA : lister les rôles (si CA configurée)
    ssh_roles = []
    try:
        ssh_result = await list_ssh_roles(vault_id)
        if ssh_result.get("status") == "ok":
            ssh_roles = ssh_result.get("roles", [])
    except Exception:
        pass

    await _json_response(send, 200, {
        "status": "ok",
        "vault_id": vault_id,
        "description": info.get("description", ""),
        "secrets_count": info.get("secrets_count", 0),
        "secret_keys": keys,
        "created_at": info.get("created_at", ""),
        "created_by": info.get("created_by", ""),
        "updated_at": info.get("updated_at", ""),
        "updated_by": info.get("updated_by", ""),
        "ssh_ca_roles": ssh_roles,
        "has_ssh_ca": len(ssh_roles) > 0,
    })


async def _api_generate_password(send):
    """GET /admin/api/generate-password — Génère un mot de passe CSPRNG."""
    from ..vault.types import generate_password
    password = generate_password(length=24, uppercase=True, lowercase=True, digits=True, symbols=True)
    await _json_response(send, 200, {"status": "ok", "password": password, "length": len(password)})


async def _api_logs(send):
    """GET /admin/api/logs — Activité récente (ring buffer)."""
    logs = get_activity_log()
    await _json_response(send, 200, {"status": "ok", "count": len(logs), "logs": logs[-50:]})


async def _api_audit(send, scope):
    """GET /admin/api/audit — Journal d'audit MCP avec filtres."""
    from ..audit import get_audit_store

    store = get_audit_store()
    if not store:
        return await _json_response(send, 200, {"status": "ok", "entries": [], "count": 0})

    # Parser les query params
    qs = scope.get("query_string", b"").decode()
    params = {}
    for param in qs.split("&"):
        if "=" in param:
            k, v = param.split("=", 1)
            params[k] = v

    entries = store.get_entries(
        limit=int(params.get("limit", "100")),
        client=params.get("client", ""),
        vault_id=params.get("vault_id", ""),
        tool=params.get("tool", ""),
        category=params.get("category", ""),
        status=params.get("status", ""),
        since=params.get("since", ""),
    )
    stats = store.get_stats()

    await _json_response(send, 200, {
        "status": "ok",
        "entries": entries,
        "count": len(entries),
        "total_in_buffer": stats["total"],
        "stats": stats,
    })


# =============================================================================
# Endpoints — Policies
# =============================================================================

async def _api_list_policies(send):
    """GET /admin/api/policies — Liste des policies."""
    from ..auth.policies import get_policy_store
    store = get_policy_store()
    if not store:
        return await _json_response(send, 200, {"status": "ok", "policies": [], "message": "S3 non configuré"})
    policies = store.list_all()
    await _json_response(send, 200, {"status": "ok", "policies": policies, "count": len(policies)})


async def _api_create_policy(send, body):
    """POST /admin/api/policies — Créer une policy."""
    from ..auth.policies import get_policy_store
    store = get_policy_store()
    if not store:
        return await _json_response(send, 400, {"status": "error", "message": "S3 non configuré"})

    data = json.loads(body) if body else {}
    policy_id = data.get("policy_id", "").strip()
    if not policy_id:
        return await _json_response(send, 400, {"status": "error", "message": "policy_id requis"})

    result = store.create(
        policy_id=policy_id,
        description=data.get("description", ""),
        allowed_tools=data.get("allowed_tools", []),
        denied_tools=data.get("denied_tools", []),
        path_rules=data.get("path_rules", []),
        created_by="admin",
    )
    status_code = 201 if result.get("status") == "created" else 400
    await _json_response(send, status_code, result)


async def _api_get_policy(send, policy_id):
    """GET /admin/api/policies/{policy_id} — Détail d'une policy."""
    from ..auth.policies import get_policy_store
    store = get_policy_store()
    if not store:
        return await _json_response(send, 400, {"status": "error", "message": "S3 non configuré"})

    policy = store.get(policy_id)
    if not policy:
        return await _json_response(send, 404, {"status": "error", "message": f"Policy '{policy_id}' non trouvée"})

    await _json_response(send, 200, {"status": "ok", **policy})


async def _api_delete_policy(send, policy_id):
    """DELETE /admin/api/policies/{policy_id} — Supprimer une policy."""
    from ..auth.policies import get_policy_store
    store = get_policy_store()
    if not store:
        return await _json_response(send, 400, {"status": "error", "message": "S3 non configuré"})

    if store.delete(policy_id):
        await _json_response(send, 200, {"status": "deleted", "policy_id": policy_id})
    else:
        await _json_response(send, 404, {"status": "error", "message": f"Policy '{policy_id}' non trouvée"})


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


def _get_token_info(token: str) -> dict | None:
    """Retourne les infos du token (permissions, allowed_resources) ou None si invalide."""
    if not token:
        return None
    settings = get_settings()
    # Bootstrap key = admin total
    if token == settings.admin_bootstrap_key:
        return {
            "client_name": "admin",
            "permissions": ["read", "write", "admin"],
            "allowed_resources": [],
            "auth_type": "bootstrap",
        }
    # Token S3
    store = get_token_store()
    if store:
        import hashlib
        h = hashlib.sha256(token.encode()).hexdigest()
        info = store.get_by_hash(h)
        if info and not info.get("revoked"):
            return {
                "client_name": info.get("client_name", "unknown"),
                "permissions": info.get("permissions", ["read"]),
                "allowed_resources": info.get("allowed_resources", []),
                "auth_type": "token",
            }
    return None


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
