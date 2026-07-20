# -*- coding: utf-8 -*-
"""
API REST admin — Endpoints pour la console d'administration.

Tous les endpoints requièrent un Bearer token admin.
Routage depuis AdminMiddleware pour /admin/api/*.
"""

import hashlib
import hmac
import json
import platform
from pathlib import Path

from ..config import get_settings
from ..auth.context import current_token_info, check_policy, check_path_policy, can_read_vault_content
from ..auth.token_store import get_token_store, TokenStore
from ..auth.middleware import get_activity_log
from ..audit import log_audit

# Limite maximale de taille du body HTTP (10 MB)
_MAX_BODY_SIZE = 10 * 1024 * 1024


def _query_param(scope, name: str, default: str = "") -> str:
    """
    Extrait un paramètre de query string d'une requête ASGI.

    Retourne la première valeur (URL-décodée) ou `default`. Robuste : une
    query_string absente ou mal formée retombe sur `default`.
    """
    from urllib.parse import parse_qs
    qs = scope.get("query_string", b"")
    if isinstance(qs, (bytes, bytearray)):
        qs = qs.decode("utf-8", "replace")
    values = parse_qs(qs).get(name)
    return values[0] if values else default


async def _policy_error_response(send, err: dict):
    """
    Traduit un refus de check_policy()/check_path_policy() en réponse HTTP.

    issue #86 Lot 3 : distingue un refus de policy ORDINAIRE (403, l'identité
    n'a pas le droit) d'un refus dû à l'indisponibilité du PolicyStore (503,
    error_type="policy_store_unavailable" — panne/corruption S3 détectée après
    TTL). Centralisé : les ~18 sites REST qui consomment check_policy()/
    check_path_policy() passent tous par ce même helper, pour un mapping
    homogène (pas un traitement ad hoc par site).
    """
    status = 503 if err.get("error_type") == "policy_store_unavailable" else 403
    return await _json_response(send, status, err)


async def handle_admin_api(scope, receive, send, mcp):
    """Routeur principal de l'API admin."""
    path = scope.get("path", "")
    method = scope.get("method", "GET")

    # --- Auth : token valide requis ---
    token = _extract_admin_token(scope)
    token_info = _get_token_info(token)
    if not token_info:
        return await _json_response(send, 401, {"status": "error", "message": "Valid token required"})

    # Défense en profondeur (#69, reco red team) : l'Admin API est bearer/bootstrap-only.
    # _get_token_info() ne dispatche JAMAIS un JWT mission — mais on refuse ici explicitement
    # toute identité mission_jwt sur TOUTE route /admin/api/*, pour que l'invariant tienne même
    # si un changement futur faisait remonter une telle identité jusqu'ici (belt-and-suspenders).
    if token_info.get("auth_type") == "mission_jwt":
        return await _json_response(send, 403, {"status": "error", "message": "Permission admin requise"})

    # FIX: Injecter token_info dans le ContextVar pour que les fonctions
    # downstream (create_space, update_space, etc.) puissent résoudre
    # le client_name via get_current_client_name() au lieu de "anonymous".
    # Même pattern que AuthMiddleware._validate_token() → current_token_info.set()
    ctx_token = current_token_info.set(token_info)
    try:
        return await _handle_admin_routes(scope, receive, send, mcp, token_info)
    finally:
        current_token_info.reset(ctx_token)


async def _handle_admin_routes(scope, receive, send, mcp, token_info):
    """Routage interne des routes admin (appelé avec ContextVar injecté)."""
    path = scope.get("path", "")
    method = scope.get("method", "GET")

    perms = token_info.get("permissions", [])
    is_admin = "admin" in perms
    can_write = is_admin or "write" in perms
    # Typage défensif (cohérent avec auth.context, #47) : allowed_resources non-liste
    # (token mal formé) → traité comme vide, jamais comme un motif de sous-chaîne.
    allowed_vaults = token_info.get("allowed_resources", [])
    if not isinstance(allowed_vaults, list):
        allowed_vaults = []

    # --- Routes système (tout token) ---
    if path == "/admin/api/health" and method == "GET":
        return await _api_health(send, mcp)

    if path == "/admin/api/whoami" and method == "GET":
        return await _json_response(send, 200, {"status": "ok", **token_info})

    if path == "/admin/api/generate-password" and method == "GET":
        return await _api_generate_password(send)

    # SÉCURITÉ V3-02 : audit/logs requièrent admin (données sensibles de tous les clients)
    if path == "/admin/api/logs" and method == "GET":
        if not is_admin:
            return await _json_response(send, 403, {"status": "error", "message": "Permission admin requise"})
        return await _api_logs(send)

    if path == "/admin/api/audit" and method == "GET":
        if not is_admin:
            return await _json_response(send, 403, {"status": "error", "message": "Permission admin requise"})
        return await _api_audit(send, scope)

    # SÉCURITÉ (issue #47) : reload JWKS = admin only (propagation urgente d'une
    # révocation de kid sans attendre le TTL du cache).
    if path == "/admin/api/auth/jwks/reload" and method == "POST":
        if not is_admin:
            return await _json_response(send, 403, {"status": "error", "message": "Permission admin requise"})
        return await _api_jwks_reload(send)

    # --- Routes vaults (read = list/detail, write = create/update, admin = delete) ---
    if path == "/admin/api/vaults" and method == "GET":
        policy_err = check_policy("vault_list")
        if policy_err:
            return await _policy_error_response(send, policy_err)
        if is_admin:
            return await _api_list_vaults(send)
        elif allowed_vaults:
            return await _api_list_vaults(send, allowed_vault_ids=allowed_vaults)
        else:
            # Owner-based isolation : ne voir que ses propres vaults.
            client_name = token_info.get("client_name", "")
            if not client_name:
                # Identité incomplète : owner_filter="" serait ignoré par list_spaces
                # (falsy) et listerait TOUT → fail-close (aucun vault).
                return await _json_response(send, 200,
                                            {"status": "ok", "vaults": [], "count": 0})
            return await _api_list_vaults(send, owner_filter=client_name)

    if path == "/admin/api/vaults" and method == "POST":
        if not can_write:
            return await _json_response(send, 403, {"status": "error", "message": "Permission write requise"})
        policy_err = check_policy("vault_create")
        if policy_err:
            return await _policy_error_response(send, policy_err)
        body = await _read_body(receive)
        return await _api_create_vault(send, body, token_info)

    if path.startswith("/admin/api/vaults/") and "/secrets" not in path and "/ssh/" not in path:
        vault_id = path[len("/admin/api/vaults/"):]
        if "/" not in vault_id and vault_id:
            # SÉCURITÉ : vérifier l'accès au vault (owner/allowed_resources)
            access_err = _check_vault_access(token_info, vault_id)
            if access_err:
                return await _json_response(send, 403, access_err)
            if method == "GET":
                policy_err = check_policy("vault_info")
                if policy_err:
                    return await _policy_error_response(send, policy_err)
                return await _api_vault_detail(send, vault_id)
            if method == "PUT":
                if not can_write:
                    return await _json_response(send, 403, {"status": "error", "message": "Permission write requise"})
                policy_err = check_policy("vault_update")
                if policy_err:
                    return await _policy_error_response(send, policy_err)
                body = await _read_body(receive)
                return await _api_update_vault(send, vault_id, body)
            if method == "DELETE":
                if not is_admin:
                    return await _json_response(send, 403, {"status": "error", "message": "Permission admin requise"})
                policy_err = check_policy("vault_delete")
                if policy_err:
                    return await _policy_error_response(send, policy_err)
                return await _api_delete_vault(send, vault_id)

    # --- Routes SSH CA (write = setup/sign, read = ca-key/roles/role-info) ---
    if path.startswith("/admin/api/vaults/") and "/ssh/" in path:
        parts = path[len("/admin/api/vaults/"):].split("/ssh/", 1)
        vault_id = parts[0]
        ssh_path = parts[1] if len(parts) > 1 else ""

        # SÉCURITÉ : vérifier l'accès au vault (owner/allowed_resources)
        access_err = _check_vault_access(token_info, vault_id)
        if access_err:
            return await _json_response(send, 403, access_err)

        if method == "POST" and ssh_path == "setup":
            if not can_write:
                return await _json_response(send, 403, {"status": "error", "message": "Permission write requise"})
            policy_err = check_policy("ssh_ca_setup")
            if policy_err:
                return await _policy_error_response(send, policy_err)
            body = await _read_body(receive)
            return await _api_ssh_setup(send, vault_id, body)

        if method == "POST" and ssh_path == "sign":
            if not can_write:
                return await _json_response(send, 403, {"status": "error", "message": "Permission write requise"})
            policy_err = check_policy("ssh_sign_key")
            if policy_err:
                return await _policy_error_response(send, policy_err)
            body = await _read_body(receive)
            return await _api_ssh_sign(send, vault_id, body)

        if method == "GET" and ssh_path == "ca-key":
            policy_err = check_policy("ssh_ca_public_key")
            if policy_err:
                return await _policy_error_response(send, policy_err)
            return await _api_ssh_ca_key(send, vault_id)

        if method == "GET" and ssh_path == "roles":
            policy_err = check_policy("ssh_ca_list_roles")
            if policy_err:
                return await _policy_error_response(send, policy_err)
            return await _api_ssh_roles(send, vault_id)

        if method == "GET" and ssh_path.startswith("roles/"):
            role_name = ssh_path[len("roles/"):]
            if role_name:
                policy_err = check_policy("ssh_ca_role_info")
                if policy_err:
                    return await _policy_error_response(send, policy_err)
                return await _api_ssh_role_info(send, vault_id, role_name)

    # --- Routes secrets (read = list/get, write = create, admin = delete) ---
    # SÉCURITÉ #81 : le segment "/secrets" est reconnu EXACTEMENT (pas comme
    # sous-chaîne → écarte "/secretsfoo"). vault_id = 1er segment (jamais de
    # '/'). On ne retire qu'UN slash de séparation : les '//' ne sont donc pas
    # masqués silencieusement, ils seront rejetés par la validation de chemin.
    _secrets_rest = path[len("/admin/api/vaults/"):] if path.startswith("/admin/api/vaults/") else ""
    _secrets_slash = _secrets_rest.find("/")
    _secrets_vault = _secrets_rest[:_secrets_slash] if _secrets_slash != -1 else ""
    _secrets_tail = _secrets_rest[_secrets_slash:] if _secrets_slash != -1 else ""
    if _secrets_vault and (_secrets_tail == "/secrets" or _secrets_tail.startswith("/secrets/")):
        vault_id = _secrets_vault
        _after = _secrets_tail[len("/secrets"):]            # "" ou "/<secret_path>"
        secret_path = _after[1:] if _after.startswith("/") else _after

        # SÉCURITÉ : vérifier l'accès au vault (owner/allowed_resources)
        access_err = _check_vault_access(token_info, vault_id)
        if access_err:
            return await _json_response(send, 403, access_err)

        if method == "GET" and not secret_path:
            # LIST d'un niveau : racine, ou sous-dossier via ?prefix=<sous-chemin>
            # (#81). Le listing passe TOUJOURS par ce chemin contrôlé
            # (check_policy secret_list + check_path_policy). La fiche vault ne
            # renvoie plus les clés → plus de fuite des noms de secrets à un token
            # autorisé sur vault_info mais interdit sur secret_list.
            policy_err = check_policy("secret_list")
            if policy_err:
                return await _policy_error_response(send, policy_err)
            # SÉCURITÉ #81 : canonicaliser le préfixe AVANT le contrôle de policy,
            # pour que le PDP (check_path_policy) et l'appel OpenBao portent sur la
            # MÊME valeur canonique. Sinon `?prefix=%2F` (→ "/") est autorisé par une
            # policy sur "/" puis liste la racine ("") → contournement de policy.
            from ..vault.secrets import normalize_list_path
            prefix = normalize_list_path(_query_param(scope, "prefix"))
            if prefix is None:
                return await _json_response(send, 400,
                        {"status": "error", "message": "Préfixe de listing invalide"})
            path_err = check_path_policy(vault_id, prefix, "read")
            if path_err:
                return await _policy_error_response(send, path_err)
            return await _api_list_secrets(send, vault_id, prefix)
        if method == "GET" and secret_path:
            policy_err = check_policy("secret_read")
            if policy_err:
                return await _policy_error_response(send, policy_err)
            path_err = check_path_policy(vault_id, secret_path, "read")
            if path_err:
                return await _policy_error_response(send, path_err)
            return await _api_read_secret(send, vault_id, secret_path)
        if method == "POST":
            if not can_write:
                return await _json_response(send, 403, {"status": "error", "message": "Permission write requise"})
            policy_err = check_policy("secret_write")
            if policy_err:
                return await _policy_error_response(send, policy_err)
            body = await _read_body(receive)
            try:
                data = json.loads(body) if body else {}
            except (json.JSONDecodeError, ValueError):
                return await _json_response(send, 400, {"status": "error", "message": "JSON invalide"})
            path_err = check_path_policy(vault_id, data.get("path", "").strip(), "write")
            if path_err:
                return await _policy_error_response(send, path_err)
            return await _api_write_secret(send, vault_id, body)
        if method == "DELETE" and secret_path:
            if not can_write:
                return await _json_response(send, 403, {"status": "error", "message": "Permission write requise"})
            policy_err = check_policy("secret_delete")
            if policy_err:
                return await _policy_error_response(send, policy_err)
            path_err = check_path_policy(vault_id, secret_path, "write")
            if path_err:
                return await _policy_error_response(send, path_err)
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

    if path == "/admin/api/tokens/purge" and method == "POST":
        if not is_admin:
            return await _json_response(send, 403, {"status": "error", "message": "Permission admin requise"})
        body = await _read_body(receive)
        return await _api_purge_revoked_tokens(send, body)

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

    # --- Routes mission-bindings (octroi périmètre vault mission JWT, admin only, #69) ---
    # Surface d'administration séparée : bearer/bootstrap admin uniquement. Une identité
    # mission_jwt ne peut JAMAIS l'atteindre (elle n'a pas la permission "admin").
    if path == "/admin/api/mission-bindings" and method == "GET":
        if not is_admin:
            return await _json_response(send, 403, {"status": "error", "message": "Permission admin requise"})
        return await _api_list_mission_bindings(send)

    if path == "/admin/api/mission-bindings" and method == "POST":
        if not is_admin:
            return await _json_response(send, 403, {"status": "error", "message": "Permission admin requise"})
        body = await _read_body(receive)
        return await _api_create_mission_binding(send, body)

    # /purge AVANT le segment variable /{tenant_id} (sinon 'purge' serait pris pour un id).
    if path == "/admin/api/mission-bindings/purge" and method == "POST":
        if not is_admin:
            return await _json_response(send, 403, {"status": "error", "message": "Permission admin requise"})
        body = await _read_body(receive)
        return await _api_purge_mission_bindings(send, body)

    if path.startswith("/admin/api/mission-bindings/") and method == "GET":
        tenant_id = path[len("/admin/api/mission-bindings/"):]
        if tenant_id and "/" not in tenant_id:
            if not is_admin:
                return await _json_response(send, 403, {"status": "error", "message": "Permission admin requise"})
            return await _api_get_mission_binding(send, tenant_id)

    if path.startswith("/admin/api/mission-bindings/") and method == "DELETE":
        tenant_id = path[len("/admin/api/mission-bindings/"):]
        if tenant_id and "/" not in tenant_id:
            if not is_admin:
                return await _json_response(send, 403, {"status": "error", "message": "Permission admin requise"})
            return await _api_delete_mission_binding(send, tenant_id)

    # --- PKI Certificate Authority ---
    if path == "/admin/api/pki/status" and method == "GET":
        return await _api_pki_status(send)

    if path == "/admin/api/pki/setup" and method == "POST":
        if not is_admin:
            return await _json_response(send, 403, {"status": "error", "message": "Permission admin requise"})
        body = await _read_body(receive)
        return await _api_pki_setup(send, body)

    if path == "/admin/api/pki/issue" and method == "POST":
        if not is_admin:
            return await _json_response(send, 403, {"status": "error", "message": "Permission admin requise"})
        body = await _read_body(receive)
        return await _api_pki_issue(send, body)

    # Rôles PKI — non-secret (configuration de l'autorité ACME), accessible à tout token valide
    # pour permettre le diagnostic sans droits admin. Les données exposées sont les domaines
    # autorisés, les flags TLS, les TTL — aucune clé privée ni secret.
    if path == "/admin/api/pki/roles" and method == "GET":
        return await _api_pki_list_roles(send)

    if path.startswith("/admin/api/pki/roles/") and method == "GET":
        role_name = path[len("/admin/api/pki/roles/"):]
        if role_name and "/" not in role_name:
            return await _api_pki_role_info(send, role_name)

    if path == "/admin/api/pki/certs" and method == "GET":
        if not is_admin:
            return await _json_response(send, 403, {"status": "error", "message": "Permission admin requise"})
        return await _api_pki_list_certs(send)

    if path.startswith("/admin/api/pki/certs/") and method == "POST" and path.endswith("/revoke"):
        if not is_admin:
            return await _json_response(send, 403, {"status": "error", "message": "Permission admin requise"})
        serial = path[len("/admin/api/pki/certs/"):-len("/revoke")]
        # Défense en profondeur : validation format serial avant transmission à pki_ca
        import re as _re
        if not _re.match(r'^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2})+$', serial):
            return await _json_response(send, 400, {"status": "error", "message": "Serial invalide"})
        return await _api_pki_revoke_cert(send, serial)

    if path == "/admin/api/pki/ca/rotate" and method == "POST":
        if not is_admin:
            return await _json_response(send, 403, {"status": "error", "message": "Permission admin requise"})
        body = await _read_body(receive)
        return await _api_pki_rotate(send, body)

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

    try:
        data = json.loads(body) if body else {}
    except (json.JSONDecodeError, ValueError):
        return await _json_response(send, 400, {"status": "error", "message": "JSON invalide"})
    # issue #86 Lot 3 (round 3 diff review) : un JSON valide mais non-objet
    # (ex. `[]`) lèverait AttributeError sur data.get() sans ce garde.
    if not isinstance(data, dict):
        return await _json_response(send, 400, {"status": "error", "message": "JSON invalide (objet attendu)"})

    client_name = data.get("client_name", "")
    permissions = data.get("permissions", ["read"])
    allowed_resources = data.get("allowed_resources", [])

    # SÉCURITÉ V3-03 : validation whitelist des permissions
    # (source unique : TokenStore.VALID_PERMISSIONS — cohérent avec create/update)
    if not isinstance(permissions, list) or not all(isinstance(p, str) and p in TokenStore.VALID_PERMISSIONS for p in permissions):
        return await _json_response(send, 400, {"status": "error", "message": f"Permissions invalides: {permissions}. Valides: read, write, admin"})
    email = data.get("email", "")
    expires_in_days = data.get("expires_in_days", 90)
    policy_id = data.get("policy_id", "")

    if not client_name:
        return await _json_response(send, 400, {"status": "error", "message": "client_name requis"})

    # Validation expiration (issue #65) — source unique partagée avec le store. 0 = jamais
    # expirer (illimité EXPLICITE) ; tout invalide (null/négatif/string/float/bool/hors borne)
    # → 400, jamais d'illimité accidentel ni de TypeError 500. Double couche API + store
    # (même posture que la validation des permissions).
    exp_err = TokenStore.validate_expires_in_days(expires_in_days)
    if exp_err:
        return await _json_response(send, 400, {"status": "error", "message": exp_err})

    # Valider que la policy existe (cohérent avec l'outil MCP token_update).
    # issue #86 Lot 3 (round 2 diff review) : un policy_id de type invalide (ex.
    # `false`) est FALSY comme une chaîne vide — sans cette garde de type, le bloc
    # entier serait sauté et un token serait créé avec policy_id=False stocké tel
    # quel, jamais vérifié, alors qu'une valeur (même malformée) avait été fournie.
    if policy_id is not None and not isinstance(policy_id, str):
        return await _json_response(send, 400, {"status": "error",
                "message": "policy_id doit être une chaîne"})
    # issue #86 Lot 3 : un policy_id fourni DOIT être vérifiable — store absent OU
    # indisponible = référence NON vérifiable → refus explicite (bug historique
    # corrigé : `if pstore and ...` acceptait silencieusement tout policy_id
    # quand pstore était None).
    if policy_id:
        from ..auth.policies import get_policy_store, PolicyStoreUnavailable
        pstore = get_policy_store()
        if not pstore:
            return await _json_response(send, 400, {"status": "error",
                    "message": "Policy Store non configuré — policy_id ne peut être vérifié"})
        try:
            policy_found = pstore.get(policy_id)
        except PolicyStoreUnavailable as e:
            return await _json_response(send, 503, {"status": "error",
                    "error_type": "policy_store_unavailable",
                    "message": f"Policy Store indisponible — policy_id ne peut être vérifié ({e})"})
        if not policy_found:
            return await _json_response(send, 400, {"status": "error", "message": f"Policy '{policy_id}' non trouvée"})

    result = store.create(client_name, permissions, allowed_resources,
                          expires_in_days=expires_in_days, email=email,
                          policy_id=policy_id)
    if result.get("status") == "error":
        status_code = 503 if result.get("error_type") == "storage_unavailable" else 400
        return await _json_response(send, status_code, result)
    # Audit (SecNumCloud/HDS) — JAMAIS le token brut dans le détail
    log_audit("token_create", "created",
              detail=f"client={client_name} perms={permissions} "
                     f"scope={allowed_resources or 'owner-based'}")
    await _json_response(send, 201, {"status": "created", **result})


async def _api_update_token(send, hash_prefix, body):
    """PUT /admin/api/tokens/{hash_prefix} — Modifier un token."""
    store = get_token_store()
    if not store:
        return await _json_response(send, 400, {"status": "error", "message": "S3 non configuré"})

    try:
        data = json.loads(body) if body else {}
    except (json.JSONDecodeError, ValueError):
        return await _json_response(send, 400, {"status": "error", "message": "JSON invalide"})
    if not isinstance(data, dict):
        return await _json_response(send, 400, {"status": "error", "message": "JSON invalide (objet attendu)"})

    # Préparer les champs (None = pas de changement)
    policy_id = data.get("policy_id")  # None si absent
    permissions = data.get("permissions")  # None si absent
    allowed_resources = data.get("allowed_resources")  # None si absent

    # Valider que la policy existe si fournie et non vide (cohérent avec l'outil MCP).
    # issue #86 Lot 3 (round 2 diff review) : garde de type AVANT le test falsy —
    # même raison que _api_create_token (policy_id=false sauterait sinon la
    # vérification silencieusement).
    if policy_id is not None and not isinstance(policy_id, str):
        return await _json_response(send, 400, {"status": "error",
                "message": "policy_id doit être une chaîne"})
    # issue #86 Lot 3 : même correction que _api_create_token (fail-close explicite).
    if policy_id and policy_id != "_remove":
        from ..auth.policies import get_policy_store, PolicyStoreUnavailable
        pstore = get_policy_store()
        if not pstore:
            return await _json_response(send, 400, {"status": "error",
                    "message": "Policy Store non configuré — policy_id ne peut être vérifié"})
        try:
            policy_found = pstore.get(policy_id)
        except PolicyStoreUnavailable as e:
            return await _json_response(send, 503, {"status": "error",
                    "error_type": "policy_store_unavailable",
                    "message": f"Policy Store indisponible — policy_id ne peut être vérifié ({e})"})
        if not policy_found:
            return await _json_response(send, 400, {"status": "error", "message": f"Policy '{policy_id}' non trouvée"})

    result = store.update(
        hash_prefix=hash_prefix,
        policy_id=policy_id,
        permissions=permissions,
        allowed_resources=allowed_resources,
    )
    if result.get("error_type") == "storage_unavailable":
        return await _json_response(send, 503, result)
    status_code = 200 if result.get("status") == "updated" else 400
    if result.get("status") == "updated":
        log_audit("token_update", "updated",
                  detail=f"hash={hash_prefix[:12]} fields={result.get('updated_fields', [])}")
    await _json_response(send, status_code, result)


async def _api_revoke_token(send, hash_prefix):
    """DELETE /admin/api/tokens/{hash_prefix} — Révoquer un token."""
    store = get_token_store()
    if not store:
        return await _json_response(send, 400, {"status": "error", "message": "S3 non configuré"})

    result = store.revoke(hash_prefix)
    revoke_status = result.get("status")
    # Normalise le corps de réponse : status="error" dans tous les cas d'échec
    # (le status interne dict est distinct du status JSON retourné au client)
    err_body = {"status": "error", "message": result.get("message", "Erreur révocation")}
    if revoke_status == "ok":
        # Audit (SecNumCloud/HDS) : trace persistante, indépendante du token store
        log_audit("token_revoke", "ok", detail=f"hash={hash_prefix[:12]}")
        await _json_response(send, 200, result)
    elif revoke_status == "storage_unavailable":
        # Révocation NON persistée = le token reste valide → événement critique
        log_audit("token_revoke", "error",
                  detail=f"hash={hash_prefix[:12]} NON PERSISTÉE (S3 indisponible) — token reste valide")
        await _json_response(send, 503, err_body)
    elif revoke_status == "invalid_prefix":
        await _json_response(send, 400, err_body)  # mauvaise entrée → 400, pas 404
    else:
        # not_found | ambiguous
        await _json_response(send, 404, err_body)


async def _api_purge_revoked_tokens(send, body):
    """POST /admin/api/tokens/purge — Purger les tokens révoqués (rétention).

    Body JSON optionnel : {"older_than_days": int (défaut 30), "dry_run": bool}.
    Réservé admin. Chaque token réellement purgé est audité (trace persistante
    dans audit-mcp.jsonl, indépendant de tokens.json → survit au purge)."""
    store = get_token_store()
    if not store:
        return await _json_response(send, 400, {"status": "error", "message": "S3 non configuré"})
    try:
        data = json.loads(body) if body else {}
    except (json.JSONDecodeError, ValueError):
        return await _json_response(send, 400, {"status": "error", "message": "JSON invalide"})

    older_than_days = data.get("older_than_days", 30)
    # bool est sous-classe de int → rejeter explicitement True/False.
    # Borne sup. : évite un OverflowError sur timedelta(days=...) (≈ DoS auto-infligé).
    if (isinstance(older_than_days, bool) or not isinstance(older_than_days, int)
            or older_than_days < 0 or older_than_days > 36500):
        return await _json_response(send, 400, {"status": "error",
                "message": "older_than_days doit être un entier entre 0 et 36500"})
    # dry_run booléen STRICT (dette task_a5346701, jumeau de la faille fermée en #69 sur
    # _api_purge_mission_bindings) : ne PAS coercer — bool([]) / bool(0) == False
    # transformerait une entrée invalide falsy en purge DESTRUCTIVE réelle (fail-open).
    dry_run = data.get("dry_run", False)
    if not isinstance(dry_run, bool):
        return await _json_response(send, 400, {"status": "error",
                "message": "dry_run doit être un booléen (true/false)"})

    result = store.purge_revoked(older_than_days, dry_run=dry_run)

    if not dry_run and result.get("status") == "ok":
        # Audit basé sur ce qui a RÉELLEMENT été purgé (pas sur un dry-run préalable
        # qui pourrait diverger). Jamais de secret dans le détail.
        for c in result.get("purged", []):
            log_audit("token_purge", "deleted",
                      detail=f"hash={c.get('hash_prefix')} client={c.get('client_name')} "
                             f"revoked_at={c.get('revoked_at')}")
        log_audit("token_purge", "ok",
                  detail=f"count={result.get('count', 0)} older_than_days={older_than_days}")
    elif not dry_run and result.get("status") == "storage_unavailable":
        log_audit("token_purge", "error",
                  detail=f"purge NON persistée (S3) older_than_days={older_than_days}")
        # Normaliser en status=error : un échec destructif ne doit jamais s'afficher
        # comme un succès (cohérent avec _api_revoke_token ; CLI/SPA rendent une erreur).
        return await _json_response(send, 503, {"status": "error",
                "message": result.get("message", "Purge non persistée — S3 indisponible")})

    await _json_response(send, 200, result)


async def _api_create_vault(send, body, token_info):
    """POST /admin/api/vaults — Créer un vault."""
    from ..vault.spaces import create_space
    data = json.loads(body) if body else {}
    vault_id = data.get("vault_id", "").strip()
    description = data.get("description", "")
    if not vault_id:
        return await _json_response(send, 400, {"status": "error", "message": "vault_id requis"})
    access_err = _check_vault_access(token_info, vault_id)
    if access_err:
        return await _json_response(send, 403, access_err)
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


async def _api_list_secrets(send, vault_id, prefix=""):
    """
    GET /admin/api/vaults/{vault_id}/secrets[?prefix=<sous-dossier>]

    Liste les entrées d'un niveau : racine par défaut, ou contenu du sous-dossier
    `prefix` (#81). Les sous-dossiers ressortent avec un '/' final ; les clés sont
    relatives à `prefix`. Un préfixe invalide (validation `list_secrets`) → 400.
    """
    from ..vault.secrets import list_secrets
    result = await list_secrets(vault_id, prefix)
    status = 200 if result.get("status") == "ok" else 400
    await _json_response(send, status, result)


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
        vid = vault["vault_id"]
        try:
            # #81 : cardinalité seulement si l'identité peut LISTER ce vault
            # (moindre privilège, test silencieux — pas de faux « denied »).
            info = await get_space_info(vid, count=can_read_vault_content(vid))
            enriched.append({
                "vault_id": vid,
                "description": info.get("description", vault.get("description", "")),
                # None (absent) = inconnu / non autorisé → jamais un « 0 » trompeur ;
                # l'UI affiche « — » (backend indisponible ≠ vault vide).
                "root_entries_count": info.get("root_entries_count"),
                "secrets_count": info.get("secrets_count"),
                "created_at": info.get("created_at", ""),
                "created_by": info.get("created_by", ""),
                "updated_at": info.get("updated_at", ""),
            })
        except Exception:
            enriched.append({
                "vault_id": vid,
                "description": vault.get("description", ""),
                "root_entries_count": None,
                "secrets_count": None,
            })

    await _json_response(send, 200, {
        "status": "ok",
        "vaults": enriched,
        "count": len(enriched),
    })


async def _api_vault_detail(send, vault_id):
    """GET /admin/api/vaults/{vault_id} — Détail d'un vault."""
    from ..vault.spaces import get_space_info
    from ..vault.ssh_ca import list_ssh_roles

    # SÉCURITÉ #81 : la fiche vault NE divulgue PLUS le contenu (ni noms ni
    # cardinalité). count=False → get_space_info ne fait aucun `list`. La console
    # affiche le nombre d'entrées à partir du listing GET .../secrets, seul canal
    # soumis à check_policy("secret_list") + check_path_policy. Un token autorisé
    # sur vault_info mais interdit sur secret_list n'apprend donc rien du contenu.
    info = await get_space_info(vault_id, count=False)
    if info.get("status") == "error":
        return await _json_response(send, 404, info)

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


async def _api_jwks_reload(send):
    """POST /admin/api/auth/jwks/reload — Force le rechargement du JWKS (issue #47).

    Propage une révocation urgente de kid sans attendre le TTL du cache.
    Admin only (gate en amont dans _handle_admin_routes).
    """
    from ..auth.mission_jwt import JWKSUnavailable, get_jwks_cache

    cache = get_jwks_cache()
    if cache is None:
        return await _json_response(send, 503, {
            "status": "error",
            "message": "JWKS non configuré (MISSION_JWKS_URL vide ou lifecycle non passé)",
        })
    try:
        count = cache.force_reload()
    except JWKSUnavailable as e:
        return await _json_response(send, 503, {
            "status": "error",
            "message": f"Rechargement JWKS échoué : {e.reason}",
        })
    return await _json_response(send, 200, {"status": "ok", "keys": count})


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

    # SÉCURITÉ V3-12 : validation numérique du paramètre limit
    try:
        limit = max(1, min(int(params.get("limit", "100")), 1000))
    except (ValueError, TypeError):
        limit = 100

    entries = store.get_entries(
        limit=limit,
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
    from ..auth.policies import get_policy_store, PolicyStoreUnavailable
    store = get_policy_store()
    if not store:
        return await _json_response(send, 200, {"status": "ok", "policies": [], "message": "S3 non configuré"})
    try:
        policies = store.list_all()
    except PolicyStoreUnavailable as e:
        return await _json_response(send, 503, {"status": "error", "error_type": "policy_store_unavailable",
                "message": f"Policy Store indisponible ({e})"})
    await _json_response(send, 200, {"status": "ok", "policies": policies, "count": len(policies)})


async def _api_create_policy(send, body):
    """POST /admin/api/policies — Créer une policy."""
    from ..auth.context import get_current_client_name
    from ..auth.policies import get_policy_store
    store = get_policy_store()
    if not store:
        return await _json_response(send, 400, {"status": "error", "message": "S3 non configuré"})

    # issue #86 Lot 3 (round 2 diff review) : JSON invalide, top-level non-objet,
    # et policy_id non-str (crash `.strip()`) laissaient remonter une exception
    # brute (500) au lieu d'un refus propre (400).
    try:
        data = json.loads(body) if body else {}
    except (json.JSONDecodeError, ValueError):
        return await _json_response(send, 400, {"status": "error", "message": "JSON invalide"})
    if not isinstance(data, dict):
        return await _json_response(send, 400, {"status": "error", "message": "JSON invalide (objet attendu)"})

    policy_id = data.get("policy_id", "")
    if not isinstance(policy_id, str):
        return await _json_response(send, 400, {"status": "error", "message": "policy_id doit être une chaîne"})
    policy_id = policy_id.strip()
    if not policy_id:
        return await _json_response(send, 400, {"status": "error", "message": "policy_id requis"})

    result = store.create(
        policy_id=policy_id,
        description=data.get("description", ""),
        allowed_tools=data.get("allowed_tools", []),
        denied_tools=data.get("denied_tools", []),
        path_rules=data.get("path_rules", []),
        created_by=get_current_client_name(),
    )
    if result.get("status") == "created":
        status_code = 201
        log_audit("policy_create", "created", detail=f"policy={policy_id}")
    elif result.get("error_type") == "policy_store_unavailable":
        status_code = 503
    else:
        status_code = 400
    await _json_response(send, status_code, result)


async def _api_get_policy(send, policy_id):
    """GET /admin/api/policies/{policy_id} — Détail d'une policy."""
    from ..auth.policies import get_policy_store, PolicyStoreUnavailable
    store = get_policy_store()
    if not store:
        return await _json_response(send, 400, {"status": "error", "message": "S3 non configuré"})

    try:
        policy = store.get(policy_id)
    except PolicyStoreUnavailable as e:
        return await _json_response(send, 503, {"status": "error", "error_type": "policy_store_unavailable",
                "message": f"Policy Store indisponible ({e})"})
    if not policy:
        return await _json_response(send, 404, {"status": "error", "message": f"Policy '{policy_id}' non trouvée"})

    await _json_response(send, 200, {"status": "ok", **policy})


async def _api_delete_policy(send, policy_id):
    """DELETE /admin/api/policies/{policy_id} — Supprimer une policy."""
    from ..auth.policies import get_policy_store
    store = get_policy_store()
    if not store:
        return await _json_response(send, 400, {"status": "error", "message": "S3 non configuré"})

    result = store.delete(policy_id)
    if result is True:
        log_audit("policy_delete", "deleted", detail=f"policy={policy_id}")
        await _json_response(send, 200, {"status": "deleted", "policy_id": policy_id})
    elif result in ("storage_error", "policy_store_unavailable"):
        log_audit("policy_delete", "error", detail=f"policy={policy_id} NON PERSISTÉE (Policy Store indisponible)")
        await _json_response(send, 503, {"status": "error", "error_type": "policy_store_unavailable",
                "message": "Suppression non persistée (Policy Store indisponible)"})
    else:
        await _json_response(send, 404, {"status": "error", "message": f"Policy '{policy_id}' non trouvée"})


# =============================================================================
# Endpoints — Mission Bindings (octroi périmètre vault mission JWT, #69)
# =============================================================================

def _binding_decision_id() -> str:
    """decision_id local (uuid4) pour tracer une mutation d'octroi dans l'audit."""
    import uuid
    return uuid.uuid4().hex


async def _api_list_mission_bindings(send):
    """GET /admin/api/mission-bindings — Liste des bindings de cette instance."""
    from ..auth.mission_bindings import (
        MissionBindingStoreUnavailable,
        get_mission_binding_store,
    )
    store = get_mission_binding_store()
    if not store:
        return await _json_response(send, 200, {"status": "ok", "bindings": [],
                                                "message": "Mission Binding Store non configuré"})
    try:
        bindings = store.list_all()
    except MissionBindingStoreUnavailable as e:
        return await _json_response(send, 503, {"status": "error",
                "message": f"Mission Binding Store indisponible ({e})"})
    await _json_response(send, 200, {"status": "ok", "bindings": bindings, "count": len(bindings)})


async def _api_create_mission_binding(send, body):
    """POST /admin/api/mission-bindings — Créer/octroyer un périmètre à un tenant.

    Body JSON : {tenant_id, allowed_resources:[...], permissions:['read'|'read','write'],
                 policy_id?, expires_at?, enabled?}. Réservé admin. Le store valide en
    profondeur (permissions strictes, vault_id, unicité, intégrité policy_id)."""
    from ..auth.context import get_current_client_name
    from ..auth.mission_bindings import get_mission_binding_store
    store = get_mission_binding_store()
    if not store:
        return await _json_response(send, 400, {"status": "error",
                "message": "Mission Binding Store non configuré"})

    try:
        data = json.loads(body) if body else {}
    except (json.JSONDecodeError, ValueError):
        return await _json_response(send, 400, {"status": "error", "message": "JSON invalide"})
    if not isinstance(data, dict):
        return await _json_response(send, 400, {"status": "error", "message": "JSON invalide (objet attendu)"})

    # tenant_id/policy_id passés TELS QUELS : le store valide le format (non-str
    # compris) et refuse proprement. issue #86 Lot 3 (round 2 diff review) :
    # l'ancien `data.get("policy_id", "") or ""` blanchissait silencieusement
    # toute valeur falsy (ex. `false`) en "" — un binding SANS policy était créé
    # alors qu'une référence (même malformée) avait été fournie.
    result = store.create(
        tenant_id=data.get("tenant_id", ""),
        allowed_resources=data.get("allowed_resources", []),
        permissions=data.get("permissions", []),
        policy_id=data.get("policy_id", ""),
        expires_at=data.get("expires_at"),
        # enabled : passé brut (défaut True si absent) — le store exige un booléen STRICT et
        # renvoie 400 si non-bool. Ne PAS coercer ici (bool("false") == True).
        enabled=data.get("enabled", True),
        created_by=get_current_client_name(),
    )
    if result.get("status") == "created":
        did = _binding_decision_id()
        log_audit("mission_binding_create", "created",
                  detail=f"decision_id={did} tenant={result.get('tenant_id')} "
                         f"vaults={len(result.get('allowed_resources', []))} "
                         f"permissions={','.join(result.get('permissions', []))} "
                         f"policy_id={result.get('policy_id', '')}")
        return await _json_response(send, 201, result)
    if result.get("error_type") in ("storage_unavailable", "policy_store_unavailable"):
        # issue #86 Lot 3 : policy_store_unavailable ajouté — le PolicyStore référencé
        # par policy_id peut désormais être indisponible (panne/corruption détectée).
        return await _json_response(send, 503, result)
    return await _json_response(send, 400, result)


async def _api_get_mission_binding(send, tenant_id):
    """GET /admin/api/mission-bindings/{tenant_id} — Détail d'un binding."""
    from ..auth.mission_bindings import (
        MissionBindingStoreUnavailable,
        get_mission_binding_store,
    )
    store = get_mission_binding_store()
    if not store:
        return await _json_response(send, 400, {"status": "error",
                "message": "Mission Binding Store non configuré"})
    try:
        binding = store.get(tenant_id)
    except MissionBindingStoreUnavailable as e:
        return await _json_response(send, 503, {"status": "error",
                "message": f"Mission Binding Store indisponible ({e})"})
    if not binding:
        return await _json_response(send, 404, {"status": "error",
                "message": f"Binding pour tenant '{tenant_id}' non trouvé"})
    await _json_response(send, 200, {"status": "ok", **binding})


async def _api_delete_mission_binding(send, tenant_id):
    """DELETE /admin/api/mission-bindings/{tenant_id} — Révoquer un octroi."""
    from ..auth.mission_bindings import get_mission_binding_store
    store = get_mission_binding_store()
    if not store:
        return await _json_response(send, 400, {"status": "error",
                "message": "Mission Binding Store non configuré"})
    result = store.delete(tenant_id)
    if result is True:
        did = _binding_decision_id()
        log_audit("mission_binding_delete", "deleted",
                  detail=f"decision_id={did} tenant={tenant_id}")
        return await _json_response(send, 200, {"status": "deleted", "tenant_id": tenant_id})
    if result == "storage_error":
        log_audit("mission_binding_delete", "error",
                  detail=f"tenant={tenant_id} NON PERSISTÉE (S3 indisponible)")
        return await _json_response(send, 503, {"status": "error",
                "message": "Suppression non persistée (S3 indisponible)"})
    if result == "storage_unavailable":
        return await _json_response(send, 503, {"status": "error",
                "message": "Mission Binding Store indisponible — suppression non tentée"})
    return await _json_response(send, 404, {"status": "error",
            "message": f"Binding pour tenant '{tenant_id}' non trouvé"})


async def _api_purge_mission_bindings(send, body):
    """POST /admin/api/mission-bindings/purge — Purger les bindings expirés (rétention).

    Body JSON optionnel : {"older_than_days": int (défaut 30), "dry_run": bool}. Réservé admin.
    Chaque binding réellement purgé est audité (trace persistante indépendante du fichier)."""
    from ..auth.mission_bindings import get_mission_binding_store
    store = get_mission_binding_store()
    if not store:
        return await _json_response(send, 400, {"status": "error",
                "message": "Mission Binding Store non configuré"})
    try:
        data = json.loads(body) if body else {}
    except (json.JSONDecodeError, ValueError):
        return await _json_response(send, 400, {"status": "error", "message": "JSON invalide"})

    older_than_days = data.get("older_than_days", 30)
    if (isinstance(older_than_days, bool) or not isinstance(older_than_days, int)
            or older_than_days < 0 or older_than_days > 36500):
        return await _json_response(send, 400, {"status": "error",
                "message": "older_than_days doit être un entier entre 0 et 36500"})
    # dry_run booléen STRICT (red team #69) : ne PAS coercer — bool([]) / bool(0) == False
    # transformerait une entrée invalide falsy en purge DESTRUCTIVE réelle (fail-open).
    dry_run = data.get("dry_run", False)
    if not isinstance(dry_run, bool):
        return await _json_response(send, 400, {"status": "error",
                "message": "dry_run doit être un booléen (true/false)"})

    result = store.purge(older_than_days, dry_run=dry_run)

    if not dry_run and result.get("status") == "ok":
        did = _binding_decision_id()
        for c in result.get("purged", []):
            log_audit("mission_binding_purge", "deleted",
                      detail=f"decision_id={did} tenant={c.get('tenant_id')} "
                             f"expires_at={c.get('expires_at')}")
        log_audit("mission_binding_purge", "ok",
                  detail=f"decision_id={did} count={result.get('count', 0)} "
                         f"older_than_days={older_than_days}")
    elif not dry_run and result.get("error_type") == "storage_unavailable":
        log_audit("mission_binding_purge", "error",
                  detail=f"purge NON persistée (S3) older_than_days={older_than_days}")
        return await _json_response(send, 503, {"status": "error",
                "message": result.get("message", "Purge non persistée — S3 indisponible")})

    await _json_response(send, 200, result)


# =============================================================================
# Endpoints — SSH CA
# =============================================================================

async def _api_ssh_setup(send, vault_id, body):
    """POST /admin/api/vaults/{vault_id}/ssh/setup — Configurer SSH CA + rôle."""
    from ..vault.ssh_ca import setup_ssh_ca
    data = json.loads(body) if body else {}
    role_name = data.get("role_name", "").strip()
    if not role_name:
        return await _json_response(send, 400, {"status": "error", "message": "role_name requis"})
    result = await setup_ssh_ca(
        vault_id=vault_id,
        role_name=role_name,
        allowed_users=data.get("allowed_users", "*"),
        default_user=data.get("default_user", "ubuntu"),
        ttl=data.get("ttl", "30m"),
    )
    status = 200 if result.get("status") == "ok" else 400
    await _json_response(send, status, result)


async def _api_ssh_sign(send, vault_id, body):
    """POST /admin/api/vaults/{vault_id}/ssh/sign — Signer une clé publique SSH."""
    from ..vault.ssh_ca import sign_ssh_key
    data = json.loads(body) if body else {}
    public_key = data.get("public_key", "").strip()
    role_name = data.get("role_name", "").strip()
    if not public_key:
        return await _json_response(send, 400, {"status": "error", "message": "public_key requis"})
    if not role_name:
        return await _json_response(send, 400, {"status": "error", "message": "role_name requis"})
    result = await sign_ssh_key(
        vault_id=vault_id,
        role_name=role_name,
        public_key=public_key,
        ttl=data.get("ttl", "30m"),
    )
    status = 200 if result.get("status") == "ok" else 400
    await _json_response(send, status, result)


async def _api_ssh_ca_key(send, vault_id):
    """GET /admin/api/vaults/{vault_id}/ssh/ca-key — Récupérer la clé publique CA."""
    from ..vault.ssh_ca import get_ca_public_key
    result = await get_ca_public_key(vault_id)
    status = 200 if result.get("status") == "ok" else 400
    await _json_response(send, status, result)


async def _api_ssh_roles(send, vault_id):
    """GET /admin/api/vaults/{vault_id}/ssh/roles — Lister les rôles SSH."""
    from ..vault.ssh_ca import list_ssh_roles
    result = await list_ssh_roles(vault_id)
    status = 200 if result.get("status") == "ok" else 400
    await _json_response(send, status, result)


async def _api_ssh_role_info(send, vault_id, role_name):
    """GET /admin/api/vaults/{vault_id}/ssh/roles/{role_name} — Détail d'un rôle."""
    from ..vault.ssh_ca import get_ssh_role_info
    result = await get_ssh_role_info(vault_id, role_name)
    status = 200 if result.get("status") == "ok" else 400
    await _json_response(send, status, result)


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
    # Comparaison constant-time contre timing attacks
    if hmac.compare_digest(token, settings.admin_bootstrap_key):
        return True
    store = get_token_store()
    if store:
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
    # Bootstrap key = admin total (comparaison constant-time contre timing attacks)
    if hmac.compare_digest(token, settings.admin_bootstrap_key):
        return {
            "client_name": "admin",
            "permissions": ["read", "write", "admin"],
            "allowed_resources": [],
            "auth_type": "bootstrap",
        }
    # Token S3
    store = get_token_store()
    if store:
        h = hashlib.sha256(token.encode()).hexdigest()
        info = store.get_by_hash(h)
        if info and not info.get("revoked"):
            return {
                "client_name": info.get("client_name", "unknown"),
                "permissions": info.get("permissions", ["read"]),
                "allowed_resources": info.get("allowed_resources", []),
                "policy_id": info.get("policy_id", ""),
                "auth_type": "token",
            }
    return None


def _check_vault_access(token_info: dict, vault_id: str) -> dict | None:
    """
    Vérifie que le token a accès au vault spécifié.

    SÉCURITÉ : applique les mêmes contrôles que check_access() dans context.py :
    1. Admin → accès total
    2. allowed_resources non vide → vault_id doit y figurer
    3. allowed_resources vide → owner-based isolation (created_by == client_name)

    Returns:
        None si OK, dict {"status": "error", ...} si refusé
    """
    perms = token_info.get("permissions", [])

    # Admin → accès total
    if "admin" in perms:
        return None

    # Liste explicite de vaults autorisés.
    # Typage défensif (cohérent avec auth.context.check_access, #47) : un
    # allowed_resources non-liste (token S3 mal formé) est traité comme vide —
    # jamais comme un motif (le test d'appartenance sur une str deviendrait un
    # test de sous-chaîne → accès non prévu).
    allowed = token_info.get("allowed_resources", [])
    if not isinstance(allowed, list):
        allowed = []
    if allowed:
        if vault_id not in allowed:
            return {"status": "error", "message": f"Accès refusé à '{vault_id}'"}
        return None

    # Owner-based isolation (allowed_resources vide).
    client_name = token_info.get("client_name", "")
    if not client_name:
        # Identité incomplète (ni périmètre, ni propriétaire) → REFUS (fail-close).
        return {"status": "error", "message": f"Accès refusé à '{vault_id}' (identité incomplète)"}
    from ..vault.spaces import check_vault_owner
    if not check_vault_owner(vault_id, client_name):
        return {"status": "error", "message": f"Accès refusé à '{vault_id}' (vous n'en êtes pas le propriétaire)"}

    return None


async def _read_body(receive) -> bytes:
    """
    Lit le body complet d'une requête ASGI.

    SÉCURITÉ : limite la taille à _MAX_BODY_SIZE (10 MB) pour
    prévenir les attaques OOM (Out Of Memory).
    """
    body = b""
    while True:
        message = await receive()
        body += message.get("body", b"")
        if len(body) > _MAX_BODY_SIZE:
            raise ValueError(f"Body trop volumineux (>{_MAX_BODY_SIZE // (1024*1024)} MB)")
        if not message.get("more_body", False):
            break
    return body


async def _json_response(send, status, data):
    """
    Envoie une réponse JSON.

    SÉCURITÉ : CORS restreint — le header Access-Control-Allow-Origin
    est défini uniquement pour les requêtes same-origin depuis /admin.
    Les requêtes cross-origin depuis des domaines tiers sont bloquées.
    """
    body = json.dumps(data, default=str).encode()
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ],
    })
    await send({"type": "http.response.body", "body": body})


# =============================================================================
# PKI Certificate Authority — Endpoints
# =============================================================================

async def _api_pki_status(send):
    """GET /admin/api/pki/status — État de la PKI."""
    from ..vault.pki_ca import get_pki_status
    result = await get_pki_status()
    code = 200 if result.get("status") in ("ok", "not_initialized") else 500
    await _json_response(send, code, result)


async def _api_pki_setup(send, body):
    """POST /admin/api/pki/setup — Initialiser la PKI (admin)."""
    from ..vault.pki_ca import setup_pki_ca
    try:
        data = json.loads(body) if body else {}
    except json.JSONDecodeError:
        data = {}
    lab_mode = data.get("lab_mode", True)
    raw_domains = data.get("allowed_domains")
    allowed_domains = [d.strip() for d in raw_domains.split(",") if d.strip()] if isinstance(raw_domains, str) else raw_domains
    leaf_ttl = data.get("leaf_ttl", "720h")
    result = await setup_pki_ca(lab_mode, allowed_domains, leaf_ttl)
    await _json_response(send, 200 if result.get("status") == "ok" else 500, result)


async def _api_pki_issue(send, body):
    """POST /admin/api/pki/issue — Émettre un certificat manuel (admin).

    La réponse contient la clé privée (one-shot). Pas d'audit de la clé.
    """
    from ..vault.pki_ca import issue_certificate
    try:
        data = json.loads(body) if body else {}
    except json.JSONDecodeError:
        data = {}
    common_name = (data.get("common_name") or "").strip()
    ttl = (data.get("ttl") or "720h").strip()
    alt_names = (data.get("alt_names") or "").strip()
    ip_sans = (data.get("ip_sans") or "").strip()
    if not common_name:
        return await _json_response(send, 400, {"status": "error", "message": "common_name requis"})
    result = await issue_certificate(common_name, ttl, alt_names, ip_sans)
    code = 200 if result.get("status") == "ok" else (
        400 if result.get("error_type") in ("invalid_input", "domain_not_allowed") else 500
    )
    await _json_response(send, code, result)


async def _api_pki_list_certs(send):
    """GET /admin/api/pki/certs — Inventaire des certificats émis."""
    from ..vault.pki_ca import list_issued_certs
    result = await list_issued_certs(limit=200)
    await _json_response(send, 200, result)


async def _api_pki_revoke_cert(send, serial):
    """POST /admin/api/pki/certs/{serial}/revoke — Révoquer un certificat (admin)."""
    from ..vault.pki_ca import revoke_cert
    result = await revoke_cert(serial)
    msg = result.get("message", "")
    code = 200 if result.get("status") == "ok" else (400 if "invalide" in msg else 500)
    await _json_response(send, code, result)


async def _api_pki_rotate(send, body):
    """POST /admin/api/pki/ca/rotate — Rotation de la CA intermédiaire (admin)."""
    from ..vault.pki_ca import rotate_intermediate
    try:
        data = json.loads(body) if body else {}
    except json.JSONDecodeError:
        data = {}
    result = await rotate_intermediate(
        keep_old_issuer=data.get("keep_old_issuer", True),
        overlap_ttl=data.get("overlap_ttl", "48h"),
    )
    await _json_response(send, 200 if result.get("status") == "ok" else 500, result)


async def _api_pki_list_roles(send):
    """GET /admin/api/pki/roles — Lister les rôles d'émission PKI."""
    from ..vault.pki_ca import list_pki_roles
    result = await list_pki_roles()
    await _json_response(send, 200, result)


async def _api_pki_role_info(send, role_name: str):
    """GET /admin/api/pki/roles/{role_name} — Détails d'un rôle PKI."""
    from ..vault.pki_ca import get_pki_role_info
    result = await get_pki_role_info(role_name)
    await _json_response(send, 200 if result.get("status") == "ok" else 404, result)
