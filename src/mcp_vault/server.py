# -*- coding: utf-8 -*-
"""
MCP Vault — Serveur principal.

Stack ASGI :
    AdminMiddleware → HealthCheckMiddleware → AuthMiddleware → LoggingMiddleware → FastMCP

Lifecycle :
    startup  → S3 download → OpenBao start → unseal
    shutdown → seal → S3 upload
"""

import logging
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .config import get_settings

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("mcp-vault")

# --- Settings ---
settings = get_settings()


import time as _time

_TOOL_LABELS = {
    "vault_create": "Création vault", "vault_list": "Liste vaults",
    "vault_info": "Détails vault", "vault_update": "Modification vault",
    "vault_delete": "Suppression vault",
    "secret_write": "Écriture secret", "secret_read": "Lecture secret",
    "secret_list": "Liste secrets", "secret_delete": "Suppression secret",
    "ssh_ca_setup": "Setup SSH CA", "ssh_sign_key": "Signature clé SSH",
    "ssh_ca_public_key": "Clé publique CA", "ssh_ca_list_roles": "Liste rôles SSH",
    "ssh_ca_role_info": "Détails rôle SSH",
    "policy_create": "Création policy", "policy_list": "Liste policies",
    "policy_get": "Détails policy", "policy_delete": "Suppression policy",
    "token_update": "Modification token", "audit_log": "Consultation audit",
}

def _r(tool: str, result: dict, vault_id: str = "", detail: str = "") -> dict:
    """Log audit event with human-readable detail, and return result."""
    from .audit import log_audit
    status = result.get("status", "?") if isinstance(result, dict) else "?"
    # Build a readable detail message (no emojis — breaks CLI table alignment)
    label = _TOOL_LABELS.get(tool, tool)
    parts = [label]
    if vault_id:
        parts.append(f"[{vault_id}]")
    if detail:
        parts.append(detail)
    if status in ("error",):
        msg = result.get("message", "") if isinstance(result, dict) else ""
        if msg:
            parts.append(f"- {msg[:60]}")
    readable = " ".join(parts)
    log_audit(tool, status, vault_id, readable)
    return result

# --- FastMCP instance ---
mcp = FastMCP(
    settings.mcp_server_name,
    instructions="MCP Vault — Gestion sécurisée des secrets pour agents IA (OpenBao embedded)",
)


# ═══════════════════════════════════════════════════════════════════════
# OUTILS MCP — System
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def system_health() -> dict:
    """
    Vérifie l'état de santé du service MCP Vault.

    Teste la connectivité OpenBao et S3, retourne le statut de chaque service.
    """
    from .openbao.lifecycle import get_vault_status
    from .s3_sync import check_s3_connectivity

    openbao_ok, openbao_detail = await get_vault_status()
    s3_ok, s3_detail = await check_s3_connectivity()

    all_ok = openbao_ok and s3_ok
    return {
        "status": "ok" if all_ok else "degraded",
        "services": {
            "openbao": {"status": "ok" if openbao_ok else "error", "detail": openbao_detail},
            "s3": {"status": "ok" if s3_ok else "error", "detail": s3_detail},
        },
    }


@mcp.tool()
async def system_about() -> dict:
    """
    Informations sur le service MCP Vault.

    Retourne la version, les outils disponibles, et les infos système.
    """
    import platform

    return {
        "service": settings.mcp_server_name,
        "description": "MCP Vault — Gestion sécurisée des secrets pour agents IA",
        "version": Path("VERSION").read_text().strip() if Path("VERSION").exists() else "0.1.0",
        "openbao_addr": settings.openbao_addr,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "tools_count": len(mcp._tool_manager._tools) if hasattr(mcp, "_tool_manager") else "unknown",
    }


# ═══════════════════════════════════════════════════════════════════════
# OUTILS MCP — Vaults (coffres de secrets, mount KV v2)
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def vault_create(vault_id: str, description: str = "") -> dict:
    """
    Crée un nouveau vault (coffre de secrets, mount KV v2 dans OpenBao).

    Args:
        vault_id: Identifiant unique du vault (alphanum + tirets)
        description: Description optionnelle du vault
    """
    from .auth.context import check_access, check_write_permission, check_policy
    from .vault.spaces import create_space

    policy_err = check_policy("vault_create")
    if policy_err:
        return policy_err
    access_err = check_access(vault_id)
    if access_err:
        return access_err
    write_err = check_write_permission()
    if write_err:
        return write_err

    return _r("vault_create", await create_space(vault_id, description), vault_id)


@mcp.tool()
async def vault_list() -> dict:
    """Liste tous les vaults (coffres de secrets) accessibles par le token courant."""
    from .auth.context import current_token_info, check_policy
    from .vault.spaces import list_spaces

    policy_err = check_policy("vault_list")
    if policy_err:
        return policy_err

    # ── Filtrage par token : isolation owner-based ──────────────────
    token_info = current_token_info.get()
    allowed_vault_ids = None
    owner_filter = None

    if token_info and "admin" not in token_info.get("permissions", []):
        allowed = token_info.get("allowed_resources", [])
        if allowed:
            # Liste explicite de vaults autorisés
            allowed_vault_ids = allowed
        else:
            # Pas de liste → owner-based : ne voir que ses propres vaults
            owner_filter = token_info.get("client_name", "")

    return _r("vault_list", await list_spaces(
        allowed_vault_ids=allowed_vault_ids,
        owner_filter=owner_filter,
    ))


@mcp.tool()
async def vault_info(vault_id: str) -> dict:
    """
    Informations détaillées sur un vault.

    Args:
        vault_id: Identifiant du vault
    """
    from .auth.context import check_access, check_policy
    from .vault.spaces import get_space_info

    policy_err = check_policy("vault_info")
    if policy_err:
        return policy_err
    access_err = check_access(vault_id)
    if access_err:
        return access_err

    return _r("vault_info", await get_space_info(vault_id), vault_id)


@mcp.tool()
async def vault_update(vault_id: str, description: str = "") -> dict:
    """
    Met à jour les métadonnées d'un vault (description).

    Args:
        vault_id: Identifiant du vault à modifier
        description: Nouvelle description du vault
    """
    from .auth.context import check_access, check_write_permission, check_policy
    from .vault.spaces import update_space

    policy_err = check_policy("vault_update")
    if policy_err:
        return policy_err
    access_err = check_access(vault_id)
    if access_err:
        return access_err
    write_err = check_write_permission()
    if write_err:
        return write_err

    if not description:
        return {"status": "error", "message": "Au moins un champ à modifier est requis (description)"}

    return _r("vault_update", await update_space(vault_id, description), vault_id)


@mcp.tool()
async def vault_delete(vault_id: str, confirm: bool = False) -> dict:
    """
    Supprime un vault et TOUS ses secrets (irréversible).

    Args:
        vault_id: Identifiant du vault à supprimer
        confirm: Doit être True pour confirmer la suppression
    """
    from .auth.context import check_access, check_admin_permission, check_policy
    from .vault.spaces import delete_space

    policy_err = check_policy("vault_delete")
    if policy_err:
        return policy_err
    access_err = check_access(vault_id)
    if access_err:
        return access_err
    admin_err = check_admin_permission()
    if admin_err:
        return admin_err

    if not confirm:
        return {"status": "error", "message": "confirm=True requis pour supprimer un vault"}

    return _r("vault_delete", await delete_space(vault_id), vault_id)


# ═══════════════════════════════════════════════════════════════════════
# OUTILS MCP — Secrets (KV v2)
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def secret_write(vault_id: str, path: str, data: dict,
                       secret_type: str = "custom", tags: str = "",
                       favorite: bool = False) -> dict:
    """
    Écrit un secret typé dans un vault.

    Types disponibles : login, password, secure_note, api_key, ssh_key,
    database, server, certificate, env_file, credit_card, identity,
    wifi, crypto_wallet, custom.

    Args:
        vault_id: Vault cible (coffre de secrets)
        path: Chemin du secret (ex: "web/github", "db/production")
        data: Données du secret (champs selon le type)
        secret_type: Type de secret (défaut: custom)
        tags: Tags séparés par des virgules (ex: "prod,critical")
        favorite: Marquer comme favori
    """
    from .auth.context import check_access, check_write_permission, check_policy, check_path_policy
    from .vault.secrets import write_secret

    policy_err = check_policy("secret_write")
    if policy_err:
        return policy_err
    access_err = check_access(vault_id)
    if access_err:
        return access_err
    path_err = check_path_policy(vault_id, path)
    if path_err:
        return path_err
    write_err = check_write_permission()
    if write_err:
        return write_err

    return _r("secret_write", await write_secret(vault_id, path, data, secret_type, tags, favorite), vault_id, path)


@mcp.tool()
async def secret_read(vault_id: str, path: str, version: int = 0) -> dict:
    """
    Lit un secret depuis un vault.

    Args:
        vault_id: Vault cible
        path: Chemin du secret
        version: Version spécifique (0 = dernière)
    """
    from .auth.context import check_access, check_policy, check_path_policy
    from .vault.secrets import read_secret

    policy_err = check_policy("secret_read")
    if policy_err:
        return policy_err
    access_err = check_access(vault_id)
    if access_err:
        return access_err
    path_err = check_path_policy(vault_id, path)
    if path_err:
        return path_err

    return _r("secret_read", await read_secret(vault_id, path, version), vault_id, path)


@mcp.tool()
async def secret_list(vault_id: str, path: str = "") -> dict:
    """
    Liste les secrets d'un vault.

    Args:
        vault_id: Vault cible
        path: Préfixe pour filtrer (optionnel)
    """
    from .auth.context import check_access, check_policy
    from .vault.secrets import list_secrets

    policy_err = check_policy("secret_list")
    if policy_err:
        return policy_err
    access_err = check_access(vault_id)
    if access_err:
        return access_err

    return _r("secret_list", await list_secrets(vault_id, path), vault_id)


@mcp.tool()
async def secret_delete(vault_id: str, path: str) -> dict:
    """
    Supprime un secret et toutes ses versions.

    Args:
        vault_id: Vault cible
        path: Chemin du secret à supprimer
    """
    from .auth.context import check_access, check_write_permission, check_policy, check_path_policy
    from .vault.secrets import delete_secret

    policy_err = check_policy("secret_delete")
    if policy_err:
        return policy_err
    access_err = check_access(vault_id)
    if access_err:
        return access_err
    path_err = check_path_policy(vault_id, path)
    if path_err:
        return path_err
    write_err = check_write_permission()
    if write_err:
        return write_err

    return _r("secret_delete", await delete_secret(vault_id, path), vault_id, path)


# ═══════════════════════════════════════════════════════════════════════
# OUTILS MCP — Types & Utilitaires
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def secret_types() -> dict:
    """
    Liste tous les types de secrets disponibles (style 1Password).

    Retourne les 14 types avec leurs champs requis et optionnels :
    login, password, secure_note, api_key, ssh_key, database, server,
    certificate, env_file, credit_card, identity, wifi, crypto_wallet, custom.
    """
    from .vault.types import list_types

    types = list_types()
    return {"status": "ok", "types": types, "count": len(types)}


@mcp.tool()
async def secret_generate_password(length: int = 24, uppercase: bool = True,
                                    lowercase: bool = True, digits: bool = True,
                                    symbols: bool = True, exclude: str = "") -> dict:
    """
    Génère un mot de passe cryptographiquement sûr (CSPRNG).

    Args:
        length: Longueur du mot de passe (8-128, défaut: 24)
        uppercase: Inclure des majuscules A-Z
        lowercase: Inclure des minuscules a-z
        digits: Inclure des chiffres 0-9
        symbols: Inclure des symboles !@#$%...
        exclude: Caractères à exclure (ex: "lI10O")
    """
    from .vault.types import generate_password

    password = generate_password(length, uppercase, lowercase, digits, symbols, exclude)
    return {
        "status": "ok",
        "password": password,
        "length": len(password),
        "charset": {
            "uppercase": uppercase,
            "lowercase": lowercase,
            "digits": digits,
            "symbols": symbols,
            "excluded": exclude,
        },
    }


# ═══════════════════════════════════════════════════════════════════════
# OUTILS MCP — Policies (Phase 8a — CRUD)
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def policy_create(policy_id: str, description: str = "",
                        allowed_tools: list = None, denied_tools: list = None,
                        path_rules: list = None) -> dict:
    """
    Crée une nouvelle policy MCP (contrôle d'accès granulaire).

    Une policy définit quels outils MCP sont accessibles et quelles
    permissions s'appliquent par vault. Assignable à un token via policy_id.

    Logique d'évaluation :
    - denied_tools a PRIORITÉ sur allowed_tools
    - allowed_tools vide = tous les outils autorisés (sauf denied)
    - Les patterns supportent les wildcards (ex: "ssh_*", "secret_*")

    Args:
        policy_id: Identifiant unique (alphanum + tirets, max 64 chars)
        description: Description lisible de la policy
        allowed_tools: Patterns d'outils autorisés (ex: ["system_*", "vault_list", "secret_read"])
        denied_tools: Patterns d'outils refusés (ex: ["vault_delete", "ssh_*"])
        path_rules: Règles par vault (ex: [{"vault_pattern": "prod-*", "permissions": ["read"]}])
    """
    from .auth.context import check_admin_permission, get_current_client_name
    from .auth.policies import get_policy_store

    admin_err = check_admin_permission()
    if admin_err:
        return admin_err

    store = get_policy_store()
    if not store:
        return {"status": "error", "message": "Policy Store non configuré (S3 requis)"}

    return store.create(
        policy_id=policy_id,
        description=description,
        allowed_tools=allowed_tools or [],
        denied_tools=denied_tools or [],
        path_rules=path_rules or [],
        created_by=get_current_client_name(),
    )


@mcp.tool()
async def policy_list() -> dict:
    """
    Liste toutes les policies MCP.

    Retourne un résumé de chaque policy (ID, description, compteurs).
    Requiert la permission admin.
    """
    from .auth.context import check_admin_permission
    from .auth.policies import get_policy_store

    admin_err = check_admin_permission()
    if admin_err:
        return admin_err

    store = get_policy_store()
    if not store:
        return {"status": "error", "message": "Policy Store non configuré (S3 requis)"}

    policies = store.list_all()
    return {"status": "ok", "policies": policies, "count": len(policies)}


@mcp.tool()
async def policy_get(policy_id: str) -> dict:
    """
    Détails complets d'une policy MCP.

    Retourne toutes les règles (allowed_tools, denied_tools, path_rules).
    Requiert la permission admin.

    Args:
        policy_id: Identifiant de la policy
    """
    from .auth.context import check_admin_permission
    from .auth.policies import get_policy_store

    admin_err = check_admin_permission()
    if admin_err:
        return admin_err

    store = get_policy_store()
    if not store:
        return {"status": "error", "message": "Policy Store non configuré (S3 requis)"}

    policy = store.get(policy_id)
    if not policy:
        return {"status": "error", "message": f"Policy '{policy_id}' non trouvée"}

    return {"status": "ok", **policy}


@mcp.tool()
async def policy_delete(policy_id: str, confirm: bool = False) -> dict:
    """
    Supprime une policy MCP (irréversible).

    ⚠️ Les tokens qui référencent cette policy perdront leur restriction.
    Le paramètre confirm doit être True pour confirmer.

    Args:
        policy_id: Identifiant de la policy à supprimer
        confirm: Doit être True pour confirmer la suppression
    """
    from .auth.context import check_admin_permission
    from .auth.policies import get_policy_store

    admin_err = check_admin_permission()
    if admin_err:
        return admin_err

    if not confirm:
        return {"status": "error", "message": "confirm=True requis pour supprimer une policy"}

    store = get_policy_store()
    if not store:
        return {"status": "error", "message": "Policy Store non configuré (S3 requis)"}

    if store.delete(policy_id):
        return {"status": "deleted", "policy_id": policy_id}
    else:
        return {"status": "error", "message": f"Policy '{policy_id}' non trouvée"}


# ═══════════════════════════════════════════════════════════════════════
# OUTILS MCP — SSH CA
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def ssh_ca_setup(vault_id: str, role_name: str, allowed_users: str = "*",
                       default_user: str = "ubuntu", ttl: str = "30m") -> dict:
    """
    Configure un rôle SSH CA dans un vault.

    Args:
        vault_id: Vault cible
        role_name: Nom du rôle SSH (ex: "prod-servers")
        allowed_users: Utilisateurs autorisés (virgules, * = tous)
        default_user: Utilisateur par défaut
        ttl: Durée de validité des certificats (ex: "30m", "1h")
    """
    from .auth.context import check_access, check_write_permission, check_policy
    from .vault.ssh_ca import setup_ssh_ca

    policy_err = check_policy("ssh_ca_setup")
    if policy_err:
        return policy_err
    access_err = check_access(vault_id)
    if access_err:
        return access_err
    write_err = check_write_permission()
    if write_err:
        return write_err

    return _r("ssh_ca_setup", await setup_ssh_ca(vault_id, role_name, allowed_users, default_user, ttl), vault_id, role_name)


@mcp.tool()
async def ssh_sign_key(vault_id: str, role_name: str, public_key: str,
                       ttl: str = "30m") -> dict:
    """
    Signe une clé publique SSH avec la CA du vault.

    Args:
        vault_id: Vault cible
        role_name: Rôle SSH à utiliser
        public_key: Contenu de la clé publique SSH
        ttl: Durée de validité du certificat
    """
    from .auth.context import check_access, check_policy
    from .vault.ssh_ca import sign_ssh_key

    policy_err = check_policy("ssh_sign_key")
    if policy_err:
        return policy_err
    access_err = check_access(vault_id)
    if access_err:
        return access_err

    return _r("ssh_sign_key", await sign_ssh_key(vault_id, role_name, public_key, ttl), vault_id, role_name)


@mcp.tool()
async def ssh_ca_public_key(vault_id: str) -> dict:
    """
    Récupère la clé publique de la CA SSH (pour configurer les serveurs cibles).

    Args:
        vault_id: Vault cible
    """
    from .auth.context import check_access, check_policy
    from .vault.ssh_ca import get_ca_public_key

    policy_err = check_policy("ssh_ca_public_key")
    if policy_err:
        return policy_err
    access_err = check_access(vault_id)
    if access_err:
        return access_err

    return _r("ssh_ca_public_key", await get_ca_public_key(vault_id), vault_id)


@mcp.tool()
async def ssh_ca_list_roles(vault_id: str) -> dict:
    """
    Liste les rôles SSH CA configurés dans un vault.

    Chaque rôle définit qui peut signer quoi (utilisateurs autorisés, TTL, extensions).

    Args:
        vault_id: Vault cible
    """
    from .auth.context import check_access, check_policy
    from .vault.ssh_ca import list_ssh_roles

    policy_err = check_policy("ssh_ca_list_roles")
    if policy_err:
        return policy_err
    access_err = check_access(vault_id)
    if access_err:
        return access_err

    return _r("ssh_ca_list_roles", await list_ssh_roles(vault_id), vault_id)


@mcp.tool()
async def ssh_ca_role_info(vault_id: str, role_name: str) -> dict:
    """
    Détails d'un rôle SSH CA (TTL, allowed_users, extensions, etc.).

    Args:
        vault_id: Vault cible
        role_name: Nom du rôle SSH à inspecter
    """
    from .auth.context import check_access, check_policy
    from .vault.ssh_ca import get_ssh_role_info

    policy_err = check_policy("ssh_ca_role_info")
    if policy_err:
        return policy_err
    access_err = check_access(vault_id)
    if access_err:
        return access_err

    return _r("ssh_ca_role_info", await get_ssh_role_info(vault_id, role_name), vault_id, role_name)


# ═══════════════════════════════════════════════════════════════════════
# OUTILS MCP — Token Management (Phase 8b)
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def token_update(hash_prefix: str, policy_id: str = "",
                       permissions: str = "", vaults: str = "") -> dict:
    """
    Met à jour un token existant (policy, permissions, vaults autorisés).

    Seuls les champs fournis (non vides) sont modifiés.
    Requiert la permission admin.

    Args:
        hash_prefix: Préfixe du hash du token à modifier (depuis token list)
        policy_id: Policy à assigner (vide = retirer la policy, "_remove" = retirer)
        permissions: Nouvelles permissions séparées par virgule (ex: "read,write")
        vaults: Vaults autorisés séparés par virgule (vide = pas de changement, "_all" = tous)
    """
    from .auth.context import check_admin_permission
    from .auth.token_store import get_token_store

    admin_err = check_admin_permission()
    if admin_err:
        return admin_err

    store = get_token_store()
    if not store:
        return {"status": "error", "message": "Token Store non configuré (S3 requis)"}

    # Préparer les champs à modifier (None = pas de changement)
    new_policy = None
    new_perms = None
    new_resources = None

    if policy_id:
        if policy_id == "_remove":
            new_policy = ""  # Retirer la policy
        else:
            # Vérifier que la policy existe
            from .auth.policies import get_policy_store
            pstore = get_policy_store()
            if pstore and not pstore.get(policy_id):
                return {"status": "error", "message": f"Policy '{policy_id}' non trouvée"}
            new_policy = policy_id

    if permissions:
        new_perms = [p.strip() for p in permissions.split(",") if p.strip()]

    if vaults:
        if vaults == "_all":
            new_resources = []  # Vide = accès à tous
        else:
            new_resources = [v.strip() for v in vaults.split(",") if v.strip()]

    return store.update(
        hash_prefix=hash_prefix,
        policy_id=new_policy,
        permissions=new_perms,
        allowed_resources=new_resources,
    )


# ═══════════════════════════════════════════════════════════════════════
# OUTILS MCP — Audit Log (Phase 8c)
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def audit_log(limit: int = 50, client: str = "", vault_id: str = "",
                    tool: str = "", category: str = "", status: str = "",
                    since: str = "") -> dict:
    """
    Journal d'audit — toutes les opérations MCP avec filtres.

    Retourne les événements les plus récents en premier. Chaque entrée
    contient : timestamp, client, outil, vault, statut, détail, durée.

    Filtres disponibles (combinables) :
    - client : nom du client (ex: "agent-sre")
    - vault_id : vault concerné (ex: "prod-servers")
    - tool : nom de l'outil (supporte préfixes, ex: "secret_*")
    - category : system, vault, secret, ssh, policy, token
    - status : ok, error, created, deleted, updated, denied
    - since : date ISO 8601 (ex: "2026-03-18T10:00:00")

    Args:
        limit: Nombre max d'entrées (défaut 50, max 1000)
        client: Filtrer par client
        vault_id: Filtrer par vault
        tool: Filtrer par outil (wildcards)
        category: Filtrer par catégorie
        status: Filtrer par statut
        since: Entrées après cette date
    """
    from .audit import get_audit_store

    store = get_audit_store()
    if not store:
        return {"status": "error", "message": "Audit Store non initialisé"}

    entries = store.get_entries(
        limit=limit, client=client, vault_id=vault_id,
        tool=tool, category=category, status=status, since=since,
    )
    stats = store.get_stats()

    return {
        "status": "ok",
        "entries": entries,
        "count": len(entries),
        "total_in_buffer": stats["total"],
        "stats": stats,
    }


# ═══════════════════════════════════════════════════════════════════════
# ASGI MIDDLEWARE STACK + MAIN
# ═══════════════════════════════════════════════════════════════════════

def create_app():
    """Construit la stack ASGI complète."""
    from .auth.middleware import AuthMiddleware, LoggingMiddleware, HealthCheckMiddleware
    from .admin.middleware import AdminMiddleware

    # Stack ASGI (ordre d'application : Admin → Health → Auth → Logging → MCP)
    app = mcp.streamable_http_app()
    app = LoggingMiddleware(app)
    app = AuthMiddleware(app, mcp)
    app = HealthCheckMiddleware(app)
    app = AdminMiddleware(app, mcp)

    return app


def main():
    """
    Point d'entrée principal avec lifecycle complet.

    Séquence :
    1. Afficher la bannière
    2. Construire la stack ASGI
    3. Lancer le startup (S3 download → OpenBao start → init → unseal → sync)
    4. Démarrer uvicorn (bloquant jusqu'à SIGTERM/SIGINT)
    5. Lancer le shutdown (sync stop → seal → S3 upload → stop OpenBao)
    """
    import asyncio
    import uvicorn

    version = Path("VERSION").read_text().strip() if Path("VERSION").exists() else "0.1.0"

    logger.info("=" * 60)
    logger.info(f"  🔐 MCP Vault v{version}")
    logger.info(f"  📡 Port: {settings.mcp_server_port}")
    logger.info(f"  🏛️  OpenBao: {settings.openbao_addr}")
    logger.info(f"  ☁️  S3: {settings.s3_bucket_name or '(non configuré)'}")
    logger.info("=" * 60)

    app = create_app()

    config = uvicorn.Config(
        app,
        host=settings.mcp_server_host,
        port=settings.mcp_server_port,
        log_level="info" if not settings.mcp_server_debug else "debug",
    )
    server = uvicorn.Server(config)

    async def serve_with_lifecycle():
        """Lance le lifecycle startup → serveur → shutdown."""
        from .lifecycle import vault_startup, vault_shutdown

        # ── STARTUP ──────────────────────────────────────────
        try:
            ok = await vault_startup()
            if not ok:
                logger.warning("⚠️ Démarrage en mode dégradé (OpenBao indisponible)")
        except Exception as e:
            logger.error(f"❌ Erreur critique au démarrage : {e}")
            logger.warning("⚠️ Démarrage en mode dégradé")

        # ── SERVEUR (bloquant jusqu'à SIGTERM/SIGINT) ────────
        try:
            await server.serve()
        except Exception as e:
            logger.error(f"❌ Erreur serveur : {e}")

        # ── SHUTDOWN ─────────────────────────────────────────
        try:
            await vault_shutdown()
        except Exception as e:
            logger.error(f"❌ Erreur au shutdown : {e}")

    asyncio.run(serve_with_lifecycle())
