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
    from .auth.context import check_access, check_write_permission
    from .vault.spaces import create_space

    access_err = check_access(vault_id)
    if access_err:
        return access_err
    write_err = check_write_permission()
    if write_err:
        return write_err

    return await create_space(vault_id, description)


@mcp.tool()
async def vault_list() -> dict:
    """Liste tous les vaults (coffres de secrets) accessibles par le token courant."""
    from .auth.context import current_token_info
    from .vault.spaces import list_spaces

    # ── Filtrage par token : les non-admin ne voient que leurs vaults ──
    token_info = current_token_info.get()
    allowed_vault_ids = None
    if token_info and "admin" not in token_info.get("permissions", []):
        allowed = token_info.get("vault_ids", [])
        if allowed:
            allowed_vault_ids = allowed

    return await list_spaces(allowed_vault_ids=allowed_vault_ids)


@mcp.tool()
async def vault_info(vault_id: str) -> dict:
    """
    Informations détaillées sur un vault.

    Args:
        vault_id: Identifiant du vault
    """
    from .auth.context import check_access
    from .vault.spaces import get_space_info

    access_err = check_access(vault_id)
    if access_err:
        return access_err

    return await get_space_info(vault_id)


@mcp.tool()
async def vault_update(vault_id: str, description: str = "") -> dict:
    """
    Met à jour les métadonnées d'un vault (description).

    Args:
        vault_id: Identifiant du vault à modifier
        description: Nouvelle description du vault
    """
    from .auth.context import check_access, check_write_permission
    from .vault.spaces import update_space

    access_err = check_access(vault_id)
    if access_err:
        return access_err
    write_err = check_write_permission()
    if write_err:
        return write_err

    if not description:
        return {"status": "error", "message": "Au moins un champ à modifier est requis (description)"}

    return await update_space(vault_id, description)


@mcp.tool()
async def vault_delete(vault_id: str, confirm: bool = False) -> dict:
    """
    Supprime un vault et TOUS ses secrets (irréversible).

    Args:
        vault_id: Identifiant du vault à supprimer
        confirm: Doit être True pour confirmer la suppression
    """
    from .auth.context import check_access, check_admin_permission
    from .vault.spaces import delete_space

    access_err = check_access(vault_id)
    if access_err:
        return access_err
    admin_err = check_admin_permission()
    if admin_err:
        return admin_err

    if not confirm:
        return {"status": "error", "message": "confirm=True requis pour supprimer un vault"}

    return await delete_space(vault_id)


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
    from .auth.context import check_access, check_write_permission
    from .vault.secrets import write_secret

    access_err = check_access(vault_id)
    if access_err:
        return access_err
    write_err = check_write_permission()
    if write_err:
        return write_err

    return await write_secret(vault_id, path, data, secret_type, tags, favorite)


@mcp.tool()
async def secret_read(vault_id: str, path: str, version: int = 0) -> dict:
    """
    Lit un secret depuis un vault.

    Args:
        vault_id: Vault cible
        path: Chemin du secret
        version: Version spécifique (0 = dernière)
    """
    from .auth.context import check_access
    from .vault.secrets import read_secret

    access_err = check_access(vault_id)
    if access_err:
        return access_err

    return await read_secret(vault_id, path, version)


@mcp.tool()
async def secret_list(vault_id: str, path: str = "") -> dict:
    """
    Liste les secrets d'un vault.

    Args:
        vault_id: Vault cible
        path: Préfixe pour filtrer (optionnel)
    """
    from .auth.context import check_access
    from .vault.secrets import list_secrets

    access_err = check_access(vault_id)
    if access_err:
        return access_err

    return await list_secrets(vault_id, path)


@mcp.tool()
async def secret_delete(vault_id: str, path: str) -> dict:
    """
    Supprime un secret et toutes ses versions.

    Args:
        vault_id: Vault cible
        path: Chemin du secret à supprimer
    """
    from .auth.context import check_access, check_write_permission
    from .vault.secrets import delete_secret

    access_err = check_access(vault_id)
    if access_err:
        return access_err
    write_err = check_write_permission()
    if write_err:
        return write_err

    return await delete_secret(vault_id, path)


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
# OUTILS MCP — SSH CA (Phase 3 — stubs)
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
    from .auth.context import check_access, check_write_permission
    from .vault.ssh_ca import setup_ssh_ca

    access_err = check_access(vault_id)
    if access_err:
        return access_err
    write_err = check_write_permission()
    if write_err:
        return write_err

    return await setup_ssh_ca(vault_id, role_name, allowed_users, default_user, ttl)


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
    from .auth.context import check_access
    from .vault.ssh_ca import sign_ssh_key

    access_err = check_access(vault_id)
    if access_err:
        return access_err

    return await sign_ssh_key(vault_id, role_name, public_key, ttl)


@mcp.tool()
async def ssh_ca_public_key(vault_id: str) -> dict:
    """
    Récupère la clé publique de la CA SSH (pour configurer les serveurs cibles).

    Args:
        vault_id: Vault cible
    """
    from .auth.context import check_access
    from .vault.ssh_ca import get_ca_public_key

    access_err = check_access(vault_id)
    if access_err:
        return access_err

    return await get_ca_public_key(vault_id)


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
