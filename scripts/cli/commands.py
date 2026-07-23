# -*- coding: utf-8 -*-
"""
CLI Click — MCP Vault : commandes scriptables.

Usage :
    python scripts/mcp_cli.py health
    python scripts/mcp_cli.py about
    python scripts/mcp_cli.py vault list
    python scripts/mcp_cli.py secret write myvault test/key --data '{"user":"me"}'
    python scripts/mcp_cli.py shell
"""

import asyncio
import click
from . import BASE_URL, TOKEN
from .client import MCPClient
from .display import (
    console, show_error, show_json,
    show_health_result, show_about_result, show_whoami_result,
    show_vault_result, show_secret_result,
    show_types_result, show_password_result,
    show_ssh_result, show_token_result,
    show_policy_result, show_audit_result, show_pki_result,
    show_wrap_result, show_mission_binding_result,
)


@click.group()
@click.option("--url", "-u", envvar=["MCP_URL"], default=BASE_URL, help="URL du serveur MCP")
@click.option("--token", "-t", envvar=["MCP_TOKEN"], default=TOKEN, help="Token d'authentification")
@click.pass_context
def cli(ctx, url, token):
    """🔐 CLI pour MCP Vault — Gestion sécurisée des secrets pour agents IA.

    \b
    Sécurité à 3 couches :
      1. Owner-based   — chaque token ne voit que ses propres vaults (par défaut)
      2. Vault-level   — restriction explicite via allowed_resources sur le token
      3. Path-level    — restriction par chemin via allowed_paths dans les policies
    """
    ctx.ensure_object(dict)
    ctx.obj["url"] = url
    ctx.obj["token"] = token


# =============================================================================
# Commandes système
# =============================================================================

@cli.command("health")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def health_cmd(ctx, output_json):
    """❤️  Vérifier l'état de santé (OpenBao + S3)."""
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("system_health", {})
        if output_json:
            show_json(result)
        else:
            show_health_result(result)
    asyncio.run(_run())


@cli.command("about")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def about_cmd(ctx, output_json):
    """ℹ️  Informations sur le service MCP Vault."""
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("system_about", {})
        if output_json:
            show_json(result)
        else:
            show_about_result(result)
    asyncio.run(_run())


@cli.command("whoami")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def whoami_cmd(ctx, output_json):
    """👤 Identité du token courant (nom, permissions, vaults autorisés)."""
    async def _run():
        import httpx
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                resp = await http.get(
                    f"{ctx.obj['url']}/admin/api/whoami",
                    headers={"Authorization": f"Bearer {ctx.obj['token']}"},
                )
                result = resp.json()
        except Exception as e:
            result = {"status": "error", "message": str(e)}
        if output_json:
            show_json(result)
        else:
            show_whoami_result(result)
    asyncio.run(_run())


# =============================================================================
# Vault Spaces (groupe)
# =============================================================================

@cli.group("vault")
@click.pass_context
def vault_group(ctx):
    """🏛️  Gestion des vaults (coffres de secrets KV v2).

    \b
    Sous-commandes : create, list, info, update, delete.
    Chaque vault est isolé — vous ne voyez que les vaults dont vous êtes propriétaire
    (sauf si votre token a des vaults explicitement autorisés, ou si vous êtes admin).
    """
    pass


@vault_group.command("create")
@click.argument("vault_id")
@click.option("--description", "-d", default="", help="Description du vault")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def vault_create_cmd(ctx, vault_id, description, output_json):
    """Créer un nouveau vault.

    \b
    Exemples :
      vault create serveurs-prod -d "Clés SSH production"
      vault create bdd-staging
    """
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("vault_create", {
            "vault_id": vault_id, "description": description,
        })
        if output_json:
            show_json(result)
        else:
            show_vault_result(result)
    asyncio.run(_run())


@vault_group.command("list")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def vault_list_cmd(ctx, output_json):
    """Lister tous les vaults accessibles."""
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("vault_list", {})
        if output_json:
            show_json(result)
        else:
            show_vault_result(result)
    asyncio.run(_run())


@vault_group.command("info")
@click.argument("vault_id")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def vault_info_cmd(ctx, vault_id, output_json):
    """Détails d'un vault (métadonnées, secrets_count, owner)."""
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("vault_info", {"vault_id": vault_id})
        if output_json:
            show_json(result)
        else:
            show_vault_result(result)
    asyncio.run(_run())


@vault_group.command("update")
@click.argument("vault_id")
@click.option("--description", "-d", required=True, help="Nouvelle description du vault")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def vault_update_cmd(ctx, vault_id, description, output_json):
    """Mettre à jour un vault (description).

    \b
    Exemples :
      vault update serveurs-prod -d "Clés SSH production v2"
    """
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("vault_update", {
            "vault_id": vault_id, "description": description,
        })
        if output_json:
            show_json(result)
        else:
            show_vault_result(result)
    asyncio.run(_run())


@vault_group.command("delete")
@click.argument("vault_id")
@click.option("--yes", "-y", is_flag=True, help="Confirmer la suppression sans prompt")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def vault_delete_cmd(ctx, vault_id, yes, output_json):
    """Supprimer un vault et TOUS ses secrets (⚠️ irréversible)."""
    if not yes:
        click.confirm(f"⚠️  Supprimer le vault '{vault_id}' et tous ses secrets ?", abort=True)
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("vault_delete", {
            "vault_id": vault_id, "confirm": True,
        })
        if output_json:
            show_json(result)
        else:
            show_vault_result(result)
    asyncio.run(_run())


# =============================================================================
# Secrets (groupe)
# =============================================================================

@cli.group("secret")
@click.pass_context
def secret_group(ctx):
    """🔑 Gestion des secrets (KV v2, typés style 1Password).

    \b
    Sous-commandes : write, read, list, delete, types, password.
    14 types : login, password, api_key, ssh_key, database, server, etc.
    """
    pass


@secret_group.command("write")
@click.argument("vault_id")
@click.argument("path")
@click.option("--data", "-d", required=True, help="Données JSON du secret")
@click.option("--type", "-t", "secret_type", default="custom", help="Type de secret (défaut: custom)")
@click.option("--tags", default="", help="Tags séparés par virgule")
@click.option("--favorite", is_flag=True, help="Marquer comme favori")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def secret_write_cmd(ctx, vault_id, path, data, secret_type, tags, favorite, output_json):
    """Écrire un secret typé.

    \b
    Exemples :
      secret write prod web/github -d '{"username":"me","password":"s3cr3t"}' -t login
      secret write staging db/main -d '{"host":"db.local","username":"root","password":"pw"}' -t database
    """
    import json as json_module
    try:
        secret_data = json_module.loads(data)
    except json_module.JSONDecodeError as e:
        show_error(f"JSON invalide : {e}")
        return
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("secret_write", {
            "vault_id": vault_id, "path": path, "data": secret_data,
            "secret_type": secret_type, "tags": tags, "favorite": favorite,
        })
        if output_json:
            show_json(result)
        else:
            show_secret_result(result)
    asyncio.run(_run())


@secret_group.command("read")
@click.argument("vault_id")
@click.argument("path")
@click.option("--version", "-v", "ver", default=0, type=int, help="Version spécifique (0=dernière)")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def secret_read_cmd(ctx, vault_id, path, ver, output_json):
    """Lire un secret.

    \b
    Exemples :
      secret read prod web/github
      secret read staging db/main --version 2
    """
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("secret_read", {
            "vault_id": vault_id, "path": path, "version": ver,
        })
        if output_json:
            show_json(result)
        else:
            show_secret_result(result)
    asyncio.run(_run())


@secret_group.command("list")
@click.argument("vault_id")
@click.option("--prefix", "-p", default="", help="Préfixe pour filtrer")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def secret_list_cmd(ctx, vault_id, prefix, output_json):
    """Lister les clés d'un vault (pas les valeurs).

    \b
    Exemples :
      secret list prod
      secret list staging --prefix db/
    """
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("secret_list", {
            "vault_id": vault_id, "path": prefix,
        })
        if output_json:
            show_json(result)
        else:
            show_secret_result(result)
    asyncio.run(_run())


@secret_group.command("delete")
@click.argument("vault_id")
@click.argument("path")
@click.option("--yes", "-y", is_flag=True, help="Confirmer sans prompt")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def secret_delete_cmd(ctx, vault_id, path, yes, output_json):
    """Supprimer un secret (toutes versions, ⚠️ irréversible)."""
    if not yes:
        click.confirm(f"⚠️  Supprimer le secret '{path}' dans '{vault_id}' ?", abort=True)
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("secret_delete", {
            "vault_id": vault_id, "path": path,
        })
        if output_json:
            show_json(result)
        else:
            show_secret_result(result)
    asyncio.run(_run())


@secret_group.command("types")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def secret_types_cmd(ctx, output_json):
    """Lister les 14 types de secrets disponibles."""
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("secret_types", {})
        if output_json:
            show_json(result)
        else:
            show_types_result(result)
    asyncio.run(_run())


@secret_group.command("password")
@click.option("--length", "-l", default=24, type=int, help="Longueur (8-128, défaut: 24)")
@click.option("--no-symbols", is_flag=True, help="Sans symboles")
@click.option("--no-uppercase", is_flag=True, help="Sans majuscules")
@click.option("--exclude", "-x", default="", help="Caractères à exclure")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def secret_password_cmd(ctx, length, no_symbols, no_uppercase, exclude, output_json):
    """Générer un mot de passe sécurisé (CSPRNG).

    \b
    Exemples :
      secret password
      secret password -l 32
      secret password -l 16 --no-symbols
    """
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("secret_generate_password", {
            "length": length, "symbols": not no_symbols,
            "uppercase": not no_uppercase, "exclude": exclude,
        })
        if output_json:
            show_json(result)
        else:
            show_password_result(result)
    asyncio.run(_run())


@secret_group.command("consume")
@click.argument("operation_id")
@click.option("--wrap-token", "wrap_token",
              envvar="VAULT_WRAP_TOKEN", required=True,
              help="Token de déballage OpenBao (SENSIBLE — utiliser VAULT_WRAP_TOKEN)")
@click.option("--mission-token", "mission_token",
              envvar="VAULT_MISSION_TOKEN", default="",
              help="JWT mission_token ES256 (SENSIBLE — utiliser VAULT_MISSION_TOKEN)")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def secret_consume_cmd(ctx, operation_id, wrap_token, mission_token, output_json):
    """Libérer un secret via wrap_token avec validation JWT (anti-confused-deputy C18).

    \b
    OPERATION_ID : Identifiant de l'opération (corrélation registry)

    \b
    Tokens sensibles passés via variables d'environnement (pas dans l'historique bash) :
      VAULT_WRAP_TOKEN    = token de déballage OpenBao (single-use)
      VAULT_MISSION_TOKEN = JWT mission_token ES256 (si mcp-mission configuré)

    \b
    Exemples :
      VAULT_WRAP_TOKEN=hvs.CAES... mcp-vault secret consume op-123
      VAULT_WRAP_TOKEN=... VAULT_MISSION_TOKEN=eyJ... mcp-vault secret consume op-123
    """
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("secret_consume", {
            "wrap_token": wrap_token,
            "operation_id": operation_id,
            "mission_token": mission_token,
        })
        if output_json:
            show_json(result)
        else:
            show_secret_result(result)
    asyncio.run(_run())


@secret_group.command("wrap")
@click.argument("vault_id")
@click.argument("secret_path")
@click.option("--mission-id", "mission_id", required=True, help="Identifiant de mission (scope)")
@click.option("--operation-id", "operation_id", required=True, help="Corrélation write-ahead (compensation)")
@click.option("--ttl", "ttl_seconds", type=int, default=300, help="TTL du wrap token en secondes (60-3600)")
@click.option("--tenant-id", "tenant_id", default="", help="Binding C18 — tenant_id attendu (optionnel)")
@click.option("--expected-aud", "expected_aud", default="", help="Binding C18 — audience attendue (optionnel)")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def secret_wrap_cmd(ctx, vault_id, secret_path, mission_id, operation_id,
                    ttl_seconds, tenant_id, expected_aud, output_json):
    """Créer un wrap token single-use pour un secret (contrat JIT broker mcp-mission).

    \b
    Outil machine-to-machine (CredentialBrokerService) — exposé au CLI pour le
    debug, les tests de contrat et l'exploitation. Le wrap_token retourné est
    SENSIBLE (single-use, à ne jamais logguer).

    \b
    Exemples :
      mcp-vault secret wrap prod db/postgres --mission-id m-42 --operation-id op-1
      mcp-vault secret wrap prod db/pg --mission-id m-42 --operation-id op-1 --tenant-id t-7 --expected-aud mcp-vault:prod
    """
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("secret_wrap", {
            "vault_id": vault_id,
            "secret_path": secret_path,
            "mission_id": mission_id,
            "operation_id": operation_id,
            "ttl_seconds": ttl_seconds,
            "tenant_id": tenant_id,
            "expected_aud": expected_aud,
        })
        if output_json:
            show_json(result)
        else:
            show_wrap_result(result)
    asyncio.run(_run())


@secret_group.command("revoke-wrap")
@click.argument("lease_id")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def secret_revoke_wrap_cmd(ctx, lease_id, output_json):
    """Révoquer un wrap token (idempotent — introuvable = succès).

    \b
    LEASE_ID : accessor du wrap token (retourné par `secret wrap`).
    """
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("secret_revoke_wrap", {"lease_id": lease_id})
        if output_json:
            show_json(result)
        else:
            show_wrap_result(result)
    asyncio.run(_run())


@secret_group.command("wrap-lookup")
@click.argument("operation_id")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def secret_wrap_lookup_cmd(ctx, operation_id, output_json):
    """Retrouver et RÉVOQUER les wraps d'un operation_id (compensation orphelins).

    \b
    OPERATION_ID : identifiant d'opération à rechercher dans le registry.
    ⚠️ Révoque les wraps trouvés. Pour consulter sans effet de bord : wrap-status.
    """
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("secret_wrap_lookup", {"operation_id": operation_id})
        if output_json:
            show_json(result)
        else:
            show_wrap_result(result)
    asyncio.run(_run())


@secret_group.command("wrap-status")
@click.argument("operation_id")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def secret_wrap_status_cmd(ctx, operation_id, output_json):
    """Consulter l'état d'un wrap par operation_id (LECTURE SEULE, ne révoque pas).

    \b
    OPERATION_ID : identifiant d'opération à consulter dans le registry.
    Instantané best-effort ; contrairement à wrap-lookup, ne révoque rien (#77).
    """
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("secret_wrap_status", {"operation_id": operation_id})
        if output_json:
            show_json(result)
        else:
            show_wrap_result(result)
    asyncio.run(_run())


# =============================================================================
# SSH CA (groupe)
# =============================================================================

@cli.group("ssh")
@click.pass_context
def ssh_group(ctx):
    """🔏 SSH Certificate Authority (signature de clés éphémères).

    \b
    Sous-commandes : profiles, request, setup, sign, ca-key, roles, role-info.
    """
    pass


@ssh_group.command("profiles")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def ssh_profiles_cmd(ctx, output_json):
    """Lister les profils JIT disponibles pour le bearer courant."""
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("ssh_operator_access_profiles", {})
        if output_json:
            show_json(result)
        else:
            show_ssh_result(result)
    asyncio.run(_run())


@ssh_group.command("request")
@click.argument("profile_id")
@click.option("--key", "-k", "public_key_file", type=click.Path(exists=True, dir_okay=False),
              help="Fichier de clé publique OpenSSH pré-enrôlée")
@click.option("--key-data", default=None, help="Clé publique OpenSSH pré-enrôlée (texte)")
@click.option("--reason", required=True, help="Motif opérationnel obligatoire")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def ssh_request_cmd(ctx, profile_id, public_key_file, key_data, reason, output_json):
    """Demander un certificat SSH JIT sur un profil préautorisé.

    Le rôle, le principal, la cible et le TTL sont imposés côté serveur.
    """
    if public_key_file:
        with open(public_key_file, "r", encoding="utf-8") as handle:
            public_key = handle.read().strip()
    elif key_data:
        public_key = key_data.strip()
    else:
        show_error("Spécifiez --key (fichier) ou --key-data (texte)")
        return

    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("ssh_request_operator_access", {
            "profile_id": profile_id,
            "public_key": public_key,
            "reason": reason,
        })
        if output_json:
            show_json(result)
        else:
            show_ssh_result(result)
    asyncio.run(_run())


@ssh_group.command("setup")
@click.argument("vault_id")
@click.argument("role_name")
@click.option("--users", default="*", help="Utilisateurs autorisés (virgules, *=tous)")
@click.option("--default-user", default="ubuntu", help="Utilisateur par défaut")
@click.option("--ttl", default="30m", help="TTL des certificats")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def ssh_setup_cmd(ctx, vault_id, role_name, users, default_user, ttl, output_json):
    """Configurer un rôle SSH CA.

    \b
    Exemples :
      ssh setup prod-servers sre-role --users deploy,admin --ttl 15m
    """
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("ssh_ca_setup", {
            "vault_id": vault_id, "role_name": role_name,
            "allowed_users": users, "default_user": default_user, "ttl": ttl,
        })
        if output_json:
            show_json(result)
        else:
            show_ssh_result(result)
    asyncio.run(_run())


@ssh_group.command("sign")
@click.argument("vault_id")
@click.argument("role_name")
@click.option("--key", "-k", "public_key_file", type=click.Path(exists=True), help="Fichier clé publique SSH")
@click.option("--key-data", default=None, help="Clé publique SSH (texte)")
@click.option("--ttl", default="30m", help="TTL du certificat")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def ssh_sign_cmd(ctx, vault_id, role_name, public_key_file, key_data, ttl, output_json):
    """Signer une clé publique SSH (certificat éphémère).

    \b
    Exemples :
      ssh sign prod-servers sre-role -k ~/.ssh/id_ed25519.pub
      ssh sign staging dev-role --key-data "ssh-ed25519 AAAA..."
    """
    if public_key_file:
        with open(public_key_file, "r") as f:
            pub_key = f.read().strip()
    elif key_data:
        pub_key = key_data
    else:
        show_error("Spécifiez --key (fichier) ou --key-data (texte)")
        return
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("ssh_sign_key", {
            "vault_id": vault_id, "role_name": role_name,
            "public_key": pub_key, "ttl": ttl,
        })
        if output_json:
            show_json(result)
        else:
            show_ssh_result(result)
    asyncio.run(_run())


@ssh_group.command("ca-key")
@click.argument("vault_id")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def ssh_ca_key_cmd(ctx, vault_id, output_json):
    """Récupérer la clé publique CA (pour TrustedUserCAKeys)."""
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("ssh_ca_public_key", {"vault_id": vault_id})
        if output_json:
            show_json(result)
        else:
            show_ssh_result(result)
    asyncio.run(_run())


@ssh_group.command("roles")
@click.argument("vault_id")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def ssh_roles_cmd(ctx, vault_id, output_json):
    """Lister les rôles SSH CA d'un vault.

    \b
    Exemples :
      ssh roles llmaas-infra
    """
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("ssh_ca_list_roles", {"vault_id": vault_id})
        if output_json:
            show_json(result)
        else:
            show_ssh_result(result)
    asyncio.run(_run())


@ssh_group.command("role-info")
@click.argument("vault_id")
@click.argument("role_name")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def ssh_role_info_cmd(ctx, vault_id, role_name, output_json):
    """Détails d'un rôle SSH CA (TTL, allowed_users, etc.).

    \b
    Exemples :
      ssh role-info llmaas-infra adminct
      ssh role-info prod-servers agentic
    """
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("ssh_ca_role_info", {
            "vault_id": vault_id, "role_name": role_name,
        })
        if output_json:
            show_json(result)
        else:
            show_ssh_result(result)
    asyncio.run(_run())


# =============================================================================
# PKI Certificate Authority (groupe admin — issue #15)
# =============================================================================

@cli.group("pki")
@click.pass_context
def pki_group(ctx):
    """🔐 PKI interne — CA OpenBao + serveur ACME.

    \b
    Sous-commandes : setup, ca-key, roles, role-info, certs, revoke, rotate.
    """
    pass


@pki_group.command("setup")
@click.option("--lab/--prod", default=True, help="Lab=CA self-signed, prod=CSR pour CA externe")
@click.option("--domains", default="*.lesur.lan,lesur.lan", help="Domaines ACME autorisés (virgules)")
@click.option("--ttl", default="720h", help="TTL max des certificats feuilles")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def pki_setup_cmd(ctx, lab, domains, ttl, output_json):
    """Initialiser la PKI interne (CA racine + intermédiaire + ACME).

    \b
    Exemples :
      pki setup --lab --domains '*.lesur.lan,lesur.lan'
      pki setup --prod --domains 'mcp.cloud-temple.app' --ttl 720h
    """
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("pki_ca_setup", {
            "lab_mode": lab,
            "allowed_domains": domains,
            "leaf_ttl": ttl,
        })
        if output_json:
            show_json(result)
        else:
            show_pki_result(result)
    asyncio.run(_run())


@pki_group.command("ca-key")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def pki_ca_key_cmd(ctx, output_json):
    """Afficher la CA racine PEM (empreinte SHA-256 + URL stable)."""
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("pki_ca_public_key", {})
        if output_json:
            show_json(result)
        else:
            show_pki_result(result)
    asyncio.run(_run())


@pki_group.command("roles")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def pki_roles_cmd(ctx, output_json):
    """Lister les rôles d'émission PKI."""
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("pki_ca_list_roles", {})
        if output_json:
            show_json(result)
        else:
            show_pki_result(result)
    asyncio.run(_run())


@pki_group.command("role-info")
@click.argument("role_name")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def pki_role_info_cmd(ctx, role_name, output_json):
    """Détails d'un rôle d'émission PKI (domaines, TTL, flags TLS).

    \b
    Exemples :
      pki role-info acme-servers
    """
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("pki_ca_role_info", {"role_name": role_name})
        if output_json:
            show_json(result)
        else:
            show_pki_result(result)
    asyncio.run(_run())


@pki_group.command("certs")
@click.option("--limit", default=100, type=int, help="Nombre max de certificats")
@click.option("--offset", default=0, type=int, help="Offset de pagination")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def pki_certs_cmd(ctx, limit, offset, output_json):
    """Inventaire des certificats émis (serial, SANs, expiration, statut).

    \b
    Exemples :
      pki certs
      pki certs --limit 20 --offset 20
    """
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("pki_list_certs", {"limit": limit, "offset": offset})
        if output_json:
            show_json(result)
        else:
            show_pki_result(result)
    asyncio.run(_run())


@pki_group.command("issue")
@click.argument("common_name")
@click.option("--ttl", default="720h", help="Durée de validité (ex: 720h, 30m, 90d)")
@click.option("--alt-names", "alt_names", default="", help="SANs DNS supplémentaires (virgules)")
@click.option("--ip-sans", "ip_sans", default="", help="SANs IP (virgules)")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def pki_issue_cmd(ctx, common_name, ttl, alt_names, ip_sans, output_json):
    """Émettre un certificat serveur signé par la CA intermédiaire (émission manuelle).

    \b
    ⚠️  La clé privée est affichée UNE FOIS — la sauvegarder immédiatement.
        Le common_name doit appartenir aux domaines autorisés de la PKI.

    \b
    Exemples :
      pki issue www.cloud-temple.app
      pki issue api.cloud-temple.app --ttl 2160h --alt-names api2.cloud-temple.app
      pki issue node1.cloud-temple.app --ip-sans 10.0.0.4
    """
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("pki_issue_cert", {
            "common_name": common_name,
            "ttl": ttl,
            "alt_names": alt_names,
            "ip_sans": ip_sans,
        })
        if output_json:
            show_json(result)
        else:
            show_pki_result(result)
    asyncio.run(_run())


@pki_group.command("revoke")
@click.argument("serial_number")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def pki_revoke_cmd(ctx, serial_number, output_json):
    """Révoquer un certificat et mettre à jour la CRL.

    \b
    Exemples :
      pki revoke 12:34:ab:cd:ef:12:34:56
    """
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("pki_revoke_cert", {"serial_number": serial_number})
        if output_json:
            show_json(result)
        else:
            show_pki_result(result)
    asyncio.run(_run())


@pki_group.command("rotate")
@click.option("--keep-old/--no-keep-old", default=True, help="Conserver l'ancien issuer")
@click.option("--overlap", default="48h", help="Durée de chevauchement documentée")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def pki_rotate_cmd(ctx, keep_old, overlap, output_json):
    """Rotation sans coupure de la CA intermédiaire.

    \b
    Les certificats existants restent valides si --keep-old (défaut).
    Les nouvelles émissions utilisent le nouvel issuer immédiatement.
    """
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("pki_ca_rotate_intermediate", {
            "keep_old_issuer": keep_old,
            "overlap_ttl": overlap,
        })
        if output_json:
            show_json(result)
        else:
            show_pki_result(result)
    asyncio.run(_run())


# =============================================================================
# Policies (groupe admin)
# =============================================================================

@cli.group("policy")
@click.pass_context
def policy_group(ctx):
    """📋 Gestion des policies MCP (contrôle d'accès granulaire, admin).

    \b
    Sous-commandes : create, list, get, delete.

    \b
    Une policy contrôle 3 niveaux d'accès :
      - allowed_tools / denied_tools : quels outils MCP (wildcards: ssh_*)
      - path_rules  : quels vaults et quels chemins de secrets
    Les denied_tools sont TOUJOURS prioritaires sur les allowed_tools.
    """
    pass


@policy_group.command("create")
@click.argument("policy_id")
@click.option("--description", "-d", default="", help="Description de la policy")
@click.option("--allowed", "-a", default="", help="Outils autorisés (virgule, wildcards, ex: 'secret_*,vault_list')")
@click.option("--denied", "-D", default="", help="Outils refusés (virgule, PRIORITAIRE, ex: 'vault_delete')")
@click.option("--path-rules", "-R", "path_rules_json", default="",
              help="Règles par chemin JSON (ex: '[{\"vault_pattern\":\"shared-*\",\"permissions\":[\"read\"],\"allowed_paths\":[\"shared/*\"]}]')")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def policy_create_cmd(ctx, policy_id, description, allowed, denied, path_rules_json, output_json):
    """Créer une policy MCP (contrôle d'accès outils + chemins).

    \b
    Exemples simples (outils) :
      policy create readonly -d "Lecture seule" --allowed "system_*,vault_list,secret_read,secret_list"
      policy create no-ssh -d "Pas de SSH" --denied "ssh_*"
      policy create full-except-delete --denied "vault_delete,secret_delete"

    \b
    Exemple avancé (restriction par chemin de secret) :
      policy create team-alice -d "Accès shared/* uniquement" \\
        --allowed "secret_*,vault_list" \\
        --path-rules '[{"vault_pattern":"shared-*","permissions":["read","write"],"allowed_paths":["shared/*","config/*"]}]'

    \b
    Structure d'une path_rule :
      vault_pattern  — pattern fnmatch du vault (ex: "prod-*", "shared-*")
      permissions    — ["read"], ["read","write"], ou ["read","write","admin"]
      allowed_paths  — patterns de chemins autorisés (ex: ["shared/*", "db/*"])
                       vide = tous les chemins du vault sont accessibles
    """
    import json as json_module
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        at = [t.strip() for t in allowed.split(",") if t.strip()] if allowed else []
        dt = [t.strip() for t in denied.split(",") if t.strip()] if denied else []
        pr = []
        if path_rules_json:
            try:
                pr = json_module.loads(path_rules_json)
                if not isinstance(pr, list):
                    show_error("--path-rules doit être un tableau JSON (ex: '[{...}]')")
                    return
            except json_module.JSONDecodeError as e:
                show_error(f"JSON invalide dans --path-rules : {e}")
                return
        result = await client.call_tool("policy_create", {
            "policy_id": policy_id, "description": description,
            "allowed_tools": at, "denied_tools": dt,
            "path_rules": pr,
        })
        if output_json:
            show_json(result)
        else:
            show_policy_result(result)
    asyncio.run(_run())


@policy_group.command("list")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def policy_list_cmd(ctx, output_json):
    """Lister toutes les policies."""
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("policy_list", {})
        if output_json:
            show_json(result)
        else:
            show_policy_result(result)
    asyncio.run(_run())


@policy_group.command("get")
@click.argument("policy_id")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def policy_get_cmd(ctx, policy_id, output_json):
    """Détails complets d'une policy (allowed/denied tools, path rules)."""
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("policy_get", {"policy_id": policy_id})
        if output_json:
            show_json(result)
        else:
            show_policy_result(result)
    asyncio.run(_run())


@policy_group.command("delete")
@click.argument("policy_id")
@click.option("--yes", "-y", is_flag=True, help="Confirmer sans prompt")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def policy_delete_cmd(ctx, policy_id, yes, output_json):
    """Supprimer une policy (⚠️ irréversible)."""
    if not yes:
        click.confirm(f"⚠️  Supprimer la policy '{policy_id}' ?", abort=True)
    async def _run():
        client = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await client.call_tool("policy_delete", {
            "policy_id": policy_id, "confirm": True,
        })
        if output_json:
            show_json(result)
        else:
            show_policy_result(result)
    asyncio.run(_run())


# =============================================================================
# Token management (groupe admin)
# =============================================================================

@cli.group("token")
@click.pass_context
def token_group(ctx):
    """🎫 Gestion des tokens d'accès MCP (admin).

    \b
    Sous-commandes : create, list, update, revoke.

    \b
    Comportement par défaut (vaults vide) :
      Le token ne voit que les vaults qu'il a créés (owner-based isolation).
      Pour donner accès à des vaults spécifiques, utilisez --vaults.
      Pour assigner une policy de sécurité, utilisez --policy ou token update.
    """
    pass


class _ExpiresDaysType(click.ParamType):
    """Contrat #65 STRICT (aligné front/API, un seul contrat auditable) : entier ASCII
    [0, 36500], 0 = jamais. isascii()+isdigit() = [0-9]+ pur → rejette non-entier, négatif,
    '+5', chiffres non-ASCII ('٥'), float. Pas de coercition (contrairement à IntRange/int())."""
    name = "days"

    def convert(self, value, param, ctx):
        if isinstance(value, int) and not isinstance(value, bool):
            n = value  # valeur par défaut (90) déjà entière
        elif isinstance(value, str) and value.isascii() and value.isdigit():
            n = int(value)
        else:
            self.fail(f"{value!r} : entier de jours attendu (0=jamais, sans signe ni décimale)", param, ctx)
        if n > 36500:
            self.fail(f"{value!r} : hors borne (max 36500)", param, ctx)
        return n


_EXPIRES_DAYS = _ExpiresDaysType()


@token_group.command("create")
@click.argument("name")
@click.option("--permissions", "-p", default="read,write", help="Permissions (virgule: read,write,admin)")
@click.option("--vaults", "-s", default="", help="Vaults autorisés (virgule, vide = owner-based)")
@click.option("--policy", default="", help="Policy ID à assigner (contrôle outils + chemins)")
@click.option("--expires", "-e", default=90, type=_EXPIRES_DAYS,
              help="Expiration en jours (0=jamais, max 36500)")
@click.option("--email", default="", help="Email du propriétaire")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def token_create_cmd(ctx, name, permissions, vaults, policy, expires, email, output_json):
    """Créer un nouveau token d'accès.

    \b
    Par défaut (vaults vide), le token ne voit que les vaults qu'il crée.
    Utilisez --vaults pour donner accès à des vaults spécifiques.
    Utilisez --policy pour restreindre les outils et chemins de secrets.

    \b
    Exemples :
      token create agent-sre --vaults serveurs-prod --permissions read
      token create admin-user --permissions admin --expires 365
      token create ci-cd --email ci@company.com --permissions read,write
      token create agent-deploy --policy readonly --vaults prod-app
    """
    async def _run():
        perms = [p.strip() for p in permissions.split(",") if p.strip()]
        vault_list_ids = [s.strip() for s in vaults.split(",") if s.strip()] if vaults else []
        import httpx
        payload = {
            "client_name": name,
            "permissions": perms,
            "allowed_resources": vault_list_ids,
            "expires_in_days": expires,
            "email": email,
        }
        if policy:
            payload["policy_id"] = policy
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                resp = await http.post(
                    f"{ctx.obj['url']}/admin/api/tokens",
                    headers={"Authorization": f"Bearer {ctx.obj['token']}"},
                    json=payload,
                )
                result = resp.json()
        except Exception as e:
            result = {"status": "error", "message": str(e)}
        if output_json:
            show_json(result)
        else:
            show_token_result(result)
    asyncio.run(_run())


@token_group.command("list")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def token_list_cmd(ctx, output_json):
    """Lister tous les tokens."""
    async def _run():
        import httpx
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                resp = await http.get(
                    f"{ctx.obj['url']}/admin/api/tokens",
                    headers={"Authorization": f"Bearer {ctx.obj['token']}"},
                )
                result = resp.json()
        except Exception as e:
            result = {"status": "error", "message": str(e)}
        if output_json:
            show_json(result)
        else:
            show_token_result(result)
    asyncio.run(_run())


@token_group.command("update")
@click.argument("hash_prefix")
@click.option("--policy", default="", help="Policy ID à assigner (vide = retirer)")
@click.option("--permissions", "-p", default="", help="Nouvelles permissions (virgule)")
@click.option("--vaults", default="", help="Vaults autorisés (virgule, '_all' = tous)")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def token_update_cmd(ctx, hash_prefix, policy, permissions, vaults, output_json):
    """Modifier un token (policy, permissions, vaults).

    \b
    Exemples :
      token update abc123 --policy readonly
      token update abc123 --policy _remove
      token update abc123 --permissions read --vaults prod-servers
    """
    async def _run():
        import httpx
        data = {}
        if policy:
            data["policy_id"] = "" if policy == "_remove" else policy
        if permissions:
            data["permissions"] = [p.strip() for p in permissions.split(",") if p.strip()]
        if vaults:
            if vaults == "_all":
                data["allowed_resources"] = []
            else:
                data["allowed_resources"] = [v.strip() for v in vaults.split(",") if v.strip()]
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                resp = await http.put(
                    f"{ctx.obj['url']}/admin/api/tokens/{hash_prefix}",
                    headers={"Authorization": f"Bearer {ctx.obj['token']}"},
                    json=data,
                )
                result = resp.json()
        except Exception as e:
            result = {"status": "error", "message": str(e)}
        if output_json:
            show_json(result)
        else:
            show_policy_result(result)
    asyncio.run(_run())


@token_group.command("revoke")
@click.argument("hash_prefix")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def token_revoke_cmd(ctx, hash_prefix, output_json):
    """Révoquer un token par préfixe de hash."""
    async def _run():
        import httpx
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                resp = await http.delete(
                    f"{ctx.obj['url']}/admin/api/tokens/{hash_prefix}",
                    headers={"Authorization": f"Bearer {ctx.obj['token']}"},
                )
                result = resp.json()
        except Exception as e:
            result = {"status": "error", "message": str(e)}
        if output_json:
            show_json(result)
        else:
            show_token_result(result)
    asyncio.run(_run())


@token_group.command("purge-revoked")
@click.option("--older-than", type=int, default=30, show_default=True,
              help="Ne purger que les tokens révoqués depuis plus de N jours")
@click.option("--dry-run", is_flag=True, help="Lister les candidats sans rien supprimer")
@click.option("--yes", "-y", is_flag=True, help="Confirmer la purge sans prompt")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def token_purge_revoked_cmd(ctx, older_than, dry_run, yes, output_json):
    """Purger définitivement les tokens révoqués depuis plus de N jours (irréversible)."""
    async def _run():
        import httpx
        base = ctx.obj["url"]
        headers = {"Authorization": f"Bearer {ctx.obj['token']}"}
        # Toujours un dry-run d'abord pour connaître le décompte
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                preview = (await http.post(f"{base}/admin/api/tokens/purge", headers=headers,
                           json={"older_than_days": older_than, "dry_run": True})).json()
        except Exception as e:
            preview = {"status": "error", "message": str(e)}
        if preview.get("status") != "ok":
            return show_json(preview) if output_json else show_token_result(preview)

        n = preview.get("count", 0)
        if dry_run:
            return show_json(preview) if output_json else show_token_result(preview)
        if n == 0:
            if output_json:
                show_json(preview)
            else:
                click.echo(f"Aucun token révoqué depuis plus de {older_than} jours à purger.")
            return
        if not yes:
            click.confirm(f"Purger DÉFINITIVEMENT {n} token(s) révoqué(s) depuis >{older_than}j ? Irréversible.",
                          abort=True)
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                result = (await http.post(f"{base}/admin/api/tokens/purge", headers=headers,
                          json={"older_than_days": older_than, "dry_run": False})).json()
        except Exception as e:
            result = {"status": "error", "message": str(e)}
        show_json(result) if output_json else show_token_result(result)
    asyncio.run(_run())


# =============================================================================
# Mission Bindings (octroi périmètre vault mission JWT, #69) — groupe admin
# =============================================================================

@cli.group("mission-binding")
@click.pass_context
def mission_binding_group(ctx):
    """🎟️  Octroi de périmètre vault aux identités mission JWT (admin).

    \b
    Sous-commandes : create, list, get, delete, purge.

    \b
    Un binding associe à un tenant (client mission) un périmètre local sur CETTE
    instance : coffres autorisés + permissions (read | read,write). Sans binding,
    une mission n'a AUCUN accès (deny-by-default). Data-plane strict : une mission
    ne peut jamais créer/détruire un coffre ni gérer une CA SSH.
    """
    pass


@mission_binding_group.command("create")
@click.argument("tenant_id")
@click.option("--vaults", "-s", required=True, help="Coffres autorisés (virgule) — requis, non vide")
@click.option("--permissions", "-p", default="read", help="read | read,write ('write' seul refusé)")
@click.option("--policy", default="", help="Policy ID optionnelle (durcissement path/tool)")
@click.option("--expires-at", default="", help="Expiration ISO 8601 (vide = jamais)")
@click.option("--disabled", is_flag=True, help="Créer le binding désactivé")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def mission_binding_create_cmd(ctx, tenant_id, vaults, permissions, policy, expires_at, disabled, output_json):
    """Octroyer un périmètre vault à un tenant mission.

    \b
    Exemples :
      mission-binding create acme-corp --vaults prod-app --permissions read
      mission-binding create acme-corp --vaults prod-app,staging --permissions read,write
      mission-binding create acme-corp --vaults prod-app --policy readonly --expires-at 2026-12-31T00:00:00+00:00
    """
    async def _run():
        import httpx
        perms = [p.strip() for p in permissions.split(",") if p.strip()]
        vault_ids = [v.strip() for v in vaults.split(",") if v.strip()]
        payload = {
            "tenant_id": tenant_id,
            "allowed_resources": vault_ids,
            "permissions": perms,
            "enabled": not disabled,
        }
        if policy:
            payload["policy_id"] = policy
        if expires_at:
            payload["expires_at"] = expires_at
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                resp = await http.post(
                    f"{ctx.obj['url']}/admin/api/mission-bindings",
                    headers={"Authorization": f"Bearer {ctx.obj['token']}"},
                    json=payload,
                )
                result = resp.json()
        except Exception as e:
            result = {"status": "error", "message": str(e)}
        show_json(result) if output_json else show_mission_binding_result(result)
    asyncio.run(_run())


@mission_binding_group.command("list")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def mission_binding_list_cmd(ctx, output_json):
    """Lister les bindings de cette instance."""
    async def _run():
        import httpx
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                resp = await http.get(
                    f"{ctx.obj['url']}/admin/api/mission-bindings",
                    headers={"Authorization": f"Bearer {ctx.obj['token']}"},
                )
                result = resp.json()
        except Exception as e:
            result = {"status": "error", "message": str(e)}
        show_json(result) if output_json else show_mission_binding_result(result)
    asyncio.run(_run())


@mission_binding_group.command("get")
@click.argument("tenant_id")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def mission_binding_get_cmd(ctx, tenant_id, output_json):
    """Afficher le binding d'un tenant."""
    async def _run():
        import httpx
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                resp = await http.get(
                    f"{ctx.obj['url']}/admin/api/mission-bindings/{tenant_id}",
                    headers={"Authorization": f"Bearer {ctx.obj['token']}"},
                )
                result = resp.json()
        except Exception as e:
            result = {"status": "error", "message": str(e)}
        show_json(result) if output_json else show_mission_binding_result(result)
    asyncio.run(_run())


@mission_binding_group.command("delete")
@click.argument("tenant_id")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def mission_binding_delete_cmd(ctx, tenant_id, output_json):
    """Révoquer l'octroi d'un tenant."""
    async def _run():
        import httpx
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                resp = await http.delete(
                    f"{ctx.obj['url']}/admin/api/mission-bindings/{tenant_id}",
                    headers={"Authorization": f"Bearer {ctx.obj['token']}"},
                )
                result = resp.json()
        except Exception as e:
            result = {"status": "error", "message": str(e)}
        show_json(result) if output_json else show_mission_binding_result(result)
    asyncio.run(_run())


@mission_binding_group.command("purge")
@click.option("--older-than", type=int, default=30, show_default=True,
              help="Ne purger que les bindings expirés depuis plus de N jours")
@click.option("--dry-run", is_flag=True, help="Lister les candidats sans rien supprimer")
@click.option("--yes", "-y", is_flag=True, help="Confirmer la purge sans prompt")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def mission_binding_purge_cmd(ctx, older_than, dry_run, yes, output_json):
    """Purger définitivement les bindings expirés depuis plus de N jours (irréversible)."""
    async def _run():
        import httpx
        base = ctx.obj["url"]
        headers = {"Authorization": f"Bearer {ctx.obj['token']}"}
        # Dry-run préalable pour le décompte
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                preview = (await http.post(f"{base}/admin/api/mission-bindings/purge", headers=headers,
                           json={"older_than_days": older_than, "dry_run": True})).json()
        except Exception as e:
            preview = {"status": "error", "message": str(e)}
        if preview.get("status") != "ok":
            return show_json(preview) if output_json else show_mission_binding_result(preview)

        n = preview.get("count", 0)
        if dry_run:
            return show_json(preview) if output_json else show_mission_binding_result(preview)
        if n == 0:
            if output_json:
                show_json(preview)
            else:
                click.echo(f"Aucun binding expiré depuis plus de {older_than} jours à purger.")
            return
        if not yes:
            click.confirm(f"Purger DÉFINITIVEMENT {n} binding(s) expiré(s) depuis >{older_than}j ? Irréversible.",
                          abort=True)
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                result = (await http.post(f"{base}/admin/api/mission-bindings/purge", headers=headers,
                          json={"older_than_days": older_than, "dry_run": False})).json()
        except Exception as e:
            result = {"status": "error", "message": str(e)}
        show_json(result) if output_json else show_mission_binding_result(result)
    asyncio.run(_run())


# =============================================================================
# Audit Log
# =============================================================================

@cli.command("audit")
@click.option("--limit", "-n", default=50, type=int, help="Nombre d'entrées (défaut: 50)")
@click.option("--client", "-c", default="", help="Filtrer par client")
@click.option("--vault", "-v", default="", help="Filtrer par vault")
@click.option("--tool", default="", help="Filtrer par outil (wildcards: secret_*)")
@click.option("--category", default="", help="Filtrer: system|vault|secret|ssh|policy|token")
@click.option("--status", "-s", default="", help="Filtrer: ok|error|created|deleted|denied")
@click.option("--since", default="", help="Après cette date ISO 8601 (ex: 2026-03-18T10:00:00)")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def audit_cmd(ctx, limit, client, vault, tool, category, status, since, output_json):
    """📊 Journal d'audit — toutes les opérations MCP.

    \b
    Exemples :
      audit                              — 50 derniers événements
      audit -n 100 --category secret     — 100 derniers secrets
      audit --status denied              — refus de policy
      audit --client agent-sre --vault prod-servers
      audit --since 2026-03-18T10:00:00  — après une date
    """
    async def _run():
        mcpc = MCPClient(ctx.obj["url"], ctx.obj["token"])
        result = await mcpc.call_tool("audit_log", {
            "limit": limit, "client": client, "vault_id": vault,
            "tool": tool, "category": category, "status": status,
            "since": since,
        })
        if output_json:
            show_json(result)
        else:
            show_audit_result(result)
    asyncio.run(_run())


@cli.command("logs")
@click.pass_context
def logs_cmd(ctx):
    """🌐 Activité HTTP récente du serveur (ring buffer admin).

    Distinct de `audit` : journal d'activité HTTP (méthode/chemin/statut/durée),
    pas le journal d'audit de conformité. Réservé admin.
    """
    async def _run():
        import httpx
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                resp = await http.get(
                    f"{ctx.obj['url']}/admin/api/logs",
                    headers={"Authorization": f"Bearer {ctx.obj['token']}"},
                )
                result = resp.json()
        except Exception as e:
            result = {"status": "error", "message": str(e)}
        show_json(result)
    asyncio.run(_run())


# =============================================================================
# Shell interactif
# =============================================================================

@cli.command("shell")
@click.pass_context
def shell_cmd(ctx):
    """🐚 Lancer le shell interactif MCP Vault."""
    from .shell import run_shell
    asyncio.run(run_shell(ctx.obj["url"], ctx.obj["token"]))
