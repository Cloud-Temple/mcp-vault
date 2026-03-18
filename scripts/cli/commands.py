# -*- coding: utf-8 -*-
"""
CLI Click — MCP Vault : commandes scriptables.

Usage :
    python scripts/mcp_cli.py health
    python scripts/mcp_cli.py about
    python scripts/mcp_cli.py space list
    python scripts/mcp_cli.py secret write myspace test/key --data '{"user":"me"}'
    python scripts/mcp_cli.py shell
"""

import asyncio
import click
from . import BASE_URL, TOKEN
from .client import MCPClient
from .display import (
    console, show_error, show_json,
    show_health_result, show_about_result,
    show_vault_result, show_secret_result,
    show_types_result, show_password_result,
    show_ssh_result, show_token_result,
)


@click.group()
@click.option("--url", "-u", envvar=["MCP_URL"], default=BASE_URL, help="URL du serveur MCP")
@click.option("--token", "-t", envvar=["MCP_TOKEN"], default=TOKEN, help="Token d'authentification")
@click.pass_context
def cli(ctx, url, token):
    """🔐 CLI pour MCP Vault — Gestion sécurisée des secrets pour agents IA."""
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


# =============================================================================
# Vault Spaces (groupe)
# =============================================================================

@cli.group("vault")
@click.pass_context
def vault_group(ctx):
    """🏛️  Gestion des vaults vault (mount KV v2).

    \b
    Sous-commandes : create, list, info, delete.
    Chaque vault est un mount point KV v2 dans OpenBao.
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


# =============================================================================
# SSH CA (groupe)
# =============================================================================

@cli.group("ssh")
@click.pass_context
def ssh_group(ctx):
    """🔏 SSH Certificate Authority (signature de clés éphémères).

    \b
    Sous-commandes : setup, sign, ca-key.
    """
    pass


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


# =============================================================================
# Token management (groupe admin)
# =============================================================================

@cli.group("token")
@click.pass_context
def token_group(ctx):
    """🎫 Gestion des tokens d'accès MCP (admin).

    \b
    Sous-commandes : create, list, revoke.
    """
    pass


@token_group.command("create")
@click.argument("name")
@click.option("--permissions", "-p", default="read,write", help="Permissions (séparées par virgule)")
@click.option("--spaces", "-s", default="", help="Vaults autorisés (virgule, vide=tous)")
@click.option("--expires", "-e", default=90, type=int, help="Expiration en jours (0=jamais)")
@click.option("--email", default="", help="Email du propriétaire")
@click.option("--json", "-j", "output_json", is_flag=True, help="Sortie JSON brute")
@click.pass_context
def token_create_cmd(ctx, name, permissions, spaces, expires, email, output_json):
    """Créer un nouveau token.

    \b
    Exemples :
      token create agent-sre --spaces serveurs-prod --permissions read
      token create admin-user --permissions admin --expires 365
      token create ci-cd --email ci@company.com --permissions read,write
    """
    async def _run():
        perms = [p.strip() for p in permissions.split(",") if p.strip()]
        space_list = [s.strip() for s in spaces.split(",") if s.strip()] if spaces else []
        import httpx
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                resp = await http.post(
                    f"{ctx.obj['url']}/admin/api/tokens",
                    headers={"Authorization": f"Bearer {ctx.obj['token']}"},
                    json={
                        "client_name": name,
                        "permissions": perms,
                        "allowed_resources": space_list,
                        "expires_in_days": expires,
                        "email": email,
                    },
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


# =============================================================================
# Shell interactif
# =============================================================================

@cli.command("shell")
@click.pass_context
def shell_cmd(ctx):
    """🐚 Lancer le shell interactif MCP Vault."""
    from .shell import run_shell
    asyncio.run(run_shell(ctx.obj["url"], ctx.obj["token"]))
