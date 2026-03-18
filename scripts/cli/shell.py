# -*- coding: utf-8 -*-
"""
Shell interactif — MCP Vault.
"""

import asyncio
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import FileHistory
from pathlib import Path

from .client import MCPClient
from .display import (
    console, show_error, show_warning, show_json,
    show_health_result, show_about_result,
    show_vault_result, show_secret_result,
    show_types_result, show_password_result,
    show_ssh_result, show_token_result,
)


SHELL_COMMANDS = {
    "help":       "Afficher l'aide",
    "health":     "Vérifier l'état de santé (OpenBao + S3)",
    "about":      "Informations sur le service",
    "vault":      "vault <op> [args] — create, list, info, update, delete",
    "secret":     "secret <op> <vault> [args] — write, read, list, delete",
    "types":      "Lister les 14 types de secrets",
    "password":   "password [length] — Générer un mot de passe CSPRNG",
    "ssh":        "ssh <op> <vault> [args] — setup, sign, ca-key, roles, role-info",
    "token":      "token <op> [args] — create, list, revoke",
    "quit":       "Quitter le shell",
}


async def cmd_health(client, args="", json_output=False):
    result = await client.call_tool("system_health", {})
    if json_output:
        show_json(result)
    else:
        show_health_result(result)


async def cmd_about(client, args="", json_output=False):
    result = await client.call_tool("system_about", {})
    if json_output:
        show_json(result)
    else:
        show_about_result(result)


VAULT_OPS = ("create", "list", "info", "delete")


async def cmd_vault(client, args="", json_output=False):
    parts = args.strip().split()
    if not parts or parts[0] not in VAULT_OPS:
        show_warning("Usage: vault <op> [args]")
        show_warning("")
        show_warning("  vault list                              — lister les vaults")
        show_warning("  vault create my-vault                   — créer un vault")
        show_warning("  vault create my-vault --desc 'Ma desc'  — avec description")
        show_warning("  vault info my-vault                     — détails")
        show_warning("  vault delete my-vault                   — supprimer")
        return

    op = parts[0]
    if op == "list":
        result = await client.call_tool("vault_list", {})
    elif op == "create" and len(parts) >= 2:
        desc = ""
        if "--desc" in parts:
            idx = parts.index("--desc")
            if idx + 1 < len(parts):
                desc = " ".join(parts[idx + 1:])
                parts = parts[:idx]
        result = await client.call_tool("vault_create", {
            "vault_id": parts[1], "description": desc,
        })
    elif op == "info" and len(parts) >= 2:
        result = await client.call_tool("vault_info", {"vault_id": parts[1]})
    elif op == "delete" and len(parts) >= 2:
        result = await client.call_tool("vault_delete", {
            "vault_id": parts[1], "confirm": True,
        })
    else:
        show_warning(f"Usage: vault {op} <vault_id>")
        return

    if json_output:
        show_json(result)
    else:
        show_vault_result(result)


SECRET_OPS = ("write", "read", "list", "delete")


async def cmd_secret(client, args="", json_output=False):
    parts = args.strip().split()
    if not parts or parts[0] not in SECRET_OPS:
        show_warning("Usage: secret <op> <vault> [path] [options]")
        show_warning("")
        show_warning("  secret list my-vault                    — lister les clés")
        show_warning("  secret read my-vault web/github         — lire un secret")
        show_warning("  secret write my-vault test/key --data '{\"user\":\"me\"}' --type login")
        show_warning("  secret delete my-vault test/key         — supprimer")
        return

    op = parts[0]
    if op == "list" and len(parts) >= 2:
        prefix = parts[2] if len(parts) > 2 else ""
        result = await client.call_tool("secret_list", {
            "vault_id": parts[1], "path": prefix,
        })
    elif op == "read" and len(parts) >= 3:
        result = await client.call_tool("secret_read", {
            "vault_id": parts[1], "path": parts[2],
        })
    elif op == "write" and len(parts) >= 3:
        import json as json_module
        data_str = "{}"
        secret_type = "custom"
        tags = ""
        # Parse --data and --type
        i = 3
        while i < len(parts):
            if parts[i] == "--data" and i + 1 < len(parts):
                data_str = parts[i + 1]
                i += 2
            elif parts[i] == "--type" and i + 1 < len(parts):
                secret_type = parts[i + 1]
                i += 2
            elif parts[i] == "--tags" and i + 1 < len(parts):
                tags = parts[i + 1]
                i += 2
            else:
                i += 1
        try:
            data = json_module.loads(data_str)
        except json_module.JSONDecodeError as e:
            show_error(f"JSON invalide: {e}")
            return
        result = await client.call_tool("secret_write", {
            "vault_id": parts[1], "path": parts[2],
            "data": data, "secret_type": secret_type, "tags": tags,
        })
    elif op == "delete" and len(parts) >= 3:
        result = await client.call_tool("secret_delete", {
            "vault_id": parts[1], "path": parts[2],
        })
    else:
        show_warning(f"Usage: secret {op} <vault> <path>")
        return

    if json_output:
        show_json(result)
    else:
        show_secret_result(result)


async def cmd_types(client, args="", json_output=False):
    result = await client.call_tool("secret_types", {})
    if json_output:
        show_json(result)
    else:
        show_types_result(result)


async def cmd_password(client, args="", json_output=False):
    length = 24
    parts = args.strip().split()
    if parts:
        try:
            length = int(parts[0])
        except ValueError:
            pass
    result = await client.call_tool("secret_generate_password", {"length": length})
    if json_output:
        show_json(result)
    else:
        show_password_result(result)


SSH_OPS = ("setup", "sign", "ca-key", "roles", "role-info")


async def cmd_ssh(client, args="", json_output=False):
    parts = args.strip().split()
    if not parts or parts[0] not in SSH_OPS:
        show_warning("Usage: ssh <op> <vault> [args]")
        show_warning("")
        show_warning("  ssh setup my-vault my-role --users deploy --ttl 15m")
        show_warning("  ssh sign my-vault my-role --key-data 'ssh-ed25519 ...'")
        show_warning("  ssh ca-key my-vault")
        show_warning("  ssh roles my-vault")
        show_warning("  ssh role-info my-vault my-role")
        return

    op = parts[0]
    if op == "ca-key" and len(parts) >= 2:
        result = await client.call_tool("ssh_ca_public_key", {"vault_id": parts[1]})
    elif op == "roles" and len(parts) >= 2:
        result = await client.call_tool("ssh_ca_list_roles", {"vault_id": parts[1]})
    elif op == "role-info" and len(parts) >= 3:
        result = await client.call_tool("ssh_ca_role_info", {
            "vault_id": parts[1], "role_name": parts[2],
        })
    elif op == "setup" and len(parts) >= 3:
        # Parse optional args
        users = "*"
        ttl = "30m"
        default_user = "ubuntu"
        i = 3
        while i < len(parts):
            if parts[i] == "--users" and i + 1 < len(parts):
                users = parts[i + 1]
                i += 2
            elif parts[i] == "--ttl" and i + 1 < len(parts):
                ttl = parts[i + 1]
                i += 2
            elif parts[i] == "--default-user" and i + 1 < len(parts):
                default_user = parts[i + 1]
                i += 2
            else:
                i += 1
        result = await client.call_tool("ssh_ca_setup", {
            "vault_id": parts[1], "role_name": parts[2],
            "allowed_users": users, "default_user": default_user, "ttl": ttl,
        })
    elif op == "sign" and len(parts) >= 3:
        key_data = ""
        ttl = "30m"
        i = 3
        while i < len(parts):
            if parts[i] == "--key-data" and i + 1 < len(parts):
                key_data = parts[i + 1]
                i += 2
            elif parts[i] == "--ttl" and i + 1 < len(parts):
                ttl = parts[i + 1]
                i += 2
            else:
                i += 1
        if not key_data:
            show_error("--key-data requis")
            return
        result = await client.call_tool("ssh_sign_key", {
            "vault_id": parts[1], "role_name": parts[2],
            "public_key": key_data, "ttl": ttl,
        })
    else:
        show_warning(f"Usage: ssh {op} <vault> ...")
        return

    if json_output:
        show_json(result)
    else:
        show_ssh_result(result)


TOKEN_OPS = ("create", "list", "revoke")


async def cmd_token(client, args="", json_output=False):
    parts = args.strip().split()
    if not parts or parts[0] not in TOKEN_OPS:
        show_warning("Usage: token <op> [args]")
        show_warning("")
        show_warning("  token list")
        show_warning("  token create agent-prod --permissions read --vaults prod")
        show_warning("  token revoke <hash_prefix>")
        return

    op = parts[0]
    import httpx

    if op == "list":
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                resp = await http.get(
                    f"{client.base_url}/admin/api/tokens",
                    headers={"Authorization": f"Bearer {client.token}"},
                )
                result = resp.json()
        except Exception as e:
            result = {"status": "error", "message": str(e)}
    elif op == "create" and len(parts) >= 2:
        perms = ["read", "write"]
        vaults = []
        expires = 90
        email = ""
        i = 2
        while i < len(parts):
            if parts[i] == "--permissions" and i + 1 < len(parts):
                perms = [p.strip() for p in parts[i + 1].split(",")]
                i += 2
            elif parts[i] == "--vaults" and i + 1 < len(parts):
                vaults = [s.strip() for s in parts[i + 1].split(",")]
                i += 2
            elif parts[i] == "--expires" and i + 1 < len(parts):
                expires = int(parts[i + 1])
                i += 2
            elif parts[i] == "--email" and i + 1 < len(parts):
                email = parts[i + 1]
                i += 2
            else:
                i += 1
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                resp = await http.post(
                    f"{client.base_url}/admin/api/tokens",
                    headers={"Authorization": f"Bearer {client.token}"},
                    json={
                        "client_name": parts[1],
                        "permissions": perms,
                        "allowed_resources": vaults,
                        "expires_in_days": expires,
                        "email": email,
                    },
                )
                result = resp.json()
        except Exception as e:
            result = {"status": "error", "message": str(e)}
    elif op == "revoke" and len(parts) >= 2:
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                resp = await http.delete(
                    f"{client.base_url}/admin/api/tokens/{parts[1]}",
                    headers={"Authorization": f"Bearer {client.token}"},
                )
                result = resp.json()
        except Exception as e:
            result = {"status": "error", "message": str(e)}
    else:
        show_warning(f"Usage: token {op} ...")
        return

    if json_output:
        show_json(result)
    else:
        show_token_result(result)


def cmd_help():
    from rich.table import Table
    table = Table(title="🐚 Commandes disponibles", show_header=True)
    table.add_column("Commande", style="cyan bold", min_width=20)
    table.add_column("Description", style="white")
    for cmd, desc in SHELL_COMMANDS.items():
        table.add_row(cmd, desc)
    table.add_row("", "")
    table.add_row("[dim]--json[/dim]", "[dim]Ajouter pour la sortie JSON[/dim]")
    console.print(table)


async def run_shell(url: str, token: str):
    client = MCPClient(url, token)

    completer = WordCompleter(
        list(SHELL_COMMANDS.keys()) + ["--json"],
        ignore_case=True,
    )

    history_path = Path.home() / ".mcp_vault_shell_history"
    session = PromptSession(
        history=FileHistory(str(history_path)),
        completer=completer,
    )

    console.print(f"\n[bold cyan]🐚 MCP Vault Shell[/bold cyan] — connecté à [green]{url}[/green]")
    console.print("[dim]Tapez 'help' pour l'aide, 'quit' pour quitter.[/dim]\n")

    while True:
        try:
            user_input = await session.prompt_async("mcp-vault> ")
            if not user_input.strip():
                continue

            parts = user_input.strip().split(None, 1)
            command = parts[0].lower()
            args = parts[1] if len(parts) > 1 else ""

            json_output = "--json" in args
            if json_output:
                args = args.replace("--json", "").strip()

            if command == "quit":
                console.print("[dim]Au revoir 👋[/dim]")
                break
            elif command == "help":
                cmd_help()
            elif command == "health":
                await cmd_health(client, args, json_output)
            elif command == "about":
                await cmd_about(client, args, json_output)
            elif command == "vault":
                await cmd_vault(client, args, json_output)
            elif command == "secret":
                await cmd_secret(client, args, json_output)
            elif command == "types":
                await cmd_types(client, args, json_output)
            elif command == "password":
                await cmd_password(client, args, json_output)
            elif command == "ssh":
                await cmd_ssh(client, args, json_output)
            elif command == "token":
                await cmd_token(client, args, json_output)
            else:
                show_warning(f"Commande inconnue: '{command}'. Tapez 'help'.")

        except KeyboardInterrupt:
            console.print("\n[dim]Ctrl+C — tapez 'quit' pour quitter[/dim]")
        except EOFError:
            console.print("[dim]Au revoir 👋[/dim]")
            break
        except Exception as e:
            show_error(f"Erreur: {e}")
