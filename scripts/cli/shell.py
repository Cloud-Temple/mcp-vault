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
    show_health_result, show_about_result, show_whoami_result,
    show_vault_result, show_secret_result,
    show_types_result, show_password_result,
    show_ssh_result, show_token_result,
    show_policy_result, show_audit_result, show_pki_result,
    show_wrap_result,
)


SHELL_COMMANDS = {
    "help":       "Afficher l'aide",
    "health":     "Vérifier l'état de santé (OpenBao + S3)",
    "about":      "Informations sur le service",
    "whoami":     "Identité du token courant (nom, permissions, vaults)",
    "vault":      "vault <op> [args] — create, list, info, update, delete",
    "secret":     "secret <op> <vault> [args] — write, read, list, delete, consume, wrap, revoke-wrap, wrap-lookup",
    "types":      "Lister les 14 types de secrets",
    "password":   "password [length] — Générer un mot de passe CSPRNG",
    "ssh":        "ssh <op> <vault> [args] — setup, sign, ca-key, roles, role-info",
    "policy":     "policy <op> [args] — create, list, get, delete",
    "token":      "token <op> [args] — create, list, update, revoke, purge-revoked",
    "audit":      "audit [options] — journal d'audit complet",
    "logs":       "logs — activité HTTP récente du serveur (ring buffer admin)",
    "pki":        "pki <op> [args] — setup, ca-key, roles, role-info, certs, issue, revoke, rotate",
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


async def cmd_whoami(client, args="", json_output=False):
    import httpx
    try:
        async with httpx.AsyncClient(timeout=10) as http:
            resp = await http.get(
                f"{client.base_url}/admin/api/whoami",
                headers={"Authorization": f"Bearer {client.token}"},
            )
            result = resp.json()
    except Exception as e:
        result = {"status": "error", "message": str(e)}
    if json_output:
        show_json(result)
    else:
        show_whoami_result(result)


VAULT_OPS = ("create", "list", "info", "update", "delete")


async def cmd_vault(client, args="", json_output=False):
    parts = args.strip().split()
    if not parts or parts[0] not in VAULT_OPS:
        show_warning("Usage: vault <op> [args]")
        show_warning("")
        show_warning("  vault list                              — lister les vaults")
        show_warning("  vault create my-vault                   — créer un vault")
        show_warning("  vault create my-vault --desc 'Ma desc'  — avec description")
        show_warning("  vault info my-vault                     — détails")
        show_warning("  vault update my-vault --desc 'Nouvelle desc' — modifier")
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
    elif op == "update" and len(parts) >= 2:
        desc = ""
        if "--desc" in parts:
            idx = parts.index("--desc")
            if idx + 1 < len(parts):
                desc = " ".join(parts[idx + 1:])
        if not desc:
            show_warning("Usage: vault update <vault_id> --desc 'Nouvelle description'")
            return
        result = await client.call_tool("vault_update", {
            "vault_id": parts[1], "description": desc,
        })
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


SECRET_OPS = ("write", "read", "list", "delete", "consume",
              "wrap", "revoke-wrap", "wrap-lookup")
WRAP_OPS = ("wrap", "revoke-wrap", "wrap-lookup")


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
    elif op == "consume" and len(parts) >= 2:
        # secret consume <operation_id>
        # Tokens sensibles depuis les variables d'environnement (pas dans l'historique)
        import os
        wrap_token_val = os.environ.get("VAULT_WRAP_TOKEN", "")
        mission_token_val = os.environ.get("VAULT_MISSION_TOKEN", "")
        if not wrap_token_val:
            show_error("VAULT_WRAP_TOKEN non défini (export VAULT_WRAP_TOKEN=...)")
            return
        result = await client.call_tool("secret_consume", {
            "wrap_token": wrap_token_val,
            "operation_id": parts[1],
            "mission_token": mission_token_val,
        })
    elif op == "wrap" and len(parts) >= 5:
        # secret wrap <vault> <path> <mission_id> <operation_id> [ttl] [--tenant-id X] [--expected-aud Y]
        ttl_val = 300
        tenant_id_val = ""
        expected_aud_val = ""
        i = 5
        while i < len(parts):
            if parts[i] == "--tenant-id" and i + 1 < len(parts):
                tenant_id_val = parts[i + 1]; i += 2
            elif parts[i] == "--expected-aud" and i + 1 < len(parts):
                expected_aud_val = parts[i + 1]; i += 2
            elif parts[i].isdigit():
                ttl_val = int(parts[i]); i += 1
            else:
                i += 1
        result = await client.call_tool("secret_wrap", {
            "vault_id": parts[1], "secret_path": parts[2],
            "mission_id": parts[3], "operation_id": parts[4],
            "ttl_seconds": ttl_val,
            "tenant_id": tenant_id_val, "expected_aud": expected_aud_val,
        })
    elif op == "revoke-wrap" and len(parts) >= 2:
        # secret revoke-wrap <lease_id>
        result = await client.call_tool("secret_revoke_wrap", {"lease_id": parts[1]})
    elif op == "wrap-lookup" and len(parts) >= 2:
        # secret wrap-lookup <operation_id>
        result = await client.call_tool("secret_wrap_lookup", {"operation_id": parts[1]})
    else:
        show_warning(f"Usage: secret {op} <vault> <path>")
        if op == "wrap":
            show_warning("  secret wrap <vault> <path> <mission_id> <operation_id> [ttl]")
        return

    if json_output:
        show_json(result)
    elif op in WRAP_OPS:
        show_wrap_result(result)
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


PKI_OPS = ("setup", "ca-key", "roles", "role-info", "certs", "issue", "revoke", "rotate")


async def cmd_pki(client, args="", json_output=False):
    parts = args.strip().split()
    if not parts or parts[0] not in PKI_OPS:
        show_warning("Usage: pki <op> [args]")
        show_warning("")
        show_warning("  pki setup --lab --domains '*.lesur.lan,lesur.lan'")
        show_warning("  pki ca-key")
        show_warning("  pki roles")
        show_warning("  pki role-info <role_name>")
        show_warning("  pki certs [--limit N]")
        show_warning("  pki issue <common_name> [--ttl 720h] [--alt-names a,b] [--ip-sans 10.0.0.1]")
        show_warning("  pki revoke <serial>")
        show_warning("  pki rotate [--keep-old]")
        return

    op = parts[0]

    if op == "ca-key":
        result = await client.call_tool("pki_ca_public_key", {})

    elif op == "roles":
        result = await client.call_tool("pki_ca_list_roles", {})

    elif op == "role-info" and len(parts) >= 2:
        result = await client.call_tool("pki_ca_role_info", {"role_name": parts[1]})

    elif op == "certs":
        limit = 100
        offset = 0
        i = 1
        while i < len(parts):
            if parts[i] == "--limit" and i + 1 < len(parts):
                try:
                    limit = max(1, int(parts[i + 1]))
                except ValueError:
                    show_error("--limit doit être un entier positif"); return
                i += 2
            elif parts[i] == "--offset" and i + 1 < len(parts):
                try:
                    offset = max(0, int(parts[i + 1]))
                except ValueError:
                    show_error("--offset doit être un entier positif"); return
                i += 2
            else:
                i += 1
        result = await client.call_tool("pki_list_certs", {"limit": limit, "offset": offset})

    elif op == "issue":
        if len(parts) < 2:
            show_warning("Usage: pki issue <common_name> [--ttl 720h] [--alt-names a,b] [--ip-sans IP]"); return
        common_name = parts[1]
        ttl = "720h"
        alt_names = ""
        ip_sans = ""
        i = 2
        while i < len(parts):
            if parts[i] == "--ttl" and i + 1 < len(parts):
                ttl = parts[i + 1]; i += 2
            elif parts[i] == "--alt-names" and i + 1 < len(parts):
                alt_names = parts[i + 1]; i += 2
            elif parts[i] == "--ip-sans" and i + 1 < len(parts):
                ip_sans = parts[i + 1]; i += 2
            else:
                i += 1
        result = await client.call_tool("pki_issue_cert", {
            "common_name": common_name, "ttl": ttl,
            "alt_names": alt_names, "ip_sans": ip_sans,
        })

    elif op == "revoke":
        if len(parts) < 2:
            show_warning("Usage: pki revoke <serial_number>"); return
        result = await client.call_tool("pki_revoke_cert", {"serial_number": parts[1]})

    elif op == "rotate":
        keep_old = "--no-keep-old" not in parts
        overlap = "48h"
        i = 1
        while i < len(parts):
            if parts[i] == "--overlap" and i + 1 < len(parts):
                overlap = parts[i + 1]; i += 2
            else:
                i += 1
        result = await client.call_tool("pki_ca_rotate_intermediate", {
            "keep_old_issuer": keep_old, "overlap_ttl": overlap,
        })

    elif op == "setup":
        lab = "--prod" not in parts
        domains = "*.lesur.lan,lesur.lan"
        ttl = "720h"
        i = 1
        while i < len(parts):
            if parts[i] == "--domains" and i + 1 < len(parts):
                domains = parts[i + 1]; i += 2
            elif parts[i] == "--ttl" and i + 1 < len(parts):
                ttl = parts[i + 1]; i += 2
            else:
                i += 1
        result = await client.call_tool("pki_ca_setup", {
            "lab_mode": lab, "allowed_domains": domains, "leaf_ttl": ttl,
        })

    else:
        show_warning(f"Usage: pki {op} ...")
        return

    if json_output:
        show_json(result)
    else:
        show_pki_result(result)


POLICY_OPS = ("create", "list", "get", "delete")


async def cmd_policy(client, args="", json_output=False):
    parts = args.strip().split()
    if not parts or parts[0] not in POLICY_OPS:
        show_warning("Usage: policy <op> [args]")
        show_warning("")
        show_warning("  policy list")
        show_warning("  policy create readonly --desc 'Lecture seule' --allowed 'secret_read,vault_list'")
        show_warning("  policy create no-ssh --denied 'ssh_*'")
        show_warning("  policy create team-x --allowed 'secret_*' --path-rules '[{\"vault_pattern\":\"shared-*\",\"allowed_paths\":[\"shared/*\"]}]'")
        show_warning("  policy get readonly")
        show_warning("  policy delete readonly")
        show_warning("")
        show_warning("  denied_tools est TOUJOURS prioritaire sur allowed_tools.")
        show_warning("  --path-rules : JSON pour restreindre les chemins de secrets (fnmatch wildcards).")
        return

    op = parts[0]
    if op == "list":
        result = await client.call_tool("policy_list", {})
    elif op == "get" and len(parts) >= 2:
        result = await client.call_tool("policy_get", {"policy_id": parts[1]})
    elif op == "create" and len(parts) >= 2:
        import json as json_module
        desc = ""
        allowed = []
        denied = []
        path_rules = []
        i = 2
        while i < len(parts):
            if parts[i] == "--desc" and i + 1 < len(parts):
                desc = parts[i + 1]
                i += 2
            elif parts[i] == "--allowed" and i + 1 < len(parts):
                allowed = [t.strip() for t in parts[i + 1].split(",") if t.strip()]
                i += 2
            elif parts[i] == "--denied" and i + 1 < len(parts):
                denied = [t.strip() for t in parts[i + 1].split(",") if t.strip()]
                i += 2
            elif parts[i] == "--path-rules" and i + 1 < len(parts):
                try:
                    path_rules = json_module.loads(parts[i + 1])
                    if not isinstance(path_rules, list):
                        show_error("--path-rules doit etre un tableau JSON")
                        return
                except json_module.JSONDecodeError as e:
                    show_error(f"JSON invalide dans --path-rules: {e}")
                    return
                i += 2
            else:
                i += 1
        result = await client.call_tool("policy_create", {
            "policy_id": parts[1], "description": desc,
            "allowed_tools": allowed, "denied_tools": denied,
            "path_rules": path_rules,
        })
    elif op == "delete" and len(parts) >= 2:
        result = await client.call_tool("policy_delete", {
            "policy_id": parts[1], "confirm": True,
        })
    else:
        show_warning(f"Usage: policy {op} <policy_id>")
        return

    if json_output:
        show_json(result)
    else:
        show_policy_result(result)


TOKEN_OPS = ("create", "list", "update", "revoke", "purge-revoked")


async def cmd_token(client, args="", json_output=False):
    parts = args.strip().split()
    if not parts or parts[0] not in TOKEN_OPS:
        show_warning("Usage: token <op> [args]")
        show_warning("")
        show_warning("  token list")
        show_warning("  token create agent-prod --permissions read --vaults prod")
        show_warning("  token create agent-deploy --policy readonly --vaults prod-app")
        show_warning("  token update <hash> --policy readonly       — assigner une policy")
        show_warning("  token update <hash> --policy _remove        — retirer la policy")
        show_warning("  token update <hash> --vaults prod,staging   — restreindre les vaults")
        show_warning("  token revoke <hash>")
        show_warning("  token purge-revoked [--older-than 30] [--yes]  — purge les révoqués anciens")
        show_warning("")
        show_warning("  Par defaut (vaults vide), le token ne voit que les vaults qu'il cree.")
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
        policy_id = ""
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
            elif parts[i] == "--policy" and i + 1 < len(parts):
                policy_id = parts[i + 1]
                i += 2
            else:
                i += 1
        payload = {
            "client_name": parts[1],
            "permissions": perms,
            "allowed_resources": vaults,
            "expires_in_days": expires,
            "email": email,
        }
        if policy_id:
            payload["policy_id"] = policy_id
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                resp = await http.post(
                    f"{client.base_url}/admin/api/tokens",
                    headers={"Authorization": f"Bearer {client.token}"},
                    json=payload,
                )
                result = resp.json()
        except Exception as e:
            result = {"status": "error", "message": str(e)}
    elif op == "update" and len(parts) >= 2:
        data = {}
        i = 2
        while i < len(parts):
            if parts[i] == "--policy" and i + 1 < len(parts):
                data["policy_id"] = "" if parts[i + 1] == "_remove" else parts[i + 1]
                i += 2
            elif parts[i] == "--permissions" and i + 1 < len(parts):
                data["permissions"] = [p.strip() for p in parts[i + 1].split(",")]
                i += 2
            elif parts[i] == "--vaults" and i + 1 < len(parts):
                if parts[i + 1] == "_all":
                    data["allowed_resources"] = []
                else:
                    data["allowed_resources"] = [v.strip() for v in parts[i + 1].split(",")]
                i += 2
            else:
                i += 1
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                resp = await http.put(
                    f"{client.base_url}/admin/api/tokens/{parts[1]}",
                    headers={"Authorization": f"Bearer {client.token}"},
                    json=data,
                )
                result = resp.json()
        except Exception as e:
            result = {"status": "error", "message": str(e)}
        if json_output:
            show_json(result)
        else:
            show_policy_result(result)
        return
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
    elif op == "purge-revoked":
        older_than = 30
        older_than_err = False
        do_purge = "--yes" in parts
        i = 1
        while i < len(parts):
            if parts[i] == "--older-than":
                # Fail-close : valeur absente ou non entière → on refuse, pas de purge
                if i + 1 >= len(parts):
                    older_than_err = True
                    break
                try:
                    older_than = int(parts[i + 1])
                except ValueError:
                    older_than_err = True
                    break
                i += 2
            else:
                i += 1
        if older_than_err:
            show_error("--older-than attend un entier (ex: token purge-revoked --older-than 30 --yes)")
            return
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                preview = (await http.post(
                    f"{client.base_url}/admin/api/tokens/purge",
                    headers={"Authorization": f"Bearer {client.token}"},
                    json={"older_than_days": older_than, "dry_run": True},
                )).json()
        except Exception as e:
            preview = {"status": "error", "message": str(e)}
        if not isinstance(preview, dict) or preview.get("status") != "ok":
            # Fail-close : un dry-run en échec n'autorise JAMAIS la purge effective
            result = preview if isinstance(preview, dict) else {"status": "error", "message": "réponse invalide"}
        elif not do_purge:
            # Pas de --yes : on n'exécute QUE le dry-run (le shell n'a pas de prompt interactif)
            n = preview.get("count", 0)
            show_warning(f"{n} token(s) révoqué(s) depuis >{older_than}j seraient purgés. "
                         f"Ajoutez --yes pour confirmer.")
            result = preview
        else:
            try:
                async with httpx.AsyncClient(timeout=10) as http:
                    result = (await http.post(
                        f"{client.base_url}/admin/api/tokens/purge",
                        headers={"Authorization": f"Bearer {client.token}"},
                        json={"older_than_days": older_than, "dry_run": False},
                    )).json()
            except Exception as e:
                result = {"status": "error", "message": str(e)}
    else:
        show_warning(f"Usage: token {op} ...")
        return

    if json_output:
        show_json(result)
    else:
        show_token_result(result)


async def cmd_logs(client, args="", json_output=False):
    """Activité HTTP récente du serveur (ring buffer admin) — distincte du journal d'audit."""
    import httpx
    try:
        async with httpx.AsyncClient(timeout=10) as http:
            resp = await http.get(
                f"{client.base_url}/admin/api/logs",
                headers={"Authorization": f"Bearer {client.token}"},
            )
            result = resp.json()
    except Exception as e:
        result = {"status": "error", "message": str(e)}
    show_json(result)


async def cmd_audit(client, args="", json_output=False):
    params = {"limit": 50}
    parts = args.strip().split()
    i = 0
    while i < len(parts):
        if parts[i] == "--limit" and i + 1 < len(parts):
            params["limit"] = int(parts[i + 1]); i += 2
        elif parts[i] == "--client" and i + 1 < len(parts):
            params["client"] = parts[i + 1]; i += 2
        elif parts[i] == "--vault" and i + 1 < len(parts):
            params["vault_id"] = parts[i + 1]; i += 2
        elif parts[i] == "--tool" and i + 1 < len(parts):
            params["tool"] = parts[i + 1]; i += 2
        elif parts[i] == "--category" and i + 1 < len(parts):
            params["category"] = parts[i + 1]; i += 2
        elif parts[i] == "--status" and i + 1 < len(parts):
            params["status"] = parts[i + 1]; i += 2
        elif parts[i] == "--since" and i + 1 < len(parts):
            params["since"] = parts[i + 1]; i += 2
        else:
            i += 1
    result = await client.call_tool("audit_log", params)
    if json_output:
        show_json(result)
    else:
        show_audit_result(result)


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
            elif command == "whoami":
                await cmd_whoami(client, args, json_output)
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
            elif command == "policy":
                await cmd_policy(client, args, json_output)
            elif command == "token":
                await cmd_token(client, args, json_output)
            elif command == "audit":
                await cmd_audit(client, args, json_output)
            elif command == "logs":
                await cmd_logs(client, args, json_output)
            elif command == "pki":
                await cmd_pki(client, args, json_output)
            else:
                show_warning(f"Commande inconnue: '{command}'. Tapez 'help'.")

        except KeyboardInterrupt:
            console.print("\n[dim]Ctrl+C — tapez 'quit' pour quitter[/dim]")
        except EOFError:
            console.print("[dim]Au revoir 👋[/dim]")
            break
        except Exception as e:
            show_error(f"Erreur: {e}")
