#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════════════════
  🔐 TEST CLI LIVE — MCP Vault (serveur réel)
═══════════════════════════════════════════════════════════════════════════════

  Ce script exécute les commandes CLI RÉELLES contre un serveur MCP Vault
  en cours d'exécution. Il valide le cycle complet :

    CLI → MCP Protocol → OpenBao → S3 → Réponse → Affichage

  Scénario complet testé :
    1. Système          — health, about, whoami
    2. Vault CRUD       — create, list, info, update, delete
    3. Secrets          — write (3 types), read, list, delete, password
    4. Policy + Paths   — create avec path_rules, get, enforcement
    5. Token + Policy   — create avec --policy, update, enforcement
    6. SSH CA           — setup, roles, role-info, ca-key, sign
    7. Audit            — vérifier que les événements sont enregistrés
    8. Nettoyage        — suppression de tout ce qui a été créé

  Usage :
    # Dans le conteneur Docker (serveur déjà running)
    docker compose exec mcp-vault python tests/test_cli_live.py

    # En local avec le serveur sur un autre port
    MCP_URL=http://localhost:8085 python tests/test_cli_live.py

    # Verbose
    python tests/test_cli_live.py --verbose

═══════════════════════════════════════════════════════════════════════════════
"""

import asyncio
import json
import os
import sys
import argparse

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

BASE_URL = os.getenv("MCP_URL", "http://localhost:8030")
TOKEN = os.getenv("MCP_TOKEN", os.getenv("ADMIN_BOOTSTRAP_KEY", "change_me_in_production"))
VERBOSE = False

# Compteurs
PASS = 0
FAIL = 0

# Préfixe pour les objets de test (facilite le nettoyage)
PREFIX = "clitest"


# ═════════════════════════════════════════════════════════════════════════════
#  Helpers
# ═════════════════════════════════════════════════════════════════════════════

def banner(title: str):
    print()
    print("=" * 70)
    print(f"  {title}")
    print("=" * 70)


def section(title: str):
    print(f"\n  ── {title} ──")


def cli_equiv(cmd: str):
    """Affiche la commande CLI équivalente pour la traçabilité."""
    print(f"    $ mcp-vault {cmd}")


def check(name: str, condition: bool, detail: str = "") -> bool:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"    ✅ {name}")
    else:
        FAIL += 1
        msg = f"    ❌ {name}"
        if detail:
            msg += f" — {detail}"
        print(msg)
    return condition


def check_value(name, actual, expected, detail=""):
    ok = actual == expected
    return check(name, ok, "" if ok else (detail or f"got={actual!r}, expected={expected!r}"))


def check_contains(name, text, substring):
    ok = substring in str(text)
    return check(name, ok, f"'{substring}' non trouvé" if not ok else "")


async def mcp(tool_name: str, args: dict, token_override: str = None) -> dict:
    """
    Appelle un outil MCP via Streamable HTTP.
    Équivalent de ce que le CLI fait en coulisses.
    """
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    use_token = token_override or TOKEN
    headers = {"Authorization": f"Bearer {use_token}"}
    try:
        async with streamablehttp_client(
            f"{BASE_URL}/mcp", headers=headers, timeout=30, sse_read_timeout=60,
        ) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool_name, args)
                text = getattr(result.content[0], "text", "") if result.content else ""
                return json.loads(text) if text else {"status": "error", "message": "Réponse vide"}
    except Exception as e:
        return {"status": "error", "message": f"MCP call failed: {e}"}


async def api(method: str, path: str, data: dict = None, token_override: str = None) -> dict:
    """Appelle l'API admin REST (ce que le CLI fait pour les tokens)."""
    import httpx
    use_token = token_override or TOKEN
    headers = {"Authorization": f"Bearer {use_token}"}
    try:
        async with httpx.AsyncClient(timeout=15) as http:
            kw = {"headers": headers}
            if data is not None:
                kw["json"] = data
            if method == "GET":
                resp = await http.get(f"{BASE_URL}{path}", **kw)
            elif method == "POST":
                resp = await http.post(f"{BASE_URL}{path}", **kw)
            elif method == "PUT":
                resp = await http.put(f"{BASE_URL}{path}", **kw)
            elif method == "DELETE":
                resp = await http.delete(f"{BASE_URL}{path}", **kw)
            else:
                return {"status": "error"}
            return resp.json()
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ═════════════════════════════════════════════════════════════════════════════
#  TESTS LIVE
# ═════════════════════════════════════════════════════════════════════════════

async def run_all_tests():

    # =====================================================================
    #  1. SYSTÈME — health, about, whoami
    # =====================================================================
    banner("1. SYSTÈME — health, about, whoami")

    section("1a. Health — état du serveur")
    cli_equiv("health")
    r = await mcp("system_health", {})
    if not check_value("health status = ok", r.get("status"), "ok"):
        print(f"\n    ⛔ Serveur inaccessible à {BASE_URL}")
        print(f"    Token : {TOKEN[:8]}...")
        print(f"    Arrêt des tests.")
        return
    check("OpenBao connecté", "openbao" in str(r.get("services", {})).lower())

    section("1b. About — informations du service")
    cli_equiv("about")
    r = await mcp("system_about", {})
    # system_about ne retourne pas de champ "status", on vérifie la version
    check("about retourne des données", bool(r.get("version") or r.get("service")))
    check("Version présente", bool(r.get("version")))
    check("tools_count > 0", r.get("tools_count", 0) > 0)
    print(f"    → Version {r.get('version')}, {r.get('tools_count')} outils")

    section("1c. Whoami — identité du token")
    cli_equiv("whoami")
    r = await api("GET", "/admin/api/whoami")
    check_value("whoami status", r.get("status"), "ok")
    check("client_name présent", bool(r.get("client_name")))
    check("permissions présentes", len(r.get("permissions", [])) > 0)
    print(f"    → Connecté en tant que '{r.get('client_name')}' ({r.get('auth_type')})")

    # =====================================================================
    #  2. VAULT CRUD — create, list, info, update, delete
    # =====================================================================
    banner("2. VAULT CRUD — create, list, info, update, delete")

    VAULT = f"{PREFIX}-prod"
    VAULT2 = f"{PREFIX}-staging"

    section("2a. Créer 2 vaults")
    cli_equiv(f"vault create {VAULT} -d 'Production'")
    r = await mcp("vault_create", {"vault_id": VAULT, "description": "Production"})
    check_value(f"vault_create '{VAULT}'", r.get("status"), "created")

    cli_equiv(f"vault create {VAULT2} -d 'Staging'")
    r = await mcp("vault_create", {"vault_id": VAULT2, "description": "Staging"})
    check_value(f"vault_create '{VAULT2}'", r.get("status"), "created")

    section("2b. Lister les vaults")
    cli_equiv("vault list")
    r = await mcp("vault_list", {})
    check_value("vault_list status", r.get("status"), "ok")
    vault_ids = [v["vault_id"] for v in r.get("vaults", [])]
    check(f"'{VAULT}' dans la liste", VAULT in vault_ids)
    check(f"'{VAULT2}' dans la liste", VAULT2 in vault_ids)

    section("2c. Info d'un vault")
    cli_equiv(f"vault info {VAULT}")
    r = await mcp("vault_info", {"vault_id": VAULT})
    check_value("vault_info status", r.get("status"), "ok")
    check_value("description", r.get("description"), "Production")
    check("created_by présent", bool(r.get("created_by")))

    section("2d. Mettre à jour un vault")
    cli_equiv(f"vault update {VAULT} -d 'Production v2'")
    r = await mcp("vault_update", {"vault_id": VAULT, "description": "Production v2"})
    check("vault_update status", r.get("status") in ("ok", "updated"))

    # Vérifier la mise à jour
    r = await mcp("vault_info", {"vault_id": VAULT})
    check_value("description mise à jour", r.get("description"), "Production v2")

    # =====================================================================
    #  3. SECRETS — write (3 types), read, list, delete, password
    # =====================================================================
    banner("3. SECRETS — write, read, list, delete, password")

    section("3a. Écrire 3 secrets typés")
    cli_equiv(f"secret write {VAULT} web/github -d '{{\"username\":\"me\",\"password\":\"s3cr3t\"}}' -t login")
    r = await mcp("secret_write", {
        "vault_id": VAULT, "path": "web/github",
        "data": {"username": "me", "password": "s3cr3t"}, "secret_type": "login",
    })
    check_value("write login", r.get("status"), "ok")

    cli_equiv(f"secret write {VAULT} db/postgres -d '{{\"host\":\"db.local\",\"username\":\"pg\",\"password\":\"pw\"}}' -t database")
    r = await mcp("secret_write", {
        "vault_id": VAULT, "path": "db/postgres",
        "data": {"host": "db.local", "username": "pg", "password": "pw"}, "secret_type": "database",
    })
    check_value("write database", r.get("status"), "ok")

    cli_equiv(f"secret write {VAULT} shared/config -d '{{\"env\":\"prod\",\"debug\":\"false\"}}' -t custom")
    r = await mcp("secret_write", {
        "vault_id": VAULT, "path": "shared/config",
        "data": {"env": "prod", "debug": "false"}, "secret_type": "custom",
    })
    check_value("write custom", r.get("status"), "ok")

    section("3b. Lire un secret")
    cli_equiv(f"secret read {VAULT} web/github")
    r = await mcp("secret_read", {"vault_id": VAULT, "path": "web/github"})
    check_value("read status", r.get("status"), "ok")
    check_value("username", r.get("data", {}).get("username"), "me")
    check_value("type = login", r.get("data", {}).get("_type"), "login")

    section("3c. Lister les secrets")
    cli_equiv(f"secret list {VAULT}")
    r = await mcp("secret_list", {"vault_id": VAULT})
    check_value("list status", r.get("status"), "ok")
    keys = r.get("keys", [])
    check_value("3 secrets visibles", len(keys), 3)
    # KV v2 list retourne les clés au niveau répertoire (web/, db/, shared/)
    keys_str = str(keys)
    check("web/ dans la liste", "web" in keys_str)

    section("3d. Supprimer un secret")
    cli_equiv(f"secret delete {VAULT} db/postgres -y")
    r = await mcp("secret_delete", {"vault_id": VAULT, "path": "db/postgres"})
    check_value("delete status", r.get("status"), "deleted")

    # Vérifier la suppression
    r = await mcp("secret_list", {"vault_id": VAULT})
    check_value("2 secrets restants", len(r.get("keys", [])), 2)

    section("3e. Générer un mot de passe")
    cli_equiv("secret password -l 32")
    r = await mcp("secret_generate_password", {"length": 32})
    check_value("password status", r.get("status"), "ok")
    check_value("longueur = 32", len(r.get("password", "")), 32)

    # =====================================================================
    #  4. POLICY + PATH RULES — create, get, enforcement
    # =====================================================================
    banner("4. POLICY + PATH RULES — create, get, enforcement")

    POLICY = f"{PREFIX}-restricted"

    section("4a. Créer une policy avec path_rules + allowed_paths")
    path_rules_json = json.dumps([
        {"vault_pattern": VAULT, "permissions": ["read", "write"], "allowed_paths": ["shared/*"]},
    ])
    cli_equiv(f"policy create {POLICY} -d 'Accès shared/* uniquement' "
              f"--allowed 'secret_*,vault_list,vault_info,system_*' "
              f"--denied 'vault_delete,vault_create' "
              f"--path-rules '{path_rules_json}'")
    r = await mcp("policy_create", {
        "policy_id": POLICY,
        "description": "Accès shared/* uniquement",
        "allowed_tools": ["secret_*", "vault_list", "vault_info", "system_*"],
        "denied_tools": ["vault_delete", "vault_create"],
        "path_rules": [
            {"vault_pattern": VAULT, "permissions": ["read", "write"], "allowed_paths": ["shared/*"]},
        ],
    })
    check_value("policy_create status", r.get("status"), "created")
    check_value("path_rules count", len(r.get("path_rules", [])), 1)

    section("4b. Lire la policy — vérifier la structure")
    cli_equiv(f"policy get {POLICY}")
    r = await mcp("policy_get", {"policy_id": POLICY})
    check_value("policy_get status", r.get("status"), "ok")
    pr = r.get("path_rules", [])
    check_value("path_rule vault_pattern", pr[0].get("vault_pattern") if pr else None, VAULT)
    check_value("path_rule allowed_paths", pr[0].get("allowed_paths") if pr else None, ["shared/*"])
    check("allowed_tools contient secret_*", "secret_*" in r.get("allowed_tools", []))
    check("denied_tools contient vault_delete", "vault_delete" in r.get("denied_tools", []))

    section("4c. Lister les policies")
    cli_equiv("policy list")
    r = await mcp("policy_list", {})
    check_value("policy_list status", r.get("status"), "ok")
    policy_ids = [p["policy_id"] for p in r.get("policies", [])]
    check(f"'{POLICY}' dans la liste", POLICY in policy_ids)

    # =====================================================================
    #  5. TOKEN + POLICY — create, enforcement, update
    # =====================================================================
    banner("5. TOKEN + POLICY — create avec --policy, enforcement")

    AGENT_NAME = f"{PREFIX}-agent"

    # Pré-nettoyage : révoquer tout token résiduel des runs précédents
    r = await api("GET", "/admin/api/tokens")
    for t in r.get("tokens", []):
        if t.get("client_name") == AGENT_NAME:
            old_hash = t.get("hash_prefix", "")
            if old_hash:
                await api("DELETE", f"/admin/api/tokens/{old_hash}")
                print(f"    [cleanup] Token résiduel '{AGENT_NAME}' ({old_hash}) révoqué")

    section("5a. Créer un token avec policy assignée")
    cli_equiv(f"token create {AGENT_NAME} --permissions read,write --vaults {VAULT} --policy {POLICY}")
    r = await api("POST", "/admin/api/tokens", {
        "client_name": AGENT_NAME,
        "permissions": ["read", "write"],
        "allowed_resources": [VAULT],
        "expires_in_days": 1,
        "policy_id": POLICY,
    })
    check_value("token create status", r.get("status"), "created")
    agent_token = r.get("raw_token", "")
    agent_hash = r.get("hash_prefix", "?")
    check("raw_token non vide", len(agent_token) > 10)
    print(f"    → Token '{AGENT_NAME}' hash={agent_hash}")

    section("5b. Vérifier la policy dans token list")
    cli_equiv("token list")
    r = await api("GET", "/admin/api/tokens")
    found = None
    for t in r.get("tokens", []):
        # Chercher le token actif (pas révoqué) avec le bon nom
        if t.get("client_name") == AGENT_NAME and not t.get("revoked"):
            found = t
            break
    check(f"Token '{AGENT_NAME}' trouvé", found is not None)
    if found:
        check_value("policy_id dans la liste", found.get("policy_id"), POLICY)
        # Récupérer le hash depuis la liste (create ne le retourne pas toujours)
        if found.get("hash_prefix"):
            agent_hash = found["hash_prefix"]
            print(f"    → Hash récupéré depuis token list: {agent_hash}")

    section("5c. Enforcement path-level — shared/* autorisé")
    cli_equiv(f"--token <agent> secret read {VAULT} shared/config")
    r = await mcp("secret_read", {"vault_id": VAULT, "path": "shared/config"}, token_override=agent_token)
    check_value("Lecture shared/config → OK", r.get("status"), "ok")

    section("5d. Enforcement path-level — web/* REFUSÉ")
    cli_equiv(f"--token <agent> secret read {VAULT} web/github")
    r = await mcp("secret_read", {"vault_id": VAULT, "path": "web/github"}, token_override=agent_token)
    check_value("Lecture web/github → DENIED", r.get("status"), "error")
    check_contains("Message mentionne le chemin", r.get("message", ""), "web/github")
    print(f"    → Path enforcement OK !")

    section("5e. Enforcement tool-level — vault_delete REFUSÉ")
    cli_equiv(f"--token <agent> vault delete {VAULT} -y")
    r = await mcp("vault_delete", {"vault_id": VAULT, "confirm": True}, token_override=agent_token)
    check_value("vault_delete → DENIED", r.get("status"), "error")
    check_contains("Refusé par policy", r.get("message", ""), POLICY)
    print(f"    → Tool enforcement OK !")

    section("5f. Enforcement tool-level — vault_list AUTORISÉ")
    cli_equiv(f"--token <agent> vault list")
    r = await mcp("vault_list", {}, token_override=agent_token)
    check_value("vault_list → OK", r.get("status"), "ok")

    section("5g. Modifier le token — retirer la policy")
    cli_equiv(f"token update {agent_hash} --policy _remove")
    r = await api("PUT", f"/admin/api/tokens/{agent_hash}", {"policy_id": ""})
    check_value("token update status", r.get("status"), "updated")

    # Sans policy, le token peut maintenant lire web/github
    # Note: le PolicyStore a un cache TTL 5 min, petit délai pour le refresh
    import time; time.sleep(1)
    cli_equiv(f"--token <agent> secret read {VAULT} web/github  (après retrait policy)")
    r = await mcp("secret_read", {"vault_id": VAULT, "path": "web/github"}, token_override=agent_token)
    check("Lecture web/github → OK (policy retirée)", r.get("status") == "ok",
          "Le cache PolicyStore (TTL 5min) peut retarder la prise en compte" if r.get("status") != "ok" else "")
    print(f"    → Token update + retrait policy OK !")

    # =====================================================================
    #  6. SSH CA — setup, roles, role-info, ca-key, sign
    # =====================================================================
    banner("6. SSH CA — setup, roles, role-info, ca-key, sign")

    ROLE = "test-sre"

    section("6a. Setup SSH CA")
    cli_equiv(f"ssh setup {VAULT} {ROLE} --users deploy,admin --ttl 15m")
    r = await mcp("ssh_ca_setup", {
        "vault_id": VAULT, "role_name": ROLE,
        "allowed_users": "deploy,admin", "default_user": "deploy", "ttl": "15m",
    })
    check_value("ssh_ca_setup status", r.get("status"), "ok")
    check("mount_point présent", bool(r.get("mount_point")))

    section("6b. Lister les rôles SSH")
    cli_equiv(f"ssh roles {VAULT}")
    r = await mcp("ssh_ca_list_roles", {"vault_id": VAULT})
    check_value("ssh_ca_list_roles status", r.get("status"), "ok")
    check(f"Rôle '{ROLE}' dans la liste", ROLE in r.get("roles", []))

    section("6c. Info d'un rôle SSH")
    cli_equiv(f"ssh role-info {VAULT} {ROLE}")
    r = await mcp("ssh_ca_role_info", {"vault_id": VAULT, "role_name": ROLE})
    check_value("role_info status", r.get("status"), "ok")
    check_value("key_type = ca", r.get("key_type"), "ca")
    check_contains("allowed_users", r.get("allowed_users", ""), "deploy")

    section("6d. Récupérer la clé publique CA")
    cli_equiv(f"ssh ca-key {VAULT}")
    r = await mcp("ssh_ca_public_key", {"vault_id": VAULT})
    check_value("ca_public_key status", r.get("status"), "ok")
    # Le champ peut être "ca_public_key" ou "public_key" selon la version
    pub = r.get("ca_public_key", "") or r.get("public_key", "")
    check("Clé publique non vide", len(pub) > 20)

    section("6e. Signer une clé SSH (ed25519)")
    # Générer une clé de test
    import subprocess
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = os.path.join(tmpdir, "test_key")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", key_path, "-N", "", "-q"], check=True)
        with open(f"{key_path}.pub") as f:
            pub_key = f.read().strip()

    cli_equiv(f"ssh sign {VAULT} {ROLE} --key-data '{pub_key[:40]}...'")
    r = await mcp("ssh_sign_key", {
        "vault_id": VAULT, "role_name": ROLE, "public_key": pub_key, "ttl": "5m",
    })
    check_value("ssh_sign_key status", r.get("status"), "ok")
    check("signed_key non vide", len(r.get("signed_key", "")) > 50)
    check("serial_number présent", bool(r.get("serial_number")))
    print(f"    → SSH CA cycle complet OK !")

    # =====================================================================
    #  7. AUDIT — vérifier que les événements sont enregistrés
    # =====================================================================
    banner("7. AUDIT — vérifier les événements")

    section("7a. Consulter l'audit log")
    cli_equiv("audit --limit 10")
    r = await mcp("audit_log", {"limit": 10})
    check_value("audit_log status", r.get("status"), "ok")
    check("Événements > 0", r.get("total_in_buffer", 0) > 0)
    check("Entrées retournées", len(r.get("entries", [])) > 0)

    section("7b. Filtrer par status denied")
    cli_equiv("audit --status denied --limit 5")
    r = await mcp("audit_log", {"status": "denied", "limit": 5})
    check_value("audit denied status", r.get("status"), "ok")
    denied_count = len(r.get("entries", []))
    check(f"Au moins 2 denied (on en a généré 2)", denied_count >= 2)

    section("7c. Filtrer par vault")
    cli_equiv(f"audit --vault {VAULT} --limit 10")
    r = await mcp("audit_log", {"vault_id": VAULT, "limit": 10})
    check_value("audit vault filter status", r.get("status"), "ok")
    check("Événements pour le vault", len(r.get("entries", [])) > 0)

    section("7d. Stats d'audit")
    cli_equiv("audit --limit 1")
    r = await mcp("audit_log", {"limit": 1})
    stats = r.get("stats", {})
    check("Stats by_category présentes", bool(stats.get("by_category")))
    check("Stats by_status présentes", bool(stats.get("by_status")))
    print(f"    → Audit OK, {r.get('total_in_buffer', 0)} événements au total")

    # =====================================================================
    #  8. NETTOYAGE — supprimer tout ce qui a été créé
    # =====================================================================
    banner("8. NETTOYAGE — suppression de tous les objets de test")

    section("8a. Supprimer les secrets")
    for path in ["web/github", "shared/config"]:
        cli_equiv(f"secret delete {VAULT} {path} -y")
        r = await mcp("secret_delete", {"vault_id": VAULT, "path": path})
        check(f"delete {path}", r.get("status") in ("deleted", "error"))

    section("8b. Supprimer les vaults")
    for vid in [VAULT, VAULT2]:
        cli_equiv(f"vault delete {vid} -y")
        r = await mcp("vault_delete", {"vault_id": vid, "confirm": True})
        check(f"delete vault '{vid}'", r.get("status") in ("deleted", "error"))

    section("8c. Révoquer le token agent")
    if agent_hash and agent_hash != "?":
        cli_equiv(f"token revoke {agent_hash}")
        r = await api("DELETE", f"/admin/api/tokens/{agent_hash}")
        check(f"revoke token '{AGENT_NAME}'", r.get("status") in ("ok", "error"))

    section("8d. Supprimer la policy")
    cli_equiv(f"policy delete {POLICY} -y")
    r = await mcp("policy_delete", {"policy_id": POLICY, "confirm": True})
    check(f"delete policy '{POLICY}'", r.get("status") in ("deleted", "error"))

    print(f"\n    → Nettoyage terminé !")


# ═════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════════════════════

def main():
    global VERBOSE

    parser = argparse.ArgumentParser(description="Tests CLI LIVE — MCP Vault (serveur réel)")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()
    VERBOSE = args.verbose

    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║   Tests CLI LIVE — MCP Vault (serveur réel)                  ║")
    print("║                                                              ║")
    print("║  Teste le cycle complet contre un serveur en exécution :     ║")
    print("║    1. Système (health, about, whoami)                        ║")
    print("║    2. Vault CRUD (create, list, info, update, delete)        ║")
    print("║    3. Secrets (write, read, list, delete, password)          ║")
    print("║    4. Policy + Paths (create, get, enforcement)              ║")
    print("║    5. Token + Policy (create, update, enforcement)           ║")
    print("║    6. SSH CA (setup, roles, role-info, ca-key, sign)         ║")
    print("║    7. Audit (événements, filtres, stats)                     ║")
    print("║    8. Nettoyage complet                                      ║")
    print("║                                                              ║")
    print("╚══════════════════════════════════════════════════════════════╝")

    print(f"  Serveur : {BASE_URL:<47s}                                   ")
    print(f"  Token   : {TOKEN[:8]}{'.' * 39}{'':>1s}                     ")

    asyncio.run(run_all_tests())

    # Résumé
    total = PASS + FAIL
    print()
    print("=" * 70)
    if FAIL == 0:
        print(f"  ✅ TOUS LES TESTS PASSENT — {PASS}/{total}")
    else:
        print(f"  ❌ {FAIL} ÉCHEC(S) sur {total} tests — {PASS} OK, {FAIL} KO")
    print("=" * 70)
    print()

    sys.exit(1 if FAIL > 0 else 0)


if __name__ == "__main__":
    main()
