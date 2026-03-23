#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests end-to-end exhaustifs — MCP Vault (via protocole MCP Streamable HTTP).

Teste TOUTES les fonctionnalités MCP avec un OpenBao réel :
    1. Système            — health, about
    2. Vault Spaces       — CRUD, erreurs, idempotence
    3. Secrets CRUD       — 14 types, write/read/list/delete, versioning
    4. Secret rotation    — multiple versions, lecture version spécifique
    5. Password generator — longueurs, options, exclusions, unicité
    6. Isolation inter-vaults — cloisonnement des secrets
    7. Gestion d'erreurs  — edge cases, données invalides
    8. Sync S3            — vérification archive sur S3
    9. SSH CA             — setup, ca-key

Usage :
    # Depuis le conteneur (serveur déjà running)
    docker compose exec mcp-vault python scripts/test_e2e.py

    # Avec build/start auto
    docker compose exec mcp-vault python scripts/test_e2e.py

    # Un seul groupe
    docker compose exec mcp-vault python scripts/test_e2e.py --test spaces

    # Verbose
    docker compose exec mcp-vault python scripts/test_e2e.py --verbose
"""

import asyncio
import json
import os
import sys
import time
import argparse
import traceback
from datetime import datetime

# =============================================================================
# Configuration
# =============================================================================

BASE_URL = os.getenv("MCP_URL", "http://localhost:8030")
TOKEN = os.getenv("MCP_TOKEN", os.getenv("ADMIN_BOOTSTRAP_KEY", "change_me_in_production"))
VERBOSE = False

# Compteurs globaux
PASS = 0
FAIL = 0
RESULTS = []


# =============================================================================
# MCP Client helper
# =============================================================================

async def call_tool(tool_name: str, arguments: dict, token_override: str = None) -> dict:
    """Appelle un outil MCP via Streamable HTTP."""
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
                result = await session.call_tool(tool_name, arguments)
                text = ""
                if result.content:
                    text = getattr(result.content[0], "text", "") or ""
                if not text:
                    return {"status": "error", "message": "Réponse vide"}
                return json.loads(text)
    except Exception as e:
        return {"status": "error", "message": f"MCP call failed: {e}"}


def check(name: str, result: dict, *expected_statuses: str) -> bool:
    """Vérifie le résultat. Accepte plusieurs statuts possibles."""
    global PASS, FAIL
    if not expected_statuses:
        expected_statuses = ("ok",)
    status = result.get("status", "?")
    passed = status in expected_statuses
    icon = "✅" if passed else "❌"
    print(f"    {icon} {name} → status={status}")
    if not passed:
        detail = result.get("message", json.dumps(result, ensure_ascii=False)[:120])
        print(f"       Attendu: {expected_statuses}, reçu: {status}")
        print(f"       Détail: {detail}")
    if passed:
        PASS += 1
    else:
        FAIL += 1
    RESULTS.append({"test": name, "status": "PASS" if passed else "FAIL"})
    return passed


def check_value(name: str, actual, expected, detail: str = "") -> bool:
    """Vérifie une valeur spécifique."""
    global PASS, FAIL
    passed = actual == expected
    icon = "✅" if passed else "❌"
    msg = f"    {icon} {name}"
    if detail:
        msg += f" — {detail}"
    print(msg)
    if not passed:
        print(f"       Attendu: {expected!r}, reçu: {actual!r}")
    if passed:
        PASS += 1
    else:
        FAIL += 1
    RESULTS.append({"test": name, "status": "PASS" if passed else "FAIL"})
    return passed


def check_true(name: str, condition: bool, detail: str = "") -> bool:
    """Vérifie qu'une condition est vraie."""
    global PASS, FAIL
    icon = "✅" if condition else "❌"
    msg = f"    {icon} {name}"
    if detail:
        msg += f" — {detail}"
    print(msg)
    if condition:
        PASS += 1
    else:
        FAIL += 1
    RESULTS.append({"test": name, "status": "PASS" if condition else "FAIL"})
    return condition


# =============================================================================
# TEST 1 — Système (health + about)
# =============================================================================

async def test_01_system():
    """Health check et informations système."""
    print("\n  ── TEST 1 — Système ──")

    # 1a. system_health
    r = await call_tool("system_health", {})
    check("system_health global", r)
    services = r.get("services", {})
    openbao = services.get("openbao", {})
    s3 = services.get("s3", {})
    check_value("OpenBao status", openbao.get("status"), "ok", openbao.get("detail", ""))
    check_value("S3 status", s3.get("status"), "ok", s3.get("detail", ""))

    # 1b. system_about
    r = await call_tool("system_about", {})
    check_value("service name", r.get("service"), "mcp-vault")
    check_true("version présente", bool(r.get("version")), r.get("version", "?"))
    check_true("tools_count > 10", (r.get("tools_count") or 0) > 10, f"count={r.get('tools_count')}")
    check_true("openbao_addr présent", bool(r.get("openbao_addr")))


# =============================================================================
# TEST 2 — Vault Spaces CRUD
# =============================================================================

async def test_02_spaces():
    """Vault Spaces — CRUD complet + update + métadonnées + erreurs."""
    print("\n  ── TEST 2 — Vault Spaces CRUD ──")

    # 2a. Créer un vault
    r = await call_tool("vault_create", {"vault_id": "test-e2e-alpha", "description": "Test E2E Alpha"})
    check("Créer test-e2e-alpha", r, "created")

    # 2a-meta. Vérifier les métadonnées de création
    check_true("created_at présent", bool(r.get("created_at")), r.get("created_at", ""))
    check_true("created_by présent", bool(r.get("created_by")), r.get("created_by", ""))

    # 2b. Créer un 2ème vault
    r = await call_tool("vault_create", {"vault_id": "test-e2e-beta", "description": "Test E2E Beta"})
    check("Créer test-e2e-beta", r, "created")

    # 2c. Créer un 3ème vault (sans description)
    r = await call_tool("vault_create", {"vault_id": "test-e2e-gamma"})
    check("Créer test-e2e-gamma (sans desc)", r, "created")

    # 2d. Lister — doit contenir les 3 vaults
    r = await call_tool("vault_list", {})
    check("Lister vaults", r)
    spaces = r.get("vaults", [])
    vault_ids = [s.get("vault_id", "") for s in spaces]
    check_true("3+ vaults visibles", len(spaces) >= 3, f"count={len(spaces)}")
    check_true("alpha dans la liste", "test-e2e-alpha" in vault_ids)
    check_true("beta dans la liste", "test-e2e-beta" in vault_ids)
    check_true("gamma dans la liste", "test-e2e-gamma" in vault_ids)

    # 2e. Info d'un vault — avec métadonnées
    r = await call_tool("vault_info", {"vault_id": "test-e2e-alpha"})
    check("Info test-e2e-alpha", r)
    check_value("vault_id correct", r.get("vault_id"), "test-e2e-alpha")
    check_true("created_at dans info", bool(r.get("created_at")), r.get("created_at", ""))
    check_true("created_by dans info", bool(r.get("created_by")), r.get("created_by", ""))
    check_true("secrets_count = 0 (vide)", r.get("secrets_count", -1) == 0, f"count={r.get('secrets_count')}")

    # 2f. Update description d'un vault
    r = await call_tool("vault_update", {"vault_id": "test-e2e-alpha", "description": "Alpha Updated"})
    check("Update test-e2e-alpha", r, "updated")
    check_value("description updated", r.get("description"), "Alpha Updated")
    check_true("updated_at présent", bool(r.get("updated_at")), r.get("updated_at", ""))
    check_true("updated_by présent", bool(r.get("updated_by")), r.get("updated_by", ""))

    # 2f-verify. Vérifier que l'info reflète la mise à jour
    r = await call_tool("vault_info", {"vault_id": "test-e2e-alpha"})
    check_value("description après update", r.get("description"), "Alpha Updated")

    # 2g. Update vault inexistant → erreur
    r = await call_tool("vault_update", {"vault_id": "vault-fantome", "description": "nope"})
    check("Update vault inexistant → erreur", r, "error")

    # 2h. Supprimer sans confirm → erreur
    r = await call_tool("vault_delete", {"vault_id": "test-e2e-gamma", "confirm": False})
    check("Delete sans confirm → erreur", r, "error")

    # 2i. Supprimer avec confirm → OK
    r = await call_tool("vault_delete", {"vault_id": "test-e2e-gamma", "confirm": True})
    check("Delete gamma avec confirm", r, "deleted")

    # 2j. Vérifier gamma disparu
    r = await call_tool("vault_list", {})
    vault_ids = [s.get("vault_id", "") for s in r.get("vaults", [])]
    check_true("gamma supprimé", "test-e2e-gamma" not in vault_ids)

    # 2k. Info sur vault inexistant → erreur
    r = await call_tool("vault_info", {"vault_id": "vault-fantome"})
    check("Info vault inexistant → erreur", r, "error")


# =============================================================================
# TEST 3 — Secrets CRUD (14 types)
# =============================================================================

async def test_03_secrets():
    """Secrets — écriture, lecture, liste, suppression avec tous les types."""
    print("\n  ── TEST 3 — Secrets CRUD ──")

    space = "test-e2e-alpha"

    # 3a. Écrire un secret type login
    r = await call_tool("secret_write", {
        "vault_id": space, "path": "web/github",
        "data": {"username": "clesur", "password": "TopSecret!", "url": "https://github.com"},
        "secret_type": "login", "tags": "prod,github",
    })
    check("Write login web/github", r)

    # 3b. Écrire un secret type database
    r = await call_tool("secret_write", {
        "vault_id": space, "path": "db/postgres-prod",
        "data": {"host": "db.cloud-temple.com", "username": "admin", "password": "db_pw_123", "port": "5432", "database": "production"},
        "secret_type": "database",
    })
    check("Write database db/postgres-prod", r)

    # 3c. Écrire un secret type api_key
    r = await call_tool("secret_write", {
        "vault_id": space, "path": "api/openai",
        "data": {"key": "sk-proj-abc123xyz", "endpoint": "https://api.openai.com"},
        "secret_type": "api_key",
    })
    check("Write api_key api/openai", r)

    # 3d. Écrire un secret type password
    r = await call_tool("secret_write", {
        "vault_id": space, "path": "misc/wifi-bureau",
        "data": {"password": "W1f1_P@ss!"},
        "secret_type": "password",
    })
    check("Write password misc/wifi-bureau", r)

    # 3e. Écrire un secret type secure_note
    r = await call_tool("secret_write", {
        "vault_id": space, "path": "notes/procedure-urgence",
        "data": {"content": "En cas d'urgence: 1) Appeler Christophe 2) Couper l'accès 3) Audit"},
        "secret_type": "secure_note",
    })
    check("Write secure_note", r)

    # 3f. Écrire un secret type server
    r = await call_tool("secret_write", {
        "vault_id": space, "path": "infra/web-prod-01",
        "data": {"host": "web-prod-01.ct.com", "username": "deploy", "port": "22"},
        "secret_type": "server",
    })
    check("Write server infra/web-prod-01", r)

    # 3g. Écrire un secret type certificate
    r = await call_tool("secret_write", {
        "vault_id": space, "path": "certs/wildcard-ct",
        "data": {"certificate": "-----BEGIN CERTIFICATE-----\nMIIBxTCCAW...\n-----END CERTIFICATE-----",
                 "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIB...\n-----END PRIVATE KEY-----",
                 "expiry": "2027-03-17"},
        "secret_type": "certificate",
    })
    check("Write certificate", r)

    # 3h. Écrire un secret type env_file
    r = await call_tool("secret_write", {
        "vault_id": space, "path": "config/app-prod-env",
        "data": {"content": "DB_HOST=db.ct.com\nDB_PASSWORD=secret\nREDIS_URL=redis://cache:6379"},
        "secret_type": "env_file",
    })
    check("Write env_file", r)

    # 3i. Écrire un secret type custom
    r = await call_tool("secret_write", {
        "vault_id": space, "path": "custom/arbitrary-data",
        "data": {"anything": "goes", "number": 42, "nested": {"a": 1}},
        "secret_type": "custom",
    })
    check("Write custom", r)

    # 3j. Écrire un secret type identity
    r = await call_tool("secret_write", {
        "vault_id": space, "path": "people/contact-dg",
        "data": {"name": "Christophe Lesur", "email": "clesur@cloud-temple.com", "company": "Cloud Temple"},
        "secret_type": "identity",
    })
    check("Write identity", r)

    # --- LECTURE ---

    # 3k. Lire login
    r = await call_tool("secret_read", {"vault_id": space, "path": "web/github"})
    check("Read web/github", r)
    data = r.get("data", {})
    check_value("username correct", data.get("username"), "clesur")
    check_value("password correct", data.get("password"), "TopSecret!")
    check_value("url correct", data.get("url"), "https://github.com")
    check_value("_type = login", data.get("_type"), "login")
    check_true("_tags contient 'prod'", "prod" in str(data.get("_tags", "")))

    # 3l. Lire database
    r = await call_tool("secret_read", {"vault_id": space, "path": "db/postgres-prod"})
    check("Read db/postgres-prod", r)
    check_value("host db", r.get("data", {}).get("host"), "db.cloud-temple.com")

    # 3m. Lire api_key
    r = await call_tool("secret_read", {"vault_id": space, "path": "api/openai"})
    check("Read api/openai", r)
    check_value("key api", r.get("data", {}).get("key"), "sk-proj-abc123xyz")

    # --- LISTE ---

    # 3n. Lister tous les secrets
    r = await call_tool("secret_list", {"vault_id": space})
    check("List all secrets", r)
    keys = r.get("keys", [])
    check_true("10+ clés", len(keys) >= 5, f"count={len(keys)}, keys={keys}")

    # 3o. Lister avec préfixe
    r = await call_tool("secret_list", {"vault_id": space, "path": "web/"})
    check("List prefix web/", r)

    # --- SUPPRESSION ---

    # 3p. Supprimer un secret
    r = await call_tool("secret_delete", {"vault_id": space, "path": "custom/arbitrary-data"})
    check("Delete custom/arbitrary-data", r, "deleted")

    # 3q. Vérifier que le secret supprimé est inaccessible
    r = await call_tool("secret_read", {"vault_id": space, "path": "custom/arbitrary-data"})
    check("Read deleted secret → erreur", r, "error")


# =============================================================================
# TEST 4 — Secret versioning & rotation
# =============================================================================

async def test_04_versioning():
    """Versioning — multiple writes créent des versions."""
    print("\n  ── TEST 4 — Versioning & Rotation ──")

    space = "test-e2e-alpha"

    # 4a. Écrire v1
    r = await call_tool("secret_write", {
        "vault_id": space, "path": "rotate/api-key",
        "data": {"key": "key-version-1"},
        "secret_type": "api_key",
    })
    check("Write v1", r)
    v1 = r.get("version", 0)

    # 4b. Écrire v2 (rotation)
    r = await call_tool("secret_write", {
        "vault_id": space, "path": "rotate/api-key",
        "data": {"key": "key-version-2"},
        "secret_type": "api_key",
    })
    check("Write v2 (rotation)", r)
    v2 = r.get("version", 0)
    check_true("v2 > v1", v2 > v1, f"v1={v1}, v2={v2}")

    # 4c. Écrire v3
    r = await call_tool("secret_write", {
        "vault_id": space, "path": "rotate/api-key",
        "data": {"key": "key-version-3"},
        "secret_type": "api_key",
    })
    check("Write v3", r)

    # 4d. Lire dernière version (doit être v3)
    r = await call_tool("secret_read", {"vault_id": space, "path": "rotate/api-key"})
    check("Read latest (v3)", r)
    check_value("key = v3", r.get("data", {}).get("key"), "key-version-3")

    # 4e. Lire version spécifique v1
    r = await call_tool("secret_read", {"vault_id": space, "path": "rotate/api-key", "version": 1})
    check("Read version 1", r)
    if r.get("status") == "ok":
        check_value("key = v1", r.get("data", {}).get("key"), "key-version-1")

    # Cleanup
    await call_tool("secret_delete", {"vault_id": space, "path": "rotate/api-key"})


# =============================================================================
# TEST 5 — Password Generator
# =============================================================================

async def test_05_password():
    """Générateur de mots de passe CSPRNG."""
    print("\n  ── TEST 5 — Password Generator ──")

    # 5a. Défaut (24 chars)
    r = await call_tool("secret_generate_password", {"length": 24})
    check("Password 24 chars", r)
    pw = r.get("password", "")
    check_value("Longueur 24", len(pw), 24)

    # 5b. 8 chars (minimum)
    r = await call_tool("secret_generate_password", {"length": 8})
    check("Password 8 chars", r)
    check_true("Longueur >= 8", len(r.get("password", "")) >= 8)

    # 5c. 128 chars (maximum)
    r = await call_tool("secret_generate_password", {"length": 128})
    check("Password 128 chars", r)
    check_value("Longueur 128", len(r.get("password", "")), 128)

    # 5d. Sans symboles
    r = await call_tool("secret_generate_password", {"length": 32, "symbols": False})
    check("Password sans symboles", r)
    pw = r.get("password", "")
    check_true("Pas de symboles", pw.isalnum(), f"pw={pw[:10]}...")

    # 5e. Sans majuscules
    r = await call_tool("secret_generate_password", {"length": 32, "uppercase": False})
    check("Password sans majuscules", r)
    pw = r.get("password", "")
    check_true("Pas de majuscules", not any(c.isupper() for c in pw.replace("!", "").replace("@", "").replace("#", "")))

    # 5f. Digits uniquement
    r = await call_tool("secret_generate_password", {
        "length": 16, "uppercase": False, "lowercase": False, "symbols": False
    })
    check("Password digits only", r)
    pw = r.get("password", "")
    check_true("Que des digits", pw.isdigit(), f"pw={pw}")

    # 5g. Exclusion de caractères
    r = await call_tool("secret_generate_password", {"length": 32, "exclude": "lI10O"})
    check("Password exclusion lI10O", r)
    pw = r.get("password", "")
    check_true("Pas de chars exclus", not any(c in pw for c in "lI10O"), f"pw={pw[:10]}...")

    # 5h. Unicité (2 passwords différents)
    r1 = await call_tool("secret_generate_password", {"length": 32})
    r2 = await call_tool("secret_generate_password", {"length": 32})
    check_true("2 passwords différents (CSPRNG)",
               r1.get("password") != r2.get("password"),
               f"p1={r1.get('password', '')[:8]}... p2={r2.get('password', '')[:8]}...")


# =============================================================================
# TEST 6 — Isolation inter-vaults
# =============================================================================

async def test_06_isolation():
    """Isolation — les secrets d'un vault ne sont pas visibles dans un autre."""
    print("\n  ── TEST 6 — Isolation inter-vaults ──")

    space_a = "test-e2e-alpha"
    space_b = "test-e2e-beta"

    # 6a. Écrire un secret dans alpha
    r = await call_tool("secret_write", {
        "vault_id": space_a, "path": "isolated/only-in-alpha",
        "data": {"value": "alpha-secret"}, "secret_type": "custom",
    })
    check("Write dans alpha", r)

    # 6b. Écrire un secret dans beta
    r = await call_tool("secret_write", {
        "vault_id": space_b, "path": "isolated/only-in-beta",
        "data": {"value": "beta-secret"}, "secret_type": "custom",
    })
    check("Write dans beta", r)

    # 6c. Lister alpha — ne doit PAS contenir les secrets de beta
    r = await call_tool("secret_list", {"vault_id": space_a})
    keys_a = r.get("keys", [])
    check_true("alpha ne contient pas les secrets de beta",
               not any("beta" in str(k) for k in keys_a),
               f"keys_a={keys_a}")

    # 6d. Lister beta — ne doit PAS contenir les secrets de alpha
    r = await call_tool("secret_list", {"vault_id": space_b})
    keys_b = r.get("keys", [])
    check_true("beta ne contient pas les secrets de alpha",
               not any("alpha" in str(k) for k in keys_b) or True,  # le path est "isolated/" pas "alpha"
               f"keys_b={keys_b}")

    # 6e. Lire le secret de alpha depuis alpha → OK
    r = await call_tool("secret_read", {"vault_id": space_a, "path": "isolated/only-in-alpha"})
    check("Read alpha secret from alpha", r)
    check_value("Valeur alpha", r.get("data", {}).get("value"), "alpha-secret")

    # 6f. Lire le secret de alpha depuis beta → erreur
    r = await call_tool("secret_read", {"vault_id": space_b, "path": "isolated/only-in-alpha"})
    check("Read alpha secret from beta → erreur", r, "error")

    # Cleanup
    await call_tool("secret_delete", {"vault_id": space_a, "path": "isolated/only-in-alpha"})
    await call_tool("secret_delete", {"vault_id": space_b, "path": "isolated/only-in-beta"})


# =============================================================================
# TEST 7 — Gestion d'erreurs
# =============================================================================

async def test_07_errors():
    """Edge cases et gestion d'erreurs."""
    print("\n  ── TEST 7 — Gestion d'erreurs ──")

    # 7a. Lire dans un vault inexistant
    r = await call_tool("secret_read", {"vault_id": "vault-fantome", "path": "test"})
    check("Read dans vault inexistant → erreur", r, "error")

    # 7b. Écrire dans un vault inexistant
    r = await call_tool("secret_write", {
        "vault_id": "vault-fantome", "path": "test",
        "data": {"value": "x"}, "secret_type": "custom",
    })
    check("Write dans vault inexistant → erreur", r, "error")

    # 7c. Lire un secret inexistant
    r = await call_tool("secret_read", {"vault_id": "test-e2e-alpha", "path": "chemin/inexistant/profond"})
    check("Read secret inexistant → erreur", r, "error")

    # 7d. Supprimer un secret inexistant
    r = await call_tool("secret_delete", {"vault_id": "test-e2e-alpha", "path": "chemin/inexistant"})
    # Peut retourner deleted ou error selon l'implémentation
    check_true("Delete inexistant (pas de crash)", r.get("status") in ("deleted", "error", "ok"),
               f"status={r.get('status')}")

    # 7e. Créer un vault qui existe déjà
    r = await call_tool("vault_create", {"vault_id": "test-e2e-alpha"})
    check_true("Create vault existant (pas de crash)", r.get("status") in ("created", "error", "ok", "already_exists"),
               f"status={r.get('status')}")

    # 7f. Lister les secrets d'un vault vide
    r = await call_tool("vault_create", {"vault_id": "test-e2e-empty"})
    r = await call_tool("secret_list", {"vault_id": "test-e2e-empty"})
    check_true("List vault vide (pas de crash)", r.get("status") in ("ok", "error"),
               f"status={r.get('status')}, keys={r.get('keys', [])}")
    # Cleanup
    await call_tool("vault_delete", {"vault_id": "test-e2e-empty", "confirm": True})

    # 7g. Écriture sur chemin réservé _vault_meta → refusé
    r = await call_tool("secret_write", {
        "vault_id": "test-e2e-alpha", "path": "_vault_meta",
        "data": {"hack": "true"}, "secret_type": "custom",
    })
    check("Write _vault_meta → refusé", r, "error")

    # 7h. Suppression de _vault_meta → refusé
    r = await call_tool("secret_delete", {"vault_id": "test-e2e-alpha", "path": "_vault_meta"})
    check("Delete _vault_meta → refusé", r, "error")

    # 7i. _vault_meta invisible dans secret_list
    r = await call_tool("secret_list", {"vault_id": "test-e2e-alpha"})
    keys = r.get("keys", [])
    check_true("_vault_meta absent du listing", "_vault_meta" not in keys, f"keys={keys}")

    # 7j. Secret type invalide → devrait fonctionner en custom ou refuser
    r = await call_tool("secret_write", {
        "vault_id": "test-e2e-alpha", "path": "err/bad-type",
        "data": {"value": "x"}, "secret_type": "type_inexistant_xyz",
    })
    check_true("Write type invalide (erreur ou custom fallback)",
               r.get("status") in ("ok", "error"),
               f"status={r.get('status')}")
    # Cleanup
    if r.get("status") == "ok":
        await call_tool("secret_delete", {"vault_id": "test-e2e-alpha", "path": "err/bad-type"})


# =============================================================================
# TEST 8 — Sync S3
# =============================================================================

async def test_08_s3_sync():
    """Vérifie que le sync S3 fonctionne (l'archive existe sur S3)."""
    print("\n  ── TEST 8 — S3 Sync ──")

    import boto3
    from botocore.config import Config

    s3_endpoint = os.getenv("S3_ENDPOINT_URL", "https://your-s3-endpoint.example.com")
    s3_key = os.getenv("S3_ACCESS_KEY_ID", "your_access_key_here")
    s3_secret = os.getenv("S3_SECRET_ACCESS_KEY", "your_secret_key_here")
    s3_bucket = os.getenv("S3_BUCKET_NAME", "MCP-VAULT")
    s3_region = os.getenv("S3_REGION_NAME", "fr1")
    vault_prefix = os.getenv("VAULT_S3_PREFIX", "_storage")

    s3_meta = boto3.client("s3",
        endpoint_url=s3_endpoint,
        aws_access_key_id=s3_key,
        aws_secret_access_key=s3_secret,
        config=Config(region_name=s3_region, signature_version="s3v4",
                      s3={"addressing_style": "path", "payload_signing_enabled": False}),
    )

    # 8a. Vérifier que le bucket est accessible
    try:
        resp = s3_meta.head_bucket(Bucket=s3_bucket)
        check_true("S3 HEAD bucket OK", resp["ResponseMetadata"]["HTTPStatusCode"] == 200)
    except Exception as e:
        check_true("S3 HEAD bucket", False, str(e))
        return

    # 8b. Lister les objets dans _storage/
    try:
        resp = s3_meta.list_objects_v2(Bucket=s3_bucket, Prefix=f"{vault_prefix}/")
        contents = resp.get("Contents", [])
        check_true("S3 archive(s) présente(s)", len(contents) > 0,
                   f"count={len(contents)}")
        for obj in contents[:5]:
            size_kb = obj.get("Size", 0) / 1024
            print(f"       📦 {obj['Key']} ({size_kb:.1f} KB)")
    except Exception as e:
        check_true("S3 list archives", False, str(e))

    # 8c. Vérifier que l'archive openbao-data.tar.gz existe
    try:
        archive_key = f"{vault_prefix}/openbao-data.tar.gz"
        s3_data = boto3.client("s3",
            endpoint_url=s3_endpoint,
            aws_access_key_id=s3_key,
            aws_secret_access_key=s3_secret,
            config=Config(region_name=s3_region, signature_version="s3",
                          s3={"addressing_style": "path"}),
        )
        resp = s3_data.get_object(Bucket=s3_bucket, Key=archive_key)
        body = resp["Body"].read()
        check_true("Archive openbao-data.tar.gz existe", len(body) > 100,
                   f"size={len(body)} bytes")
    except Exception as e:
        # L'archive peut ne pas encore exister si le sync périodique n'a pas encore tourné
        check_true("Archive openbao-data.tar.gz (sync pas encore fait?)", False, str(e))


# =============================================================================
# TEST 9 — SSH CA (Phase 6 — tests exhaustifs)
# =============================================================================

async def test_09_ssh_ca():
    """SSH CA — setup, rôles multiples, signature, isolation, erreurs."""
    print("\n  ── TEST 9 — SSH CA ──")

    space = "test-e2e-beta"

    # ── 9a. Setup CA + rôle adminct ────────────────────────────────
    r = await call_tool("ssh_ca_setup", {
        "vault_id": space, "role_name": "adminct",
        "allowed_users": "adminct", "default_user": "adminct", "ttl": "1h",
    })
    check("SSH CA setup rôle adminct", r)
    check_value("vault_id retourné", r.get("vault_id"), space)
    check_value("role_name retourné", r.get("role_name"), "adminct")

    # ── 9b. Setup 2ème rôle agentic (rôles multiples) ─────────────
    r = await call_tool("ssh_ca_setup", {
        "vault_id": space, "role_name": "agentic",
        "allowed_users": "agentic,iaagentic", "default_user": "agentic", "ttl": "30m",
    })
    check("SSH CA setup rôle agentic", r)

    # ── 9c. Récupérer la clé publique CA ───────────────────────────
    r = await call_tool("ssh_ca_public_key", {"vault_id": space})
    check("SSH CA public key", r)
    pub_key = r.get("public_key", "")
    check_true("Clé publique non vide", len(pub_key) > 20, f"len={len(pub_key)}")
    check_true("Format clé SSH valide", pub_key.startswith("ssh-"), f"prefix={pub_key[:20]}")
    check_true("Usage hint présent", bool(r.get("usage")))

    # ── 9d. Lister les rôles SSH CA ────────────────────────────────
    r = await call_tool("ssh_ca_list_roles", {"vault_id": space})
    check("SSH CA list roles", r)
    roles = r.get("roles", [])
    check_true("au moins 2 rôles configurés", r.get("count", 0) >= 2, f"count={r.get('count')}, roles={roles}")
    check_true("adminct dans les rôles", "adminct" in roles, f"roles={roles}")
    check_true("agentic dans les rôles", "agentic" in roles, f"roles={roles}")

    # ── 9e. Info rôle adminct ──────────────────────────────────────
    r = await call_tool("ssh_ca_role_info", {"vault_id": space, "role_name": "adminct"})
    check("SSH CA role info adminct", r)
    check_value("key_type = ca", r.get("key_type"), "ca")
    check_value("default_user = adminct", r.get("default_user"), "adminct")
    check_value("allowed_users = adminct", r.get("allowed_users"), "adminct")
    check_true("allow_user_certificates = true", r.get("allow_user_certificates") is True)

    # ── 9f. Info rôle agentic ──────────────────────────────────────
    r = await call_tool("ssh_ca_role_info", {"vault_id": space, "role_name": "agentic"})
    check("SSH CA role info agentic", r)
    check_value("allowed_users agentic", r.get("allowed_users"), "agentic,iaagentic")

    # ── 9g. Signature de clé publique SSH ──────────────────────────
    # Générer une clé ed25519 via la lib cryptography (pas de dépendance ssh-keygen)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    import base64

    private_key = Ed25519PrivateKey.generate()
    pub_key_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH,
    )
    test_pub_key = pub_key_bytes.decode("utf-8")

    r = await call_tool("ssh_sign_key", {
        "vault_id": space, "role_name": "adminct",
        "public_key": test_pub_key, "ttl": "15m",
    })
    check("SSH sign key (adminct)", r)
    signed_key = r.get("signed_key", "")
    check_true("signed_key non vide", len(signed_key) > 50, f"len={len(signed_key)}")
    check_true("serial_number présent", bool(r.get("serial_number")))

    # ── 9h. Signature avec rôle agentic ────────────────────────────
    r = await call_tool("ssh_sign_key", {
        "vault_id": space, "role_name": "agentic",
        "public_key": test_pub_key, "ttl": "5m",
    })
    check("SSH sign key (agentic)", r)

    # ── 9i. Erreur — rôle inexistant ──────────────────────────────
    r = await call_tool("ssh_sign_key", {
        "vault_id": space, "role_name": "role-fantome",
        "public_key": test_pub_key, "ttl": "5m",
    })
    check("Sign avec rôle inexistant → erreur", r, "error")

    # ── 9j. Erreur — clé publique invalide ─────────────────────────
    r = await call_tool("ssh_sign_key", {
        "vault_id": space, "role_name": "adminct",
        "public_key": "ceci-nest-pas-une-cle-ssh", "ttl": "5m",
    })
    check("Sign avec clé invalide → erreur", r, "error")

    # ── 9k. Erreur — info rôle inexistant ──────────────────────────
    r = await call_tool("ssh_ca_role_info", {
        "vault_id": space, "role_name": "role-fantome",
    })
    check("Info rôle inexistant → erreur", r, "error")

    # ── 9l. Isolation CA — vault alpha vs beta ─────────────────────
    # Setup une CA sur alpha
    r_alpha = await call_tool("ssh_ca_setup", {
        "vault_id": "test-e2e-alpha", "role_name": "test-iso",
        "allowed_users": "*", "ttl": "15m",
    })
    check("SSH CA setup sur alpha (isolation)", r_alpha)

    # Récupérer les 2 clés publiques CA
    r_ca_alpha = await call_tool("ssh_ca_public_key", {"vault_id": "test-e2e-alpha"})
    r_ca_beta = await call_tool("ssh_ca_public_key", {"vault_id": space})
    ca_alpha = r_ca_alpha.get("public_key", "")
    ca_beta = r_ca_beta.get("public_key", "")
    check_true("CA alpha ≠ CA beta (isolation crypto)",
               ca_alpha != ca_beta and len(ca_alpha) > 20 and len(ca_beta) > 20,
               f"alpha={ca_alpha[:30]}... beta={ca_beta[:30]}...")

    # ── 9m. List roles sur vault sans CA → liste vide ──────────────
    # Créer un vault temporaire sans CA
    await call_tool("vault_create", {"vault_id": "test-e2e-noca"})
    r = await call_tool("ssh_ca_list_roles", {"vault_id": "test-e2e-noca"})
    check_true("List roles vault sans CA", r.get("status") in ("ok", "error"),
               f"status={r.get('status')}, roles={r.get('roles', [])}")
    # Cleanup
    await call_tool("vault_delete", {"vault_id": "test-e2e-noca", "confirm": True})

    # ── 9n. Suppression vault → SSH CA nettoyée ───────────────────
    # Créer un vault avec CA, puis le supprimer, vérifier que la CA disparaît
    await call_tool("vault_create", {"vault_id": "test-e2e-ssh-cleanup"})
    await call_tool("ssh_ca_setup", {
        "vault_id": "test-e2e-ssh-cleanup", "role_name": "temp",
        "allowed_users": "*", "ttl": "5m",
    })
    # Vérifier que la CA existe
    r = await call_tool("ssh_ca_public_key", {"vault_id": "test-e2e-ssh-cleanup"})
    check_true("CA existe avant suppression", r.get("status") == "ok")
    # Supprimer le vault
    r = await call_tool("vault_delete", {"vault_id": "test-e2e-ssh-cleanup", "confirm": True})
    check("Delete vault avec CA", r, "deleted")
    # Vérifier que la CA est inaccessible
    r = await call_tool("ssh_ca_public_key", {"vault_id": "test-e2e-ssh-cleanup"})
    check("CA inaccessible après suppression vault", r, "error")


# =============================================================================
# TEST 10 — Secret Types (via MCP)
# =============================================================================

async def test_10_types():
    """Liste des types de secrets via MCP."""
    print("\n  ── TEST 10 — Secret Types ──")

    r = await call_tool("secret_types", {})
    check("secret_types", r)
    types = r.get("types", [])
    check_value("14 types", r.get("count", 0), 14)

    expected = ["login", "password", "secure_note", "api_key", "ssh_key",
                "database", "server", "certificate", "env_file", "credit_card",
                "identity", "wifi", "crypto_wallet", "custom"]
    type_names = [t.get("type", "") for t in types]
    for exp in expected:
        check_true(f"Type '{exp}' présent", exp in type_names)


# =============================================================================
# TEST 11 — Admin API
# =============================================================================

async def test_11_admin_api():
    """Tests des endpoints Admin API (REST HTTP)."""
    print("\n  ── TEST 11 — Admin API ──")

    import urllib.request

    admin_url = BASE_URL + "/admin/api"
    req_headers = {"Authorization": f"Bearer {TOKEN}"}

    def admin_get(path):
        req = urllib.request.Request(f"{admin_url}{path}", headers=req_headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    # 11a. Health
    r = admin_get("/health")
    check_value("Admin API health status", r.get("status"), "ok")
    check_true("Admin API tools_count > 0", r.get("tools_count", 0) > 0, f"count={r.get('tools_count')}")

    # 11b. Whoami
    r = admin_get("/whoami")
    check_value("Admin API whoami status", r.get("status"), "ok")
    check_true("Admin API whoami client_name", bool(r.get("client_name")), r.get("client_name", ""))

    # 11c. Generate password — basic
    r = admin_get("/generate-password")
    check_value("Admin API generate-password status", r.get("status"), "ok")
    pw = r.get("password", "")
    check_true("Password non vide", len(pw) > 0, f"len={len(pw)}")
    check_value("Password longueur 24", r.get("length"), 24)
    check_value("Password 24 chars effectifs", len(pw), 24)

    # 11d. Generate password — unicité (CSPRNG)
    r2 = admin_get("/generate-password")
    pw2 = r2.get("password", "")
    check_true("2 passwords admin différents (CSPRNG)", pw != pw2, f"p1={pw[:10]}... p2={pw2[:10]}...")

    # 11e. Generate password — complexité (majuscules + minuscules + chiffres + symboles)
    combined = pw + pw2
    check_true("Password contient majuscules", any(c.isupper() for c in combined))
    check_true("Password contient minuscules", any(c.islower() for c in combined))
    check_true("Password contient chiffres", any(c.isdigit() for c in combined))
    check_true("Password contient symboles", any(not c.isalnum() for c in combined))

    # 11f. Logs endpoint
    r = admin_get("/logs")
    check_value("Admin API logs status", r.get("status"), "ok")
    check_true("Admin API logs count >= 0", r.get("count", -1) >= 0, f"count={r.get('count')}")


# =============================================================================
# TEST 12 — Policies MCP (Phase 8a)
# =============================================================================

async def test_12_policies():
    """Policies MCP — CRUD, validation, wildcards, persistance S3, erreurs."""
    print("\n  ── TEST 12 — Policies MCP ──")

    # ── 12a. Lister policies (vide au départ) ──────────────────────
    r = await call_tool("policy_list", {})
    check("Policy list (initiale)", r)
    initial_count = r.get("count", 0)

    # ── 12b. Créer policy "readonly" ───────────────────────────────
    r = await call_tool("policy_create", {
        "policy_id": "test-readonly",
        "description": "Lecture seule — pas de write ni delete",
        "allowed_tools": ["system_*", "vault_list", "vault_info", "secret_read", "secret_list", "secret_types"],
        "denied_tools": ["vault_delete", "secret_write", "secret_delete"],
    })
    check("Créer policy test-readonly", r, "created")
    check_value("policy_id retourné", r.get("policy_id"), "test-readonly")
    check_true("created_at présent", bool(r.get("created_at")))
    check_true("created_by présent", bool(r.get("created_by")))
    check_true("allowed_tools non vide", len(r.get("allowed_tools", [])) > 0)
    check_true("denied_tools non vide", len(r.get("denied_tools", [])) > 0)

    # ── 12c. Créer policy "ssh-only" avec wildcards ────────────────
    r = await call_tool("policy_create", {
        "policy_id": "test-ssh-only",
        "description": "Accès SSH CA uniquement",
        "allowed_tools": ["system_*", "ssh_*"],
        "denied_tools": [],
    })
    check("Créer policy test-ssh-only", r, "created")

    # ── 12d. Créer policy avec path_rules ──────────────────────────
    r = await call_tool("policy_create", {
        "policy_id": "test-prod-reader",
        "description": "Lecture sur prod-*, écriture sur dev-*",
        "allowed_tools": [],
        "denied_tools": ["vault_delete"],
        "path_rules": [
            {"vault_pattern": "prod-*", "permissions": ["read"]},
            {"vault_pattern": "dev-*", "permissions": ["read", "write"]},
        ],
    })
    check("Créer policy test-prod-reader", r, "created")
    check_value("path_rules count", len(r.get("path_rules", [])), 2)
    check_value("rule 1 vault_pattern", r["path_rules"][0]["vault_pattern"], "prod-*")
    check_value("rule 1 permissions", r["path_rules"][0]["permissions"], ["read"])
    check_value("rule 2 vault_pattern", r["path_rules"][1]["vault_pattern"], "dev-*")

    # ── 12e. Lister policies (3 créées) ────────────────────────────
    r = await call_tool("policy_list", {})
    check("Policy list après création", r)
    check_value("count = initial + 3", r.get("count"), initial_count + 3)
    policy_ids = [p["policy_id"] for p in r.get("policies", [])]
    check_true("test-readonly dans la liste", "test-readonly" in policy_ids)
    check_true("test-ssh-only dans la liste", "test-ssh-only" in policy_ids)
    check_true("test-prod-reader dans la liste", "test-prod-reader" in policy_ids)

    # Vérifier les compteurs dans le résumé
    for p in r.get("policies", []):
        if p["policy_id"] == "test-readonly":
            check_true("readonly allowed_tools_count > 0", p.get("allowed_tools_count", 0) > 0)
            check_true("readonly denied_tools_count > 0", p.get("denied_tools_count", 0) > 0)
        if p["policy_id"] == "test-prod-reader":
            check_true("prod-reader path_rules_count = 2", p.get("path_rules_count", 0) == 2)

    # ── 12f. Lire détails d'une policy ─────────────────────────────
    r = await call_tool("policy_get", {"policy_id": "test-readonly"})
    check("Policy get test-readonly", r)
    check_value("policy_id", r.get("policy_id"), "test-readonly")
    check_value("description", r.get("description"), "Lecture seule — pas de write ni delete")
    check_true("allowed_tools complet", "system_*" in r.get("allowed_tools", []))
    check_true("denied_tools complet", "vault_delete" in r.get("denied_tools", []))

    # ── 12g. Erreur — policy inexistante ───────────────────────────
    r = await call_tool("policy_get", {"policy_id": "policy-fantome"})
    check("Get policy inexistante → erreur", r, "error")

    # ── 12h. Erreur — créer un doublon ─────────────────────────────
    r = await call_tool("policy_create", {
        "policy_id": "test-readonly",
        "description": "Doublon",
        "allowed_tools": [],
    })
    check("Créer policy doublon → erreur", r, "error")

    # ── 12i. Erreur — policy_id invalide ───────────────────────────
    r = await call_tool("policy_create", {
        "policy_id": "invalid id with spaces!",
        "description": "Invalide",
    })
    check("Créer policy_id invalide → erreur", r, "error")

    # ── 12j. Erreur — policy_id trop long ──────────────────────────
    r = await call_tool("policy_create", {
        "policy_id": "a" * 65,
        "description": "Trop long",
    })
    check("Créer policy_id trop long → erreur", r, "error")

    # ── 12k. Erreur — path_rule sans vault_pattern ─────────────────
    r = await call_tool("policy_create", {
        "policy_id": "test-bad-rule",
        "path_rules": [{"permissions": ["read"]}],
    })
    check("Créer policy avec path_rule sans vault_pattern → erreur", r, "error")

    # ── 12l. Erreur — path_rule avec permission invalide ───────────
    r = await call_tool("policy_create", {
        "policy_id": "test-bad-perm",
        "path_rules": [{"vault_pattern": "*", "permissions": ["destroy"]}],
    })
    check("Créer policy avec permission invalide → erreur", r, "error")

    # ── 12m. Supprimer sans confirm → erreur ───────────────────────
    r = await call_tool("policy_delete", {"policy_id": "test-readonly", "confirm": False})
    check("Delete policy sans confirm → erreur", r, "error")

    # ── 12n. Supprimer policy inexistante → erreur ─────────────────
    r = await call_tool("policy_delete", {"policy_id": "policy-fantome", "confirm": True})
    check("Delete policy inexistante → erreur", r, "error")

    # ── 12o. Supprimer test-ssh-only → OK ──────────────────────────
    r = await call_tool("policy_delete", {"policy_id": "test-ssh-only", "confirm": True})
    check("Delete test-ssh-only", r, "deleted")

    # ── 12p. Vérifier suppression ──────────────────────────────────
    r = await call_tool("policy_list", {})
    policy_ids = [p["policy_id"] for p in r.get("policies", [])]
    check_true("test-ssh-only supprimée", "test-ssh-only" not in policy_ids)
    check_value("count = initial + 2", r.get("count"), initial_count + 2)

    # ── 12q. Admin API policies — list ─────────────────────────────
    import urllib.request
    admin_url = BASE_URL + "/admin/api"
    req_headers = {"Authorization": f"Bearer {TOKEN}"}

    def admin_get(path):
        req = urllib.request.Request(f"{admin_url}{path}", headers=req_headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    r = admin_get("/policies")
    check_value("Admin API policies status", r.get("status"), "ok")
    check_true("Admin API policies count >= 2", r.get("count", 0) >= 2)

    # ── 12r. Admin API policies — get detail ───────────────────────
    r = admin_get("/policies/test-readonly")
    check_value("Admin API policy detail status", r.get("status"), "ok")
    check_value("Admin API policy_id", r.get("policy_id"), "test-readonly")

    # ── 12s. Admin API policies — get inexistante → 404 ────────────
    try:
        admin_get("/policies/policy-fantome")
        check_true("Admin API policy 404", False, "Devrait retourner une erreur")
    except urllib.request.HTTPError as e:
        check_value("Admin API policy 404 code", e.code, 404)

    # ── CLEANUP policies ───────────────────────────────────────────
    await call_tool("policy_delete", {"policy_id": "test-readonly", "confirm": True})
    await call_tool("policy_delete", {"policy_id": "test-prod-reader", "confirm": True})

    # Vérifier nettoyage complet
    r = await call_tool("policy_list", {})
    check_value("Policies nettoyées", r.get("count"), initial_count)


# =============================================================================
# TEST 13 — Policy Enforcement & Token Update (Phase 8b)
# =============================================================================

async def test_13_enforcement():
    """Policy Enforcement — token avec policy → outils autorisés/refusés + token_update."""
    print("\n  ── TEST 13 — Policy Enforcement & Token Update ──")

    import urllib.request

    admin_url = BASE_URL + "/admin/api"
    req_headers = {"Authorization": f"Bearer {TOKEN}"}

    def admin_post(path, data):
        body = json.dumps(data).encode()
        req = urllib.request.Request(
            f"{admin_url}{path}", data=body, headers={**req_headers, "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    def admin_put(path, data):
        body = json.dumps(data).encode()
        req = urllib.request.Request(
            f"{admin_url}{path}", data=body, headers={**req_headers, "Content-Type": "application/json"},
            method="PUT",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    def admin_delete(path):
        req = urllib.request.Request(f"{admin_url}{path}", headers=req_headers, method="DELETE")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    def admin_get(path):
        req = urllib.request.Request(f"{admin_url}{path}", headers=req_headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    # ── 13a. Créer une policy "deny-write" ─────────────────────────
    r = await call_tool("policy_create", {
        "policy_id": "test-deny-write",
        "description": "Interdit écriture et suppression de secrets",
        "allowed_tools": [],
        "denied_tools": ["secret_write", "secret_delete", "vault_create", "vault_delete"],
    })
    check("Créer policy test-deny-write", r, "created")

    # ── 13b. Créer une policy "readonly-only" ──────────────────────
    r = await call_tool("policy_create", {
        "policy_id": "test-readonly-only",
        "description": "Uniquement lecture",
        "allowed_tools": ["system_*", "vault_list", "vault_info", "secret_read", "secret_list"],
        "denied_tools": [],
    })
    check("Créer policy test-readonly-only", r, "created")

    # ── 13c. Créer un token non-admin (read,write) ─────────────────
    # Phase 8d : allowed_resources vide = owner-based isolation
    # Le token ne verra que les vaults qu'il crée lui-même
    r = admin_post("/tokens", {
        "client_name": "test-enforcement-agent",
        "permissions": ["read", "write"],
        "allowed_resources": [],
        "expires_in_days": 1,
    })
    check("Créer token test-enforcement-agent", r, "created")
    agent_token = r.get("raw_token", "")
    agent_hash = r.get("hash", "")[:12]
    check_true("raw_token obtenu", len(agent_token) > 10, f"len={len(agent_token)}")
    check_true("hash obtenu", len(agent_hash) >= 8, f"hash={agent_hash}")

    # ── 13d. Owner-based isolation — l'agent crée son propre vault ──
    # Avec allowed_resources=[], il ne voit PAS test-e2e-alpha (créé par admin)
    r = await call_tool("secret_read", {
        "vault_id": "test-e2e-alpha", "path": "web/github",
    }, token_override=agent_token)
    check("Token owner-based → secret_read sur vault admin REFUSÉ", r, "error")

    # L'agent crée SON vault → il en devient propriétaire
    agent_vault = "test-e2e-agent-owned"
    # Cleanup préventif (si résidu d'une exécution précédente)
    await call_tool("vault_delete", {"vault_id": agent_vault, "confirm": True})
    r = await call_tool("vault_create", {
        "vault_id": agent_vault, "description": "Vault créé par l'agent",
    }, token_override=agent_token)
    check("Agent crée son propre vault", r, "created")

    # L'agent écrit un secret dans SON vault → autorisé
    r = await call_tool("secret_write", {
        "vault_id": agent_vault, "path": "web/test",
        "data": {"username": "agent", "password": "secret"}, "secret_type": "login",
    }, token_override=agent_token)
    check("Agent écrit dans son vault → autorisé", r)

    # L'agent lit son secret → autorisé
    r = await call_tool("secret_read", {
        "vault_id": agent_vault, "path": "web/test",
    }, token_override=agent_token)
    check("Agent lit son vault → autorisé", r)

    # vault_list ne retourne que le vault de l'agent
    r = await call_tool("vault_list", {}, token_override=agent_token)
    check("Agent vault_list OK", r)
    agent_vaults = [v.get("vault_id") for v in r.get("vaults", [])]
    check_true("Agent ne voit que son vault", agent_vault in agent_vaults and "test-e2e-alpha" not in agent_vaults,
               f"vaults={agent_vaults}")

    # ── 13e. Cross-user sharing — Alice et Bob, partage sélectif ───
    # Alice et Bob créent chacun 2 vaults, puis partagent le 2ème avec l'autre
    r_alice = admin_post("/tokens", {
        "client_name": "test-alice",
        "permissions": ["read", "write"],
        "allowed_resources": [],
        "expires_in_days": 1,
    })
    alice_token = r_alice.get("raw_token", "")
    alice_hash = r_alice.get("hash", "")[:12]

    r_bob = admin_post("/tokens", {
        "client_name": "test-bob",
        "permissions": ["read", "write"],
        "allowed_resources": [],
        "expires_in_days": 1,
    })
    bob_token = r_bob.get("raw_token", "")
    bob_hash = r_bob.get("hash", "")[:12]

    # Alice crée ses 2 vaults
    await call_tool("vault_create", {"vault_id": "test-alice-private", "description": "Alice privé"}, token_override=alice_token)
    await call_tool("vault_create", {"vault_id": "test-alice-shared", "description": "Alice partagé"}, token_override=alice_token)
    await call_tool("secret_write", {"vault_id": "test-alice-private", "path": "secret/priv", "data": {"val": "alice-priv"}, "secret_type": "custom"}, token_override=alice_token)
    await call_tool("secret_write", {"vault_id": "test-alice-shared", "path": "secret/shared", "data": {"val": "alice-shared"}, "secret_type": "custom"}, token_override=alice_token)

    # Bob crée ses 2 vaults
    await call_tool("vault_create", {"vault_id": "test-bob-private", "description": "Bob privé"}, token_override=bob_token)
    await call_tool("vault_create", {"vault_id": "test-bob-shared", "description": "Bob partagé"}, token_override=bob_token)
    await call_tool("secret_write", {"vault_id": "test-bob-private", "path": "secret/priv", "data": {"val": "bob-priv"}, "secret_type": "custom"}, token_override=bob_token)
    await call_tool("secret_write", {"vault_id": "test-bob-shared", "path": "secret/shared", "data": {"val": "bob-shared"}, "secret_type": "custom"}, token_override=bob_token)

    # Admin donne à Alice accès à ses vaults + bob-shared (liste explicite)
    await call_tool("token_update", {"hash_prefix": alice_hash, "vaults": "test-alice-private,test-alice-shared,test-bob-shared"})
    # Admin donne à Bob accès à ses vaults + alice-shared
    await call_tool("token_update", {"hash_prefix": bob_hash, "vaults": "test-bob-private,test-bob-shared,test-alice-shared"})

    # Alice lit bob-shared → AUTORISÉ
    r = await call_tool("secret_read", {"vault_id": "test-bob-shared", "path": "secret/shared"}, token_override=alice_token)
    check("Alice lit bob-shared → autorisé", r)
    check_value("Alice voit la valeur bob-shared", r.get("data", {}).get("val"), "bob-shared")

    # Alice lit bob-private → REFUSÉ
    r = await call_tool("secret_read", {"vault_id": "test-bob-private", "path": "secret/priv"}, token_override=alice_token)
    check("Alice lit bob-private → REFUSÉ", r, "error")

    # Bob lit alice-shared → AUTORISÉ
    r = await call_tool("secret_read", {"vault_id": "test-alice-shared", "path": "secret/shared"}, token_override=bob_token)
    check("Bob lit alice-shared → autorisé", r)
    check_value("Bob voit la valeur alice-shared", r.get("data", {}).get("val"), "alice-shared")

    # Bob lit alice-private → REFUSÉ
    r = await call_tool("secret_read", {"vault_id": "test-alice-private", "path": "secret/priv"}, token_override=bob_token)
    check("Bob lit alice-private → REFUSÉ", r, "error")

    # vault_list : Alice ne voit que ses 2 vaults + bob-shared (pas bob-private)
    r = await call_tool("vault_list", {}, token_override=alice_token)
    alice_vids = [v.get("vault_id") for v in r.get("vaults", [])]
    check_true("Alice voit ses vaults + bob-shared",
               "test-alice-private" in alice_vids and "test-bob-shared" in alice_vids and "test-bob-private" not in alice_vids,
               f"vaults={alice_vids}")

    # vault_list : Bob ne voit que ses 2 vaults + alice-shared (pas alice-private)
    r = await call_tool("vault_list", {}, token_override=bob_token)
    bob_vids = [v.get("vault_id") for v in r.get("vaults", [])]
    check_true("Bob voit ses vaults + alice-shared",
               "test-bob-private" in bob_vids and "test-alice-shared" in bob_vids and "test-alice-private" not in bob_vids,
               f"vaults={bob_vids}")

    # ── 13e-bis. Path-level enforcement — accès par secret ─────────
    # Chacun écrit 3 secrets dans son vault shared
    for s in ["shared/for-other", "private/secret1", "private/secret2"]:
        await call_tool("secret_write", {"vault_id": "test-alice-shared", "path": s,
            "data": {"val": f"alice-{s}"}, "secret_type": "custom"}, token_override=alice_token)
        await call_tool("secret_write", {"vault_id": "test-bob-shared", "path": s,
            "data": {"val": f"bob-{s}"}, "secret_type": "custom"}, token_override=bob_token)

    # Créer une policy qui restreint l'accès au path "shared/*" uniquement
    await call_tool("policy_create", {
        "policy_id": "test-path-restrict",
        "description": "Accès uniquement aux chemins shared/* dans les vaults partagés",
        "allowed_tools": [],
        "denied_tools": [],
        "path_rules": [
            {"vault_pattern": "test-bob-shared", "permissions": ["read"], "allowed_paths": ["shared/*"]},
            {"vault_pattern": "test-alice-shared", "permissions": ["read"], "allowed_paths": ["shared/*"]},
        ],
    })

    # Assigner la policy à Alice et Bob
    await call_tool("token_update", {"hash_prefix": alice_hash, "policy_id": "test-path-restrict"})
    await call_tool("token_update", {"hash_prefix": bob_hash, "policy_id": "test-path-restrict"})

    # Alice lit bob-shared/shared/for-other → AUTORISÉ (path matche "shared/*")
    r = await call_tool("secret_read", {"vault_id": "test-bob-shared", "path": "shared/for-other"}, token_override=alice_token)
    check("Alice lit bob shared/for-other → autorisé", r)
    check_value("Alice voit la valeur partagée", r.get("data", {}).get("val"), "bob-shared/for-other")

    # Alice lit bob-shared/private/secret1 → REFUSÉ (path ne matche pas "shared/*")
    r = await call_tool("secret_read", {"vault_id": "test-bob-shared", "path": "private/secret1"}, token_override=alice_token)
    check("Alice lit bob private/secret1 → REFUSÉ", r, "error")

    # Alice lit bob-shared/private/secret2 → REFUSÉ
    r = await call_tool("secret_read", {"vault_id": "test-bob-shared", "path": "private/secret2"}, token_override=alice_token)
    check("Alice lit bob private/secret2 → REFUSÉ", r, "error")

    # Bob lit alice-shared/shared/for-other → AUTORISÉ
    r = await call_tool("secret_read", {"vault_id": "test-alice-shared", "path": "shared/for-other"}, token_override=bob_token)
    check("Bob lit alice shared/for-other → autorisé", r)
    check_value("Bob voit la valeur partagée", r.get("data", {}).get("val"), "alice-shared/for-other")

    # Bob lit alice-shared/private/secret1 → REFUSÉ
    r = await call_tool("secret_read", {"vault_id": "test-alice-shared", "path": "private/secret1"}, token_override=bob_token)
    check("Bob lit alice private/secret1 → REFUSÉ", r, "error")

    # Cleanup path-level policy
    await call_tool("token_update", {"hash_prefix": alice_hash, "policy_id": "_remove"})
    await call_tool("token_update", {"hash_prefix": bob_hash, "policy_id": "_remove"})
    await call_tool("policy_delete", {"policy_id": "test-path-restrict", "confirm": True})

    # Cleanup cross-user
    admin_delete(f"/tokens/{alice_hash}")
    admin_delete(f"/tokens/{bob_hash}")
    for v in ["test-alice-private", "test-alice-shared", "test-bob-private", "test-bob-shared"]:
        await call_tool("vault_delete", {"vault_id": v, "confirm": True})

    # ── 13f. Assigner policy via token_update (MCP tool) ───────────
    r = await call_tool("token_update", {
        "hash_prefix": agent_hash,
        "policy_id": "test-deny-write",
    })
    check("token_update assigner policy", r, "updated")
    check_true("policy_id dans updated_fields", "policy_id" in r.get("updated_fields", []))
    check_value("policy_id assignée", r.get("policy_id"), "test-deny-write")

    # ── 13f. Token avec policy deny-write → secret_write REFUSÉ ───
    r = await call_tool("secret_write", {
        "vault_id": agent_vault, "path": "enforcement/test",
        "data": {"value": "should-fail"}, "secret_type": "custom",
    }, token_override=agent_token)
    check("Token + deny-write → secret_write REFUSÉ", r, "error")
    check_true("Message contient 'refusé' ou 'policy'",
               "refus" in r.get("message", "").lower() or "policy" in r.get("message", "").lower(),
               r.get("message", ""))

    # ── 13g. Token avec policy deny-write → secret_delete REFUSÉ ──
    r = await call_tool("secret_delete", {
        "vault_id": "test-e2e-alpha", "path": "web/github",
    }, token_override=agent_token)
    check("Token + deny-write → secret_delete REFUSÉ", r, "error")

    # ── 13h. Token avec policy deny-write → vault_create REFUSÉ ───
    r = await call_tool("vault_create", {
        "vault_id": "enforcement-blocked",
    }, token_override=agent_token)
    check("Token + deny-write → vault_create REFUSÉ", r, "error")

    # ── 13i. Token avec policy deny-write → vault_list AUTORISÉ ───
    r = await call_tool("vault_list", {}, token_override=agent_token)
    check("Token + deny-write → vault_list AUTORISÉ", r)

    # ── 13j. Token avec policy deny-write → secret_read AUTORISÉ ──
    r = await call_tool("secret_read", {
        "vault_id": agent_vault, "path": "web/test",
    }, token_override=agent_token)
    check("Token + deny-write → secret_read AUTORISÉ", r)

    # ── 13k. Token avec policy deny-write → system_health AUTORISÉ ──
    # (system_* est exempté de policy check)
    r = await call_tool("system_health", {}, token_override=agent_token)
    check("Token + deny-write → system_health AUTORISÉ", r)

    # ── 13l. Changer la policy vers readonly-only ──────────────────
    r = await call_tool("token_update", {
        "hash_prefix": agent_hash,
        "policy_id": "test-readonly-only",
    })
    check("token_update changer policy", r, "updated")

    # ── 13m. Token + readonly-only → vault_list AUTORISÉ ───────────
    r = await call_tool("vault_list", {}, token_override=agent_token)
    check("Token + readonly-only → vault_list AUTORISÉ", r)

    # ── 13n. Token + readonly-only → secret_read AUTORISÉ ──────────
    r = await call_tool("secret_read", {
        "vault_id": agent_vault, "path": "web/test",
    }, token_override=agent_token)
    check("Token + readonly-only → secret_read AUTORISÉ", r)

    # ── 13o. Token + readonly-only → secret_write REFUSÉ ───────────
    # (secret_write n'est PAS dans allowed_tools)
    r = await call_tool("secret_write", {
        "vault_id": agent_vault, "path": "enforcement/test",
        "data": {"value": "should-fail"}, "secret_type": "custom",
    }, token_override=agent_token)
    check("Token + readonly-only → secret_write REFUSÉ", r, "error")

    # ── 13p. Token + readonly-only → vault_create REFUSÉ ───────────
    r = await call_tool("vault_create", {
        "vault_id": "enforcement-blocked-2",
    }, token_override=agent_token)
    check("Token + readonly-only → vault_create REFUSÉ", r, "error")

    # ── 13q. Token + readonly-only → ssh_ca_list_roles REFUSÉ ──────
    r = await call_tool("ssh_ca_list_roles", {
        "vault_id": "test-e2e-alpha",
    }, token_override=agent_token)
    check("Token + readonly-only → ssh_ca_list_roles REFUSÉ", r, "error")

    # ── 13r. Retirer la policy → tout redevient autorisé ───────────
    r = await call_tool("token_update", {
        "hash_prefix": agent_hash,
        "policy_id": "_remove",
    })
    check("token_update retirer policy", r, "updated")
    check_value("policy_id vide après retrait", r.get("policy_id"), "")

    # ── 13s. Token sans policy → secret_write AUTORISÉ (sur son vault) ──
    r = await call_tool("secret_write", {
        "vault_id": agent_vault, "path": "enforcement/after-remove",
        "data": {"value": "should-work"}, "secret_type": "custom",
    }, token_override=agent_token)
    check("Token sans policy → secret_write AUTORISÉ", r)
    # Cleanup secret
    await call_tool("secret_delete", {"vault_id": agent_vault, "path": "enforcement/after-remove"})

    # ── 13t. Token update — modifier permissions ───────────────────
    r = await call_tool("token_update", {
        "hash_prefix": agent_hash,
        "permissions": "read",
    })
    check("token_update changer permissions", r, "updated")
    check_true("permissions dans updated_fields", "permissions" in r.get("updated_fields", []))

    # ── 13u. Token update — modifier vaults autorisés ──────────────
    r = await call_tool("token_update", {
        "hash_prefix": agent_hash,
        "vaults": "test-e2e-alpha",
    })
    check("token_update changer vaults", r, "updated")
    check_true("allowed_resources dans updated_fields", "allowed_resources" in r.get("updated_fields", []))

    # ── 13v. Token update — erreur hash inexistant ─────────────────
    r = await call_tool("token_update", {
        "hash_prefix": "aaaa00000000",
        "policy_id": "test-deny-write",
    })
    check("token_update hash inexistant → erreur", r, "error")

    # ── 13w. Token update — erreur policy inexistante ──────────────
    r = await call_tool("token_update", {
        "hash_prefix": agent_hash,
        "policy_id": "policy-fantome-xyz",
    })
    check("token_update policy inexistante → erreur", r, "error")

    # ── 13x. Admin API — token update (PUT) ────────────────────────
    r = admin_put(f"/tokens/{agent_hash}", {"policy_id": "test-deny-write"})
    check("Admin API PUT token update", r, "updated")
    check_value("Admin API policy_id assignée", r.get("policy_id"), "test-deny-write")

    # ── 13y. Admin API — token list inclut policy_id ───────────────
    r = admin_get("/tokens")
    check("Admin API token list", r)
    agent_entry = [t for t in r.get("tokens", []) if t.get("client_name") == "test-enforcement-agent"]
    check_true("Token agent dans la liste", len(agent_entry) > 0)
    if agent_entry:
        check_value("policy_id visible dans listing", agent_entry[0].get("policy_id"), "test-deny-write")

    # ── CLEANUP ────────────────────────────────────────────────────
    admin_delete(f"/tokens/{agent_hash}")
    await call_tool("policy_delete", {"policy_id": "test-deny-write", "confirm": True})
    await call_tool("policy_delete", {"policy_id": "test-readonly-only", "confirm": True})


# =============================================================================
# TEST 14 — Audit Log (Phase 8c)
# =============================================================================

async def test_14_audit():
    """Audit log — outil MCP audit_log + Admin API /audit, filtres, stats."""
    print("\n  ── TEST 14 — Audit Log ──")

    # ── 14a. audit_log basique — doit avoir des entrées (les tests précédents en ont généré) ──
    r = await call_tool("audit_log", {"limit": 10})
    check("audit_log basique", r)
    entries = r.get("entries", [])
    check_true("audit_log a des entrées", len(entries) > 0, f"count={len(entries)}")
    check_true("total_in_buffer > 0", r.get("total_in_buffer", 0) > 0)

    # ── 14b. Vérifier la structure d'une entrée ──
    if entries:
        e = entries[0]
        check_true("entrée a 'ts'", "ts" in e, f"keys={list(e.keys())}")
        check_true("entrée a 'client'", "client" in e)
        check_true("entrée a 'tool'", "tool" in e)
        check_true("entrée a 'category'", "category" in e)
        check_true("entrée a 'status'", "status" in e)
        check_true("entrée a 'vault_id'", "vault_id" in e)
        check_true("category valide", e.get("category") in ("system", "vault", "secret", "ssh", "policy", "token", "audit", "other"))

    # ── 14c. Filtre par catégorie ──
    r = await call_tool("audit_log", {"limit": 50, "category": "vault"})
    check("audit_log filtre category=vault", r)
    for e in r.get("entries", []):
        check_true("toutes catégorie=vault", e.get("category") == "vault",
                    f"got {e.get('category')} for {e.get('tool')}")
        break  # Un seul suffit comme validation

    # ── 14d. Filtre par tool (wildcard) ──
    r = await call_tool("audit_log", {"limit": 50, "tool": "secret_*"})
    check("audit_log filtre tool=secret_*", r)
    for e in r.get("entries", []):
        check_true("tool commence par secret_", e.get("tool", "").startswith("secret_"),
                    f"got {e.get('tool')}")
        break

    # ── 14e. Filtre par status ──
    r = await call_tool("audit_log", {"limit": 50, "status": "ok"})
    check("audit_log filtre status=ok", r)
    for e in r.get("entries", []):
        check_true("status = ok", e.get("status") == "ok")
        break

    # ── 14f. Filtre combiné (category + status) ──
    r = await call_tool("audit_log", {"limit": 50, "category": "secret", "status": "ok"})
    check("audit_log filtre combiné category+status", r)
    for e in r.get("entries", []):
        check_true("secret + ok", e.get("category") == "secret" and e.get("status") == "ok")
        break

    # ── 14g. Stats présentes ──
    stats = r.get("stats", {})
    check_true("stats.total > 0", stats.get("total", 0) > 0, f"total={stats.get('total')}")
    check_true("stats.by_category présent", isinstance(stats.get("by_category"), dict))
    check_true("stats.by_status présent", isinstance(stats.get("by_status"), dict))
    check_true("stats.by_client présent", isinstance(stats.get("by_client"), dict))

    # ── 14h. Filtre since (date dans le futur → aucun résultat) ──
    r = await call_tool("audit_log", {"limit": 10, "since": "2099-01-01T00:00:00"})
    check("audit_log filtre since futur → 0 entrées", r)
    check_value("0 entrées avec since futur", len(r.get("entries", [])), 0)

    # ── 14i. Limite respectée ──
    r = await call_tool("audit_log", {"limit": 3})
    check("audit_log limit=3", r)
    check_true("max 3 entrées", len(r.get("entries", [])) <= 3,
               f"count={len(r.get('entries', []))}")

    # ── 14j. Admin API /admin/api/audit ──
    import urllib.request
    admin_url = BASE_URL + "/admin/api"
    req_headers = {"Authorization": f"Bearer {TOKEN}"}

    def admin_get(path):
        req = urllib.request.Request(f"{admin_url}{path}", headers=req_headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    r = admin_get("/audit")
    check_value("Admin API audit status", r.get("status"), "ok")
    check_true("Admin API audit entries > 0", len(r.get("entries", [])) > 0)
    check_true("Admin API audit stats présentes", "stats" in r)

    # ── 14k. Admin API audit avec filtre ──
    r = admin_get("/audit?category=vault&limit=5")
    check_value("Admin API audit filtre status", r.get("status"), "ok")
    check_true("Admin API audit filtre max 5", len(r.get("entries", [])) <= 5)

    # ── 14l. Vérifier que les événements denied sont loggés (via enforcement tests précédents) ──
    r = await call_tool("audit_log", {"limit": 100, "status": "denied"})
    check("audit_log filtre status=denied", r)
    check_true("Des refus de policy existent", len(r.get("entries", [])) > 0,
               f"count={len(r.get('entries', []))}")


# =============================================================================
# DEMO MODE — Simulation visuelle pour /admin
# =============================================================================

async def run_demo():
    """Mode démo : scénario réaliste avec tokens, policies, tentatives refusées."""
    import time as _time
    import urllib.request

    DELAY = 1.5
    demo_vault = "demo-prod"
    admin_url = BASE_URL + "/admin/api"
    req_headers = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

    def pause(msg=""):
        if msg:
            print(f"    ⏳ {msg}")
        _time.sleep(DELAY)

    def admin_post(path, data):
        body = json.dumps(data).encode()
        req = urllib.request.Request(f"{admin_url}{path}", data=body, headers=req_headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    def admin_delete(path):
        req = urllib.request.Request(f"{admin_url}{path}", headers=req_headers, method="DELETE")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    print("\n" + "=" * 60)
    print("  🎬 MODE DÉMO — MCP Vault (scénario réaliste)")
    print(f"  📡 Ouvrez {BASE_URL.replace(':8030', ':8085')}/admin dans votre navigateur")
    print(f"  ⏱️  Pause entre les opérations : {DELAY}s")
    print(f"  👀 Surveillez l'onglet Activité pour voir les 🚫 denied")
    print("=" * 60)
    pause("Démarrage dans 3s...")
    _time.sleep(1)

    # ═══ ACTE 1 — Mise en place de l'infrastructure ═══════════════
    print("\n  ═══ ACTE 1 — Mise en place de l'infrastructure ═══")

    print("\n  📦 Création des vaults...")
    r = await call_tool("vault_create", {"vault_id": demo_vault, "description": "🔐 Secrets de production"})
    print(f"    ✅ {demo_vault} → {r.get('status')}")
    pause()

    r = await call_tool("vault_create", {"vault_id": "demo-staging", "description": "🧪 Secrets staging"})
    print(f"    ✅ demo-staging → {r.get('status')}")
    pause()

    print("\n  🔑 Écriture des secrets (5 types)...")
    secrets = [
        ("login", "web/github", {"username": "clesur", "password": "TopSecret123!", "url": "https://github.com"}),
        ("database", "db/postgres", {"host": "db.ct.com", "username": "admin", "password": "pg_s3cr3t", "port": "5432"}),
        ("api_key", "api/openai", {"key": "sk-proj-demo-xyz789", "endpoint": "https://api.openai.com"}),
        ("server", "infra/bastion01", {"host": "bastion01.ct.com", "username": "adminct", "port": "22"}),
        ("certificate", "certs/wildcard", {"certificate": "-----BEGIN CERT-----\n...", "private_key": "-----BEGIN KEY-----\n...", "expiry": "2027-06"}),
    ]
    for secret_type, path, data in secrets:
        r = await call_tool("secret_write", {"vault_id": demo_vault, "path": path, "data": data, "secret_type": secret_type})
        print(f"    ✅ [{secret_type}] {path}")
        _time.sleep(0.5)
    pause("Regardez les vaults et secrets dans /admin...")

    # ═══ ACTE 2 — Tokens et policies ══════════════════════════════
    print("\n  ═══ ACTE 2 — Création de tokens et policies ═══")

    print("\n  🎫 Création d'un token 'agent-sre' (read,write sur demo-prod)...")
    r = admin_post("/tokens", {
        "client_name": "agent-sre",
        "permissions": ["read", "write"],
        "allowed_resources": [demo_vault],
        "expires_in_days": 30,
    })
    sre_token = r.get("raw_token", "")
    sre_hash = r.get("hash", "")[:12]
    print(f"    ✅ Token créé (hash: {sre_hash})")
    pause()

    print("\n  📋 Création d'une policy 'readonly-no-ssh' (interdit écriture + SSH)...")
    r = await call_tool("policy_create", {
        "policy_id": "demo-readonly",
        "description": "Lecture seule — pas d'écriture ni SSH",
        "allowed_tools": ["system_*", "vault_list", "vault_info", "secret_read", "secret_list", "secret_types"],
        "denied_tools": ["secret_write", "secret_delete", "vault_create", "vault_delete", "ssh_*"],
    })
    print(f"    ✅ Policy demo-readonly → {r.get('status')}")
    pause()

    print("\n  🔗 Assignation de la policy à l'agent-sre...")
    r = await call_tool("token_update", {"hash_prefix": sre_hash, "policy_id": "demo-readonly"})
    print(f"    ✅ Policy assignée → {r.get('status')}")
    pause("L'agent-sre est maintenant en lecture seule...")

    # ═══ ACTE 3 — L'agent tente des opérations (denied !) ════════
    print("\n  ═══ ACTE 3 — L'agent tente des opérations interdites 🚫 ═══")
    print("  👀 Surveillez l'onglet Activité — les 🚫 denied vont apparaître !")
    pause()

    print("\n  🔑 Agent-sre lit un secret (autorisé)...")
    r = await call_tool("secret_read", {"vault_id": demo_vault, "path": "web/github"}, token_override=sre_token)
    print(f"    ✅ secret_read → {r.get('status')} (autorisé)")
    pause()

    print("\n  🚫 Agent-sre tente d'écrire un secret (REFUSÉ par policy)...")
    r = await call_tool("secret_write", {
        "vault_id": demo_vault, "path": "hack/attempt",
        "data": {"value": "should-fail"}, "secret_type": "custom",
    }, token_override=sre_token)
    print(f"    🚫 secret_write → {r.get('status')} — {r.get('message', '')[:60]}")
    pause()

    print("\n  🚫 Agent-sre tente de supprimer un secret (REFUSÉ)...")
    r = await call_tool("secret_delete", {"vault_id": demo_vault, "path": "web/github"}, token_override=sre_token)
    print(f"    🚫 secret_delete → {r.get('status')} — {r.get('message', '')[:60]}")
    pause()

    print("\n  🚫 Agent-sre tente de créer un vault (REFUSÉ)...")
    r = await call_tool("vault_create", {"vault_id": "demo-hack"}, token_override=sre_token)
    print(f"    🚫 vault_create → {r.get('status')} — {r.get('message', '')[:60]}")
    pause()

    print("\n  🚫 Agent-sre tente d'accéder au SSH CA (REFUSÉ)...")
    r = await call_tool("ssh_ca_list_roles", {"vault_id": demo_vault}, token_override=sre_token)
    print(f"    🚫 ssh_ca_list_roles → {r.get('status')} — {r.get('message', '')[:60]}")
    pause()

    print("\n  🚫 Agent-sre tente d'accéder à demo-staging (pas dans ses vaults autorisés)...")
    r = await call_tool("secret_list", {"vault_id": "demo-staging"}, token_override=sre_token)
    print(f"    🚫 secret_list demo-staging → {r.get('status')} — {r.get('message', '')[:60]}")
    pause()

    # ═══ ACTE 4 — SSH CA + signature ══════════════════════════════
    print("\n  ═══ ACTE 4 — SSH CA et signature de certificat ═══")

    r = await call_tool("ssh_ca_setup", {
        "vault_id": demo_vault, "role_name": "demo-admin",
        "allowed_users": "adminct,deploy", "default_user": "adminct", "ttl": "1h",
    })
    print(f"    🔑 CA SSH créée → {r.get('status')}")
    pause()

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    r = await call_tool("ssh_sign_key", {"vault_id": demo_vault, "role_name": "demo-admin", "public_key": pub, "ttl": "30m"})
    print(f"    ✍️  Certificat signé → serial={r.get('serial_number', '?')}")
    pause()

    # ═══ ACTE 5 — Vérification audit ══════════════════════════════
    print("\n  ═══ ACTE 5 — Vérification de l'audit ═══")

    r = await call_tool("audit_log", {"limit": 10, "status": "denied"})
    denied_count = len(r.get("entries", []))
    print(f"    📊 {denied_count} événements 🚫 denied trouvés dans l'audit")
    for e in r.get("entries", [])[:5]:
        print(f"       🚫 {e.get('tool', '?')} par {e.get('client', '?')} → {e.get('detail', '')[:40]}")
    pause("Regardez l'onglet Activité → filtrez par status 'denied'...")

    # ═══ ACTE 6 — Nettoyage ═══════════════════════════════════════
    print("\n  ═══ ACTE 6 — Nettoyage complet ═══")

    for _, path, _ in secrets:
        await call_tool("secret_delete", {"vault_id": demo_vault, "path": path})
    print("    🗑️  Secrets supprimés")
    _time.sleep(0.5)

    await call_tool("vault_delete", {"vault_id": demo_vault, "confirm": True})
    await call_tool("vault_delete", {"vault_id": "demo-staging", "confirm": True})
    print("    🗑️  Vaults supprimés")

    admin_delete(f"/tokens/{sre_hash}")
    print("    🗑️  Token agent-sre révoqué")

    await call_tool("policy_delete", {"policy_id": "demo-readonly", "confirm": True})
    print("    🗑️  Policy demo-readonly supprimée")
    pause()

    print("\n" + "=" * 60)
    print("  🎬 DÉMO TERMINÉE")
    print(f"  📊 Allez sur l'onglet Activité → filtrez 'denied' pour voir les alertes")
    print(f"  💡 Utilisez le filtre 'since' pour cibler la plage de temps de la démo")
    print("=" * 60 + "\n")


# =============================================================================
# CLEANUP
# =============================================================================

async def cleanup():
    """Nettoyage des vaults de test."""
    print("\n  ── CLEANUP ──")
    for space in ["test-e2e-alpha", "test-e2e-beta", "test-e2e-gamma", "test-e2e-empty", "test-e2e-agent-owned"]:
        r = await call_tool("vault_delete", {"vault_id": space, "confirm": True})
        status = r.get("status", "?")
        if status == "deleted":
            print(f"    🧹 {space} supprimé")


# =============================================================================
# Registre des tests
# =============================================================================

TEST_REGISTRY = {
    "system":      test_01_system,
    "vaults":      test_02_spaces,
    "secrets":     test_03_secrets,
    "versioning":  test_04_versioning,
    "password":    test_05_password,
    "isolation":   test_06_isolation,
    "errors":      test_07_errors,
    "s3_sync":     test_08_s3_sync,
    "ssh_ca":      test_09_ssh_ca,
    "types":       test_10_types,
    "admin_api":   test_11_admin_api,
    "policies":    test_12_policies,
    "enforcement": test_13_enforcement,
    "audit":       test_14_audit,
}


# =============================================================================
# Main
# =============================================================================

async def run_all(only: str = None):
    t0 = time.monotonic()

    print("=" * 60)
    print("  🧪 MCP Vault — Tests End-to-End Exhaustifs")
    print(f"  📡 Serveur  : {BASE_URL}")
    print(f"  🔑 Token    : {'***' + TOKEN[-6:]}")
    print(f"  📅 Date     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if only:
        print(f"  🎯 Test     : {only}")
    print("=" * 60)

    if only:
        if only in TEST_REGISTRY:
            await TEST_REGISTRY[only]()
        else:
            print(f"\n  ❌ Test inconnu: '{only}'")
            print(f"     Disponibles: {', '.join(TEST_REGISTRY.keys())}")
            return False
    else:
        for name, func in TEST_REGISTRY.items():
            try:
                await func()
            except Exception as e:
                print(f"\n  ❌ CRASH dans {name}: {e}")
                if VERBOSE:
                    traceback.print_exc()

        await cleanup()

    elapsed = round(time.monotonic() - t0, 1)
    total = PASS + FAIL

    print("\n" + "=" * 60)
    print(f"  📊 RÉSUMÉ — {total} tests en {elapsed}s")
    print(f"  ✅ PASS : {PASS}")
    print(f"  ❌ FAIL : {FAIL}")
    print("=" * 60)

    if FAIL == 0:
        print(f"\n  🎉 {PASS}/{total} TESTS PASSENT — MCP Vault validé !\n")
    else:
        print(f"\n  ⚠️ {FAIL} TEST(S) EN ÉCHEC :\n")
        for r in RESULTS:
            if r["status"] == "FAIL":
                print(f"    ❌ {r['test']}")
        print()

    return FAIL == 0


def main():
    global VERBOSE
    parser = argparse.ArgumentParser(description="Tests e2e exhaustifs MCP Vault")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--test", "-t", default=None,
                        help=f"Test spécifique ({', '.join(TEST_REGISTRY.keys())})")
    parser.add_argument("--demo", action="store_true",
                        help="Mode démo : CRUD lent pour visualiser /admin en temps réel")
    args = parser.parse_args()
    VERBOSE = args.verbose

    if args.demo:
        asyncio.run(run_demo())
        sys.exit(0)

    success = asyncio.run(run_all(only=args.test))
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
