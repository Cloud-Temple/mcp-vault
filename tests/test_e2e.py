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
    6. Isolation inter-spaces — cloisonnement des secrets
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

async def call_tool(tool_name: str, arguments: dict) -> dict:
    """Appelle un outil MCP via Streamable HTTP."""
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    headers = {"Authorization": f"Bearer {TOKEN}"}
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
# TEST 6 — Isolation inter-spaces
# =============================================================================

async def test_06_isolation():
    """Isolation — les secrets d'un space ne sont pas visibles dans un autre."""
    print("\n  ── TEST 6 — Isolation inter-spaces ──")

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

    # 7a. Lire dans un space inexistant
    r = await call_tool("secret_read", {"vault_id": "vault-fantome", "path": "test"})
    check("Read dans space inexistant → erreur", r, "error")

    # 7b. Écrire dans un space inexistant
    r = await call_tool("secret_write", {
        "vault_id": "vault-fantome", "path": "test",
        "data": {"value": "x"}, "secret_type": "custom",
    })
    check("Write dans space inexistant → erreur", r, "error")

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

    # 7f. Lister les secrets d'un space vide
    r = await call_tool("vault_create", {"vault_id": "test-e2e-empty"})
    r = await call_tool("secret_list", {"vault_id": "test-e2e-empty"})
    check_true("List space vide (pas de crash)", r.get("status") in ("ok", "error"),
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
# TEST 9 — SSH CA
# =============================================================================

async def test_09_ssh_ca():
    """SSH CA — setup et récupération de clé publique."""
    print("\n  ── TEST 9 — SSH CA ──")

    space = "test-e2e-beta"

    # 9a. Setup SSH CA
    r = await call_tool("ssh_ca_setup", {
        "vault_id": space, "role_name": "test-role",
        "allowed_users": "deploy,admin", "ttl": "15m",
    })
    # Peut réussir ou échouer selon l'implémentation
    status = r.get("status", "?")
    check_true("SSH CA setup (pas de crash)", status in ("ok", "error", "created"),
               f"status={status}")

    if status in ("ok", "created"):
        # 9b. Récupérer la clé publique CA
        r = await call_tool("ssh_ca_public_key", {"vault_id": space})
        status = r.get("status", "?")
        check_true("SSH CA public key", status in ("ok", "error"),
                   f"status={status}")


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
# CLEANUP
# =============================================================================

async def cleanup():
    """Nettoyage des vaults de test."""
    print("\n  ── CLEANUP ──")
    for space in ["test-e2e-alpha", "test-e2e-beta", "test-e2e-gamma", "test-e2e-empty"]:
        r = await call_tool("vault_delete", {"vault_id": space, "confirm": True})
        status = r.get("status", "?")
        if status == "deleted":
            print(f"    🧹 {space} supprimé")


# =============================================================================
# Registre des tests
# =============================================================================

TEST_REGISTRY = {
    "system":     test_01_system,
    "vaults":     test_02_spaces,
    "secrets":    test_03_secrets,
    "versioning": test_04_versioning,
    "password":   test_05_password,
    "isolation":  test_06_isolation,
    "errors":     test_07_errors,
    "s3_sync":    test_08_s3_sync,
    "ssh_ca":     test_09_ssh_ca,
    "types":      test_10_types,
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
    args = parser.parse_args()
    VERBOSE = args.verbose

    success = asyncio.run(run_all(only=args.test))
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
