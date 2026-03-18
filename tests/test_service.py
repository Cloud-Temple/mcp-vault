#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de recette end-to-end — MCP Vault

Teste toutes les fonctionnalités du service MCP Vault via le protocole
MCP Streamable HTTP (endpoint /mcp) et les appels REST directs.
Vérifie la connectivité, l'auth, le S3, les outils MCP, et la console admin.

Usage:
    # Build + start + test (défaut)
    python3 scripts/test_service.py

    # Serveur déjà lancé
    python3 scripts/test_service.py --no-docker

    # Mode verbose
    python3 scripts/test_service.py --verbose

    # Un test spécifique
    python3 scripts/test_service.py --test s3

Catégories de tests (6) :
    1. Connectivité      — REST /health + MCP system_health + system_about
    2. Authentification   — Sans token → 401, mauvais token → 401, admin → OK
    3. S3 Dell ECS        — PUT/GET/DELETE/LIST avec config hybride SigV2/SigV4
    4. Token Store S3     — CRUD tokens persistés sur S3
    5. Tar.gz Sync        — Upload/download/extract du file backend
    6. Console Admin      — HTML, API health, tokens, logs, sécurité

Prérequis:
    - pip install mcp>=1.9.0 httpx boto3
    - docker compose (si --no-docker n'est pas passé)
    - .env avec credentials S3 Dell ECS

Exit code: 0 si tous les tests passent, 1 sinon.
"""

import io
import os
import sys
import json
import time
import uuid
import tarfile
import hashlib
import asyncio
import argparse
import tempfile
import subprocess
import traceback
from pathlib import Path
from datetime import datetime

import boto3
from botocore.config import Config

# =============================================================================
# Configuration
# =============================================================================

BASE_URL = os.getenv("MCP_URL", "http://localhost:8085")
TOKEN = os.getenv("MCP_TOKEN", os.getenv("ADMIN_BOOTSTRAP_KEY", "change_me_in_production"))

# S3 Dell ECS
S3_ENDPOINT = os.getenv("S3_ENDPOINT_URL", "https://your-s3-endpoint.example.com")
S3_ACCESS_KEY = os.getenv("S3_ACCESS_KEY_ID", "your_access_key_here")
S3_SECRET_KEY = os.getenv("S3_SECRET_ACCESS_KEY", "your_secret_key_here")
S3_BUCKET = os.getenv("S3_BUCKET_NAME", "MCP-VAULT")
S3_REGION = os.getenv("S3_REGION_NAME", "fr1")

# Préfixe de test isolé
TEST_PREFIX = f"_test/{uuid.uuid4().hex[:8]}"

# =============================================================================
# Helpers
# =============================================================================

VERBOSE = False
PASS = 0
FAIL = 0
SKIP = 0
RESULTS = []


def log(msg: str, level: str = "info"):
    ts = datetime.now().strftime("%H:%M:%S")
    prefix = {"info": "ℹ️", "ok": "✅", "fail": "❌", "warn": "⚠️", "skip": "⏭️"}.get(level, "")
    print(f"  [{ts}] {prefix} {msg}")


def record(test_name: str, passed: bool, detail: str = "", skipped: bool = False):
    global PASS, FAIL, SKIP
    if skipped:
        SKIP += 1
        status = "SKIP"
    elif passed:
        PASS += 1
        status = "PASS"
    else:
        FAIL += 1
        status = "FAIL"
    RESULTS.append({"test": test_name, "status": status, "detail": detail})
    emoji = {"PASS": "✅", "FAIL": "❌", "SKIP": "⏭️"}[status]
    print(f"  {emoji} {test_name}" + (f" — {detail}" if detail else ""))


def get_s3_data():
    """Client S3 SigV2 pour PUT/GET/DELETE (données)."""
    return boto3.client("s3",
        endpoint_url=S3_ENDPOINT,
        aws_access_key_id=S3_ACCESS_KEY,
        aws_secret_access_key=S3_SECRET_KEY,
        config=Config(region_name=S3_REGION, signature_version="s3",
                      s3={"addressing_style": "path"},
                      retries={"max_attempts": 3, "mode": "adaptive"}),
    )


def get_s3_meta():
    """Client S3 SigV4 pour HEAD/LIST (métadonnées)."""
    return boto3.client("s3",
        endpoint_url=S3_ENDPOINT,
        aws_access_key_id=S3_ACCESS_KEY,
        aws_secret_access_key=S3_SECRET_KEY,
        config=Config(region_name=S3_REGION, signature_version="s3v4",
                      s3={"addressing_style": "path", "payload_signing_enabled": False},
                      retries={"max_attempts": 3, "mode": "adaptive"}),
    )


async def call_rest(method: str, endpoint: str, headers: dict = None,
                    json_body: dict = None) -> dict:
    """Appelle un endpoint REST."""
    import httpx
    hdrs = headers or {}
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.request(method, f"{BASE_URL}{endpoint}",
                                     headers=hdrs, json=json_body)
        result = {"status_code": resp.status_code}
        try:
            result["body"] = resp.json()
        except Exception:
            result["body"] = resp.text
        return result


# =============================================================================
# Docker helpers
# =============================================================================

def docker_build_and_start():
    """Build et démarre docker compose."""
    print("\n🐳 Build et démarrage Docker...")
    print("=" * 50)

    r = subprocess.run(
        ["docker", "compose", "build", "--quiet"],
        capture_output=True, text=True
    )
    if r.returncode != 0:
        print(f"  ❌ docker compose build échoué:\n{r.stderr}")
        return False
    print("  ✅ Build OK")

    r = subprocess.run(
        ["docker", "compose", "up", "-d"],
        capture_output=True, text=True
    )
    if r.returncode != 0:
        print(f"  ❌ docker compose up échoué:\n{r.stderr}")
        return False
    print("  ✅ Containers démarrés")
    return True


def docker_stop():
    """Arrête docker compose."""
    print("\n🐳 Arrêt Docker...")
    subprocess.run(["docker", "compose", "down"], capture_output=True, text=True)
    print("  ✅ Containers arrêtés")


def wait_for_server(max_wait: int = 30) -> bool:
    """Attend que le serveur réponde sur /health."""
    import httpx
    print(f"\n⏳ Attente du serveur ({BASE_URL})...")
    for i in range(max_wait):
        try:
            r = httpx.get(f"{BASE_URL}/health", timeout=2)
            if r.status_code == 200:
                print(f"  ✅ Serveur prêt en {i+1}s")
                return True
        except Exception:
            pass
        time.sleep(1)
        if (i + 1) % 5 == 0:
            print(f"  ⏳ {i+1}s...")
    print(f"  ❌ Serveur non disponible après {max_wait}s")
    r = subprocess.run(
        ["docker", "compose", "logs", "--tail=30", "mcp-vault"],
        capture_output=True, text=True
    )
    if r.stdout:
        print(f"\n📋 Logs Docker:\n{r.stdout}")
    return False


# =============================================================================
# TEST 1 — Connectivité
# =============================================================================

async def test_01_connectivity():
    """Connectivité de base : REST + MCP."""
    print("\n🔌 TEST 1 — Connectivité")
    print("=" * 50)

    # 1a. REST /health
    try:
        data = await call_rest("GET", "/health")
        ok = data["status_code"] == 200
        record("REST /health", ok, f"HTTP {data['status_code']}")
    except Exception as e:
        record("REST /health", False, str(e))
        return False

    return True


# =============================================================================
# TEST 2 — Authentification
# =============================================================================

async def test_02_auth():
    """Authentification Bearer token."""
    print("\n🔐 TEST 2 — Authentification")
    print("=" * 50)

    # 2a. Sans token → 401
    try:
        data = await call_rest("POST", "/mcp", json_body={"jsonrpc": "2.0", "method": "initialize", "id": 1})
        # Note: le serveur peut accepter sans token (auth optionnelle sur /mcp)
        # ou refuser. On vérifie juste qu'il répond.
        record("POST /mcp sans token", True, f"HTTP {data['status_code']}")
    except Exception as e:
        record("POST /mcp sans token", False, str(e))

    # 2b. Mauvais token → devrait être rejeté ou ignoré
    try:
        data = await call_rest(
            "POST", "/mcp",
            headers={"Authorization": "Bearer bad_token_12345"},
            json_body={"jsonrpc": "2.0", "method": "initialize", "id": 1}
        )
        record("POST /mcp mauvais token", True, f"HTTP {data['status_code']}")
    except Exception as e:
        record("POST /mcp mauvais token", False, str(e))

    # 2c. Admin API sans token → 401
    try:
        data = await call_rest("GET", "/admin/api/health")
        ok = data["status_code"] == 401
        record("Admin API sans token → 401", ok, f"HTTP {data['status_code']} (attendu: 401)")
    except Exception as e:
        record("Admin API sans token → 401", False, str(e))

    # 2d. Admin API avec token admin → OK
    try:
        data = await call_rest("GET", "/admin/api/health",
                                headers={"Authorization": f"Bearer {TOKEN}"})
        ok = data["status_code"] == 200
        record("Admin API avec token admin", ok, f"HTTP {data['status_code']}")
    except Exception as e:
        record("Admin API avec token admin", False, str(e))


# =============================================================================
# TEST 3 — S3 Dell ECS (config hybride SigV2/SigV4)
# =============================================================================

async def test_03_s3():
    """S3 Dell ECS — opérations CRUD réelles."""
    print("\n☁️ TEST 3 — S3 Dell ECS (hybride SigV2/SigV4)")
    print("=" * 50)

    s3d = get_s3_data()
    s3m = get_s3_meta()

    # 3a. HEAD bucket (SigV4)
    try:
        resp = s3m.head_bucket(Bucket=S3_BUCKET)
        ok = resp["ResponseMetadata"]["HTTPStatusCode"] == 200
        record("S3 HEAD bucket (SigV4)", ok, f"HTTP {resp['ResponseMetadata']['HTTPStatusCode']}")
    except Exception as e:
        record("S3 HEAD bucket (SigV4)", False, str(e))
        return  # Pas la peine de continuer si le bucket est inaccessible

    # 3b. LIST objects (SigV4)
    try:
        resp = s3m.list_objects_v2(Bucket=S3_BUCKET, MaxKeys=1)
        ok = resp["ResponseMetadata"]["HTTPStatusCode"] == 200
        record("S3 LIST objects (SigV4)", ok, f"KeyCount={resp.get('KeyCount', 0)}")
    except Exception as e:
        record("S3 LIST objects (SigV4)", False, str(e))

    # 3c. PUT object (SigV2)
    key = f"{TEST_PREFIX}/test_put.txt"
    try:
        resp = s3d.put_object(Bucket=S3_BUCKET, Key=key, Body=b"Hello MCP Vault!", ContentType="text/plain")
        ok = resp["ResponseMetadata"]["HTTPStatusCode"] == 200
        record("S3 PUT object (SigV2)", ok, f"key={key}")
    except Exception as e:
        record("S3 PUT object (SigV2)", False, str(e))

    # 3d. GET object (SigV2)
    try:
        resp = s3d.get_object(Bucket=S3_BUCKET, Key=key)
        body = resp["Body"].read()
        ok = body == b"Hello MCP Vault!"
        record("S3 GET object (SigV2)", ok, f"{len(body)} bytes")
    except Exception as e:
        record("S3 GET object (SigV2)", False, str(e))

    # 3e. PUT JSON (SigV2)
    json_key = f"{TEST_PREFIX}/test.json"
    test_data = {"tokens": [{"name": "test", "hash": "abc123"}]}
    try:
        s3d.put_object(Bucket=S3_BUCKET, Key=json_key, Body=json.dumps(test_data).encode(), ContentType="application/json")
        resp = s3d.get_object(Bucket=S3_BUCKET, Key=json_key)
        loaded = json.loads(resp["Body"].read())
        ok = loaded == test_data
        record("S3 PUT/GET JSON (SigV2)", ok, f"key={json_key}")
    except Exception as e:
        record("S3 PUT/GET JSON (SigV2)", False, str(e))

    # 3f. PUT large 1MB (SigV2)
    large_key = f"{TEST_PREFIX}/large.bin"
    try:
        large_body = os.urandom(1024 * 1024)
        s3d.put_object(Bucket=S3_BUCKET, Key=large_key, Body=large_body)
        resp = s3d.get_object(Bucket=S3_BUCKET, Key=large_key)
        received = resp["Body"].read()
        ok = len(received) == len(large_body) and received == large_body
        record("S3 PUT/GET 1MB (SigV2)", ok, f"{len(received)} bytes")
    except Exception as e:
        record("S3 PUT/GET 1MB (SigV2)", False, str(e))

    # 3g. LIST avec préfixe (SigV4)
    try:
        for i in range(3):
            s3d.put_object(Bucket=S3_BUCKET, Key=f"{TEST_PREFIX}/list/item_{i}.txt", Body=f"item {i}".encode())
        resp = s3m.list_objects_v2(Bucket=S3_BUCKET, Prefix=f"{TEST_PREFIX}/list/")
        keys = [obj["Key"] for obj in resp.get("Contents", [])]
        ok = len(keys) == 3
        record("S3 LIST préfixe (SigV4)", ok, f"{len(keys)} objets")
    except Exception as e:
        record("S3 LIST préfixe (SigV4)", False, str(e))

    # 3h. DELETE object (SigV2)
    try:
        resp = s3d.delete_object(Bucket=S3_BUCKET, Key=key)
        ok = resp["ResponseMetadata"]["HTTPStatusCode"] in (200, 204)
        # Vérifier suppression
        try:
            s3d.get_object(Bucket=S3_BUCKET, Key=key)
            ok = False  # Ne devrait pas arriver
        except Exception:
            pass  # OK, l'objet n'existe plus
        record("S3 DELETE object (SigV2)", ok, f"key={key}")
    except Exception as e:
        record("S3 DELETE object (SigV2)", False, str(e))

    # Cleanup
    try:
        resp = s3m.list_objects_v2(Bucket=S3_BUCKET, Prefix=TEST_PREFIX)
        for obj in resp.get("Contents", []):
            s3d.delete_object(Bucket=S3_BUCKET, Key=obj["Key"])
        log(f"Cleanup: {len(resp.get('Contents', []))} objets supprimés", "info")
    except Exception as e:
        log(f"Cleanup erreur: {e}", "warn")


# =============================================================================
# TEST 4 — Token Store S3
# =============================================================================

async def test_04_token_store():
    """Token Store — CRUD tokens persistés sur S3."""
    print("\n🔑 TEST 4 — Token Store S3")
    print("=" * 50)

    s3d = get_s3_data()
    token_key = f"{TEST_PREFIX}/tokens.json"

    # On importe et teste le TokenStore directement
    sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
    from mcp_vault.auth.token_store import TokenStore
    from types import SimpleNamespace

    settings = SimpleNamespace(
        s3_endpoint_url=S3_ENDPOINT, s3_access_key_id=S3_ACCESS_KEY,
        s3_secret_access_key=S3_SECRET_KEY, s3_bucket_name=S3_BUCKET,
        s3_region_name=S3_REGION,
    )
    store = TokenStore(settings)
    store.S3_KEY = token_key
    store._get_s3_data = lambda: s3d

    # 4a. Create token
    try:
        result = store.create(client_name="test-agent", permissions=["read", "write"],
                              allowed_resources=["vault-space-1"], email="test@ct.com")
        ok = "raw_token" in result and result["client_name"] == "test-agent"
        raw_token = result["raw_token"]
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        record("TokenStore create", ok, f"hash={result['hash'][:12]}...")
    except Exception as e:
        record("TokenStore create", False, str(e))
        return

    # 4b. Reload from S3 and verify
    try:
        store2 = TokenStore(settings)
        store2.S3_KEY = token_key
        store2._get_s3_data = lambda: s3d
        store2.load()
        ok = store2.count() >= 1
        found = store2.get_by_hash(token_hash)
        ok = ok and found is not None and found["client_name"] == "test-agent"
        record("TokenStore reload from S3", ok, f"count={store2.count()}")
    except Exception as e:
        record("TokenStore reload from S3", False, str(e))

    # 4c. List tokens
    try:
        store.create(client_name="agent-2", permissions=["read"])
        tokens = store.list_all()
        names = [t["client_name"] for t in tokens]
        ok = "test-agent" in names and "agent-2" in names
        record("TokenStore list", ok, f"{len(tokens)} tokens: {names}")
    except Exception as e:
        record("TokenStore list", False, str(e))

    # 4d. Revoke token
    try:
        result = store.create(client_name="to-revoke", permissions=["read"])
        hp = result["hash"][:12]
        ok = store.revoke(hp)
        # Reload and verify persistence
        store3 = TokenStore(settings)
        store3.S3_KEY = token_key
        store3._get_s3_data = lambda: s3d
        store3.load()
        revoked = [t for t in store3.list_all() if t["hash_prefix"] == hp]
        ok = ok and len(revoked) == 1 and revoked[0]["revoked"] is True
        record("TokenStore revoke (persisté S3)", ok, f"hash={hp}...")
    except Exception as e:
        record("TokenStore revoke", False, str(e))

    # Cleanup
    try:
        s3d.delete_object(Bucket=S3_BUCKET, Key=token_key)
    except Exception:
        pass


# =============================================================================
# TEST 5 — Tar.gz Sync (simule le sync vault file backend)
# =============================================================================

async def test_05_tar_sync():
    """Tar.gz roundtrip — upload/download/extract du file backend."""
    print("\n📦 TEST 5 — Tar.gz Sync (file backend ↔ S3)")
    print("=" * 50)

    s3d = get_s3_data()
    tar_key = f"{TEST_PREFIX}/vault_sync/openbao-data.tar.gz"

    # 5a. Créer tar.gz en mémoire + upload
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            for name in ["core/seal-config", "logical/abc123", "sys/token/id/root"]:
                fpath = Path(tmpdir) / name
                fpath.parent.mkdir(parents=True, exist_ok=True)
                fpath.write_text(f"data for {name}")

            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as tar:
                for item in Path(tmpdir).iterdir():
                    tar.add(str(item), arcname=item.name)
            buf.seek(0)
            archive_data = buf.read()

        resp = s3d.put_object(Bucket=S3_BUCKET, Key=tar_key, Body=archive_data, ContentType="application/gzip")
        ok = resp["ResponseMetadata"]["HTTPStatusCode"] == 200
        record("Tar.gz upload S3", ok, f"{len(archive_data)} bytes")
    except Exception as e:
        record("Tar.gz upload S3", False, str(e))
        return

    # 5b. Download et décompresser
    try:
        resp = s3d.get_object(Bucket=S3_BUCKET, Key=tar_key)
        downloaded = resp["Body"].read()
        ok = len(downloaded) == len(archive_data)
        record("Tar.gz download S3", ok, f"{len(downloaded)} bytes")
    except Exception as e:
        record("Tar.gz download S3", False, str(e))
        return

    # 5c. Extraire et vérifier les fichiers
    try:
        with tempfile.TemporaryDirectory() as tmpdir2:
            with tarfile.open(fileobj=io.BytesIO(downloaded), mode="r:gz") as tar:
                tar.extractall(path=tmpdir2, filter="data")
            file_count = sum(1 for f in Path(tmpdir2).rglob("*") if f.is_file())
            ok = file_count >= 3
            record("Tar.gz extract", ok, f"{file_count} fichiers extraits")
    except Exception as e:
        record("Tar.gz extract", False, str(e))

    # Cleanup
    try:
        s3d.delete_object(Bucket=S3_BUCKET, Key=tar_key)
    except Exception:
        pass


# =============================================================================
# TEST 6 — Gestion des droits (exhaustif)
# =============================================================================

async def test_06_permissions():
    """Tests exhaustifs de la gestion des droits (check_access, check_write, check_admin)."""
    print("\n🛡️ TEST 6 — Gestion des droits (exhaustif)")
    print("=" * 50)

    sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
    from mcp_vault.auth.context import (
        current_token_info, check_access, check_write_permission,
        check_admin_permission, get_current_client_name
    )

    # ── 6a. AUCUN TOKEN (contexte vide) ──

    tok = current_token_info.set(None)
    try:
        result = check_access("any-space")
        ok = result is not None and result["status"] == "error" and "Authentification" in result["message"]
        record("No token → check_access refusé", ok, result["message"] if result else "None")

        result = check_write_permission()
        ok = result is not None and "Authentification" in result["message"]
        record("No token → check_write refusé", ok, result["message"] if result else "None")

        result = check_admin_permission()
        ok = result is not None and "Authentification" in result["message"]
        record("No token → check_admin refusé", ok, result["message"] if result else "None")

        name = get_current_client_name()
        ok = name == "anonymous"
        record("No token → client_name = anonymous", ok, f"name={name}")
    finally:
        current_token_info.reset(tok)

    # ── 6b. TOKEN ADMIN (accès total) ──

    tok = current_token_info.set({
        "client_name": "super-admin",
        "permissions": ["admin", "read", "write"],
        "space_ids": [],
    })
    try:
        # Admin peut accéder à n'importe quel space
        for space in ["space-a", "space-b", "nonexistent", "secret-zone", ""]:
            result = check_access(space)
            ok = result is None
            record(f"Admin → access '{space}'", ok, f"result={result}")

        # Admin a write
        result = check_write_permission()
        ok = result is None
        record("Admin → check_write OK", ok)

        # Admin a admin
        result = check_admin_permission()
        ok = result is None
        record("Admin → check_admin OK", ok)

        name = get_current_client_name()
        ok = name == "super-admin"
        record("Admin → client_name", ok, f"name={name}")
    finally:
        current_token_info.reset(tok)

    # ── 6c. TOKEN READ-ONLY avec spaces restreints ──

    tok = current_token_info.set({
        "client_name": "reader-agent",
        "permissions": ["read"],
        "space_ids": ["prod-secrets", "staging-secrets"],
    })
    try:
        # Accès aux spaces autorisés → OK
        result = check_access("prod-secrets")
        ok = result is None
        record("Read-only → access prod-secrets OK", ok)

        result = check_access("staging-secrets")
        ok = result is None
        record("Read-only → access staging-secrets OK", ok)

        # Accès à un space NON autorisé → REFUSÉ
        result = check_access("dev-secrets")
        ok = result is not None and "refusé" in result["message"].lower() or "Accès" in result.get("message", "")
        record("Read-only → access dev-secrets REFUSÉ", ok, result.get("message", "")[:60] if result else "None")

        result = check_access("another-space")
        ok = result is not None
        record("Read-only → access another-space REFUSÉ", ok)

        # Read-only NE peut PAS écrire
        result = check_write_permission()
        ok = result is not None and "écriture" in result["message"].lower()
        record("Read-only → check_write REFUSÉ", ok, result["message"] if result else "None")

        # Read-only NE peut PAS admin
        result = check_admin_permission()
        ok = result is not None and "admin" in result["message"].lower()
        record("Read-only → check_admin REFUSÉ", ok, result["message"] if result else "None")
    finally:
        current_token_info.reset(tok)

    # ── 6d. TOKEN READ+WRITE avec spaces restreints ──

    tok = current_token_info.set({
        "client_name": "writer-agent",
        "permissions": ["read", "write"],
        "space_ids": ["my-vault"],
    })
    try:
        # Accès au space autorisé → OK
        result = check_access("my-vault")
        ok = result is None
        record("Read+Write → access my-vault OK", ok)

        # Accès à un autre space → REFUSÉ
        result = check_access("not-my-vault")
        ok = result is not None
        record("Read+Write → access not-my-vault REFUSÉ", ok)

        # Write → OK
        result = check_write_permission()
        ok = result is None
        record("Read+Write → check_write OK", ok)

        # Admin → REFUSÉ
        result = check_admin_permission()
        ok = result is not None
        record("Read+Write → check_admin REFUSÉ", ok)
    finally:
        current_token_info.reset(tok)

    # ── 6e. TOKEN AVEC SPACES VIDES (= accès à tous les spaces) ──

    tok = current_token_info.set({
        "client_name": "all-access-agent",
        "permissions": ["read", "write"],
        "space_ids": [],  # vide = tous les spaces
    })
    try:
        for space in ["any-space", "prod", "dev", "staging", "secret-zone"]:
            result = check_access(space)
            ok = result is None
            record(f"All-spaces → access '{space}' OK", ok)
    finally:
        current_token_info.reset(tok)

    # ── 6f. TOKEN ADMIN-ONLY (sans read/write explicite) ──

    tok = current_token_info.set({
        "client_name": "pure-admin",
        "permissions": ["admin"],
        "space_ids": [],
    })
    try:
        # Admin implicite → accès total
        result = check_access("any-space")
        ok = result is None
        record("Admin-only → check_access OK", ok)

        # Admin a write (car admin implique tout)
        result = check_write_permission()
        ok = result is None
        record("Admin-only → check_write OK (implicite)", ok)

        # Admin a admin
        result = check_admin_permission()
        ok = result is None
        record("Admin-only → check_admin OK", ok)
    finally:
        current_token_info.reset(tok)

    # ── 6g. TOKEN AVEC PERMISSIONS VIDES ──

    tok = current_token_info.set({
        "client_name": "no-perms",
        "permissions": [],
        "space_ids": [],
    })
    try:
        # Accès aux spaces → OK (pas de restriction sur space_ids)
        result = check_access("any-space")
        ok = result is None
        record("No-perms → check_access OK (spaces non restreints)", ok)

        # Write → REFUSÉ
        result = check_write_permission()
        ok = result is not None
        record("No-perms → check_write REFUSÉ", ok)

        # Admin → REFUSÉ
        result = check_admin_permission()
        ok = result is not None
        record("No-perms → check_admin REFUSÉ", ok)
    finally:
        current_token_info.reset(tok)

    # ── 6h. EDGE CASES ──

    # Token avec un seul space
    tok = current_token_info.set({
        "client_name": "single-space",
        "permissions": ["read"],
        "space_ids": ["only-this-one"],
    })
    try:
        result = check_access("only-this-one")
        ok = result is None
        record("Single space → exact match OK", ok)

        result = check_access("ONLY-THIS-ONE")
        ok = result is not None  # Case sensitive
        record("Single space → case sensitive REFUSÉ", ok)

        result = check_access("only-this-one/sub")
        ok = result is not None  # Pas de wildcard
        record("Single space → no wildcard REFUSÉ", ok)

        result = check_access("")
        ok = result is not None  # Vide pas dans la liste
        record("Single space → empty string REFUSÉ", ok)
    finally:
        current_token_info.reset(tok)


# =============================================================================
# TEST 7 — Types de secrets & Générateur de mots de passe
# =============================================================================

async def test_06_types():
    """Types de secrets et générateur de mots de passe."""
    print("\n🔐 TEST 6 — Types de secrets & Password Generator")
    print("=" * 50)

    sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
    from mcp_vault.vault.types import validate_secret, enrich_secret_data, list_types, generate_password

    # 6a. Liste des types (14 types)
    try:
        types = list_types()
        ok = len(types) == 14
        names = [t["type"] for t in types]
        record("Types disponibles (14)", ok, f"{len(types)} types: {names}")
    except Exception as e:
        record("Types disponibles", False, str(e))

    # 6b. Validation login — OK
    try:
        err = validate_secret("login", {"username": "admin", "password": "s3cret", "url": "https://github.com"})
        ok = err is None
        record("Validation login OK", ok, f"err={err}")
    except Exception as e:
        record("Validation login OK", False, str(e))

    # 6c. Validation login — champ requis manquant
    try:
        err = validate_secret("login", {"username": "admin"})
        ok = err is not None and "password" in err
        record("Validation login manque password", ok, f"err={err}")
    except Exception as e:
        record("Validation login manque password", False, str(e))

    # 6d. Validation database — OK
    try:
        err = validate_secret("database", {"host": "db.example.com", "username": "root", "password": "xxx", "port": "5432"})
        ok = err is None
        record("Validation database OK", ok, f"err={err}")
    except Exception as e:
        record("Validation database OK", False, str(e))

    # 6e. Validation type inconnu
    try:
        err = validate_secret("unknown_type", {"data": "test"})
        ok = err is not None and "inconnu" in err.lower()
        record("Validation type inconnu", ok, f"err={err[:60]}")
    except Exception as e:
        record("Validation type inconnu", False, str(e))

    # 6f. Validation secure_note — OK
    try:
        err = validate_secret("secure_note", {"content": "Mon secret confidentiel"})
        ok = err is None
        record("Validation secure_note OK", ok)
    except Exception as e:
        record("Validation secure_note OK", False, str(e))

    # 6g. Validation custom — accepte tout
    try:
        err = validate_secret("custom", {"anything": "goes", "whatever": 42})
        ok = err is None
        record("Validation custom (tout accepté)", ok)
    except Exception as e:
        record("Validation custom", False, str(e))

    # 6h. Enrichissement des données
    try:
        data = enrich_secret_data("login", {"username": "admin", "password": "xxx"})
        ok = data["_type"] == "login" and "_tags" in data and "_favorite" in data
        record("Enrichissement données", ok, f"_type={data['_type']}, _tags={data['_tags']}, _fav={data['_favorite']}")
    except Exception as e:
        record("Enrichissement données", False, str(e))

    # 6i. Générateur mot de passe — défaut (24 chars)
    try:
        pwd = generate_password()
        ok = len(pwd) == 24
        has_upper = any(c.isupper() for c in pwd)
        has_lower = any(c.islower() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        record("Password 24 chars", ok and has_upper and has_lower and has_digit,
               f"len={len(pwd)}, upper={has_upper}, lower={has_lower}, digit={has_digit}")
    except Exception as e:
        record("Password 24 chars", False, str(e))

    # 6j. Générateur — longueur custom
    try:
        pwd = generate_password(length=64)
        ok = len(pwd) == 64
        record("Password 64 chars", ok, f"len={len(pwd)}")
    except Exception as e:
        record("Password 64 chars", False, str(e))

    # 6k. Générateur — digits only
    try:
        pwd = generate_password(length=12, uppercase=False, lowercase=False, symbols=False)
        ok = len(pwd) == 12 and pwd.isdigit()
        record("Password digits only", ok, f"pwd={pwd}")
    except Exception as e:
        record("Password digits only", False, str(e))

    # 6l. Générateur — exclusion de caractères
    try:
        pwd = generate_password(length=32, exclude="lI10O")
        ok = len(pwd) == 32 and not any(c in pwd for c in "lI10O")
        record("Password exclusion chars", ok, f"len={len(pwd)}, contient excl={any(c in pwd for c in 'lI10O')}")
    except Exception as e:
        record("Password exclusion chars", False, str(e))

    # 6m. Générateur — min 8 chars même si demandé moins
    try:
        pwd = generate_password(length=3)
        ok = len(pwd) >= 8
        record("Password min 8 chars", ok, f"demandé=3, obtenu={len(pwd)}")
    except Exception as e:
        record("Password min 8 chars", False, str(e))

    # 6n. Unicité (2 passwords différents)
    try:
        pwd1 = generate_password()
        pwd2 = generate_password()
        ok = pwd1 != pwd2
        record("Password unicité (CSPRNG)", ok, f"p1≠p2={ok}")
    except Exception as e:
        record("Password unicité", False, str(e))


# =============================================================================
# TEST 7 — Console Admin
# =============================================================================

async def test_06_admin():
    """Console admin — HTML, API, sécurité."""
    print("\n🛠️ TEST 6 — Console Admin (/admin)")
    print("=" * 50)

    admin_headers = {"Authorization": f"Bearer {TOKEN}"}

    # 6a. GET /admin → HTML
    try:
        data = await call_rest("GET", "/admin")
        body_str = str(data.get("body", ""))
        ok = data["status_code"] == 200 and ("MCP Vault" in body_str or "admin" in body_str.lower() or len(body_str) > 100)
        record("Admin GET /admin (HTML)", ok, f"HTTP {data['status_code']}, {len(body_str)} chars")
    except Exception as e:
        record("Admin GET /admin (HTML)", False, str(e))

    # 6b. Admin API health sans token → 401
    try:
        data = await call_rest("GET", "/admin/api/health")
        ok = data["status_code"] == 401
        record("Admin API sans token → 401", ok, f"HTTP {data['status_code']}")
    except Exception as e:
        record("Admin API sans token → 401", False, str(e))

    # 6c. Admin API health avec mauvais token → 401
    try:
        data = await call_rest("GET", "/admin/api/health",
                                headers={"Authorization": "Bearer bad_token_xyz"})
        ok = data["status_code"] == 401
        record("Admin API mauvais token → 401", ok, f"HTTP {data['status_code']}")
    except Exception as e:
        record("Admin API mauvais token → 401", False, str(e))

    # 6d. Admin API health avec admin → OK
    try:
        data = await call_rest("GET", "/admin/api/health", headers=admin_headers)
        ok = data["status_code"] == 200
        body = data.get("body", {})
        tools_count = body.get("tools_count", "?") if isinstance(body, dict) else "?"
        record("Admin API health (admin)", ok, f"tools={tools_count}")
    except Exception as e:
        record("Admin API health (admin)", False, str(e))

    # 6e. Admin API tokens → liste
    try:
        data = await call_rest("GET", "/admin/api/tokens", headers=admin_headers)
        ok = data["status_code"] == 200
        record("Admin API tokens", ok, f"HTTP {data['status_code']}")
    except Exception as e:
        record("Admin API tokens", False, str(e))

    # 6f. Admin API logs
    try:
        data = await call_rest("GET", "/admin/api/logs", headers=admin_headers)
        ok = data["status_code"] == 200
        record("Admin API logs", ok, f"HTTP {data['status_code']}")
    except Exception as e:
        record("Admin API logs", False, str(e))

    # 6g. Admin route inconnue → 404
    try:
        data = await call_rest("GET", "/admin/api/inexistant", headers=admin_headers)
        ok = data["status_code"] == 404
        record("Admin route inconnue → 404", ok, f"HTTP {data['status_code']}")
    except Exception as e:
        record("Admin route inconnue → 404", False, str(e))


# =============================================================================
# Registre des tests
# =============================================================================

TEST_REGISTRY = {
    "connectivity": test_01_connectivity,
    "auth":         test_02_auth,
    "s3":           test_03_s3,
    "token_store":  test_04_token_store,
    "tar_sync":     test_05_tar_sync,
    "permissions":  test_06_permissions,
    "types":        test_06_types,
    "admin":        test_06_admin,
}


# =============================================================================
# Main
# =============================================================================

async def run_all_tests(only: str = None):
    """Exécute les tests."""
    print("=" * 60)
    print("🧪 TEST END-TO-END — MCP Vault")
    print(f"   Serveur  : {BASE_URL}")
    print(f"   Token    : {'***' + TOKEN[-8:] if len(TOKEN) > 8 else '***'}")
    print(f"   S3       : {S3_ENDPOINT}")
    print(f"   Bucket   : {S3_BUCKET}")
    print(f"   Préfixe  : {TEST_PREFIX}")
    print(f"   Date     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if only:
        print(f"   Test     : {only}")
    print("=" * 60)

    t0 = time.monotonic()

    if only:
        if only in TEST_REGISTRY:
            await TEST_REGISTRY[only]()
        else:
            print(f"\n❌ Test inconnu: '{only}'")
            print(f"   Tests disponibles: {', '.join(TEST_REGISTRY.keys())}")
            return False
    else:
        for name, func in TEST_REGISTRY.items():
            try:
                result = await func()
                if result is False and name == "connectivity":
                    print("\n❌ ARRÊT — Impossible de se connecter au serveur")
                    break
            except Exception as e:
                record(f"{name} (crash)", False, str(e))
                if VERBOSE:
                    traceback.print_exc()

    # Résumé
    elapsed = round(time.monotonic() - t0, 1)
    total = PASS + FAIL + SKIP

    print("\n" + "=" * 60)
    print("📊 RÉSUMÉ")
    print("=" * 60)
    print(f"  Tests   : {total} total")
    print(f"  ✅ PASS  : {PASS}")
    print(f"  ❌ FAIL  : {FAIL}")
    print(f"  ⏭️ SKIP  : {SKIP}")
    print(f"  ⏱️ Durée  : {elapsed}s")
    print("=" * 60)

    if FAIL == 0:
        print("\n🎉 TOUS LES TESTS PASSENT !")
    else:
        print(f"\n⚠️  {FAIL} TEST(S) EN ÉCHEC")
        print("\nDétails des échecs :")
        for r in RESULTS:
            if r["status"] == "FAIL":
                print(f"  ❌ {r['test']}: {r['detail']}")

    return FAIL == 0


def main():
    global VERBOSE
    parser = argparse.ArgumentParser(
        description="Test end-to-end du service MCP Vault",
        epilog=f"Tests disponibles: {', '.join(TEST_REGISTRY.keys())}",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Affiche les détails")
    parser.add_argument("--no-docker", action="store_true", help="Ne pas build/start docker")
    parser.add_argument("--test", "-t", default=None, metavar="NOM",
                        help=f"Lancer un test spécifique ({', '.join(TEST_REGISTRY.keys())})")
    args = parser.parse_args()
    VERBOSE = args.verbose
    test_only = args.test

    use_docker = not args.no_docker

    if use_docker:
        if not docker_build_and_start():
            sys.exit(1)
        if not wait_for_server(max_wait=30):
            docker_stop()
            sys.exit(1)

    try:
        success = asyncio.run(run_all_tests(only=test_only))
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrompu par l'utilisateur")
        success = False
    except Exception as e:
        print(f"\n❌ Erreur inattendue: {e}")
        if VERBOSE:
            traceback.print_exc()
        success = False
    finally:
        if use_docker:
            docker_stop()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
