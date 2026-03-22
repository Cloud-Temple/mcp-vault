#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests d'intégration MCP Vault — RÉELS, PAS DE MOCKING.

Tous les tests se connectent au vrai S3 Dell ECS Cloud Temple.
Les tests OpenBao nécessitent le binaire `bao` installé.

Usage :
    # Tous les tests S3 (nécessite .env configuré)
    python -m pytest tests/test_integration.py -v

    # Seulement les tests S3
    python -m pytest tests/test_integration.py -v -k "s3"

    # Seulement les tests auth
    python -m pytest tests/test_integration.py -v -k "auth"

Nettoyage :
    Les tests créent des objets dans le préfixe _test/ sur S3
    et les nettoient automatiquement (cleanup fixtures).
"""

import io
import json
import os
import sys
import hashlib
import tarfile
import tempfile
import time
import uuid

import boto3
import pytest
from botocore.config import Config

# =============================================================================
# Configuration — lit les credentials depuis .env ou variables d'environnement
# =============================================================================

# Charger .env si présent
from pathlib import Path
env_file = Path(__file__).parent.parent / ".env"
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())

S3_ENDPOINT = os.environ.get("S3_ENDPOINT_URL", "")
S3_ACCESS_KEY = os.environ.get("S3_ACCESS_KEY_ID", "")
S3_SECRET_KEY = os.environ.get("S3_SECRET_ACCESS_KEY", "")
S3_BUCKET = os.environ.get("S3_BUCKET_NAME", "")
S3_REGION = os.environ.get("S3_REGION_NAME", "fr1")

# Préfixe de test pour isoler les objets
TEST_PREFIX = f"_test/{uuid.uuid4().hex[:8]}"

# Skip si S3 non configuré
s3_configured = all([S3_ENDPOINT, S3_ACCESS_KEY, S3_SECRET_KEY, S3_BUCKET])
skip_no_s3 = pytest.mark.skipif(not s3_configured, reason="S3 non configuré (variables d'env manquantes)")


# =============================================================================
# Fixtures S3 — Clients réels Dell ECS (hybride SigV2/SigV4)
# =============================================================================

@pytest.fixture(scope="module")
def s3_data():
    """Client S3 SigV2 pour opérations de données (PUT/GET/DELETE)."""
    config_v2 = Config(
        region_name=S3_REGION,
        signature_version="s3",  # SigV2 legacy — requis par Dell ECS
        s3={"addressing_style": "path"},
        retries={"max_attempts": 3, "mode": "adaptive"},
    )
    return boto3.client(
        "s3",
        endpoint_url=S3_ENDPOINT,
        aws_access_key_id=S3_ACCESS_KEY,
        aws_secret_access_key=S3_SECRET_KEY,
        config=config_v2,
    )


@pytest.fixture(scope="module")
def s3_meta():
    """Client S3 SigV4 pour opérations métadonnées (HEAD/LIST)."""
    config_v4 = Config(
        region_name=S3_REGION,
        signature_version="s3v4",
        s3={"addressing_style": "path", "payload_signing_enabled": False},
        retries={"max_attempts": 3, "mode": "adaptive"},
    )
    return boto3.client(
        "s3",
        endpoint_url=S3_ENDPOINT,
        aws_access_key_id=S3_ACCESS_KEY,
        aws_secret_access_key=S3_SECRET_KEY,
        config=config_v4,
    )


@pytest.fixture(scope="module", autouse=True)
def cleanup_s3(s3_data, s3_meta):
    """Nettoie les objets de test après les tests."""
    yield
    # Cleanup : lister et supprimer tous les objets dans _test/
    try:
        resp = s3_meta.list_objects_v2(Bucket=S3_BUCKET, Prefix=TEST_PREFIX)
        for obj in resp.get("Contents", []):
            s3_data.delete_object(Bucket=S3_BUCKET, Key=obj["Key"])
            print(f"  🧹 Nettoyé: {obj['Key']}")
    except Exception as e:
        print(f"  ⚠️ Cleanup erreur: {e}")


# =============================================================================
# TEST 1 : S3 Connectivité — HEAD Bucket (SigV4)
# =============================================================================

@skip_no_s3
class TestS3Connectivity:
    """Tests de connectivité S3 réelle vers Dell ECS Cloud Temple."""

    def test_head_bucket_sigv4(self, s3_meta):
        """HEAD bucket avec SigV4 — vérifie que le bucket existe et est accessible."""
        resp = s3_meta.head_bucket(Bucket=S3_BUCKET)
        assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
        print(f"✅ HEAD bucket OK: {S3_BUCKET}")

    def test_list_objects_sigv4(self, s3_meta):
        """LIST objects avec SigV4 — vérifie qu'on peut lister."""
        resp = s3_meta.list_objects_v2(Bucket=S3_BUCKET, MaxKeys=1)
        assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
        print(f"✅ LIST objects OK (KeyCount={resp.get('KeyCount', 0)})")


# =============================================================================
# TEST 2 : S3 Opérations CRUD — PUT/GET/DELETE (SigV2)
# =============================================================================

@skip_no_s3
class TestS3DataOperations:
    """Tests CRUD S3 réels avec SigV2 (requis par Dell ECS pour les données)."""

    def test_put_object(self, s3_data):
        """PUT object — écrit un objet de test sur S3."""
        key = f"{TEST_PREFIX}/test_put.txt"
        body = b"Hello MCP Vault test!"

        resp = s3_data.put_object(Bucket=S3_BUCKET, Key=key, Body=body, ContentType="text/plain")
        assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
        print(f"✅ PUT object OK: {key}")

    def test_get_object(self, s3_data):
        """GET object — lit l'objet écrit précédemment."""
        key = f"{TEST_PREFIX}/test_put.txt"

        # Écrire d'abord
        s3_data.put_object(Bucket=S3_BUCKET, Key=key, Body=b"Hello GET test!", ContentType="text/plain")

        # Lire
        resp = s3_data.get_object(Bucket=S3_BUCKET, Key=key)
        body = resp["Body"].read()
        assert body == b"Hello GET test!"
        print(f"✅ GET object OK: {key} ({len(body)} bytes)")

    def test_delete_object(self, s3_data):
        """DELETE object — supprime l'objet de test."""
        key = f"{TEST_PREFIX}/test_delete.txt"

        # Écrire puis supprimer
        s3_data.put_object(Bucket=S3_BUCKET, Key=key, Body=b"to be deleted")
        resp = s3_data.delete_object(Bucket=S3_BUCKET, Key=key)
        assert resp["ResponseMetadata"]["HTTPStatusCode"] in (200, 204)
        print(f"✅ DELETE object OK: {key}")

        # Vérifier que l'objet n'existe plus
        with pytest.raises(Exception) as exc_info:
            s3_data.get_object(Bucket=S3_BUCKET, Key=key)
        assert "NoSuchKey" in str(exc_info.value) or "404" in str(exc_info.value)

    def test_put_json_object(self, s3_data):
        """PUT JSON — écrit un objet JSON (comme tokens.json)."""
        key = f"{TEST_PREFIX}/test_json.json"
        data = {"tokens": [{"name": "test", "hash": "abc123"}]}
        body = json.dumps(data, indent=2).encode()

        resp = s3_data.put_object(Bucket=S3_BUCKET, Key=key, Body=body, ContentType="application/json")
        assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200

        # Relire et vérifier
        resp = s3_data.get_object(Bucket=S3_BUCKET, Key=key)
        loaded = json.loads(resp["Body"].read().decode())
        assert loaded == data
        print(f"✅ PUT/GET JSON OK: {key}")

    def test_put_large_object(self, s3_data):
        """PUT large — écrit un objet de 1 MB (simule un tar.gz vault)."""
        key = f"{TEST_PREFIX}/test_large.bin"
        body = os.urandom(1024 * 1024)  # 1 MB

        resp = s3_data.put_object(Bucket=S3_BUCKET, Key=key, Body=body)
        assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200

        # Vérifier la taille
        resp = s3_data.get_object(Bucket=S3_BUCKET, Key=key)
        received = resp["Body"].read()
        assert len(received) == len(body)
        assert received == body
        print(f"✅ PUT/GET large object OK: {key} (1 MB)")


# =============================================================================
# TEST 3 : S3 LIST avec préfixe (SigV4)
# =============================================================================

@skip_no_s3
class TestS3ListOperations:
    """Tests de listing S3 avec SigV4."""

    def test_list_with_prefix(self, s3_data, s3_meta):
        """LIST avec préfixe — vérifie qu'on retrouve les objets créés."""
        # Écrire quelques objets
        for i in range(3):
            key = f"{TEST_PREFIX}/list_test/item_{i}.txt"
            s3_data.put_object(Bucket=S3_BUCKET, Key=key, Body=f"item {i}".encode())

        # Lister
        resp = s3_meta.list_objects_v2(Bucket=S3_BUCKET, Prefix=f"{TEST_PREFIX}/list_test/")
        keys = [obj["Key"] for obj in resp.get("Contents", [])]
        assert len(keys) == 3
        print(f"✅ LIST avec préfixe OK: {len(keys)} objets trouvés")

    def test_list_empty_prefix(self, s3_meta):
        """LIST avec préfixe inexistant — retourne 0 résultats."""
        resp = s3_meta.list_objects_v2(Bucket=S3_BUCKET, Prefix=f"_nonexistent_{uuid.uuid4().hex}/")
        assert resp.get("KeyCount", 0) == 0
        print("✅ LIST préfixe vide OK: 0 résultats")


# =============================================================================
# TEST 4 : Tar.gz upload/download (simule le sync vault)
# =============================================================================

@skip_no_s3
class TestS3TarGzSync:
    """Tests du pattern tar.gz pour la sync du file backend OpenBao."""

    def test_tar_gz_roundtrip(self, s3_data):
        """Crée un tar.gz en mémoire, upload, download, décompresse, vérifie."""
        key = f"{TEST_PREFIX}/vault_sync/openbao-data.tar.gz"

        # Créer un répertoire temporaire avec des fichiers
        with tempfile.TemporaryDirectory() as tmpdir:
            # Simuler des fichiers vault
            for name in ["core/seal-config", "logical/abc123", "sys/token/id/root"]:
                fpath = Path(tmpdir) / name
                fpath.parent.mkdir(parents=True, exist_ok=True)
                fpath.write_text(f"data for {name}")

            # Créer l'archive tar.gz en mémoire
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as tar:
                for item in Path(tmpdir).iterdir():
                    tar.add(str(item), arcname=item.name)
            buf.seek(0)
            archive_data = buf.read()
            archive_size = len(archive_data)

            # Upload sur S3
            resp = s3_data.put_object(
                Bucket=S3_BUCKET, Key=key,
                Body=archive_data, ContentType="application/gzip",
            )
            assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
            print(f"  📤 Upload tar.gz OK ({archive_size} bytes)")

        # Download depuis S3
        resp = s3_data.get_object(Bucket=S3_BUCKET, Key=key)
        downloaded = resp["Body"].read()
        assert len(downloaded) == archive_size
        print(f"  📥 Download tar.gz OK ({len(downloaded)} bytes)")

        # Décompresser dans un nouveau répertoire
        with tempfile.TemporaryDirectory() as tmpdir2:
            with tarfile.open(fileobj=io.BytesIO(downloaded), mode="r:gz") as tar:
                tar.extractall(path=tmpdir2)

            # Vérifier les fichiers
            extracted_files = list(Path(tmpdir2).rglob("*"))
            file_count = sum(1 for f in extracted_files if f.is_file())
            assert file_count >= 3, f"Attendu >= 3 fichiers, trouvé {file_count}"
            print(f"  📂 Extraction OK ({file_count} fichiers)")

        print(f"✅ Tar.gz roundtrip complet: {key}")


# =============================================================================
# TEST 5 : Token Store S3 (CRUD réel)
# =============================================================================

@skip_no_s3
class TestTokenStoreS3:
    """Tests du Token Store avec un vrai S3."""

    def _make_store(self, s3_data):
        """Crée un TokenStore avec les vrais credentials et un préfixe de test."""
        from types import SimpleNamespace
        settings = SimpleNamespace(
            s3_endpoint_url=S3_ENDPOINT,
            s3_access_key_id=S3_ACCESS_KEY,
            s3_secret_access_key=S3_SECRET_KEY,
            s3_bucket_name=S3_BUCKET,
            s3_region_name=S3_REGION,
        )
        # On crée un store custom avec un S3_KEY préfixé pour les tests
        from mcp_vault.auth.token_store import TokenStore
        store = TokenStore(settings)
        store.S3_KEY = f"{TEST_PREFIX}/tokens.json"
        # Override les méthodes S3 pour utiliser nos clients de test
        store._get_s3_data = lambda: s3_data
        return store

    def test_create_and_load_token(self, s3_data):
        """Crée un token, sauvegarde sur S3, recharge et vérifie."""
        store = self._make_store(s3_data)

        # Créer un token
        result = store.create(
            client_name="test-agent",
            permissions=["read", "write"],
            allowed_resources=["vault-space-1"],
            email="test@cloudtemple.com",
        )

        assert "raw_token" in result
        assert result["client_name"] == "test-agent"
        assert result["permissions"] == ["read", "write"]
        raw_token = result["raw_token"]
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        print(f"  ✅ Token créé: {result['hash'][:12]}...")

        # Recharger depuis S3 dans un nouveau store
        store2 = self._make_store(s3_data)
        store2.load()
        assert store2.count() >= 1
        print(f"  ✅ Token rechargé depuis S3 ({store2.count()} tokens)")

        # Vérifier par hash
        found = store2.get_by_hash(token_hash)
        assert found is not None
        assert found["client_name"] == "test-agent"
        print(f"  ✅ Token trouvé par hash: {found['client_name']}")

    def test_list_tokens(self, s3_data):
        """Liste les tokens après création."""
        store = self._make_store(s3_data)
        store.create(client_name="agent-1", permissions=["read"])
        store.create(client_name="agent-2", permissions=["read", "write"])

        tokens = store.list_all()
        assert len(tokens) >= 2
        names = [t["client_name"] for t in tokens]
        assert "agent-1" in names
        assert "agent-2" in names
        print(f"  ✅ Liste tokens OK ({len(tokens)} tokens)")

    def test_revoke_token(self, s3_data):
        """Révoque un token et vérifie qu'il est marqué révoqué."""
        store = self._make_store(s3_data)
        result = store.create(client_name="to-revoke", permissions=["read"])
        hash_prefix = result["hash"][:12]

        # Révoquer
        assert store.revoke(hash_prefix) is True
        print(f"  ✅ Token révoqué: {hash_prefix}...")

        # Vérifier
        tokens = store.list_all()
        revoked = [t for t in tokens if t["hash_prefix"] == hash_prefix]
        assert len(revoked) == 1
        assert revoked[0]["revoked"] is True

        # Recharger et re-vérifier la persistance
        store2 = self._make_store(s3_data)
        store2.load()
        tokens2 = store2.list_all()
        revoked2 = [t for t in tokens2 if t["hash_prefix"] == hash_prefix]
        assert len(revoked2) == 1
        assert revoked2[0]["revoked"] is True
        print(f"  ✅ Révocation persistée sur S3")

    def test_cleanup_test_tokens(self, s3_data):
        """Nettoie le fichier tokens.json de test sur S3."""
        key = f"{TEST_PREFIX}/tokens.json"
        try:
            s3_data.delete_object(Bucket=S3_BUCKET, Key=key)
            print(f"  🧹 Nettoyé: {key}")
        except Exception:
            pass


# =============================================================================
# TEST 6 : Auth Context (logique pure, pas de S3)
# =============================================================================

class TestAuthContext:
    """Tests de la logique d'autorisation (check_access, check_write, check_admin)."""

    def test_check_access_no_token(self):
        """Sans token → accès refusé."""
        from mcp_vault.auth.context import current_token_info, check_access
        tok = current_token_info.set(None)
        try:
            result = check_access("my-space")
            assert result is not None
            assert result["status"] == "error"
            assert "Authentification" in result["message"]
            print("✅ check_access sans token → refusé")
        finally:
            current_token_info.reset(tok)

    def test_check_access_admin(self):
        """Token admin → accès total."""
        from mcp_vault.auth.context import current_token_info, check_access
        tok = current_token_info.set({
            "client_name": "admin",
            "permissions": ["admin", "read", "write"],
            "space_ids": [],
        })
        try:
            result = check_access("any-space")
            assert result is None  # None = OK
            print("✅ check_access admin → OK")
        finally:
            current_token_info.reset(tok)

    def test_check_access_allowed_space(self):
        """Token avec space autorisé → OK."""
        from mcp_vault.auth.context import current_token_info, check_access
        tok = current_token_info.set({
            "client_name": "agent-1",
            "permissions": ["read"],
            "space_ids": ["space-a", "space-b"],
        })
        try:
            assert check_access("space-a") is None
            assert check_access("space-b") is None
            result = check_access("space-c")
            assert result is not None
            assert "refusé" in result["message"].lower() or "Accès" in result["message"]
            print("✅ check_access space autorisé/refusé → OK")
        finally:
            current_token_info.reset(tok)

    def test_check_write_permission(self):
        """Vérifie les permissions d'écriture."""
        from mcp_vault.auth.context import current_token_info, check_write_permission

        # Token read-only → refusé
        tok = current_token_info.set({"client_name": "reader", "permissions": ["read"]})
        try:
            result = check_write_permission()
            assert result is not None
            assert "écriture" in result["message"].lower()
            print("✅ check_write read-only → refusé")
        finally:
            current_token_info.reset(tok)

        # Token write → OK
        tok = current_token_info.set({"client_name": "writer", "permissions": ["read", "write"]})
        try:
            assert check_write_permission() is None
            print("✅ check_write read+write → OK")
        finally:
            current_token_info.reset(tok)

    def test_check_admin_permission(self):
        """Vérifie les permissions admin."""
        from mcp_vault.auth.context import current_token_info, check_admin_permission

        # Token non-admin → refusé
        tok = current_token_info.set({"client_name": "user", "permissions": ["read", "write"]})
        try:
            result = check_admin_permission()
            assert result is not None
            assert "admin" in result["message"].lower()
            print("✅ check_admin non-admin → refusé")
        finally:
            current_token_info.reset(tok)

        # Token admin → OK
        tok = current_token_info.set({"client_name": "admin", "permissions": ["admin"]})
        try:
            assert check_admin_permission() is None
            print("✅ check_admin admin → OK")
        finally:
            current_token_info.reset(tok)


# =============================================================================
# TEST 7 : Configuration
# =============================================================================

class TestConfig:
    """Tests de chargement de la configuration."""

    def test_default_settings(self):
        """Vérifie les valeurs par défaut de la config."""
        os.environ.setdefault("MCP_SERVER_NAME", "mcp-vault")
        from mcp_vault.config import Settings
        settings = Settings()
        assert settings.mcp_server_name == "mcp-vault"
        assert settings.mcp_server_port == 8030
        assert settings.openbao_addr == "http://127.0.0.1:8200"
        assert settings.openbao_shares == 1
        assert settings.openbao_threshold == 1
        assert settings.vault_s3_sync_interval == 60
        print("✅ Config par défaut OK")

    def test_openbao_settings(self):
        """Vérifie les settings OpenBao."""
        from mcp_vault.config import Settings
        settings = Settings()
        assert settings.openbao_data_dir == "/openbao/file"
        assert settings.openbao_config_dir == "/openbao/config"
        print("✅ Config OpenBao OK")


# =============================================================================
# TEST 8 : OpenBao HCL Config Generation
# =============================================================================

class TestOpenBaoConfig:
    """Tests de la génération du fichier HCL."""

    def test_generate_hcl(self):
        """Génère un HCL dans un répertoire temporaire et vérifie le contenu."""
        os.environ["OPENBAO_CONFIG_DIR"] = tempfile.mkdtemp()
        os.environ["OPENBAO_DATA_DIR"] = "/tmp/openbao-test-data"
        os.environ["OPENBAO_ADDR"] = "http://127.0.0.1:8200"

        # Clear le cache pydantic
        from mcp_vault.config import get_settings
        get_settings.cache_clear()

        from mcp_vault.openbao.config import generate_hcl_config
        config_path = generate_hcl_config()

        assert os.path.exists(config_path)
        content = open(config_path).read()

        # Vérifier les éléments clés
        assert 'storage "file"' in content
        assert "/tmp/openbao-test-data" in content
        assert 'listener "tcp"' in content
        assert "127.0.0.1:8200" in content
        assert "tls_disable = true" in content
        assert "disable_mlock = true" in content
        assert "ui = false" in content
        print(f"✅ HCL généré OK: {config_path}")
        print(f"   Contenu:\n{content}")

        # Cleanup
        os.unlink(config_path)
        get_settings.cache_clear()


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
