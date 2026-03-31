# -*- coding: utf-8 -*-
"""
Token Store S3 avec cache mémoire TTL 5 minutes.

Si S3 n'est pas configuré, les tokens sont gérés en mémoire uniquement
(bootstrap key). Quand S3 est configuré, les tokens sont stockés dans
_system/tokens.json sur le bucket S3.

Pattern :
    init_token_store()     → Appelé au démarrage (charge depuis S3)
    get_token_store()      → Getter singleton (retourne None si pas configuré)
"""

import sys
import time
import json
import hashlib
from typing import Optional

from ..config import get_settings

# =============================================================================
# Token Store singleton
# =============================================================================

_token_store = None


def get_token_store() -> Optional["TokenStore"]:
    """Retourne le Token Store (None si S3 non configuré)."""
    return _token_store


def init_token_store():
    """Initialise le Token Store au démarrage (charge depuis S3 si configuré)."""
    global _token_store
    settings = get_settings()

    if settings.s3_endpoint_url and settings.s3_bucket_name:
        _token_store = TokenStore(settings)
        _token_store.load()
        print(f"🔑 Token Store S3 initialisé ({_token_store.count()} tokens)", file=sys.stderr)
    else:
        print("🔑 Token Store S3 non configuré (bootstrap key uniquement)", file=sys.stderr)


# =============================================================================
# TokenStore — Stockage S3 + cache mémoire TTL
# =============================================================================

class TokenStore:
    """
    Gestion des tokens d'accès MCP.

    - Stockage sur S3 : _system/tokens.json
    - Cache mémoire avec TTL de 5 minutes
    - CRUD : create, list, info, revoke
    """

    CACHE_TTL = 300  # 5 minutes
    S3_KEY = "_system/tokens.json"

    def __init__(self, settings):
        self.settings = settings
        self._tokens: dict = {}  # hash → token_info
        self._cache_time: float = 0
        self._s3_client = None

    def _get_s3_data(self):
        """Client S3 SigV2 pour PUT/GET/DELETE (données)."""
        from ..s3_client import get_s3_data_client
        return get_s3_data_client()

    def _get_s3_meta(self):
        """Client S3 SigV4 pour HEAD/LIST (métadonnées)."""
        from ..s3_client import get_s3_meta_client
        return get_s3_meta_client()

    def load(self):
        """Charge les tokens depuis S3 (GET = SigV2)."""
        try:
            s3 = self._get_s3_data()
            resp = s3.get_object(Bucket=self.settings.s3_bucket_name, Key=self.S3_KEY)
            data = json.loads(resp["Body"].read().decode())
            self._tokens = {t["hash"]: t for t in data.get("tokens", [])}
            self._cache_time = time.time()
        except Exception as e:
            if "NoSuchKey" in str(e) or "404" in str(e):
                self._tokens = {}
                self._cache_time = time.time()
            else:
                print(f"⚠️  Token Store S3 : {e}", file=sys.stderr)

    def _save(self):
        """Sauvegarde les tokens sur S3 (PUT = SigV2)."""
        try:
            s3 = self._get_s3_data()
            data = json.dumps(
                {"tokens": list(self._tokens.values())},
                indent=2, default=str,
            )
            s3.put_object(
                Bucket=self.settings.s3_bucket_name,
                Key=self.S3_KEY,
                Body=data.encode(),
                ContentType="application/json",
            )
        except Exception as e:
            print(f"⚠️  Token Store S3 save : {e}", file=sys.stderr)

    def _maybe_refresh(self):
        """Rafraîchit le cache si le TTL est dépassé."""
        if time.time() - self._cache_time > self.CACHE_TTL:
            self.load()

    def get_by_hash(self, token_hash: str) -> Optional[dict]:
        """Cherche un token par son hash SHA-256. Vérifie l'expiration."""
        self._maybe_refresh()
        token = self._tokens.get(token_hash)
        if token and token.get("expires_at"):
            from datetime import datetime, timezone
            try:
                expires = datetime.fromisoformat(token["expires_at"])
                if datetime.now(timezone.utc) > expires:
                    return None  # Token expiré
            except (ValueError, TypeError):
                # SÉCURITÉ V2-17 : fail-close — expires_at corrompu = token invalide
                return None
        return token

    def create(self, client_name: str, permissions: list, allowed_resources: list = None,
               expires_in_days: int = 90, email: str = "", policy_id: str = "") -> dict:
        """Crée un nouveau token et le sauvegarde sur S3."""
        import secrets
        from datetime import datetime, timezone, timedelta

        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

        now = datetime.now(timezone.utc)
        expires_at = None
        if expires_in_days and expires_in_days > 0:
            expires_at = (now + timedelta(days=expires_in_days)).isoformat()

        token_info = {
            "hash": token_hash,
            "client_name": client_name,
            "permissions": permissions,
            "allowed_resources": allowed_resources or [],
            "policy_id": policy_id,
            "email": email,
            "created_at": now.isoformat(),
            "expires_at": expires_at,
            "revoked": False,
        }

        self._tokens[token_hash] = token_info
        self._save()

        return {"raw_token": raw_token, **token_info}

    def list_all(self) -> list:
        """Liste tous les tokens (sans les hash complets)."""
        self._maybe_refresh()
        return [
            {
                "client_name": t["client_name"],
                "permissions": t["permissions"],
                "policy_id": t.get("policy_id", ""),
                "email": t.get("email", ""),
                "hash_prefix": t["hash"][:12],
                "allowed_resources": t.get("allowed_resources", []),
                "created_at": t.get("created_at", ""),
                "expires_at": t.get("expires_at"),
                "revoked": t.get("revoked", False),
                "revoked_at": t.get("revoked_at", ""),
            }
            for t in self._tokens.values()
        ]

    def update(self, hash_prefix: str, policy_id: str = None,
               permissions: list = None, allowed_resources: list = None) -> dict:
        """
        Met à jour un token existant (policy_id, permissions, allowed_resources).

        Seuls les champs fournis (non-None) sont modifiés.
        Retourne le token mis à jour ou une erreur.
        """
        self._maybe_refresh()

        # Trouver le token par préfixe de hash
        target_hash = None
        for h in self._tokens:
            if h.startswith(hash_prefix):
                target_hash = h
                break

        if not target_hash:
            return {"status": "error", "message": f"Token {hash_prefix}... non trouvé"}

        token = self._tokens[target_hash]
        if token.get("revoked"):
            return {"status": "error", "message": f"Token {hash_prefix}... est révoqué"}

        updated_fields = []

        if policy_id is not None:
            token["policy_id"] = policy_id
            updated_fields.append("policy_id")

        if permissions is not None:
            valid_perms = {"read", "write", "admin"}
            if not all(p in valid_perms for p in permissions):
                return {"status": "error", "message": f"Permissions invalides: {permissions}"}
            token["permissions"] = permissions
            updated_fields.append("permissions")

        if allowed_resources is not None:
            token["allowed_resources"] = allowed_resources
            updated_fields.append("allowed_resources")

        if not updated_fields:
            return {"status": "error", "message": "Aucun champ à modifier"}

        self._save()

        return {
            "status": "updated",
            "hash_prefix": hash_prefix,
            "client_name": token["client_name"],
            "updated_fields": updated_fields,
            "policy_id": token.get("policy_id", ""),
            "permissions": token["permissions"],
            "allowed_resources": token.get("allowed_resources", []),
        }

    def revoke(self, hash_prefix: str) -> bool:
        """Révoque un token par préfixe de hash."""
        from datetime import datetime, timezone
        for h, t in self._tokens.items():
            if h.startswith(hash_prefix):
                t["revoked"] = True
                t["revoked_at"] = datetime.now(timezone.utc).isoformat()
                self._save()
                return True
        return False

    def count(self) -> int:
        """Nombre de tokens actifs."""
        return sum(1 for t in self._tokens.values() if not t.get("revoked", False))
