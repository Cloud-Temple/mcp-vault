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
                pass
        return token

    def create(self, client_name: str, permissions: list, allowed_resources: list = None,
               expires_in_days: int = 90, email: str = "") -> dict:
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
                "email": t.get("email", ""),
                "hash_prefix": t["hash"][:12],
                "expires_at": t.get("expires_at"),
                "revoked": t.get("revoked", False),
            }
            for t in self._tokens.values()
        ]

    def revoke(self, hash_prefix: str) -> bool:
        """Révoque un token par préfixe de hash."""
        for h, t in self._tokens.items():
            if h.startswith(hash_prefix):
                t["revoked"] = True
                self._save()
                return True
        return False

    def count(self) -> int:
        """Nombre de tokens actifs."""
        return sum(1 for t in self._tokens.values() if not t.get("revoked", False))
