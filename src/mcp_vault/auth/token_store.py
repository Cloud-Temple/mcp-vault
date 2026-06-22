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

import logging
import sys
import time
import json
import hashlib
from typing import Optional

logger = logging.getLogger("mcp-vault.token-store")

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
    # Source unique de vérité des niveaux de permission valides (flags non
    # hiérarchiques). Utilisée par create() et update(), et référencée par
    # admin/api.py (_api_create_token) pour éviter toute divergence.
    VALID_PERMISSIONS = frozenset({"read", "write", "admin"})

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
            # Migration : nettoie les valeurs "_remove" stockées par erreur
            # (bug SPA < v0.4.11 : l'admin /admin envoyait le sentinel MCP tel quel).
            dirty = False
            for token in self._tokens.values():
                if token.get("policy_id") == "_remove":
                    token["policy_id"] = ""
                    dirty = True
            if dirty:
                self._save()
                print("ℹ️  Token Store : migration policy_id '_remove' → '' effectuée.", file=sys.stderr)
        except Exception as e:
            if "NoSuchKey" in str(e) or "404" in str(e):
                self._tokens = {}
                self._cache_time = time.time()
            else:
                print(f"⚠️  Token Store S3 : {e}", file=sys.stderr)

    def _save(self) -> bool:
        """
        Sauvegarde les tokens sur S3 (PUT = SigV2).

        Retourne True si succès, False si S3 indisponible.
        Les appelants doivent rollback l'état mémoire si False est retourné
        (révocation perdue = faille sécurité critique).

        LIMITATION V1 — last-write-wins (issue #13) :
        En déploiement multi-instance, deux instances concurrent peuvent s'écraser
        mutuellement (ex: instance A révoque T1 pendant qu'instance B crée T3 →
        la révocation de T1 peut être perdue). Acceptable en V1 (single-instance).
        V2 : utiliser S3 conditional write (If-Match: ETag) ou lock distribué.
        """
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
            return True
        except Exception as e:
            logger.error("Token Store S3 save FAILED: %s — état mémoire non persisté", type(e).__name__)
            return False

    def _maybe_refresh(self):
        """Rafraîchit le cache si le TTL est dépassé."""
        if time.time() - self._cache_time > self.CACHE_TTL:
            self.load()

    def get_by_hash(self, token_hash: str) -> Optional[dict]:
        """Cherche un token par son hash SHA-256. Vérifie l'expiration."""
        self._maybe_refresh()
        token = self._tokens.get(token_hash)
        if token is None:
            return None
        # SÉCURITÉ V2-17 : fail-close — expires_at corrompu ou expiré = token invalide
        if self._is_expired(token):
            return None
        return token

    def create(self, client_name: str, permissions: list, allowed_resources: list = None,
               expires_in_days: int = 90, email: str = "", policy_id: str = "") -> dict:
        """Crée un nouveau token et le sauvegarde sur S3."""
        # Validation des permissions — défense en profondeur (issue #48).
        # Le store ne doit JAMAIS persister un flag inconnu ni une liste vide,
        # quel que soit l'appelant (le point d'entrée HTTP valide déjà, mais le
        # store doit être sûr par lui-même). Cohérent avec update().
        if not isinstance(permissions, list) or not permissions:
            return {"status": "error", "error_type": "invalid_permissions",
                    "message": "permissions doit être une liste non vide (read|write|admin)"}
        if not all(isinstance(p, str) and p in self.VALID_PERMISSIONS for p in permissions):
            return {"status": "error", "error_type": "invalid_permissions",
                    "message": f"Permissions invalides: {permissions}. Valides: read, write, admin"}

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
        if not self._save():
            del self._tokens[token_hash]  # rollback mémoire
            return {"status": "error", "error_type": "storage_unavailable",
                    "message": "Impossible de créer le token (S3 indisponible)"}

        return {"raw_token": raw_token, **token_info}

    def list_all(self) -> list:
        """Liste tous les tokens (sans les hash complets) avec champ 'expired'."""
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
                "expired": self._is_expired(t),
            }
            for t in self._tokens.values()
        ]

    @staticmethod
    def _normalize_hash_prefix(hash_prefix: str) -> str:
        """Normalise un hash_prefix : strip whitespace + lowercase (SHA-256 = hex lowercase)."""
        return hash_prefix.strip().lower() if hash_prefix else ""

    @staticmethod
    def _validate_hash_prefix(hash_prefix: str) -> Optional[str]:
        """
        Valide un préfixe de hash token pour les opérations update/revoke.
        Retourne None si OK, message d'erreur si invalide.

        - Minimum 12 chars (list_all expose 12 chars — en dessous, ambiguïté garantie)
        - Hexadécimal uniquement (lowercase après normalisation)
        - Non vide
        """
        hp = TokenStore._normalize_hash_prefix(hash_prefix)
        if not hp:
            return "hash_prefix requis"
        if len(hp) < 12:
            return f"hash_prefix trop court ({len(hp)} chars, minimum 12)"
        if not all(c in "0123456789abcdef" for c in hp):
            return "hash_prefix invalide (hexadécimal uniquement)"
        return None

    def _resolve_hash(self, hash_prefix: str) -> Optional[str]:
        """
        Résout un préfixe de hash normalisé en hash complet.
        Retourne None si aucun match.
        Lève ValueError si ambiguïté (plusieurs tokens matchent).
        """
        hp = self._normalize_hash_prefix(hash_prefix)
        matches = [h for h in self._tokens if h.startswith(hp)]
        if len(matches) == 0:
            return None
        if len(matches) > 1:
            raise ValueError(f"hash_prefix '{hash_prefix}' ambigu : {len(matches)} tokens matchent")
        return matches[0]

    def update(self, hash_prefix: str, policy_id: str = None,
               permissions: list = None, allowed_resources: list = None) -> dict:
        """
        Met à jour un token existant (policy_id, permissions, allowed_resources).

        Seuls les champs fournis (non-None) sont modifiés.
        Retourne le token mis à jour ou une erreur.
        """
        err = self._validate_hash_prefix(hash_prefix)
        if err:
            return {"status": "error", "message": err}

        self._maybe_refresh()

        try:
            target_hash = self._resolve_hash(hash_prefix)
        except ValueError as e:
            return {"status": "error", "message": str(e)}

        if not target_hash:
            return {"status": "error", "message": f"Token {hash_prefix}... non trouvé"}

        token = self._tokens[target_hash]
        if token.get("revoked"):
            return {"status": "error", "message": f"Token {hash_prefix}... est révoqué"}

        # ── TOUTES les validations AVANT toute mutation ──────────────────
        if permissions is not None:
            if not all(isinstance(p, str) and p in self.VALID_PERMISSIONS for p in permissions):
                return {"status": "error", "message": f"Permissions invalides: {permissions}"}

        updated_fields = []
        if policy_id is not None:
            updated_fields.append("policy_id")
        if permissions is not None:
            updated_fields.append("permissions")
        if allowed_resources is not None:
            updated_fields.append("allowed_resources")

        if not updated_fields:
            return {"status": "error", "message": "Aucun champ à modifier"}

        # ── Snapshot AVANT mutation pour rollback si _save échoue ────────
        import copy
        snapshot = copy.deepcopy(dict(token))

        # ── Mutations uniquement après validation et snapshot ─────────────
        if policy_id is not None:
            # Convertit le sentinel "_remove" en "" pour compatibilité avec l'outil MCP
            token["policy_id"] = "" if policy_id == "_remove" else policy_id

        if permissions is not None:
            token["permissions"] = permissions

        if allowed_resources is not None:
            token["allowed_resources"] = allowed_resources

        if not self._save():
            self._tokens[target_hash].clear()
            self._tokens[target_hash].update(snapshot)  # rollback vers l'état pré-mutation
            return {"status": "error", "error_type": "storage_unavailable",
                    "message": "Modification non persistée (S3 indisponible)"}

        return {
            "status": "updated",
            "hash_prefix": hash_prefix,
            "client_name": token["client_name"],
            "updated_fields": updated_fields,
            "policy_id": token.get("policy_id", ""),
            "permissions": token["permissions"],
            "allowed_resources": token.get("allowed_resources", []),
        }

    def revoke(self, hash_prefix: str) -> dict:
        """
        Révoque un token par préfixe de hash (minimum 12 chars, hexadécimal).

        Retourne un dict avec status : "ok" | "not_found" | "invalid_prefix"
                                      | "ambiguous" | "storage_unavailable"
        Distingue les différentes causes d'échec pour une propagation HTTP correcte.
        """
        from datetime import datetime, timezone
        err = self._validate_hash_prefix(hash_prefix)
        if err:
            return {"status": "invalid_prefix", "message": err}
        self._maybe_refresh()
        try:
            target_hash = self._resolve_hash(hash_prefix)
        except ValueError as e:
            return {"status": "ambiguous", "message": str(e)}
        if not target_hash:
            return {"status": "not_found", "message": f"Token {hash_prefix}... non trouvé"}
        t = self._tokens[target_hash]
        old_revoked = t.get("revoked", False)
        old_revoked_at = t.get("revoked_at")
        t["revoked"] = True
        t["revoked_at"] = datetime.now(timezone.utc).isoformat()
        if not self._save():
            # Rollback : une révocation non persistée est CRITIQUE
            t["revoked"] = old_revoked
            if old_revoked_at:
                t["revoked_at"] = old_revoked_at
            else:
                t.pop("revoked_at", None)
            logger.error("Révocation du token %s... non persistée — S3 indisponible", hash_prefix[:12])
            return {"status": "storage_unavailable",
                    "message": f"Révocation non persistée — S3 indisponible (token {hash_prefix[:12]}...)"}
        return {"status": "ok", "message": f"Token {hash_prefix[:12]}... révoqué"}

    def purge_revoked(self, older_than_days: int = 30, dry_run: bool = False) -> dict:
        """
        Purge définitivement les tokens RÉVOQUÉS depuis plus de `older_than_days`
        jours (rétention). N'affecte JAMAIS les tokens actifs, ni les tokens
        expirés non révoqués (qui doivent rester visibles).

        Fail-close : un token révoqué sans `revoked_at` parseable n'est PAS purgé
        — on ne détruit pas une preuve qu'on ne sait pas dater.

        Args:
            older_than_days: rétention (défaut 30). 0 = purger tous les révoqués.
            dry_run: si True, ne supprime rien et retourne les candidats.

        Retourne {"status": "ok"|"storage_unavailable", "count", "dry_run",
                  "older_than_days", "candidates"|"purged": [...]}.
        """
        from datetime import datetime, timezone, timedelta
        self._maybe_refresh()
        cutoff = datetime.now(timezone.utc) - timedelta(days=max(0, older_than_days))

        candidates = []
        for h, t in self._tokens.items():
            if not t.get("revoked"):
                continue
            try:
                revoked_dt = datetime.fromisoformat(t.get("revoked_at"))
                if revoked_dt.tzinfo is None or revoked_dt >= cutoff:
                    continue  # date non comparable, ou révoqué trop récemment (rétention)
            except (ValueError, TypeError):
                continue  # fail-close : revoked_at absent / corrompu → non purgé
            candidates.append((h, t))

        summary = [
            {"client_name": t.get("client_name", ""), "hash_prefix": h[:12],
             "revoked_at": t.get("revoked_at", "")}
            for h, t in candidates
        ]

        if dry_run:
            return {"status": "ok", "dry_run": True, "count": len(summary),
                    "older_than_days": older_than_days, "candidates": summary,
                    "message": f"{len(summary)} token(s) révoqué(s) seraient purgés "
                               f"(rétention {older_than_days} j)"}

        if not candidates:
            return {"status": "ok", "dry_run": False, "count": 0,
                    "older_than_days": older_than_days, "purged": [],
                    "message": "Aucun token révoqué à purger (rétention respectée)"}

        # Snapshot pour rollback si _save échoue (cohérent avec revoke())
        import copy
        removed = {h: copy.deepcopy(self._tokens[h]) for h, _ in candidates}
        for h in removed:
            del self._tokens[h]

        if not self._save():
            self._tokens.update(removed)  # rollback : restaurer les tokens supprimés
            logger.error("Purge de %d token(s) révoqué(s) non persistée — S3 indisponible", len(removed))
            return {"status": "storage_unavailable", "dry_run": False, "count": 0,
                    "older_than_days": older_than_days,
                    "message": "Purge non persistée — S3 indisponible"}

        return {"status": "ok", "dry_run": False, "count": len(summary),
                "older_than_days": older_than_days, "purged": summary,
                "message": f"{len(summary)} token(s) révoqué(s) purgé(s)"}

    @staticmethod
    def _is_expired(token: dict) -> bool:
        """Vérifie si un token est expiré (cohérent avec get_by_hash)."""
        expires_at = token.get("expires_at")
        if not expires_at:
            return False
        from datetime import datetime, timezone
        try:
            return datetime.now(timezone.utc) > datetime.fromisoformat(expires_at)
        except (ValueError, TypeError):
            return True  # fail-close : date corrompue = expiré

    def count(self) -> int:
        """Nombre de tokens actifs (non révoqués et non expirés)."""
        return sum(
            1 for t in self._tokens.values()
            if not t.get("revoked", False) and not self._is_expired(t)
        )
