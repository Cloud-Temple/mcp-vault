# -*- coding: utf-8 -*-
"""
Policy Store S3 avec cache mémoire TTL 5 minutes.

Les policies MCP définissent les droits d'accès granulaires :
- allowed_tools / denied_tools : contrôle des outils MCP accessibles
- path_rules : permissions par vault pattern (wildcards supportés)

Stockage : _system/policies.json sur S3
Pattern identique à TokenStore (singleton + cache TTL).

Usage :
    init_policy_store()    → Appelé au démarrage (charge depuis S3)
    get_policy_store()     → Getter singleton
"""

import fnmatch
import json
import sys
import time
from datetime import datetime, timezone
from typing import Optional

from ..config import get_settings

# =============================================================================
# Policy Store singleton
# =============================================================================

_policy_store = None


def get_policy_store() -> Optional["PolicyStore"]:
    """Retourne le Policy Store (None si S3 non configuré)."""
    return _policy_store


def init_policy_store():
    """Initialise le Policy Store au démarrage (charge depuis S3 si configuré)."""
    global _policy_store
    settings = get_settings()

    if settings.s3_endpoint_url and settings.s3_bucket_name:
        _policy_store = PolicyStore(settings)
        _policy_store.load()
        print(f"📋 Policy Store S3 initialisé ({_policy_store.count()} policies)", file=sys.stderr)
    else:
        print("📋 Policy Store S3 non configuré", file=sys.stderr)


# =============================================================================
# PolicyStore — Stockage S3 + cache mémoire TTL
# =============================================================================

class PolicyStore:
    """
    Gestion des policies MCP.

    - Stockage sur S3 : _system/policies.json
    - Cache mémoire avec TTL de 5 minutes
    - CRUD : create, list, get, delete
    - Matching : wildcards sur tool names et vault patterns
    """

    CACHE_TTL = 300  # 5 minutes
    S3_KEY = "_system/policies.json"

    def __init__(self, settings):
        self.settings = settings
        self._policies: dict = {}  # policy_id → policy_info
        self._cache_time: float = 0

    def _get_s3_data(self):
        """Client S3 SigV2 pour PUT/GET/DELETE (données)."""
        from ..s3_client import get_s3_data_client
        return get_s3_data_client()

    def load(self):
        """Charge les policies depuis S3 (GET = SigV2)."""
        try:
            s3 = self._get_s3_data()
            resp = s3.get_object(Bucket=self.settings.s3_bucket_name, Key=self.S3_KEY)
            data = json.loads(resp["Body"].read().decode())
            self._policies = {p["policy_id"]: p for p in data.get("policies", [])}
            self._cache_time = time.time()
        except Exception as e:
            if "NoSuchKey" in str(e) or "404" in str(e):
                self._policies = {}
                self._cache_time = time.time()
            else:
                print(f"⚠️  Policy Store S3 : {e}", file=sys.stderr)

    def _save(self):
        """Sauvegarde les policies sur S3 (PUT = SigV2)."""
        try:
            s3 = self._get_s3_data()
            data = json.dumps(
                {"policies": list(self._policies.values())},
                indent=2, default=str,
            )
            s3.put_object(
                Bucket=self.settings.s3_bucket_name,
                Key=self.S3_KEY,
                Body=data.encode(),
                ContentType="application/json",
            )
        except Exception as e:
            print(f"⚠️  Policy Store S3 save : {e}", file=sys.stderr)

    def _maybe_refresh(self):
        """Rafraîchit le cache si le TTL est dépassé."""
        if time.time() - self._cache_time > self.CACHE_TTL:
            self.load()

    # ── CRUD ─────────────────────────────────────────────────────────

    def create(self, policy_id: str, description: str = "",
               allowed_tools: list = None, denied_tools: list = None,
               path_rules: list = None, created_by: str = "admin") -> dict:
        """
        Crée une nouvelle policy.

        Args:
            policy_id: Identifiant unique (alphanum + tirets, max 64 chars)
            description: Description lisible de la policy
            allowed_tools: Liste de patterns d'outils autorisés (ex: ["system_*", "vault_list"])
                           Vide = tous autorisés (sauf denied_tools)
            denied_tools: Liste de patterns d'outils refusés (ex: ["vault_delete"])
                          denied_tools a priorité sur allowed_tools
            path_rules: Règles par chemin vault (ex: [{"vault_pattern": "prod-*", "permissions": ["read"]}])
            created_by: Nom du créateur

        Returns:
            Policy créée ou erreur
        """
        self._maybe_refresh()

        # ── Validation ──
        if not policy_id or not policy_id.replace("-", "").replace("_", "").isalnum():
            return {"status": "error", "message": "policy_id invalide (alphanum, tirets, underscores)"}

        if len(policy_id) > 64:
            return {"status": "error", "message": "policy_id trop long (max 64 caractères)"}

        if policy_id in self._policies:
            return {"status": "error", "message": f"Policy '{policy_id}' existe déjà"}

        # ── Validation des path_rules ──
        validated_rules = []
        if path_rules:
            for rule in path_rules:
                if not isinstance(rule, dict):
                    return {"status": "error", "message": "Chaque path_rule doit être un objet"}
                if "vault_pattern" not in rule:
                    return {"status": "error", "message": "Chaque path_rule doit avoir un 'vault_pattern'"}
                perms = rule.get("permissions", ["read"])
                valid_perms = {"read", "write", "admin"}
                if not all(p in valid_perms for p in perms):
                    return {"status": "error", "message": f"Permissions invalides dans path_rule: {perms}"}
                validated_rules.append({
                    "vault_pattern": rule["vault_pattern"],
                    "permissions": perms,
                    "allowed_paths": rule.get("allowed_paths", []),
                })

        now = datetime.now(timezone.utc).isoformat()

        policy = {
            "policy_id": policy_id,
            "description": description,
            "allowed_tools": allowed_tools or [],
            "denied_tools": denied_tools or [],
            "path_rules": validated_rules,
            "created_at": now,
            "created_by": created_by,
        }

        self._policies[policy_id] = policy
        self._save()

        return {"status": "created", **policy}

    def get(self, policy_id: str) -> Optional[dict]:
        """Récupère une policy par son ID."""
        self._maybe_refresh()
        return self._policies.get(policy_id)

    def list_all(self) -> list:
        """Liste toutes les policies."""
        self._maybe_refresh()
        return [
            {
                "policy_id": p["policy_id"],
                "description": p.get("description", ""),
                "allowed_tools_count": len(p.get("allowed_tools", [])),
                "denied_tools_count": len(p.get("denied_tools", [])),
                "path_rules_count": len(p.get("path_rules", [])),
                "created_at": p.get("created_at", ""),
                "created_by": p.get("created_by", ""),
            }
            for p in self._policies.values()
        ]

    def delete(self, policy_id: str) -> bool:
        """Supprime une policy par son ID. Retourne True si supprimée."""
        self._maybe_refresh()
        if policy_id in self._policies:
            del self._policies[policy_id]
            self._save()
            return True
        return False

    def count(self) -> int:
        """Nombre de policies."""
        return len(self._policies)

    # ── Matching (pour Phase 8b — enforcement) ───────────────────────

    def is_tool_allowed(self, policy_id: str, tool_name: str) -> bool:
        """
        Vérifie si un outil est autorisé par la policy.

        Logique :
        1. Policy inexistante → REFUSÉ (fail-close, sécurité)
        2. Si denied_tools match → refusé (prioritaire)
        3. Si allowed_tools est vide → autorisé (tout est permis)
        4. Si allowed_tools match → autorisé
        5. Sinon → refusé

        Les patterns supportent les wildcards (* via fnmatch).

        SÉCURITÉ : fail-close — si la policy référencée par un token a été
        supprimée, le token est bloqué plutôt que devenir non-restreint.
        """
        policy = self.get(policy_id)
        if not policy:
            return False  # SÉCURITÉ : fail-close — policy supprimée = tout bloqué

        # denied_tools a priorité
        for pattern in policy.get("denied_tools", []):
            if fnmatch.fnmatch(tool_name, pattern):
                return False

        # allowed_tools vide = tout autorisé
        allowed = policy.get("allowed_tools", [])
        if not allowed:
            return True

        # Vérifier si au moins un pattern match
        for pattern in allowed:
            if fnmatch.fnmatch(tool_name, pattern):
                return True

        return False

    def get_vault_permissions(self, policy_id: str, vault_id: str) -> list:
        """
        Retourne les permissions pour un vault selon les path_rules.

        Si aucune règle ne matche → permissions par défaut du token.
        Les patterns supportent les wildcards (* via fnmatch).

        Returns:
            Liste de permissions (ex: ["read", "write"]) ou [] si aucune règle
        """
        policy = self.get(policy_id)
        if not policy:
            return []

        for rule in policy.get("path_rules", []):
            if fnmatch.fnmatch(vault_id, rule["vault_pattern"]):
                return rule.get("permissions", ["read"])

        return []  # Aucune règle applicable

    def is_path_allowed(self, policy_id: str, vault_id: str, path: str) -> bool:
        """
        Vérifie si un chemin de secret est autorisé dans un vault selon les path_rules.

        Logique :
        1. Pas de policy → autorisé
        2. Pas de path_rule matchant le vault → autorisé (pas de restriction path)
        3. path_rule sans allowed_paths → autorisé (restriction vault-level seulement)
        4. path_rule avec allowed_paths → le path doit matcher au moins un pattern

        Les patterns supportent les wildcards (* via fnmatch).

        Args:
            policy_id: ID de la policy
            vault_id: ID du vault
            path: Chemin du secret (ex: "web/github", "db/postgres")

        Returns:
            True si le chemin est autorisé
        """
        policy = self.get(policy_id)
        if not policy:
            return True  # Policy inexistante = pas de restriction

        # Chercher la première path_rule qui matche le vault
        for rule in policy.get("path_rules", []):
            if fnmatch.fnmatch(vault_id, rule["vault_pattern"]):
                allowed_paths = rule.get("allowed_paths", [])
                if not allowed_paths:
                    return True  # Pas de restriction path dans cette règle
                # Vérifier si le path matche au moins un pattern autorisé
                return any(fnmatch.fnmatch(path, p) for p in allowed_paths)

        return True  # Aucune règle vault matchante = pas de restriction path
