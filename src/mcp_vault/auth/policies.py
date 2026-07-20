# -*- coding: utf-8 -*-
"""
Policy Store S3 avec cache mémoire TTL 5 minutes.

Les policies MCP définissent les droits d'accès granulaires :
- allowed_tools / denied_tools : contrôle des outils MCP accessibles
- path_rules : permissions par vault pattern (wildcards supportés)

Stockage : _system/policies.json sur S3
Pattern calqué sur MissionBindingStore (état available/last_error, fail-close
sur panne S3 détectée après TTL — issue #86 Lot 3).

Sécurité (issue #86, finding 3) :
    Après expiration du TTL, une indisponibilité ou corruption détectée du
    PolicyStore ne sert plus une policy périmée ; le PEP refuse de manière
    observable (jamais un fail-open silencieux basé sur un cache périmé).

    LIMITATION CONNUE (HORS SCOPE de ce lot, issue #51/#13) : ce mécanisme
    ferme le sous-cas « panne/corruption détectée », PAS la race d'écriture
    multi-instance générale (deux instances qui écrivent concurremment SANS
    aucune panne — last-write-wins structurel sur le fichier unique partagé
    `_system/policies.json`, nécessite un vrai CAS/ETag S3 pour être fermé).
    Ne PAS présenter ce lot comme « PolicyStore multi-instance sécurisé ».

Usage :
    init_policy_store()    → Appelé au démarrage (charge depuis S3)
    get_policy_store()     → Getter singleton
"""

import fnmatch
import json
import logging
import sys
import time

logger = logging.getLogger("mcp-vault.policy-store")
from datetime import datetime, timezone
from typing import Optional

from ..config import get_settings

# Intervalle minimal de re-tentative de chargement après un échec (store indisponible).
# Évite de marteler S3 à chaque requête tout en récupérant vite dès qu'il revient.
# Borné PAR PROCESSUS SEULEMENT (pas de garantie multi-worker/réplica) — même
# compromis assumé que MissionBindingStore.
_RETRY_AFTER_ERROR_SECONDS = 10.0

# Permissions valides pour une path_rule (contrat fermé).
_VALID_PERMISSIONS = frozenset({"read", "write", "admin"})

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
        if _policy_store.available:
            print(f"📋 Policy Store S3 initialisé ({_policy_store.count()} policies)", file=sys.stderr)
        else:
            # Fail-close observable : le store existe mais son état est invalide au boot.
            # Les décisions de policy seront refusées (503/erreur structurée) ; aucune
            # policy périmée ne sera servie ; aucune mutation ne sera tentée.
            print(
                f"⚠️  Policy Store S3 INDISPONIBLE au démarrage : {_policy_store.last_error} — "
                "les décisions de policy seront refusées jusqu'à rétablissement",
                file=sys.stderr,
            )
    else:
        print("📋 Policy Store S3 non configuré", file=sys.stderr)


# =============================================================================
# Validation (module-level, testable isolément)
# =============================================================================

class PolicyStoreUnavailable(Exception):
    """Levée par get()/list_all()/get_vault_permissions()/is_tool_allowed()/
    is_path_allowed() quand le store est configuré mais indisponible/corrompu
    (panne S3 détectée après TTL, ou blob JSON/policy structurellement invalide).

    Les appelants (auth/context.py) doivent la mapper en refus OBSERVABLE (503
    REST, dict d'erreur structuré côté MCP) — JAMAIS un deny/allow silencieux
    basé sur un cache périmé.
    """


def _validate_and_normalize_policy(policy) -> dict:
    """Valide strictement une policy et retourne sa forme canonique normalisée.

    Ne mute jamais l'entrée fournie. Lève ValueError(message) si invalide.

    Défense en profondeur (issue #86 Lot 3, rounds de revue 3/4) : une policy
    structurellement incomplète ou corrompue ne doit JAMAIS devenir permissive
    par défaut (ex. une path_rule sans "permissions" ne doit pas hériter de
    {"read","write","admin"} — bug historique corrigé ici). Cette validation
    porte sur la CORRUPTION DÉTECTABLE (types, champs requis, énumérations) —
    elle ne prétend pas détecter l'altération sémantiquement valide d'un blob
    malveillant (limite assumée, pas un trou de CE lot).
    """
    if not isinstance(policy, dict):
        raise ValueError("policy doit être un objet")

    policy_id = policy.get("policy_id")
    if not isinstance(policy_id, str) or not policy_id:
        raise ValueError(f"policy_id invalide : {policy_id!r}")

    for key in ("allowed_tools", "denied_tools", "path_rules"):
        if key not in policy:
            raise ValueError(f"champ requis absent : {key!r}")

    allowed_tools = policy["allowed_tools"]
    denied_tools = policy["denied_tools"]
    path_rules = policy["path_rules"]

    if not isinstance(allowed_tools, list) or not all(isinstance(t, str) for t in allowed_tools):
        raise ValueError("allowed_tools doit être une liste de chaînes")
    if not isinstance(denied_tools, list) or not all(isinstance(t, str) for t in denied_tools):
        raise ValueError("denied_tools doit être une liste de chaînes")
    if not isinstance(path_rules, list):
        raise ValueError("path_rules doit être une liste")

    normalized_rules = []
    for rule in path_rules:
        if not isinstance(rule, dict):
            raise ValueError("chaque path_rule doit être un objet")
        vault_pattern = rule.get("vault_pattern")
        if not isinstance(vault_pattern, str) or not vault_pattern:
            raise ValueError(f"vault_pattern invalide (chaîne non vide requise) : {vault_pattern!r}")
        if "permissions" in rule:
            permissions = rule["permissions"]
            # isinstance(p, str) AVANT le test d'appartenance : un élément non
            # hachable (ex. `permissions: [["read"]]`) ferait lever TypeError par
            # `in _VALID_PERMISSIONS` sans le court-circuit — bug round 1 diff review.
            if (not isinstance(permissions, list) or not permissions
                    or not all(isinstance(p, str) and p in _VALID_PERMISSIONS for p in permissions)):
                raise ValueError(f"permissions invalides dans path_rule : {permissions!r}")
            permissions = list(permissions)
        else:
            # Champ absent : normalisation EXPLICITE au moins permissif — JAMAIS
            # un défaut admin/write (bug historique de is_path_allowed(), corrigé
            # par cette validation centralisée, issue #86 Lot 3).
            permissions = ["read"]
        allowed_paths = rule.get("allowed_paths", [])
        if not isinstance(allowed_paths, list) or not all(isinstance(p, str) for p in allowed_paths):
            raise ValueError(f"allowed_paths invalide (liste de chaînes attendue) : {allowed_paths!r}")
        normalized_rules.append({
            "vault_pattern": vault_pattern,
            "permissions": permissions,
            "allowed_paths": list(allowed_paths),
        })

    return {
        "policy_id": policy_id,
        "description": policy.get("description", ""),
        "allowed_tools": list(allowed_tools),
        "denied_tools": list(denied_tools),
        "path_rules": normalized_rules,
        "created_at": policy.get("created_at", ""),
        "created_by": policy.get("created_by", ""),
    }


# =============================================================================
# PolicyStore — Stockage S3 + cache mémoire TTL
# =============================================================================

class PolicyStore:
    """
    Gestion des policies MCP.

    - Stockage sur S3 : _system/policies.json
    - Cache mémoire avec TTL de 5 minutes (re-tentative accélérée à 10s si invalide)
    - État observable : available / last_error (issue #86 Lot 3)
    - CRUD : create, list, get, delete
    - Matching : wildcards sur tool names et vault patterns
    """

    CACHE_TTL = 300  # 5 minutes
    S3_KEY = "_system/policies.json"

    def __init__(self, settings):
        self.settings = settings
        self._policies: dict = {}  # policy_id → policy_info
        self._cache_time: float = 0.0
        self._available: bool = True
        self._last_error: str = ""

    # ── État observable (issue #86 Lot 3) ─────────────────────────────
    @property
    def available(self) -> bool:
        return self._available

    @property
    def last_error(self) -> str:
        return self._last_error

    def _get_s3_data(self):
        """Client S3 SigV2 pour PUT/GET/DELETE (données)."""
        from ..s3_client import get_s3_data_client
        return get_s3_data_client()

    @staticmethod
    def _is_missing_key_error(e: Exception) -> bool:
        """True UNIQUEMENT pour l'absence nominale de l'objet policies.json (NoSuchKey).

        Ne se fie JAMAIS à une sous-chaîne "404"/"NoSuchKey" dans str(e) — un port ou
        un request-id contenant ces motifs ferait passer une panne pour un fichier
        absent. Seul botocore ClientError.response["Error"]["Code"] == "NoSuchKey" est
        nominal (1er démarrage) ; tout le reste (NoSuchBucket, 403, timeout, endpoint
        cassé...) est une VRAIE panne → fail-close (même logique que MissionBindingStore).
        """
        try:
            from botocore.exceptions import ClientError
        except ImportError:
            return False  # sans botocore, toute erreur = indisponible (fail-close)
        if not isinstance(e, ClientError):
            return False
        resp = getattr(e, "response", {}) or {}
        return resp.get("Error", {}).get("Code", "") == "NoSuchKey"

    def _mark_invalid(self, msg: str):
        """Passe le store en état INDISPONIBLE observable (sans écraser le cache mémoire)."""
        self._available = False
        self._last_error = msg
        self._cache_time = time.time()  # throttle la re-tentative (_maybe_refresh)
        logger.error(
            "Policy Store INVALIDE : %s — décisions de policy refusées jusqu'à "
            "rétablissement (aucune policy périmée servie)", msg,
        )

    def load(self):
        """Charge les policies depuis S3 avec validation atomique (défense en profondeur).

        - Objet absent (NoSuchKey)              → store VIDE mais writable — nominal (1er boot).
        - Réseau/403/timeout/bucket absent       → INVALID, cache conservé, PAS d'écrasement.
        - JSON corrompu / schéma top-level cassé → INVALID (top-level doit être
          exactement {"policies": [...]} — un objet sans cette clé, ou {} tout court,
          n'est PAS traité comme un store vide : seul NoSuchKey l'est).
        - policy_id dupliqué dans le JSON source → INVALID (jamais un écrasement
          silencieux — la compréhension dict naïve masquerait le doublon).
        - UNE SEULE policy non conforme (schéma/permissions/types)
          → INVALID : on ne sert JAMAIS une policy qui n'a pas passé la validation
          stricte (anti élévation de privilège via fichier forgé/corrompu).
        """
        try:
            s3 = self._get_s3_data()
            resp = s3.get_object(Bucket=self.settings.s3_bucket_name, Key=self.S3_KEY)
            raw = resp["Body"].read().decode()
        except Exception as e:
            if self._is_missing_key_error(e):
                self._policies = {}
                self._cache_time = time.time()
                self._available = True
                self._last_error = ""
                return
            self._mark_invalid(f"S3 GET: {type(e).__name__}")
            return

        try:
            data = json.loads(raw)
        except ValueError:
            self._mark_invalid("JSON invalide")
            return

        if not isinstance(data, dict) or not isinstance(data.get("policies"), list):
            self._mark_invalid("schéma top-level invalide (attendu {'policies': [...]})")
            return

        validated: dict = {}
        for p in data["policies"]:
            try:
                norm = _validate_and_normalize_policy(p)
            except ValueError as e:
                pid = p.get("policy_id") if isinstance(p, dict) else None
                self._mark_invalid(f"policy {pid!r} non conforme: {e}")
                return
            if norm["policy_id"] in validated:
                self._mark_invalid(f"policy_id dupliqué: {norm['policy_id']!r}")
                return
            validated[norm["policy_id"]] = norm

        self._policies = validated
        self._cache_time = time.time()
        self._available = True
        self._last_error = ""

    def _save(self) -> bool:
        """
        Sauvegarde les policies sur S3 (PUT = SigV2).
        Retourne True si succès, False si échec (les appelants DOIVENT rollback
        l'état mémoire si False).

        Distingue la sérialisation locale (bug de code — ne marque PAS le store
        invalide) d'un échec RÉEL du PUT S3 (preuve d'indisponibilité — marque le
        store invalide, cf. _mark_invalid).

        LIMITATION V1 — last-write-wins (issue #13/#51) : pas d'ETag/CAS. Ce lot
        (#86 finding 3) ferme le fail-open sur panne/corruption DÉTECTÉE, PAS
        cette race structurelle (acceptable V1 single-instance, cf. docstring
        module — même compromis déjà assumé pour TokenStore).
        """
        try:
            data = json.dumps(
                {"policies": list(self._policies.values())},
                indent=2, default=str,
            )
        except (TypeError, ValueError) as e:
            logger.error("Policy Store sérialisation locale FAILED: %s (bug, pas une panne S3)", type(e).__name__)
            return False
        try:
            s3 = self._get_s3_data()
            s3.put_object(
                Bucket=self.settings.s3_bucket_name,
                Key=self.S3_KEY,
                Body=data.encode(),
                ContentType="application/json",
            )
            return True
        except Exception as e:
            logger.error(
                "Policy Store S3 save FAILED: %s — état mémoire non persisté, "
                "store marqué INDISPONIBLE", type(e).__name__,
            )
            self._mark_invalid(f"S3 PUT: {type(e).__name__}")
            return False

    def _maybe_refresh(self):
        """Rafraîchit le cache si le TTL est dépassé (ou plus vite si état invalide)."""
        elapsed = time.time() - self._cache_time
        if self._available:
            if elapsed > self.CACHE_TTL:
                self.load()
        else:
            if elapsed > _RETRY_AFTER_ERROR_SECONDS:
                self.load()

    def _ensure_available(self):
        """Rafraîchit puis lève si le store est indisponible (lectures/décisions).

        Raises:
            PolicyStoreUnavailable si le store est indisponible.
        """
        self._maybe_refresh()
        if not self._available:
            raise PolicyStoreUnavailable(self._last_error or "store indisponible")

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
            Policy créée, ou erreur (`error_type: "policy_store_unavailable"` si le
            store est indisponible — refus AVANT toute écriture, ou échec du PUT).
        """
        self._maybe_refresh()
        if not self._available:
            return {"status": "error", "error_type": "policy_store_unavailable",
                    "message": f"Policy Store indisponible ({self._last_error})"}

        # ── Validation ──
        if not policy_id or not policy_id.replace("-", "").replace("_", "").isalnum():
            return {"status": "error", "message": "policy_id invalide (alphanum, tirets, underscores)"}

        if len(policy_id) > 64:
            return {"status": "error", "message": "policy_id trop long (max 64 caractères)"}

        if policy_id in self._policies:
            return {"status": "error", "message": f"Policy '{policy_id}' existe déjà"}

        now = datetime.now(timezone.utc).isoformat()
        # `is None` STRICT (round 1 diff review) — jamais `x or []` : une valeur
        # falsy invalide (ex. allowed_tools=False au lieu d'une liste/None) serait
        # sinon silencieusement blanchie en [] AVANT validation, créant une policy
        # "tout autorisé" au lieu d'être rejetée par _validate_and_normalize_policy.
        draft = {
            "policy_id": policy_id,
            "description": description,
            "allowed_tools": [] if allowed_tools is None else allowed_tools,
            "denied_tools": [] if denied_tools is None else denied_tools,
            "path_rules": [] if path_rules is None else path_rules,
            "created_at": now,
            "created_by": created_by,
        }
        try:
            policy = _validate_and_normalize_policy(draft)
        except ValueError as e:
            return {"status": "error", "message": str(e)}

        self._policies[policy_id] = policy
        if not self._save():
            del self._policies[policy_id]  # rollback mémoire
            return {"status": "error", "error_type": "policy_store_unavailable",
                    "message": "Impossible de créer la policy (S3 indisponible)"}

        return {"status": "created", **policy}

    def get(self, policy_id: str) -> Optional[dict]:
        """Récupère une policy par son ID.

        Raises:
            PolicyStoreUnavailable si le store est indisponible (panne/corruption
            détectée après TTL) — issue #86 Lot 3.
        """
        self._ensure_available()
        return self._policies.get(policy_id)

    def list_all(self) -> list:
        """Liste toutes les policies.

        Raises:
            PolicyStoreUnavailable si le store est indisponible.
        """
        self._ensure_available()
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

    def delete(self, policy_id: str):
        """
        Supprime une policy par son ID.

        Retourne :
          True                       — supprimée avec succès
          False                      — policy introuvable
          "storage_error"            — échec du PUT PENDANT cette suppression
                                        (rollback effectué, policy toujours présente)
          "policy_store_unavailable" — store DÉJÀ indisponible, aucune écriture tentée
        """
        self._maybe_refresh()
        if not self._available:
            return "policy_store_unavailable"
        if policy_id not in self._policies:
            return False
        policy_backup = self._policies.pop(policy_id)
        if not self._save():
            self._policies[policy_id] = policy_backup  # rollback
            logger.error("Suppression policy '%s' non persistée — S3 indisponible", policy_id)
            return "storage_error"
        return True

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

        Raises:
            PolicyStoreUnavailable si le store est indisponible (panne/corruption
            détectée après TTL) — le PEP doit refuser de façon observable, jamais
            servir une décision basée sur un cache périmé (issue #86 Lot 3).
        """
        self._ensure_available()
        policy = self._policies.get(policy_id)
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

        Aucun appelant applicatif connu aujourd'hui (conservée pour compatibilité
        documentaire — issue #86 Lot 3 round 4 : la supprimer n'apporterait
        aucune sécurité et ajouterait du bruit de diff/doc).

        Returns:
            Liste de permissions (ex: ["read", "write"]) ou [] si aucune règle

        Raises:
            PolicyStoreUnavailable si le store est indisponible (propagée par
            l'appel interne à get()).
        """
        policy = self.get(policy_id)
        if not policy:
            return []

        for rule in policy.get("path_rules", []):
            if fnmatch.fnmatch(vault_id, rule["vault_pattern"]):
                return rule.get("permissions", ["read"])

        return []  # Aucune règle applicable

    def is_path_allowed(self, policy_id: str, vault_id: str, path: str,
                         required_permission: str = "read") -> bool:
        """
        Vérifie si un chemin de secret est autorisé dans un vault selon les path_rules.

        Logique :
        1. Pas de policy → REFUSÉ (fail-close, cohérent avec is_tool_allowed())
        2. Pas de path_rule matchant le vault → autorisé (pas de restriction path)
        3. path_rule matchante → le chemin ET la permission doivent être autorisés :
           a. La permission requise doit être dans rule["permissions"]
              ("write" couvre delete ; "admin" couvre tout)
           b. Si allowed_paths non vide → le path doit matcher au moins un pattern

        Les patterns supportent les wildcards (* via fnmatch).

        Args:
            policy_id: ID de la policy
            vault_id: ID du vault
            path: Chemin du secret (ex: "web/github", "db/postgres")
            required_permission: Opération demandée : "read", "write" (couvre delete), "admin"

        Returns:
            True si le chemin et la permission sont autorisés

        Raises:
            PolicyStoreUnavailable si le store est indisponible (idem is_tool_allowed).
        """
        self._ensure_available()
        policy = self._policies.get(policy_id)
        if not policy:
            return False  # SÉCURITÉ V2-02 : fail-close cohérent avec is_tool_allowed()

        # Chercher la première path_rule qui matche le vault
        for rule in policy.get("path_rules", []):
            if fnmatch.fnmatch(vault_id, rule["vault_pattern"]):
                # Toute policy en cache est passée par _validate_and_normalize_policy :
                # "permissions" y est TOUJOURS présent (normalisé à ["read"] si absent
                # à la source). Défaut défensif à ["read"] SEUL ici — JAMAIS
                # admin/write (bug historique corrigé, issue #86 Lot 3).
                rule_perms = set(rule.get("permissions", ["read"]))
                if required_permission == "admin":
                    perm_ok = "admin" in rule_perms
                elif required_permission == "write":
                    perm_ok = bool(rule_perms & {"write", "admin"})
                else:  # "read"
                    perm_ok = bool(rule_perms & {"read", "write", "admin"})
                if not perm_ok:
                    return False

                # Vérifier si le path matche un pattern autorisé
                allowed_paths = rule.get("allowed_paths", [])
                if not allowed_paths:
                    return True  # Pas de restriction path dans cette règle
                return any(fnmatch.fnmatch(path, p) for p in allowed_paths)

        return True  # Aucune règle vault matchante = pas de restriction path
