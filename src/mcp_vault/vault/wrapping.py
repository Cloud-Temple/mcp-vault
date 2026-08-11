# -*- coding: utf-8 -*-
"""
JIT Wrap Broker — Response wrapping single-use pour mcp-mission.

Expose un contrat VaultClient pour le CredentialBrokerService :
    wrap(vault_id, secret_path, mission_id, operation_id, ttl_seconds) → WrapTokenRef
    revoke(lease_id)           → idempotent (introuvable dans un registre
                                 DISPONIBLE = succès ; registre non initialisé
                                 = error/registry_unavailable, cf. #120)
    lookup_by_operation_id(op) → états : not_found | found_unattached | already_revoked
                                          | revoked | ambiguous | backend_unavailable

Architecture :
- OpenBao response wrapping (cubbyhole single-use) garantit le single-use et le TTL.
- Un WrapRegistry sur S3 (`_system/wrap_registry.json`) corrèle operation_id → accessor
  pour la compensation des provisions orphelines (#74).
- Pattern write-ahead : le registry est écrit en "pending" AVANT l'appel OpenBao,
  puis mis à jour en "active" avec l'accessor après succès. Si crash entre les deux,
  lookup_by_operation_id retourne "found_unattached" (TTL fera expirer le wrap côté Vault).

Invariants de sécurité :
- Le wrap_token (secret) n'est jamais loggué, stocké, ni inclus dans les erreurs.
- Le WrapRegistry ne stocke que l'accessor (non utilisable seul pour unwrap).
- revoke_wrap ne révoque que des accessors présents dans le registry (pas de révocation
  arbitraire de tokens OpenBao hors périmètre broker).
- Les erreurs sont typées et neutres (aucune valeur sensible dans le message).

Limites V1 (documentées) :
- Le WrapRegistry n'utilise pas de CAS/ETag S3 → last-write-wins en cas de deux
  brokers simultanés. Acceptable avec un seul broker en V1 ; nécessite du locking
  distribué (S3 conditional write, Redis, etc.) pour multi-instance.
"""

import json
import logging
import re
import sys
import time
from datetime import datetime, timezone, timedelta
from typing import Optional

from ..vault_ids import is_valid_vault_id

logger = logging.getLogger("mcp-vault.wrapping")

# Chemins réservés non accessibles via wrap (cohérent avec secrets.py RESERVED_PATHS)
_RESERVED_PREFIXES = ("_vault_meta", "_init/", "_system/")

# Validation légère du operation_id / mission_id (anti-injection logs)
_SAFE_ID_RE = re.compile(r'^[a-zA-Z0-9_\-:.]{1,256}$')


def is_safe_id(value) -> bool:
    """Valide STRICTEMENT un identifiant (operation_id, mission_id, accessor/lease_id).

    Validateur centralisé (#78/D6). Utilise fullmatch et NON match : `_SAFE_ID_RE.match("op\\n")`
    renvoyait un match (le `$` autorise un `\\n` final en fin de chaîne), laissant passer une
    injection de saut de ligne dans les logs/audit. fullmatch exige que TOUTE la chaîne soit
    conforme, ce qui ferme la faille. Refuse aussi les non-str (fail-close).
    """
    return isinstance(value, str) and _SAFE_ID_RE.fullmatch(value) is not None

# =============================================================================
# Wrappers lazy — patchables dans les tests sans cascade d'imports
# =============================================================================

def _get_client():
    """Wrapper lazy autour de get_hvac_client."""
    from ..openbao.manager import get_hvac_client
    return get_hvac_client()


def _get_config():
    """Wrapper lazy autour de get_settings."""
    from ..config import get_settings
    return get_settings()


# =============================================================================
# WrapRegistry — Stockage S3 des corrélations operation_id ↔ accessor
# =============================================================================

_wrap_registry: Optional["WrapRegistry"] = None


def get_wrap_registry() -> Optional["WrapRegistry"]:
    """Retourne le WrapRegistry (None si S3 non configuré)."""
    return _wrap_registry


def init_wrap_registry():
    """Initialise le WrapRegistry au démarrage (charge depuis S3 si configuré)."""
    global _wrap_registry
    from ..config import get_settings
    settings = get_settings()
    if settings.s3_endpoint_url and settings.s3_bucket_name:
        _wrap_registry = WrapRegistry(settings)
        _wrap_registry.load()
        print(f"🔐 Wrap Registry initialisé ({_wrap_registry.count()} entrées)", file=sys.stderr)
    else:
        print("🔐 Wrap Registry non configuré (S3 requis)", file=sys.stderr)


class WrapRegistry:
    """
    Registre des wrap tokens provisionnés.

    Pattern write-ahead :
        1. register_pending(op_id, ...) AVANT l'appel OpenBao → status="pending"
        2. mark_active(op_id, accessor)  APRÈS succès OpenBao → status="active"
        3. mark_failed(op_id)            si OpenBao échoue    → status="failed"

    En cas de crash entre 1 et 2 : l'entrée reste en "pending", visible lors du
    lookup → état "found_unattached" (le TTL côté OpenBao fera expirer le wrap).

    Le registry NE stocke JAMAIS le wrap_token lui-même, uniquement l'accessor
    (non utilisable pour unwrap sans le wrap_token).

    Schéma S3 (_system/wrap_registry.json) :
        {
          "wraps": [
            {
              "operation_id": str,
              "accessor": str | null,   # null si status="pending" ou "failed"
              "mission_id": str,
              "vault_id": str,
              "secret_path": str,
              "created_at": ISO,
              "expires_at": ISO,
              "status": "pending" | "active" | "consuming" | "consumed" | "revoked" | "failed",
              "tenant_id": str,         # optionnel — pour binding JWT C18
              "expected_aud": str,      # optionnel — vault_ref anti-confused-deputy
            }, ...
          ]
        }

    Cycle de vie étendu (issue #26) :
        "pending" → "active" → "consuming" → "consumed"
                                            → "revoked" (si révocation explicite)

    Limite V1 : pas de CAS S3 → last-write-wins en cas de deux brokers simultanés.
    """

    CACHE_TTL = 30  # secondes (court pour réduire la fenêtre de race condition)
    S3_KEY = "_system/wrap_registry.json"

    def __init__(self, settings):
        self.settings = settings
        self._wraps: list[dict] = []
        self._cache_time: float = 0
        # #77 : True tant que le dernier load() a abouti (succès ou 404 = vide connu) ;
        # False si un load() a échoué sur une panne S3 effective. Sert à la
        # consultation d'état (status_by_operation_id) pour ne pas présenter un
        # instantané périmé comme fiable. Additif — n'affecte pas le flux broker.
        self._last_load_ok: bool = True

    def _get_s3_data(self):
        from ..s3_client import get_s3_data_client
        return get_s3_data_client()

    def load(self):
        try:
            s3 = self._get_s3_data()
            resp = s3.get_object(Bucket=self.settings.s3_bucket_name, Key=self.S3_KEY)
            data = json.loads(resp["Body"].read().decode())
            self._wraps = data.get("wraps", [])
            self._cache_time = time.time()
            self._last_load_ok = True
        except Exception as e:
            if "NoSuchKey" in str(e) or "404" in str(e):
                self._wraps = []
                self._cache_time = time.time()
                self._last_load_ok = True  # absence de fichier = registre vide connu
            else:
                # #77 : panne S3 effective — le cache n'est PAS rafraîchi. On le
                # signale pour que la consultation d'état (status) ne masque pas
                # l'indisponibilité en renvoyant un not_found/active trompeur.
                self._last_load_ok = False
                logger.warning("WrapRegistry S3 load: %s", type(e).__name__)

    def _save(self) -> bool:
        """
        Sauvegarde sur S3. Retourne True si succès, False si S3 indisponible.

        NOTE V1 : last-write-wins — sérialise l'état mémoire courant sans rechargement
        préalable. Un rechargement ici écraserait la mutation juste ajoutée (bug
        critique de write-ahead). Le vrai fix multi-instance nécessite un CAS/ETag
        S3 ou du locking distribué, reporté post-V1.
        """
        try:
            s3 = self._get_s3_data()
            data = json.dumps({"wraps": self._wraps}, indent=2, default=str)
            s3.put_object(
                Bucket=self.settings.s3_bucket_name,
                Key=self.S3_KEY,
                Body=data.encode(),
                ContentType="application/json",
            )
            self._cache_time = time.time()  # invalide le cache après write
            # #77 : un save réussi prouve que S3 est joignable et que le cache mémoire
            # est persisté — on lève un éventuel _last_load_ok=False laissé par une
            # panne S3 antérieure (sinon la consultation d'état resterait bloquée en
            # backend_unavailable après reprise de S3).
            self._last_load_ok = True
            return True
        except Exception as e:
            logger.error("WrapRegistry S3 save FAILED: %s — compensation indisponible", type(e).__name__)
            return False

    def _maybe_refresh(self):
        if time.time() - self._cache_time > self.CACHE_TTL:
            self.load()

    # ── Write-ahead methods ──────────────────────────────────────────

    def register_pending(self, operation_id: str, mission_id: str,
                         vault_id: str, secret_path: str, ttl_seconds: int,
                         tenant_id: str = "", expected_aud: str = "") -> bool:
        """
        Enregistre une intention de wrap AVANT l'appel OpenBao (status="pending").

        tenant_id et expected_aud sont optionnels — utilisés pour le binding JWT (issue #26).
        Retourne True si persisté sur S3, False si S3 indisponible (erreur à remonter).
        """
        self._maybe_refresh()
        now = datetime.now(timezone.utc)
        entry = {
            "operation_id": operation_id,
            "accessor": None,   # inconnu avant l'appel OpenBao
            "mission_id": mission_id,
            "vault_id": vault_id,
            "secret_path": secret_path,
            "created_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=ttl_seconds)).isoformat(),
            "status": "pending",
            "tenant_id": tenant_id,
            "expected_aud": expected_aud,
        }
        self._wraps.append(entry)
        if not self._save():
            self._wraps.pop()  # rollback mémoire — évite les entrées fantômes
            return False
        return True

    def mark_active(self, operation_id: str, accessor: str) -> bool:
        """
        Met à jour la dernière entrée "pending" de cet operation_id vers "active"
        avec l'accessor reçu d'OpenBao après un wrap réussi.
        """
        self._maybe_refresh()
        for entry in reversed(self._wraps):
            if entry["operation_id"] == operation_id and entry["status"] == "pending":
                entry["accessor"] = accessor
                entry["status"] = "active"
                break
        return self._save()

    def mark_failed(self, operation_id: str) -> None:
        """Marque la dernière entrée "pending" comme "failed" (OpenBao a échoué)."""
        self._maybe_refresh()
        for entry in reversed(self._wraps):
            if entry["operation_id"] == operation_id and entry["status"] == "pending":
                entry["status"] = "failed"
                break
        self._save()

    def mark_revoked(self, accessor: str) -> bool:
        """Marque les entrées portant cet accessor comme "revoked". Retourne True si trouvé."""
        self._maybe_refresh()
        found = False
        for entry in self._wraps:
            if entry.get("accessor") == accessor and entry["status"] in ("active", "pending"):
                entry["status"] = "revoked"
                found = True
        if found:
            self._save()
        return found

    def mark_entries_revoked(self, entries: list) -> bool:
        """
        Marque comme "revoked" UNIQUEMENT les entrées passées (références vivantes
        de _wraps) puis persiste. Retourne True si au moins une entrée a mué.

        SÉCURITÉ #115 : contrairement à mark_revoked(accessor) qui mute TOUTES
        les entrées d'un accessor (y compris une entrée hors du périmètre de
        l'appelant en cas de registre dupliqué/incohérent), cette méthode ne
        touche que la sélection déjà filtrée par visibilité. AUCUN
        _maybe_refresh ici : un rechargement remplacerait _wraps et détacherait
        les références passées — la mutation serait perdue silencieusement. Le
        refresh a lieu UNE fois en tête de primitive, avant la sélection.
        """
        found = False
        for entry in entries:
            if isinstance(entry, dict) and entry.get("status") in ("active", "pending"):
                entry["status"] = "revoked"
                found = True
        if found:
            self._save()
        return found

    def has_accessor(self, accessor: str) -> bool:
        """Vérifie que l'accessor appartient à un wrap géré par ce registry."""
        self._maybe_refresh()
        return any(e.get("accessor") == accessor for e in self._wraps)

    def find_by_operation_id(self, operation_id: str) -> list[dict]:
        """Retourne toutes les entrées correspondant à un operation_id."""
        self._maybe_refresh()
        return [e for e in self._wraps if e["operation_id"] == operation_id]

    # ── Méthodes issue #26 (JWT binding + anti-replay) ──────────────

    def get_by_composite_key(self, operation_id: str, mission_id: str) -> Optional[dict]:
        """
        Lookup par (operation_id, mission_id) — clé composite anti-collision.

        Retourne l'entrée "active" ou "consuming" si trouvée.
        Retourne None si introuvable ou déjà consumed/revoked.

        Si plusieurs entrées correspondent (anomalie), retourne None (ambiguité → erreur).
        """
        self._maybe_refresh()
        candidates = [
            e for e in self._wraps
            if e["operation_id"] == operation_id
            and e["mission_id"] == mission_id
            and e["status"] in ("active", "consuming")
        ]
        if len(candidates) == 1:
            return candidates[0]
        if len(candidates) > 1:
            logger.warning(
                # %r : op/mission peuvent venir d'une entrée S3 historique (fins de ligne)
                # ou d'un mission_id de claim non validé (#78) — repr échappe les contrôles.
                "⚠️ WrapRegistry : %d entrées (op=%r, mission=%r) — ambiguïté",
                len(candidates), operation_id[:16], mission_id[:16],
            )
            return None
        return None

    def try_mark_consuming(self, operation_id: str, mission_id: str) -> bool:
        """
        Tente de passer l'entrée (op_id, mission_id) de "active" → "consuming".

        Pattern atomic compare-and-swap (best-effort S3 V1) :
            - Si status != "active" : return False (déjà consumed/raced)
            - Set status = "consuming"
            - Persisté sur S3 : return True
            - Si S3 fail : rollback → return False

        Le vrai backstop contre le double-consume est OpenBao single-use (le
        wrap_token ne peut être consommé qu'une fois côté OpenBao).
        """
        self._maybe_refresh()
        for entry in self._wraps:
            if (entry["operation_id"] == operation_id
                    and entry["mission_id"] == mission_id
                    and entry["status"] == "active"):
                entry["status"] = "consuming"
                if self._save():
                    return True
                # Rollback si S3 fail
                entry["status"] = "active"
                return False
        return False

    def mark_consumed(self, operation_id: str, mission_id: str) -> bool:
        """
        Finalise la consommation : "consuming" → "consumed".
        Appelé APRÈS succès de l'unwrap OpenBao.
        """
        for entry in self._wraps:
            if (entry["operation_id"] == operation_id
                    and entry["mission_id"] == mission_id
                    and entry["status"] == "consuming"):
                entry["status"] = "consumed"
                return self._save()
        return False

    def rollback_consuming(self, operation_id: str, mission_id: str) -> bool:
        """
        Rollback : "consuming" → "active" si l'unwrap OpenBao a échoué.
        Retourne True si S3 OK, False si S3 fail (état mémoire corrigé,
        S3 garde "consuming" jusqu'au prochain rechargement/timeout).
        """
        for entry in self._wraps:
            if (entry["operation_id"] == operation_id
                    and entry["mission_id"] == mission_id
                    and entry["status"] == "consuming"):
                entry["status"] = "active"
                ok = self._save()
                if not ok:
                    logger.warning(
                        "⚠️ rollback_consuming S3 fail (op=%r) — "
                        "état mémoire: active, S3: stale-consuming",
                        operation_id[:16],
                    )
                return ok
        return False

    def count(self) -> int:
        return len(self._wraps)


# =============================================================================
# Validation des inputs
# =============================================================================

def _validate_inputs(vault_id: str, secret_path: str,
                     mission_id: str, operation_id: str) -> Optional[str]:
    """
    Valide vault_id, secret_path, mission_id, operation_id.
    Retourne un message d'erreur si invalide, None si OK.
    La validation de secret_path est propre à cette fonction (indépendante de
    _validate_secret_path() dans secrets.py, pour ne pas coupler le chemin
    critique wrap au listing admin) ; elle réutilise la liste de préfixes
    réservés via _is_reserved_path.
    """
    # vault_id : source unique mcp_vault.vault_ids (découverte revue round 2
    # du fix critique isolation owner-based, 2026-07-23 : cette regex locale
    # divergeait de la canonique — plus stricte sur les underscores/tiret
    # final, sans ouvrir de bypass ici puisque secret_wrap passe déjà par
    # check_access() en amont, mais source de dérive future).
    if not is_valid_vault_id(vault_id):
        return "vault_id invalide (alphanum + tirets/underscores, 1-64 chars)"

    # secret_path : validation locale (proche de secrets.py _validate_secret_path
    # mais indépendante — le chemin critique wrap n'est pas couplé au listing admin).
    # Regex : alphanum + / _ . - uniquement, commence par alphanum
    _PATH_RE = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9/_.\-]{0,255}')
    if not isinstance(secret_path, str) or not secret_path:
        return "secret_path requis"
    # #78 : fullmatch + message SANS echo de la valeur brute (anti-reflection dans le
    # message renvoyé au client et versé à l'audit).
    if ".." in secret_path or "\\" in secret_path or not _PATH_RE.fullmatch(secret_path):
        return "secret_path invalide (caractères autorisés : alphanum / _ . -)"
    for prefix in _RESERVED_PREFIXES:
        if secret_path.startswith(prefix):
            return f"secret_path '{secret_path}' est un chemin réservé"
    # Vérification supplémentaire via secrets.py si disponible
    try:
        from .secrets import _is_reserved_path
        if _is_reserved_path(secret_path):
            return f"secret_path '{secret_path}' est un chemin réservé"
    except ImportError:
        pass

    # mission_id / operation_id : anti-injection logs
    if not is_safe_id(mission_id):
        return "mission_id invalide (alphanum + _-:., 1-256 chars)"
    if not is_safe_id(operation_id):
        return "operation_id invalide (alphanum + _-:., 1-256 chars)"

    return None


# =============================================================================
# Fonctions core wrap / revoke / lookup
# =============================================================================

async def wrap_secret(
    vault_id: str,
    secret_path: str,
    mission_id: str,
    operation_id: str,
    ttl_seconds: int = 300,
    tenant_id: str = "",
    expected_aud: str = "",
) -> dict:
    """
    Crée un wrap token single-use pour (vault_id, secret_path) scopé à la mission.

    Pattern write-ahead :
        1. Enregistre "pending" dans le registry AVANT d'appeler OpenBao.
        2. Appelle OpenBao avec l'API bas niveau (wrap_ttl header).
        3. Met à jour "pending" → "active" avec l'accessor.
    En cas de crash entre 2 et 3 : l'entrée reste "pending" (found_unattached lors
    du lookup) et le TTL OpenBao fera expirer le wrap automatiquement.

    Le wrap_token retourné ne doit jamais être loggué côté broker.

    Returns:
        {status: "ok", wrap_token (SENSIBLE), secret_id, accessor, vault_url, expires_at, intended_use}
    """
    # ── Validation des inputs ────────────────────────────────────────
    err = _validate_inputs(vault_id, secret_path, mission_id, operation_id)
    if err:
        return {"status": "error", "error_type": "invalid_input", "message": err}

    # ── Vérifier la disponibilité OpenBao ────────────────────────────
    client = _get_client()
    if not client:
        return {"status": "error", "error_type": "backend_unavailable",
                "message": "OpenBao non disponible"}

    settings = _get_config()

    # ── Write-ahead : persister l'intention AVANT l'appel OpenBao ───
    registry = get_wrap_registry()
    # Registry REQUIS : sans lui la compensation (#74) est impossible → fail-close
    if registry is None:
        return {"status": "error", "error_type": "registry_unavailable",
                "message": "Registre de compensation non configuré (S3 requis)"}
    if not registry.register_pending(operation_id, mission_id, vault_id, secret_path, ttl_seconds,
                                     tenant_id=tenant_id, expected_aud=expected_aud):
        # S3 indisponible → compensation impossible → refuser le wrap
        return {"status": "error", "error_type": "registry_unavailable",
                "message": "Registre de compensation indisponible — wrap refusé pour intégrité"}

    # ── Appeler OpenBao : API bas niveau (wrap_ttl passé en header) ──
    # KV v2 : le chemin de données est "{mount_point}/data/{path}"
    kv_data_path = f"{vault_id}/data/{secret_path}"
    try:
        response = client.read(kv_data_path, wrap_ttl=f"{ttl_seconds}s")
    except Exception as e:
        logger.warning("wrap_secret error for vault=%s path_len=%d: %s",
                       vault_id, len(secret_path), type(e).__name__)
        # Marquer le pending comme failed (pas d'accessor à révoquer)
        if registry:
            registry.mark_failed(operation_id)
        err_type = "not_found" if any(k in str(e) for k in ("404", "Not Found", "No value")) \
                   else "backend_error"
        return {"status": "error", "error_type": err_type,
                "message": "Impossible de créer le wrap token (voir logs serveur)"}

    wrap_info = response.get("wrap_info") if isinstance(response, dict) else None
    if not wrap_info:
        logger.warning("wrap_secret: réponse sans wrap_info pour vault=%s", vault_id)
        if registry:
            registry.mark_failed(operation_id)
        return {"status": "error", "error_type": "backend_error",
                "message": "Réponse wrap inattendue (voir logs serveur)"}

    wrap_token = wrap_info.get("token", "")
    accessor = wrap_info.get("accessor", "")

    if not wrap_token or not accessor:
        if registry:
            registry.mark_failed(operation_id)
        return {"status": "error", "error_type": "backend_error",
                "message": "wrap_info incomplet (voir logs serveur)"}

    # ── Mettre à jour "pending" → "active" avec l'accessor ──────────
    if not registry.mark_active(operation_id, accessor):
        # S3 indisponible au passage active : le wrap_token existe côté OpenBao
        # mais n'est pas corrélé → révoquer immédiatement pour éviter une provision
        # non compensable, et retourner une erreur au broker.
        logger.error("wrap_secret: mark_active S3 failed pour op=%r — révocation immédiate",
                     operation_id[:32])
        try:
            client.auth.token.revoke_accessor(accessor=accessor)
        except Exception as rev_e:
            logger.error("wrap_secret: révocation d'urgence échouée: %s — "
                         "wrap token orphelin possible (TTL=%ss)", type(rev_e).__name__, ttl_seconds)
        return {"status": "error", "error_type": "registry_unavailable",
                "message": "Wrap créé mais non persisté — révoqué pour intégrité"}

    expires_at_dt = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)

    return {
        "status": "ok",
        "wrap_token": wrap_token,                        # SENSIBLE — ne jamais logger
        "secret_id": f"{mission_id}:{accessor[:12]}",   # opaque, agent-facing
        "accessor": accessor,                            # lease_id pour revoke
        "vault_url": settings.openbao_addr,
        "expires_at": expires_at_dt.isoformat(),
        "intended_use": _infer_intended_use(secret_path),
        "operation_id": operation_id,
        "mission_id": mission_id,
    }


# ── Sélection défensive & visibilité du registre (issue #115) ────────────────
# Les trois primitives revoke/lookup/status travaillent sur une sélection
# UNIQUE, défensive (une entrée malformée n'est jamais lue par clé sans garde)
# et filtrée par l'identité courante (un token wrap ne voit que les entrées de
# son périmètre vault+chemins). Garde placée DANS la primitive (pattern
# anti-contournement du projet) — un futur point d'entrée ne peut pas
# réintroduire le bypass.

def _entry_well_formed(entry) -> bool:
    """Entrée de registre structurellement exploitable (types stricts)."""
    return (
        isinstance(entry, dict)
        and isinstance(entry.get("operation_id"), str)
        and isinstance(entry.get("vault_id"), str)
        and isinstance(entry.get("secret_path"), str)
        and isinstance(entry.get("status"), str)
        and (entry.get("accessor") is None or isinstance(entry.get("accessor"), str))
    )


def _select_wrap_entries(wraps, *, accessor: str = None,
                         operation_id: str = None) -> tuple:
    """
    Sélection défensive : retourne (entrées_valides_matchantes, saw_malformed).

    N'accède JAMAIS à une clé d'entrée sans garde de type. saw_malformed
    signale une entrée inexploitable N'IMPORTE OÙ dans le registre (miroir du
    comportement historique : l'itération complète de find_by_operation_id
    levait sur toute entrée malformée, matchante ou non) — consommé par
    status_by_operation_id pour préserver `registry_inconsistent` côté admin.
    """
    valid, saw_malformed = [], False
    for entry in wraps or []:
        if not _entry_well_formed(entry):
            saw_malformed = True
            continue
        if accessor is not None and entry.get("accessor") != accessor:
            continue
        if operation_id is not None and entry.get("operation_id") != operation_id:
            continue
        valid.append(entry)
    return valid, saw_malformed


def _caller_is_admin() -> bool:
    """Identité courante admin ? token absent → False (JAMAIS traité admin)."""
    from ..auth.context import current_token_info
    token_info = current_token_info.get()
    if not isinstance(token_info, dict):
        return False
    perms = token_info.get("permissions", [])
    return isinstance(perms, list) and "admin" in perms


def _visible_entries(entries: list) -> list:
    """
    Filtre d'autorisation par entrée pour l'identité courante (issue #115).

    - admin → toutes les entrées (comportement historique inchangé) ;
    - toute autre identité (y compris contexte ABSENT — fail-close, None n'est
      jamais admin) : l'entrée n'est visible que si check_access(vault_id)
      passe ET si le chemin passe l'évaluation STRICTE de policy
      (check_wrap_path_policy — symétrie avec la création : ce qu'un token ne
      peut pas wrapper, il ne peut ni le voir ni le révoquer).
    Les entrées hors scope sont présentées comme ABSENTES (not_found en aval),
    pas comme refusées : aucune fuite d'existence inter-tenant.
    """
    if _caller_is_admin():
        return list(entries)
    from ..auth.context import check_access, check_wrap_path_policy
    visible = []
    for entry in entries:
        if check_access(entry["vault_id"]) is not None:
            continue
        # audit=False : une entrée hors scope est un cas nominal du filtrage,
        # pas un refus d'opération — ne pas générer de faux événements denied.
        if check_wrap_path_policy(entry["vault_id"], entry["secret_path"],
                                  audit=False) is not None:
            continue
        visible.append(entry)
    return visible


async def revoke_wrap(lease_id: str) -> dict:
    """
    Révoque un wrap token de façon IDEMPOTENTE.

    lease_id = accessor du wrap token.
    - Introuvable DANS UN REGISTRE DISPONIBLE → "not_found" (OK, idempotent).
    - Registre non initialisé (S3 absent) → status="error",
      error_type="registry_unavailable" : aucune révocation n'a été tentée,
      l'appelant ne doit PAS créditer un succès (#120).
    - Déjà révoqué → "already_revoked" (OK, idempotent).
    - OpenBao dit "bad accessor" / "404" → idempotent (+ mise à jour registry).
    - Erreur réseau / 5xx → erreur réelle (broker doit retenter).

    Sécurité : ne révoque QUE des accessors présents dans le registry géré par
    ce broker (empêche la révocation arbitraire de tokens OpenBao hors scope).

    Returns:
        {status: "ok", state: "revoked" | "already_revoked" | "not_found"}
        ou {status: "error", error_type: "registry_unavailable" | "backend_unavailable"
        | "backend_error"} — aucune révocation tentée/confirmée dans ces cas.
    """
    registry = get_wrap_registry()

    # ── Fail-close si registry NON INITIALISÉ : erreur CONTRACTUELLE (#120) ──
    # Sans registre, on ne peut pas vérifier que l'accessor appartient au broker
    # → on ne touche pas à OpenBao. Mais ce cas ne doit PAS se présenter comme
    # `ok/not_found` : le contrat documente « introuvable = succès idempotent »,
    # donc un client (broker mcp-mission, leur #507) créditait une révocation
    # qui n'a jamais été TENTÉE. La `note` n'est pas contractuelle et ne doit
    # pas servir à désambiguïser. `registry_unavailable` est la même erreur que
    # celle déjà renvoyée par wrap_secret/consume_wrap_secret dans ce cas.
    if registry is None:
        return {"status": "error", "error_type": "registry_unavailable",
                "message": "Registre des wraps non initialisé (S3 requis) — "
                           "révocation impossible sans vérification de périmètre"}

    # ── Sélection défensive + visibilité (issue #115) ────────────────
    # UN SEUL refresh en tête, puis toutes les décisions, l'appel OpenBao ET
    # les mutations portent sur cette sélection : entrée malformée jamais lue
    # par clé, entrée hors du périmètre de l'appelant traitée comme ABSENTE,
    # et jamais mutée même si elle partage l'accessor d'une entrée visible.
    registry._maybe_refresh()
    # FAIL-CLOSE (revue pré-commit #115) : si le refresh S3 a échoué, le cache
    # est un instantané AMBIGU — aucune décision destructive (revoke OpenBao,
    # _save last-write-wins qui écraserait un état S3 plus récent) ne doit être
    # prise dessus. Le broker retente (contrat : erreur réseau = erreur réelle).
    if getattr(registry, "_last_load_ok", True) is False:
        return {"status": "error", "error_type": "backend_unavailable",
                "message": "Registre non rafraîchi (S3 injoignable) — révocation refusée (réessayer)"}
    entries, _ = _select_wrap_entries(registry._wraps, accessor=lease_id)
    visible = _visible_entries(entries)
    if not visible:
        return {"status": "ok", "state": "not_found", "accessor": lease_id[:12] + "..."}

    # ── Vérifier si déjà révoqué dans le registry ────────────────────
    if all(e["status"] == "revoked" for e in visible):
        return {"status": "ok", "state": "already_revoked", "accessor": lease_id[:12] + "..."}

    return await _revoke_accessor_selected(registry, lease_id, visible)


async def _revoke_accessor_selected(registry, accessor: str, selection: list) -> dict:
    """
    Révoque un accessor côté OpenBao et marque UNIQUEMENT la sélection passée.

    AUCUN refresh ici (revue pré-commit #115) : la sélection a été établie par
    l'appelant après SON refresh fail-close — un rechargement intercalé
    détacherait les références et invaliderait la décision de visibilité.
    Mapping idempotent : accessor inconnu/expiré côté OpenBao → already_revoked.
    """
    client = _get_client()
    if not client:
        return {"status": "error", "error_type": "backend_unavailable",
                "message": "OpenBao non disponible"}

    try:
        client.auth.token.revoke_accessor(accessor=accessor)
        registry.mark_entries_revoked(selection)
        return {"status": "ok", "state": "revoked", "accessor": accessor[:12] + "..."}
    except Exception as e:
        err_str = str(e).lower()
        # OpenBao : "bad accessor" ou token déjà révoqué/expiré → idempotent
        if any(k in err_str for k in ("bad accessor", "not found", "invalid accessor")):
            # Marquer comme révoqué dans le registry (est expiré ou déjà révoqué côté Vault)
            registry.mark_entries_revoked(selection)
            return {"status": "ok", "state": "already_revoked", "accessor": accessor[:12] + "..."}
        # Distinguer HTTP 4xx (client error, idem already_revoked) vs 5xx/réseau
        if any(k in err_str for k in ("404", "400")):
            registry.mark_entries_revoked(selection)
            return {"status": "ok", "state": "already_revoked", "accessor": accessor[:12] + "..."}
        # 5xx / réseau → erreur réelle (broker doit retenter)
        logger.warning("revoke_wrap backend_error: %s", type(e).__name__)
        return {"status": "error", "error_type": "backend_error",
                "message": "Erreur de révocation (réessayer)"}


async def lookup_and_revoke_by_operation_id(operation_id: str) -> dict:
    """
    Retrouve et révoque les wraps créés avec un operation_id donné.

    États retournés (idempotent) :
        not_found        — aucune provision pour cet operation_id
        found_unattached — provision "pending" trouvée sans accessor (crash window) ;
                           pas de révocation possible, le TTL Vault gérera l'expiration
        already_revoked  — toutes les provisions déjà révoquées
        revoked          — révocation effectuée (1 entrée)
        ambiguous        — plusieurs provisions révoquées (potentielle duplication)

    Returns:
        {status, state, operation_id, count_revoked, entries_found}
    """
    registry = get_wrap_registry()
    if not registry:
        return {"status": "error", "error_type": "backend_unavailable",
                "message": "WrapRegistry non disponible (S3 requis)"}

    # Sélection défensive + visibilité (issue #115) : états et comptages
    # calculés sur les SEULES entrées visibles par l'identité courante — les
    # entrées hors scope ou malformées sont traitées comme absentes.
    # UN SEUL refresh (les révocations passent ensuite par
    # _revoke_accessor_selected, qui ne refresh pas).
    registry._maybe_refresh()
    # FAIL-CLOSE (revue pré-commit #115) : cache ambigu après échec de refresh
    # → aucune révocation ni _save (voir revoke_wrap).
    if getattr(registry, "_last_load_ok", True) is False:
        return {"status": "error", "error_type": "backend_unavailable",
                "message": "Registre non rafraîchi (S3 injoignable) — compensation refusée (réessayer)"}
    all_matching, _ = _select_wrap_entries(registry._wraps, operation_id=operation_id)
    entries = _visible_entries(all_matching)

    if not entries:
        return {
            "status": "ok", "state": "not_found",
            "operation_id": operation_id, "count_revoked": 0, "entries_found": 0,
        }

    # Détecter les pending sans accessor (crash window)
    pending_no_accessor = [e for e in entries if e["status"] == "pending" and not e.get("accessor")]
    if pending_no_accessor and all(e["status"] in ("pending", "failed") for e in entries):
        return {
            "status": "ok", "state": "found_unattached",
            "operation_id": operation_id, "count_revoked": 0,
            "entries_found": len(entries),
            "note": "Provision orpheline sans accessor — le TTL Vault gérera l'expiration",
        }

    count_already = sum(1 for e in entries if e["status"] == "revoked")
    active_entries = [e for e in entries if e["status"] == "active" and e.get("accessor")]

    if not active_entries:
        return {
            "status": "ok", "state": "already_revoked",
            "operation_id": operation_id, "count_revoked": 0, "entries_found": len(entries),
        }

    # Révoquer toutes les entrées actives — DIRECTEMENT sur la sélection déjà
    # établie et filtrée ci-dessus (pas de re-lookup ni de second refresh :
    # F4 revue pré-commit #115). GROUPÉES PAR ACCESSOR AVANT la boucle (revue
    # pré-commit R2) : un accessor partagé n'est révoqué qu'une fois ; le
    # compteur n'avance que sur résultat ok, de la taille du groupe — en cas
    # d'échec OpenBao, AUCUNE entrée du groupe n'est comptée révoquée.
    count_revoked = 0
    errors = []
    groups: dict = {}
    for entry in active_entries:
        groups.setdefault(entry["accessor"], []).append(entry)
    for accessor, group in groups.items():
        # La sélection marquée couvre TOUTES les entrées visibles de cet
        # accessor (y compris un éventuel "pending" incohérent qui le
        # partagerait) — même sémantique que l'historique mark_revoked par
        # accessor, mais bornée à la visibilité de l'appelant.
        selection = [e for e in entries if e.get("accessor") == accessor]
        result = await _revoke_accessor_selected(registry, accessor, selection)
        if result["status"] == "ok":
            count_revoked += len(group)
        else:
            errors.append(result.get("error_type", "backend_error"))

    if errors:
        return {
            "status": "error", "error_type": "partial_revocation",
            "operation_id": operation_id, "count_revoked": count_revoked,
            "entries_found": len(entries),
            "message": f"{len(errors)} révocations échouées (réessayer)",
        }

    total_entries = len(entries)
    if total_entries > 1:
        state = "ambiguous"
    elif count_already > 0:
        state = "ambiguous"
    else:
        state = "revoked"

    return {
        "status": "ok", "state": state,
        "operation_id": operation_id, "count_revoked": count_revoked,
        "entries_found": total_entries,
    }


# États d'entrée reconnus du registre (transitions register_pending → mark_active
# → try_mark_consuming → mark_consumed, + mark_revoked / mark_failed).
_KNOWN_WRAP_STATUSES = frozenset({"pending", "active", "consuming", "consumed", "revoked", "failed"})


async def status_by_operation_id(operation_id: str) -> dict:
    """
    Consulte l'état des wraps d'un operation_id — **lecture seule, aucune
    révocation ni écriture durable** (issue #77). À l'inverse de
    `lookup_and_revoke_by_operation_id`, cette fonction ne modifie rien.

    ⚠️ Contrat = **instantané best-effort du registre**, PAS une vérité OpenBao :
    - le registre a un cache (`CACHE_TTL`) et S3 est *last-write-wins* ;
    - `active` signifie « actif dans l'instantané » — **pas** une garantie de
      consommabilité (un wrap expiré côté OpenBao peut encore ressortir `active`,
      et une consommation concurrente peut invalider l'instantané) ;
    - la lecture peut rafraîchir le cache mémoire (`find_by_operation_id` →
      `_maybe_refresh`), mais n'écrit jamais sur S3 et ne révoque jamais ;
    - `backend_unavailable` signale que le DERNIER rafraîchissement S3 a échoué ;
      une panne S3 survenant PENDANT la fenêtre de cache (`CACHE_TTL`) n'est pas
      détectée — l'état renvoyé peut alors être périmé (best-effort assumé).

    États : `not_found | pending | active | consuming | consumed | revoked |
    failed | ambiguous | registry_inconsistent` (OK) ; `backend_unavailable`
    (status=error). Ne renvoie **jamais** d'`accessor` ni de `wrap_token`.
    """
    registry = get_wrap_registry()
    if not registry:
        return {"status": "error", "error_type": "backend_unavailable",
                "message": "WrapRegistry non disponible (S3 requis)"}

    # Lecture DÉFENSIVE (#77, refondue #115) : la sélection n'accède jamais à
    # une clé d'entrée sans garde — un registre corrompu ne produit JAMAIS
    # d'exception MCP. Pour un ADMIN, toute entrée malformée dans le registre
    # signale `registry_inconsistent` (comportement historique : l'itération
    # complète levait sur l'entrée malformée). Pour une identité non-admin,
    # une entrée malformée est simplement INVISIBLE (fail-close → not_found),
    # comme une entrée hors de son périmètre vault+chemins.
    registry._maybe_refresh()
    all_matching, saw_malformed = _select_wrap_entries(
        registry._wraps, operation_id=operation_id)

    is_admin = _caller_is_admin()
    if is_admin and saw_malformed:
        logger.warning("status_by_operation_id : registre illisible (op=%r)", operation_id[:16])
        return {"status": "ok", "state": "registry_inconsistent"}

    # #77 : si le dernier rafraîchissement S3 a échoué (panne effective), l'instantané
    # est indéterminé — ne pas le présenter comme fiable (not_found/active trompeur).
    if getattr(registry, "_last_load_ok", True) is False:
        return {"status": "error", "error_type": "backend_unavailable",
                "message": "Registre non rafraîchi (S3 injoignable) — état indéterminé"}

    entries = all_matching if is_admin else _visible_entries(all_matching)

    if not entries:
        return {"status": "ok", "state": "not_found"}
    if len(entries) > 1:
        # Anomalie (duplication) — on ne divulgue pas le compte (activité interne).
        return {"status": "ok", "state": "ambiguous"}

    # Une seule entrée. PROJECTION NEUVE : la sélection renvoie des références
    # VIVANTES du registre — on ne mute jamais l'entrée (un pop/masquage
    # corromprait la mémoire, puis S3 au prochain _save). On lit, on construit un
    # dict neuf, sans jamais exposer accessor/wrap_token.
    entry = entries[0]
    raw_status = entry.get("status")
    # Contrôle de TYPE avant le test d'appartenance : un status non-str (liste/dict,
    # non hashable) ferait lever `in frozenset`. Registre corrompu → état neutre.
    if not isinstance(raw_status, str) or raw_status not in _KNOWN_WRAP_STATUSES:
        return {"status": "ok", "state": "registry_inconsistent"}

    result = {"status": "ok", "state": raw_status}
    # expires_at INDICATIF pour les états vivants (aide le consommateur à jauger la
    # fraîcheur) — le TTL faisant foi reste côté OpenBao. Validé STRICTEMENT comme
    # ISO-8601 avant d'être reflété : une entrée de registre corrompue pourrait sinon
    # y cacher une valeur arbitraire (ex. un secret) qui ressortirait au client (#77).
    if raw_status in ("pending", "active", "consuming"):
        expires_at = entry.get("expires_at")
        if isinstance(expires_at, str) and expires_at:
            try:
                datetime.fromisoformat(expires_at)
            except ValueError:
                pass  # non-ISO → on n'expose rien
            else:
                result["expires_at"] = expires_at
    return result


def _infer_intended_use(secret_path: str) -> str:
    """Déduit l'intended_use depuis le chemin du secret (heuristique)."""
    path_lower = secret_path.lower()
    if any(k in path_lower for k in ("ssh", "id_rsa", "id_ed25519", "id_ecdsa")):
        return "ssh_key"
    if any(k in path_lower for k in ("cert", "tls", "pem", "crt")):
        return "cert"
    if any(k in path_lower for k in ("api", "key", "token", "apikey")):
        return "api_key"
    return "password"


# =============================================================================
# Consommation médiée (issue #26 — anti-confused-deputy C18)
# =============================================================================

async def consume_wrap_secret(
    wrap_token: str,
    operation_id: str,
    mission_id: str,
    tenant_id: str = "",
    expected_aud: str = "",
    enforce: bool = False,
) -> dict:
    """
    Libère un secret via le wrap_token après vérification du binding mission complet.

    Appelé depuis server.secret_consume APRÈS validation du JWT mission_token.
    La validation JWT (ES256/JWKS, iss/aud/exp) est faite en amont par le serveur.

    Flux :
    1. Lookup registry par (operation_id, mission_id) — clé composite
    1b. Vérification binding C18 complet : tenant_id + expected_aud (P1 — issue #29)
    2. try_mark_consuming() — atomic best-effort (backstop : OpenBao single-use)
    3. Unwrap OpenBao cubbyhole avec wrap_token
    4. mark_consumed() — anti-replay
    5. Retourner le secret (jamais wrap_token dans le retour)

    Sécurité :
    - wrap_token jamais loggué (paramètre SENSIBLE)
    - Binding mismatch détecté AVANT try_mark_consuming (pas d'état orphelin)
    - En cas d'échec OpenBao, rollback_consuming() pour permettre un retry
    - mission_id dans tous les logs (non-sensible, corrélation)
    """
    registry = get_wrap_registry()
    if registry is None:
        return {"status": "error", "error_type": "registry_unavailable",
                "message": "Registre non disponible"}

    client = _get_client()
    if not client:
        return {"status": "error", "error_type": "backend_unavailable",
                "message": "OpenBao non disponible"}

    settings = _get_config()

    # ── 1. Lookup par clé composite ─────────────────────────────────
    entry = registry.get_by_composite_key(operation_id, mission_id)
    if entry is None:
        # Chercher si l'entrée est consumed ou revoked (anti-replay)
        all_entries = registry.find_by_operation_id(operation_id)
        already_consumed = any(
            e["mission_id"] == mission_id and e["status"] in ("consumed", "revoked")
            for e in all_entries
        )
        if already_consumed:
            return {"status": "error", "error_type": "already_consumed",
                    "message": "Ce wrap a déjà été consommé"}
        return {"status": "error", "error_type": "not_found",
                "message": "Wrap introuvable (opération inconnue ou expirée)"}

    # ── 1b. Vérification binding C18 complet (P1 — issue #29) ───────
    # Vérification AVANT try_mark_consuming : pas d'état "consuming" orphelin si mismatch.
    # tenant_id et expected_aud sont optionnels (rétrocompat wraps legacy).
    # En mode enforce=True : les wraps sans expected_aud sont refusés (binding incomplet).
    if entry.get("tenant_id") and tenant_id != entry["tenant_id"]:
        logger.warning(
            "⚠️ consume_wrap_secret : binding mismatch (tenant_id) op=%r — confused-deputy rejeté",
            operation_id[:16],
        )
        return {"status": "error", "error_type": "binding_mismatch",
                "message": "binding mismatch"}
    if entry.get("expected_aud") and expected_aud != entry["expected_aud"]:
        logger.warning(
            "⚠️ consume_wrap_secret : binding mismatch (aud) op=%r — confused-deputy rejeté",
            operation_id[:16],
        )
        return {"status": "error", "error_type": "binding_mismatch",
                "message": "binding mismatch"}
    if enforce and not entry.get("expected_aud"):
        logger.warning(
            "⚠️ consume_wrap_secret : wrap sans expected_aud en mode enforced op=%r — rejeté",
            operation_id[:16],
        )
        return {"status": "error", "error_type": "binding_incomplete",
                "message": "binding incomplet (expected_aud manquant)"}

    # ── 2. Atomic try_mark_consuming ────────────────────────────────
    if not registry.try_mark_consuming(operation_id, mission_id):
        return {"status": "error", "error_type": "already_consuming",
                "message": "Wrap en cours de consommation ou déjà consommé"}

    # ── 3. Unwrap OpenBao cubbyhole ─────────────────────────────────
    try:
        # Utiliser un client éphémère avec le wrap_token comme token d'auth
        import hvac as _hvac
        ephemeral_client = _hvac.Client(url=settings.openbao_addr, token=wrap_token)
        unwrap_response = ephemeral_client.sys.unwrap()

        secret_data = unwrap_response.get("data", {})
        if not secret_data:
            registry.rollback_consuming(operation_id, mission_id)
            return {"status": "error", "error_type": "empty_secret",
                    "message": "Le wrap a retourné des données vides"}

    except Exception as e:
        err_str = str(e).lower()
        registry.rollback_consuming(operation_id, mission_id)

        if any(k in err_str for k in ("403", "forbidden", "bad token")):
            return {"status": "error", "error_type": "invalid_wrap_token",
                    "message": "Wrap token invalide ou expiré"}
        if any(k in err_str for k in ("404", "not found")):
            return {"status": "error", "error_type": "wrap_expired",
                    "message": "Wrap token expiré ou déjà utilisé (single-use)"}

        logger.error("consume_wrap_secret OpenBao error: %s", type(e).__name__)
        return {"status": "error", "error_type": "backend_error",
                "message": "Erreur lors de l'unwrap (réessayer)"}

    # ── 4. Marquer consumed ─────────────────────────────────────────
    registry.mark_consumed(operation_id, mission_id)
    # #78 : %r (repr échappe les caractères de contrôle) — vault_id/secret_path
    # proviennent du registre S3, qui a pu être écrit avec des fins de ligne par une
    # version antérieure (validation .match+$). Évite l'injection de ligne au log.
    logger.info(
        "✅ consume_wrap_secret : op=%r mission=%r vault=%r path=%r",
        operation_id[:16], mission_id[:16],
        entry.get("vault_id", "?"), entry.get("secret_path", "?"),
    )

    return {
        "status": "ok",
        "data": secret_data,
        "operation_id": operation_id,
        "mission_id": mission_id,
        "vault_id": entry.get("vault_id", ""),
        "secret_path": entry.get("secret_path", ""),
    }
