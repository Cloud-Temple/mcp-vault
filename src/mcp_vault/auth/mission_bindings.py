# -*- coding: utf-8 -*-
"""
Mission Binding Store — octroi de périmètre vault local pour les identités mission JWT.

Contexte (issue #47 / #69 — PR2) :
    Le mission_token émis par mcp-mission ne porte AUCUNE autorisation vault (ni `vaults`
    ni `permissions`). mcp-vault joue le rôle de PDP local : l'autorisation fine est
    provisionnée ICI, indexée par `tenant_id` (claim stable, immuable au refresh).

    Un « binding » associe à un tenant, pour CETTE instance Vault, un périmètre :
    liste de coffres autorisés + niveau de permission (lecture, ou lecture+écriture) +
    éventuellement une policy fine (path/tool) référencée dans le PolicyStore.

Modèle de sécurité (deny-by-default) :
    - Aucun binding pour un tenant  → aucun accès (la garde mission_jwt de context.py refuse).
    - Binding désactivé / expiré     → aucun accès (fail-close).
    - Store indisponible / corrompu  → refus OBSERVABLE (503), JAMAIS un deny silencieux,
      et AUCUNE écriture (pas d'écrasement destructeur d'un fichier corrompu).

Topologie multi-instance (reco Codex #69) :
    Un fichier S3 PAR INSTANCE : `_system/mission_bindings/{encoded_instance_id}.json`.
    Réduit fortement le last-write-wins cross-instance vs un fichier unique partagé.
    `instance_id` est également conservé dans chaque entrée (défense en profondeur) et
    filtré à la lecture. La révocation instantanée inter-instance (CAS/ETag) reste #51.

Pattern calqué sur PolicyStore/TokenStore (singleton + cache TTL + rollback sur _save).
"""

import asyncio
import functools
import hashlib
import json
import logging
import re
import sys
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger("mcp-vault.mission-binding-store")

from ..async_offload import run_blocking
from ..s3_client import objet_absent
from ..config import get_settings
from ..store_refresh import RETRY_AFTER_ERROR_SECONDS, Freshness, magasin_ferme
from ..vault_ids import is_valid_vault_id

# Format défensif d'un tenant_id utilisé comme identité REST/CLI et clé de binding.
# Le contrat mcp-mission garantit seulement « str non vide » ; on impose ici un format
# URL-safe (pas de '/', espace, '%') pour que les routes /admin/api/mission-bindings/{id}
# ne soient jamais ambiguës. On autorise ':' (les client_id peuvent en contenir).
_TENANT_ID_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$")

# Segments de route réservés : un tenant_id ne doit jamais les usurper.
_RESERVED_TENANT_IDS = frozenset({"purge"})

# Nombre maximal de coffres dans un même binding (garde-fou anti-abus / anti-payload géant).
_MAX_ALLOWED_RESOURCES = 100

# Intervalle minimal de re-tentative de chargement après un échec (store indisponible).
# Évite de marteler S3 à chaque requête tout en récupérant vite dès qu'il revient.
# Conservé sous son nom historique : plusieurs bancs l'importent pour vérifier la
# cadence de re-tentative. La valeur vit désormais dans `store_refresh`, partagée
# par les quatre magasins (issue #123).
_RETRY_AFTER_ERROR_SECONDS = RETRY_AFTER_ERROR_SECONDS


class MissionBindingStoreUnavailable(Exception):
    """Levée par resolve() quand le store est configuré mais indisponible/corrompu.

    Le PEP (AuthMiddleware) doit la mapper en 503 `binding_store_unavailable` — surtout
    PAS en deny silencieux (qui masquerait une panne du PDP local).
    """


# =============================================================================
# Mission Binding Store singleton
# =============================================================================

_mission_binding_store = None


def get_mission_binding_store() -> Optional["MissionBindingStore"]:
    """Retourne le Mission Binding Store (None si non configuré)."""
    return _mission_binding_store


def init_mission_binding_store():
    """Initialise le Mission Binding Store au démarrage.

    Conditions d'activation : S3 configuré ET une identité d'instance (resolved_mission_aud)
    connue — sans quoi un octroi de périmètre mission n'a pas de sens (mode bearer pur).
    """
    global _mission_binding_store
    settings = get_settings()

    if not (settings.s3_endpoint_url and settings.s3_bucket_name):
        print("🎟️  Mission Binding Store S3 non configuré", file=sys.stderr)
        return

    if not settings.resolved_mission_aud:
        # PEP mission JWT inactif (mode bearer sans instance_id) : aucun binding utile.
        print(
            "🎟️  Mission Binding Store inactif (MCP_INSTANCE_ID/MISSION_TOKEN_AUD absent)",
            file=sys.stderr,
        )
        return

    _mission_binding_store = MissionBindingStore(settings)
    _mission_binding_store.load()
    if _mission_binding_store.available:
        print(
            f"🎟️  Mission Binding Store S3 initialisé "
            f"({_mission_binding_store.count()} binding(s) actif(s), instance="
            f"{_mission_binding_store.instance_id})",
            file=sys.stderr,
        )
    else:
        # Fail-close observable : le store existe mais son état est invalide au boot.
        # Le runtime renverra 503 ; les mutations seront refusées ; aucun overwrite.
        print(
            f"⚠️  Mission Binding Store S3 INDISPONIBLE au démarrage : "
            f"{_mission_binding_store.last_error} — les missions seront refusées (503) "
            f"jusqu'à rétablissement",
            file=sys.stderr,
        )


# =============================================================================
# Helpers de validation (module-level, testables isolément)
# =============================================================================

def _encode_instance_id(instance_id: str) -> str:
    """Dérive un nom de fichier S3 sûr et unique pour une instance.

    slug lisible (débuggable) + suffixe hash court (anti-collision après normalisation).
    """
    slug = re.sub(r"[^A-Za-z0-9._-]", "_", instance_id)[:48]
    digest = hashlib.sha256(instance_id.encode()).hexdigest()[:8]
    return f"{slug}.{digest}"


def normalize_permissions(permissions) -> Optional[list]:
    """Valide et normalise les permissions d'un binding (contrat STRICT).

    Il n'existe pas de `check_read_permission` : la lecture est induite par l'appartenance
    au périmètre (check_access). On garantit donc que `read` est TOUJOURS présent, sinon un
    binding « write-only » ou vide octroierait la lecture par surprise. `write` est un droit
    SUPPLÉMENTAIRE, réellement vérifié par check_write_permission. `admin` est INTERDIT
    (une mission ne fait jamais d'administration — arbitrage produit #69).

    Returns:
        ["read"] ou ["read", "write"] (normalisé, trié), ou None si invalide.
    """
    if not isinstance(permissions, list) or not permissions:
        return None
    if not all(isinstance(p, str) for p in permissions):
        return None
    perms = set(permissions)
    if perms == {"read"}:
        return ["read"]
    if perms == {"read", "write"}:
        return ["read", "write"]
    return None  # rejette [], ["write"], ["admin"], ["read","admin"], toute valeur inconnue


def validate_allowed_resources(allowed_resources) -> tuple[Optional[list], str]:
    """Valide la liste des coffres d'un binding.

    Exige : liste non vide ; chaque élément str au format vault_id (regex) ; pas de doublon ;
    pas de valeur passe-partout (`*` est de toute façon exclu par la regex) ; taille bornée.

    Returns:
        (liste_validée, "") si OK, (None, message) sinon.
    """
    if not isinstance(allowed_resources, list) or not allowed_resources:
        return None, "allowed_resources doit être une liste non vide"
    if len(allowed_resources) > _MAX_ALLOWED_RESOURCES:
        return None, f"allowed_resources trop long (max {_MAX_ALLOWED_RESOURCES})"
    seen = set()
    for vid in allowed_resources:
        if not is_valid_vault_id(vid):
            return None, f"vault_id invalide dans allowed_resources : {vid!r}"
        if vid in seen:
            return None, f"vault_id dupliqué dans allowed_resources : {vid!r}"
        seen.add(vid)
    return list(allowed_resources), ""


def validate_tenant_id(tenant_id) -> tuple[bool, str]:
    """Valide le format défensif d'un tenant_id (identité REST/CLI + clé de binding)."""
    if not isinstance(tenant_id, str) or not tenant_id:
        return False, "tenant_id requis (chaîne non vide)"
    if tenant_id in _RESERVED_TENANT_IDS:
        return False, f"tenant_id réservé : {tenant_id!r}"
    # fullmatch (pas match) : round 3 revue fix critique vault_id — même
    # piège `$` accepte un `\n` final, ici sur un identifiant utilisé comme
    # clé de binding C18 (tenant_id).
    if not _TENANT_ID_PATTERN.fullmatch(tenant_id):
        return False, (
            f"tenant_id invalide : {tenant_id!r} — format URL-safe attendu "
            "(alphanum, '.', '_', ':', '-', 1-128 caractères)"
        )
    return True, ""


def _is_expired(binding: dict) -> bool:
    """True si le binding est expiré. Fail-close : date corrompue = expiré."""
    expires_at = binding.get("expires_at")
    if not expires_at:
        return False
    try:
        return datetime.now(timezone.utc) > datetime.fromisoformat(expires_at)
    except (ValueError, TypeError):
        return True  # fail-close : date corrompue = expiré


def validate_binding_record(binding) -> tuple[bool, str]:
    """Valide une entrée binding TELLE QUE LUE depuis S3 (défense en profondeur au chargement).

    CRITIQUE (revue Codex #69, BLOQUANT-1) : les mêmes invariants stricts que create() doivent
    tenir sur l'état persistant — un fichier forgé/corrompu/legacy avec `permissions=["admin"]`
    ou `["write"]` seul ne doit JAMAIS être servi (sinon élévation de privilège : check_access
    donne l'accès total sur `admin`, et check_policy court-circuite le plafond d'outils).

    N.B. : le FORMAT de policy_id est validé ici, pas son existence (déjà vérifiée à create() ;
    une policy supprimée après coup est de toute façon fail-close via check_policy).

    Returns:
        (True, "") si l'entrée est conforme, (False, message) sinon.
    """
    if not isinstance(binding, dict):
        return False, "entrée non-dict"
    ok, msg = validate_tenant_id(binding.get("tenant_id"))
    if not ok:
        return False, f"tenant_id: {msg}"
    if normalize_permissions(binding.get("permissions")) is None:
        return False, f"permissions non conformes: {binding.get('permissions')!r}"
    res, rmsg = validate_allowed_resources(binding.get("allowed_resources"))
    if res is None:
        return False, f"allowed_resources: {rmsg}"
    if not isinstance(binding.get("enabled"), bool):
        return False, "enabled non booléen"
    exp = binding.get("expires_at")
    if exp is not None:
        if not isinstance(exp, str):
            return False, "expires_at non-str"
        try:
            datetime.fromisoformat(exp)
        except (ValueError, TypeError):
            return False, "expires_at non parseable"
    if not isinstance(binding.get("policy_id", ""), str):
        return False, "policy_id non-str"
    return True, ""


# =============================================================================
# MissionBindingStore — Stockage S3 par instance + cache mémoire TTL
# =============================================================================

class MissionBindingStore:
    """Octroi de périmètre vault local pour les identités mission JWT (un fichier par instance).

    - Stockage S3 : _system/mission_bindings/{encoded_instance_id}.json
    - Cache mémoire TTL 5 min (re-tentative accélérée à 10s si indisponible)
    - État observable : available / last_error (BLOQUANT-2 revue #69)
    - CRUD : create / get / list_all / delete / purge (+ resolve pour le PEP)
    """

    # #86 finding 7 — révocation différée : ARBITRAGE DE NE PAS RÉDUIRE, motivé.
    #
    # ⚠️ Ce TTL est une borne de FRAÎCHEUR et de fail-close, pas la cadence de polling
    # (le rafraîchisseur de fond travaille à la moitié, cf. #123).
    #
    # Ce qu'il NE retarde PAS, vérifié : une révocation faite par NOTRE API est
    # effective immédiatement — les mutations publient l'instantané en mémoire après un
    # `_save()` confirmé (cf. `delete`, `create`, `purge`) ; et `expires_at` est évalué
    # à CHAQUE `resolve()`, sans attendre un rechargement.
    #
    # Ce qu'il retarde : une mutation faite HORS de notre API — édition directe du
    # fichier S3, ou une AUTRE réplique. Or nous sommes mono-instance (« single-process
    # en pratique », cf. `_save`), et l'édition directe de S3 n'est pas une procédure
    # de révocation supportée. L'exposition réelle est donc nulle aujourd'hui.
    #
    # Réduire le TTL coûterait des lectures S3 sur tous les magasins pour un gain nul.
    # DÉCLENCHEURS qui rendent ce compromis réel, et qui appartiennent à #51 :
    # passage multi-instance, apparition d'un second writer, ou reconnaissance de
    # l'édition directe S3 comme procédure d'exploitation.
    CACHE_TTL = 300  # 5 minutes
    S3_KEY_PREFIX = "_system/mission_bindings/"

    def __init__(self, settings):
        self.settings = settings
        # Identité canonique de l'instance = source unique d'audience (#47).
        self.instance_id = settings.resolved_mission_aud
        self.s3_key = f"{self.S3_KEY_PREFIX}{_encode_instance_id(self.instance_id)}.json"
        # ⚠️ INSTANTANÉ PUBLIÉ (#123) : jamais muté en place. Une mutation
        # construit un candidat, le persiste, et ne réassigne cet attribut
        # qu'après confirmation du PUT (copy-on-write).
        self._bindings: dict = {}  # tenant_id → binding
        self.freshness = Freshness()
        self.refresh_lock = asyncio.Lock()
        self._available: bool = True
        self._last_error: str = ""

    # ── État observable ───────────────────────────────────────────────
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

    def _mark_invalid(self, msg: str):
        """Passe le store en état INDISPONIBLE observable (sans écraser le cache mémoire)."""
        self._available = False
        self._last_error = msg
        # Seule `last_attempt` avance : brider la re-tentative ne doit pas
        # rajeunir un instantané qui n'a pas été rechargé (#123).
        self.freshness.mark_failure(msg)
        logger.error(
            "Mission Binding Store INVALIDE key=%s : %s — runtime 503 + mutations refusées "
            "jusqu'à rétablissement", self.s3_key, msg,
        )

    def load(self):
        """Charge les bindings depuis S3 avec validation atomique (défense en profondeur).

        - Objet absent (NoSuchKey/404) → store VIDE mais writable (available) — nominal.
        - Réseau/403/timeout           → INVALID (503), cache conservé, PAS d'écrasement.
        - JSON corrompu / schéma cassé → INVALID.
        - UNE entrée de cette instance non conforme (permissions/allowed_resources/tenant_id/
          doublon/…) → INVALID : on ne sert JAMAIS un binding qui n'a pas passé les validations
          strictes (anti élévation de privilège via fichier forgé, Codex BLOQUANT-1).
        """
        try:
            s3 = self._get_s3_data()
            resp = s3.get_object(Bucket=self.settings.s3_bucket_name, Key=self.s3_key)
            raw = resp["Body"].read().decode()
        except Exception as e:
            if objet_absent(e):
                # Absence nominale (1er démarrage) : chargement RÉUSSI d'un
                # magasin vide, la fraîcheur doit avancer (#123).
                self._bindings = {}
                self.freshness.mark_success()
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

        if not isinstance(data, dict) or not isinstance(data.get("bindings", []), list):
            self._mark_invalid("schéma top-level invalide (attendu {'bindings': [...]})")
            return

        validated: dict = {}
        for b in data.get("bindings", []):
            if not isinstance(b, dict):
                self._mark_invalid("entrée binding non-dict")
                return
            # Fichier par instance : ignorer (sans invalider) une entrée d'une autre instance ;
            # elle n'est de toute façon jamais servie (filtre instance_id).
            if b.get("instance_id") != self.instance_id:
                continue
            ok, why = validate_binding_record(b)
            if not ok:
                self._mark_invalid(f"binding tenant={b.get('tenant_id')!r} non conforme: {why}")
                return
            tid = b["tenant_id"]
            if tid in validated:
                self._mark_invalid(f"tenant_id dupliqué: {tid!r}")
                return
            validated[tid] = b

        self._bindings = validated
        self.freshness.mark_success()
        self._available = True
        self._last_error = ""

    def force_reload(self):
        """Force un rechargement immédiat (ignore le TTL).

        ⚠️ **Aucun appelant en production aujourd'hui** (vérifié : le
        `force_reload()` de l'API admin porte sur le cache JWKS, pas sur ce
        magasin). Conservée pour un usage d'exploitation ponctuel.

        ⚠️ Appel S3 **SYNCHRONE**. L'appeler depuis la boucle réintroduirait
        exactement le gel de #110 que #123 vient de fermer : le rechargement
        appartient au rafraîchisseur de fond, et tout appel ici doit rester hors
        boucle (démarrage, script d'exploitation) ou passer par `run_blocking`.
        """
        self.load()

    def _save(self, snapshot: dict) -> bool:
        """Persiste le SNAPSHOT CANDIDAT sur S3 (PUT = SigV2). Ne publie rien.

        ⚠️ Prend le candidat en argument et ne lit JAMAIS `self._bindings`
        (#123) : la publication appartient à l'appelant, et seulement après un
        True. `resolve()` ne prend aucun verrou — sans cela il pourrait servir
        un binding créé mais non persisté.
        LIMITATION V1 — last-write-wins intra-instance (issue #13/#51) : pas d'ETag/CAS.
        Le fichier par instance élimine le clobbering cross-instance ; deux writers sur la
        MÊME instance restent en last-write-wins (rare, single-process en pratique).
        """
        try:
            s3 = self._get_s3_data()
            data = json.dumps(
                {"instance_id": self.instance_id, "bindings": list(snapshot.values())},
                indent=2, default=str,
            )
            s3.put_object(
                Bucket=self.settings.s3_bucket_name,
                Key=self.s3_key,
                Body=data.encode(),
                ContentType="application/json",
            )
            return True
        except Exception as e:
            # Revue Codex #69 (BLOQUANT-2) : un PUT échoué prouve que S3 est indisponible →
            # basculer en état INVALID (cohérent avec l'invariant "panne S3 observable").
            # resolve() lèvera 503 au lieu de servir un cache pendant que S3 est inaccessible ;
            # le prochain load() (re-tentative 10s) rétablira l'état si S3 revient.
            logger.error(
                "Mission Binding Store S3 save FAILED: %s — état mémoire non persisté, "
                "store marqué INDISPONIBLE", type(e).__name__,
            )
            self._available = False
            self._last_error = f"S3 PUT: {type(e).__name__}"
            self.freshness.mark_failure(self._last_error)
            return False

    def _maybe_refresh(self):
        """
        Constate la fraîcheur de l'instantané publié. **MÉMOIRE PURE** — aucun
        appel réseau (#123, voir `store_refresh`).

        Le fail-close de #69/#86 est conservé à l'identique : un instantané
        périmé au-delà du TTL ne sert plus aucune décision. Seul le mécanisme
        change — on le constate au lieu de le découvrir en tentant un GET
        SYNCHRONE depuis la boucle.
        """
        if self._available and self.freshness.is_stale(self.CACHE_TTL):
            self._available = False
            self._last_error = (
                "instantané périmé : aucun rechargement réussi depuis plus de "
                f"{self.CACHE_TTL:.0f}s"
            )
            logger.error(
                "Mission Binding Store PÉRIMÉ key=%s (%s) — runtime 503 jusqu'à "
                "un rechargement réussi du rafraîchisseur de fond",
                self.s3_key, self._last_error,
            )

    def _ensure_available(self):
        """Rafraîchit puis lève si le store est indisponible (pour resolve/mutations)."""
        self._maybe_refresh()
        if not self._available:
            raise MissionBindingStoreUnavailable(self._last_error or "store indisponible")

    # ── Résolution runtime (PEP) ──────────────────────────────────────
    def resolve(self, tenant_id: str) -> Optional[dict]:
        """Résout le binding actif d'un tenant pour le PEP.

        Returns:
            Le binding (dict) si présent, activé, non expiré et de CETTE instance.
            None si aucun binding applicable (→ deny-all côté PEP).
        Raises:
            MissionBindingStoreUnavailable si le store est configuré mais indisponible (→ 503).
        """
        self._ensure_available()
        binding = self._bindings.get(tenant_id)
        if binding is None:
            return None
        # Défense en profondeur : ignorer une entrée d'une autre instance (bucket partagé).
        if binding.get("instance_id") != self.instance_id:
            return None
        if not binding.get("enabled", False):
            return None
        if _is_expired(binding):
            return None
        return binding

    # ── CRUD (administration) ─────────────────────────────────────────
    def create(self, tenant_id: str, allowed_resources: list, permissions: list,
               policy_id: str = "", expires_at: Optional[str] = None,
               enabled: bool = True, created_by: str = "admin") -> dict:
        """Crée un binding tenant→périmètre pour cette instance.

        Validation défense-en-profondeur (indépendante du point d'entrée HTTP) :
        tenant_id format + non réservé + unicité ; permissions ∈ {read | read,write} ;
        allowed_resources = vrais vault_id non vides/dédupliqués ; policy_id référencé existant.
        """
        # Store indisponible → aucune écriture (pas d'écrasement).
        self._maybe_refresh()
        if not self._available:
            return {"status": "error", "error_type": "storage_unavailable",
                    "message": f"Mission Binding Store indisponible ({self._last_error})"}

        ok, msg = validate_tenant_id(tenant_id)
        if not ok:
            return {"status": "error", "message": msg}

        # `enabled` : booléen STRICT (revue Codex #69). Ne JAMAIS coercer — `bool("false")` vaut
        # True, ce qui activerait un octroi qu'un admin croit créer désactivé.
        if not isinstance(enabled, bool):
            return {"status": "error", "message": "enabled doit être un booléen (true/false)"}

        if tenant_id in self._bindings:
            return {"status": "error", "message": f"Binding pour tenant '{tenant_id}' existe déjà"}

        norm_perms = normalize_permissions(permissions)
        if norm_perms is None:
            return {"status": "error", "error_type": "invalid_permissions",
                    "message": "permissions doit valoir exactement ['read'] ou ['read','write'] "
                               "('write' seul, [], et 'admin' sont refusés)"}

        resources, res_msg = validate_allowed_resources(allowed_resources)
        if resources is None:
            return {"status": "error", "message": res_msg}

        # issue #86 Lot 3 (round 2 diff review) : garde de type AVANT le test
        # falsy — un policy_id non-str (ex. False) est falsy comme une chaîne
        # vide et sauterait sinon silencieusement toute vérification.
        if policy_id is not None and not isinstance(policy_id, str):
            return {"status": "error", "message": "policy_id doit être une chaîne"}
        if policy_id:
            # issue #86 Lot 3 : référence policy_id non vérifiable (store absent OU
            # indisponible) → refus explicite, aucun binding créé sur une référence
            # que l'on ne peut pas confirmer.
            from .policies import get_policy_store, PolicyStoreUnavailable
            ps = get_policy_store()
            if ps is None:
                return {"status": "error", "message": "policy_id référencé mais Policy Store non configuré"}
            try:
                policy_found = ps.get(policy_id)
            except PolicyStoreUnavailable as e:
                return {"status": "error", "error_type": "policy_store_unavailable",
                        "message": f"Policy Store indisponible — policy_id '{policy_id}' ne peut être vérifié ({e})"}
            if policy_found is None:
                return {"status": "error", "message": f"policy_id '{policy_id}' inexistant"}

        # expires_at : si fourni, doit être une date ISO parseable (fail-fast à la création).
        if expires_at is not None:
            try:
                datetime.fromisoformat(expires_at)
            except (ValueError, TypeError):
                return {"status": "error", "message": f"expires_at invalide (ISO 8601 attendu) : {expires_at!r}"}

        now = datetime.now(timezone.utc).isoformat()
        binding = {
            "instance_id": self.instance_id,
            "tenant_id": tenant_id,
            "policy_id": policy_id or "",
            "allowed_resources": resources,
            "permissions": norm_perms,
            "enabled": enabled,
            "expires_at": expires_at,
            "created_at": now,
            "created_by": created_by,
        }

        # Copy-on-write (#123) : publication seulement après PUT confirmé. Plus
        # de rollback à écrire — donc plus de rollback à oublier — et `resolve()`,
        # qui ne prend aucun verrou, ne peut pas servir un binding non persisté.
        candidate = dict(self._bindings)
        candidate[tenant_id] = binding
        if not self._save(candidate):
            return {"status": "error", "error_type": "storage_unavailable",
                    "message": "Impossible de créer le binding (S3 indisponible)"}
        self._bindings = candidate

        return {"status": "created", **binding}

    def get(self, tenant_id: str) -> Optional[dict]:
        """Récupère l'entrée brute d'un binding (vue admin : montre enabled/expired tel quel).

        Raises:
            MissionBindingStoreUnavailable si le store est indisponible.
        """
        self._ensure_available()
        binding = self._bindings.get(tenant_id)
        if binding is None or binding.get("instance_id") != self.instance_id:
            return None
        return {**binding, "expired": _is_expired(binding)}

    def list_all(self) -> list:
        """Liste tous les bindings de cette instance (vue admin, avec état calculé).

        Raises:
            MissionBindingStoreUnavailable si le store est indisponible.
        """
        self._ensure_available()
        return [
            {
                "tenant_id": b["tenant_id"],
                "allowed_resources": b.get("allowed_resources", []),
                "permissions": b.get("permissions", []),
                "policy_id": b.get("policy_id", ""),
                "enabled": b.get("enabled", False),
                "expires_at": b.get("expires_at"),
                "expired": _is_expired(b),
                "created_at": b.get("created_at", ""),
                "created_by": b.get("created_by", ""),
            }
            for b in self._bindings.values()
            if b.get("instance_id") == self.instance_id
        ]

    def delete(self, tenant_id: str):
        """Supprime un binding.

        Retourne : True (supprimé) | False (introuvable) | "storage_error" (S3 KO, rollback)
                   | "storage_unavailable" (store invalide, aucune écriture tentée).
        """
        self._maybe_refresh()
        if not self._available:
            return "storage_unavailable"
        if tenant_id not in self._bindings:
            return False
        # Copy-on-write (#123) : le binding reste servi tant que sa suppression
        # n'est pas persistée. Une disparition transitoire ferait refuser un
        # accès légitime pendant tout l'aller-retour S3.
        candidate = dict(self._bindings)
        del candidate[tenant_id]
        if not self._save(candidate):
            logger.error("Suppression binding '%s' non persistée — S3 indisponible", tenant_id)
            return "storage_error"
        self._bindings = candidate
        return True

    def purge(self, older_than_days: int = 30, dry_run: bool = False) -> dict:
        """Purge les bindings EXPIRÉS depuis plus de `older_than_days` jours.

        Fail-close : un binding sans `expires_at` parseable n'est jamais purgé (on ne
        détruit pas ce qu'on ne sait pas dater). Les bindings actifs ou seulement
        désactivés (non datés) ne sont pas purgés — un admin les supprime via delete().
        """
        self._maybe_refresh()
        if not self._available:
            return {"status": "error", "error_type": "storage_unavailable",
                    "message": f"Mission Binding Store indisponible ({self._last_error})"}

        cutoff = datetime.now(timezone.utc) - timedelta(days=max(0, older_than_days))
        candidates = []
        for tid, b in self._bindings.items():
            expires_at = b.get("expires_at")
            if not expires_at:
                continue  # jamais expirant → non purgeable
            try:
                exp_dt = datetime.fromisoformat(expires_at)
            except (ValueError, TypeError):
                continue  # fail-close : date corrompue → non purgé
            if exp_dt.tzinfo is None:
                continue  # date non comparable (naïve) → fail-close
            if exp_dt > cutoff:
                continue  # pas encore au-delà de la rétention
            candidates.append((tid, b))

        summary = [
            {"tenant_id": tid, "expires_at": b.get("expires_at", "")}
            for tid, b in candidates
        ]

        if dry_run:
            return {"status": "ok", "dry_run": True, "count": len(summary),
                    "older_than_days": older_than_days, "candidates": summary,
                    "message": f"{len(summary)} binding(s) expiré(s) seraient purgés "
                               f"(rétention {older_than_days} j)"}

        if not candidates:
            return {"status": "ok", "dry_run": False, "count": 0,
                    "older_than_days": older_than_days, "purged": [],
                    "message": "Aucun binding expiré à purger (rétention respectée)"}

        # Copy-on-write (#123) : cf. delete(). La copie profonde d'avant servait
        # à restaurer les entrées supprimées ; il n'y a plus de rollback. Le
        # candidat doit en revanche être une copie DISTINCTE, sans quoi la
        # suppression toucherait l'instantané en cours d'utilisation.
        candidate = dict(self._bindings)
        for tid, _ in candidates:
            del candidate[tid]

        if not self._save(candidate):
            logger.error("Purge de %d binding(s) expiré(s) non persistée — S3 indisponible", len(candidates))
            return {"status": "error", "error_type": "storage_unavailable", "dry_run": False,
                    "count": 0, "older_than_days": older_than_days,
                    "message": "Purge non persistée — S3 indisponible"}

        self._bindings = candidate

        return {"status": "ok", "dry_run": False, "count": len(summary),
                "older_than_days": older_than_days, "purged": summary,
                "message": f"{len(summary)} binding(s) expiré(s) purgé(s)"}

    # ── Façades async (issue #123) ───────────────────────────────────
    #
    # Les mutations font un PUT S3 SYNCHRONE ; appelées depuis un outil MCP ou
    # l'API admin (tous `async`), elles gèlent la boucle. Ces façades les
    # exécutent hors boucle, sous le verrou du magasin. Elles n'ajoutent AUCUNE
    # logique : l'implémentation reste la méthode synchrone, seule couverte par
    # les bancs.

    async def acreate(self, *args, **kwargs) -> dict:
        """`create()` hors boucle, sérialisé par le verrou du magasin."""
        if magasin_ferme(self):
            return {"status": "error", "error_type": "storage_unavailable",
                    "message": "Arrêt en cours — aucune mutation acceptée"}
        async with self.refresh_lock:
            return await run_blocking(functools.partial(self.create, *args, **kwargs))

    async def adelete(self, tenant_id: str):
        """`delete()` hors boucle, sérialisé par le verrou du magasin."""
        if magasin_ferme(self):
            return "storage_unavailable"
        async with self.refresh_lock:
            return await run_blocking(functools.partial(self.delete, tenant_id))

    async def apurge(self, *args, **kwargs) -> dict:
        """`purge()` hors boucle, sérialisé par le verrou du magasin."""
        if magasin_ferme(self):
            return {"status": "error", "error_type": "storage_unavailable",
                    "dry_run": False, "count": 0,
                    "message": "Arrêt en cours — aucune mutation acceptée"}
        async with self.refresh_lock:
            return await run_blocking(functools.partial(self.purge, *args, **kwargs))

    def count(self) -> int:
        """Nombre de bindings actifs (activés et non expirés) de cette instance."""
        return sum(
            1 for b in self._bindings.values()
            if b.get("instance_id") == self.instance_id
            and b.get("enabled", False) and not _is_expired(b)
        )
