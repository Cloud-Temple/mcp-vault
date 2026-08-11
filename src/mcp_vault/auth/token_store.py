# -*- coding: utf-8 -*-
"""
Token Store S3 avec cache mémoire TTL 5 minutes.

Si S3 n'est pas configuré, les tokens sont gérés en mémoire uniquement
(bootstrap key). Quand S3 est configuré, les tokens sont stockés dans
_system/tokens.json sur le bucket S3.

Pattern :
    init_token_store()     → Appelé au démarrage (charge depuis S3)
    get_token_store()      → Getter singleton (retourne None si pas configuré)

Durcissement validation (issue #86, extension Lot 3) :
    `create()`/`update()`/`load()` partagent désormais la MÊME validation
    stricte de `permissions`/`allowed_resources` (jamais permissive par
    défaut — corrige un bug d'élévation de privilège : `update()` acceptait
    un `permissions` non-liste, par ex. `{"admin": true}`, dont l'itération
    sur les CLÉS du dict passait à tort le test `isinstance(p, str) and p in
    VALID_PERMISSIONS` ; un `tokens.json` corrompu avec `permissions: "admin"`
    (string) produisait le même bypass via `"admin" in "admin"`).

    ⚠️ LIMITE EXPLICITE DE CE LOT : `available`/`last_error` sont
    DIAGNOSTIQUES SEULEMENT. `get_by_hash()`/`create()`/`update()`/`revoke()`
    ne consultent PAS cet état — une panne S3 détectée après TTL continue de
    servir le cache bearer périmé (y compris après une révocation distante),
    exactement comme avant ce lot. Fermer ce résidu (fail-close complet de
    l'authentification bearer, comme PolicyStore/MissionBindingStore) est un
    chantier séparé à impact opérationnel plus large (deny-all bearer
    pendant une panne S3), qui reste hors scope ici.
"""

import logging
import re
import sys
import time
import json
import hashlib
from typing import Optional

logger = logging.getLogger("mcp-vault.token-store")

from ..config import get_settings

# Intervalle minimal de re-tentative de chargement après un échec (store
# diagnostiqué invalide). N'affecte QUE la vitesse de récupération d'un état
# `available` observable — ne bloque aucune décision dans ce lot (cf. limite
# ci-dessus).
_RETRY_AFTER_ERROR_SECONDS = 10.0

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
        if _token_store.available:
            print(f"🔑 Token Store S3 initialisé ({_token_store.count()} tokens)", file=sys.stderr)
        else:
            print(
                f"⚠️  Token Store S3 INDISPONIBLE au démarrage : {_token_store.last_error} — "
                "voir docstring module (diagnostic seulement, aucune mutation/lecture bloquée)",
                file=sys.stderr,
            )
    else:
        print("🔑 Token Store S3 non configuré (bootstrap key uniquement)", file=sys.stderr)


# =============================================================================
# Validation (module-level, testable isolément)
# =============================================================================

_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def _validate_permissions(permissions) -> tuple:
    """Valide une liste de permissions (source unique — create()/update()/load()).

    Returns:
        (liste_validée, "") si OK, (None, message) sinon.
    """
    if not isinstance(permissions, list) or not permissions:
        return None, "permissions doit être une liste non vide (read|write|admin|wrap)"
    if not all(isinstance(p, str) and p in TokenStore.VALID_PERMISSIONS for p in permissions):
        return None, f"Permissions invalides: {permissions}. Valides: read, write, admin, wrap"
    return list(permissions), ""


def _validate_allowed_resources(allowed_resources) -> tuple:
    """Valide allowed_resources (liste de vault_id ; vide = owner-based, légitime).

    Returns:
        (liste_validée, "") si OK, (None, message) sinon.
    """
    if not isinstance(allowed_resources, list) or not all(isinstance(v, str) for v in allowed_resources):
        return None, "allowed_resources doit être une liste de chaînes"
    return list(allowed_resources), ""


def _validate_and_normalize_token(raw) -> dict:
    """Valide strictement un token TEL QUE LU depuis S3 (défense en profondeur).

    Ne mute jamais l'entrée fournie. Lève ValueError(message) si invalide.

    Réutilise EXACTEMENT la même validation permissions/allowed_resources que
    create()/update() (_validate_permissions/_validate_allowed_resources) —
    un token chargé depuis un blob corrompu ne doit jamais devenir plus
    permissif qu'un token créé/modifié normalement via l'API.
    """
    if not isinstance(raw, dict):
        raise ValueError("token doit être un objet")

    token_hash = raw.get("hash")
    if not isinstance(token_hash, str) or not _HASH_RE.match(token_hash):
        raise ValueError(f"hash invalide (SHA-256 hex 64 caractères minuscules attendu) : {token_hash!r}")

    client_name = raw.get("client_name", "")
    if not isinstance(client_name, str):
        raise ValueError(f"client_name invalide : {client_name!r}")

    permissions, perr = _validate_permissions(raw.get("permissions"))
    if permissions is None:
        raise ValueError(f"permissions invalides : {perr}")

    allowed_resources, aerr = _validate_allowed_resources(raw.get("allowed_resources", []))
    if allowed_resources is None:
        raise ValueError(f"allowed_resources invalide : {aerr}")

    # Compat historique : les tokens antérieurs à l'ajout des policies n'ont pas
    # ce champ (absent → ""). Sentinel "_remove" (bug SPA < v0.4.11) normalisé
    # ICI, dans la forme validée — jamais persisté tel quel par create()/update().
    policy_id = raw.get("policy_id", "")
    if policy_id == "_remove":
        policy_id = ""
    if not isinstance(policy_id, str):
        raise ValueError(f"policy_id invalide : {policy_id!r}")

    revoked = raw.get("revoked", False)
    if not isinstance(revoked, bool):
        raise ValueError(f"revoked invalide (booléen attendu) : {revoked!r}")

    expires_at = raw.get("expires_at")
    if expires_at is not None:
        if not isinstance(expires_at, str):
            raise ValueError(f"expires_at invalide : {expires_at!r}")
        from datetime import datetime
        try:
            parsed = datetime.fromisoformat(expires_at)
        except ValueError:
            raise ValueError(f"expires_at non parseable : {expires_at!r}")
        if parsed.tzinfo is None:
            raise ValueError(f"expires_at doit être timezone-aware : {expires_at!r}")

    def _as_str(v):
        return v if isinstance(v, str) else ""

    return {
        "hash": token_hash,
        "client_name": client_name,
        "permissions": permissions,
        "allowed_resources": allowed_resources,
        "policy_id": policy_id,
        "email": _as_str(raw.get("email", "")),
        "created_at": _as_str(raw.get("created_at", "")),
        "expires_at": expires_at,
        "revoked": revoked,
        "revoked_at": _as_str(raw.get("revoked_at", "")),
    }


# =============================================================================
# TokenStore — Stockage S3 + cache mémoire TTL
# =============================================================================

class TokenStore:
    """
    Gestion des tokens d'accès MCP.

    - Stockage sur S3 : _system/tokens.json
    - Cache mémoire avec TTL de 5 minutes
    - CRUD : create, list, info, revoke
    - État observable available/last_error : DIAGNOSTIQUE SEULEMENT dans ce
      lot (voir docstring module) — ne bloque ni lecture ni mutation.
    """

    CACHE_TTL = 300  # 5 minutes
    S3_KEY = "_system/tokens.json"
    # Source unique de vérité des niveaux de permission valides (flags non
    # hiérarchiques). Utilisée par create() et update(), et référencée par
    # admin/api.py (_api_create_token) pour éviter toute divergence.
    # "wrap" (issue #115) : broker JIT non-admin — donne accès aux seuls outils
    # secret_wrap/secret_revoke_wrap/secret_wrap_lookup/secret_wrap_status, et
    # EXIGE allowed_resources non vide + policy explicite (check_wrap_permission).
    # ⚠️ Downgrade : un tokens.json contenant "wrap" est rejeté ATOMIQUEMENT par
    # les versions < 0.10.0 (whitelist) — révoquer ces tokens avant tout rollback.
    VALID_PERMISSIONS = frozenset({"read", "write", "admin", "wrap"})
    # Borne de POLITIQUE de durée de vie (≈ 100 ans), cohérente avec le cap
    # older_than_days de la purge. Empêche des durées absurdes / abus DoS. Ce n'est
    # PAS la limite d'overflow technique de timedelta (bien plus haute) : c'est un
    # plafond métier. Référencée par validate_expires_in_days() et admin/api.py.
    MAX_EXPIRES_IN_DAYS = 36500

    @staticmethod
    def validate_expires_in_days(value) -> Optional[str]:
        """Valide expires_in_days (issue #65). Retourne None si OK, message sinon.

        Source UNIQUE du contrat (partagée par create() et admin/api.py, pour éviter
        deux validations divergentes) : `0` = jamais expirer (illimité EXPLICITE) ;
        entier dans [1, MAX_EXPIRES_IN_DAYS] = durée en jours. Tout le reste est REFUSÉ
        — ni illimité accidentel, ni TypeError silencieuse :
        - bool est sous-classe d'int → refusé (True/False n'est pas une durée) ;
        - non-int (string, float, None, list…) → refusé ;
        - négatif ou > MAX_EXPIRES_IN_DAYS → refusé.
        """
        if (isinstance(value, bool) or not isinstance(value, int)
                or value < 0 or value > TokenStore.MAX_EXPIRES_IN_DAYS):
            return (f"expires_in_days doit être un entier entre 0 (jamais) "
                    f"et {TokenStore.MAX_EXPIRES_IN_DAYS}")
        return None

    def __init__(self, settings):
        self.settings = settings
        self._tokens: dict = {}  # hash → token_info
        self._cache_time: float = 0.0
        self._s3_client = None
        self._available: bool = True
        self._last_error: str = ""

    # ── État observable (diagnostique seulement, cf. docstring module) ────
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

    def _get_s3_meta(self):
        """Client S3 SigV4 pour HEAD/LIST (métadonnées)."""
        from ..s3_client import get_s3_meta_client
        return get_s3_meta_client()

    @staticmethod
    def _is_missing_key_error(e: Exception) -> bool:
        """True UNIQUEMENT pour l'absence nominale de l'objet tokens.json (NoSuchKey).

        Même logique robuste que PolicyStore/MissionBindingStore : ne se fie JAMAIS
        à une sous-chaîne "404"/"NoSuchKey" dans str(e) — seul botocore
        ClientError.response["Error"]["Code"] == "NoSuchKey" est nominal.
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
        """Passe le store en état INDISPONIBLE observable (diagnostique seulement).

        Ne touche jamais self._tokens. N'empêche AUCUNE lecture/mutation dans ce
        lot (cf. limite documentée en tête de module) — sert uniquement à rendre
        une corruption/panne détectée VISIBLE (logs, futur lot).
        """
        self._available = False
        self._last_error = msg
        self._cache_time = time.time()  # throttle la re-tentative (_maybe_refresh)
        logger.error(
            "Token Store INVALIDE : %s — cache bearer conservé tel quel "
            "(diagnostique seulement dans ce lot, voir docstring module)", msg,
        )

    def load(self):
        """Charge les tokens depuis S3 avec validation atomique (défense en profondeur).

        - Objet absent (NoSuchKey)              → store VIDE mais writable — nominal (1er boot).
        - Réseau/403/timeout/bucket absent       → INVALID, cache conservé, PAS d'écrasement.
        - JSON corrompu / schéma top-level cassé → INVALID (top-level doit être
          exactement {"tokens": [...]} — {} seul n'est PAS traité comme un store
          vide, seul NoSuchKey l'est).
        - hash dupliqué                          → INVALID (jamais un écrasement
          silencieux via la compréhension dict naïve).
        - UNE SEULE entrée non conforme (schéma/permissions/types) → INVALID :
          tout-ou-rien, cohérent avec PolicyStore.load() — un chargement partiel
          ferait confiance à un fichier déclaré corrompu.
        """
        try:
            s3 = self._get_s3_data()
            resp = s3.get_object(Bucket=self.settings.s3_bucket_name, Key=self.S3_KEY)
            raw = resp["Body"].read().decode()
        except Exception as e:
            if self._is_missing_key_error(e):
                self._tokens = {}
                self._cache_time = time.time()
                self._available = True
                self._last_error = ""
                return
            self._mark_invalid(f"S3 GET: {type(e).__name__}")
            return

        try:
            data = json.loads(raw)
        except Exception as e:
            # round diff review : json.loads() peut lever bien plus qu'un
            # ValueError sur une entrée pathologique (ex. RecursionError sur un
            # JSON profondément imbriqué, `[`×2000 `]`×2000) — un except trop
            # étroit laissait cette exception non gérée remonter jusqu'à
            # get_by_hash()/l'authentification bearer au lieu de fail-close.
            self._mark_invalid(f"JSON invalide ({type(e).__name__})")
            return

        if not isinstance(data, dict) or not isinstance(data.get("tokens"), list):
            self._mark_invalid("schéma top-level invalide (attendu {'tokens': [...]})")
            return

        validated: dict = {}
        dirty = False  # migration policy_id "_remove" → "" à re-persister
        for t in data["tokens"]:
            if isinstance(t, dict) and t.get("policy_id") == "_remove":
                dirty = True
            try:
                norm = _validate_and_normalize_token(t)
            except ValueError as e:
                h = t.get("hash") if isinstance(t, dict) else None
                self._mark_invalid(f"token hash={h!r} non conforme: {e}")
                return
            if norm["hash"] in validated:
                self._mark_invalid(f"hash dupliqué: {norm['hash']!r}")
                return
            validated[norm["hash"]] = norm

        self._tokens = validated
        self._cache_time = time.time()
        self._available = True
        self._last_error = ""

        # Migration : nettoie les valeurs "_remove" stockées par erreur
        # (bug SPA < v0.4.11 : l'admin /admin envoyait le sentinel MCP tel quel).
        # La forme en mémoire est déjà propre (normalisée par le validateur) ;
        # on re-persiste pour que le fichier S3 lui-même soit nettoyé.
        if dirty:
            if self._save():
                print("ℹ️  Token Store : migration policy_id '_remove' → '' effectuée.", file=sys.stderr)
            else:
                logger.error("Token Store : migration '_remove' non persistée — S3 indisponible")

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
        # store doit être sûr par lui-même). Cohérent avec update() (source unique
        # _validate_permissions, pas une resaisie divergente).
        permissions, perr = _validate_permissions(permissions)
        if permissions is None:
            return {"status": "error", "error_type": "invalid_permissions", "message": perr}

        # `is None` STRICT (TokenStore hardening) — jamais `x or []` : une valeur
        # falsy invalide (ex. allowed_resources=False) serait sinon silencieusement
        # blanchie en [] AVANT toute validation réelle du contenu.
        allowed_resources = [] if allowed_resources is None else allowed_resources
        allowed_resources, aerr = _validate_allowed_resources(allowed_resources)
        if allowed_resources is None:
            return {"status": "error", "message": aerr}

        # Validation expiration (défense en profondeur, issue #65) : même règle qu'à la
        # frontière HTTP (source unique validate_expires_in_days). Le store doit être sûr
        # par lui-même, quel que soit l'appelant.
        exp_err = self.validate_expires_in_days(expires_in_days)
        if exp_err:
            return {"status": "error", "error_type": "invalid_expiration", "message": exp_err}

        if not isinstance(policy_id, str):
            return {"status": "error", "message": "policy_id doit être une chaîne"}

        import secrets
        from datetime import datetime, timezone, timedelta

        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

        now = datetime.now(timezone.utc)
        expires_at = None
        if expires_in_days > 0:  # 0 = jamais expirer (illimité EXPLICITE, issue #65)
            expires_at = (now + timedelta(days=expires_in_days)).isoformat()

        token_info = {
            "hash": token_hash,
            "client_name": client_name,
            "permissions": permissions,
            "allowed_resources": allowed_resources,
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

        # ── TOUTES les validations AVANT tout effet de bord ──────────────
        # (TokenStore hardening) : un payload invalide ne doit déclencher NI
        # refresh S3 NI résolution de hash NI écriture de migration. Source
        # unique de validation, réutilisée par create()/load() — pas une
        # resaisie locale divergente.
        validated_permissions = None
        if permissions is not None:
            validated_permissions, perr = _validate_permissions(permissions)
            if validated_permissions is None:
                return {"status": "error", "error_type": "invalid_permissions", "message": perr}

        validated_allowed_resources = None
        if allowed_resources is not None:
            validated_allowed_resources, aerr = _validate_allowed_resources(allowed_resources)
            if validated_allowed_resources is None:
                return {"status": "error", "message": aerr}

        validated_policy_id = None
        if policy_id is not None:
            if not isinstance(policy_id, str):
                return {"status": "error", "message": "policy_id doit être une chaîne"}
            # Convertit le sentinel "_remove" en "" pour compatibilité avec l'outil MCP
            validated_policy_id = "" if policy_id == "_remove" else policy_id

        updated_fields = []
        if policy_id is not None:
            updated_fields.append("policy_id")
        if permissions is not None:
            updated_fields.append("permissions")
        if allowed_resources is not None:
            updated_fields.append("allowed_resources")

        if not updated_fields:
            return {"status": "error", "message": "Aucun champ à modifier"}

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

        # ── Snapshot AVANT mutation pour rollback si _save échoue ────────
        import copy
        snapshot = copy.deepcopy(dict(token))

        # ── Mutations uniquement après validation et snapshot ─────────────
        if policy_id is not None:
            token["policy_id"] = validated_policy_id

        if permissions is not None:
            token["permissions"] = validated_permissions

        if allowed_resources is not None:
            token["allowed_resources"] = validated_allowed_resources

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
