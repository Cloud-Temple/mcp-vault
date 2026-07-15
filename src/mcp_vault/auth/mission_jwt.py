# -*- coding: utf-8 -*-
"""
PEP mission JWT (issue #47) — cache JWKS partagé + validation du mission_token.

Ce module est le **cache JWKS unique du processus** (anti-divergence — Codex bloqueur #1
du plan v2). Il est consommé par :
  - `AuthMiddleware` (validation du bearer entrant sur /mcp, contrat 9 étapes) ;
  - `MissionTokenValidator` (auth/jwt_validator.py) qui délègue ici la résolution de
    clé pour `secret_consume` — ainsi il n'existe QU'UN cache JWKS et un seul rate-limit
    effectif face à l'endpoint JWKS de mcp-mission.

Sécurité :
  - ES256 uniquement (ECDSA P-256). Refus catégorique de tout autre `alg` (anti alg=none,
    anti confusion RS/ES).
  - Fail-close : un cache JWKS EXPIRÉ n'est JAMAIS servi. Si le refresh échoue et que le
    cache est périmé → JWKSUnavailable (503). Pas de clé périmée acceptée.
  - Backoff exponentiel + jitter sur échec de fetch (anti-DoS de l'endpoint JWKS).
  - HTTP conditionnel ETag/If-None-Match → 304 (économie de bande passante, révocation
    propagée au TTL).
  - Jamais de secret manipulé (un JWKS ne contient que des clés PUBLIQUES) ; jamais le
    token compact ni un claim sensible dans les logs (seul le type d'erreur).

Ce module NE DOIT PAS importer hvac (ni transitivement) : il doit rester importable dans
les tests unitaires sans OpenBao. Import autorisés : jwt (PyJWT), httpx, stdlib.
"""

import json
import logging
import random
import threading
import time
from typing import Callable, Optional

import httpx
import jwt as _pyjwt
from jwt.algorithms import ECAlgorithm

logger = logging.getLogger("mcp-vault.mission-jwt")

# Contrat mcp-mission (vérifié dans le code émetteur v0.5.0, cf. Cloud-Temple/starter-kit#14, §17.10).
_ALG = "ES256"
_ISS = "mcp-mission"

# Backoff exponentiel sur échec de fetch JWKS.
_BACKOFF_BASE_SECONDS = 1.0
_BACKOFF_MAX_SECONDS = 30.0
_BACKOFF_JITTER = 0.2  # ±20 %

# Intervalle minimal entre deux refresh JWKS déclenchés par un `kid` INCONNU
# (anti-DoS : sans ça, un flot de JWT à kids aléatoires provoquerait un fetch
# réseau par requête). Un refresh réussi ne « désarme » pas le backoff d'échec ;
# ce throttle est distinct et borne les refresh « kid inconnu » à 1 par fenêtre,
# quel que soit le volume d'attaque. force_reload() (admin) est le seul bypass.
_UNKNOWN_KID_MIN_REFRESH_INTERVAL = 10.0

# NB : le mission_token NE PORTE PAS de claim `vaults` ni `permissions` (contrat réel mcp-mission
# vérifié). L'autorisation vault est LOCALE à mcp-vault (MissionBindingStore, keyé par tenant_id —
# livré dans une PR ultérieure). Ce module ne fait qu'authentifier + lier à l'instance.


# ── Exceptions (mappées vers des statuts HTTP par le middleware) ────────────────

class MissionTokenInvalid(Exception):
    """Token absent/malformé/signature/exp/iat/iss/kid/claim invalide → 401.

    `reason` est un code machine SANS le token ni de donnée sensible.
    """

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class MissionTokenForbidden(Exception):
    """Token authentique mais aud/component_id non conforme à cette instance → 403.

    Porte les claims VÉRIFIÉS (signature/exp/iss OK) : le refus concerne un token
    authentifié, l'audit doit en tracer l'identité (tenant_id/mission_id/jti).
    """

    def __init__(self, reason: str, claims: Optional[dict] = None):
        self.reason = reason
        self.claims = claims or {}
        super().__init__(reason)


class JWKSUnavailable(Exception):
    """JWKS indisponible (cache expiré + fetch impossible) → 503 (fail-close)."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


# ── Fetch HTTP par défaut (injectable pour les tests) ───────────────────────────

def _default_http_fetch(
    url: str, etag: Optional[str], timeout: float
) -> tuple[int, Optional[str], Optional[bytes]]:
    """Fetch HTTP conditionnel du JWKS.

    Returns:
        (status, etag, body) — body=None si 304. Lève httpx.HTTPError/OSError sur échec
        réseau (capturé par _refetch_locked → backoff).
    """
    headers = {}
    if etag:
        headers["If-None-Match"] = etag
    resp = httpx.get(url, headers=headers, timeout=timeout, follow_redirects=False)
    new_etag = resp.headers.get("etag")
    if resp.status_code == 304:
        return 304, new_etag or etag, None
    return resp.status_code, new_etag, resp.content


class JWKSCache:
    """Cache thread-safe du JWKS de mcp-mission (fail-close, backoff, ETag/304).

    `fetch` et `time_func` sont injectables pour des tests déterministes (aucun réseau,
    aucune horloge réelle).
    """

    def __init__(
        self,
        url: str,
        ttl_seconds: int,
        *,
        fetch: Callable[[str, Optional[str], float], tuple[int, Optional[str], Optional[bytes]]] = _default_http_fetch,
        timeout: float = 5.0,
        time_func: Callable[[], float] = time.monotonic,
    ) -> None:
        if not url:
            raise ValueError("url JWKS requise pour JWKSCache")
        self._url = url
        self._ttl = ttl_seconds
        self._fetch = fetch
        self._timeout = timeout
        self._now = time_func
        self._lock = threading.Lock()

        # État du cache.
        self._keys_by_kid: dict[str, dict] = {}
        self._etag: Optional[str] = None
        self._fetched_at: Optional[float] = None  # None = jamais peuplé.

        # État du backoff.
        self._next_attempt_at: float = 0.0
        self._fail_count: int = 0
        # Throttle des refresh déclenchés par un kid inconnu (anti-DoS).
        self._last_unknown_kid_refresh_at: float = 0.0

    # -- API publique -----------------------------------------------------------

    def get_key(self, kid: str) -> dict:
        """Retourne le JWK (dict) correspondant au `kid`, cache rafraîchi si besoin.

        Raises:
            JWKSUnavailable    : cache expiré + impossible de (re)fetch.
            MissionTokenInvalid: JWKS disponible mais `kid` inconnu/révoqué.
        """
        with self._lock:
            self._ensure_fresh_locked()
            key = self._keys_by_kid.get(kid)
            if key is None:
                # kid absent : rotation très récente ? On tente UN refresh forcé,
                # MAIS throttlé (anti-DoS) : au plus un refresh « kid inconnu » par
                # _UNKNOWN_KID_MIN_REFRESH_INTERVAL, quel que soit le volume de kids
                # inconnus reçus. Sinon → rejet immédiat sans fetch réseau.
                now = self._now()
                if (self._fetched_at is not None and self._can_attempt_locked()
                        and (now - self._last_unknown_kid_refresh_at)
                        >= _UNKNOWN_KID_MIN_REFRESH_INTERVAL):
                    self._last_unknown_kid_refresh_at = now
                    try:
                        self._refetch_locked(force=True)
                    except JWKSUnavailable:
                        pass
                    key = self._keys_by_kid.get(kid)
            if key is None:
                # kid réellement inconnu → token non authentique (révoqué ou jamais
                # publié). Refus sans révéler la liste des kid connus.
                raise MissionTokenInvalid("unknown_kid")
            return key

    def force_reload(self) -> int:
        """Force un refresh JWKS immédiat (réinitialise le backoff).

        Utilisé par l'endpoint admin POST /admin/api/auth/jwks/reload pour propager une
        révocation urgente de kid sans attendre le TTL.

        Returns:
            Nombre de clés chargées après reload.

        Raises:
            JWKSUnavailable si le fetch échoue.
        """
        with self._lock:
            self._fail_count = 0
            self._next_attempt_at = 0.0
            self._last_unknown_kid_refresh_at = 0.0  # admin = bypass du throttle
            self._refetch_locked(force=True)
            return len(self._keys_by_kid)

    def key_count(self) -> int:
        """Nombre de clés actuellement en cache (diagnostic)."""
        with self._lock:
            return len(self._keys_by_kid)

    # -- Interne (sous _lock) ---------------------------------------------------

    def _is_fresh_locked(self) -> bool:
        return self._fetched_at is not None and (self._now() - self._fetched_at) < self._ttl

    def _can_attempt_locked(self) -> bool:
        return self._now() >= self._next_attempt_at

    def _reset_backoff_locked(self) -> None:
        self._fail_count = 0
        self._next_attempt_at = 0.0

    def _backoff_delay_locked(self) -> float:
        exp = min(
            _BACKOFF_MAX_SECONDS,
            _BACKOFF_BASE_SECONDS * (2 ** max(0, self._fail_count - 1)),
        )
        jitter = exp * _BACKOFF_JITTER
        return max(0.0, exp + random.uniform(-jitter, jitter))

    def _schedule_backoff_locked(self) -> None:
        self._fail_count += 1
        self._next_attempt_at = self._now() + self._backoff_delay_locked()

    def _ensure_fresh_locked(self) -> None:
        """Garantit un cache exploitable, ou lève JWKSUnavailable (FAIL-CLOSE).

        Un cache expiré n'est JAMAIS servi : pas de fallback sur cache périmé.
        """
        if self._is_fresh_locked():
            return

        if self._can_attempt_locked():
            try:
                self._refetch_locked(force=False)
            except JWKSUnavailable:
                pass  # décision fail-close ci-dessous.

        if not self._is_fresh_locked():
            raise JWKSUnavailable("jwks_unavailable")

    def _refetch_locked(self, *, force: bool) -> None:
        """Fetch HTTP conditionnel (ETag) + mise à jour du cache.

        `force=True` ignore la fenêtre de backoff (reload admin, retry kid). Sur échec :
        programme le prochain essai (backoff + jitter) et lève JWKSUnavailable.
        """
        if not force and not self._can_attempt_locked():
            raise JWKSUnavailable("jwks_backoff")

        try:
            status, etag, body = self._fetch(self._url, self._etag, self._timeout)
        except (httpx.HTTPError, OSError, ValueError) as exc:
            self._schedule_backoff_locked()
            logger.warning(
                "JWKS fetch échec (%s) — backoff #%d", type(exc).__name__, self._fail_count
            )
            raise JWKSUnavailable("jwks_fetch_error") from exc

        if status == 304:
            if self._fetched_at is None:
                # 304 sans cache initial : anomalie serveur → fail-close.
                self._schedule_backoff_locked()
                raise JWKSUnavailable("jwks_304_without_cache")
            self._fetched_at = self._now()  # prolonge la fraîcheur.
            self._reset_backoff_locked()
            return

        if status != 200 or not body:
            self._schedule_backoff_locked()
            raise JWKSUnavailable(f"jwks_http_{status}")

        try:
            keys = self._parse_jwks(body)
        except ValueError as exc:
            # JWKS malformé : ne PAS corrompre le cache existant.
            self._schedule_backoff_locked()
            logger.warning("JWKS malformé (%s) — backoff", type(exc).__name__)
            raise JWKSUnavailable("jwks_malformed") from exc

        self._keys_by_kid = keys
        self._etag = etag
        self._fetched_at = self._now()
        self._reset_backoff_locked()
        logger.info("JWKS rafraîchi depuis %s — %d clé(s) ES256/P-256", self._url, len(keys))

    @staticmethod
    def _parse_jwks(body: bytes) -> dict[str, dict]:
        """Parse un document JWKS → dict {kid: jwk}. Ne garde que les clés EC/P-256.

        Raises:
            ValueError si le document est malformé ou ne contient aucune clé exploitable.
        """
        try:
            doc = json.loads(body)
        except Exception as exc:
            raise ValueError("json_decode") from exc

        if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list):
            raise ValueError("no_keys_array")

        keys: dict[str, dict] = {}
        for jwk in doc["keys"]:
            if not isinstance(jwk, dict):
                continue
            if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
                continue
            kid = jwk.get("kid")
            if not isinstance(kid, str) or not kid:
                continue
            keys[kid] = jwk

        if not keys:
            raise ValueError("no_usable_ec_p256_keys")
        return keys


# ── Singleton process-wide ──────────────────────────────────────────────────────

_jwks_cache: Optional[JWKSCache] = None


def init_jwks_cache(
    url: str,
    ttl_seconds: int,
    *,
    fetch: Optional[Callable] = None,
) -> Optional[JWKSCache]:
    """Initialise le cache JWKS singleton process-wide.

    Appelé une fois au startup (lifecycle) et par init_mission_token_validator.
    Retourne None si `url` est vide (mode standalone sans mcp-mission).
    Idempotent : réutilise l'instance existante si l'URL est inchangée.
    """
    global _jwks_cache
    if not url:
        _jwks_cache = None
        return None
    if _jwks_cache is not None and _jwks_cache._url == url:
        return _jwks_cache
    kwargs = {"fetch": fetch} if fetch is not None else {}
    _jwks_cache = JWKSCache(url, ttl_seconds, **kwargs)
    logger.info("JWKSCache singleton initialisé (jwks=%s, ttl=%ds)", url, ttl_seconds)
    return _jwks_cache


def get_jwks_cache() -> Optional[JWKSCache]:
    """Retourne le cache JWKS singleton, ou None si non configuré."""
    return _jwks_cache


# ── Discriminant structurel JWT vs bearer opaque ────────────────────────────────

def looks_like_jwt(token: str) -> bool:
    """Détermine si un token est STRUCTURELLEMENT un JWT compact.

    Critère purement structurel : 3 segments séparés par '.', premier segment
    décodable en JSON portant un champ "alg". La VALEUR d'alg n'entre PAS dans le
    discriminant (anti alg-confusion) : un compact JWT alg=none/HS256 est routé vers
    la validation JWT, qui le REJETTE en 401 — il ne retombe jamais sur le chemin
    bearer opaque en dual-stack.

    Les bearers du Token Store (secrets.token_urlsafe) n'ont pas 3 segments : jamais
    confondus.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return False
    try:
        padded = parts[0] + "=" * (-len(parts[0]) % 4)
        import base64
        header = json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return False
    return isinstance(header, dict) and "alg" in header


# ── Validation PEP du mission_token (contrat réel mcp-mission v0.5.0) ───────────

def validate_mission_token(
    token: str,
    jwks_cache: JWKSCache,
    *,
    instance_id: str,
    component_kind: str,
    iat_leeway: int,
    now: Optional[float] = None,
) -> dict:
    """Valide un mission_token bearer selon le contrat RÉEL de mcp-mission.

    Étapes (fail-close à chaque étape) :
      1. Structure compact JWT ; header → alg (ES256 strict), kid requis.
      2. Clé publique via kid (JWKSCache — refresh sur kid inconnu, fail-close).
      3. Signature ES256 + exp (leeway 0 — la grâce de refresh 300s est INTERNE au
         broker mcp-mission, PAS une tolérance PEP) + iss + claims requis.
      4. iat <= now + iat_leeway (anti-skew horloge avancée ; leeway séparé de exp).
      5. Typage strict : mission_id/jti/tenant_id str non vides, scope list[str]
         non vide (opaque — jamais interprété comme autorisation).
      6. aud (str ou list[str] — RFC 7519) doit CONTENIR instance_id → sinon 403.
      7. component_id dict avec component_id[component_kind] == instance_id → sinon 403.

    Le token compact n'apparaît JAMAIS dans les logs ni les exceptions.

    Raises:
        MissionTokenInvalid   : token malformé/signature/exp/iat/iss/kid/claims → 401.
        MissionTokenForbidden : token authentique mais aud/component_id ≠ instance → 403.
        JWKSUnavailable       : JWKS indisponible (fail-close) → 503.
    """
    if not token or token.count(".") != 2:
        raise MissionTokenInvalid("not_a_jwt")

    # 1. Header → alg + kid (sans vérification de signature).
    try:
        header = _pyjwt.get_unverified_header(token)
    except _pyjwt.PyJWTError:
        raise MissionTokenInvalid("bad_header")

    if header.get("alg") != _ALG:
        # Refus catégorique de tout algo ≠ ES256 (anti alg=none, anti confusion RS/ES).
        raise MissionTokenInvalid("bad_alg")

    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise MissionTokenInvalid("missing_kid")

    # 2. Clé publique (lève JWKSUnavailable ou MissionTokenInvalid("unknown_kid")).
    jwk = jwks_cache.get_key(kid)
    try:
        public_key = ECAlgorithm.from_jwk(json.dumps(jwk))
    except Exception as exc:  # noqa: BLE001 — JWK corrompu = token non vérifiable
        logger.warning("JWK ES256 illisible pour kid (%s)", type(exc).__name__)
        raise MissionTokenInvalid("bad_jwk")

    # 3. Signature + exp (leeway 0) + iss + claims requis. aud/iat vérifiés
    #    manuellement (aud → 403 distinct ; iat → anti-skew futur).
    try:
        claims = _pyjwt.decode(
            token,
            public_key,
            algorithms=[_ALG],
            issuer=_ISS,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": False,   # vérifié manuellement (étape 4)
                "verify_aud": False,   # vérifié manuellement (étape 6, 403 distinct)
                "require": ["exp", "iat", "iss", "aud", "mission_id", "jti",
                            "scope", "tenant_id"],
            },
            leeway=0,  # grâce 0 côté PEP — le refresh est géré côté broker mcp-mission
        )
    except _pyjwt.ExpiredSignatureError:
        raise MissionTokenInvalid("expired")
    except _pyjwt.InvalidIssuerError:
        raise MissionTokenInvalid("bad_iss")
    except _pyjwt.MissingRequiredClaimError as exc:
        logger.warning("mission_token claim requis manquant (%s)", getattr(exc, "claim", "?"))
        raise MissionTokenInvalid("missing_claim")
    except _pyjwt.InvalidSignatureError:
        logger.warning("mission_token signature invalide")
        raise MissionTokenInvalid("bad_signature")
    except _pyjwt.PyJWTError as exc:
        logger.warning("mission_token rejeté (%s)", type(exc).__name__)
        raise MissionTokenInvalid("invalid")

    # 4. Anti-skew iat : un token daté dans le futur au-delà du leeway est suspect.
    ref = time.time() if now is None else now
    iat = claims.get("iat")
    if not isinstance(iat, (int, float)) or iat > ref + iat_leeway:
        logger.warning("mission_token iat dans le futur au-delà du skew toléré")
        raise MissionTokenInvalid("iat_future")

    # 5. Claims de traçabilité/identité : obligatoires et typés strictement.
    mission_id = claims.get("mission_id")
    if not isinstance(mission_id, str) or not mission_id:
        raise MissionTokenInvalid("bad_mission_id")

    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti:
        raise MissionTokenInvalid("bad_jti")

    tenant_id = claims.get("tenant_id")
    if not isinstance(tenant_id, str) or not tenant_id:
        # Contrat mcp-mission : jamais émis vide en mode broker (fail-close émetteur).
        raise MissionTokenInvalid("bad_tenant_id")

    scope = claims.get("scope")
    if not isinstance(scope, list) or not scope \
            or not all(isinstance(s, str) and s for s in scope):
        raise MissionTokenInvalid("bad_scope")
    # NB : scope est OPAQUE (enveloppe "{ref}:mission/{id}:*") — jamais interprété
    # comme une autorisation fine (contrat mcp-mission, décision A4).

    # 6. aud doit contenir l'identifiant d'instance de CE vault (anti-confused-deputy).
    #    str ou list[str] (RFC 7519) ; toute autre forme = malformé → 401, jamais 500.
    aud = claims.get("aud")
    if isinstance(aud, str):
        aud_values = [aud]
    elif isinstance(aud, list) and all(isinstance(a, str) for a in aud):
        aud_values = aud
    else:
        raise MissionTokenInvalid("bad_aud")
    if instance_id not in aud_values:
        logger.warning("mission_token aud ne contient pas l'instance configurée")
        raise MissionTokenForbidden("wrong_audience", claims=claims)

    # 7. component_id[kind] doit désigner CETTE instance (clé littérale, ex "vault").
    component_id = claims.get("component_id")
    if not isinstance(component_id, dict) or component_id.get(component_kind) != instance_id:
        logger.warning("mission_token component_id ne correspond pas à l'instance/kind configurés")
        raise MissionTokenForbidden("component_id_mismatch", claims=claims)

    return claims


# ── Vérification mission active (déplacée depuis server.py — issue #47) ─────────
# Le middleware PEP et secret_consume partagent ce check et son cache.

_mission_status_cache: dict[str, tuple[bool, float]] = {}
import asyncio as _asyncio_for_lock
_mission_status_lock = _asyncio_for_lock.Lock()
del _asyncio_for_lock

# Allow-list des états dans lesquels mcp-mission continue d'émettre/re-signer des
# tokens (contrat confirmé : _REFRESHABLE = {RUNNING, WAITING_HUMAN, PAUSED} — une
# mission PAUSED reçoit des tokens re-signés). Tout autre état, état inconnu ou champ
# absent = INACTIF (fail-close — corrige la deny-list historique qui traitait un état
# inconnu comme actif).
_ACTIVE_MISSION_STATES = frozenset({"RUNNING", "WAITING_HUMAN", "PAUSED"})


async def check_mission_active(
    mission_id: str, status_url_template: str, cache_ttl: int
) -> tuple[bool, str]:
    """Vérifie si une mission est active auprès de mcp-mission.

    Retourne (True, "") si active, (False, raison) sinon.
    Fail-close : erreur de connexion, HTTP != 200, état hors allow-list → inactive.
    Cache TTL court pour réduire la fenêtre post-abort (mcp-mission recommande ≤ 30s).
    """
    import time as _time
    now = _time.time()
    async with _mission_status_lock:
        if mission_id in _mission_status_cache:
            cached_ok, cached_at = _mission_status_cache[mission_id]
            if now - cached_at < cache_ttl:
                return cached_ok, "" if cached_ok else "mission_inactive_cached"

    try:
        url = status_url_template.format(mission_id=mission_id)
        async with httpx.AsyncClient(timeout=3.0) as http:
            resp = await http.get(url)
        if resp.status_code == 200:
            body = resp.json()
            state = str(body.get("status", body.get("state", "")))
            active = state.upper() in _ACTIVE_MISSION_STATES
            async with _mission_status_lock:
                _mission_status_cache[mission_id] = (active, now)
            if active:
                return True, ""
            # #78/D5 : reason FERMÉ — l'état renvoyé par le service mission est une valeur
            # EXTERNE ; on la loggue côté serveur mais on ne la reflète jamais dans le code
            # d'erreur (renvoyé au client / versé à l'audit).
            logger.info("check_mission_active: mission %s inactive (state=%s)",
                        mission_id[:16], state)
            return False, "mission_inactive"
        # 404 = mission inconnue → fail-close ; code HTTP non reflété dans le reason.
        logger.info("check_mission_active: mission %s → HTTP %s",
                    mission_id[:16], resp.status_code)
        return False, "mission_status_error"
    except Exception as e:
        logger.error("check_mission_active error: %s", type(e).__name__)
        return False, "service_unavailable"
