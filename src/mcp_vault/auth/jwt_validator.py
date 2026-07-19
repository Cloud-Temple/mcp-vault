# -*- coding: utf-8 -*-
"""
Validateur JWT mission_token (ES256/JWKS) — Issue #26, anti-confused-deputy C18.

Usage :
    from mcp_vault.auth.jwt_validator import MissionTokenValidator, MissionTokenError

    validator = MissionTokenValidator(
        jwks_url="https://mcp-mission/.well-known/jwks.json",
        expected_aud="mcp-vault:prod:v1",
    )
    try:
        claims = validator.validate(token_compact)
    except MissionTokenError as e:
        # e.reason = code d'erreur ("invalid_signature", "token_expired", ...)
        # Jamais le token compact dans e.reason ni dans les logs

Sécurité :
    - ES256 uniquement (ECDSA P-256)
    - Depuis le Lot 2 (issue #86, finding 2) : `validate()` délègue intégralement à
      `mission_jwt.validate_mission_token()` — le MÊME contrat que le PEP /mcp
      (issue #47). Avant ce lot, ce validateur dupliquait sa propre logique
      `jwt.decode()`, en retard sur le PEP : `iat`, `jti`, `tenant_id`, `scope` et
      surtout `component_id` n'étaient PAS vérifiés ici, ouvrant un chemin où un
      mission_token authentique mais destiné à une AUTRE instance vault (aud
      multiple, component_id différent) passait C18 alors que le PEP l'aurait
      refusé. Résolution des clés déléguée au JWKSCache partagé (auth/mission_jwt.py) :
      UN SEUL cache JWKS process-wide (TTL, backoff exponentiel + jitter, ETag/304,
      fail-close) partagé entre ce validateur (secret_consume) et le PEP /mcp
      (AuthMiddleware).
    - `exp` est désormais STRICT (leeway=0), comme le PEP — le durcissement
      recherché. `leeway_seconds`/`MISSION_TOKEN_LEEWAY_SECONDS` ne s'applique
      QU'À `iat` (anti-skew horloge future), jamais à `exp` (auparavant ce paramètre
      était placé dans `options={"leeway": ...}` de `jwt.decode()`, où PyJWT
      l'ignore silencieusement — le leeway effectif sur `exp` était déjà 0 de
      fait ; ce lot rend ce comportement explicite et intentionnel).
    - kid absent du JWKS après refresh = token rejeté (révocation implicite)
    - Jamais le token compact dans les messages d'erreur ni les logs

Standalone (sans mcp-mission) :
    Quand MISSION_JWKS_URL est vide, MissionTokenValidator n'est pas instancié
    et secret_consume fonctionne en mode non-enforced (log warning si ENFORCE=false,
    hard-reject si ENFORCE=true).
"""

import logging
from typing import Optional

from .mission_jwt import (
    JWKSCache,
    JWKSUnavailable,
    MissionTokenForbidden,
    MissionTokenInvalid,
    get_jwks_cache,
    init_jwks_cache,
    validate_mission_token,
)

logger = logging.getLogger("mcp-vault.jwt-validator")

# Contrat mcp-mission : issuer figé, non configurable (aligné sur mission_jwt._ISS).
_EXPECTED_ISS = "mcp-mission"

# ── Mapping des reasons internes (mission_jwt.py, contrat PEP) vers le vocabulaire
# historique C18 (contrat de ce module, antérieur au Lot 2 — issue #86 finding 2).
# Objectif : ne pas changer inutilement le wording des logs serveur / de la doc
# technique existants pour les cas déjà couverts avant ce lot. Les nouveaux
# contrôles (absents avant ce lot) reçoivent des codes stables inédits.
_INVALID_REASON_MAP = {
    "not_a_jwt": "invalid_token_format",
    "bad_header": "invalid_token_format",
    "bad_alg": "unsupported_algorithm",
    "missing_kid": "kid_unknown_or_revoked",
    "unknown_kid": "kid_unknown_or_revoked",
    "bad_jwk": "jwks_unavailable",
    "expired": "token_expired",
    "bad_iss": "invalid_issuer",
    # "missing_claim"/"missing_claim:<claim>" : géré à part dans validate() (préfixe
    # dynamique, cf. ci-dessous) — pas d'entrée ici, une seule clé ne peut pas
    # représenter toutes les combinaisons "missing_claim:<claim>" possibles.
    "bad_signature": "invalid_signature",
    "invalid": "validation_failed",
    "bad_aud": "invalid_audience",
    # Nouveaux contrôles (issue #86 finding 2) : pas d'équivalent historique C18.
    "iat_future": "iat_future",
    "bad_mission_id": "bad_mission_id",
    "bad_jti": "bad_jti",
    "bad_tenant_id": "bad_tenant_id",
    "bad_scope": "bad_scope",
}

_FORBIDDEN_REASON_MAP = {
    "wrong_audience": "invalid_audience",
    # Nouveau contrôle (issue #86 finding 2) : pas d'équivalent historique C18.
    "component_id_mismatch": "component_id_mismatch",
}


class MissionTokenError(Exception):
    """
    Erreur de validation JWT — ne contient JAMAIS le token compact.

    Attributes:
        reason: Code d'erreur lisible machine (ex: "invalid_signature",
                "token_expired", "kid_unknown_or_revoked", "invalid_audience",
                ou l'un des nouveaux codes du Lot 2 : "iat_future", "bad_mission_id",
                "bad_jti", "bad_tenant_id", "bad_scope", "component_id_mismatch").
                Ne jamais inclure le token compact ou des données sensibles.
    """

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class MissionTokenValidator:
    """
    Validateur JWT ES256 pour le mission_token PARAMÈTRE de secret_consume.

    Depuis le Lot 2 (issue #86), `validate()` délègue à
    `mission_jwt.validate_mission_token()` — le même contrat que le PEP /mcp
    (mêmes claims requis : exp, iat, iss, aud, mission_id, jti, scope, tenant_id ;
    même vérification component_id[component_kind] == instance_id). La résolution
    des clés passe par le JWKSCache partagé (singleton process-wide, injectable
    pour les tests via `jwks_cache`). Thread-safe (le cache l'est).
    """

    def __init__(
        self,
        jwks_url: str,
        expected_iss: str = "mcp-mission",
        expected_aud: str = "",
        cache_ttl: int = 60,
        max_refresh_per_min: int = 3,
        leeway_seconds: int = 10,
        jwks_cache: Optional[JWKSCache] = None,
        component_kind: str = "vault",
    ):
        if not jwks_url:
            raise ValueError("jwks_url requis pour MissionTokenValidator")
        if expected_iss != _EXPECTED_ISS:
            # Le contrat mcp-mission fixe iss="mcp-mission" (mission_jwt._ISS,
            # partagé avec le PEP) — un override donnerait l'illusion trompeuse
            # d'un issuer configurable alors qu'il ne l'est plus depuis le Lot 2.
            raise ValueError(
                f"expected_iss='{expected_iss}' non supporté — le contrat "
                f"mcp-mission fixe l'issuer à '{_EXPECTED_ISS}' (non configurable "
                "depuis l'alignement sur le PEP, issue #86)."
            )
        self._expected_aud = expected_aud
        self._cache_ttl = cache_ttl
        # max_refresh_per_min : conservé pour compatibilité de signature — le
        # rate-limit fenêtré est remplacé par le backoff exponentiel du JWKSCache.
        self._leeway = leeway_seconds
        self._jwks_url = jwks_url
        self._jwks_cache = jwks_cache  # None = résolu au singleton à l'usage
        self._component_kind = component_kind

    def _get_cache(self) -> JWKSCache:
        """Retourne le cache JWKS (injecté, sinon singleton — initialisé au besoin)."""
        if self._jwks_cache is not None:
            return self._jwks_cache
        cache = get_jwks_cache()
        if cache is None:
            cache = init_jwks_cache(self._jwks_url, self._cache_ttl)
        return cache

    def validate(self, token_compact: str) -> dict:
        """
        Valide un JWT mission_token ES256 selon le contrat PEP (issue #47/#86).

        Args:
            token_compact: JWT compact (jamais loggué ni inclus dans les erreurs).

        Returns:
            dict des claims si valide : iss, aud, exp, iat, mission_id, jti,
            tenant_id, scope, component_id.

        Raises:
            MissionTokenError: reason = code d'erreur machine (sans le token).
        """
        # Filet défensif : l'API publique de ce validateur ne doit jamais laisser
        # fuir un TypeError/AttributeError sur une entrée non-string — seul
        # MissionTokenError est un contrat garanti pour les appelants directs.
        if not isinstance(token_compact, str):
            raise MissionTokenError("invalid_token_format")

        if not self._expected_aud:
            # Sans audience configurée, aucune instance ne peut être vérifiée —
            # la validation échouerait de toute façon (aud/component_id ne
            # matcheront jamais une chaîne vide). Fail-fast explicite plutôt que de
            # déléguer vers un rejet 403 dont la vraie cause serait masquée.
            raise MissionTokenError("misconfigured_expected_aud")

        try:
            claims = validate_mission_token(
                token_compact,
                self._get_cache(),
                instance_id=self._expected_aud,
                component_kind=self._component_kind,
                iat_leeway=self._leeway,
            )
        except MissionTokenInvalid as e:
            # "missing_claim[:<claim>]" est déjà au format historique C18 attendu
            # (préserve le nom du claim, cf. mission_jwt.validate_mission_token) —
            # ne PAS le passer par le dict, qui ne peut pas connaître à l'avance
            # chaque combinaison "missing_claim:<claim>" possible.
            if e.reason.startswith("missing_claim"):
                raise MissionTokenError(e.reason) from None
            raise MissionTokenError(_INVALID_REASON_MAP.get(e.reason, "validation_failed")) from None
        except MissionTokenForbidden as e:
            raise MissionTokenError(_FORBIDDEN_REASON_MAP.get(e.reason, "invalid_audience")) from None
        except JWKSUnavailable:
            raise MissionTokenError("jwks_unavailable") from None

        return claims


# ── Singleton process-wide (P0 — issue #29) ────────────────────────────────────
# Un seul validateur partagé pour tout le processus, adossé au JWKSCache singleton
# (issue #47) : cache JWKS et anti-DoS (backoff) effectivement globaux.
_validator: Optional["MissionTokenValidator"] = None


def init_mission_token_validator(
    jwks_url: str,
    expected_aud: str = "",
    cache_ttl: int = 60,
    max_refresh_per_min: int = 3,
    leeway_seconds: int = 10,
    component_kind: str = "vault",
) -> Optional["MissionTokenValidator"]:
    """
    Initialise le validateur singleton process-wide.
    Appelé une fois au startup depuis lifecycle.py.
    Retourne None si jwks_url est vide (mode standalone sans mcp-mission).

    Initialise aussi le JWKSCache singleton partagé (issue #47) — le PEP /mcp
    (AuthMiddleware) et ce validateur utilisent le MÊME cache.
    """
    global _validator
    if not jwks_url:
        _validator = None
        return None
    init_jwks_cache(jwks_url, cache_ttl)
    _validator = MissionTokenValidator(
        jwks_url=jwks_url,
        expected_aud=expected_aud,
        cache_ttl=cache_ttl,
        max_refresh_per_min=max_refresh_per_min,
        leeway_seconds=leeway_seconds,
        component_kind=component_kind,
    )
    logger.info("MissionTokenValidator singleton initialisé (jwks=%s)", jwks_url)
    return _validator


def get_mission_token_validator() -> Optional["MissionTokenValidator"]:
    """Retourne le singleton process-wide, ou None si non configuré."""
    return _validator
