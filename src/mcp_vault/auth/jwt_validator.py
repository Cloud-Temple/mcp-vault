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
    - Résolution des clés déléguée au JWKSCache partagé (auth/mission_jwt.py) :
      UN SEUL cache JWKS process-wide (TTL, backoff exponentiel + jitter, ETag/304,
      fail-close) partagé entre ce validateur (secret_consume) et le PEP /mcp
      (AuthMiddleware) — issue #47. Plus de cache/rate-limit propre ici.
    - kid absent du JWKS après refresh = token rejeté (révocation implicite)
    - Jamais le token compact dans les messages d'erreur ni les logs

Standalone (sans mcp-mission) :
    Quand MISSION_JWKS_URL est vide, MissionTokenValidator n'est pas instancié
    et secret_consume fonctionne en mode non-enforced (log warning si ENFORCE=false,
    hard-reject si ENFORCE=true).
"""

import json
import logging
from typing import Optional

import jwt
from jwt.algorithms import ECAlgorithm

from .mission_jwt import (
    JWKSCache,
    JWKSUnavailable,
    MissionTokenInvalid,
    get_jwks_cache,
    init_jwks_cache,
)

logger = logging.getLogger("mcp-vault.jwt-validator")


class MissionTokenError(Exception):
    """
    Erreur de validation JWT — ne contient JAMAIS le token compact.

    Attributes:
        reason: Code d'erreur lisible machine (ex: "invalid_signature",
                "token_expired", "kid_unknown_or_revoked", "invalid_audience").
                Ne jamais inclure le token compact ou des données sensibles.
    """

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class MissionTokenValidator:
    """
    Validateur JWT ES256 pour le mission_token PARAMÈTRE de secret_consume.

    La résolution des clés passe par le JWKSCache partagé (singleton process-wide,
    injectable pour les tests via `jwks_cache`). Thread-safe (le cache l'est).
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
    ):
        if not jwks_url:
            raise ValueError("jwks_url requis pour MissionTokenValidator")
        self._jwks_url = jwks_url
        self._expected_iss = expected_iss
        self._expected_aud = expected_aud
        self._cache_ttl = cache_ttl
        # max_refresh_per_min : conservé pour compatibilité de signature — le
        # rate-limit fenêtré est remplacé par le backoff exponentiel du JWKSCache.
        self._leeway = leeway_seconds
        self._jwks_cache = jwks_cache  # None = résolu au singleton à l'usage

    def _get_cache(self) -> JWKSCache:
        """Retourne le cache JWKS (injecté, sinon singleton — initialisé au besoin)."""
        if self._jwks_cache is not None:
            return self._jwks_cache
        cache = get_jwks_cache()
        if cache is None:
            cache = init_jwks_cache(self._jwks_url, self._cache_ttl)
        return cache

    def _get_signing_key(self, kid: str):
        """Résout la clé de signature pour kid via le JWKSCache partagé.

        Le cache gère TTL, refresh forcé sur kid inconnu, backoff et fail-close.
        Mappe les exceptions du cache vers MissionTokenError (codes historiques
        attendus par secret_consume).
        """
        try:
            jwk = self._get_cache().get_key(kid)
        except MissionTokenInvalid:
            # kid absent après refresh = révoqué ou jamais publié.
            raise MissionTokenError("kid_unknown_or_revoked")
        except JWKSUnavailable:
            raise MissionTokenError("jwks_unavailable")

        try:
            return ECAlgorithm.from_jwk(json.dumps(jwk))
        except Exception:
            logger.warning("JWK ES256 illisible pour kid")
            raise MissionTokenError("jwks_unavailable")

    def validate(self, token_compact: str) -> dict:
        """
        Valide un JWT mission_token ES256.

        Args:
            token_compact: JWT compact (jamais loggué ni inclus dans les erreurs).

        Returns:
            dict des claims si valide : iss, aud, exp, mission_id, sub?, tenant_id?

        Raises:
            MissionTokenError: reason = code d'erreur machine (sans le token).
        """
        # Extraire le header sans vérification
        try:
            header = jwt.get_unverified_header(token_compact)
        except Exception:
            raise MissionTokenError("invalid_token_format")

        kid = header.get("kid", "")
        alg = header.get("alg", "")

        if alg != "ES256":
            raise MissionTokenError(f"unsupported_algorithm:{alg or 'missing'}")

        signing_key = self._get_signing_key(kid)

        # Décoder et valider
        try:
            decode_kwargs: dict = {
                "algorithms": ["ES256"],
                "issuer": self._expected_iss,
                "options": {
                    "require": ["exp", "iss", "mission_id"],
                    "leeway": self._leeway,
                    "verify_exp": True,
                    "verify_iss": True,
                },
            }
            if self._expected_aud:
                decode_kwargs["audience"] = self._expected_aud

            claims = jwt.decode(
                token_compact,
                signing_key,
                **decode_kwargs,
            )
        except jwt.ExpiredSignatureError:
            raise MissionTokenError("token_expired")
        except jwt.InvalidIssuerError:
            raise MissionTokenError("invalid_issuer")
        except jwt.InvalidAudienceError:
            raise MissionTokenError("invalid_audience")
        except jwt.InvalidSignatureError:
            raise MissionTokenError("invalid_signature")
        except jwt.MissingRequiredClaimError as e:
            raise MissionTokenError(f"missing_claim:{getattr(e, 'claim', 'unknown')}")
        except jwt.DecodeError:
            raise MissionTokenError("decode_error")
        except Exception:
            raise MissionTokenError("validation_failed")

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
    )
    logger.info("MissionTokenValidator singleton initialisé (jwks=%s)", jwks_url)
    return _validator


def get_mission_token_validator() -> Optional["MissionTokenValidator"]:
    """Retourne le singleton process-wide, ou None si non configuré."""
    return _validator
