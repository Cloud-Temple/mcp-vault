"""Vault-owned closed Mission retention proof; no private Mission dependency."""

import hashlib
import json
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
from time import monotonic
from uuid import UUID

import httpx
import jwt
from jwt.algorithms import ECAlgorithm

from ..auth.mission_jwt import MissionTokenInvalid, init_jwks_cache

IDENTITY = frozenset(
    {
        "owner",
        "tenant_id",
        "mission_id",
        "root_agent_id",
        "claim_id",
        "claim_revision",
        "terminal_at",
        "retain_until",
        "manifest_sha256",
    }
)


def endpoint(settings):
    issuer, jwks = settings.mission_retention_issuer, settings.mission_jwks_url
    for value in (issuer, jwks):
        url = urlsplit(value)
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or url.query
            or url.fragment
        ):
            raise ValueError("Explicit HTTPS retention authority required")
    a, b = urlsplit(issuer), urlsplit(jwks)
    if (
        (a.hostname, a.port or 443) != (b.hostname, b.port or 443)
        or not settings.mission_retention_audience
        or len(settings.mission_retention_audience.encode()) > 256
    ):
        raise ValueError("Retention issuer/JWKS origin refused")
    return issuer.rstrip("/") + "/internal/retention/claim-check"


def decode(settings, cache, token, *, now=None):
    endpoint(settings)
    if not isinstance(token, str) or not token or len(token) > 16384:
        raise ValueError("Retention proof refused")
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "ES256" or not isinstance(header.get("kid"), str):
            raise ValueError()
        body = jwt.decode(
            token,
            ECAlgorithm.from_jwk(cache.get_key(header["kid"])),
            algorithms=["ES256"],
            audience=settings.mission_retention_audience,
            issuer=settings.mission_retention_issuer,
            options={
                "strict_aud": True,
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
        if (
            set(body)
            != IDENTITY | {"iss", "aud", "sub", "purpose", "iat", "nbf", "exp", "jti"}
            or body["sub"] != "mission-retention-maintenance"
            or body["purpose"] != "mission-retention-v1"
            or body["owner"] != "vault"
            or type(body["claim_revision"]) is not int
            or body["claim_revision"] < 1
            or any(
                not isinstance(body[k], str)
                or not body[k]
                or len(body[k].encode()) > 256
                for k in ("tenant_id", "mission_id")
            )
            or not isinstance(body["root_agent_id"], str)
            or len(body["root_agent_id"].encode()) > 256
            or str(UUID(body["claim_id"])) != body["claim_id"]
            or any(type(body[k]) is not int for k in ("iat", "nbf", "exp"))
            or body["nbf"] != body["iat"]
            or not 1 <= body["exp"] - body["iat"] <= 30
        ):
            raise ValueError()
        for key, length in (("manifest_sha256", 64), ("jti", 32)):
            if (
                not isinstance(body[key], str)
                or len(body[key]) != length
                or any(c not in "0123456789abcdef" for c in body[key])
            ):
                raise ValueError()
        ended, until = (
            datetime.fromisoformat(body[k]) for k in ("terminal_at", "retain_until")
        )
        stamp = now or datetime.now(timezone.utc)
        if (
            stamp.utcoffset() is None
            or ended.utcoffset() is None
            or until.utcoffset() is None
            or ended > stamp
            or until < ended + timedelta(days=365)
            or not body["iat"] <= stamp.timestamp() < body["exp"]
        ):
            raise ValueError()
        result = {k: body[k] for k in IDENTITY}
        result.update(
            terminal_at=ended.astimezone(timezone.utc).isoformat(),
            retain_until=until.astimezone(timezone.utc).isoformat(),
        )
        return result, datetime.fromtimestamp(body["exp"], timezone.utc)
    except (
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        jwt.InvalidTokenError,
        MissionTokenInvalid,
    ):
        raise ValueError("Retention proof refused") from None


def _live(settings, token):
    """Inspection only. Local maintenance SQL authority is still required."""
    deadline = monotonic() + settings.mission_retention_callback_seconds
    url = endpoint(settings)
    cache = init_jwks_cache(settings.mission_jwks_url, settings.mission_jwks_cache_ttl)
    identity, _ = decode(settings, cache, token)
    # Existing JWKS cache and httpx use the system TLS trust (SSL_CERT_FILE may
    # name the operator's private CA). No verify=False, redirect or bearer echo.
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise ValueError("Retention proof deadline exceeded")
    with httpx.Client(timeout=remaining, follow_redirects=False) as client:
        with client.stream(
            "POST", url, headers={"Authorization": "Bearer " + token}
        ) as response:
            raw = bytearray()
            for block in response.iter_bytes():
                if len(raw) + len(block) > 4096 or monotonic() >= deadline:
                    raise ValueError("Retention callback refused")
                raw.extend(block)
            if response.status_code != 200 or json.loads(raw) != {"active": True}:
                raise ValueError("Retention claim unavailable")
    fresh, expires = decode(settings, cache, token)
    if fresh != identity or monotonic() >= deadline:
        raise ValueError("Retention claim changed")
    return identity, expires


def live(settings, token):
    try:
        return _live(settings, token)
    except ValueError:
        raise
    except Exception:
        from .postgres import MetadataUnavailable

        raise MetadataUnavailable("retention_authority_unavailable") from None


def fingerprint(identity):
    return hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
