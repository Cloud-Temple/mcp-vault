"""Contexte utilisateur de lecture842 : ne remplace jamais l'opaque Vault local."""

from __future__ import annotations

import hashlib
from functools import partial
import json
import re
import ssl
import time
from urllib.parse import urlsplit

import httpx2
import jwt
from jwt.algorithms import ECAlgorithm

from .mission_jwt import JWKSCache, MissionTokenInvalid, valider_hors_boucle

PURPOSE = "hub-vault-activity-v1"
PATH = "/internal/hub/vault-activity"
HEADER = b"x-vault-hub-context"
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
MISSION = re.compile(r"mis_(?:[0-9a-f]{8}|[0-9a-f]{24})\Z")
SUBJECT = re.compile(r"(?:opaque|oidc):[0-9a-f]{64}\Z")


def strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate field")
        value[key] = item
    return value


def https_url(value):
    parsed = urlsplit(value)
    return bool(
        parsed.scheme == "https"
        and parsed.hostname
        and not parsed.username
        and not parsed.password
        and not parsed.query
        and not parsed.fragment
    )


class HubContext:
    def __init__(self, cfg, client_factory=httpx2.AsyncClient):
        self.cfg, self.client_factory = cfg, client_factory

        def fetch(url, etag, timeout):
            with httpx2.Client(
                verify=ssl.create_default_context(cafile=cfg.hub_vault_ca_file),
                trust_env=False,
                follow_redirects=False,
                timeout=timeout,
            ) as client:
                with client.stream(
                    "GET", url, headers={"If-None-Match": etag} if etag else {}
                ) as reply:
                    raw = bytearray()
                    for chunk in reply.iter_bytes():
                        raw.extend(chunk)
                        if len(raw) > 65536:
                            raise ValueError("JWKS bound exceeded")
                    return reply.status_code, reply.headers.get("etag"), bytes(raw)

        self.jwks = JWKSCache(
            cfg.hub_vault_jwks_url,
            cfg.mission_jwks_cache_ttl,
            fetch=fetch,
            timeout=cfg.hub_vault_timeout_seconds,
        )

    async def verify(self, token, raw, body):
        try:
            encoded_header, encoded_claims, _signature = token.split(".")
            header = json.loads(
                jwt.utils.base64url_decode(encoded_header),
                object_pairs_hook=strict_object,
            )
            json.loads(
                jwt.utils.base64url_decode(encoded_claims),
                object_pairs_hook=strict_object,
            )
            if not isinstance(header, dict):
                raise ValueError()
        except (ValueError, TypeError, UnicodeError):
            raise PermissionError("delegation refused") from None
        if (
            set(header) - {"alg", "kid", "typ"}
            or header.get("alg") != "ES256"
            or header.get("typ") != "JWT"
            or not isinstance(header.get("kid"), str)
            or not IDENT.fullmatch(header["kid"])
        ):
            raise PermissionError("delegation refused")
        try:
            key = await valider_hors_boucle(
                self.jwks, partial(self.jwks.get_key, header["kid"])
            )
        except MissionTokenInvalid as exc:
            raise PermissionError("delegation refused") from exc
        if key.get("kty") != "EC" or key.get("crv") != "P-256":
            raise PermissionError("delegation refused")
        claims = jwt.decode(
            token,
            ECAlgorithm.from_jwk(key),
            algorithms=["ES256"],
            issuer=self.cfg.hub_vault_issuer,
            audience=self.cfg.hub_vault_audience,
            options={
                "strict_aud": True,
                "require": ["iss", "aud", "sub", "iat", "nbf", "exp", "jti"],
            },
        )
        expected = {
            "iss",
            "aud",
            "sub",
            "iat",
            "nbf",
            "exp",
            "jti",
            "purpose",
            "permissions",
            "resources",
            "tenant_id",
            "mission_id",
            "owner_id",
            "request_sha256",
        }
        if (
            set(claims) != expected
            or claims["purpose"] != PURPOSE
            or claims["permissions"] != ["vault.activity.read"]
            or not isinstance(claims["sub"], str)
            or not SUBJECT.fullmatch(claims["sub"])
            or any(type(claims[k]) is not int for k in ("iat", "nbf", "exp"))
            or claims["nbf"] != claims["iat"]
            or not 0 < claims["exp"] - claims["iat"] <= 30
            or not isinstance(claims["jti"], str)
            or not re.fullmatch(r"[0-9a-f]{32}", claims["jti"])
            or claims["resources"] != [body["mission_id"]]
            or claims["mission_id"] != body["mission_id"]
            or claims["tenant_id"] != body["tenant_id"]
            or claims["owner_id"] != self.cfg.metadata_instance_id
            or claims["request_sha256"] != hashlib.sha256(raw).hexdigest()
        ):
            raise PermissionError("delegation refused")
        return claims

    async def active(self, token, claims):
        if time.time() >= claims["exp"]:
            raise PermissionError("delegation expired")
        async with self.client_factory(
            verify=ssl.create_default_context(cafile=self.cfg.hub_vault_ca_file),
            trust_env=False,
            follow_redirects=False,
            timeout=self.cfg.hub_vault_timeout_seconds,
        ) as client:
            async with client.stream(
                "POST",
                self.cfg.hub_vault_check_url,
                content=b"{}",
                headers={
                    "Authorization": "Bearer " + token,
                    "Content-Type": "application/json",
                },
            ) as reply:
                raw = bytearray()
                async for chunk in reply.aiter_bytes():
                    raw.extend(chunk)
                    if len(raw) > 1024:
                        raise RuntimeError("delegation check unavailable")
                if reply.status_code == 403:
                    raise PermissionError("delegation refused")
                value = json.loads(raw, object_pairs_hook=strict_object)
                if (
                    reply.status_code != 200
                    or not isinstance(value, dict)
                    or set(value) != {"active"}
                    or value["active"] is not True
                ):
                    raise RuntimeError("delegation check unavailable")
        if time.time() >= claims["exp"]:
            raise PermissionError("delegation expired")
