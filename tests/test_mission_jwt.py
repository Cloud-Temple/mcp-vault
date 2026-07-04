# -*- coding: utf-8 -*-
"""
Tests du PEP mission JWT (issue #47) — PR1 : durcissement de la porte /mcp.

Couvre :
  - JWKSCache : TTL, ETag/304, backoff anti-DoS, fail-close, force_reload.
  - looks_like_jwt : discriminant STRUCTUREL (anti alg-confusion).
  - validate_mission_token : contrat RÉEL mcp-mission v0.5.0 (aud=liste,
    component_id={kind:ref}, tenant_id/jti/scope requis, leeway exp=0).
  - check_mission_active : allow-list {RUNNING, WAITING_HUMAN, PAUSED} (fail-close
    sur état inconnu — corrige la deny-list historique).
  - AuthMiddleware : modes bearer (non-régression) / jwt / dual-stack, refus ACTIFS
    401/403/503, pas de fallback silencieux JWT→bearer, audit des refus.
  - check_access / get_listing_filter / enforce_mission_jwt_tool : deny-by-default
    des identités mission_jwt (jamais owner-based).
  - Admin API : POST /admin/api/auth/jwks/reload (admin only) + exclusion des
    mission JWT de toute la surface /admin/api/*.
  - Config : check_mission_pep_config + fail-fast create_app.

Contrat de référence : mémoire project_mission_token_contract (vérifié dans le code
émetteur mcp-mission, PAS la doc "cible").
"""

import base64
import json
import os
import sys
import time
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from mcp_vault.auth.mission_jwt import (
    JWKSCache,
    JWKSUnavailable,
    MissionTokenForbidden,
    MissionTokenInvalid,
    check_mission_active,
    looks_like_jwt,
    validate_mission_token,
)

# ── Constantes de test (contrat réel) ──────────────────────────────────────────

INSTANCE_ID = "vault-test-1"
TENANT_ID = "tenant-acme"
MISSION_ID = "mis_0000test"
BOOTSTRAP_KEY = "bootstrap-key-for-tests-only-0123456789"


# ── Helpers ─────────────────────────────────────────────────────────────────────

def _run(coro):
    """Exécute une coroutine sans fermer la boucle (cf. test_jwt_validator)."""
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


def _make_es256_keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    return priv, pub


def _make_jwks(pub_key, kid: str = "test-key-1") -> dict:
    nums = pub_key.public_numbers()

    def b64url(n: int) -> str:
        return base64.urlsafe_b64encode(n.to_bytes(32, "big")).rstrip(b"=").decode()

    return {
        "keys": [{
            "kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256",
            "kid": kid, "x": b64url(nums.x), "y": b64url(nums.y),
        }]
    }


def _priv_pem(priv_key) -> bytes:
    return priv_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _make_mission_token(
    priv_key=None,
    *,
    kid: str = "test-key-1",
    instance_id: str = INSTANCE_ID,
    mission_id: str = MISSION_ID,
    tenant_id: str = TENANT_ID,
    exp_delta: int = 300,
    iat_delta: int = 0,
    alg: str = "ES256",
    hs_key: str = "hs-secret",
    overrides: dict = None,
    drop: list = None,
) -> str:
    """Génère un mission_token conforme au contrat RÉEL de mcp-mission v0.5.0.

    overrides remplace des claims ; drop en supprime (pour tester les rejets).
    """
    now = datetime.now(timezone.utc)
    payload = {
        "iss": "mcp-mission",
        "sub": f"mission:{mission_id}",
        "aud": [instance_id, "live-mem-test"],       # LISTE de refs d'instance
        "exp": int((now + timedelta(seconds=exp_delta)).timestamp()),
        "iat": int((now + timedelta(seconds=iat_delta)).timestamp()),
        "jti": uuid.uuid4().hex,
        "mission_id": mission_id,
        "tenant_id": tenant_id,
        "component_id": {"vault": instance_id, "live_memory": "live-mem-test"},
        "scope": [f"{instance_id}:mission/{mission_id}:*"],
        "provenance": [{"actor": "mcp-mission", "via": "broker",
                        "decision_id": "dec-issuer-123"}],
    }
    if overrides:
        payload.update(overrides)
    for key in (drop or []):
        payload.pop(key, None)

    headers = {"kid": kid}
    if alg == "ES256":
        return jwt.encode(payload, _priv_pem(priv_key), algorithm="ES256", headers=headers)
    if alg == "none":
        return jwt.encode(payload, None, algorithm="none", headers=headers)
    return jwt.encode(payload, hs_key, algorithm=alg, headers=headers)


def _static_cache(jwks_dict: dict, ttl: int = 60) -> JWKSCache:
    """JWKSCache dont le fetch renvoie toujours le même document (pas de réseau)."""
    def fetch(url, etag, timeout):
        return 200, None, json.dumps(jwks_dict).encode()
    return JWKSCache("http://mock-jwks/x", ttl_seconds=ttl, fetch=fetch)


def _validate(token, cache, **kw):
    kw.setdefault("instance_id", INSTANCE_ID)
    kw.setdefault("component_kind", "vault")
    kw.setdefault("iat_leeway", 10)
    return validate_mission_token(token, cache, **kw)


@pytest.fixture(autouse=True)
def _reset_global_state():
    """Isole l'état module-level entre les tests (cache mission-status, singleton JWKS)."""
    import mcp_vault.auth.mission_jwt as mj
    mj._mission_status_cache.clear()
    saved = mj._jwks_cache
    yield
    mj._mission_status_cache.clear()
    mj._jwks_cache = saved


# ═══════════════════════════════════════════════════════════════════════════════
# JWKSCache
# ═══════════════════════════════════════════════════════════════════════════════

class TestJWKSCache:

    def test_get_key_populates_and_serves_from_cache(self):
        _, pub = _make_es256_keypair()
        calls = [0]

        def fetch(url, etag, timeout):
            calls[0] += 1
            return 200, 'W/"v1"', json.dumps(_make_jwks(pub)).encode()

        cache = JWKSCache("http://mock/x", ttl_seconds=60, fetch=fetch)
        key1 = cache.get_key("test-key-1")
        key2 = cache.get_key("test-key-1")
        assert key1["kid"] == "test-key-1"
        assert key2 is key1
        assert calls[0] == 1, "le cache frais ne doit pas refetch"

    def test_ttl_expiry_triggers_refetch(self):
        _, pub = _make_es256_keypair()
        calls = [0]
        clock = [1000.0]

        def fetch(url, etag, timeout):
            calls[0] += 1
            return 200, None, json.dumps(_make_jwks(pub)).encode()

        cache = JWKSCache("http://mock/x", ttl_seconds=60, fetch=fetch,
                          time_func=lambda: clock[0])
        cache.get_key("test-key-1")
        clock[0] += 61  # TTL dépassé
        cache.get_key("test-key-1")
        assert calls[0] == 2

    def test_etag_304_extends_freshness(self):
        _, pub = _make_es256_keypair()
        clock = [1000.0]
        state = {"first": True}

        def fetch(url, etag, timeout):
            if state["first"]:
                state["first"] = False
                return 200, 'W/"v1"', json.dumps(_make_jwks(pub)).encode()
            assert etag == 'W/"v1"', "If-None-Match doit porter l'ETag du cache"
            return 304, 'W/"v1"', None

        cache = JWKSCache("http://mock/x", ttl_seconds=60, fetch=fetch,
                          time_func=lambda: clock[0])
        cache.get_key("test-key-1")
        clock[0] += 61
        key = cache.get_key("test-key-1")  # 304 → cache prolongé, clé servie
        assert key["kid"] == "test-key-1"

    def test_304_without_initial_cache_fails_close(self):
        def fetch(url, etag, timeout):
            return 304, None, None

        cache = JWKSCache("http://mock/x", ttl_seconds=60, fetch=fetch)
        with pytest.raises(JWKSUnavailable):
            cache.get_key("any")

    def test_expired_cache_plus_fetch_failure_fails_close(self):
        """FAIL-CLOSE central : un cache expiré n'est JAMAIS servi."""
        _, pub = _make_es256_keypair()
        clock = [1000.0]
        state = {"fail": False}

        def fetch(url, etag, timeout):
            if state["fail"]:
                raise OSError("down")
            return 200, None, json.dumps(_make_jwks(pub)).encode()

        cache = JWKSCache("http://mock/x", ttl_seconds=60, fetch=fetch,
                          time_func=lambda: clock[0])
        cache.get_key("test-key-1")          # peuple
        state["fail"] = True
        clock[0] += 61                        # cache expiré
        with pytest.raises(JWKSUnavailable):
            cache.get_key("test-key-1")       # PAS de clé périmée servie

    def test_backoff_blocks_immediate_refetch(self):
        calls = [0]
        clock = [1000.0]

        def fetch(url, etag, timeout):
            calls[0] += 1
            raise OSError("down")

        cache = JWKSCache("http://mock/x", ttl_seconds=60, fetch=fetch,
                          time_func=lambda: clock[0])
        with pytest.raises(JWKSUnavailable):
            cache.get_key("k")
        n = calls[0]
        with pytest.raises(JWKSUnavailable):
            cache.get_key("k")               # fenêtre de backoff → pas de refetch
        assert calls[0] == n

        clock[0] += 120                       # après le backoff max (30s + jitter)
        with pytest.raises(JWKSUnavailable):
            cache.get_key("k")
        assert calls[0] == n + 1              # nouvelle tentative autorisée

    def test_unknown_kid_after_forced_refresh(self):
        _, pub = _make_es256_keypair()
        cache = _static_cache(_make_jwks(pub, kid="key-v1"))
        with pytest.raises(MissionTokenInvalid) as exc_info:
            cache.get_key("key-v2")
        assert exc_info.value.reason == "unknown_kid"

    def test_unknown_kid_flood_throttled_no_ddos(self):
        """ANTI-DoS : un flot de kids inconnus ne déclenche PAS un fetch réseau par
        requête (throttle des refresh unknown-kid). Sinon un attaquant DoS l'endpoint
        JWKS de mcp-mission via des JWT à kids aléatoires."""
        _, pub = _make_es256_keypair()
        calls = [0]
        clock = [1000.0]

        def fetch(url, etag, timeout):
            calls[0] += 1
            return 200, None, json.dumps(_make_jwks(pub, kid="real")).encode()

        cache = JWKSCache("http://mock/x", ttl_seconds=300, fetch=fetch,
                          time_func=lambda: clock[0])
        cache.get_key("real")            # 1 fetch (peuple)
        assert calls[0] == 1
        # 50 kids inconnus dans la même fenêtre → au plus 1 refresh supplémentaire.
        for i in range(50):
            with pytest.raises(MissionTokenInvalid):
                cache.get_key(f"ghost-{i}")
        assert calls[0] <= 2, (
            f"DoS JWKS : {calls[0]} fetchs pour 50 kids inconnus (throttle cassé)")

    def test_unknown_kid_refresh_allowed_after_interval(self):
        """Après l'intervalle de throttle, un nouveau refresh unknown-kid est permis
        (propagation d'une vraie rotation de clé)."""
        _, pub = _make_es256_keypair()
        calls = [0]
        clock = [1000.0]

        def fetch(url, etag, timeout):
            calls[0] += 1
            return 200, None, json.dumps(_make_jwks(pub, kid="real")).encode()

        cache = JWKSCache("http://mock/x", ttl_seconds=300, fetch=fetch,
                          time_func=lambda: clock[0])
        cache.get_key("real")
        with pytest.raises(MissionTokenInvalid):
            cache.get_key("ghost")       # refresh unknown-kid #1
        n = calls[0]
        clock[0] += 11                    # > _UNKNOWN_KID_MIN_REFRESH_INTERVAL (10s)
        with pytest.raises(MissionTokenInvalid):
            cache.get_key("ghost2")      # nouveau refresh autorisé
        assert calls[0] == n + 1

    def test_force_reload_bypasses_unknown_kid_throttle(self):
        """L'admin (force_reload) reste le bypass explicite du throttle."""
        _, pub = _make_es256_keypair()
        calls = [0]
        clock = [1000.0]

        def fetch(url, etag, timeout):
            calls[0] += 1
            return 200, None, json.dumps(_make_jwks(pub, kid="real")).encode()

        cache = JWKSCache("http://mock/x", ttl_seconds=300, fetch=fetch,
                          time_func=lambda: clock[0])
        cache.get_key("real")
        with pytest.raises(MissionTokenInvalid):
            cache.get_key("ghost")
        n = calls[0]
        cache.force_reload()             # bypass throttle immédiatement
        assert calls[0] == n + 1

    def test_malformed_jwks_does_not_corrupt_cache(self):
        _, pub = _make_es256_keypair()
        clock = [1000.0]
        state = {"malformed": False}

        def fetch(url, etag, timeout):
            if state["malformed"]:
                return 200, None, b"{not json"
            return 200, None, json.dumps(_make_jwks(pub)).encode()

        cache = JWKSCache("http://mock/x", ttl_seconds=60, fetch=fetch,
                          time_func=lambda: clock[0])
        cache.get_key("test-key-1")
        state["malformed"] = True
        clock[0] += 61
        # Cache expiré + document malformé → fail-close (et pas de crash).
        with pytest.raises(JWKSUnavailable):
            cache.get_key("test-key-1")

    def test_force_reload_resets_backoff_and_reloads(self):
        _, pub = _make_es256_keypair()
        state = {"fail": True}

        def fetch(url, etag, timeout):
            if state["fail"]:
                raise OSError("down")
            return 200, None, json.dumps(_make_jwks(pub)).encode()

        cache = JWKSCache("http://mock/x", ttl_seconds=60, fetch=fetch)
        with pytest.raises(JWKSUnavailable):
            cache.get_key("test-key-1")       # échec → backoff armé
        state["fail"] = False
        count = cache.force_reload()          # ignore le backoff, recharge
        assert count == 1
        assert cache.get_key("test-key-1")["kid"] == "test-key-1"

    def test_parse_jwks_keeps_only_ec_p256(self):
        _, pub = _make_es256_keypair()
        doc = _make_jwks(pub)
        doc["keys"].append({"kty": "RSA", "kid": "rsa-1", "n": "x", "e": "AQAB"})
        doc["keys"].append({"kty": "EC", "crv": "P-384", "kid": "p384-1"})
        keys = JWKSCache._parse_jwks(json.dumps(doc).encode())
        assert set(keys) == {"test-key-1"}

    def test_empty_url_rejected(self):
        with pytest.raises(ValueError):
            JWKSCache("", ttl_seconds=60)


# ═══════════════════════════════════════════════════════════════════════════════
# looks_like_jwt — discriminant structurel (anti alg-confusion)
# ═══════════════════════════════════════════════════════════════════════════════

class TestLooksLikeJwt:

    def test_opaque_bearer_not_jwt(self):
        import secrets
        for _ in range(5):
            assert looks_like_jwt(secrets.token_urlsafe(32)) is False

    def test_es256_compact_is_jwt(self):
        priv, _ = _make_es256_keypair()
        assert looks_like_jwt(_make_mission_token(priv)) is True

    def test_hs256_compact_is_jwt_structurally(self):
        """CRUCIAL : un compact alg=HS256 est un JWT structurel — il sera routé
        vers la validation (→ 401 bad_alg), JAMAIS vers le chemin bearer."""
        assert looks_like_jwt(_make_mission_token(alg="HS256")) is True

    def test_alg_none_compact_is_jwt_structurally(self):
        assert looks_like_jwt(_make_mission_token(alg="none")) is True

    def test_two_segments_not_jwt(self):
        assert looks_like_jwt("abc.def") is False

    def test_non_json_header_not_jwt(self):
        assert looks_like_jwt("notbase64!!.payload.sig") is False


# ═══════════════════════════════════════════════════════════════════════════════
# validate_mission_token — contrat réel
# ═══════════════════════════════════════════════════════════════════════════════

class TestValidateMissionToken:

    def _assert_invalid(self, token, cache, reason_prefix, **kw):
        with pytest.raises(MissionTokenInvalid) as exc_info:
            _validate(token, cache, **kw)
        assert exc_info.value.reason.startswith(reason_prefix), (
            f"attendu '{reason_prefix}*', obtenu '{exc_info.value.reason}'")
        if token:  # "" est sous-chaîne de tout — pas un test de fuite pertinent
            assert token not in str(exc_info.value), "token compact divulgué !"

    def _assert_forbidden(self, token, cache, reason, **kw):
        with pytest.raises(MissionTokenForbidden) as exc_info:
            _validate(token, cache, **kw)
        assert exc_info.value.reason == reason
        assert token not in str(exc_info.value), "token compact divulgué !"

    def test_valid_token_returns_claims(self):
        priv, pub = _make_es256_keypair()
        cache = _static_cache(_make_jwks(pub))
        claims = _validate(_make_mission_token(priv), cache)
        assert claims["mission_id"] == MISSION_ID
        assert claims["tenant_id"] == TENANT_ID
        assert INSTANCE_ID in claims["aud"]

    def test_aud_as_plain_string_accepted(self):
        """aud str (RFC 7519) contenant exactement l'instance → accepté."""
        priv, pub = _make_es256_keypair()
        cache = _static_cache(_make_jwks(pub))
        token = _make_mission_token(priv, overrides={"aud": INSTANCE_ID})
        assert _validate(token, cache)["aud"] == INSTANCE_ID

    def test_not_a_jwt(self):
        _, pub = _make_es256_keypair()
        cache = _static_cache(_make_jwks(pub))
        for bad in ("", "abc", "a.b", "a.b.c.d"):
            self._assert_invalid(bad, cache, "not_a_jwt")

    def test_alg_hs256_rejected(self):
        _, pub = _make_es256_keypair()
        cache = _static_cache(_make_jwks(pub))
        self._assert_invalid(_make_mission_token(alg="HS256"), cache, "bad_alg")

    def test_alg_none_rejected(self):
        _, pub = _make_es256_keypair()
        cache = _static_cache(_make_jwks(pub))
        self._assert_invalid(_make_mission_token(alg="none"), cache, "bad_alg")

    def test_missing_kid_rejected(self):
        priv, pub = _make_es256_keypair()
        cache = _static_cache(_make_jwks(pub))
        payload = {"iss": "mcp-mission", "aud": [INSTANCE_ID],
                   "exp": int(time.time()) + 300, "iat": int(time.time()),
                   "mission_id": MISSION_ID, "jti": "j", "tenant_id": TENANT_ID,
                   "scope": ["s"], "component_id": {"vault": INSTANCE_ID}}
        token = jwt.encode(payload, _priv_pem(priv), algorithm="ES256")  # pas de kid
        self._assert_invalid(token, cache, "missing_kid")

    def test_unknown_kid_rejected(self):
        priv, pub = _make_es256_keypair()
        cache = _static_cache(_make_jwks(pub, kid="key-v1"))
        token = _make_mission_token(priv, kid="key-v2")
        self._assert_invalid(token, cache, "unknown_kid")

    def test_bad_signature_rejected(self):
        priv1, pub1 = _make_es256_keypair()
        priv2, _ = _make_es256_keypair()
        cache = _static_cache(_make_jwks(pub1))
        token = _make_mission_token(priv2)  # signé par une AUTRE clé, même kid
        self._assert_invalid(token, cache, "bad_signature")

    def test_expired_rejected_leeway_zero(self):
        """leeway exp = 0 strict : un token expiré d'1s est refusé (la grâce de
        refresh 300s de mcp-mission est INTERNE au broker, pas une tolérance PEP)."""
        priv, pub = _make_es256_keypair()
        cache = _static_cache(_make_jwks(pub))
        token = _make_mission_token(priv, exp_delta=-1)
        self._assert_invalid(token, cache, "expired")

    def test_wrong_issuer_rejected(self):
        priv, pub = _make_es256_keypair()
        cache = _static_cache(_make_jwks(pub))
        token = _make_mission_token(priv, overrides={"iss": "evil"})
        self._assert_invalid(token, cache, "bad_iss")

    def test_iat_future_beyond_leeway_rejected(self):
        priv, pub = _make_es256_keypair()
        cache = _static_cache(_make_jwks(pub))
        token = _make_mission_token(priv, iat_delta=60)  # 60s dans le futur > 10s leeway
        self._assert_invalid(token, cache, "iat_future")

    def test_iat_slightly_future_within_leeway_accepted(self):
        priv, pub = _make_es256_keypair()
        cache = _static_cache(_make_jwks(pub))
        token = _make_mission_token(priv, iat_delta=5)  # 5s < 10s leeway
        assert _validate(token, cache)["mission_id"] == MISSION_ID

    @pytest.mark.parametrize("claim", ["exp", "iat", "aud", "mission_id", "jti",
                                       "scope", "tenant_id"])
    def test_missing_required_claim_rejected(self, claim):
        priv, pub = _make_es256_keypair()
        cache = _static_cache(_make_jwks(pub))
        token = _make_mission_token(priv, drop=[claim])
        with pytest.raises(MissionTokenInvalid):
            _validate(token, cache)

    @pytest.mark.parametrize("bad_value,reason", [
        ("", "bad_mission_id"), (42, "bad_mission_id"),
    ])
    def test_bad_mission_id(self, bad_value, reason):
        priv, pub = _make_es256_keypair()
        cache = _static_cache(_make_jwks(pub))
        token = _make_mission_token(priv, overrides={"mission_id": bad_value})
        with pytest.raises(MissionTokenInvalid) as exc_info:
            _validate(token, cache)
        # "" déclenche missing_claim ou bad_mission_id selon PyJWT — les deux fail-close.
        assert exc_info.value.reason in (reason, "missing_claim")

    def test_bad_tenant_id_rejected(self):
        priv, pub = _make_es256_keypair()
        cache = _static_cache(_make_jwks(pub))
        token = _make_mission_token(priv, overrides={"tenant_id": 42})
        self._assert_invalid(token, cache, "bad_tenant_id")

    def test_bad_jti_rejected(self):
        priv, pub = _make_es256_keypair()
        cache = _static_cache(_make_jwks(pub))
        token = _make_mission_token(priv, overrides={"jti": 123})
        # PyJWT ≥ 2.10 rejette lui-même un jti non-str (InvalidJTIError → "invalid") ;
        # notre check "bad_jti" reste une défense en profondeur. Les deux → 401.
        with pytest.raises(MissionTokenInvalid) as exc_info:
            _validate(token, cache)
        assert exc_info.value.reason in ("bad_jti", "invalid")

    @pytest.mark.parametrize("bad_scope", ["str-pas-liste", [], [42], ["ok", ""]])
    def test_bad_scope_rejected(self, bad_scope):
        priv, pub = _make_es256_keypair()
        cache = _static_cache(_make_jwks(pub))
        token = _make_mission_token(priv, overrides={"scope": bad_scope})
        with pytest.raises(MissionTokenInvalid) as exc_info:
            _validate(token, cache)
        assert exc_info.value.reason in ("bad_scope", "missing_claim")

    def test_aud_wrong_type_rejected_401_not_500(self):
        """aud forgé (dict) → 401 propre, jamais un crash."""
        priv, pub = _make_es256_keypair()
        cache = _static_cache(_make_jwks(pub))
        token = _make_mission_token(priv, overrides={"aud": {"evil": True}})
        self._assert_invalid(token, cache, "bad_aud")

    def test_aud_without_instance_forbidden_403(self):
        priv, pub = _make_es256_keypair()
        cache = _static_cache(_make_jwks(pub))
        token = _make_mission_token(priv, overrides={"aud": ["autre-vault", "x"]})
        self._assert_forbidden(token, cache, "wrong_audience")

    def test_component_id_missing_forbidden(self):
        priv, pub = _make_es256_keypair()
        cache = _static_cache(_make_jwks(pub))
        token = _make_mission_token(priv, drop=["component_id"])
        self._assert_forbidden(token, cache, "component_id_mismatch")

    def test_component_id_not_dict_forbidden(self):
        priv, pub = _make_es256_keypair()
        cache = _static_cache(_make_jwks(pub))
        token = _make_mission_token(priv, overrides={"component_id": "vault-test-1"})
        self._assert_forbidden(token, cache, "component_id_mismatch")

    def test_component_id_wrong_instance_forbidden(self):
        priv, pub = _make_es256_keypair()
        cache = _static_cache(_make_jwks(pub))
        token = _make_mission_token(
            priv, overrides={"component_id": {"vault": "autre-instance"}})
        self._assert_forbidden(token, cache, "component_id_mismatch")

    def test_component_id_missing_vault_kind_forbidden(self):
        priv, pub = _make_es256_keypair()
        cache = _static_cache(_make_jwks(pub))
        token = _make_mission_token(
            priv, overrides={"component_id": {"teleport": "tp-1"}})
        self._assert_forbidden(token, cache, "component_id_mismatch")


# ═══════════════════════════════════════════════════════════════════════════════
# check_mission_active — allow-list (fail-close)
# ═══════════════════════════════════════════════════════════════════════════════

class TestCheckMissionActive:

    def _mock_status_response(self, status_code=200, state="RUNNING"):
        resp = MagicMock()
        resp.status_code = status_code
        resp.json.return_value = {"status": state}
        client = MagicMock()
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        client.get = AsyncMock(return_value=resp)
        return client

    def _check(self, state="RUNNING", status_code=200, mission="mis_x"):
        client = self._mock_status_response(status_code, state)
        with patch("mcp_vault.auth.mission_jwt.httpx.AsyncClient",
                   return_value=client):
            return _run(check_mission_active(
                mission, status_url_template="http://mission/api/{mission_id}/status",
                cache_ttl=5))

    @pytest.mark.parametrize("state", ["RUNNING", "WAITING_HUMAN", "PAUSED",
                                       "running", "paused"])
    def test_active_states_allowed(self, state):
        """Allow-list 3 états — PAUSED inclus (contrat mcp-mission : une mission
        PAUSED reçoit des tokens re-signés)."""
        active, why = self._check(state=state, mission=f"mis_{state}")
        assert active is True, f"état {state} doit être actif ({why})"

    @pytest.mark.parametrize("state", ["CLOSED", "ABORTED", "CLOSING", "FAILED"])
    def test_terminal_states_inactive(self, state):
        active, why = self._check(state=state, mission=f"mis_{state}")
        assert active is False

    @pytest.mark.parametrize("state", ["LIMBO", "UNKNOWN_FUTURE_STATE", "", "42"])
    def test_unknown_state_is_inactive_fail_close(self, state):
        """LE FIX : état inconnu/vide = INACTIF (la deny-list historique le
        traitait comme actif — fail-open)."""
        active, why = self._check(state=state, mission=f"mis_u{state or 'empty'}")
        assert active is False, f"état inconnu '{state}' traité comme actif (fail-open) !"

    def test_http_404_fail_close(self):
        active, why = self._check(status_code=404, mission="mis_404")
        assert active is False
        assert "404" in why

    def test_network_error_fail_close(self):
        client = MagicMock()
        client.__aenter__ = AsyncMock(side_effect=OSError("down"))
        client.__aexit__ = AsyncMock(return_value=False)
        with patch("mcp_vault.auth.mission_jwt.httpx.AsyncClient",
                   return_value=client):
            active, why = _run(check_mission_active(
                "mis_neterr", status_url_template="http://mission/{mission_id}",
                cache_ttl=5))
        assert active is False
        assert why == "service_unavailable"

    def test_cache_hit_avoids_second_call(self):
        client = self._mock_status_response(200, "RUNNING")
        with patch("mcp_vault.auth.mission_jwt.httpx.AsyncClient",
                   return_value=client) as mock_cls:
            _run(check_mission_active("mis_cache", "http://m/{mission_id}", 60))
            _run(check_mission_active("mis_cache", "http://m/{mission_id}", 60))
        assert mock_cls.call_count == 1, "le cache TTL doit éviter le 2e appel HTTP"


# ═══════════════════════════════════════════════════════════════════════════════
# AuthMiddleware — PEP par mode
# ═══════════════════════════════════════════════════════════════════════════════

def _pep_settings(mode="jwt", status_url=""):
    return SimpleNamespace(
        mcp_auth_mode=mode,
        admin_bootstrap_key=BOOTSTRAP_KEY,
        resolved_mission_aud=INSTANCE_ID,
        mcp_component_kind="vault",
        mission_token_leeway_seconds=10,
        mission_status_url=status_url,
        mission_status_cache_ttl=5,
    )


class _MiddlewareHarness:
    """Monte AuthMiddleware sur une app factice qui capture le contextvar."""

    def __init__(self, settings_ns, jwks_cache=None):
        from mcp_vault.auth.middleware import AuthMiddleware
        self.captured = {}

        async def downstream(scope, receive, send):
            from mcp_vault.auth.context import current_token_info
            self.captured["token_info"] = current_token_info.get()
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"{}"})

        self.mw = AuthMiddleware(downstream)
        self.settings_ns = settings_ns
        self.jwks_cache = jwks_cache

    def call(self, token=None, scope_type="http", path="/mcp"):
        headers = []
        if token is not None:
            headers.append((b"authorization", b"Bearer " + token.encode()))
        scope = {"type": scope_type, "path": path, "headers": headers,
                 "query_string": b""}
        events = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(ev):
            events.append(ev)

        import mcp_vault.auth.mission_jwt as mj
        with patch("mcp_vault.auth.middleware.get_settings",
                   return_value=self.settings_ns), \
             patch.object(mj, "_jwks_cache", self.jwks_cache):
            _run(self.mw(scope, receive, send))
        return events

    @staticmethod
    def status_of(events):
        for ev in events:
            if ev["type"] == "http.response.start":
                return ev["status"]
        return None

    @staticmethod
    def body_of(events):
        for ev in events:
            if ev["type"] == "http.response.body":
                return json.loads(ev["body"]) if ev["body"] else {}
        return None


class TestAuthMiddlewareBearerMode:
    """Non-régression : mode bearer = comportement historique strict."""

    def test_no_token_proceeds_with_none(self):
        h = _MiddlewareHarness(_pep_settings(mode="bearer"))
        events = h.call(token=None)
        assert h.status_of(events) == 200
        assert h.captured["token_info"] is None

    def test_bootstrap_key_grants_admin(self):
        h = _MiddlewareHarness(_pep_settings(mode="bearer"))
        events = h.call(token=BOOTSTRAP_KEY)
        assert h.status_of(events) == 200
        assert "admin" in h.captured["token_info"]["permissions"]

    def test_jwt_shaped_token_not_validated_as_jwt(self):
        """En mode bearer, un compact JWT est traité comme bearer opaque
        (comportement historique — aucun dispatch JWT)."""
        priv, _ = _make_es256_keypair()
        h = _MiddlewareHarness(_pep_settings(mode="bearer"))
        with patch("mcp_vault.auth.middleware.get_token_store", return_value=None):
            events = h.call(token=_make_mission_token(priv))
        assert h.status_of(events) == 200          # pas de 401 actif
        assert h.captured["token_info"] is None    # store inconnu → None injecté


class TestAuthMiddlewareJwtMode:

    def _valid_setup(self, status_url=""):
        priv, pub = _make_es256_keypair()
        cache = _static_cache(_make_jwks(pub))
        h = _MiddlewareHarness(_pep_settings(mode="jwt", status_url=status_url),
                               jwks_cache=cache)
        return priv, h

    def test_missing_token_401(self):
        _, h = self._valid_setup()
        events = h.call(token=None)
        assert h.status_of(events) == 401
        assert "token_info" not in h.captured, "l'app ne doit PAS être atteinte"

    def test_opaque_token_401(self):
        _, h = self._valid_setup()
        events = h.call(token="un-bearer-opaque-quelconque")
        assert h.status_of(events) == 401

    def test_bootstrap_key_still_works_break_glass(self):
        _, h = self._valid_setup()
        events = h.call(token=BOOTSTRAP_KEY)
        assert h.status_of(events) == 200
        assert "admin" in h.captured["token_info"]["permissions"]

    def test_valid_jwt_proceeds_with_mission_identity(self):
        priv, h = self._valid_setup()
        events = h.call(token=_make_mission_token(priv))
        assert h.status_of(events) == 200
        info = h.captured["token_info"]
        assert info["auth_type"] == "mission_jwt"
        assert info["client_name"] == f"mission:{TENANT_ID}"
        assert info["allowed_resources"] == []      # aucun binding store configuré → deny-all (#69)
        assert info["policy_id"] == ""
        assert "admin" not in info["permissions"]
        assert info["tenant_id"] == TENANT_ID
        assert info["mission_id"] == MISSION_ID

    def test_invalid_signature_401(self):
        priv, h = self._valid_setup()
        other_priv, _ = _make_es256_keypair()
        events = h.call(token=_make_mission_token(other_priv))
        assert h.status_of(events) == 401

    def test_hs256_jwt_401_never_bearer(self):
        _, h = self._valid_setup()
        events = h.call(token=_make_mission_token(alg="HS256"))
        assert h.status_of(events) == 401

    def test_expired_jwt_401(self):
        priv, h = self._valid_setup()
        events = h.call(token=_make_mission_token(priv, exp_delta=-1))
        assert h.status_of(events) == 401

    def test_wrong_audience_403(self):
        priv, h = self._valid_setup()
        events = h.call(token=_make_mission_token(
            priv, overrides={"aud": ["autre-instance"]}))
        assert h.status_of(events) == 403

    def test_component_id_mismatch_403(self):
        priv, h = self._valid_setup()
        events = h.call(token=_make_mission_token(
            priv, overrides={"component_id": {"vault": "autre"}}))
        assert h.status_of(events) == 403

    def test_jwks_cache_not_initialized_503(self):
        priv, _ = _make_es256_keypair()
        h = _MiddlewareHarness(_pep_settings(mode="jwt"), jwks_cache=None)
        events = h.call(token=_make_mission_token(priv))
        assert h.status_of(events) == 503

    def test_jwks_unavailable_503(self):
        priv, _ = _make_es256_keypair()

        def failing_fetch(url, etag, timeout):
            raise OSError("down")

        cache = JWKSCache("http://mock/x", ttl_seconds=60, fetch=failing_fetch)
        h = _MiddlewareHarness(_pep_settings(mode="jwt"), jwks_cache=cache)
        events = h.call(token=_make_mission_token(priv))
        assert h.status_of(events) == 503

    def test_mission_inactive_403(self):
        priv, h = self._valid_setup(status_url="http://mission/{mission_id}/status")
        with patch("mcp_vault.auth.middleware.AuthMiddleware._validate_mission_jwt",
                   wraps=None) if False else patch(
                "mcp_vault.auth.mission_jwt.check_mission_active",
                new=AsyncMock(return_value=(False, "mission_status:CLOSED"))):
            events = h.call(token=_make_mission_token(priv))
        assert h.status_of(events) == 403

    def test_mission_status_unavailable_503(self):
        priv, h = self._valid_setup(status_url="http://mission/{mission_id}/status")
        with patch("mcp_vault.auth.mission_jwt.check_mission_active",
                   new=AsyncMock(return_value=(False, "service_unavailable"))):
            events = h.call(token=_make_mission_token(priv))
        assert h.status_of(events) == 503

    def test_401_has_www_authenticate_and_generic_body(self):
        _, h = self._valid_setup()
        events = h.call(token="opaque")
        start = next(e for e in events if e["type"] == "http.response.start")
        headers = dict(start["headers"])
        assert headers.get(b"www-authenticate") == b"Bearer"
        body = h.body_of(events)
        assert body == {"status": "error", "message": "invalid_token"}, (
            "le corps doit être GÉNÉRIQUE (pas de reason détaillé — anti-oracle)")

    def test_websocket_deny_closes_1008(self):
        _, h = self._valid_setup()
        events = h.call(token="opaque", scope_type="websocket")
        assert events == [{"type": "websocket.close", "code": 1008}]

    def test_forbidden_deny_audits_full_identity(self):
        """Refus 403 d'un token AUTHENTIFIÉ (aud/component_id) : l'audit doit
        porter l'identité vérifiée (tenant_id/mission_id/issuer_decision_id),
        jamais le token."""
        priv, h = self._valid_setup()
        token = _make_mission_token(priv, overrides={"aud": ["autre"]})
        with patch("mcp_vault.audit.log_audit") as mock_audit:
            events = h.call(token=token)
        assert h.status_of(events) == 403
        assert mock_audit.called
        args, kwargs = mock_audit.call_args
        assert args[0] == "mission_pep" and args[1] == "denied"
        detail = kwargs.get("detail", "")
        assert "reason=wrong_audience" in detail
        assert "decision_id=" in detail
        assert f"tenant_id={TENANT_ID}" in detail
        assert f"mission_id={MISSION_ID}" in detail
        assert "issuer_decision_id=dec-issuer-123" in detail
        assert token not in detail, "token compact dans l'audit !"

    def test_component_mismatch_deny_audits_identity(self):
        priv, h = self._valid_setup()
        token = _make_mission_token(priv, overrides={"component_id": {"vault": "x"}})
        with patch("mcp_vault.audit.log_audit") as mock_audit:
            events = h.call(token=token)
        assert h.status_of(events) == 403
        detail = mock_audit.call_args.kwargs.get("detail", "")
        assert "reason=component_id_mismatch" in detail
        assert f"tenant_id={TENANT_ID}" in detail


class TestAuthMiddlewareMissionBinding:
    """#69 : résolution du périmètre vault via le MissionBindingStore à la porte /mcp."""

    def _setup(self, status_url=""):
        priv, pub = _make_es256_keypair()
        cache = _static_cache(_make_jwks(pub))
        h = _MiddlewareHarness(_pep_settings(mode="jwt", status_url=status_url),
                               jwks_cache=cache)
        return priv, h

    def _store(self, resolve_return=None, resolve_exc=None):
        from unittest.mock import MagicMock
        store = MagicMock()
        if resolve_exc is not None:
            store.resolve.side_effect = resolve_exc
        else:
            store.resolve.return_value = resolve_return
        return store

    def test_binding_grants_real_scope(self):
        priv, h = self._setup()
        store = self._store(resolve_return={
            "instance_id": INSTANCE_ID, "tenant_id": TENANT_ID, "policy_id": "pol1",
            "allowed_resources": ["prod", "staging"], "permissions": ["read", "write"],
            "enabled": True, "expires_at": None,
        })
        with patch("mcp_vault.auth.mission_bindings.get_mission_binding_store",
                   return_value=store):
            events = h.call(token=_make_mission_token(priv))
        assert h.status_of(events) == 200
        info = h.captured["token_info"]
        assert info["allowed_resources"] == ["prod", "staging"]
        assert info["permissions"] == ["read", "write"]
        assert info["policy_id"] == "pol1"
        # La clé de lookup DOIT être le tenant_id cryptographiquement validé (anti fail-open).
        store.resolve.assert_called_once_with(TENANT_ID)

    def test_read_only_binding(self):
        priv, h = self._setup()
        store = self._store(resolve_return={
            "instance_id": INSTANCE_ID, "tenant_id": TENANT_ID, "policy_id": "",
            "allowed_resources": ["prod"], "permissions": ["read"],
            "enabled": True, "expires_at": None,
        })
        with patch("mcp_vault.auth.mission_bindings.get_mission_binding_store",
                   return_value=store):
            events = h.call(token=_make_mission_token(priv))
        info = h.captured["token_info"]
        assert info["permissions"] == ["read"]
        assert "write" not in info["permissions"]

    def test_no_binding_denies_all(self):
        priv, h = self._setup()
        store = self._store(resolve_return=None)  # aucun binding pour ce tenant
        with patch("mcp_vault.auth.mission_bindings.get_mission_binding_store",
                   return_value=store):
            events = h.call(token=_make_mission_token(priv))
        assert h.status_of(events) == 200
        info = h.captured["token_info"]
        assert info["allowed_resources"] == [] and info["policy_id"] == ""

    def test_store_unavailable_503(self):
        from mcp_vault.auth.mission_bindings import MissionBindingStoreUnavailable
        priv, h = self._setup()
        store = self._store(resolve_exc=MissionBindingStoreUnavailable("S3 down"))
        with patch("mcp_vault.auth.mission_bindings.get_mission_binding_store",
                   return_value=store):
            events = h.call(token=_make_mission_token(priv))
        assert h.status_of(events) == 503
        assert "token_info" not in h.captured, "l'app ne doit PAS être atteinte"

    def test_store_unavailable_is_audited(self):
        from mcp_vault.auth.mission_bindings import MissionBindingStoreUnavailable
        priv, h = self._setup()
        store = self._store(resolve_exc=MissionBindingStoreUnavailable("S3 down"))
        with patch("mcp_vault.auth.mission_bindings.get_mission_binding_store",
                   return_value=store), \
             patch("mcp_vault.audit.log_audit") as mock_audit:
            h.call(token=_make_mission_token(priv))
        assert mock_audit.called
        detail = mock_audit.call_args.kwargs.get("detail", "")
        assert "reason=binding_store_unavailable" in detail
        assert f"tenant_id={TENANT_ID}" in detail  # identité tracée, jamais le token

    def test_no_store_configured_denies_all(self):
        priv, h = self._setup()
        with patch("mcp_vault.auth.mission_bindings.get_mission_binding_store",
                   return_value=None):
            events = h.call(token=_make_mission_token(priv))
        assert h.status_of(events) == 200
        assert h.captured["token_info"]["allowed_resources"] == []


class TestAuthMiddlewareDualStack:

    def _setup(self):
        priv, pub = _make_es256_keypair()
        cache = _static_cache(_make_jwks(pub))
        h = _MiddlewareHarness(_pep_settings(mode="dual-stack"), jwks_cache=cache)
        return priv, h

    def test_valid_jwt_proceeds(self):
        priv, h = self._setup()
        events = h.call(token=_make_mission_token(priv))
        assert h.status_of(events) == 200
        assert h.captured["token_info"]["auth_type"] == "mission_jwt"

    def test_invalid_jwt_401_no_bearer_fallback(self):
        """CRUCIAL : un JWT invalide ne retombe JAMAIS sur le chemin bearer."""
        priv, h = self._setup()
        other_priv, _ = _make_es256_keypair()
        store = MagicMock()
        with patch("mcp_vault.auth.middleware.get_token_store",
                   return_value=store):
            events = h.call(token=_make_mission_token(other_priv))
        assert h.status_of(events) == 401
        assert not store.get_by_hash.called, (
            "fallback silencieux JWT→bearer détecté (INTERDIT)")

    def test_alg_none_jwt_401_no_bearer_fallback(self):
        _, h = self._setup()
        store = MagicMock()
        with patch("mcp_vault.auth.middleware.get_token_store",
                   return_value=store):
            events = h.call(token=_make_mission_token(alg="none"))
        assert h.status_of(events) == 401
        assert not store.get_by_hash.called

    def test_opaque_bearer_follows_bearer_path(self):
        import hashlib
        _, h = self._setup()
        info = {"client_name": "cli-1", "permissions": ["read"],
                "allowed_resources": [], "revoked": False}
        store = MagicMock()
        store.get_by_hash.return_value = info
        with patch("mcp_vault.auth.middleware.get_token_store",
                   return_value=store):
            events = h.call(token="opaque-token-abc")
        assert h.status_of(events) == 200
        assert h.captured["token_info"] == info
        expected_hash = hashlib.sha256(b"opaque-token-abc").hexdigest()
        store.get_by_hash.assert_called_once_with(expected_hash)

    def test_no_token_401_not_anonymous_passthrough(self):
        """dual-stack est un mode de DURCISSEMENT : pas de passthrough anonyme
        (qui rendrait tous les vaults visibles via get_listing_filter(None))."""
        _, h = self._setup()
        events = h.call(token=None)
        assert h.status_of(events) == 401
        assert "token_info" not in h.captured

    def test_invalid_opaque_bearer_401_no_passthrough(self):
        """Bearer opaque inconnu → 401 actif, jamais injection silencieuse de None."""
        _, h = self._setup()
        store = MagicMock()
        store.get_by_hash.return_value = None   # token inconnu du store
        with patch("mcp_vault.auth.middleware.get_token_store", return_value=store):
            events = h.call(token="opaque-inconnu")
        assert h.status_of(events) == 401
        assert "token_info" not in h.captured

    def test_bootstrap_key_checked_before_jwt_dispatch(self):
        _, h = self._setup()
        events = h.call(token=BOOTSTRAP_KEY)
        assert h.status_of(events) == 200
        assert "admin" in h.captured["token_info"]["permissions"]


# ═══════════════════════════════════════════════════════════════════════════════
# check_access / get_listing_filter / enforce_mission_jwt_tool
# ═══════════════════════════════════════════════════════════════════════════════

def _mission_token_info(allowed=None, client=f"mission:{TENANT_ID}"):
    return {
        "auth_type": "mission_jwt",
        "client_name": client,
        "permissions": ["read"],
        "allowed_resources": allowed if allowed is not None else [],
        "policy_id": "",
        "tenant_id": TENANT_ID,
        "mission_id": MISSION_ID,
        "jti": "jti-1",
    }


class _ContextVarGuard:
    def __init__(self, token_info):
        self.token_info = token_info

    def __enter__(self):
        from mcp_vault.auth.context import current_token_info
        self._cv = current_token_info
        self._tok = current_token_info.set(self.token_info)
        return self

    def __exit__(self, *a):
        self._cv.reset(self._tok)
        return False


class TestCheckAccessMissionJwt:

    def test_mission_jwt_without_scope_denied_not_owner_based(self):
        """Garde anti fail-open : mission_jwt + allowed_resources=[] → DENY,
        et check_vault_owner (owner-based) n'est JAMAIS consulté."""
        import sys
        from mcp_vault.auth.context import check_access
        mock_spaces = MagicMock()
        with _ContextVarGuard(_mission_token_info()), \
             patch.dict(sys.modules, {"mcp_vault.vault.spaces": mock_spaces}):
            err = check_access("vault-quelconque")
        assert err is not None and err["status"] == "error"
        assert not mock_spaces.check_vault_owner.called, (
            "fallback owner-based atteint pour une identité mission (fail-open) !")

    def test_mission_jwt_with_explicit_scope_membership(self):
        """PR2-ready : un binding futur remplira allowed_resources — la branche
        membership standard s'applique alors."""
        from mcp_vault.auth.context import check_access
        with _ContextVarGuard(_mission_token_info(allowed=["v1"])):
            assert check_access("v1") is None
            err = check_access("v2")
        assert err is not None and err["status"] == "error"

    def test_bearer_empty_allowed_keeps_owner_based(self):
        """Non-régression : bearer + allowed_resources=[] → owner-based intact."""
        import sys
        from mcp_vault.auth.context import check_access
        bearer_info = {"client_name": "cli-1", "permissions": ["read"],
                       "allowed_resources": []}
        mock_spaces = MagicMock()
        mock_spaces.check_vault_owner.return_value = True
        with _ContextVarGuard(bearer_info), \
             patch.dict(sys.modules, {"mcp_vault.vault.spaces": mock_spaces}):
            assert check_access("son-vault") is None
        mock_spaces.check_vault_owner.assert_called_once_with("son-vault", "cli-1")

    def test_no_token_denied(self):
        from mcp_vault.auth.context import check_access
        with _ContextVarGuard(None):
            err = check_access("v1")
        assert err is not None

    def test_incomplete_identity_denied_not_fail_open(self):
        """Token présent, non-admin, allowed_resources=[] ET client_name="" →
        DENY (fail-close). Avant : tombait sur return None (autorise tout)."""
        import sys
        from mcp_vault.auth.context import check_access
        broken = {"client_name": "", "permissions": ["read"], "allowed_resources": []}
        mock_spaces = MagicMock()
        with _ContextVarGuard(broken), \
             patch.dict(sys.modules, {"mcp_vault.vault.spaces": mock_spaces}):
            err = check_access("v1")
        assert err is not None and err["status"] == "error"
        assert not mock_spaces.check_vault_owner.called

    def test_non_list_allowed_resources_treated_as_empty(self):
        """allowed_resources non-liste (mal formé) → jamais un motif (sous-chaîne)."""
        import sys
        from mcp_vault.auth.context import check_access
        broken = {"client_name": "cli", "permissions": ["read"],
                  "allowed_resources": "v1"}  # str, pas list
        mock_spaces = MagicMock()
        mock_spaces.check_vault_owner.return_value = False
        with _ContextVarGuard(broken), \
             patch.dict(sys.modules, {"mcp_vault.vault.spaces": mock_spaces}):
            err = check_access("v1")   # ne doit PAS matcher "v1" in "v1" (substring)
        assert err is not None, "allowed_resources str traité comme motif (bug substring) !"


class TestGetListingFilter:

    def test_mission_jwt_without_scope_sees_nothing(self):
        from mcp_vault.auth.context import get_listing_filter
        with _ContextVarGuard(_mission_token_info()):
            f = get_listing_filter()
        assert f["visible"] is False

    def test_mission_jwt_with_scope_gets_explicit_list(self):
        from mcp_vault.auth.context import get_listing_filter
        with _ContextVarGuard(_mission_token_info(allowed=["v1", "v2"])):
            f = get_listing_filter()
        assert f == {"visible": True, "allowed_vault_ids": ["v1", "v2"],
                     "owner_filter": None}

    def test_admin_sees_all(self):
        from mcp_vault.auth.context import get_listing_filter
        info = {"client_name": "admin", "permissions": ["admin"],
                "allowed_resources": []}
        with _ContextVarGuard(info):
            f = get_listing_filter()
        assert f == {"visible": True, "allowed_vault_ids": None, "owner_filter": None}

    def test_bearer_owner_based_preserved(self):
        from mcp_vault.auth.context import get_listing_filter
        info = {"client_name": "cli-1", "permissions": ["read"],
                "allowed_resources": []}
        with _ContextVarGuard(info):
            f = get_listing_filter()
        assert f == {"visible": True, "allowed_vault_ids": None,
                     "owner_filter": "cli-1"}

    def test_empty_client_name_not_visible_fail_close(self):
        """Identité incomplète (client_name="") → rien de visible : owner_filter=""
        serait ignoré par list_spaces (falsy) et listerait TOUT."""
        from mcp_vault.auth.context import get_listing_filter
        info = {"client_name": "", "permissions": ["read"], "allowed_resources": []}
        with _ContextVarGuard(info):
            f = get_listing_filter()
        assert f["visible"] is False

    def test_vault_list_short_circuits_for_unscoped_mission(self):
        """vault_list ne doit PAS appeler list_spaces (le piège list_spaces([])
        ignorerait le filtre) : court-circuit → 0 vault."""
        import sys
        from mcp_vault import server
        vault_list_fn = getattr(server.vault_list, "fn", server.vault_list)
        mock_spaces = MagicMock()
        mock_spaces.list_spaces = AsyncMock(
            return_value={"status": "ok", "vaults": [{"vault_id": "LEAK"}]})
        with _ContextVarGuard(_mission_token_info()), \
             patch.dict(sys.modules, {"mcp_vault.vault.spaces": mock_spaces}):
            result = _run(vault_list_fn())
        assert result == {"status": "ok", "vaults": [], "count": 0}
        assert not mock_spaces.list_spaces.called


class TestEnforceMissionJwtTool:

    @pytest.mark.parametrize("tool", ["pki_ca_list_roles", "pki_ca_public_key",
                                      "pki_list_certs", "system_health",
                                      "system_about", "audit_log",
                                      # #69 data-plane strict : l'admin-plane est
                                      # désormais REFUSÉ aux missions (BLOQUANT-3 Codex).
                                      "vault_create", "vault_update", "vault_delete",
                                      "ssh_ca_setup", "ssh_sign_key", "ssh_ca_public_key",
                                      "ssh_ca_list_roles", "ssh_ca_role_info"])
    def test_mission_jwt_denied_outside_allowlist(self, tool):
        from mcp_vault.auth.context import enforce_mission_jwt_tool
        with _ContextVarGuard(_mission_token_info()):
            err = enforce_mission_jwt_tool(tool)
        assert err is not None and err["status"] == "error"

    @pytest.mark.parametrize("tool", ["vault_list", "vault_info", "secret_read",
                                      "secret_list", "secret_write", "secret_delete",
                                      "secret_types", "secret_generate_password"])
    def test_mission_jwt_allowed_tools(self, tool):
        from mcp_vault.auth.context import enforce_mission_jwt_tool
        with _ContextVarGuard(_mission_token_info()):
            assert enforce_mission_jwt_tool(tool) is None

    def test_bearer_unrestricted(self):
        from mcp_vault.auth.context import enforce_mission_jwt_tool
        info = {"client_name": "cli-1", "permissions": ["read"],
                "allowed_resources": []}
        with _ContextVarGuard(info):
            assert enforce_mission_jwt_tool("pki_ca_list_roles") is None

    def test_check_policy_denies_mission_jwt_before_permissive_return(self):
        """L'ordre compte : mission_jwt a policy_id="" — sans le garde placé AVANT
        le retour permissif 'pas de policy', l'outil serait autorisé."""
        from mcp_vault.auth.context import check_policy
        with _ContextVarGuard(_mission_token_info()):
            err = check_policy("pki_ca_list_roles")
        assert err is not None and "mission" in err["message"]

    def test_check_policy_bearer_no_policy_still_permissive(self):
        from mcp_vault.auth.context import check_policy
        info = {"client_name": "cli-1", "permissions": ["read"],
                "allowed_resources": [], "policy_id": ""}
        with _ContextVarGuard(info):
            assert check_policy("pki_ca_list_roles") is None

    def test_system_about_denies_mission_jwt(self):
        from mcp_vault import server
        fn = getattr(server.system_about, "fn", server.system_about)
        with _ContextVarGuard(_mission_token_info()):
            result = _run(fn())
        assert result["status"] == "error"
        assert "openbao_addr" not in result, "métadonnées d'infra divulguées !"

    def test_system_health_denies_mission_jwt(self):
        from mcp_vault import server
        fn = getattr(server.system_health, "fn", server.system_health)
        with _ContextVarGuard(_mission_token_info()):
            result = _run(fn())
        assert result["status"] == "error"
        assert "services" not in result

    def test_deny_is_audited(self):
        from mcp_vault.auth.context import enforce_mission_jwt_tool
        with _ContextVarGuard(_mission_token_info()), \
             patch("mcp_vault.audit.log_audit") as mock_audit:
            enforce_mission_jwt_tool("pki_ca_list_roles")
        assert mock_audit.called
        assert mock_audit.call_args[0][1] == "denied"


# ═══════════════════════════════════════════════════════════════════════════════
# Admin API — reload JWKS + exclusion des mission JWT
# ═══════════════════════════════════════════════════════════════════════════════

class TestAdminJwksReload:

    def _call_admin(self, path="/admin/api/auth/jwks/reload", method="POST",
                    token_info="patched", auth_header=b"Bearer test-tok"):
        from mcp_vault.admin.api import handle_admin_api
        scope = {"type": "http", "method": method, "path": path,
                 "headers": [(b"authorization", auth_header)], "query_string": b""}
        events = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(ev):
            events.append(ev)

        if token_info == "patched":
            token_info = {"client_name": "admin", "permissions": ["admin"],
                          "allowed_resources": []}
        if token_info is not None:
            ctx = patch("mcp_vault.admin.api._get_token_info",
                        return_value=token_info)
        else:
            ctx = patch("mcp_vault.admin.api._get_token_info", return_value=None)
        with ctx:
            _run(handle_admin_api(scope, receive, send, None))

        start = next(e for e in events if e["type"] == "http.response.start")
        body_ev = next(e for e in events if e["type"] == "http.response.body")
        return start["status"], json.loads(body_ev["body"])

    def test_admin_reload_ok(self):
        _, pub = _make_es256_keypair()
        cache = _static_cache(_make_jwks(pub))
        import mcp_vault.auth.mission_jwt as mj
        with patch.object(mj, "_jwks_cache", cache):
            status, body = self._call_admin()
        assert status == 200
        assert body == {"status": "ok", "keys": 1}

    def test_non_admin_403(self):
        status, body = self._call_admin(
            token_info={"client_name": "user", "permissions": ["read", "write"],
                        "allowed_resources": []})
        assert status == 403

    def test_no_token_401(self):
        status, body = self._call_admin(token_info=None)
        assert status == 401

    def test_cache_not_configured_503(self):
        import mcp_vault.auth.mission_jwt as mj
        with patch.object(mj, "_jwks_cache", None):
            status, body = self._call_admin()
        assert status == 503

    def test_reload_failure_503(self):
        def failing_fetch(url, etag, timeout):
            raise OSError("down")
        cache = JWKSCache("http://mock/x", ttl_seconds=60, fetch=failing_fetch)
        import mcp_vault.auth.mission_jwt as mj
        with patch.object(mj, "_jwks_cache", cache):
            status, body = self._call_admin()
        assert status == 503

    def test_mission_jwt_excluded_from_admin_api(self):
        """INVARIANT : _get_token_info ne dispatch JAMAIS les JWT — un mission
        JWT valide reste 401 sur toute la surface /admin/api/*."""
        from mcp_vault.admin.api import handle_admin_api
        priv, pub = _make_es256_keypair()
        token = _make_mission_token(priv)
        for path, method in [("/admin/api/vaults", "GET"),
                             ("/admin/api/whoami", "GET"),
                             ("/admin/api/health", "GET"),
                             ("/admin/api/auth/jwks/reload", "POST"),
                             # #69 : une mission ne peut JAMAIS s'auto-octroyer un périmètre.
                             ("/admin/api/mission-bindings", "GET"),
                             ("/admin/api/mission-bindings", "POST")]:
            scope = {"type": "http", "method": method, "path": path,
                     "headers": [(b"authorization", b"Bearer " + token.encode())],
                     "query_string": b""}
            events = []

            async def receive():
                return {"type": "http.request", "body": b"", "more_body": False}

            async def send(ev):
                events.append(ev)

            # _get_token_info RÉEL (non patché) : bootstrap ≠ JWT, store absent.
            with patch("mcp_vault.admin.api.get_token_store", return_value=None):
                _run(handle_admin_api(scope, receive, send, None))
            start = next(e for e in events if e["type"] == "http.response.start")
            assert start["status"] == 401, (
                f"mission JWT accepté sur {method} {path} — exclusion cassée !")


# ═══════════════════════════════════════════════════════════════════════════════
# Config PEP — validation + fail-fast boot
# ═══════════════════════════════════════════════════════════════════════════════

class TestMissionPepConfig:

    def _settings(self, **overrides):
        from mcp_vault.config import Settings
        return Settings(**overrides)

    def test_default_bearer_mode_valid(self):
        ok, msg = self._settings().check_mission_pep_config()
        assert ok is True

    def test_invalid_mode_rejected(self):
        ok, msg = self._settings(mcp_auth_mode="yolo").check_mission_pep_config()
        assert ok is False
        assert "MCP_AUTH_MODE" in msg

    def test_jwt_mode_without_jwks_url_rejected(self):
        ok, msg = self._settings(
            mcp_auth_mode="jwt", mcp_instance_id=INSTANCE_ID,
        ).check_mission_pep_config()
        assert ok is False
        assert "MISSION_JWKS_URL" in msg

    def test_jwt_mode_without_audience_rejected(self):
        ok, msg = self._settings(
            mcp_auth_mode="jwt", mission_jwks_url="http://m/jwks",
        ).check_mission_pep_config()
        assert ok is False
        assert "MCP_INSTANCE_ID" in msg

    def test_aud_drift_rejected(self):
        ok, msg = self._settings(
            mcp_instance_id="vault-a", mission_token_aud="vault-b",
        ).check_mission_pep_config()
        assert ok is False
        assert "divergent" in msg

    def test_aud_identical_accepted(self):
        ok, _ = self._settings(
            mcp_instance_id="vault-a", mission_token_aud="vault-a",
        ).check_mission_pep_config()
        assert ok is True

    def test_dual_stack_complete_config_valid(self):
        ok, _ = self._settings(
            mcp_auth_mode="dual-stack", mission_jwks_url="http://m/jwks",
            mcp_instance_id=INSTANCE_ID,
        ).check_mission_pep_config()
        assert ok is True

    def test_resolved_mission_aud_priority(self):
        s = self._settings(mcp_instance_id="canonical")
        assert s.resolved_mission_aud == "canonical"
        s2 = self._settings(mission_token_aud="legacy")
        assert s2.resolved_mission_aud == "legacy"

    def test_create_app_fail_fast_on_bad_pep_config(self):
        """create_app refuse de démarrer en mode jwt sans JWKS (garde-fou #3)."""
        import secrets
        from mcp_vault.server import create_app, settings
        saved = (settings.admin_bootstrap_key, settings.mcp_auth_mode,
                 settings.mission_jwks_url, settings.mcp_instance_id)
        try:
            object.__setattr__(settings, "admin_bootstrap_key",
                               secrets.token_urlsafe(48))
            object.__setattr__(settings, "mcp_auth_mode", "jwt")
            object.__setattr__(settings, "mission_jwks_url", "")
            object.__setattr__(settings, "mcp_instance_id", "")
            with pytest.raises(RuntimeError) as exc_info:
                create_app()
            assert "PEP" in str(exc_info.value)
        finally:
            object.__setattr__(settings, "admin_bootstrap_key", saved[0])
            object.__setattr__(settings, "mcp_auth_mode", saved[1])
            object.__setattr__(settings, "mission_jwks_url", saved[2])
            object.__setattr__(settings, "mcp_instance_id", saved[3])


class TestAdminRestVaultAccessHardening:
    """Le chemin Admin REST (_check_vault_access + GET /admin/api/vaults) doit être
    AUSSI fail-close que le chemin MCP (auth.context) — pas de divergence
    d'enforcement (finding revue indépendante élargie)."""

    def test_check_vault_access_non_list_allowed_treated_empty(self):
        """allowed_resources=str → jamais un test de sous-chaîne ; owner-based."""
        from mcp_vault.admin.api import _check_vault_access
        ti = {"client_name": "cli", "permissions": ["read"],
              "allowed_resources": "prod"}  # str, pas list
        import sys
        mock_spaces = MagicMock()
        mock_spaces.check_vault_owner.return_value = False
        with patch.dict(sys.modules, {"mcp_vault.vault.spaces": mock_spaces}):
            err = _check_vault_access(ti, "prod")  # ne doit PAS matcher "prod" in "prod"
        assert err is not None, "allowed_resources str traité comme motif (bug substring) !"

    def test_check_vault_access_empty_client_name_fail_close(self):
        from mcp_vault.admin.api import _check_vault_access
        ti = {"client_name": "", "permissions": ["read"], "allowed_resources": []}
        import sys
        mock_spaces = MagicMock()
        with patch.dict(sys.modules, {"mcp_vault.vault.spaces": mock_spaces}):
            err = _check_vault_access(ti, "v1")
        assert err is not None and err["status"] == "error"
        assert not mock_spaces.check_vault_owner.called

    def test_check_vault_access_membership_ok(self):
        from mcp_vault.admin.api import _check_vault_access
        ti = {"client_name": "cli", "permissions": ["read"],
              "allowed_resources": ["v1", "v2"]}
        assert _check_vault_access(ti, "v1") is None
        assert _check_vault_access(ti, "v3") is not None

    def test_admin_list_vaults_empty_client_name_fail_close(self):
        """GET /admin/api/vaults avec client_name vide → 0 vault (owner_filter=""
        aurait listé TOUT)."""
        from mcp_vault.admin.api import handle_admin_api
        ti = {"client_name": "", "permissions": ["read"], "allowed_resources": []}
        scope = {"type": "http", "method": "GET", "path": "/admin/api/vaults",
                 "headers": [(b"authorization", b"Bearer x")], "query_string": b""}
        events = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(ev):
            events.append(ev)

        with patch("mcp_vault.admin.api._get_token_info", return_value=ti):
            _run(handle_admin_api(scope, receive, send, None))
        start = next(e for e in events if e["type"] == "http.response.start")
        body = json.loads(next(e for e in events
                               if e["type"] == "http.response.body")["body"])
        assert start["status"] == 200
        assert body == {"status": "ok", "vaults": [], "count": 0}


class TestResolvedAudSingleSourceC18:
    """L'audience du PEP et celle de C18 (secret_consume/wrap/validator) doivent
    provenir de la MÊME source (resolved_mission_aud) — une config mcp_instance_id
    SEUL (mission_token_aud vide) ne doit pas casser le binding C18 (finding Codex)."""

    def test_resolved_aud_with_instance_id_only(self):
        """Config mcp_instance_id seul → resolved_mission_aud propage l'audience
        (c'est la valeur passée à init_mission_token_validator / secret_wrap /
        secret_consume depuis le fix #47)."""
        from mcp_vault.config import Settings
        s = Settings(mcp_instance_id="vault-x", mission_token_aud="",
                     mission_jwks_url="http://m/jwks")
        assert s.resolved_mission_aud == "vault-x", (
            "audience résolue vide → binding C18 cassé en config instance_id-only")

    def test_secret_wrap_enrichment_uses_resolved_aud(self):
        """secret_wrap enrichit expected_aud depuis resolved_mission_aud : une config
        mcp_instance_id seul donne un binding complet, pas 'misconfigured'."""
        from mcp_vault import server
        from mcp_vault.config import Settings
        fn = getattr(server.secret_wrap, "fn", server.secret_wrap)

        s = Settings(mcp_instance_id="vault-x", mission_token_aud="",
                     enforce_mission_token_validation=True,
                     mission_jwks_url="http://m/jwks")
        captured = {}

        async def fake_wrap(vault_id, secret_path, mission_id, operation_id,
                            ttl_seconds, tenant_id="", expected_aud=""):
            captured["expected_aud"] = expected_aud
            return {"status": "ok", "wrap_token": "x", "accessor": "a",
                    "ttl_seconds": ttl_seconds}

        import sys
        mock_wrapping = MagicMock()
        mock_wrapping.wrap_secret = fake_wrap
        admin_info = {"client_name": "admin", "permissions": ["admin", "read", "write"],
                      "allowed_resources": []}
        with patch.object(server, "settings", s), \
             _ContextVarGuard(admin_info), \
             patch.dict(sys.modules, {"mcp_vault.vault.wrapping": mock_wrapping}):
            result = _run(fn(vault_id="v1", secret_path="web/x",
                             mission_id="mis_1", operation_id="op_1", ttl_seconds=60))
        assert result.get("error_type") != "misconfigured", result
        assert captured.get("expected_aud") == "vault-x"
