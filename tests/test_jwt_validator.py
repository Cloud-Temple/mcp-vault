#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests non-complaisant — MissionTokenValidator (issue #26, C18).

Vérifie que le validateur JWT ES256/JWKS échoue RÉELLEMENT sur chaque
variante invalide, et non pas seulement quand il "devrait" échouer
conceptuellement.

Usage :
    PYTHONPATH=src python -m pytest tests/test_jwt_validator.py -v
"""

import json
import time
import os
import sys
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


os.environ.setdefault("MCP_SERVER_NAME", "mcp-vault-test")
os.environ.setdefault("ADMIN_BOOTSTRAP_KEY", "Test-Bootstrap-Key-2026-Pour-Tests!!")


def _run(coro):
    """Run coroutine sans fermer la boucle (évite de casser get_event_loop() dans les tests suivants)."""
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

# ── Génération de clés ES256 pour les tests ───────────────────────────────────

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import jwt


def _make_es256_keypair():
    """Génère une paire de clés EC P-256 pour les tests."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return priv, pub, priv_pem


def _make_jwks(pub_key, kid: str = "test-key-1") -> dict:
    """Construit un JWKS minimaliste à partir d'une clé publique EC P-256."""
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
    import base64
    pub_numbers = pub_key.public_key().public_numbers() if hasattr(pub_key, 'public_key') else pub_key.public_numbers()

    def b64url(n: int) -> str:
        b = n.to_bytes(32, "big")
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    return {
        "keys": [{
            "kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256",
            "kid": kid,
            "x": b64url(pub_numbers.x),
            "y": b64url(pub_numbers.y),
        }]
    }


def _make_token(
    priv_key,
    kid: str = "test-key-1",
    mission_id: str = "mission-abc",
    iss: str = "mcp-mission",
    aud: str = "mcp-vault:test",
    exp_delta: int = 300,
    iat_delta: int = 0,
    extra_claims: dict = None,
    component_kind: str = "vault",
    omit: tuple = (),
) -> str:
    """Génère un JWT ES256 signé pour les tests, COMPLET par défaut (issue #86,
    Lot 2 : le validateur exige désormais les mêmes claims que le PEP — iss, aud,
    exp, iat, mission_id, jti, tenant_id, scope, component_id).

    `iat_delta` : décalage de `iat` par rapport à maintenant (secondes) — permet de
    tester l'anti-skew futur (iat_delta > leeway configuré).

    `omit` : noms de claims à retirer du payload par ailleurs complet — pour tester
    l'absence d'UN claim précis sans construire un payload minimal à la main (qui
    ne prouverait que "un claim quelconque manque", pas lequel).
    """
    now = datetime.now(timezone.utc)
    payload = {
        "iss": iss,
        "aud": aud,
        "exp": int((now + timedelta(seconds=exp_delta)).timestamp()),
        "iat": int((now + timedelta(seconds=iat_delta)).timestamp()),
        "mission_id": mission_id,
        "jti": f"jti-{mission_id}",
        "tenant_id": "tenant-test",
        "scope": [f"{aud}:mission/{mission_id}:*"],
        "component_id": {component_kind: aud},
    }
    for key in omit:
        payload.pop(key, None)
    if extra_claims:
        payload.update(extra_claims)

    priv_pem = priv_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return jwt.encode(payload, priv_pem, algorithm="ES256", headers={"kid": kid})


# ── Fixture : validator avec JWKS mocké ───────────────────────────────────────

def _make_validator(jwks_dict: dict, aud: str = "mcp-vault:test", component_kind: str = "vault"):
    """Crée un MissionTokenValidator adossé à un JWKSCache mocké (pas d'appel réseau).

    Depuis l'issue #47, le validator délègue la résolution des clés au JWKSCache
    partagé — on injecte ici un cache dont le fetch HTTP est simulé.
    """
    import json as _json
    from mcp_vault.auth.jwt_validator import MissionTokenValidator
    from mcp_vault.auth.mission_jwt import JWKSCache

    def fake_fetch(url, etag, timeout):
        return 200, None, _json.dumps(jwks_dict).encode()

    cache = JWKSCache("http://mock-jwks/.well-known/jwks.json",
                      ttl_seconds=60, fetch=fake_fetch)
    return MissionTokenValidator(
        jwks_url="http://mock-jwks/.well-known/jwks.json",
        expected_aud=aud,
        cache_ttl=60,
        max_refresh_per_min=3,
        jwks_cache=cache,
        component_kind=component_kind,
    )


# ── Tests de validation nominale ──────────────────────────────────────────────

class TestMissionTokenValidatorNominal:
    """Contrôle positif : token valide → claims retournés."""

    def test_valid_token_returns_claims(self):
        """Token ES256 valide → claims dict avec mission_id."""
        priv, pub, _ = _make_es256_keypair()
        jwks = _make_jwks(pub)
        validator = _make_validator(jwks)
        token = _make_token(priv, mission_id="mission-xyz", aud="mcp-vault:test")

        claims = validator.validate(token)

        assert claims["mission_id"] == "mission-xyz"
        assert claims["iss"] == "mcp-mission"
        assert "exp" in claims

    def test_valid_token_with_tenant_id(self):
        """Token avec tenant_id → claim retourné."""
        priv, pub, _ = _make_es256_keypair()
        jwks = _make_jwks(pub)
        validator = _make_validator(jwks)
        token = _make_token(priv, extra_claims={"tenant_id": "tenant-42"})

        claims = validator.validate(token)
        assert claims["tenant_id"] == "tenant-42"


# ── Tests C18 : variantes invalides rejetées ─────────────────────────────────

class TestMissionTokenValidatorC18:
    """
    Tests non-complaisant C18 — chaque variante doit être rejetée AVANT
    tout effet (aucun secret libéré, aucun token compact dans les erreurs).
    """

    def _assert_rejected(self, validator, token: str, expected_reason_prefix: str):
        """Vérifie que le token est rejeté avec le bon reason code."""
        from mcp_vault.auth.jwt_validator import MissionTokenError
        with pytest.raises(MissionTokenError) as exc_info:
            validator.validate(token)
        reason = exc_info.value.reason
        assert reason.startswith(expected_reason_prefix), (
            f"Attendu reason '{expected_reason_prefix}*', obtenu '{reason}'"
        )
        # Non-complaisant : le token compact NE doit PAS apparaître dans reason
        assert token not in reason, "Token compact divulgué dans le message d'erreur !"

    def test_invalid_signature_rejected(self):
        """Signature altérée → invalid_signature."""
        priv, pub, _ = _make_es256_keypair()
        priv2, pub2, _ = _make_es256_keypair()  # Clé différente
        jwks = _make_jwks(pub)  # JWKS avec pub1, token signé avec priv2
        validator = _make_validator(jwks)
        token = _make_token(priv2, kid="test-key-1")  # Signe avec priv2 mais kid de pub1

        self._assert_rejected(validator, token, "invalid_signature")

    def test_expired_token_rejected(self):
        """Token expiré → token_expired."""
        priv, pub, _ = _make_es256_keypair()
        jwks = _make_jwks(pub)
        validator = _make_validator(jwks)
        token = _make_token(priv, exp_delta=-10)  # expiré depuis 10s

        self._assert_rejected(validator, token, "token_expired")

    def test_wrong_issuer_rejected(self):
        """iss ≠ mcp-mission → invalid_issuer."""
        priv, pub, _ = _make_es256_keypair()
        jwks = _make_jwks(pub)
        validator = _make_validator(jwks)
        token = _make_token(priv, iss="evil-issuer")

        self._assert_rejected(validator, token, "invalid_issuer")

    def test_wrong_audience_rejected(self):
        """aud ≠ vault_ref configuré → invalid_audience (confused-deputy)."""
        priv, pub, _ = _make_es256_keypair()
        jwks = _make_jwks(pub)
        validator = _make_validator(jwks, aud="mcp-vault:prod")
        token = _make_token(priv, aud="mcp-teleport:prod")  # Token pour teleport, pas vault

        self._assert_rejected(validator, token, "invalid_audience")

    def test_missing_mission_id_rejected(self):
        """mission_id absent (token par ailleurs complet) → missing_claim."""
        priv, pub, _ = _make_es256_keypair()
        jwks = _make_jwks(pub)
        validator = _make_validator(jwks)
        token = _make_token(priv, omit=("mission_id",))

        self._assert_rejected(validator, token, "missing_claim")

    def test_wrong_algorithm_rejected(self):
        """Algorithme non ES256 (ex: HS256) → unsupported_algorithm."""
        from mcp_vault.auth.jwt_validator import MissionTokenValidator, MissionTokenError
        priv, pub, _ = _make_es256_keypair()
        jwks = _make_jwks(pub)
        validator = _make_validator(jwks)

        payload = {
            "iss": "mcp-mission", "aud": "mcp-vault:test",
            "exp": int((datetime.now(timezone.utc) + timedelta(seconds=300)).timestamp()),
            "mission_id": "m-abc",
        }
        token = jwt.encode(payload, "secret-hmac", algorithm="HS256")

        self._assert_rejected(validator, token, "unsupported_algorithm")
        # #78/D5 : fermeture STRICTE — le reason NE doit PAS contenir la valeur `alg`
        # (l'ancien format "unsupported_algorithm:HS256" passait le check de préfixe).
        with pytest.raises(MissionTokenError) as exc_info:
            validator.validate(token)
        assert exc_info.value.reason == "unsupported_algorithm", \
            f"reason non fermé (valeur alg reflétée ?): {exc_info.value.reason!r}"

    def test_unknown_kid_after_refresh_rejected(self):
        """kid absent du JWKS même après refresh → kid_unknown_or_revoked."""
        priv, pub, _ = _make_es256_keypair()
        priv2, pub2, _ = _make_es256_keypair()
        jwks = _make_jwks(pub, kid="key-v1")  # JWKS ne contient que key-v1
        validator = _make_validator(jwks)

        # Token signé avec key-v2 (inconnu du JWKS)
        token = _make_token(priv2, kid="key-v2")

        # Le fetch mocké du JWKSCache retourne toujours le même JWKS (sans key-v2) :
        # le refresh forcé sur kid inconnu ne trouve rien → kid_unknown_or_revoked.
        self._assert_rejected(validator, token, "kid_unknown_or_revoked")

    # ── Lot 2 (issue #86, finding 2) — alignement sur le contrat PEP ────────────

    def test_component_id_mismatch_rejected(self):
        """RÉGRESSION EXACTE DU FINDING 2 : un JWT avec `aud` MULTIPLE (contient
        l'audience attendue ET une autre instance) mais `component_id` pointant
        vers l'AUTRE instance doit être rejeté. Avant ce lot, ce token passait C18
        (aud non vérifié comme liste, component_id jamais vérifié) alors que le PEP
        /mcp l'aurait refusé — confusion inter-instances (confused-deputy)."""
        priv, pub, _ = _make_es256_keypair()
        jwks = _make_jwks(pub)
        validator = _make_validator(jwks, aud="mcp-vault:prod")
        token = _make_token(
            priv, aud="mcp-vault:prod",
            extra_claims={
                "aud": ["mcp-vault:prod", "mcp-vault:staging"],  # contient bien l'attendue
                "component_id": {"vault": "mcp-vault:staging"},  # mais désigne l'AUTRE instance
            },
        )
        self._assert_rejected(validator, token, "component_id_mismatch")

    def test_missing_component_id_rejected(self):
        """component_id absent (token par ailleurs complet) → component_id_mismatch
        (pas missing_claim : component_id n'est pas dans le `require` PyJWT, c'est
        le check manuel post-décodage de validate_mission_token qui le détecte)."""
        priv, pub, _ = _make_es256_keypair()
        jwks = _make_jwks(pub)
        validator = _make_validator(jwks)
        token = _make_token(priv, omit=("component_id",))
        self._assert_rejected(validator, token, "component_id_mismatch")

    def test_component_kind_non_default_respected(self):
        """component_kind non-défaut (ex: 'live_memory') est réellement pris en
        compte, pas juste accepté silencieusement sans effet : un component_id
        clé 'vault' (l'ancien défaut) ne doit PLUS matcher pour ce validateur."""
        priv, pub, _ = _make_es256_keypair()
        jwks = _make_jwks(pub)
        validator = _make_validator(jwks, component_kind="live_memory")

        token_ok = _make_token(
            priv, extra_claims={"component_id": {"live_memory": "mcp-vault:test"}},
        )
        claims = validator.validate(token_ok)
        assert claims["mission_id"] == "mission-abc"

        token_wrong_kind = _make_token(
            priv, extra_claims={"component_id": {"vault": "mcp-vault:test"}},
        )
        self._assert_rejected(validator, token_wrong_kind, "component_id_mismatch")

    def test_init_mission_token_validator_propagates_component_kind(self):
        """Câblage réel : `init_mission_token_validator()` (le point d'entrée
        utilisé par lifecycle.py, pas la construction directe de
        MissionTokenValidator) doit transmettre `component_kind` jusqu'au
        validateur singleton résultant — sinon MCP_COMPONENT_KIND non-défaut ne
        ferait rien malgré le câblage dans lifecycle.py (issue #86)."""
        import mcp_vault.auth.jwt_validator as jv
        from mcp_vault.auth.jwt_validator import MissionTokenError
        priv, pub, _ = _make_es256_keypair()
        jwks = _make_jwks(pub)
        import json as _json

        def fake_fetch(url, etag, timeout):
            return 200, None, _json.dumps(jwks).encode()

        saved = jv._validator
        try:
            from mcp_vault.auth.mission_jwt import JWKSCache
            # init_mission_token_validator() appelle init_jwks_cache() en interne,
            # qui créerait un JWKSCache RÉEL (fetch HTTP véritable au premier
            # get_key()). On patche get_jwks_cache — consulté par _get_cache() de
            # l'instance à CHAQUE validate() — pour qu'il retourne toujours le cache
            # mocké, peu importe ce que fait init_jwks_cache en parallèle. Le patch
            # doit rester actif pendant les appels validate() ci-dessous, pas
            # seulement pendant l'initialisation.
            cache = JWKSCache("http://mock-jwks/x", ttl_seconds=60, fetch=fake_fetch)
            patcher = patch.object(jv, "get_jwks_cache", return_value=cache)
            patcher.start()
            try:
                validator = jv.init_mission_token_validator(
                    jwks_url="http://mock-jwks/x",
                    expected_aud="mcp-vault:test",
                    component_kind="live_memory",
                )
                assert jv.get_mission_token_validator() is validator

                token_ok = _make_token(
                    priv, extra_claims={"component_id": {"live_memory": "mcp-vault:test"}},
                )
                claims = validator.validate(token_ok)
                assert claims["mission_id"] == "mission-abc"

                token_wrong_kind = _make_token(
                    priv, extra_claims={"component_id": {"vault": "mcp-vault:test"}},
                )
                with pytest.raises(MissionTokenError) as exc_info:
                    validator.validate(token_wrong_kind)
                assert exc_info.value.reason == "component_id_mismatch"
            finally:
                patcher.stop()
        finally:
            jv._validator = saved

    def test_missing_tenant_id_rejected(self):
        priv, pub, _ = _make_es256_keypair()
        jwks = _make_jwks(pub)
        validator = _make_validator(jwks)
        token = _make_token(priv, omit=("tenant_id",))
        self._assert_rejected(validator, token, "missing_claim")

    def test_missing_jti_rejected(self):
        priv, pub, _ = _make_es256_keypair()
        jwks = _make_jwks(pub)
        validator = _make_validator(jwks)
        token = _make_token(priv, omit=("jti",))
        self._assert_rejected(validator, token, "missing_claim")

    def test_missing_scope_rejected(self):
        priv, pub, _ = _make_es256_keypair()
        jwks = _make_jwks(pub)
        validator = _make_validator(jwks)
        token = _make_token(priv, omit=("scope",))
        self._assert_rejected(validator, token, "missing_claim")

    def test_empty_scope_rejected(self):
        """scope PRÉSENT mais liste vide → bad_scope (distinct de missing_claim :
        PyJWT considère une liste vide comme un claim « présent »)."""
        priv, pub, _ = _make_es256_keypair()
        jwks = _make_jwks(pub)
        validator = _make_validator(jwks)
        token = _make_token(priv, extra_claims={"scope": []})
        self._assert_rejected(validator, token, "bad_scope")

    def test_empty_tenant_id_rejected(self):
        priv, pub, _ = _make_es256_keypair()
        jwks = _make_jwks(pub)
        validator = _make_validator(jwks)
        token = _make_token(priv, extra_claims={"tenant_id": ""})
        self._assert_rejected(validator, token, "bad_tenant_id")

    def test_iat_in_future_beyond_leeway_rejected(self):
        """iat daté dans le futur au-delà du leeway configuré → iat_future
        (anti-skew horloge avancée — absent de C18 avant ce lot)."""
        priv, pub, _ = _make_es256_keypair()
        jwks = _make_jwks(pub)
        from mcp_vault.auth.jwt_validator import MissionTokenValidator
        from mcp_vault.auth.mission_jwt import JWKSCache
        import json as _json

        def fake_fetch(url, etag, timeout):
            return 200, None, _json.dumps(jwks).encode()

        cache = JWKSCache("http://mock-jwks/x", ttl_seconds=60, fetch=fake_fetch)
        validator = MissionTokenValidator(
            jwks_url="http://mock-jwks/x", expected_aud="mcp-vault:test",
            jwks_cache=cache, leeway_seconds=10,
        )
        token = _make_token(priv, iat_delta=100)  # 100s dans le futur, leeway=10s
        self._assert_rejected(validator, token, "iat_future")

    def test_expired_with_configured_leeway_still_rejected(self):
        """`exp` reste STRICT (leeway=0) même avec MISSION_TOKEN_LEEWAY_SECONDS
        configuré à une valeur non nulle — le leeway ne s'applique QU'à `iat`,
        jamais à `exp` (alignement PEP, issue #86). Avant ce lot, ce comportement
        était déjà celui produit de fait (bug PyJWT ignorant `options["leeway"]"),
        ce test le rend explicite et intentionnel."""
        priv, pub, _ = _make_es256_keypair()
        jwks = _make_jwks(pub)
        from mcp_vault.auth.jwt_validator import MissionTokenValidator
        from mcp_vault.auth.mission_jwt import JWKSCache
        import json as _json

        def fake_fetch(url, etag, timeout):
            return 200, None, _json.dumps(jwks).encode()

        cache = JWKSCache("http://mock-jwks/x", ttl_seconds=60, fetch=fake_fetch)
        validator = MissionTokenValidator(
            jwks_url="http://mock-jwks/x", expected_aud="mcp-vault:test",
            jwks_cache=cache, leeway_seconds=10,
        )
        token = _make_token(priv, exp_delta=-1)  # expiré depuis 1s
        self._assert_rejected(validator, token, "token_expired")

    def test_expected_iss_override_rejected_at_construction(self):
        """Un `expected_iss` différent de 'mcp-mission' est refusé à la
        construction — le contrat mcp-mission fixe l'issuer, non configurable
        depuis l'alignement sur le PEP (évite l'illusion d'un réglage sans effet)."""
        from mcp_vault.auth.jwt_validator import MissionTokenValidator
        with pytest.raises(ValueError, match="mcp-mission"):
            MissionTokenValidator(jwks_url="http://m/jwks", expected_iss="other-issuer")

    def test_empty_expected_aud_rejected_explicitly(self):
        """`expected_aud` vide → rejet EXPLICITE (misconfigured_expected_aud), pas
        un rejet confus « invalid_audience » qui laisserait croire à un problème
        côté token alors que la cause est une configuration serveur incomplète."""
        from mcp_vault.auth.jwt_validator import MissionTokenValidator, MissionTokenError
        priv, pub, _ = _make_es256_keypair()
        validator = _make_validator(_make_jwks(pub), aud="")
        token = _make_token(priv)
        with pytest.raises(MissionTokenError) as exc_info:
            validator.validate(token)
        assert exc_info.value.reason == "misconfigured_expected_aud"

    def test_token_compact_never_in_error_message(self):
        """Le token compact ne doit jamais apparaître dans le message d'erreur."""
        from mcp_vault.auth.jwt_validator import MissionTokenError
        priv, pub, _ = _make_es256_keypair()
        jwks = _make_jwks(pub)
        validator = _make_validator(jwks)
        token = _make_token(priv, iss="evil-issuer")  # Invalide

        with pytest.raises(MissionTokenError) as exc_info:
            validator.validate(token)

        error_str = str(exc_info.value)
        assert token not in error_str, "CRITIQUE : token compact divulgué dans l'erreur !"
        assert "eyJ" not in error_str, "CRITIQUE : fragment JWT trouvé dans l'erreur !"

    def test_malformed_token_rejected(self):
        """Token complètement malformé → invalid_token_format."""
        from mcp_vault.auth.jwt_validator import MissionTokenError
        priv, pub, _ = _make_es256_keypair()
        validator = _make_validator(_make_jwks(pub))

        for bad_token in ["not.a.jwt", "garbage", "", "eyJ.bad"]:
            with pytest.raises(MissionTokenError) as exc_info:
                validator.validate(bad_token)
            # #78/D5 : reason FERMÉ — plus de valeur `alg` interpolée (était "unsupported_algorithm:missing").
            assert exc_info.value.reason in ("invalid_token_format", "decode_error",
                                              "unsupported_algorithm", "validation_failed")


# ── Tests JWKS cache et anti-DoS (via le JWKSCache partagé — issue #47) ───────

class TestJwksCacheAndRateLimit:
    """Cache JWKS TTL-borné et anti-DoS (backoff exponentiel du JWKSCache partagé).

    Depuis l'issue #47, le rate-limit fenêtré interne du validator est remplacé
    par le backoff exponentiel du JWKSCache — même objectif anti-DoS de
    l'endpoint JWKS de mcp-mission, sémantique testée ici via délégation.
    """

    def test_jwks_cache_used_within_ttl(self):
        """Dans le TTL, le fetch HTTP n'est pas rappelé (cache servi)."""
        import json as _json
        from mcp_vault.auth.jwt_validator import MissionTokenValidator
        from mcp_vault.auth.mission_jwt import JWKSCache

        priv, pub, _ = _make_es256_keypair()
        jwks_dict = _make_jwks(pub)
        fetch_count = [0]

        def counting_fetch(url, etag, timeout):
            fetch_count[0] += 1
            return 200, None, _json.dumps(jwks_dict).encode()

        cache = JWKSCache("http://mock-jwks/x", ttl_seconds=60, fetch=counting_fetch)
        validator = MissionTokenValidator(
            jwks_url="http://mock-jwks/x", expected_aud="mcp-vault:test",
            jwks_cache=cache,
        )
        token = _make_token(priv)

        validator.validate(token)   # 1er appel → peuple le cache (1 fetch)
        validator.validate(token)   # cache frais → aucun fetch supplémentaire

        assert fetch_count[0] == 1, (
            f"Cache non utilisé dans le TTL (fetch appelé {fetch_count[0]} fois)"
        )

    def test_backoff_blocks_refetch_after_failure(self):
        """Fetch en échec → fail-close jwks_unavailable, et la fenêtre de backoff
        bloque tout refetch réseau immédiat (anti-DoS)."""
        from mcp_vault.auth.jwt_validator import MissionTokenValidator, MissionTokenError
        from mcp_vault.auth.mission_jwt import JWKSCache

        calls = [0]

        def failing_fetch(url, etag, timeout):
            calls[0] += 1
            raise OSError("connexion refusée")

        cache = JWKSCache("http://mock-jwks/x", ttl_seconds=60, fetch=failing_fetch)
        validator = MissionTokenValidator(
            jwks_url="http://mock-jwks/x", expected_aud="mcp-vault:test",
            jwks_cache=cache,
        )
        priv, pub, _ = _make_es256_keypair()
        token = _make_token(priv)

        # Cache jamais peuplé + fetch KO → fail-close (jamais de clé servie).
        with pytest.raises(MissionTokenError) as exc_info:
            validator.validate(token)
        assert exc_info.value.reason == "jwks_unavailable"
        first_calls = calls[0]
        assert first_calls >= 1

        # Appel immédiat suivant : la fenêtre de backoff interdit le refetch réseau.
        with pytest.raises(MissionTokenError) as exc_info:
            validator.validate(token)
        assert exc_info.value.reason == "jwks_unavailable"
        assert calls[0] == first_calls, (
            "Refetch réseau pendant la fenêtre de backoff — anti-DoS cassé"
        )


# ── Tests WrapRegistry extensions ────────────────────────────────────────────

class TestWrapRegistryC18Extensions:
    """Tests des nouvelles méthodes WrapRegistry (composite key, consuming, consumed)."""

    def _make_registry(self):
        """WrapRegistry en mémoire (pas de S3)."""
        from mcp_vault.vault.wrapping import WrapRegistry

        class InMemoryRegistry(WrapRegistry):
            def __init__(self):
                self._wraps = []
                self._cache_time = float("inf")

            def load(self): pass
            def _save(self) -> bool: return True

        return InMemoryRegistry()

    def test_get_by_composite_key_found(self):
        """Lookup (op_id, mission_id) retourne l'entrée active."""
        r = self._make_registry()
        r.register_pending("op-1", "m-1", "vault-a", "path/key", 300)
        r.mark_active("op-1", "m-1", "accessor-xyz")

        entry = r.get_by_composite_key("op-1", "m-1")
        assert entry is not None
        assert entry["mission_id"] == "m-1"
        assert entry["status"] == "active"

    def test_get_by_composite_key_not_found_wrong_mission(self):
        """Lookup avec mission_id incorrect → None (anti-collision)."""
        r = self._make_registry()
        r.register_pending("op-1", "m-1", "vault-a", "path/key", 300)
        r.mark_active("op-1", "m-1", "accessor-xyz")

        entry = r.get_by_composite_key("op-1", "m-WRONG")
        assert entry is None

    def test_try_mark_consuming_transitions_to_consuming(self):
        """try_mark_consuming passe "active" → "consuming"."""
        r = self._make_registry()
        r.register_pending("op-1", "m-1", "vault-a", "path/key", 300)
        r.mark_active("op-1", "m-1", "accessor-xyz")

        result = r.try_mark_consuming("op-1", "m-1")
        assert result is True

        entry = next(e for e in r._wraps if e["operation_id"] == "op-1")
        assert entry["status"] == "consuming"

    def test_try_mark_consuming_already_consuming_returns_false(self):
        """Deuxième try_mark_consuming sur même entry → False (anti-replay)."""
        r = self._make_registry()
        r.register_pending("op-1", "m-1", "vault-a", "path/key", 300)
        r.mark_active("op-1", "m-1", "accessor-xyz")

        r.try_mark_consuming("op-1", "m-1")  # Premier
        result = r.try_mark_consuming("op-1", "m-1")  # Deuxième
        assert result is False

    def test_mark_consumed_after_consuming(self):
        """mark_consumed finalise l'état "consuming" → "consumed"."""
        r = self._make_registry()
        r.register_pending("op-1", "m-1", "vault-a", "path/key", 300)
        r.mark_active("op-1", "m-1", "accessor-xyz")
        r.try_mark_consuming("op-1", "m-1")

        result = r.mark_consumed("op-1", "m-1")
        assert result is True

        entry = next(e for e in r._wraps if e["operation_id"] == "op-1")
        assert entry["status"] == "consumed"

    def test_aucun_retour_a_active_apres_le_cas(self):
        """
        REMPLACE `test_rollback_consuming_restores_active` (issue #78, finding 2).

        L'ancien test asseyait le défaut : il exigeait qu'un échec d'unwrap
        ramène l'entrée à "active", donc « réessayable ». Or une fois le CAS
        franchi, l'appel est parti — OpenBao a pu consommer le jeton avant que
        la réponse ne se perde. Réinscrire "active" annonce disponible une
        provision peut-être brûlée.

        La primitive de retour arrière n'existe donc plus, et aucune transition
        ne ramène à "active" depuis "consuming".
        """
        r = self._make_registry()
        assert not hasattr(r, "rollback_consuming"), (
            "rollback_consuming est réintroduit — le registre peut de nouveau "
            "annoncer disponible un wrap potentiellement consommé")

        for terminal, methode in (("unusable", "mark_unusable"),
                                  ("consume_outcome_unknown", "mark_outcome_unknown")):
            r._wraps = []
            r.register_pending("op-1", "m-1", "vault-a", "path/key", 300)
            r.mark_active("op-1", "m-1", "accessor-xyz")
            r.try_mark_consuming("op-1", "m-1")

            getattr(r, methode)("op-1", "m-1")

            entry = next(e for e in r._wraps if e["operation_id"] == "op-1")
            assert entry["status"] == terminal
            assert entry["status"] != "active"

    def test_les_etats_terminaux_sont_definitifs(self):
        """Aucune transition ne sort d'un état terminal de consommation."""
        r = self._make_registry()
        r.register_pending("op-1", "m-1", "vault-a", "path/key", 300)
        r.mark_active("op-1", "m-1", "accessor-xyz")
        r.try_mark_consuming("op-1", "m-1")
        r.mark_unusable("op-1", "m-1")

        # Ni une seconde consommation, ni une révocation ne doivent le muter.
        assert r.try_mark_consuming("op-1", "m-1") is False
        assert r.mark_consumed("op-1", "m-1") is False
        assert r.mark_revoked("accessor-xyz") is False

        entry = next(e for e in r._wraps if e["operation_id"] == "op-1")
        assert entry["status"] == "unusable"

    def test_register_pending_stores_tenant_id_and_aud(self):
        """register_pending stocke tenant_id et expected_aud (issue #26)."""
        r = self._make_registry()
        r.register_pending(
            "op-1", "m-1", "vault-a", "path/key", 300,
            tenant_id="tenant-42", expected_aud="mcp-vault:prod",
        )
        entry = r._wraps[0]
        assert entry["tenant_id"] == "tenant-42"
        assert entry["expected_aud"] == "mcp-vault:prod"

    def test_get_by_composite_key_ambiguity_returns_none(self):
        """Deux entrées active avec même (op_id, mission_id) → None (anomalie)."""
        r = self._make_registry()
        # Forcer deux entrées actives (état anormal)
        r._wraps = [
            {"operation_id": "op-1", "mission_id": "m-1", "status": "active",
             "accessor": "a1", "vault_id": "v", "secret_path": "p",
             "created_at": "", "expires_at": "", "tenant_id": "", "expected_aud": ""},
            {"operation_id": "op-1", "mission_id": "m-1", "status": "active",
             "accessor": "a2", "vault_id": "v", "secret_path": "p",
             "created_at": "", "expires_at": "", "tenant_id": "", "expected_aud": ""},
        ]
        assert r.get_by_composite_key("op-1", "m-1") is None


# ── Tests secret_consume (outil MCP) ─────────────────────────────────────────

class TestSecretConsumeEndToEnd:
    """Tests comportementaux de l'outil MCP secret_consume."""

    def _make_scope(self, token="admin-token"):
        import asyncio

        async def _call_tool(tool_name, args, settings_override=None):
            """Appelle l'outil server.secret_consume avec mocks."""
            import os
            os.environ["MCP_SERVER_NAME"] = "mcp-vault-test"
            os.environ["ADMIN_BOOTSTRAP_KEY"] = "Test-Bootstrap-Key-2026-Pour-Tests!!"
            if settings_override:
                for k, v in settings_override.items():
                    os.environ[k.upper()] = str(v)
            from mcp_vault.server import secret_consume
            return await secret_consume(**args)

        return _call_tool

    def test_consume_no_jwks_no_enforce_succeeds(self):
        """Sans JWKS configuré et ENFORCE=false : consume réussit si registry OK."""
        import asyncio
        import os

        os.environ.pop("MISSION_JWKS_URL", None)
        os.environ["ENFORCE_MISSION_TOKEN_VALIDATION"] = "false"

        from unittest.mock import AsyncMock, patch, MagicMock

        mock_secret_data = {"data": {"password": "s3cr3t"}, "status": "ok"}

        with patch("mcp_vault.vault.wrapping.consume_wrap_secret",
                   new_callable=AsyncMock, return_value=mock_secret_data) as mock_consume:
            from mcp_vault.server import secret_consume
            result = _run(secret_consume(
                wrap_token="wt-abc",
                operation_id="op-123",
                mission_token="dummy-not-validated",
            ))

        assert result["status"] == "ok"
        mock_consume.assert_called_once()

    def test_consume_with_enforce_and_no_jwks_returns_error(self):
        """ENFORCE=true mais MISSION_JWKS_URL vide → erreur misconfigured."""
        import asyncio, os
        from mcp_vault.server import settings

        original_enforce = settings.enforce_mission_token_validation
        original_jwks = settings.mission_jwks_url
        try:
            # Patcher les settings directement (pas de reload de module)
            object.__setattr__(settings, 'enforce_mission_token_validation', True)
            object.__setattr__(settings, 'mission_jwks_url', '')

            from mcp_vault.server import secret_consume
            result = _run(secret_consume(
                wrap_token="wt-abc",
                operation_id="op-123",
                mission_token="dummy",
            ))

            assert result["status"] == "error"
            assert result["error_type"] == "misconfigured"
        finally:
            object.__setattr__(settings, 'enforce_mission_token_validation', original_enforce)
            object.__setattr__(settings, 'mission_jwks_url', original_jwks)

    def test_consume_with_enforce_and_empty_expected_aud_returns_misconfigured(self):
        """ENFORCE=true, JWKS configuré, mais audience résolue vide (JWT_URL
        configuré sans MCP_INSTANCE_ID/MISSION_TOKEN_AUD) → misconfigured (pas
        jwt_invalid) — cohérent avec les autres retours misconfigured de ce bloc
        et avec secret_wrap (issue #86)."""
        import mcp_vault.auth.jwt_validator as jv
        from mcp_vault.auth.jwt_validator import MissionTokenError
        from mcp_vault.server import settings

        original_enforce = settings.enforce_mission_token_validation
        original_jwks = settings.mission_jwks_url
        try:
            object.__setattr__(settings, "enforce_mission_token_validation", True)
            object.__setattr__(settings, "mission_jwks_url", "http://mock/.well-known/jwks.json")

            mock_validator = MagicMock()
            mock_validator.validate.side_effect = MissionTokenError("misconfigured_expected_aud")

            with patch.object(jv, "_validator", mock_validator):
                from mcp_vault.server import secret_consume
                result = _run(secret_consume(
                    wrap_token="wt-abc", operation_id="op-123", mission_token="dummy",
                ))
        finally:
            object.__setattr__(settings, "enforce_mission_token_validation", original_enforce)
            object.__setattr__(settings, "mission_jwks_url", original_jwks)

        assert result["status"] == "error", result
        assert result["error_type"] == "misconfigured", (
            f"attendu misconfigured (config serveur), obtenu {result['error_type']!r} "
            "— ne doit pas être confondu avec un JWT réellement invalide"
        )

    def test_singleton_used_not_reinstantiated(self):
        """
        P0 — Le singleton MissionTokenValidator est réutilisé entre appels.
        Non-complaisant : si secret_consume réinstanciait le validator, le mock
        posé sur l'instance singleton ne serait jamais appelé.
        """
        from unittest.mock import MagicMock, patch, AsyncMock
        import mcp_vault.auth.jwt_validator as jv

        mock_validator = MagicMock()
        mock_validator.validate.return_value = {
            "mission_id": "m-singleton", "aud": "mcp-vault:test",
            "tenant_id": "", "iss": "mcp-mission", "exp": 9999999999,
        }
        mock_consume = AsyncMock(return_value={"status": "ok", "data": {}})

        from mcp_vault.server import settings
        orig_jwks = settings.mission_jwks_url
        try:
            object.__setattr__(settings, "mission_jwks_url", "http://mock/.well-known/jwks.json")
            with patch.object(jv, "_validator", mock_validator), \
                 patch("mcp_vault.vault.wrapping.consume_wrap_secret", new_callable=AsyncMock,
                        return_value={"status": "ok"}):
                from mcp_vault.server import secret_consume
                _run(secret_consume(wrap_token="wt1", operation_id="op-1", mission_token="t1"))
                _run(secret_consume(wrap_token="wt2", operation_id="op-2", mission_token="t2"))
        finally:
            object.__setattr__(settings, "mission_jwks_url", orig_jwks)

        # Le singleton doit avoir été appelé 2 fois (pas réinstancié)
        assert mock_validator.validate.call_count == 2, (
            f"Attendu 2 appels au singleton, obtenu {mock_validator.validate.call_count}"
            " — le validator a probablement été réinstancié à chaque appel !"
        )

    def test_secret_wrap_enforce_true_auto_enriches_expected_aud(self):
        """
        ÉLEVÉ — En mode ENFORCE=true+JWKS, secret_wrap impose expected_aud automatiquement.
        Non-complaisant : si expected_aud reste vide, le binding C18 est inactif en prod.
        """
        from mcp_vault.server import settings
        from unittest.mock import AsyncMock, patch

        orig_enforce = settings.enforce_mission_token_validation
        orig_jwks = settings.mission_jwks_url
        orig_aud = settings.mission_token_aud
        try:
            object.__setattr__(settings, "enforce_mission_token_validation", True)
            object.__setattr__(settings, "mission_jwks_url", "http://mock/.well-known/jwks.json")
            object.__setattr__(settings, "mission_token_aud", "mcp-vault:prod")

            captured_calls = []

            async def mock_wrap(vault_id, secret_path, mission_id, operation_id,
                                ttl_seconds=300, tenant_id="", expected_aud=""):
                captured_calls.append({"expected_aud": expected_aud})
                return {"status": "ok", "wrap_token": "wt", "accessor": "ACC",
                        "secret_id": "s", "expires_at": "2026-01-01", "vault_url": "",
                        "intended_use": "password"}

            # #115 : la garde de secret_wrap est check_policy + check_wrap_permission
            # — une identité admin injectée passe tout (bypass), plus de patchs
            # de check_admin/check_access/check_path_policy.
            from tests.conftest import admin_auth_context
            with patch("mcp_vault.vault.wrapping.wrap_secret", side_effect=mock_wrap), \
                 admin_auth_context():
                from mcp_vault.server import secret_wrap
                _run(secret_wrap(
                    vault_id="prod", secret_path="db/pass",
                    mission_id="m-1", operation_id="op-1",
                    # expected_aud NON fourni → doit être auto-enrichi
                    # #78 finding 4 : tenant_id est OBLIGATOIRE en mode durci — le
                    # serveur ne peut pas le déduire. Il est fourni ici pour que ce
                    # test continue de porter sur l'enrichissement de l'AUDIENCE,
                    # et non sur le refus de binding incomplet (couvert par
                    # tests/test_binding_enforce_78.py).
                    tenant_id="tenant-1",
                ))
        finally:
            object.__setattr__(settings, "enforce_mission_token_validation", orig_enforce)
            object.__setattr__(settings, "mission_jwks_url", orig_jwks)
            object.__setattr__(settings, "mission_token_aud", orig_aud)

        assert len(captured_calls) == 1, "wrap_secret non appelé"
        assert captured_calls[0]["expected_aud"] == "mcp-vault:prod", (
            f"expected_aud non enrichi en mode ENFORCE=true: {captured_calls[0]}"
        )

    def test_singleton_absent_enforce_true_returns_misconfigured(self):
        """
        ÉLEVÉ — Si singleton None + ENFORCE=true → misconfigured (pas de fallback éphémère).
        Non-complaisant : si le fallback réinstanciait un validator, le cache serait perdu
        et le rate-limit non global — exactement le bug P0 qu'on corrige.
        """
        import mcp_vault.auth.jwt_validator as jv
        from mcp_vault.server import settings

        orig_enforce = settings.enforce_mission_token_validation
        orig_jwks = settings.mission_jwks_url
        try:
            object.__setattr__(settings, "enforce_mission_token_validation", True)
            object.__setattr__(settings, "mission_jwks_url", "http://mock/.well-known/jwks.json")
            with patch.object(jv, "_validator", None):  # singleton absent
                from mcp_vault.server import secret_consume
                result = _run(secret_consume(
                    wrap_token="wt", operation_id="op-1", mission_token="dummy"
                ))
        finally:
            object.__setattr__(settings, "enforce_mission_token_validation", orig_enforce)
            object.__setattr__(settings, "mission_jwks_url", orig_jwks)

        assert result["status"] == "error", f"Attendu error, obtenu: {result}"
        assert result["error_type"] == "misconfigured", f"Attendu misconfigured: {result}"

    def test_enforce_true_inactive_parameter_mission_blocked_despite_active_header_identity(self):
        """
        CRITIQUE (issue #86, finding 1 — POC de la revue Codex pré-canari #47).

        Le PEP /mcp valide le TRANSPORT (header, identité A). `secret_consume`
        valide le PARAMÈTRE `mission_token` (identité B) — volontairement découplé
        du header (cf. auth/context.py, confirmé par la revue de plan Lot 1 : ne PAS
        lier les deux, le design est correct une fois l'enforcement C18 garanti).

        POC original (AVANT ce lot) : `inactive_parameter_mission_with_active_
        header_context_release=ok` — avec ENFORCE_MISSION_TOKEN_VALIDATION=false
        (défaut), une mission B confirmée INACTIVE libérait quand même le secret.

        Ce test prouve qu'avec enforce=true (désormais imposé au boot par
        Settings.check_mission_pep_config() dès que la validation mission_token est
        active), la mission B inactive est refusée AVANT tout appel à
        consume_wrap_secret — quelle que soit l'identité active sur le transport.

        NON-COMPLAISANCE (revue du diff Codex, mutation adversariale) : le mock de
        `_check_mission_active` doit être DISCRIMINANT (side_effect qui distingue
        mission-A de mission-B), sinon un bug qui confondrait les deux missions
        resterait indétectable — une première version de ce test avec un
        `return_value` statique restait verte même après substitution de
        `mission-B` par `mission-A` dans le code testé.
        """
        import mcp_vault.auth.jwt_validator as jv
        from mcp_vault.auth.context import current_token_info
        from mcp_vault.server import settings

        orig_enforce = settings.enforce_mission_token_validation
        orig_jwks = settings.mission_jwks_url
        orig_status_url = settings.mission_status_url
        try:
            object.__setattr__(settings, "enforce_mission_token_validation", True)
            object.__setattr__(settings, "mission_jwks_url", "http://mock/.well-known/jwks.json")
            object.__setattr__(settings, "mission_status_url", "http://mock/status/{mission_id}")

            # Paramètre mission_token : identité B, JWT authentifié (validateur mocké).
            mock_validator = MagicMock()
            mock_validator.validate.return_value = {
                "mission_id": "mission-B", "tenant_id": "tenant-B",
                "aud": "mcp-vault:test", "iss": "mcp-mission", "exp": 9999999999,
            }

            # Contexte transport : identité A, active, SANS AUCUN lien avec B — le
            # PEP aurait validé A sur le header ; secret_consume ne le consulte pas.
            tok = current_token_info.set({
                "auth_type": "mission_jwt", "client_name": "mission:tenant-A",
                "mission_id": "mission-A", "tenant_id": "tenant-A",
                "permissions": ["read"], "allowed_resources": ["vault-a"],
            })

            # Discriminant : A est active, B est inactive. Un code qui vérifierait
            # (par erreur) l'identité du transport (A) au lieu du paramètre (B)
            # obtiendrait `active=True` et le test échouerait sur l'assertion finale.
            async def fake_check_mission_active(mission_id, status_url_template, cache_ttl):
                if mission_id == "mission-A":
                    return True, ""
                if mission_id == "mission-B":
                    return False, "mission_inactive"
                raise AssertionError(f"mission_id inattendu dans le test : {mission_id!r}")

            mock_consume = AsyncMock(return_value={"status": "ok", "data": {"secret": "leaked"}})
            try:
                with patch.object(jv, "_validator", mock_validator), \
                     patch("mcp_vault.server._check_mission_active",
                           side_effect=fake_check_mission_active) as mock_status, \
                     patch("mcp_vault.vault.wrapping.consume_wrap_secret", mock_consume):
                    from mcp_vault.server import secret_consume
                    result = _run(secret_consume(
                        wrap_token="wt-b", operation_id="op-b",
                        mission_token="jwt-of-mission-b",
                    ))
            finally:
                current_token_info.reset(tok)
        finally:
            object.__setattr__(settings, "enforce_mission_token_validation", orig_enforce)
            object.__setattr__(settings, "mission_jwks_url", orig_jwks)
            object.__setattr__(settings, "mission_status_url", orig_status_url)

        assert mock_status.await_count == 1, "check_mission_active jamais appelé"
        # Preuve explicite que c'est bien B (le paramètre), et non A (le transport),
        # qui a été soumis au contrôle d'activité — pas seulement le résultat final.
        called_mission_id = mock_status.call_args.kwargs.get("mission_id")
        assert called_mission_id == "mission-B", (
            f"check_mission_active appelé avec mission_id={called_mission_id!r} — "
            "attendu 'mission-B' (le paramètre mission_token), pas l'identité du "
            "transport."
        )
        assert result["status"] == "error", (
            f"mission B inactive mais secret_consume a renvoyé un succès : {result}")
        assert result["error_type"] == "mission_inactive", result
        mock_consume.assert_not_called()

    def test_enforce_true_active_parameter_mission_reaches_unwrap(self):
        """
        Symétrique du test précédent (issue #86) : si la mission B du PARAMÈTRE est
        ACTIVE, `secret_consume` doit atteindre l'unwrap normalement — preuve que le
        contrôle porte spécifiquement sur B (le paramètre) et non sur un état global
        toujours-inactif qui ferait passer le test précédent par accident.
        """
        import mcp_vault.auth.jwt_validator as jv
        from mcp_vault.auth.context import current_token_info
        from mcp_vault.server import settings

        orig_enforce = settings.enforce_mission_token_validation
        orig_jwks = settings.mission_jwks_url
        orig_status_url = settings.mission_status_url
        try:
            object.__setattr__(settings, "enforce_mission_token_validation", True)
            object.__setattr__(settings, "mission_jwks_url", "http://mock/.well-known/jwks.json")
            object.__setattr__(settings, "mission_status_url", "http://mock/status/{mission_id}")

            mock_validator = MagicMock()
            mock_validator.validate.return_value = {
                "mission_id": "mission-B", "tenant_id": "tenant-B",
                "aud": "mcp-vault:test", "iss": "mcp-mission", "exp": 9999999999,
            }

            tok = current_token_info.set({
                "auth_type": "mission_jwt", "client_name": "mission:tenant-A",
                "mission_id": "mission-A", "tenant_id": "tenant-A",
                "permissions": ["read"], "allowed_resources": ["vault-a"],
            })

            async def fake_check_mission_active(mission_id, status_url_template, cache_ttl):
                if mission_id == "mission-A":
                    return False, "mission_inactive"  # A inactive n'a AUCUNE importance
                if mission_id == "mission-B":
                    return True, ""
                raise AssertionError(f"mission_id inattendu dans le test : {mission_id!r}")

            mock_consume = AsyncMock(return_value={"status": "ok", "data": {"secret": "x"}})
            try:
                with patch.object(jv, "_validator", mock_validator), \
                     patch("mcp_vault.server._check_mission_active",
                           side_effect=fake_check_mission_active) as mock_status, \
                     patch("mcp_vault.vault.wrapping.consume_wrap_secret", mock_consume):
                    from mcp_vault.server import secret_consume
                    result = _run(secret_consume(
                        wrap_token="wt-b", operation_id="op-b",
                        mission_token="jwt-of-mission-b",
                    ))
            finally:
                current_token_info.reset(tok)
        finally:
            object.__setattr__(settings, "enforce_mission_token_validation", orig_enforce)
            object.__setattr__(settings, "mission_jwks_url", orig_jwks)
            object.__setattr__(settings, "mission_status_url", orig_status_url)

        called_mission_id = mock_status.call_args.kwargs.get("mission_id")
        assert called_mission_id == "mission-B", (
            f"check_mission_active appelé avec mission_id={called_mission_id!r} — "
            "attendu 'mission-B'."
        )
        assert result["status"] == "ok", (
            f"mission B active mais secret_consume a renvoyé une erreur : {result}")
        mock_consume.assert_called_once()

    def test_wrap_token_never_in_audit_result(self):
        """wrap_token et mission_token ne doivent JAMAIS apparaître dans l'audit."""
        import asyncio

        audited: list[dict] = []

        def mock_r(tool, result, vault_id="", detail=""):
            audited.append({"tool": tool, "result": result})
            return result

        mock_secret = {"status": "ok", "data": {"password": "s3cr3t"}, "operation_id": "op-1"}

        with patch("mcp_vault.server._r", side_effect=mock_r), \
             patch("mcp_vault.vault.wrapping.consume_wrap_secret",
                   new_callable=AsyncMock, return_value=mock_secret):
            from mcp_vault.server import secret_consume

            result = _run(secret_consume(
                wrap_token="SENSITIVE_WRAP_TOKEN_12345",
                operation_id="op-1",
                mission_token="SENSITIVE_MISSION_TOKEN_EYJABC",
            ))

        # Vérifier que les tokens sensibles ne sont pas dans l'audit
        for entry in audited:
            result_str = str(entry)
            assert "SENSITIVE_WRAP_TOKEN_12345" not in result_str, "wrap_token divulgué dans audit !"
            assert "SENSITIVE_MISSION_TOKEN" not in result_str, "mission_token divulgué dans audit !"
