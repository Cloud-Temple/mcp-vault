#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests adversariaux du parcours SSH JIT opérateur (#230 plateforme).

Ces tests sont 100 % locaux. Ils prouvent que l'émission opérateur reste une
opération dédiée et contrainte : identité bearer nominative, clé publique
standard pré-enrôlée, profil serveur immuable.

Décision produit (2026-07-22) : pas de clé de sécurité matérielle FIDO2 pour
l'instant (cf. docstring de ``mcp_vault.ssh_operator``) — l'identité repose
sur le bearer nominatif + la policy dédiée. Quelques tests conservent des
clés au format FIDO2 (``_legacy_fido2_*_key``) uniquement pour prouver
qu'elles sont désormais rejetées comme type inconnu (non-régression).
"""

import asyncio
import base64
import hashlib
import json
import os
import struct
import sys
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

os.environ.setdefault("MCP_SERVER_NAME", "mcp-vault-test")
os.environ.setdefault("ADMIN_BOOTSTRAP_KEY", "Test-Bootstrap-Key-2026-Pour-Tests!!")


def _field(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def _operator_ed25519_key(seed: int = 7) -> tuple[str, str]:
    """Clé SSH standard (ssh-ed25519, pas FIDO2) — clé enrôlée par défaut des tests."""
    key_type = b"ssh-ed25519"
    blob = _field(key_type) + _field(bytes([seed]) * 32)
    encoded = base64.b64encode(blob).decode("ascii")
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return f"{key_type.decode()} {encoded} operator@example", fingerprint


def _operator_ecdsa_key() -> tuple[str, str]:
    """Clé SSH standard (ecdsa-sha2-nistp256, pas FIDO2)."""
    key_type = b"ecdsa-sha2-nistp256"
    point_bytes = ec.derive_private_key(
        7, ec.SECP256R1()
    ).public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    blob = _field(key_type) + _field(b"nistp256") + _field(point_bytes)
    encoded = base64.b64encode(blob).decode("ascii")
    fingerprint = "SHA256:" + base64.b64encode(
        hashlib.sha256(blob).digest()
    ).decode("ascii").rstrip("=")
    return f"{key_type.decode()} {encoded} operator@example", fingerprint


def _software_ed25519_key() -> str:
    """Clé standard non enrôlée (empreinte différente de PUBLIC_KEY/FINGERPRINT) —
    utilisée pour prouver qu'une clé non enrôlée ou un rôle générique reste
    refusé, pas pour tester "logiciel vs matériel" (cette distinction n'existe
    plus, cf. décision produit dans la docstring du module)."""
    key_type = b"ssh-ed25519"
    blob = _field(key_type) + _field(bytes([3]) * 32)
    return f"ssh-ed25519 {base64.b64encode(blob).decode('ascii')} software"


def _legacy_fido2_ed25519_key(seed: int = 7) -> str:
    """Format FIDO2 (``sk-ssh-ed25519@openssh.com``) — uniquement pour
    prouver la non-régression : ce type n'est plus accepté."""
    key_type = b"sk-ssh-ed25519@openssh.com"
    blob = _field(key_type) + _field(bytes([seed]) * 32) + _field(b"ssh:operator-key")
    encoded = base64.b64encode(blob).decode("ascii")
    return f"{key_type.decode()} {encoded} operator@example"


def _legacy_fido2_ecdsa_key() -> str:
    """Cf. _legacy_fido2_ed25519_key() — variante ecdsa-sk."""
    key_type = b"sk-ecdsa-sha2-nistp256@openssh.com"
    point_bytes = ec.derive_private_key(
        7, ec.SECP256R1()
    ).public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    blob = (
        _field(key_type)
        + _field(b"nistp256")
        + _field(point_bytes)
        + _field(b"ssh:operator-key")
    )
    encoded = base64.b64encode(blob).decode("ascii")
    return f"{key_type.decode()} {encoded} operator@example"


PUBLIC_KEY, FINGERPRINT = _operator_ed25519_key()


def _profiles_json(**overrides) -> str:
    profile = {
        "client_name": "operator-christophe",
        "policy_id": "operator-ssh-jit",
        "key_fingerprints": [FINGERPRINT],
        "vault_id": "agentic-platform",
        "role_name": "bastion-operator",
        "principal": "ctadmin",
        "target": "bastion-01",
        "ttl_seconds": 900,
    }
    profile.update(overrides)
    return json.dumps({"bastion-prod": profile})


def _valid_expires_at(days: int = 1) -> str:
    """Expiration bearer valide par défaut pour les fixtures de tests
    (dans la fenêtre autorisée par ssh_operator_jit_max_bearer_expires_days)."""
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def _settings(profiles_json: str | None = None):
    return SimpleNamespace(
        ssh_operator_profiles_json=(profiles_json if profiles_json is not None else _profiles_json()),
        ssh_operator_profiles_b64="",
        ssh_operator_jit_max_config_chars=65536,
        ssh_operator_jit_min_ttl_seconds=60,
        ssh_operator_jit_max_ttl_seconds=900,
        ssh_operator_jit_max_reason_chars=512,
        ssh_operator_jit_max_public_key_chars=16384,
        ssh_operator_jit_max_profiles=32,
        ssh_operator_jit_max_bearer_expires_days=1,
    )


def _dedicated_policy_store() -> MagicMock:
    store = MagicMock()
    store.get.return_value = {
        "policy_id": "operator-ssh-jit",
        "allowed_tools": [
            "ssh_operator_access_profiles",
            "ssh_request_operator_access",
        ],
        "denied_tools": [],
        "path_rules": [],
    }
    store.is_tool_allowed.return_value = False
    return store


def _run(coro):
    return asyncio.run(coro)


class TestOperatorProfileValidation:
    def test_valid_profile_is_normalized(self):
        from mcp_vault.ssh_operator import parse_operator_profiles

        profiles = parse_operator_profiles(_settings())
        profile = profiles["bastion-prod"]
        assert profile.client_name == "operator-christophe"
        assert profile.policy_id == "operator-ssh-jit"
        assert profile.vault_id == "agentic-platform"
        assert profile.role_name == "bastion-operator"
        assert profile.principal == "ctadmin"
        assert profile.target == "bastion-01"
        assert profile.ttl_seconds == 900
        assert profile.key_fingerprints == (FINGERPRINT,)

    @pytest.mark.parametrize(
        "payload",
        [
            "[]",
            json.dumps({"../escape": json.loads(_profiles_json())["bastion-prod"]}),
            _profiles_json(ttl_seconds=True),
            _profiles_json(ttl_seconds=901),
            _profiles_json(principal="root,ctadmin"),
            _profiles_json(key_fingerprints=["SHA256:not-a-fingerprint"]),
            _profiles_json(client_name="operator\nspoof"),
        ],
    )
    def test_invalid_profile_configuration_fails_closed(self, payload):
        from mcp_vault.ssh_operator import OperatorSSHConfigurationError, parse_operator_profiles

        with pytest.raises(OperatorSSHConfigurationError):
            parse_operator_profiles(_settings(payload))

    def test_empty_configuration_disables_feature_without_boot_failure(self):
        from mcp_vault.ssh_operator import parse_operator_profiles

        assert parse_operator_profiles(_settings("")) == {}

    def test_urlsafe_base64_configuration_is_supported_for_strict_env_renderers(self):
        from mcp_vault.ssh_operator import parse_operator_profiles

        settings = _settings("")
        settings.ssh_operator_profiles_b64 = base64.urlsafe_b64encode(
            _profiles_json().encode("utf-8")
        ).decode("ascii").rstrip("=")

        profiles = parse_operator_profiles(settings)

        assert profiles["bastion-prod"].principal == "ctadmin"

    def test_json_and_base64_sources_are_mutually_exclusive(self):
        from mcp_vault.ssh_operator import (
            OperatorSSHConfigurationError,
            parse_operator_profiles,
        )

        settings = _settings()
        settings.ssh_operator_profiles_b64 = base64.urlsafe_b64encode(
            _profiles_json().encode("utf-8")
        ).decode("ascii")

        with pytest.raises(OperatorSSHConfigurationError, match="mutuellement exclusives"):
            parse_operator_profiles(settings)

    @pytest.mark.parametrize("encoded", ["***", "_w"])
    def test_invalid_base64_or_non_utf8_configuration_fails_closed(self, encoded):
        from mcp_vault.ssh_operator import (
            OperatorSSHConfigurationError,
            parse_operator_profiles,
        )

        settings = _settings("")
        settings.ssh_operator_profiles_b64 = encoded

        with pytest.raises(OperatorSSHConfigurationError, match="B64 invalide"):
            parse_operator_profiles(settings)

    def test_profile_configuration_size_is_bounded_before_decode(self):
        from mcp_vault.ssh_operator import (
            OperatorSSHConfigurationError,
            parse_operator_profiles,
        )

        settings = _settings("")
        settings.ssh_operator_profiles_b64 = "A" * 16
        settings.ssh_operator_jit_max_config_chars = 8

        with pytest.raises(OperatorSSHConfigurationError, match="surdimensionnée"):
            parse_operator_profiles(settings)

    @pytest.mark.parametrize(
        ("field", "value", "expected"),
        [
            ("ssh_operator_jit_max_reason_chars", 0, "MAX_REASON_CHARS"),
            ("ssh_operator_jit_max_public_key_chars", 0, "MAX_PUBLIC_KEY_CHARS"),
        ],
    )
    def test_request_limits_fail_fast_when_feature_is_enabled(
        self, field, value, expected
    ):
        from mcp_vault.ssh_operator import (
            OperatorSSHConfigurationError,
            parse_operator_profiles,
        )

        settings = _settings()
        setattr(settings, field, value)
        with pytest.raises(OperatorSSHConfigurationError, match=expected):
            parse_operator_profiles(settings)


class TestOperatorPublicKeyValidation:
    """Décision produit (2026-07-22) : plus de clé de sécurité matérielle
    FIDO2 — une clé SSH standard (ssh-ed25519/ecdsa-sha2-nistp256) suffit,
    l'identité repose sur le bearer nominatif + la policy dédiée."""

    def test_standard_ed25519_key_is_accepted(self):
        from mcp_vault.ssh_operator import inspect_operator_public_key

        inspected = inspect_operator_public_key(PUBLIC_KEY)
        assert inspected.key_type == "ssh-ed25519"
        assert inspected.fingerprint == FINGERPRINT
        assert inspected.canonical_public_key == " ".join(PUBLIC_KEY.split()[:2])

    def test_standard_ecdsa_nistp256_key_is_accepted(self):
        from mcp_vault.ssh_operator import inspect_operator_public_key

        public_key, fingerprint = _operator_ecdsa_key()
        inspected = inspect_operator_public_key(public_key)
        assert inspected.key_type == "ecdsa-sha2-nistp256"
        assert inspected.fingerprint == fingerprint
        assert inspected.canonical_public_key == " ".join(public_key.split()[:2])

    @pytest.mark.parametrize(
        "legacy_key", [_legacy_fido2_ed25519_key(), _legacy_fido2_ecdsa_key()],
    )
    def test_legacy_fido2_key_format_is_now_rejected_as_unknown_type(self, legacy_key):
        """Non-régression : le retrait de l'exigence FIDO2 ne doit pas, par
        accident, accepter AUSSI l'ancien format (`sk-*@openssh.com`) en plus
        du nouveau — seuls les types standard sont désormais reconnus.

        Le message est volontairement épinglé sur le refus de TYPE (pas un
        `pytest.raises` non filtré) : un sabotage de `_OPERATOR_KEY_TYPES`
        pour y réintroduire les types `sk-*` fait toujours lever une
        `OperatorSSHRequestError`, mais pour une raison différente et non
        pertinente (le wire format `sk-*` a un champ `application` en plus
        qui fait échouer le parsing ecdsa/ed25519 en aval) — un
        `pytest.raises` non filtré resterait vert par accident et ne
        prouverait rien sur le vrai garde à tester."""
        from mcp_vault.ssh_operator import OperatorSSHRequestError, inspect_operator_public_key

        with pytest.raises(OperatorSSHRequestError, match="ssh-ed25519 ou ecdsa-sha2-nistp256 est requise"):
            inspect_operator_public_key(legacy_key)

    @pytest.mark.parametrize(
        "public_key",
        [
            "ssh-ed25519 !!!not-base64!!!",
            "ssh-ed25519 " + base64.b64encode(_field(b"ssh-ed25519")).decode(),
            PUBLIC_KEY.replace("ssh-ed25519 ", "ecdsa-sha2-nistp256 ", 1),
        ],
    )
    def test_malformed_or_declared_type_spoof_is_rejected(self, public_key):
        from mcp_vault.ssh_operator import OperatorSSHRequestError, inspect_operator_public_key

        with pytest.raises(OperatorSSHRequestError):
            inspect_operator_public_key(public_key)


class TestOperatorAccessAuthorization:
    def test_bearer_mode_marks_bootstrap_identity_explicitly(self):
        from mcp_vault.auth.middleware import AuthMiddleware

        settings = SimpleNamespace(admin_bootstrap_key="bootstrap-key-for-test")
        middleware = AuthMiddleware(app=object())
        with patch("mcp_vault.auth.middleware.get_settings", return_value=settings):
            identity = middleware._validate_token("bootstrap-key-for-test")

        assert identity["auth_type"] == "bootstrap"

    @pytest.mark.parametrize(
        "token_info",
        [
            None,
            {"auth_type": "bootstrap", "client_name": "admin", "permissions": ["admin", "write"]},
            {"auth_type": "token", "client_name": "admin-token", "permissions": ["admin", "write"]},
            {"auth_type": "mission_jwt", "client_name": "mission:tenant", "permissions": ["write"]},
            {"auth_type": "token", "client_name": "someone-else", "permissions": ["write"]},
        ],
    )
    def test_non_operator_identities_are_denied_before_openbao(self, token_info):
        from mcp_vault.auth.context import current_token_info
        from mcp_vault.ssh_operator import request_operator_ssh_access

        ctx = current_token_info.set(token_info)
        signer = AsyncMock()
        try:
            with patch("mcp_vault.ssh_operator.get_settings", return_value=_settings()), \
                 patch("mcp_vault.ssh_operator.sign_ssh_key", signer):
                result = _run(request_operator_ssh_access(
                    "bastion-prod", PUBLIC_KEY, "maintenance autorisée"
                ))
        finally:
            current_token_info.reset(ctx)

        assert result["status"] == "error"
        assert not signer.called

    @pytest.mark.parametrize("auth_type", ["mission_jwt", "bootstrap", None])
    def test_wrong_auth_type_alone_is_denied_even_with_nominal_bearer_shape(self, auth_type):
        """Mutation-proof (revue Codex) : seul `auth_type` diffère d'un bearer
        opérateur par ailleurs nominal (permissions/resources/policy_id
        exacts). Sans ce test, retirer le check `auth_type != "token"` dans
        `_current_operator_identity` restait invisible : chaque cas de
        `test_non_operator_identities_are_denied_before_openbao` avait une
        AUTRE raison de refuser (admin, mauvais client_name, champs
        manquants), donc la mutation restait verte."""
        from mcp_vault.auth.context import current_token_info
        from mcp_vault.ssh_operator import request_operator_ssh_access

        token_info = {
            "client_name": "operator-christophe",
            "permissions": ["read", "write"],
            "allowed_resources": ["agentic-platform"],
            "policy_id": "operator-ssh-jit",
            "expires_at": _valid_expires_at(),
        }
        if auth_type is not None:
            token_info["auth_type"] = auth_type
        ctx = current_token_info.set(token_info)
        signer = AsyncMock()
        try:
            with patch("mcp_vault.ssh_operator.get_settings", return_value=_settings()), \
                 patch("mcp_vault.ssh_operator.get_token_store", return_value=None), \
                 patch("mcp_vault.ssh_operator.check_policy", return_value=None), \
                 patch("mcp_vault.ssh_operator.get_policy_store",
                       return_value=_dedicated_policy_store()), \
                 patch("mcp_vault.ssh_operator.sign_ssh_key", signer):
                result = _run(request_operator_ssh_access(
                    "bastion-prod", PUBLIC_KEY, "maintenance autorisée"
                ))
        finally:
            current_token_info.reset(ctx)

        assert result["status"] == "error"
        assert result["message"] == "Bearer opérateur nominatif requis"
        assert not signer.called

    def test_identity_store_unavailable_denies_operator_access(self):
        """Fix (revue Codex) : un Token Store diagnostiqué indisponible
        (panne/corruption S3 détectée après TTL) ne doit jamais laisser
        passer ce parcours depuis un cache potentiellement périmé — même si
        `token_info` en contexte semble nominal. Ne change pas le
        comportement global de TokenStore.get_by_hash() (hors scope)."""
        from mcp_vault.auth.context import current_token_info
        from mcp_vault.ssh_operator import request_operator_ssh_access

        ctx = current_token_info.set({
            "auth_type": "token",
            "client_name": "operator-christophe",
            "permissions": ["read", "write"],
            "allowed_resources": ["agentic-platform"],
            "policy_id": "operator-ssh-jit",
            "expires_at": _valid_expires_at(),
        })
        degraded_store = SimpleNamespace(available=False)
        signer = AsyncMock()
        try:
            with patch("mcp_vault.ssh_operator.get_settings", return_value=_settings()), \
                 patch("mcp_vault.ssh_operator.get_token_store", return_value=degraded_store), \
                 patch("mcp_vault.ssh_operator.check_policy", return_value=None), \
                 patch("mcp_vault.ssh_operator.get_policy_store",
                       return_value=_dedicated_policy_store()), \
                 patch("mcp_vault.ssh_operator.sign_ssh_key", signer):
                result = _run(request_operator_ssh_access(
                    "bastion-prod", PUBLIC_KEY, "maintenance autorisée"
                ))
        finally:
            current_token_info.reset(ctx)

        assert result["status"] == "error"
        assert result["error_type"] == "identity_store_unavailable"
        assert not signer.called

    def test_available_identity_store_does_not_block_operator_access(self):
        """Non-régression : un Token Store présent et disponible ne doit pas
        gêner le parcours nominal."""
        from mcp_vault.auth.context import current_token_info
        from mcp_vault.ssh_operator import request_operator_ssh_access

        ctx = current_token_info.set({
            "auth_type": "token",
            "client_name": "operator-christophe",
            "permissions": ["read", "write"],
            "allowed_resources": ["agentic-platform"],
            "policy_id": "operator-ssh-jit",
            "expires_at": _valid_expires_at(),
        })
        healthy_store = SimpleNamespace(available=True)
        signer = AsyncMock(return_value={"status": "ok", "signed_key": "cert", "serial_number": "1"})
        try:
            with patch("mcp_vault.ssh_operator.get_settings", return_value=_settings()), \
                 patch("mcp_vault.ssh_operator.get_token_store", return_value=healthy_store), \
                 patch("mcp_vault.ssh_operator.check_policy", return_value=None), \
                 patch("mcp_vault.ssh_operator.get_policy_store",
                       return_value=_dedicated_policy_store()), \
                 patch("mcp_vault.ssh_operator.sign_ssh_key", signer):
                result = _run(request_operator_ssh_access(
                    "bastion-prod", PUBLIC_KEY, "maintenance autorisée"
                ))
        finally:
            current_token_info.reset(ctx)

        assert result["status"] == "ok"
        assert signer.called

    @pytest.mark.parametrize(
        "bad_expires_at",
        [
            "2026-01-01T00:00:00",  # naïf (pas de tzinfo) — TokenStore ne devrait
                                     # jamais en produire, mais ce garde ne s'y fie
                                     # pas (défense en profondeur, revue round 9)
            "2020-01-01T00:00:00+00:00",  # déjà passé — idem, injection directe
        ],
    )
    def test_bearer_with_naive_or_past_expiration_is_denied(self, bad_expires_at):
        """Défense en profondeur (revue round 9) : ce garde ne se fie pas
        uniquement au fait que TokenStore.get_by_hash() a déjà fail-close sur
        un bearer expiré/naïf en amont — il revalide lui-même, au cas où
        `current_token_info` serait un jour construit autrement."""
        from mcp_vault.auth.context import current_token_info
        from mcp_vault.ssh_operator import request_operator_ssh_access

        ctx = current_token_info.set({
            "auth_type": "token",
            "client_name": "operator-christophe",
            "permissions": ["read", "write"],
            "allowed_resources": ["agentic-platform"],
            "policy_id": "operator-ssh-jit",
            "expires_at": bad_expires_at,
        })
        signer = AsyncMock()
        try:
            with patch("mcp_vault.ssh_operator.get_settings", return_value=_settings()), \
                 patch("mcp_vault.ssh_operator.check_policy", return_value=None), \
                 patch("mcp_vault.ssh_operator.get_policy_store",
                       return_value=_dedicated_policy_store()), \
                 patch("mcp_vault.ssh_operator.sign_ssh_key", signer):
                result = _run(request_operator_ssh_access(
                    "bastion-prod", PUBLIC_KEY, "maintenance autorisée"
                ))
        finally:
            current_token_info.reset(ctx)

        assert result["status"] == "error"
        assert "expiration" in result["message"]
        assert not signer.called

    def test_bearer_without_expiration_is_denied(self):
        """Le bearer étant la SEULE autorité d'émission (plus de FIDO2), un
        bearer sans expiration (`expires_in_days=0` côté TokenStore, donc pas
        de clé `expires_at`) donnerait une portée d'attaque illimitée en cas
        de vol — refusé, même si le reste de l'identité est nominal."""
        from mcp_vault.auth.context import current_token_info
        from mcp_vault.ssh_operator import request_operator_ssh_access

        ctx = current_token_info.set({
            "auth_type": "token",
            "client_name": "operator-christophe",
            "permissions": ["read", "write"],
            "allowed_resources": ["agentic-platform"],
            "policy_id": "operator-ssh-jit",
            # Pas de clé "expires_at" du tout : simule expires_in_days=0.
        })
        signer = AsyncMock()
        try:
            with patch("mcp_vault.ssh_operator.get_settings", return_value=_settings()), \
                 patch("mcp_vault.ssh_operator.check_policy", return_value=None), \
                 patch("mcp_vault.ssh_operator.get_policy_store",
                       return_value=_dedicated_policy_store()), \
                 patch("mcp_vault.ssh_operator.sign_ssh_key", signer):
                result = _run(request_operator_ssh_access(
                    "bastion-prod", PUBLIC_KEY, "maintenance autorisée"
                ))
        finally:
            current_token_info.reset(ctx)

        assert result["status"] == "error"
        assert "expiration" in result["message"]
        assert not signer.called

    def test_bearer_with_expiration_beyond_cap_is_denied(self):
        """Un bearer valide et non expiré, mais dont l'expiration dépasse le
        plafond configuré pour ce parcours (ex. un token général de 90 jours
        auquel la policy operator-ssh-jit aurait été attachée), est refusé —
        seul un bearer à durée de vie RESTANTE bornée est utilisable ici."""
        from mcp_vault.auth.context import current_token_info
        from mcp_vault.ssh_operator import request_operator_ssh_access

        ctx = current_token_info.set({
            "auth_type": "token",
            "client_name": "operator-christophe",
            "permissions": ["read", "write"],
            "allowed_resources": ["agentic-platform"],
            "policy_id": "operator-ssh-jit",
            "expires_at": _valid_expires_at(days=30),
        })
        signer = AsyncMock()
        try:
            with patch("mcp_vault.ssh_operator.get_settings", return_value=_settings()), \
                 patch("mcp_vault.ssh_operator.check_policy", return_value=None), \
                 patch("mcp_vault.ssh_operator.get_policy_store",
                       return_value=_dedicated_policy_store()), \
                 patch("mcp_vault.ssh_operator.sign_ssh_key", signer):
                result = _run(request_operator_ssh_access(
                    "bastion-prod", PUBLIC_KEY, "maintenance autorisée"
                ))
        finally:
            current_token_info.reset(ctx)

        assert result["status"] == "error"
        assert "long-vivant" in result["message"]
        assert not signer.called

    def test_bearer_with_expiration_exactly_at_the_cap_is_accepted(self):
        """Cas limite : une expiration exactement égale au plafond configuré
        (pas strictement supérieure) doit être acceptée — non-régression
        anti off-by-one sur le chemin nominal.

        Horloge figée (revue round 9) : la version précédente calculait
        `_valid_expires_at(days=1)` puis comparait quelques microsecondes
        plus tard — le temps restant au moment du contrôle était déjà
        LÉGÈREMENT INFÉRIEUR au plafond, donc ce test restait vert même
        après avoir muté le code de `>` en `>=` (prouvé par sabotage
        indépendant). En figeant `datetime.now()` à une référence fixe et en
        posant `expires_at = référence + plafond` EXACTEMENT, ce test
        distingue réellement `>` (accepté) de `>=` (refusé)."""
        from mcp_vault.auth.context import current_token_info
        from mcp_vault.ssh_operator import request_operator_ssh_access

        reference = datetime(2026, 1, 1, tzinfo=timezone.utc)

        class _FrozenDatetime(datetime):
            @classmethod
            def now(cls, tz=None):
                return reference if tz is not None else reference.replace(tzinfo=None)

        expires_at = (reference + timedelta(days=1)).isoformat()
        ctx = current_token_info.set({
            "auth_type": "token",
            "client_name": "operator-christophe",
            "permissions": ["read", "write"],
            "allowed_resources": ["agentic-platform"],
            "policy_id": "operator-ssh-jit",
            "expires_at": expires_at,
        })
        signer = AsyncMock(return_value={"status": "ok", "signed_key": "cert", "serial_number": "1"})
        try:
            with patch("mcp_vault.ssh_operator.get_settings", return_value=_settings()), \
                 patch("mcp_vault.ssh_operator.check_policy", return_value=None), \
                 patch("mcp_vault.ssh_operator.get_policy_store",
                       return_value=_dedicated_policy_store()), \
                 patch("mcp_vault.ssh_operator.sign_ssh_key", signer), \
                 patch("mcp_vault.ssh_operator.datetime", _FrozenDatetime):
                result = _run(request_operator_ssh_access(
                    "bastion-prod", PUBLIC_KEY, "maintenance autorisée"
                ))
        finally:
            current_token_info.reset(ctx)

        assert result["status"] == "ok"
        assert signer.called

    def test_unregistered_key_is_denied_before_openbao(self):
        from mcp_vault.auth.context import current_token_info
        from mcp_vault.ssh_operator import request_operator_ssh_access

        other_key, _ = _operator_ed25519_key(seed=9)
        ctx = current_token_info.set({
            "auth_type": "token",
            "client_name": "operator-christophe",
            "permissions": ["read", "write"],
            "allowed_resources": ["agentic-platform"],
            "policy_id": "operator-ssh-jit",
            "expires_at": _valid_expires_at(),
        })
        signer = AsyncMock()
        policy_store = _dedicated_policy_store()
        try:
            with patch("mcp_vault.ssh_operator.get_settings", return_value=_settings()), \
                 patch("mcp_vault.ssh_operator.check_policy", return_value=None), \
                 patch("mcp_vault.ssh_operator.get_policy_store", return_value=policy_store), \
                 patch("mcp_vault.ssh_operator.sign_ssh_key", signer):
                result = _run(request_operator_ssh_access(
                    "bastion-prod", other_key, "maintenance autorisée"
                ))
        finally:
            current_token_info.reset(ctx)

        assert result["status"] == "error"
        assert "enrôlée" in result["message"]
        assert not signer.called

    @pytest.mark.parametrize(
        ("permissions", "resources"),
        [
            (["write"], ["agentic-platform"]),
            (["read", "write"], ["agentic-platform", "another-vault"]),
            (["read", "write"], []),
        ],
    )
    def test_operator_bearer_must_have_exact_permissions_and_single_vault(
        self, permissions, resources
    ):
        from mcp_vault.auth.context import current_token_info
        from mcp_vault.ssh_operator import request_operator_ssh_access

        ctx = current_token_info.set({
            "auth_type": "token",
            "client_name": "operator-christophe",
            "permissions": permissions,
            "allowed_resources": resources,
            "policy_id": "operator-ssh-jit",
            "expires_at": _valid_expires_at(),
        })
        signer = AsyncMock()
        try:
            with patch("mcp_vault.ssh_operator.get_settings", return_value=_settings()), \
                 patch("mcp_vault.ssh_operator.get_policy_store",
                       return_value=_dedicated_policy_store()), \
                 patch("mcp_vault.ssh_operator.sign_ssh_key", signer):
                result = _run(request_operator_ssh_access(
                    "bastion-prod", PUBLIC_KEY, "maintenance autorisée"
                ))
        finally:
            current_token_info.reset(ctx)

        assert result["status"] == "error"
        assert "périmètre minimal" in result["message"]
        assert not signer.called

    def test_oversized_public_key_is_denied_before_parsing_and_openbao(self):
        from mcp_vault.auth.context import current_token_info
        from mcp_vault.ssh_operator import request_operator_ssh_access

        settings = _settings()
        settings.ssh_operator_jit_max_public_key_chars = len(PUBLIC_KEY) - 1
        ctx = current_token_info.set({
            "auth_type": "token",
            "client_name": "operator-christophe",
            "permissions": ["read", "write"],
            "allowed_resources": ["agentic-platform"],
            "policy_id": "operator-ssh-jit",
            "expires_at": _valid_expires_at(),
        })
        signer = AsyncMock()
        policy_store = _dedicated_policy_store()
        try:
            with patch("mcp_vault.ssh_operator.get_settings", return_value=settings), \
                 patch("mcp_vault.ssh_operator.check_policy", return_value=None), \
                 patch("mcp_vault.ssh_operator.get_policy_store",
                       return_value=policy_store), \
                 patch("mcp_vault.ssh_operator.sign_ssh_key", signer):
                result = _run(request_operator_ssh_access(
                    "bastion-prod", PUBLIC_KEY, "maintenance autorisée"
                ))
        finally:
            current_token_info.reset(ctx)

        assert result["status"] == "error"
        assert result["error_type"] == "invalid_request"
        assert not signer.called

    def test_success_pins_profile_without_key_leak(self):
        from mcp_vault.auth.context import current_token_info
        from mcp_vault.ssh_operator import request_operator_ssh_access

        token_info = {
            "auth_type": "token",
            "client_name": "operator-christophe",
            "permissions": ["read", "write"],
            "allowed_resources": ["agentic-platform"],
            "policy_id": "operator-ssh-jit",
            "expires_at": _valid_expires_at(),
        }
        ctx = current_token_info.set(token_info)
        signer = AsyncMock(return_value={
            "status": "ok",
            "signed_key": "ssh-ed25519-cert-v01@openssh.com AAAATEST",
            "serial_number": "42",
            "ttl": "900s",
        })
        audit = MagicMock()
        policy_store = _dedicated_policy_store()
        try:
            with patch("mcp_vault.ssh_operator.get_settings", return_value=_settings()), \
                 patch("mcp_vault.ssh_operator.check_policy", return_value=None), \
                 patch("mcp_vault.ssh_operator.check_access", return_value=None), \
                 patch("mcp_vault.ssh_operator.get_policy_store", return_value=policy_store), \
                 patch("mcp_vault.ssh_operator.sign_ssh_key", signer), \
                 patch("mcp_vault.ssh_operator.log_audit", audit):
                result = _run(request_operator_ssh_access(
                    "bastion-prod", PUBLIC_KEY, "maintenance autorisée"
                ))
        finally:
            current_token_info.reset(ctx)

        assert result["status"] == "ok"
        assert result["profile_id"] == "bastion-prod"
        assert result["target"] == "bastion-01"
        assert result["principal"] == "ctadmin"
        assert result["fingerprint"] == FINGERPRINT
        kwargs = signer.await_args.kwargs
        assert kwargs["vault_id"] == "agentic-platform"
        assert kwargs["role_name"] == "bastion-operator"
        assert kwargs["public_key"] == " ".join(PUBLIC_KEY.split()[:2])
        assert kwargs["ttl"] == "900s"
        assert kwargs["valid_principals"] == "ctadmin"
        assert "critical_options" not in kwargs
        assert kwargs["key_id"].startswith("operator:operator-christophe:bastion-prod:")
        audit_text = repr(audit.call_args)
        assert PUBLIC_KEY not in audit_text
        assert "AAAA" not in audit_text

    def test_comment_and_second_line_are_never_forwarded_to_openbao(self):
        from mcp_vault.auth.context import current_token_info
        from mcp_vault.ssh_operator import request_operator_ssh_access

        injected = PUBLIC_KEY + "\nssh-ed25519 AAAAATTACKER"
        token_info = {
            "auth_type": "token", "client_name": "operator-christophe",
            "permissions": ["read", "write"], "allowed_resources": ["agentic-platform"],
            "policy_id": "operator-ssh-jit",
            "expires_at": _valid_expires_at(),
        }
        ctx = current_token_info.set(token_info)
        signer = AsyncMock(return_value={"status": "ok", "signed_key": "cert", "serial_number": "43"})
        policy_store = _dedicated_policy_store()
        try:
            with patch("mcp_vault.ssh_operator.get_settings", return_value=_settings()), \
                 patch("mcp_vault.ssh_operator.check_policy", return_value=None), \
                 patch("mcp_vault.ssh_operator.check_access", return_value=None), \
                 patch("mcp_vault.ssh_operator.get_policy_store", return_value=policy_store), \
                 patch("mcp_vault.ssh_operator.sign_ssh_key", signer), \
                 patch("mcp_vault.ssh_operator.log_audit"):
                result = _run(request_operator_ssh_access(
                    "bastion-prod", injected, "maintenance autorisée"
                ))
        finally:
            current_token_info.reset(ctx)

        assert result["status"] == "ok"
        forwarded = signer.await_args.kwargs["public_key"]
        assert forwarded == " ".join(PUBLIC_KEY.split()[:2])
        assert "ATTACKER" not in forwarded
        assert "\n" not in forwarded

    def test_overly_broad_policy_is_denied_before_openbao(self):
        from mcp_vault.auth.context import current_token_info
        from mcp_vault.ssh_operator import request_operator_ssh_access

        token_info = {
            "auth_type": "token", "client_name": "operator-christophe",
            "permissions": ["read", "write"], "allowed_resources": ["agentic-platform"],
            "policy_id": "operator-ssh-jit",
            "expires_at": _valid_expires_at(),
        }
        ctx = current_token_info.set(token_info)
        signer = AsyncMock()
        policy_store = _dedicated_policy_store()
        policy_store.is_tool_allowed.side_effect = lambda _pid, tool: tool == "ssh_sign_key"
        try:
            with patch("mcp_vault.ssh_operator.get_settings", return_value=_settings()), \
                 patch("mcp_vault.ssh_operator.check_policy", return_value=None), \
                 patch("mcp_vault.ssh_operator.get_policy_store", return_value=policy_store), \
                 patch("mcp_vault.ssh_operator.sign_ssh_key", signer):
                result = _run(request_operator_ssh_access(
                    "bastion-prod", PUBLIC_KEY, "maintenance autorisée"
                ))
        finally:
            current_token_info.reset(ctx)

        assert result["status"] == "error"
        assert "trop large" in result["message"]
        assert not signer.called

    def test_policy_with_any_unrelated_tool_is_denied_before_openbao(self):
        from mcp_vault.auth.context import current_token_info
        from mcp_vault.ssh_operator import request_operator_ssh_access

        token_info = {
            "auth_type": "token", "client_name": "operator-christophe",
            "permissions": ["read", "write"],
            "allowed_resources": ["agentic-platform"],
            "policy_id": "operator-ssh-jit",
            "expires_at": _valid_expires_at(),
        }
        ctx = current_token_info.set(token_info)
        signer = AsyncMock()
        policy_store = _dedicated_policy_store()
        policy_store.get.return_value["allowed_tools"].append("secret_read")
        try:
            with patch("mcp_vault.ssh_operator.get_settings", return_value=_settings()), \
                 patch("mcp_vault.ssh_operator.check_policy", return_value=None), \
                 patch("mcp_vault.ssh_operator.get_policy_store",
                       return_value=policy_store), \
                 patch("mcp_vault.ssh_operator.sign_ssh_key", signer):
                result = _run(request_operator_ssh_access(
                    "bastion-prod", PUBLIC_KEY, "maintenance autorisée"
                ))
        finally:
            current_token_info.reset(ctx)

        assert result["status"] == "error"
        assert "seuls outils SSH JIT" in result["message"]
        assert not signer.called


class TestOpenBaoSSHSignParameters:
    def test_optional_certificate_constraints_reach_openbao(self):
        from mcp_vault.vault.ssh_ca import sign_ssh_key

        client = MagicMock()
        client.write.return_value = {
            "data": {"signed_key": "ssh-cert", "serial_number": "42"}
        }
        with patch("mcp_vault.vault.ssh_ca.get_hvac_client", return_value=client):
            result = _run(sign_ssh_key(
                vault_id="agentic-platform",
                role_name="bastion-operator",
                public_key=PUBLIC_KEY,
                ttl="900s",
                key_id="operator:identity:profile:nonce",
                valid_principals="ctadmin",
                critical_options={"verify-required": ""},
            ))

        assert result["status"] == "ok"
        client.write.assert_called_once_with(
            "ssh-ca-agentic-platform/sign/bastion-operator",
            public_key=PUBLIC_KEY,
            ttl="900s",
            key_id="operator:identity:profile:nonce",
            valid_principals="ctadmin",
            critical_options={"verify-required": ""},
        )


class TestExposedOperatorSurfaces:
    def test_settings_fail_fast_rejects_invalid_profiles(self):
        from mcp_vault.config import Settings

        settings = Settings(ssh_operator_profiles_json="[]")
        ok, message = settings.check_operator_ssh_jit_config()
        assert ok is False
        assert "objet" in message

    def test_create_app_enforces_operator_profile_fail_fast(self):
        from mcp_vault import server

        with patch("mcp_vault.openbao.crypto.validate_bootstrap_key", return_value=(True, "")), \
             patch("mcp_vault.config.Settings.check_mission_pep_config",
                   return_value=(True, "")), \
             patch("mcp_vault.config.Settings.check_operator_ssh_jit_config",
                   return_value=(False, "profil corrompu")):
            with pytest.raises(RuntimeError, match="SSH JIT opérateur"):
                server.create_app()

    def test_listing_propagates_policy_store_failure(self):
        from mcp_vault.auth.context import current_token_info
        from mcp_vault.ssh_operator import list_operator_access_profiles

        token_info = {
            "auth_type": "token", "client_name": "operator-christophe",
            "permissions": ["read", "write"], "allowed_resources": ["agentic-platform"],
            "policy_id": "operator-ssh-jit",
            "expires_at": _valid_expires_at(),
        }
        ctx = current_token_info.set(token_info)
        try:
            with patch("mcp_vault.ssh_operator.get_settings", return_value=_settings()), \
                 patch("mcp_vault.ssh_operator.check_policy", return_value={
                     "status": "error", "error_type": "policy_store_unavailable",
                     "message": "indisponible",
                 }):
                result = list_operator_access_profiles()
        finally:
            current_token_info.reset(ctx)
        assert result["error_type"] == "policy_store_unavailable"

    def test_listing_exposes_no_fingerprint_role_or_policy(self):
        from mcp_vault.auth.context import current_token_info
        from mcp_vault.ssh_operator import list_operator_access_profiles

        token_info = {
            "auth_type": "token", "client_name": "operator-christophe",
            "permissions": ["read", "write"],
            "allowed_resources": ["agentic-platform"],
            "policy_id": "operator-ssh-jit",
            "expires_at": _valid_expires_at(),
        }
        ctx = current_token_info.set(token_info)
        policy_store = _dedicated_policy_store()
        try:
            with patch("mcp_vault.ssh_operator.get_settings",
                       return_value=_settings()), \
                 patch("mcp_vault.ssh_operator.check_policy", return_value=None), \
                 patch("mcp_vault.ssh_operator.get_policy_store",
                       return_value=policy_store):
                result = list_operator_access_profiles()
        finally:
            current_token_info.reset(ctx)

        assert result["status"] == "ok"
        assert set(result["profiles"][0]) == {
            "profile_id", "vault_id", "target", "principal", "ttl_seconds",
        }

    def test_mcp_request_tool_delegates_only_request_fields(self):
        from mcp_vault import server

        delegated = AsyncMock(return_value={"status": "ok", "serial_number": "42"})
        with patch("mcp_vault.ssh_operator.request_operator_ssh_access", delegated):
            result = _run(server.ssh_request_operator_access(
                "bastion-prod", PUBLIC_KEY, "maintenance autorisée"
            ))

        assert result["status"] == "ok"
        delegated.assert_awaited_once_with(
            "bastion-prod", PUBLIC_KEY, "maintenance autorisée"
        )

    def test_admin_api_request_route_delegates_only_request_fields(self):
        from mcp_vault.admin.api import handle_admin_api

        token_info = {
            "auth_type": "token",
            "client_name": "operator-christophe",
            "permissions": ["read", "write"],
            "allowed_resources": ["agentic-platform"],
            "policy_id": "operator-ssh-jit",
            "expires_at": _valid_expires_at(),
        }
        body = json.dumps({
            "profile_id": "bastion-prod",
            "public_key": PUBLIC_KEY,
            "reason": "maintenance autorisée",
        }).encode()
        messages = []

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message):
            messages.append(message)

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/admin/api/ssh/operator-access",
            "headers": [(b"authorization", b"Bearer operator-token")],
            "query_string": b"",
        }
        delegated = AsyncMock(return_value={"status": "ok", "serial_number": "42"})
        with patch("mcp_vault.admin.api._get_token_info", return_value=token_info), \
             patch("mcp_vault.ssh_operator.request_operator_ssh_access", delegated):
            _run(handle_admin_api(scope, receive, send, mcp=None))

        start = next(item for item in messages if item["type"] == "http.response.start")
        assert start["status"] == 200
        delegated.assert_awaited_once_with(
            "bastion-prod", PUBLIC_KEY, "maintenance autorisée"
        )

    def test_admin_api_rejects_certificate_attribute_overrides(self):
        from mcp_vault.admin.api import handle_admin_api

        token_info = {
            "auth_type": "token", "client_name": "operator-christophe",
            "permissions": ["read", "write"], "allowed_resources": ["agentic-platform"],
            "policy_id": "operator-ssh-jit",
            "expires_at": _valid_expires_at(),
        }
        body = json.dumps({
            "profile_id": "bastion-prod", "public_key": PUBLIC_KEY,
            "reason": "maintenance", "ttl": "24h", "role_name": "root-anywhere",
        }).encode()
        messages = []

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message):
            messages.append(message)

        scope = {
            "type": "http", "method": "POST", "path": "/admin/api/ssh/operator-access",
            "headers": [(b"authorization", b"Bearer operator-token")], "query_string": b"",
        }
        delegated = AsyncMock()
        with patch("mcp_vault.admin.api._get_token_info", return_value=token_info), \
             patch("mcp_vault.ssh_operator.request_operator_ssh_access", delegated):
            _run(handle_admin_api(scope, receive, send, mcp=None))

        start = next(item for item in messages if item["type"] == "http.response.start")
        assert start["status"] == 400
        assert not delegated.called


class TestGenericSignerCannotReachOperatorReservedRoles:
    """Fix (revue Codex round 1+2, BLOQUANT) : reproduit puis ferme le
    contournement démontré empiriquement — un bearer write ordinaire scopé au
    vault pouvait obtenir, via le signer/setup SSH génériques (préexistants,
    inchangés par la PR d'origine), le même rôle OpenBao qu'un profil
    opérateur JIT, avec une clé LOGICIELLE et sans `verify-required`. Le
    parcours FIDO2 dédié était alors un théâtre de sécurité : fermé
    lui-même, mais contournable par la porte à côté.

    Round 2 : bloquer seulement le couple exact (vault_id, role_name) ne
    suffisait pas — la CA SSH OpenBao est partagée par mount (un seul mount
    par vault_id), donc créer un rôle ALTERNATIF (`shadow-operator`) dans le
    même mount contournait toujours FIDO2. Le garde bloque désormais le
    vault_id entier dès qu'il héberge un profil opérateur, quel que soit le
    rôle (existant ou à créer)."""

    def test_generic_signer_is_denied_on_a_role_reserved_by_an_operator_profile(self):
        from mcp_vault import server

        software_key = _software_ed25519_key()
        signer = AsyncMock()
        with patch("mcp_vault.ssh_operator.get_settings", return_value=_settings()), \
             patch("mcp_vault.auth.context.check_policy", return_value=None), \
             patch("mcp_vault.auth.context.check_access", return_value=None), \
             patch("mcp_vault.auth.context.check_write_permission", return_value=None), \
             patch("mcp_vault.vault.ssh_ca.sign_ssh_key", signer):
            result = _run(server.ssh_sign_key(
                "agentic-platform", "bastion-operator", software_key, "900s"
            ))

        assert result["status"] == "error"
        assert result["error_type"] == "reserved_for_operator_jit"
        assert not signer.called

    def test_generic_setup_is_denied_on_a_role_reserved_by_an_operator_profile(self):
        from mcp_vault import server

        setup = AsyncMock()
        with patch("mcp_vault.ssh_operator.get_settings", return_value=_settings()), \
             patch("mcp_vault.auth.context.check_policy", return_value=None), \
             patch("mcp_vault.auth.context.check_access", return_value=None), \
             patch("mcp_vault.auth.context.check_write_permission", return_value=None), \
             patch("mcp_vault.vault.ssh_ca.setup_ssh_ca", setup):
            result = _run(server.ssh_ca_setup("agentic-platform", "bastion-operator"))

        assert result["status"] == "error"
        assert result["error_type"] == "reserved_for_operator_jit"
        assert not setup.called

    def test_generic_setup_of_a_shadow_role_is_denied_on_a_reserved_vault(self):
        """Reproduction exacte du contournement round 2 : créer un rôle
        ALTERNATIF (pas le rôle réservé) dans le même coffre doit être refusé
        — sinon il suffit de le signer ensuite pour contourner FIDO2."""
        from mcp_vault import server

        setup = AsyncMock()
        with patch("mcp_vault.ssh_operator.get_settings", return_value=_settings()), \
             patch("mcp_vault.auth.context.check_policy", return_value=None), \
             patch("mcp_vault.auth.context.check_access", return_value=None), \
             patch("mcp_vault.auth.context.check_write_permission", return_value=None), \
             patch("mcp_vault.vault.ssh_ca.setup_ssh_ca", setup):
            result = _run(server.ssh_ca_setup(
                "agentic-platform", "shadow-operator", allowed_users="*", default_user="root"
            ))

        assert result["status"] == "error"
        assert result["error_type"] == "reserved_for_operator_jit"
        assert not setup.called

    def test_generic_signer_of_a_shadow_role_is_denied_on_a_reserved_vault(self):
        """Même reproduction côté signature : un rôle alternatif déjà créé
        (hypothèse la plus défavorable) ne doit pas non plus être signable
        génériquement sur un coffre réservé."""
        from mcp_vault import server

        signer = AsyncMock()
        with patch("mcp_vault.ssh_operator.get_settings", return_value=_settings()), \
             patch("mcp_vault.auth.context.check_policy", return_value=None), \
             patch("mcp_vault.auth.context.check_access", return_value=None), \
             patch("mcp_vault.auth.context.check_write_permission", return_value=None), \
             patch("mcp_vault.vault.ssh_ca.sign_ssh_key", signer):
            result = _run(server.ssh_sign_key(
                "agentic-platform", "shadow-operator", _software_ed25519_key(), "30m"
            ))

        assert result["status"] == "error"
        assert result["error_type"] == "reserved_for_operator_jit"
        assert not signer.called

    def test_generic_signer_still_works_on_a_vault_without_any_operator_profile(self):
        """Non-régression : un coffre qui n'héberge AUCUN profil opérateur
        continue de passer par le signer générique, quel que soit le rôle."""
        from mcp_vault import server

        signer = AsyncMock(return_value={"status": "ok", "signed_key": "cert", "serial_number": "1"})
        with patch("mcp_vault.ssh_operator.get_settings", return_value=_settings()), \
             patch("mcp_vault.auth.context.check_policy", return_value=None), \
             patch("mcp_vault.auth.context.check_access", return_value=None), \
             patch("mcp_vault.auth.context.check_write_permission", return_value=None), \
             patch("mcp_vault.vault.ssh_ca.sign_ssh_key", signer):
            result = _run(server.ssh_sign_key(
                "some-other-vault", "some-other-role", _software_ed25519_key(), "30m"
            ))

        assert result["status"] == "ok"
        assert signer.called

    def test_admin_bearer_cannot_bypass_reservation_via_trailing_slash(self):
        """Reproduction exacte du BLOQUANT round 5 (revue Codex) : check_access()
        autorise un bearer ADMIN avant toute validation de format de
        vault_id (court-circuit légitime pour ses autres usages). Un admin
        fournissant "agentic-platform/" (slash final) atteignait donc
        check_not_reserved_for_operator() avec un vault_id non canonique
        que la comparaison stricte ne reconnaissait pas comme réservé —
        contournement complet de FIDO2/verify-required par un bearer admin
        LÉGITIME, sans exécution de code. Contraire au contrat non
        négociable de l'issue #96 (« un token admin ne doit jamais
        contourner le contrôle d'identité opérateur »). check_access() n'est
        PAS mocké ici : c'est le vrai court-circuit admin qui doit être
        neutralisé par la validation à l'intérieur même du garde de
        réservation, pas par check_access()."""
        from mcp_vault import server
        from mcp_vault.auth.context import current_token_info

        token_info = {
            "auth_type": "token", "client_name": "admin-token",
            "permissions": ["admin", "read", "write"], "allowed_resources": [],
        }
        signer = AsyncMock()
        ctx = current_token_info.set(token_info)
        try:
            with patch("mcp_vault.ssh_operator.get_settings", return_value=_settings()), \
                 patch("mcp_vault.vault.ssh_ca.sign_ssh_key", signer):
                result = _run(server.ssh_sign_key(
                    "agentic-platform/", "shadow-operator",
                    _software_ed25519_key(), "30m",
                ))
        finally:
            current_token_info.reset(ctx)

        assert result["status"] == "error"
        assert not signer.called

    def test_admin_api_signer_is_denied_on_a_role_reserved_by_an_operator_profile(self):
        from mcp_vault.admin import api as admin_api

        messages = []

        async def send(message):
            messages.append(message)

        signer = AsyncMock()
        body = json.dumps({
            "public_key": _software_ed25519_key(), "role_name": "bastion-operator",
        }).encode()
        with patch("mcp_vault.ssh_operator.get_settings", return_value=_settings()), \
             patch("mcp_vault.vault.ssh_ca.sign_ssh_key", signer):
            _run(admin_api._api_ssh_sign(send, "agentic-platform", body))

        start = next(item for item in messages if item["type"] == "http.response.start")
        assert start["status"] in (403, 503)
        assert not signer.called

    def test_admin_bearer_rest_cannot_bypass_reservation_via_trailing_slash(self):
        """Même reproduction que test_admin_bearer_cannot_bypass_reservation_
        via_trailing_slash, côté route REST Admin — l'admin bypass de
        _check_vault_access() n'est pas mocké non plus."""
        from mcp_vault.admin import api as admin_api

        messages = []

        async def send(message):
            messages.append(message)

        signer = AsyncMock()
        body = json.dumps({
            "public_key": _software_ed25519_key(), "role_name": "shadow-operator",
        }).encode()
        with patch("mcp_vault.ssh_operator.get_settings", return_value=_settings()), \
             patch("mcp_vault.vault.ssh_ca.sign_ssh_key", signer):
            _run(admin_api._api_ssh_sign(send, "agentic-platform/", body))

        start = next(item for item in messages if item["type"] == "http.response.start")
        assert start["status"] == 400
        assert not signer.called

    def test_end_to_end_trailing_slash_bypass_from_codex_round3_is_now_closed(self):
        """Reproduction end-to-end EXACTE du contournement round 3 (revue
        Codex) : vault_id="agentic-platform/" (slash final) contournait le
        garde de réservation. Ici check_access() N'EST PAS mocké (contrairement
        aux autres tests de cette classe) : c'est le vrai correctif central
        (auth/context.py, cherry-pické depuis le fix critique
        vault-id-canonicalization) qui doit intercepter, avant même que
        check_not_reserved_for_operator ne soit consulté."""
        from mcp_vault import server

        signer = AsyncMock()
        token_info = {
            "auth_type": "token", "client_name": "unrelated-writer",
            "permissions": ["read", "write"], "allowed_resources": [],
        }
        from mcp_vault.auth.context import current_token_info
        ctx = current_token_info.set(token_info)
        try:
            with patch("mcp_vault.ssh_operator.get_settings", return_value=_settings()), \
                 patch("mcp_vault.vault.ssh_ca.sign_ssh_key", signer):
                result = _run(server.ssh_sign_key(
                    "agentic-platform/", "shadow-operator",
                    _software_ed25519_key(), "30m",
                ))
        finally:
            current_token_info.reset(ctx)

        assert result["status"] == "error"
        assert not signer.called

    def test_admin_api_signer_of_a_shadow_role_is_denied_on_a_reserved_vault(self):
        from mcp_vault.admin import api as admin_api

        messages = []

        async def send(message):
            messages.append(message)

        signer = AsyncMock()
        body = json.dumps({
            "public_key": _software_ed25519_key(), "role_name": "shadow-operator",
        }).encode()
        with patch("mcp_vault.ssh_operator.get_settings", return_value=_settings()), \
             patch("mcp_vault.vault.ssh_ca.sign_ssh_key", signer):
            _run(admin_api._api_ssh_sign(send, "agentic-platform", body))

        start = next(item for item in messages if item["type"] == "http.response.start")
        assert start["status"] in (403, 503)
        assert not signer.called


class TestSshCaDoesNotLeakBackendDiagnostics:
    """Fix (revue Codex, BLOQUANT) : sign_ssh_key()/setup_ssh_ca() ne doivent
    jamais refléter ni logger un diagnostic OpenBao brut (str(e)) — seul un
    message constant est retourné au demandeur."""

    def test_sign_ssh_key_returns_a_constant_message_on_backend_error(self):
        from mcp_vault.vault.ssh_ca import sign_ssh_key

        client = MagicMock()
        client.write.side_effect = RuntimeError("root_token=s.SENSITIVE1234 at 10.0.0.5")
        with patch("mcp_vault.vault.ssh_ca.get_hvac_client", return_value=client):
            result = _run(sign_ssh_key("agentic-platform", "bastion-operator", PUBLIC_KEY, "900s"))

        assert result["status"] == "error"
        assert result["message"] == "Erreur backend OpenBao"
        assert "SENSITIVE" not in result["message"]

    def test_setup_ssh_ca_returns_a_constant_message_on_backend_error(self):
        from mcp_vault.vault.ssh_ca import setup_ssh_ca

        client = MagicMock()
        client.sys.enable_secrets_engine.side_effect = RuntimeError(
            "root_token=s.SENSITIVE1234 at 10.0.0.5"
        )
        with patch("mcp_vault.vault.ssh_ca.get_hvac_client", return_value=client):
            result = _run(setup_ssh_ca("agentic-platform", "bastion-operator"))

        assert result["status"] == "error"
        assert result["message"] == "Erreur backend OpenBao"
        assert "SENSITIVE" not in result["message"]

    @pytest.mark.parametrize(
        ("function_name", "client_method", "args"),
        [
            ("get_ca_public_key", "read", ("agentic-platform",)),
            ("list_ssh_roles", "list", ("agentic-platform",)),
            ("get_ssh_role_info", "read", ("agentic-platform", "bastion-operator")),
        ],
    )
    def test_read_surfaces_do_not_leak_backend_diagnostics(
        self, function_name, client_method, args
    ):
        """Round 2 (revue Codex, BLOQUANT) : les trois fonctions de LECTURE
        du même module avaient le même défaut que sign_ssh_key/setup_ssh_ca,
        non couvert par le correctif initial (POC : exception
        'secret=read-surface-leak' reflétée au client et dans les logs)."""
        from mcp_vault.vault import ssh_ca

        client = MagicMock()
        getattr(client, client_method).side_effect = RuntimeError(
            "root_token=s.SENSITIVE1234 at 10.0.0.5"
        )
        with patch("mcp_vault.vault.ssh_ca.get_hvac_client", return_value=client):
            result = _run(getattr(ssh_ca, function_name)(*args))

        assert result["status"] == "error"
        assert result["message"] == "Erreur backend OpenBao"


class TestRawSignersHaveNoUnauthorizedCaller(unittest.TestCase):
    """Test structurel (revue Codex round 4, MAJEUR) : les primitives brutes
    sign_ssh_key()/setup_ssh_ca() ne doivent être APPELÉES que par leur propre
    wrapper générique gardé (vault/ssh_ca.py) ou par le parcours opérateur
    JIT légitime (ssh_operator.py). Un futur point d'entrée qui les
    importerait/appellerait directement ailleurs romprait ce test — la
    discipline de revue reste la garantie réelle (Python ne peut pas
    "sceller" une fonction), mais ce test rend une violation détectable en
    CI plutôt que silencieuse."""

    _ALLOWED_CALLER_BASENAMES = {"ssh_ca.py", "ssh_operator.py"}
    _WATCHED_NAMES = {"sign_ssh_key", "setup_ssh_ca"}

    def test_no_unauthorized_module_calls_the_raw_primitives(self):
        """Round 5 (revue Codex, MAJEUR) : la version précédente ne
        contrôlait que le nom TEXTUEL de l'appel — `from ...ssh_ca import
        sign_ssh_key as alias` puis `alias(...)` passait à tort. Corrigé :
        résolution des alias d'import.

        Round 6 (revue Codex, MAJEUR) : deux évasions supplémentaires
        passaient encore à tort — `raw = module.sign_ssh_key` (réaffectation
        d'un attribut à une variable) et `raw = getattr(module,
        "sign_ssh_key")`. Corrigées en traitant aussi ces deux formes
        d'affectation comme des alias.

        Limite assumée et documentée (pas corrigée davantage) : Python ne
        permet aucune garantie statique complète contre TOUTE indirection
        possible (réaffectations chaînées sur plusieurs variables,
        `__dict__`, `importlib`, `exec`, monkey-patching...). Poursuivre ce
        jeu du chat et de la souris indéfiniment n'améliore plus la sécurité
        réelle : un développeur qui irait jusque-là contournerait tout aussi
        bien la revue de code humaine, qui reste la garantie de fond de ce
        projet (revue adversariale obligatoire avant tout merge). Ce test
        couvre les évasions plausibles par inadvertance ; il ne prétend pas
        couvrir une évasion délibérée et outillée."""
        import ast
        import os

        import mcp_vault

        src_root = os.path.dirname(mcp_vault.__file__)
        offenders = []
        for dirpath, _dirnames, filenames in os.walk(src_root):
            for filename in filenames:
                if not filename.endswith(".py"):
                    continue
                if filename in self._ALLOWED_CALLER_BASENAMES:
                    continue
                path = os.path.join(dirpath, filename)
                with open(path, encoding="utf-8") as fh:
                    source = fh.read()
                tree = ast.parse(source, filename=path)

                # Résout les alias vers leur nom d'origine, sous 3 formes :
                # 1) `from ..vault.ssh_ca import sign_ssh_key as alias`
                # 2) `raw = module.sign_ssh_key` (réaffectation d'attribut)
                # 3) `raw = getattr(module, "sign_ssh_key")`
                local_to_original = {}
                for node in ast.walk(tree):
                    if isinstance(node, ast.ImportFrom):
                        for alias in node.names:
                            if alias.name in self._WATCHED_NAMES:
                                local_to_original[alias.asname or alias.name] = alias.name
                    elif isinstance(node, ast.Assign):
                        value = node.value
                        original = None
                        if isinstance(value, ast.Attribute) and value.attr in self._WATCHED_NAMES:
                            original = value.attr
                        elif (
                            isinstance(value, ast.Call)
                            and isinstance(value.func, ast.Name)
                            and value.func.id == "getattr"
                            and len(value.args) >= 2
                            and isinstance(value.args[1], ast.Constant)
                            and value.args[1].value in self._WATCHED_NAMES
                        ):
                            original = value.args[1].value
                        if original is not None:
                            for target in node.targets:
                                if isinstance(target, ast.Name):
                                    local_to_original[target.id] = original

                for node in ast.walk(tree):
                    if not isinstance(node, ast.Call):
                        continue
                    func = node.func
                    if isinstance(func, ast.Name):
                        original = local_to_original.get(func.id, func.id)
                        if original in self._WATCHED_NAMES:
                            offenders.append(
                                f"{path}:{node.lineno} appelle {original}() (nom local {func.id!r})"
                            )
                    elif isinstance(func, ast.Attribute) and func.attr in self._WATCHED_NAMES:
                        # Accès par attribut (ex. ssh_ca.sign_ssh_key(...)) : signalé
                        # sans condition, une fausse alerte occasionnelle vaut mieux
                        # qu'un contournement silencieux.
                        offenders.append(f"{path}:{node.lineno} appelle .{func.attr}()")
        self.assertEqual(
            offenders, [],
            "Appel direct aux primitives SSH brutes hors ssh_ca.py/ssh_operator.py : "
            + "; ".join(offenders),
        )
