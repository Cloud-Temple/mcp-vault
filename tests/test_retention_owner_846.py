"""Standalone Vault proof contract and post-COMMIT closure ACK; no fleet claim."""

import json
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import jwt
import pytest

from mcp_vault.auth.mission_jwt import JWKSCache
from mcp_vault.storage import (
    retention_maintenance as maintenance,
    retention_proof as proof,
)
from mcp_vault.storage.postgres import MetadataUnavailable, MutationUnknown
from tests.test_mission_jwt import _make_es256_keypair, _make_jwks

NOW = datetime(2026, 10, 16, tzinfo=timezone.utc)


def settings(mode="install"):
    return SimpleNamespace(
        mission_retention_issuer="https://mission.example",
        mission_retention_audience="retention-vault",
        mission_jwks_url="https://mission.example/.well-known/jwks.json",
        mission_jwks_cache_ttl=60,
        mission_retention_callback_seconds=5,
        audit_mission_retention_enabled=True,
        metadata_backend="postgres",
        metadata_operator_mode=mode,
        metadata_instance_id="vault846",
        metadata_pg_vault_id="vault846",
    )


def signed(**changes):
    key, public = _make_es256_keypair()
    stamp = int(NOW.timestamp())
    body = {
        "owner": "vault",
        "tenant_id": "tenant-a",
        "mission_id": "mission-a",
        "root_agent_id": "root-a",
        "claim_id": str(uuid4()),
        "claim_revision": 3,
        "terminal_at": (NOW - timedelta(days=366)).isoformat(),
        "retain_until": (NOW - timedelta(days=1)).isoformat(),
        "manifest_sha256": "a" * 64,
        "iss": "https://mission.example",
        "aud": "retention-vault",
        "sub": "mission-retention-maintenance",
        "purpose": "mission-retention-v1",
        "iat": stamp,
        "nbf": stamp,
        "exp": stamp + 30,
        "jti": "b" * 32,
    } | changes
    cache = JWKSCache(
        "https://mission.example/.well-known/jwks.json",
        60,
        fetch=lambda *unused: (200, None, json.dumps(_make_jwks(public)).encode()),
    )
    return jwt.encode(
        body, key, algorithm="ES256", headers={"kid": "test-key-1"}
    ), cache


def test_exact_standalone_signature_and_stable_identity_hash():
    token, cache = signed()
    identity, expires = proof.decode(settings(), cache, token, now=NOW)
    assert identity["mission_id"] == "mission-a" and expires == NOW + timedelta(
        seconds=30
    )
    assert len(proof.fingerprint(identity)) == 64 and not set(identity) & {
        "jti",
        "iat",
        "exp",
    }


@pytest.mark.parametrize(
    "changes",
    [
        {"owner": "tools"},
        {"aud": "vault-transport"},
        {"purpose": "hub-vault-v1"},
        {"sub": "browser"},
        {"exp": int(NOW.timestamp()) + 31},
        {"iat": True},
        {"claim_revision": True},
        {"terminal_at": NOW.isoformat()},
        {"retain_until": (NOW - timedelta(days=2)).isoformat()},
        {"payload": "PRIVATE"},
        {"claim_id": []},
        {"root_agent_id": False},
    ],
)
def test_valid_key_does_not_bypass_purpose_scope_shape_or_annual_origin(changes):
    token, cache = signed(**changes)
    with pytest.raises(ValueError):
        proof.decode(settings(), cache, token, now=NOW)


def test_expired_proof_or_foreign_jwks_origin_refused():
    token, cache = signed()
    with pytest.raises(ValueError):
        proof.decode(settings(), cache, token, now=NOW + timedelta(seconds=30))
    cfg = settings()
    cfg.mission_jwks_url = "https://neighbour.example/jwks"
    with pytest.raises(ValueError):
        proof.decode(cfg, cache, token, now=NOW)


@pytest.mark.parametrize(
    "commit_fails,close_fails", [(False, False), (True, False), (False, True)]
)
@pytest.mark.parametrize("mode", ["install", "retention-only"])
def test_public_closure_uses_distinct_maintenance_and_only_confirms_after_commit(
    monkeypatch, commit_fails, close_fails, mode
):
    token, cache = signed()
    identity, _ = proof.decode(settings(), cache, token, now=NOW)
    expiry = datetime.now(timezone.utc) + timedelta(seconds=20)
    calls = []

    class Conn:
        def add_notice_handler(self, handler):
            pass

        def execute(self, query, params=()):
            calls.append((query, params))
            if query == "COMMIT" and commit_fails:
                raise OSError("ACK lost")
            return SimpleNamespace(fetchone=lambda: {"result": True})

    @contextmanager
    def app():
        calls.append("app-schema-verify")
        yield

    @contextmanager
    def local():
        calls.append("maintenance-login")
        yield Conn()
        if close_fails:
            raise MetadataUnavailable("close_unconfirmed")

    monkeypatch.setattr(maintenance, "get_settings", lambda: settings(mode))
    monkeypatch.setattr(maintenance, "connection", app)
    monkeypatch.setattr(maintenance, "maintenance_connection", local)
    monkeypatch.setattr(maintenance, "validate_durability", lambda _: None)
    monkeypatch.setattr(maintenance, "live", lambda *_: (identity, expiry))
    if commit_fails or close_fails:
        with pytest.raises(MutationUnknown):
            maintenance.action(
                "audit-retention-close",
                {"proof": token, "confirm": "audit-retention-close"},
            )
    else:
        result = maintenance.action(
            "audit-retention-close",
            {"proof": token, "confirm": "audit-retention-close"},
        )
        assert (
            result["confirmed"]
            and not result["purge_confirmed"]
            and not result["inventory_complete"]
        )
    assert calls[0:2] == ["app-schema-verify", "maintenance-login"]
    assert calls[-1][0] == "COMMIT"


def test_disabled_or_missing_explicit_action_does_not_open_database(monkeypatch):
    cfg = settings()
    cfg.metadata_operator_mode = "disabled"
    monkeypatch.setattr(maintenance, "get_settings", lambda: cfg)
    monkeypatch.setattr(maintenance, "connection", lambda: pytest.fail("SQL opened"))
    with pytest.raises(MetadataUnavailable):
        maintenance.action("audit-retention-close", {"proof": "opaque"})
    cfg.metadata_operator_mode = "install"
    with pytest.raises(ValueError):
        maintenance.action("audit-retention-close", {"proof": "opaque"})


@pytest.mark.parametrize(
    "status,body",
    [
        (200, {"active": True}),
        (200, {"active": False}),
        (503, {"active": False}),
        (302, {"active": True}),
    ],
)
def test_live_callback_exact_post_no_redirect_and_revalidation(
    monkeypatch, status, body
):
    import sys

    import httpx

    monkeypatch.setattr(
        sys.modules[__name__], "NOW", datetime.now(timezone.utc).replace(microsecond=0)
    )
    token, cache = signed()
    monkeypatch.setattr(proof, "init_jwks_cache", lambda *unused: cache)
    original = httpx.Client
    observed = []

    def answer(request):
        observed.append(request)
        assert request.method == "POST"
        assert (
            str(request.url) == "https://mission.example/internal/retention/claim-check"
        )
        assert request.headers["authorization"] == "Bearer " + token
        assert request.content == b""
        return httpx.Response(status, json=body)

    def client(**kwargs):
        assert kwargs["follow_redirects"] is False and 0 < kwargs["timeout"] <= 5
        return original(transport=httpx.MockTransport(answer), **kwargs)

    monkeypatch.setattr(proof.httpx, "Client", client)
    if status == 200 and body["active"]:
        identity, expires = proof.live(settings(), token)
        assert identity["mission_id"] == "mission-a" and expires > datetime.now(
            timezone.utc
        )
    else:
        with pytest.raises(ValueError):
            proof.live(settings(), token)
    assert len(observed) == 1


def test_callback_network_failure_preserves_without_opening_owner_sql(monkeypatch):
    monkeypatch.setattr(
        proof, "_live", lambda *unused: (_ for _ in ()).throw(OSError("unavailable"))
    )
    with pytest.raises(MetadataUnavailable, match="retention_authority_unavailable"):
        proof.live(settings(), "opaque")
