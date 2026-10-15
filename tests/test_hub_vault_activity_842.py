"""ASGI/propriétaire réels, I/O PG/Bao/JWKS contrôlées ; aucune qualification native."""

import asyncio
import hashlib
import json
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

from mcp_vault.auth.hub_vault_activity import HubContext, PATH
from mcp_vault.auth.middleware import AuthMiddleware
from mcp_vault.hub_vault_activity import HubVaultActivityMiddleware
from mcp_vault.storage import (
    admission,
    audit_read,
    hub_vault_activity as service,
    postgres,
    reader,
)
from mcp_vault.storage.audit_contract import AuditScope


@pytest.fixture
def hub(monkeypatch):
    from mcp_vault import config
    from mcp_vault.auth import middleware

    cfg = config.Settings(_env_file=None).model_copy(
        update=dict(
            metadata_backend="postgres",
            metadata_instance_id="vault842",
            mcp_auth_mode="bearer",
            hub_vault_enabled=True,
            hub_vault_issuer="https://mission.example",
            hub_vault_audience="vault842",
            hub_vault_ca_file="",
            hub_vault_jwks_url="https://mission.example/.well-known/jwks.json",
            hub_vault_check_url="https://mission.example/internal/hub/vault-delegation-check",
        )
    )
    for module in (middleware, service, admission, postgres):
        monkeypatch.setattr(module, "get_settings", lambda: cfg)
    import mcp_vault.storage.stores as stores

    monkeypatch.setattr(stores, "get_settings", lambda: cfg)
    raw = "fixture-opaque842"
    th = hashlib.sha256(raw.encode()).hexdigest()
    token = dict(
        hash=th,
        client_name="reader842",
        permissions=["read"],
        allowed_resources=["coffer-a", "coffer-b"],
        policy_id="auditor",
        revoked=False,
        expires_at=None,
    )
    policy = dict(
        policy_id="auditor",
        allowed_tools=["audit_log", "vault_metadata_batch"],
        denied_tools=[],
        path_rules=[
            dict(vault_pattern="coffer-*", permissions=["read"], allowed_paths=[])
        ],
    )
    binding = dict(
        tenant_id="tenant-a",
        instance_id="vault842",
        allowed_resources=["coffer-a"],
        permissions=["read"],
        enabled=True,
        policy_id="auditor",
        expires_at=None,
        created_at=datetime.now(timezone.utc).isoformat(),
        updated_at=datetime.now(timezone.utc).isoformat(),
    )
    state = dict(
        token=token,
        policy=policy,
        binding=binding,
        revision=1,
        fail=False,
        hold=False,
        revoke=False,
    )
    calls, statements = [], []
    entered, release = asyncio.Event(), asyncio.Event()
    rows = [
        dict(
            instance_id="vault842",
            vault_id=coffer,
            actor_ref=actor,
            tenant_id=tenant,
            mission_id=mission,
            call_id=str(uuid4()),
            tool="secret_read",
            phase="public_terminal",
            outcome="completed",
            seq=i,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=365),
            duration_ms=1,
            operation_id=None,
            step_id=None,
            mutation_id=None,
            detail="PRIVATE-CANARY",
        )
        for i, (coffer, actor, tenant, mission) in enumerate(
            [
                ("coffer-a", "mission_" + "a" * 16, "tenant-a", "mis_00842001"),
                ("coffer-b", "mission_" + "a" * 16, "tenant-a", "mis_00842001"),
                ("coffer-a", "mission_" + "b" * 16, "tenant-b", "mis_00842001"),
                ("coffer-a", "mission_" + "a" * 16, "tenant-a", "mis_00842002"),
                ("coffer-a", "tok_" + "a" * 16, None, None),
            ],
            1,
        )
    ]

    class Conn:
        def execute(self, sql, params=None):
            statements.append((sql, params))
            assert not any(
                sql.startswith(k) for k in ("INSERT", "UPDATE", "DELETE", "TRUNCATE")
            )
            if state["fail"]:
                raise postgres.MetadataUnavailable("PRIVATE-CANARY")
            values = []
            if "vault_metadata.tokens" in sql:
                values = (
                    [dict(payload=state["token"], revision=1)]
                    if params[1] == th
                    else []
                )
            elif "vault_metadata.mission_bindings" in sql:
                values = [dict(payload=state["binding"], revision=state["revision"])]
            elif "vault_metadata.policies" in sql:
                values = [dict(payload=state["policy"], revision=1)]
            elif "audit_revision" in sql:
                values = [dict(revision=1)]
            elif "max(seq)" in sql:
                values = [dict(upper=5)]
            elif "JOIN vault_metadata.audit_events" in sql:
                assert "c.tenant_id=%s" in sql and "c.mission_id=%s" in sql
                assert (
                    "left(c.actor_ref,8)='mission_'" in sql
                    and "c.vault_id=ANY(%s)" in sql
                )
                instance, coffers, tenant, mid = params[:4]
                matching = [
                    r
                    for r in rows
                    if (
                        r["instance_id"] == instance
                        and r["vault_id"] in coffers
                        and r["actor_ref"].startswith("mission_")
                        and r["tenant_id"] == tenant
                        and r["mission_id"] == mid
                    )
                ]
                if sql.startswith("SELECT count"):
                    values = [dict(total=len(matching))]
                elif "GROUP BY" in sql:
                    values = []
                else:
                    values = matching[: params[-1]]
            return SimpleNamespace(
                fetchall=lambda: values, fetchone=lambda: values[0] if values else None
            )

    @contextmanager
    def connected():
        yield Conn()

    for module in (admission, postgres, service, audit_read):
        monkeypatch.setattr(module, "connection", connected)
    from unittest.mock import AsyncMock
    from mcp_vault.storage import audit_pg

    # Durable denial recording has its own179 tests; replace this I/O boundary only.
    monkeypatch.setattr(audit_pg, "record_auth_denial", AsyncMock(return_value=True))
    # Existing opaque validator consumes the admitted, validated TokenStore view.
    monkeypatch.setattr(
        middleware, "get_token_store", lambda: postgres.request_facts.get()["token"]
    )

    def metadata(vid, **kwargs):
        calls.append(vid)
        return dict(
            created_by="PRIVATE-CANARY",
            description="PRIVATE-CANARY",
            created_at="2026-10-15T00:00:00Z",
        )

    monkeypatch.setattr(reader, "owner_metadata", metadata)
    private = ec.generate_private_key(ec.SECP256R1())
    key = json.loads(ECAlgorithm.to_jwk(private.public_key()))
    key["kid"] = "fixture842"
    context = HubContext(cfg)
    context.jwks._fetch = lambda *_: (200, None, json.dumps({"keys": [key]}).encode())

    async def check(request):
        entered.set()
        if state["hold"]:
            await release.wait()
        if state["revoke"]:
            state["binding"]["enabled"] = False
            state["revision"] = 2
        return httpx2.Response(200, json={"active": True})

    context.client_factory = lambda **kw: httpx2.AsyncClient(
        transport=httpx2.MockTransport(check), **kw
    )
    monkeypatch.setattr("ssl.create_default_context", lambda **kw: True)

    async def inner(*args):
        raise AssertionError("route missed")

    route = HubVaultActivityMiddleware(inner, cfg, context=context)
    app = AuthMiddleware(route)

    def signed(body, **changes):
        now = int(time.time())
        claims = dict(
            iss=cfg.hub_vault_issuer,
            aud=cfg.hub_vault_audience,
            sub="opaque:" + "a" * 64,
            iat=now,
            nbf=now,
            exp=now + 30,
            jti="b" * 32,
            purpose="hub-vault-activity-v1",
            permissions=["vault.activity.read"],
            resources=[body["mission_id"]],
            tenant_id=body["tenant_id"],
            mission_id=body["mission_id"],
            owner_id="vault842",
            request_sha256=hashlib.sha256(
                json.dumps(body, separators=(",", ":")).encode()
            ).hexdigest(),
        )
        return jwt.encode(
            {**claims, **changes},
            private,
            algorithm="ES256",
            headers={"kid": "fixture842"},
        )

    async def call(body=None, change=None, opaque=raw, extra=None):
        body = body or dict(mission_id="mis_00842001", tenant_id="tenant-a", limit=100)
        headers = {
            "Authorization": "Bearer " + opaque,
            "X-Vault-Hub-Context": signed(body, **(change or {})),
        }
        headers.update(extra or {})
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url="https://vault"
        ) as client:
            return await client.post(
                PATH,
                headers=headers,
                content=json.dumps(body, separators=(",", ":")).encode(),
            )

    return SimpleNamespace(**locals())


async def test_asgi_intersects_local_coffer_binding_before_count_and_redacts(hub):
    result = await hub.call()
    assert result.status_code == 200, result.text
    data = result.json()
    assert data["total"] == data["count"] == 1 and data["complete"] is True
    assert data["vaults"] == [
        {
            "vault_id": "coffer-a",
            "state": "available",
            "created_at": "2026-10-15T00:00:00+00:00",
        }
    ]
    assert len(data["entries"]) == 1 and data["entries"][0]["tenant_id"] == "tenant-a"
    assert hub.calls == ["coffer-a"]
    assert "PRIVATE-CANARY" not in result.text and hub.raw not in result.text
    assert hub.route.pending == 0 and not hub.route.slots.locked()
    clauses, _ = audit_read.where_scope(AuditScope("vault842", frozenset({"coffer-a"})))
    assert "c.tenant_id IS NULL" in clauses and "c.mission_id IS NULL" in clauses


@pytest.mark.parametrize(
    "change",
    [
        {"purpose": "hub-agent-reports-v1"},
        {"aud": "tools"},
        {"owner_id": "other"},
        {"permissions": ["admin"]},
        {"sub": "anonymous"},
        {"request_sha256": "0" * 64},
        {"resources": ["mis_other"]},
        {"exp": 1},
        {"nbf": 0},
        {"jti": "not-valid"},
        {"tenant_id": "tenant-b"},
        {"extra": "PRIVATE-CANARY"},
    ],
)
async def test_invalid_or_other_purpose_context_cannot_read_metadata(hub, change):
    result = await hub.call(change=change)
    assert result.status_code == 403, result.text
    assert hub.calls == [] and "entries" not in result.json()


@pytest.mark.parametrize("target", ["token", "binding", "policy", "pg"])
async def test_local_revocation_or_metadata_outage_never_empty_success(hub, target):
    if target == "token":
        hub.state["token"]["revoked"] = True
    if target == "binding":
        hub.state["binding"]["enabled"] = False
    if target == "policy":
        hub.state["policy"]["denied_tools"] = ["vault_*"]
    if target == "pg":
        hub.state["fail"] = True
    result = await hub.call()
    assert result.status_code in (401, 403, 503)
    assert "entries" not in result.json() and "vaults" not in result.json()
    assert "PRIVATE-CANARY" not in result.text


async def test_binding_revocation_during_live_check_revalidated_with_opaque(hub):
    hub.state["revoke"] = True
    result = await hub.call()
    assert result.status_code == 403, result.text
    assert hub.calls == []
    checks = [sql for sql, _ in hub.statements if "FOR SHARE" in sql]
    assert any("tokens" in sql for sql in checks) and any(
        "mission_bindings" in sql for sql in checks
    )


@pytest.mark.parametrize(
    "kind",
    ["admin", "wrap", "unscoped", "broad-policy", "binding-foreign", "metadata-denied"],
)
async def test_reader_remains_explicit_without_upgrade_from_signed_context(hub, kind):
    if kind == "admin":
        hub.state["token"]["permissions"] = ["admin"]
    if kind == "wrap":
        hub.state["token"]["permissions"] = ["wrap"]
    if kind == "unscoped":
        hub.state["token"]["allowed_resources"] = []
    if kind == "broad-policy":
        hub.state["policy"]["allowed_tools"].append("secret_read")
    if kind == "binding-foreign":
        hub.state["binding"]["instance_id"] = "another-instance"
    if kind == "metadata-denied":
        hub.state["policy"]["denied_tools"] = ["vault_metadata_*"]
    result = await hub.call()
    assert result.status_code in (403, 503), result.text
    assert hub.calls == [] and "vaults" not in result.json()


async def test_missing_owner_metadata_is_unavailable_without_empty_coffer(
    hub, monkeypatch
):
    def missing(*args, **kwargs):
        raise reader.MetadataAbsent("metadata_absent_confirmed")

    monkeypatch.setattr(reader, "owner_metadata", missing)
    result = await hub.call()
    assert (
        result.status_code == 503
        and "vaults" not in result.json()
        and "entries" not in result.json()
    )


async def test_disabled_optional_hub_never_attempts_jwks_or_metadata(hub):
    hub.cfg.hub_vault_enabled = False
    result = await hub.call()
    assert result.status_code == 404 and hub.calls == []
