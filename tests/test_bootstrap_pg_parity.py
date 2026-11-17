"""La clé bootstrap a en mode PostgreSQL exactement le comportement du mode S3.

Chaque contrôle compare la réponse PG à la réponse S3 sur la même fonction, et
vérifie qu'un appelant inconnu reste refusé dans les couches propres à PG
(admission, revalidation de l'acteur, audit).
"""
import hashlib
import re
from types import SimpleNamespace

import pytest

KEY = "Kb7!" + "x9Q#" * 15  # 64 caractères, jamais une vraie clé


@pytest.fixture
def backend(monkeypatch):
    from mcp_vault.config import get_settings

    def use(name):
        monkeypatch.setenv("ADMIN_BOOTSTRAP_KEY", KEY)
        monkeypatch.setenv("METADATA_BACKEND", name)
        if name == "postgres":
            for var, value in {"METADATA_INSTANCE_ID": "test-vault", "METADATA_PG_VAULT_ID": "ssh-ca-prod",
                               "METADATA_PG_SECRET_PATH": "app/connection",
                               "METADATA_PG_PROVISIONER_SECRET_PATH": "provisioner/connection",
                               "METADATA_PG_DATABASE": "vault", "METADATA_PG_OWNER_ROLE": "vault_owner",
                               "METADATA_PG_APP_ROLE": "vault_app",
                               "METADATA_PG_PROVISIONER_ROLE": "vault_provisioner",
                               "METADATA_PG_CA_FILE": "unit-ca.crt"}.items():
                monkeypatch.setenv(var, value)
        get_settings.cache_clear()
        return get_settings()

    yield use
    get_settings.cache_clear()


def _identities(settings):
    """Les quatre résolutions de bearer qui testaient la clé bootstrap."""
    import asyncio
    from mcp_vault.admin import api
    from mcp_vault.auth.middleware import AuthMiddleware
    pep = asyncio.run(AuthMiddleware(None)._resolve_pep(KEY, settings))
    return {"is_admin": api._is_admin(KEY), "admin_info": api._get_token_info(KEY),
            "mcp_bearer": AuthMiddleware(None)._validate_token(KEY), "mcp_pep": pep}


def test_bearer_resolution_identical_to_s3(backend):
    s3 = _identities(backend("s3"))
    pg = _identities(backend("postgres"))
    assert s3["is_admin"] is True and s3["admin_info"]["auth_type"] == "bootstrap"
    assert s3["mcp_pep"][1] is None and s3["mcp_pep"][0]["auth_type"] == "bootstrap"
    assert pg == s3


def test_other_bearers_still_refused_in_pg(backend, monkeypatch):
    from mcp_vault.admin import api
    from mcp_vault.auth import token_store
    backend("postgres")
    monkeypatch.setattr(token_store, "_token_store", None, raising=False)
    monkeypatch.setattr(api, "get_token_store", lambda: None)
    assert api._get_token_info(KEY[:-1] + "y") is None
    assert api._is_admin("") is False


async def test_admission_lets_bootstrap_reach_facts(backend, monkeypatch):
    from mcp_vault.storage import admission
    backend("postgres")
    seen = []

    async def offload(fn, raw, tenant):
        seen.append((fn, raw, tenant))
        return {"owners": {}}

    monkeypatch.setattr(admission, "offload", offload)
    assert await admission.admit(KEY) == {"owners": {}}
    assert seen == [(admission.load_facts, KEY, None)]
    for refused in ("", "z" * 8193):
        with pytest.raises(PermissionError):
            await admission.admit(refused)
    assert len(seen) == 1


class _Conn:
    def __init__(self):
        self.sql = []

    def execute(self, sql, params=None):
        self.sql.append(sql)
        return SimpleNamespace(fetchone=lambda: None, fetchall=lambda: [])


@pytest.mark.parametrize("identity,expected", [
    ({"auth_type": "bootstrap", "client_name": "admin", "permissions": ["admin", "read", "write"]}, None),
    ({"client_name": "admin", "permissions": ["admin"]}, "actor_missing"),
    ({"auth_type": "token", "client_name": "x"}, "actor_missing"),
    ({}, "actor_missing"),
])
def test_actor_revalidation(backend, identity, expected):
    from mcp_vault.auth.context import current_token_info
    from mcp_vault.storage.postgres import MetadataUnavailable, request_facts, revalidate_actor
    backend("postgres")
    who = current_token_info.set(identity)
    facts = request_facts.set({"owners": {}, "actor_hash": None, "policy_revisions": {}})
    conn = _Conn()
    try:
        if expected is None:
            revalidate_actor(conn)
            assert not any("vault_metadata.tokens" in q for q in conn.sql)
        else:
            with pytest.raises(MetadataUnavailable) as exc:
                revalidate_actor(conn)
            assert exc.value.reason == expected
    finally:
        request_facts.reset(facts)
        current_token_info.reset(who)


@pytest.mark.parametrize("identity,actor", [
    ({"auth_type": "bootstrap", "client_name": "admin"}, "tok_" + hashlib.sha256(KEY.encode()).hexdigest()[:16]),
    ({"client_name": "admin"}, "anonymous"),
    ({}, "anonymous"),
])
def test_audit_actor(backend, identity, actor):
    from mcp_vault.auth.context import current_token_info
    from mcp_vault.storage.audit_contract import ACTOR
    from mcp_vault.storage.audit_pg import make_call
    from mcp_vault.storage.postgres import request_facts
    backend("postgres")
    who = current_token_info.set(identity)
    facts = request_facts.set({"owners": {}, "actor_hash": None})
    try:
        call = make_call("vault_list")
    finally:
        request_facts.reset(facts)
        current_token_info.reset(who)
    assert call.actor_ref == actor and ACTOR.fullmatch(call.actor_ref)
    # Le motif SQL de 002_audit.sql accepte la même valeur.
    assert re.fullmatch(r"^(anonymous|(tok|mission|operator)_[0-9a-f]{16})$", call.actor_ref)


def test_audit_admits_bootstrap_but_not_anonymous(backend, monkeypatch):
    from mcp_vault.storage import audit_pg
    from mcp_vault.storage.postgres import MetadataUnavailable
    backend("postgres")
    monkeypatch.setattr(audit_pg, "_write", lambda call, deadline, op, validate=False: ("written", validate))
    base = dict(instance="test-vault", call_id="c", tool="vault_list", vault_id="", tenant_id=None,
                mission_id=None, operation_id=None, started=0.0)
    bootstrap = audit_pg.Call(actor_ref="tok_" + "0" * 16, **base)
    assert audit_pg._admit(bootstrap, "admitted", 0) == ("written", True)
    with pytest.raises(MetadataUnavailable):
        audit_pg._admit(audit_pg.Call(actor_ref="anonymous", **base), "admitted", 0)
