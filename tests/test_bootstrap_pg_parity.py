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
    # La clé : faits isolés, sans lecture PG, même si son hash figurait dans `tokens`.
    facts = await admission.admit(KEY)
    assert seen == []
    assert (facts["actor_hash"], facts["actor_revision"], facts["policy_revisions"], facts["owners"]) == (None, None, {}, {})
    assert facts["token"].get_by_hash(hashlib.sha256(KEY.encode()).hexdigest()) is None
    # Un autre bearer suit le chemin PG ordinaire.
    assert await admission.admit("autre-bearer") == {"owners": {}}
    assert seen == [(admission.load_facts, "autre-bearer", None)]
    for refused in ("", "z" * 8193):
        with pytest.raises(PermissionError):
            await admission.admit(refused)
    assert len(seen) == 1


class _Conn:
    def __init__(self, row=None):
        self.sql, self.row = [], row

    def execute(self, sql, params=None):
        self.sql.append(sql)
        return SimpleNamespace(fetchone=lambda: self.row, fetchall=lambda: [])


BOOT_ID = {"auth_type": "bootstrap", "client_name": "admin", "permissions": ["admin", "read", "write"]}
EXPIRED = {"payload": {"revoked": True, "expires_at": "2000-01-01T00:00:00+00:00"}, "revision": 1}


@pytest.mark.parametrize("identity,expected", [
    (BOOT_ID, None),
    ({"auth_type": "token", "client_name": "x"}, "actor_changed"),
])
def test_bootstrap_ignores_a_token_row_with_its_hash(backend, identity, expected):
    """Même si des faits portent un actor_hash dont la ligne est révoquée ou expirée, la clé passe ; un token non."""
    from mcp_vault.auth.context import current_token_info
    from mcp_vault.storage.postgres import MetadataUnavailable, request_facts, revalidate_actor
    backend("postgres")
    who = current_token_info.set(identity)
    facts = request_facts.set({"owners": {}, "actor_hash": "a" * 64, "actor_revision": 1, "policy_revisions": {}})
    conn = _Conn(EXPIRED)
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


BOOTSTRAP_ACTOR = "tok_" + hashlib.sha256(b"mcp-vault:bootstrap-actor:test-vault").hexdigest()[:16]


@pytest.mark.parametrize("identity,actor", [
    ({"auth_type": "bootstrap", "client_name": "admin"}, BOOTSTRAP_ACTOR),
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


def test_audit_name_invariant_when_the_key_changes(backend, monkeypatch):
    from mcp_vault.auth.context import current_token_info
    from mcp_vault.config import get_settings
    from mcp_vault.storage.audit_pg import make_call
    from mcp_vault.storage.postgres import request_facts
    backend("postgres")
    names = []
    for key in (KEY, "Zq9$" + "w2E@" * 15):
        monkeypatch.setenv("ADMIN_BOOTSTRAP_KEY", key)
        get_settings.cache_clear()
        who = current_token_info.set({"auth_type": "bootstrap", "client_name": "admin"})
        facts = request_facts.set({"owners": {}, "actor_hash": None})
        try:
            names.append(make_call("vault_list").actor_ref)
        finally:
            request_facts.reset(facts)
            current_token_info.reset(who)
    assert names == [BOOTSTRAP_ACTOR, BOOTSTRAP_ACTOR]


def test_audit_name_never_derives_from_the_key(backend):
    """Le nom d'audit ne publie aucune empreinte de la clé (clé choisie, chiffre l'unseal)."""
    digests = {hashlib.new(name, KEY.encode()).hexdigest() for name in ("sha256", "sha1", "md5", "sha512")}
    assert not any(BOOTSTRAP_ACTOR[4:] in d for d in digests)


@pytest.mark.parametrize("identity,admitted", [
    ({"auth_type": "bootstrap", "client_name": "admin"}, True),
    ({"client_name": "admin"}, False),
])
def test_audit_admission_chain(backend, monkeypatch, identity, admitted):
    """make_call puis _admit, comme le fait admit() : la clé est admise, l'inconnu ne l'est pas."""
    from mcp_vault.auth.context import current_token_info
    from mcp_vault.storage import audit_pg
    from mcp_vault.storage.postgres import MetadataUnavailable, request_facts
    backend("postgres")
    monkeypatch.setattr(audit_pg, "_write", lambda call, deadline, op, validate=False: ("written", validate))
    who = current_token_info.set(identity)
    facts = request_facts.set({"owners": {}, "actor_hash": None})
    try:
        call = audit_pg.make_call("secret_read", "coffer-a")
    finally:
        request_facts.reset(facts)
        current_token_info.reset(who)
    if admitted:
        assert audit_pg._admit(call, "admitted", 0) == ("written", True)
    else:
        with pytest.raises(MetadataUnavailable):
            audit_pg._admit(call, "admitted", 0)


async def _asgi(middleware, token):
    sent = []
    scope = {"type": "http", "path": "/mcp", "method": "POST",
             "headers": [(b"authorization", b"Bearer " + token.encode())]}

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)
    await middleware(scope, receive, send)
    return next((m["status"] for m in sent if m["type"] == "http.response.start"), None)


@pytest.mark.parametrize("mode", ["bearer", "jwt", "dual-stack"])
async def test_mcp_request_reaches_app_with_bootstrap_in_pg(backend, monkeypatch, mode):
    """Chemin ASGI réel de /mcp en PG : admission, puis résolution du bearer, puis l'application."""
    from mcp_vault.auth import middleware as mw
    from mcp_vault.auth.context import current_token_info
    from mcp_vault.storage import admission, audit_pg
    from mcp_vault.storage.postgres import request_facts
    monkeypatch.setenv("MCP_AUTH_MODE", mode)
    backend("postgres")

    async def offload(fn, raw, tenant):
        return {"owners": {}, "actor_hash": None}

    async def denial(tool):
        return True
    monkeypatch.setattr(admission, "offload", offload)
    monkeypatch.setattr(audit_pg, "record_auth_denial", denial)
    monkeypatch.setattr(mw, "get_token_store", lambda: None)
    seen = []

    async def app(scope, receive, send):
        seen.append((current_token_info.get(), request_facts.get()))
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    status = await _asgi(mw.AuthMiddleware(app), KEY)
    assert status == 200 and len(seen) == 1
    identity, facts = seen[0]
    assert identity["auth_type"] == "bootstrap" and "admin" in identity["permissions"]
    assert facts["actor_hash"] is None and facts["policy_revisions"] == {}
    # Un autre bearer, inconnu, n'atteint pas l'application.
    status = await _asgi(mw.AuthMiddleware(app), KEY[:-1] + "y")
    assert status in (401, 403) and len(seen) == 1
