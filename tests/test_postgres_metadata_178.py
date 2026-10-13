"""Contrats #178 sans service ; aucun résultat PostgreSQL réel revendiqué."""
import asyncio
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest


@pytest.fixture
def pg(monkeypatch):
    from mcp_vault.config import get_settings
    values = {"METADATA_BACKEND":"postgres","METADATA_INSTANCE_ID":"test-vault",
        "METADATA_PG_VAULT_ID":"ssh-ca-prod","METADATA_PG_SECRET_PATH":"app/connection",
        "METADATA_PG_PROVISIONER_SECRET_PATH":"provisioner/connection","METADATA_PG_DATABASE":"vault",
        "METADATA_PG_OWNER_ROLE":"vault_owner","METADATA_PG_APP_ROLE":"vault_app",
        "METADATA_PG_PROVISIONER_ROLE":"vault_provisioner","METADATA_PG_CA_FILE":"unit-ca.crt",
        "ADMIN_BOOTSTRAP_KEY":"a"*64}
    for name,value in values.items():
        monkeypatch.setenv(name,value)
    get_settings.cache_clear()
    from mcp_vault.auth.context import current_token_info
    from mcp_vault.storage.postgres import request_facts
    actor = current_token_info.set({"client_name":"first-admin","permissions":["admin"],"allowed_resources":[]})
    facts = request_facts.set({"owners":{}})
    yield get_settings()
    request_facts.reset(facts)
    current_token_info.reset(actor)
    get_settings.cache_clear()


def forbidden_backend(*args,**kwargs):
    pytest.fail("OpenBao métier appelé avant garde",pytrace=False)


@pytest.mark.parametrize("kind",["delete","setup","sign","key","roles","cleanup"])
async def test_derived_mount_primitives_refuse_before_backend(pg,monkeypatch,kind):
    from mcp_vault.vault import spaces,ssh_ca
    from mcp_vault.reserved_metadata import ReservedMetadataAccess
    monkeypatch.setattr(spaces,"get_hvac_client",forbidden_backend)
    monkeypatch.setattr(ssh_ca,"get_hvac_client",forbidden_backend)
    calls = {"delete":lambda:spaces.delete_space("prod"),
        "setup":lambda:ssh_ca.setup_ssh_ca("prod","role"),
        "sign":lambda:ssh_ca.sign_ssh_key("prod","role","ssh-ed25519 AA"),
        "key":lambda:ssh_ca.get_ca_public_key("prod"),
        "roles":lambda:ssh_ca.list_ssh_roles("prod"),
        "cleanup":lambda:ssh_ca.cleanup_ssh_ca("prod")}
    if kind=="cleanup":
        with pytest.raises(ReservedMetadataAccess):
            await calls[kind]()
    else:
        assert (await calls[kind]())["error_type"]=="access_denied"


async def test_kv_pure_target_and_mixed_batch(pg,monkeypatch):
    from mcp_vault.reserved_metadata import target_error
    from mcp_vault.storage import admission
    assert target_error("prod") is None
    assert target_error("prod",ssh=True)["error_type"]=="access_denied"
    monkeypatch.setattr(admission,"offload",forbidden_backend)
    result = await admission.batch_metadata(["ordinary","ssh-ca-prod"])
    assert result["status"]=="error" and "total" not in result and "vaults" not in result


async def test_bootstrap_rejected_without_pg_or_vault(pg,monkeypatch):
    from mcp_vault.storage import admission
    monkeypatch.setattr(admission,"offload",forbidden_backend)
    with pytest.raises(PermissionError):
        await admission.admit(pg.admin_bootstrap_key)
    from mcp_vault.auth.middleware import AuthMiddleware
    result = await AuthMiddleware(None)._resolve_pep(pg.admin_bootstrap_key,pg)
    assert result[0] is None and result[1][0]==403


async def test_batch_preloads_all_before_page_and_no_partial(pg,monkeypatch):
    from mcp_vault.storage import admission,reader
    from mcp_vault.storage.postgres import request_facts,MetadataUnavailable
    from mcp_vault.auth.context import current_token_info
    actor = current_token_info.set({"client_name":"owner","permissions":["read"],"allowed_resources":[]})
    read_threads = []
    import threading
    main = threading.get_ident()
    def owner(vid,**kwargs):
        read_threads.append(threading.get_ident())
        if vid=="z-last":
            raise MetadataUnavailable("metadata_corrupt")
        return {"created_by":"owner","description":"ordinary"}
    monkeypatch.setattr(reader,"owner_metadata",owner)
    try:
        result = await admission.batch_metadata(["a-first","z-last"],limit=1)
        assert result["status"]=="error" and result["classification"]=="corrupt"
        assert "total" not in result and "vaults" not in result
        assert request_facts.get()["owners"]=={}
        assert len(read_threads)==2 and all(t!=main for t in read_threads)
    finally:
        current_token_info.reset(actor)


async def test_info_no_mount_scan_or_swallowed_outage(pg,monkeypatch):
    from mcp_vault.vault import spaces
    from mcp_vault.storage import reader
    from mcp_vault.storage.postgres import MetadataUnavailable
    monkeypatch.setattr(spaces,"get_hvac_client",forbidden_backend)
    def failed(*args,**kwargs):
        raise MetadataUnavailable("backend_denied")
    monkeypatch.setattr(reader,"owner_metadata",failed)
    result = await spaces.get_space_info("ordinary",count=False)
    assert result["status"]=="error" and "created_by" not in result


async def test_rest_first_admin_derived_target_before_backend(pg,monkeypatch):
    from mcp_vault.admin import api
    monkeypatch.setattr(api,"_api_delete_vault",AsyncMock(side_effect=forbidden_backend))
    messages = []
    async def send(message):
        messages.append(message)
    async def receive():
        return {"type":"http.request","body":b""}
    await api._handle_admin_routes({"type":"http","method":"DELETE","path":"/admin/api/vaults/prod"},receive,send,None,
        {"client_name":"first-admin","permissions":["admin"],"allowed_resources":[]})
    assert messages[0]["status"]==403
    api._api_delete_vault.assert_not_called()


@pytest.mark.parametrize("notice",[False,True])
def test_unknown_commit_ids_do_not_collide_between_missions(pg,monkeypatch,notice):
    from mcp_vault.storage import postgres
    receipts = []
    class Connection:
        def add_notice_handler(self,callback):
            self.callback = callback
        def execute(self,query,params=None):
            if query.startswith("INSERT INTO vault_metadata.operation_receipts"):
                receipts.append(params)
            if query=="COMMIT":
                if notice:
                    self.callback(SimpleNamespace(sqlstate="01000"))
                else:
                    raise ConnectionError("ack lost")
            return SimpleNamespace(fetchone=lambda:None)
    @contextmanager
    def connected():
        yield Connection()
    monkeypatch.setattr(postgres,"connection",connected)
    monkeypatch.setattr(postgres,"validate_durability",lambda conn:None)
    ids = []
    for mission in ("mission-a","mission-b"):
        target = {"business_operation_id":"same-operation","mission_id":mission,
                  "expected_revision":0,"result_revision":1}
        with pytest.raises(postgres.MutationUnknown) as error:
            postgres.mutation("wrap:pending",target,lambda conn:True,operator=True)
        ids.append(error.value.mutation_id)
    assert len(set(ids))==2
    assert [r[5].obj["mission_id"] for r in receipts]==["mission-a","mission-b"]
    assert [r[1] for r in receipts]==ids


async def test_jit_reserved_profiles_hidden_and_request_refused(pg,monkeypatch):
    from mcp_vault import ssh_operator as jit
    profile = SimpleNamespace(vault_id="prod",profile_id="reserved",client_name="first-admin")
    monkeypatch.setattr(jit,"parse_operator_profiles",lambda *a,**k:{"reserved":profile})
    monkeypatch.setattr(jit,"_check_dedicated_policy",forbidden_backend)
    monkeypatch.setattr(jit,"get_token_store",lambda:None)
    from mcp_vault.auth.context import current_token_info
    from datetime import datetime,timedelta,timezone
    current_token_info.set({"auth_type":"token","client_name":"first-admin","permissions":["read"],
        "expires_at":(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()})
    assert jit.list_operator_access_profiles()["count"]==0
    result = await jit.request_operator_ssh_access("reserved","ssh-ed25519 AA","qualification")
    assert result["error_type"]=="access_denied"


@pytest.mark.parametrize("status,body,reason",[
    (404,b'{"errors":[]}',"metadata_absent_confirmed"),
    (404,b'{"errors":["unknown mount"]}',"backend_unavailable"),
    (403,b'{"errors":["permission denied"]}',"backend_denied"),
    (200,b'{"data":{"data":[]}}',"metadata_corrupt"),
    (503,b'{"errors":[]}',"backend_unavailable"),
])
def test_targeted_reader_classifies_without_scan(pg,monkeypatch,status,body,reason):
    import httpx
    from mcp_vault.storage import reader
    from mcp_vault.storage.postgres import MetadataUnavailable
    from mcp_vault.openbao import manager
    monkeypatch.setattr(manager,"get_hvac_client",lambda:SimpleNamespace(token="unit-token"))
    calls = []
    def request(req):
        calls.append((req.method,req.url.path))
        return httpx.Response(status,content=body)
    real_client = httpx.Client
    monkeypatch.setattr(httpx,"Client",lambda **kwargs:real_client(transport=httpx.MockTransport(request),**kwargs))
    with pytest.raises(MetadataUnavailable) as error:
        reader.owner_metadata("ordinary")
    assert error.value.reason==reason
    assert calls==[("GET","/v1/ordinary/data/_vault_meta")]


def test_pg_facade_never_delegates_s3_io(pg):
    from mcp_vault.storage.stores import PGStore
    for kind in ("token","policy","binding"):
        store = PGStore(kind)
        assert store.count() is None
        for name in ("load","_save","_get_s3_data"):
            with pytest.raises(AttributeError):
                getattr(store,name)


def test_external_operator_vault_auth_precedes_credential_read(tmp_path,monkeypatch):
    import importlib.util,httpx
    from pathlib import Path
    spec = importlib.util.spec_from_file_location("pg_operator",Path(__file__).parents[1]/"scripts/pg_operator.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    token = tmp_path/"operator-token"
    token.write_text("unit-token")
    calls = []
    def failed_auth(request):
        calls.append(request.url.path)
        return httpx.Response(403,json={"errors":["denied"]})
    original = httpx.Client
    monkeypatch.setattr(httpx,"Client",lambda **kwargs:original(transport=httpx.MockTransport(failed_auth),**{**kwargs,"verify":True}))
    arguments = SimpleNamespace(vault_token_file=str(token),vault_ca_file="unit-ca.crt",vault_url="https://bao.test")
    with pytest.raises(ValueError):
        module.native_connection(arguments,"infra","pg")
    assert calls==["/v1/auth/token/lookup-self"]
