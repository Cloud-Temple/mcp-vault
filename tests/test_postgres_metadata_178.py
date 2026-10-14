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


@pytest.mark.parametrize("unknown",[False,True])
@pytest.mark.parametrize("revoke_fails",[False,True])
async def test_wrap_pg_activation_failure_compensates_once(pg,monkeypatch,unknown,revoke_fails):
    from unittest.mock import MagicMock
    from mcp_vault.vault import wrapping
    from mcp_vault.storage import stores,postgres
    from tests.test_wrap import _make_registry,_make_hvac_ok
    registry = _make_registry()
    mutation_id = "c837848f-a3cb-4449-8be8-c9c9fdb8a3e5"
    error = postgres.MutationUnknown(mutation_id) if unknown else postgres.MetadataUnavailable("storage_unavailable")
    registry.mark_active = MagicMock(side_effect=error)
    client = _make_hvac_ok(wrap_token="s.PRIVATE",accessor="private-accessor")
    if revoke_fails:
        client.auth.token.revoke_accessor.side_effect = ConnectionError("ack lost")
    monkeypatch.setattr(wrapping,"_get_client",lambda:client)
    monkeypatch.setattr(wrapping,"get_wrap_registry",lambda:registry)
    # Couture de chargement PG : le corps et la façade publique restent livrés.
    # Ce test logiciel ne revendique aucun PostgreSQL/OpenBao réel.
    monkeypatch.setattr(stores,"wrap_for_worker",lambda fn,args,kwargs:fn(*args,**kwargs))
    result = await wrapping.wrap_secret("ordinary","db/p","mission-one","activation-fault")
    assert result["error_type"] == ("wrap_created_orphaned" if revoke_fails else "wrap_created_revoked")
    assert result["metadata_outcome"] == ("unknown" if unknown else "unconfirmed")
    if unknown:
        assert result["mutation_id"] == mutation_id
    assert "wrap_token" not in result and "accessor" not in result
    assert "s.PRIVATE" not in str(result) and "private-accessor" not in str(result)
    registry.mark_active.assert_called_once()
    client.auth.token.revoke_accessor.assert_called_once_with(accessor="private-accessor")


async def test_health_burst_shares_probe_and_preserves_business_admission(pg,monkeypatch):
    import threading,hashlib
    from mcp_vault import lifecycle
    from mcp_vault.storage import postgres,admission
    from mcp_vault.openbao import manager
    from unittest.mock import AsyncMock
    started,release = threading.Event(),threading.Event()
    probes = []
    monkeypatch.setattr(postgres,"_slots",threading.BoundedSemaphore(4))
    monkeypatch.setattr(lifecycle,"startup_is_ready",lambda:True)
    monkeypatch.setattr(manager,"probe_openbao",AsyncMock(return_value=manager.OpenBaoProbe(True,False,"ready")))
    lifecycle._reset_shutdown_state()
    token_hash = hashlib.sha256(b"business-token").hexdigest()
    class Cursor:
        def __init__(self,rows=()): self.rows=list(rows)
        def fetchall(self): return self.rows
    class Connection:
        def execute(self,query,params=None):
            if query.startswith("SELECT 1 FROM vault_metadata.tokens"):
                probes.append(1)
                started.set()
                if not release.wait(2):
                    raise postgres.MetadataUnavailable("test_timeout")
            if "SELECT payload,revision FROM vault_metadata.tokens" in query:
                return Cursor([{"payload":{"hash":token_hash,"client_name":"business","permissions":["read"],
                    "allowed_resources":["ordinary"],"policy_id":"","revoked":False,
                    "created_at":"2026-10-14T00:00:00+00:00","expires_at":"2030-01-01T00:00:00+00:00"},"revision":1}])
            return Cursor()
    @contextmanager
    def connected():
        acquired = postgres.slots().acquire(timeout=0.1)
        if not acquired:
            raise postgres.MetadataUnavailable("admission_timeout")
        try: yield Connection()
        finally: postgres.slots().release()
    monkeypatch.setattr(postgres,"connection",connected)
    monkeypatch.setattr(admission,"connection",connected)
    tasks = [asyncio.create_task(lifecycle.availability_status()) for _ in range(25)]
    try:
        assert await asyncio.to_thread(started.wait,1)
        tasks[0].cancel()
        with pytest.raises(asyncio.CancelledError): await tasks[0]
        facts = await admission.admit("business-token")
        assert facts["actor_hash"]==token_hash
    finally:
        release.set()
        results = await asyncio.gather(*tasks[1:],return_exceptions=True)
    assert all(value[0]==lifecycle.HEALTH_HEALTHY for value in results)
    assert len(probes)==1
    assert (await lifecycle.availability_status())[0]==lifecycle.HEALTH_HEALTHY
    assert len(probes)==1


@pytest.mark.parametrize("available",[False,True])
async def test_pg_health_cache_expires_without_auth_cache(pg,monkeypatch,available):
    from mcp_vault import lifecycle
    from mcp_vault.storage import postgres
    probes=[]
    pg.metadata_readiness_ttl_seconds=0.1
    lifecycle._reset_shutdown_state()
    @contextmanager
    def connected():
        probes.append(1)
        if not available:
            raise postgres.MetadataUnavailable("storage_unavailable")
        yield SimpleNamespace(execute=lambda *a:None)
    monkeypatch.setattr(postgres,"connection",connected)
    assert await lifecycle._metadata_readiness() is available
    assert await lifecycle._metadata_readiness() is available
    assert len(probes)==1
    await asyncio.sleep(0.12)
    assert await lifecycle._metadata_readiness() is available
    assert len(probes)==2
    lifecycle._reset_shutdown_state()
    assert await lifecycle._metadata_readiness() is available
    assert len(probes)==3


@pytest.mark.parametrize("first_cancel_ignored",[False,True])
def test_commit_deadline_cancels_and_drains_before_return(pg,first_cancel_ignored):
    import threading,time
    from mcp_vault.storage import postgres
    cancelled=threading.Event()
    calls=[]
    class Connection:
        def execute(self,query,params=None,**kwargs):
            if query=="COMMIT":
                if not cancelled.wait(2): raise AssertionError("COMMIT sans annulation")
            return object()
        def cancel_safe(self,timeout):
            calls.append(timeout)
            if not first_cancel_ignored or len(calls)>1: cancelled.set()
    bounded=postgres.BoundedConnection(Connection())
    bounded.end=time.monotonic()+0.02
    with pytest.raises(postgres.MetadataUnavailable,match="commit_deadline"):
        bounded.execute("COMMIT")
    assert len(calls)==(2 if first_cancel_ignored else 1)
    assert calls==[pg.metadata_sql_cancel_seconds]*len(calls)
    prior=len(calls)
    time.sleep(0.12)
    assert len(calls)==prior  # Aucun cancel après retour/réutilisation.


def test_ha_durability_needs_no_foreign_statistics(pg):
    from mcp_vault.storage import postgres
    pg.metadata_pg_durability="ha"
    statements=[]
    class Connection:
        def execute(self,query,params=None):
            statements.append(query)
            assert "pg_stat_replication" not in query
            value={"SHOW synchronous_commit":{"synchronous_commit":"remote_apply"},
                   "SHOW synchronous_standby_names":{"synchronous_standby_names":"FIRST 1 (standby)"},
                   "SHOW fsync":{"fsync":"on"}}.get(query)
            return SimpleNamespace(fetchone=lambda:value)
    postgres.validate_durability(Connection())
    assert "SET LOCAL synchronous_commit = 'remote_apply'" in statements


def test_pg_binding_view_keeps_validation_and_tombstone_rules(pg):
    from mcp_vault.storage import stores,postgres
    record={"tenant_id":"tenant-one","instance_id":pg.metadata_instance_id,"permissions":["read"],"allowed_resources":["ordinary"],
            "enabled":True,"policy_id":"","expires_at":None}
    row={"payload":record,"revision":1}
    assert stores.view("binding",[row]).resolve("tenant-one")==record
    with pytest.raises(postgres.MetadataUnavailable,match="binding_corrupt"):
        stores.view("binding",[{"payload":{**record,"permissions":["admin"]},"revision":1}])
    assert stores.view("binding",[{"payload":{**record,"enabled":False,"_deleted":True},"revision":2}]).get("tenant-one") is None


def test_pg_wrap_view_loads_real_validated_registry_record(pg):
    from mcp_vault.storage import stores
    from tests.test_wrap import _make_registry
    registry=_make_registry()
    assert registry.register_pending("view-op","view-mission","ordinary","db/p",300)
    assert registry.mark_active("view-op","view-mission","view-accessor")
    snapshot=stores.view("wrap",[{"payload":registry._wraps[0],"revision":2}])
    assert snapshot._wraps[0]["accessor"]=="view-accessor"


def test_deadline_mutation_keeps_uuid_and_one_local_receipt(pg,monkeypatch):
    import threading,time
    from mcp_vault.storage import postgres
    cancelled=threading.Event()
    receipts=[]
    class Connection:
        def add_notice_handler(self,callback): self.callback=callback
        def execute(self,query,params=None,**kwargs):
            if query.startswith("INSERT INTO vault_metadata.operation_receipts"):
                receipts.append(params)
            if query=="COMMIT":
                assert cancelled.wait(2)
            return SimpleNamespace(fetchone=lambda:None)
        def cancel_safe(self,timeout): cancelled.set()
    @contextmanager
    def connected():
        conn=postgres.BoundedConnection(Connection())
        conn.end=time.monotonic()+0.02
        yield conn
    monkeypatch.setattr(postgres,"connection",connected)
    monkeypatch.setattr(postgres,"validate_durability",lambda conn:None)
    with pytest.raises(postgres.MutationUnknown) as error:
        postgres.mutation("deadline-example",{"target":"ordinary"},lambda conn:True,operator=True)
    assert len(receipts)==1
    assert receipts[0][1]==error.value.mutation_id
