"""Ordre d'admission, clôture et non restitution des secrets sur erreur durable."""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from mcp_vault.storage import audit_call
from mcp_vault.storage.audit_pg import current_audit_call
from mcp_vault.storage.postgres import MetadataUnavailable, MutationUnknown


def test_admission_before_effect_and_context_released():
    async def exercise():
        order=[]
        call=SimpleNamespace(call_id='fixed')
        async def admit(value):
            assert value is call
            order.append('admission')
        async def close(value,phase,outcome):
            assert current_audit_call.get() is call
            assert (phase,outcome)==('public_terminal','completed')
            order.append('close')
        async def secret_read(vault_id):
            assert current_audit_call.get() is call
            order.append('effect')
            return {'status':'ok','secret':'private'}
        with patch.object(audit_call,'get_settings',return_value=SimpleNamespace(metadata_backend='postgres')), \
             patch.object(audit_call,'make_call',return_value=call), \
             patch.object(audit_call,'admit',admit),patch.object(audit_call,'append',close):
            result=await audit_call.audited_call(secret_read)('coffer-a')
        assert result['secret']=='private' and order==['admission','effect','close']
        assert current_audit_call.get() is None
    asyncio.run(exercise())


@pytest.mark.parametrize('error',[MetadataUnavailable('offline'),MutationUnknown('fixed')])
def test_failed_admission_never_dispatches_business(error):
    async def exercise():
        effect=AsyncMock()
        with patch.object(audit_call,'get_settings',return_value=SimpleNamespace(metadata_backend='postgres')), \
             patch.object(audit_call,'make_call',return_value=SimpleNamespace(call_id='fixed')), \
             patch.object(audit_call,'admit',AsyncMock(side_effect=error)):
            result=await audit_call.audited_call(effect)()
        assert result['error_type']=='audit_unavailable'
        effect.assert_not_awaited()
    asyncio.run(exercise())


def test_close_unknown_hides_secret_and_never_repeats_effect():
    async def exercise():
        effect=AsyncMock(return_value={'status':'ok','secret':'private'})
        with patch.object(audit_call,'get_settings',return_value=SimpleNamespace(metadata_backend='postgres')), \
             patch.object(audit_call,'make_call',return_value=SimpleNamespace(call_id='fixed')), \
             patch.object(audit_call,'admit',AsyncMock()), \
             patch.object(audit_call,'append',AsyncMock(side_effect=MutationUnknown('fixed'))):
            result=await audit_call.audited_call(effect)()
        assert 'private' not in str(result) and result['replay_allowed'] is False
        assert result['business_outcome']=='confirmed' and effect.await_count==1
        assert current_audit_call.get() is None
    asyncio.run(exercise())


def test_legacy_backend_retains_existing_dispatch_without_pg():
    async def exercise():
        effect=AsyncMock(return_value={'status':'ok'})
        admission=AsyncMock()
        with patch.object(audit_call,'get_settings',return_value=SimpleNamespace(metadata_backend='s3')), \
             patch.object(audit_call,'admit',admission):
            assert await audit_call.audited_call(effect)()=={'status':'ok'}
        admission.assert_not_awaited()
        effect.assert_awaited_once()
    asyncio.run(exercise())


def test_business_exception_closes_unknown_and_keeps_original_exception():
    async def exercise():
        close=AsyncMock()
        async def secret_read():
            raise ValueError('original')
        with patch.object(audit_call,'get_settings',return_value=SimpleNamespace(metadata_backend='postgres')), \
             patch.object(audit_call,'make_call',return_value=SimpleNamespace(call_id='fixed')), \
             patch.object(audit_call,'admit',AsyncMock()),patch.object(audit_call,'append',close):
            with pytest.raises(ValueError,match='original'):
                await audit_call.audited_call(secret_read)()
        assert close.call_args.args[1:]==('public_terminal','unknown')
        assert current_audit_call.get() is None
    asyncio.run(exercise())


def test_error_result_never_claims_confirmed_business_failure():
    async def exercise():
        close=AsyncMock()
        async def secret_read():
            return {'status':'error','error_type':'backend'}
        with patch.object(audit_call,'get_settings',return_value=SimpleNamespace(metadata_backend='postgres')), \
             patch.object(audit_call,'make_call',return_value=SimpleNamespace(call_id='fixed')), \
             patch.object(audit_call,'admit',AsyncMock()),patch.object(audit_call,'append',close):
            result=await audit_call.audited_call(secret_read)()
        assert result['error_type']=='backend'
        assert close.call_args.args[1:]==('public_terminal','unknown')
    asyncio.run(exercise())


def test_business_exception_has_priority_over_cancelled_closure():
    async def exercise():
        drained=[]
        async def secret_read():
            raise ValueError('initial business exception')
        async def close(*_):
            await asyncio.sleep(0)
            drained.append(True)
            raise asyncio.CancelledError()
        with patch.object(audit_call,'get_settings',return_value=SimpleNamespace(metadata_backend='postgres')), \
             patch.object(audit_call,'make_call',return_value=SimpleNamespace(call_id='fixed')), \
             patch.object(audit_call,'admit',AsyncMock()),patch.object(audit_call,'append',close):
            with pytest.raises(ValueError,match='initial business exception'):
                await audit_call.audited_call(secret_read)()
        assert drained==[True] and current_audit_call.get() is None
    asyncio.run(exercise())


@pytest.mark.parametrize('status',['created','updated','deleted'])
def test_existing_success_statuses_close_completed(status):
    async def exercise():
        close=AsyncMock()
        async def secret_write(): return {'status':status}
        with patch.object(audit_call,'get_settings',return_value=SimpleNamespace(metadata_backend='postgres')), \
             patch.object(audit_call,'make_call',return_value=SimpleNamespace(call_id='fixed')), \
             patch.object(audit_call,'admit',AsyncMock()),patch.object(audit_call,'append',close):
            await audit_call.audited_call(secret_write)()
        assert close.call_args.args[1:]==('public_terminal','completed')
    asyncio.run(exercise())


def test_sql_receipt_and_audit_step_share_business_commit():
    from contextlib import contextmanager
    from mcp_vault.storage import postgres, audit_pg
    order=[]
    class Conn:
        def add_notice_handler(self,_): pass
        def execute(self,query,*_):
            order.append(query)
            return SimpleNamespace(fetchone=lambda:None)
    conn=Conn()
    @contextmanager
    def connection(): yield conn
    def step(observed,call,phase,outcome,**correlation):
        assert observed is conn and phase=='sql_step_committed' and outcome=='confirmed'
        assert correlation['step_id']==correlation['mutation_id']
        order.append('AUDIT_SQL_STEP')
    marker=current_audit_call.set(SimpleNamespace(call_id='fixed'))
    try:
        with patch.object(postgres,'connection',connection), \
             patch.object(postgres,'get_settings',return_value=SimpleNamespace(metadata_instance_id='fixture')), \
             patch.object(postgres,'validate_durability'),patch.object(audit_pg,'record_step',step):
            result=postgres.mutation('write',{'coffer':'a'},lambda _:order.append('BUSINESS'),operator=True)
        assert result is None and order[-2:]==['AUDIT_SQL_STEP','COMMIT']
        assert order.index('BUSINESS')<next(i for i,q in enumerate(order) if 'INSERT INTO vault_metadata.operation_receipts' in q)<order.index('AUDIT_SQL_STEP')
    finally:
        current_audit_call.reset(marker)


def test_bao_step_does_not_return_secret_before_durable_observation():
    from mcp_vault.storage import audit_bao
    async def exercise():
        order=[]
        def effect():
            order.append('bao')
            return {'private':'secret'}
        async def record(*_,**kwargs):
            assert 'step_id' in kwargs
            order.append('pg')
            raise MutationUnknown('fixed')
        token=current_audit_call.set(SimpleNamespace(call_id='fixed'))
        try:
            with patch.object(audit_bao,'append',record):
                with pytest.raises(MutationUnknown):
                    await audit_bao.bao_step(effect)
            assert order==['bao','pg']
        finally:
            current_audit_call.reset(token)
    asyncio.run(exercise())


def test_bao_transport_failure_is_unknown_not_failed_and_compensation_distinct():
    from mcp_vault.storage import audit_bao
    async def exercise():
        close=AsyncMock()
        def effect(): raise TimeoutError('lost acknowledgement')
        token=current_audit_call.set(SimpleNamespace(call_id='fixed'))
        try:
            with patch.object(audit_bao,'append',close):
                with pytest.raises(TimeoutError):
                    await audit_bao.bao_step(effect,compensation=True)
            assert close.call_args.args[1:]==('compensation_outcome','unknown')
        finally:
            current_audit_call.reset(token)
    asyncio.run(exercise())


def test_audit_sql_notice_rolls_back_before_business_commit():
    from contextlib import contextmanager
    from mcp_vault.storage import postgres, audit_pg
    order=[]
    class Conn:
        def add_notice_handler(self,handler):self.notice=handler
        def execute(self,query,*_):
            order.append(query)
            return SimpleNamespace(fetchone=lambda:None)
    conn=Conn()
    @contextmanager
    def connection():yield conn
    def step(observed,*_,**__):observed.notice(SimpleNamespace(sqlstate='01000'))
    marker=current_audit_call.set(SimpleNamespace(call_id='fixed'))
    try:
        with patch.object(postgres,'connection',connection), \
             patch.object(postgres,'get_settings',return_value=SimpleNamespace(metadata_instance_id='fixture')), \
             patch.object(postgres,'validate_durability'),patch.object(audit_pg,'record_step',step):
            with pytest.raises(MetadataUnavailable) as error:
                postgres.mutation('write',{},lambda _:None,operator=True)
        assert error.value.reason=='transaction_notice'
        assert order[-1]=='ROLLBACK' and 'COMMIT' not in order
    finally:
        current_audit_call.reset(marker)


@pytest.mark.parametrize('dispatched',[False,True])
def test_denial_is_certain_only_before_any_backend_dispatch(dispatched):
    from mcp_vault.storage.audit_pg import current_audit_effects
    async def exercise():
        close=AsyncMock()
        async def secret_read():
            current_audit_effects.get()['dispatched']=dispatched
            return {'status':'error','error_type':'permission_denied'}
        with patch.object(audit_call,'get_settings',return_value=SimpleNamespace(metadata_backend='postgres')), \
             patch.object(audit_call,'make_call',return_value=SimpleNamespace(call_id='fixed')), \
             patch.object(audit_call,'admit',AsyncMock()),patch.object(audit_call,'append',close):
            await audit_call.audited_call(secret_read)()
        assert close.call_args.args[1:]==('public_terminal','unknown' if dispatched else 'denied')
        assert current_audit_effects.get() is None
    asyncio.run(exercise())


def test_mcp_secret_denial_is_audited_before_owner_lookup_and_no_bao():
    from mcp_vault import server
    from mcp_vault.storage import admission
    from mcp_vault.auth.context import current_token_info
    from mcp_vault.storage.postgres import request_facts
    async def exercise():
        order=[]
        async def admitted(*_):order.append('admitted')
        async def owners(*_):
            order.append('owners')
            raise PermissionError('not owner')
        async def closed(*args,**_):order.append(args[2])
        identity=current_token_info.set({'auth_type':'token','permissions':['read']})
        facts=request_facts.set({'owners':{}})
        try:
            with patch.object(audit_call,'get_settings',return_value=SimpleNamespace(metadata_backend='postgres')), \
                 patch.object(admission,'get_settings',return_value=SimpleNamespace(metadata_backend='postgres')), \
                 patch.object(audit_call,'make_call',return_value=SimpleNamespace(call_id='fixed')), \
                 patch.object(audit_call,'admit',admitted),patch.object(audit_call,'append',closed), \
                 patch.object(admission,'preload_owners',owners):
                result=await server.secret_read('coffer-a','path')
            assert result['error_type']=='access_denied' and order==['admitted','owners','denied']
        finally:
            request_facts.reset(facts)
            current_token_info.reset(identity)
    asyncio.run(exercise())


def test_mcp_secret_read_bao_observation_and_terminal_precede_secret_return():
    from mcp_vault import server
    from mcp_vault.storage import admission, audit_bao
    from mcp_vault.vault import secrets
    from mcp_vault.auth.context import current_token_info
    from mcp_vault.storage.postgres import request_facts
    from unittest.mock import MagicMock
    async def exercise():
        order=[]
        async def admitted(*_):order.append('admitted')
        async def closed(*args,**_):order.append(args[1]+':'+args[2])
        def read(**_):
            order.append('bao')
            return {'data':{'data':{'private':'secret'},'metadata':{}}}
        client=MagicMock()
        client.secrets.kv.v2.read_secret_version.side_effect=read
        identity=current_token_info.set({'auth_type':'token','permissions':['admin']})
        facts=request_facts.set({'owners':{}})
        try:
            with patch.object(audit_call,'get_settings',return_value=SimpleNamespace(metadata_backend='postgres')), \
                 patch.object(admission,'get_settings',return_value=SimpleNamespace(metadata_backend='postgres')), \
                 patch.object(audit_call,'make_call',return_value=SimpleNamespace(call_id='fixed')), \
                 patch.object(audit_call,'admit',admitted),patch.object(audit_call,'append',closed), \
                 patch.object(audit_bao,'append',closed),patch.object(secrets,'get_hvac_client',return_value=client):
                result=await server.secret_read('coffer-a','path')
            assert result['data']=={'private':'secret'}
            assert order==['admitted','bao','bao_step_outcome:confirmed','public_terminal:completed']
        finally:
            request_facts.reset(facts)
            current_token_info.reset(identity)
    asyncio.run(exercise())
