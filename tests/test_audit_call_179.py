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
