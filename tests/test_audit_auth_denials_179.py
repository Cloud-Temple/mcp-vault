"""Les refus ne récupèrent jamais les droits d'un ancien contexte/jeton PG."""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from mcp_vault.admin import api
from mcp_vault.auth.context import current_token_info
from mcp_vault.auth.middleware import AuthMiddleware
from mcp_vault.storage import admission, audit_pg
from mcp_vault.storage.postgres import MetadataUnavailable, MutationUnknown, request_facts


@pytest.mark.parametrize('tool', ['bearer_auth', 'mission_pep'])
def test_denial_identity_is_anonymous_even_with_stale_admin_facts(tool):
    async def exercise():
        identity = current_token_info.set({'auth_type': 'token', 'permissions': ['admin']})
        facts = request_facts.set({'actor_hash': 'a'*64, 'actor_revision': 1})
        insert, close = AsyncMock(), AsyncMock()
        try:
            with patch.object(audit_pg, 'get_settings', return_value=SimpleNamespace(metadata_backend='postgres', metadata_instance_id='fixture')), \
                 patch.object(audit_pg, 'admit', insert), patch.object(audit_pg, 'append', close):
                assert await audit_pg.record_auth_denial(tool) is True
            call = insert.call_args.args[0]
            assert insert.call_args.kwargs == {'denied': True}
            assert call.actor_ref == 'anonymous' and call.tool == tool
            assert (call.tenant_id, call.mission_id, call.operation_id, call.vault_id) == (None, None, None, '')
            assert close.call_args.args == (call, 'public_terminal', 'denied')
            assert current_token_info.get()['permissions'] == ['admin']  # Pas de promotion/édition du contexte.
        finally:
            request_facts.reset(facts)
            current_token_info.reset(identity)

    asyncio.run(exercise())


def test_denied_insert_does_not_revalidate_expired_or_revoked_actor():
    call = SimpleNamespace(call_id='fixed', actor_ref='anonymous')
    with patch.object(audit_pg, '_write', return_value=None) as write:
        audit_pg._admit(call, 'denied', 10)
    assert write.call_args.kwargs == {'validate': False}
    with pytest.raises(MetadataUnavailable):
        audit_pg._admit(call, 'admitted', 10)


@pytest.mark.parametrize('error', [None, MetadataUnavailable('offline'), MutationUnknown('fixed')])
@pytest.mark.parametrize('mode', ['bearer', 'jwt'])
def test_actual_mcp_auth_refusal_waits_for_audit_and_never_dispatches(error, mode):
    import mcp_vault.auth.middleware as middleware

    async def exercise():
        sent = []
        application = AsyncMock()
        settings = SimpleNamespace(metadata_backend='postgres', metadata_instance_id='fixture', mcp_auth_mode=mode)
        admitted = AsyncMock(side_effect=error)
        terminal = AsyncMock()
        with patch.object(middleware, 'get_settings', return_value=settings), \
             patch.object(audit_pg, 'get_settings', return_value=settings), \
             patch.object(audit_pg, 'admit', admitted), patch.object(audit_pg, 'append', terminal), \
             patch.object(AuthMiddleware, '_validate_token', return_value=None), \
             patch.object(AuthMiddleware, '_resolve_pep', AsyncMock(return_value=(None, (401, 'invalid', {})))):
            await AuthMiddleware(application)._call_authenticated({'type': 'http', 'path': '/mcp',
                'headers': [(b'authorization', b'Bearer PRIVATE-INVALID-CANARY')]}, AsyncMock(), AsyncMock(side_effect=sent.append))
        application.assert_not_awaited()
        assert admitted.call_args.args[0].actor_ref == 'anonymous'
        assert admitted.call_args.args[0].tool == ('bearer_auth' if mode == 'bearer' else 'mission_pep')
        assert sent[0]['status'] == (503 if error else 401)
        assert 'PRIVATE-' not in repr((admitted.call_args, terminal.call_args, sent))

    asyncio.run(exercise())


def test_actual_admin_invalid_token_has_durable_anonymous_refusal():
    async def exercise():
        sent = []
        settings = SimpleNamespace(metadata_backend='postgres', metadata_instance_id='fixture')
        admitted, closed = AsyncMock(), AsyncMock()
        with patch.object(api, '_get_token_info', return_value=None), patch.object(api, 'get_settings', return_value=settings), \
             patch.object(audit_pg, 'get_settings', return_value=settings), \
             patch.object(audit_pg, 'admit', admitted), patch.object(audit_pg, 'append', closed), \
             patch.object(api, '_handle_admin_routes', AsyncMock()) as business:
            await api._handle_authenticated_admin({'path': '/admin/api/tokens', 'method': 'POST'},
                AsyncMock(), AsyncMock(side_effect=sent.append), None)
        business.assert_not_awaited()
        assert sent[0]['status'] == 401 and admitted.call_args.args[0].actor_ref == 'anonymous'
        assert closed.call_args.args[1:] == ('public_terminal', 'denied')

    asyncio.run(exercise())


def test_actual_missing_token_admission_denies_without_entering_business():
    async def exercise():
        sent = []
        app = AsyncMock()
        deny = AsyncMock(return_value=True)
        with patch.object(admission, 'admit', AsyncMock(side_effect=PermissionError('closed'))), \
             patch.object(audit_pg, 'record_auth_denial', deny):
            await admission.admitted_call({'headers': []}, AsyncMock(), AsyncMock(side_effect=sent.append), app)
        app.assert_not_awaited()
        deny.assert_awaited_once_with('bearer_auth')
        assert sent[0]['status'] == 403

    asyncio.run(exercise())
