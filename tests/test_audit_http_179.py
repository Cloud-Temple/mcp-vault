"""Réponses API réelles retenues jusqu'à clôture, sans changer leurs droits."""
import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_vault.admin import api
from mcp_vault.auth.context import current_token_info
from mcp_vault.storage import audit_call, audit_http
from mcp_vault.storage.audit_contract import TOOLS
from mcp_vault.storage.audit_pg import current_audit_call
from mcp_vault.storage.postgres import MetadataUnavailable, MutationUnknown


@pytest.mark.parametrize('terminal_error', [None, MetadataUnavailable('offline'), MutationUnknown('fixed')])
def test_actual_api_token_create_never_sends_raw_token_before_closure(terminal_error):
    async def exercise():
        sent, order = [], []
        settings = SimpleNamespace(metadata_backend='postgres')
        store = MagicMock()

        async def create(*args, **kwargs):
            assert current_audit_call.get().tool == 'token_create'
            assert current_token_info.get()['permissions'] == ['admin']
            assert sent == []
            order.append('one-business-write')
            return {'status': 'created', 'raw_token': 'PRIVATE-API-CANARY'}

        async def close(call, phase, outcome):
            assert sent == []
            assert (phase, outcome) == ('public_terminal', 'completed')
            order.append('close')
            if terminal_error:
                raise terminal_error

        async def receive():
            return {'type': 'http.request', 'body': b'{"client_name":"fixture","permissions":["read"]}'}

        async def send(message):
            order.append('send')
            sent.append(message)

        store.acreate = AsyncMock(side_effect=create)
        with patch.object(api, '_get_token_info', return_value={'auth_type': 'token', 'permissions': ['admin']}), \
             patch.object(api, 'get_token_store', return_value=store), \
             patch.object(api, 'get_settings', return_value=settings), \
             patch.object(audit_http, 'get_settings', return_value=settings), \
             patch.object(audit_call, 'get_settings', return_value=settings), \
             patch.object(audit_call, 'make_call', side_effect=lambda tool, vid: SimpleNamespace(call_id='fixed', tool=tool)), \
             patch.object(audit_call, 'admit', AsyncMock()), patch.object(audit_call, 'append', close):
            await api._handle_authenticated_admin({'path': '/admin/api/tokens', 'method': 'POST',
                'headers': [(b'authorization', b'Bearer synthetic')]}, receive, send, None)
        store.acreate.assert_awaited_once()
        assert order == ['one-business-write', 'close', 'send', 'send']
        body = json.loads(sent[1]['body'])
        if terminal_error:
            assert sent[0]['status'] == 503 and 'PRIVATE-' not in repr(sent)
            assert body['replay_allowed'] is False and body['audit_status'] == 'unknown'
        else:
            assert sent[0]['status'] == 201 and body['raw_token'] == 'PRIVATE-API-CANARY'
        assert current_audit_call.get() is None
        assert current_token_info.get() is None

    asyncio.run(exercise())


def test_actual_api_permission_denial_has_no_business_dispatch():
    async def exercise():
        settings = SimpleNamespace(metadata_backend='postgres')
        sent = []
        close = AsyncMock()
        store = MagicMock()
        with patch.object(api, '_get_token_info', return_value={'auth_type': 'token', 'permissions': ['read']}), \
             patch.object(api, 'get_token_store', return_value=store), \
             patch.object(audit_http, 'get_settings', return_value=settings), \
             patch.object(audit_call, 'get_settings', return_value=settings), \
             patch.object(audit_call, 'make_call', return_value=SimpleNamespace(call_id='fixed')), \
             patch.object(audit_call, 'admit', AsyncMock()), patch.object(audit_call, 'append', close):
            await api._handle_authenticated_admin({'path': '/admin/api/tokens', 'method': 'POST'},
                AsyncMock(), AsyncMock(side_effect=sent.append), None)
        assert close.call_args.args[1:] == ('public_terminal', 'denied')
        assert sent[0]['status'] == 403
        store.acreate.assert_not_called()

    asyncio.run(exercise())


def test_failed_audit_admission_never_reads_request_or_sends_original_response():
    async def exercise():
        receive, business, send = AsyncMock(), AsyncMock(), AsyncMock()
        with patch.object(audit_http, 'get_settings', return_value=SimpleNamespace(metadata_backend='postgres')), \
             patch.object(audit_call, 'get_settings', return_value=SimpleNamespace(metadata_backend='postgres')), \
             patch.object(audit_call, 'make_call', return_value=SimpleNamespace(call_id='fixed')), \
             patch.object(audit_call, 'admit', AsyncMock(side_effect=MetadataUnavailable('offline'))):
            await audit_http.audited_response({'method': 'POST', 'path': '/admin/api/pki/issue'}, receive, send, business)
        business.assert_not_awaited()
        receive.assert_not_awaited()
        assert send.call_args_list[0].args[0]['status'] == 503

    asyncio.run(exercise())


@pytest.mark.parametrize('method,path,expected', [
    ('GET', '/admin/api/audit', None),
    ('GET', '/admin/api/logs', None),
    ('GET', '/admin/api/whoami', None),
    ('POST', '/admin/api/metadata-operator/install', None),
    ('POST', '/admin/api/unknown', None),
    ('POST', '/admin/api/tokens/purge', ('token_purge', '')),
    ('PUT', '/admin/api/tokens/prefix', ('token_update', '')),
    ('DELETE', '/admin/api/mission-bindings/tenant', ('mission_binding_delete', '')),
    ('POST', '/admin/api/pki/ca/rotate', ('pki_ca_rotate_intermediate', '')),
    ('POST', '/admin/api/vaults/coffer-a/secrets', ('secret_write', 'coffer-a')),
    ('DELETE', '/admin/api/vaults/coffer-a/secrets/private/password', ('secret_delete', 'coffer-a')),
    ('GET', '/admin/api/vaults/coffer-a/secrets/private/password', ('secret_read', 'coffer-a')),
    ('POST', '/admin/api/vaults/coffer-a/ssh/sign', ('ssh_sign_key', 'coffer-a')),
])
def test_routes_only_record_closed_tool_and_coffer_never_secret_path(method, path, expected):
    assert audit_http.route({'method': method, 'path': path}) == expected
    if expected:
        assert expected[0] in TOOLS
        assert 'private/password' not in repr(expected)
