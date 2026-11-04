"""Vrais callsites wrap/PKI ; seuls transports Bao et PG sont remplacés."""
import asyncio
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_vault.storage import admission, audit_call, audit_pg, stores
from mcp_vault.storage.postgres import MetadataUnavailable, MutationUnknown, request_facts
from mcp_vault.vault import pki_ca, wrapping
from tests.conftest import admin_auth_context
from tests.test_wrap import _make_registry


@pytest.mark.parametrize('audit_error', [MetadataUnavailable('offline'), MutationUnknown('step')])
@pytest.mark.parametrize('compensation', ['confirmed', 'audit_unknown', 'transport_unknown'])
def test_mcp_wrap_keeps_private_accessor_for_emergency_compensation(audit_error, compensation, caplog):
    from mcp_vault import server

    async def exercise():
        loop_thread = threading.get_ident()
        call = SimpleNamespace(call_id='audit-wrap')
        registry = _make_registry()
        registry.mark_active = MagicMock(wraps=registry.mark_active)
        client = MagicMock()
        client.read.return_value = {'wrap_info': {'token': 'PRIVATE-WRAP-CANARY', 'accessor': 'PRIVATE-ACCESSOR-CANARY'}}
        if compensation == 'transport_unknown':
            client.auth.token.revoke_accessor.side_effect = OSError('lost transport')
        observations = []

        def record(conn, observed, phase, outcome, **correlation):
            assert observed is call
            assert threading.get_ident() != loop_thread
            observations.append((phase, outcome, correlation))

        def write(observed, deadline, operation):
            operation(None)
            if len(observations) == 1 or compensation == 'audit_unknown':
                raise audit_error

        facts = request_facts.set({'owners': {}})
        terminal = AsyncMock()
        try:
            with admin_auth_context(), \
                 patch.object(audit_call, 'get_settings', return_value=SimpleNamespace(metadata_backend='postgres')), \
                 patch.object(admission, 'get_settings', return_value=SimpleNamespace(metadata_backend='postgres')), \
                 patch.object(audit_call, 'make_call', return_value=call), \
                 patch.object(audit_call, 'admit', AsyncMock()), \
                 patch.object(audit_call, 'append', terminal), \
                 patch.object(audit_pg, '_write', write), patch.object(audit_pg, 'record_step', record), \
                 patch.object(server, 'settings', SimpleNamespace(enforce_mission_token_validation=False)), \
                 patch.object(wrapping, '_get_config', return_value=SimpleNamespace(metadata_backend='postgres', openbao_addr='http://bao')), \
                 patch.object(wrapping, '_get_client', return_value=client), \
                 patch.object(wrapping, 'get_wrap_registry', return_value=registry), \
                 patch.object(stores, 'wrap_for_worker', side_effect=lambda fn, args, kwargs: fn(*args, **kwargs)):
                # Le worker, son verrou, les ContextVars et bao_step_sync sont réels.
                # Le registre en mémoire remplace uniquement le stockage métier PG.
                result = await server.secret_wrap('coffer-a', 'connection', 'mission-a', 'operation-a')
            client.read.assert_called_once_with('coffer-a/data/connection', wrap_ttl='300s')
            client.auth.token.revoke_accessor.assert_called_once_with(accessor='PRIVATE-ACCESSOR-CANARY')
            registry.mark_active.assert_not_called()
            assert result['audit_status'] == 'unknown' and result['replay_allowed'] is False
            assert result['business_outcome'] == 'unknown'
            assert terminal.call_args.args[1:] == ('public_terminal', 'unknown')
            assert [o[:2] for o in observations] == [
                ('bao_step_outcome', 'confirmed'),
                ('compensation_outcome', 'unknown' if compensation == 'transport_unknown' else 'confirmed')]
            assert 'PRIVATE-' not in repr((result, observations)) + caplog.text
            assert audit_pg.current_audit_call.get() is None
            assert not registry.refresh_lock.locked()
        finally:
            request_facts.reset(facts)

    asyncio.run(exercise())


def test_pki_setup_cancel_drains_real_helper_and_keeps_lock_and_audit_context():
    async def exercise():
        loop_thread = threading.get_ident()
        entered, release, ended = threading.Event(), threading.Event(), threading.Event()
        call = SimpleNamespace(call_id='audit-pki')
        lock = asyncio.Lock()
        observed = []
        client = MagicMock()

        def read(path):
            assert path.endswith('/config/acme')
            assert threading.get_ident() != loop_thread
            assert audit_pg.current_audit_call.get() is call
            entered.set()
            assert release.wait(3), 'test worker not released'
            ended.set()
            return None

        def record(conn, value, phase, outcome, **_):
            assert ended.is_set() and lock.locked()
            assert value is call and audit_pg.current_audit_call.get() is call
            assert threading.get_ident() != loop_thread
            observed.append((phase, outcome))

        client.read.side_effect = read
        terminal = AsyncMock()
        try:
            with patch.object(pki_ca, '_get_hvac_client', return_value=client), \
                 patch.object(pki_ca, '_get_setup_lock', return_value=lock), \
                 patch.object(pki_ca, '_base_url', return_value='https://vault'), \
                 patch.object(audit_call, 'get_settings', return_value=SimpleNamespace(metadata_backend='postgres')), \
                 patch.object(audit_call, 'make_call', return_value=call), \
                 patch.object(audit_call, 'admit', AsyncMock()), patch.object(audit_call, 'append', terminal), \
                 patch.object(audit_pg, '_write', side_effect=lambda value, deadline, fn: fn(None)), \
                 patch.object(audit_pg, 'record_step', record):
                task = asyncio.create_task(audit_call.audited_call(pki_ca.setup_pki_ca)())
                for _ in range(200):
                    if entered.is_set():
                        break
                    await asyncio.sleep(.005)
                assert entered.is_set() and lock.locked()
                task.cancel()
                await asyncio.sleep(.01)
                assert not task.done() and lock.locked() and not ended.is_set()
                terminal.assert_not_awaited()
                release.set()
                with pytest.raises(asyncio.CancelledError):
                    await task
                assert ended.is_set() and not lock.locked()
                assert observed == [('bao_step_outcome', 'confirmed')]
                client.sys.enable_secrets_engine.assert_not_called()
                client.write.assert_not_called()
                assert terminal.call_args.args[1:] == ('public_terminal', 'unknown')
        finally:
            release.set()

    asyncio.run(exercise())


def test_selected_accessor_compensation_runs_after_previous_unknown_audit():
    client = MagicMock()
    registry = MagicMock()
    registry.mark_entries_revoked.return_value = (0, True)
    effects = {'dispatched': True, 'steps': 1, 'confirmed': 1, 'audit_unknown': True}
    call_marker = audit_pg.current_audit_call.set(SimpleNamespace(call_id='audit-wrap'))
    effect_marker = audit_pg.current_audit_effects.set(effects)
    phases = []
    try:
        with patch.object(wrapping, '_get_client', return_value=client), \
             patch.object(audit_pg, '_write', side_effect=lambda call, deadline, fn: fn(None)), \
             patch.object(audit_pg, 'record_step', side_effect=lambda conn, call, phase, outcome, **kw: phases.append((phase, outcome))):
            result = wrapping._revoke_accessor_selected(registry, 'private-accessor', [])
        client.auth.token.revoke_accessor.assert_called_once_with(accessor='private-accessor')
        assert result['status'] == 'ok' and result['state'] == 'revoked'
        assert phases == [('compensation_outcome', 'confirmed')]
        assert effects['audit_unknown'] is True
    finally:
        audit_pg.current_audit_effects.reset(effect_marker)
        audit_pg.current_audit_call.reset(call_marker)


def test_pki_status_real_sync_helper_failure_is_unknown_not_not_initialized():
    async def exercise():
        client = MagicMock()
        client.sys.list_mounted_secrets_engines.return_value = {'data': {'pki/': {}, 'pki_int/': {}}}
        with patch.object(pki_ca, '_get_hvac_client', return_value=client), \
             patch.object(audit_call, 'get_settings', return_value=SimpleNamespace(metadata_backend='postgres')), \
             patch.object(audit_call, 'make_call', return_value=SimpleNamespace(call_id='audit-pki')), \
             patch.object(audit_call, 'admit', AsyncMock()), patch.object(audit_call, 'append', AsyncMock()), \
             patch.object(audit_pg, '_write', side_effect=MutationUnknown('step')):
            result = await audit_call.audited_call(pki_ca.get_pki_status)()
        assert result['error_type'] == 'audit_step_unconfirmed'
        assert result['business_outcome'] == 'confirmed' and result['replay_allowed'] is False
        client.sys.list_mounted_secrets_engines.assert_called_once()
        client.list.assert_not_called()

    asyncio.run(exercise())
