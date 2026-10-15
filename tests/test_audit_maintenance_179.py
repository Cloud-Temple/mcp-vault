"""Expiration publique bornée, identité distincte et reçu après COMMIT seulement."""
import asyncio
import json
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_vault.storage import audit_maintenance as maintenance, operator
from mcp_vault.storage.postgres import MetadataUnavailable, MutationUnknown
from mcp_vault.storage.reader import MetadataAbsent


@pytest.mark.parametrize('body', [None, [], {'batch': True}, {'batch': 501}, {'batch': 0},
    {'dry_run': 'false'}, {'dry_run': False}, {'dry_run': False, 'confirm': 'yes'}, {'unknown': 1}])
def test_bad_expiration_never_opens_connection(body):
    with patch.object(maintenance, 'connection') as connect:
        with pytest.raises(ValueError):
            maintenance.expire(body)
    connect.assert_not_called()


@pytest.mark.parametrize('dry_run,commit_fails,close_fails', [
    (True, False, False), (False, False, False), (False, True, False), (False, False, True)])
def test_expiration_one_call_receipt_only_after_commit(dry_run, commit_fails, close_fails):
    order = []
    result = {'calls': 2, 'events': 5, 'dry_run': dry_run, 'has_more': False,
              'receipt': None if dry_run else 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'}

    class Conn:
        def add_notice_handler(self, handler):
            self.notice = handler

        def execute(self, query, params=None):
            order.append((query, params))
            if query == 'COMMIT' and commit_fails:
                raise MetadataUnavailable('lost ack')
            return SimpleNamespace(fetchone=lambda: {'result': result})

    @contextmanager
    def app_connection():
        order.append('verify-app-and-maintenance-acl')
        yield

    @contextmanager
    def maint_connection():
        order.append('distinct-maintenance-login')
        yield Conn()
        if close_fails:
            raise MetadataUnavailable('close_unconfirmed')

    with patch.object(maintenance, 'connection', app_connection), \
         patch.object(maintenance, 'maintenance_connection', maint_connection), \
         patch.object(maintenance, 'get_settings', return_value=SimpleNamespace(metadata_backend='postgres', metadata_instance_id='fixture')), \
         patch.object(maintenance, 'validate_durability', side_effect=lambda conn: order.append('remote_apply')):
        body = {'dry_run': dry_run, 'confirm': 'audit-expire'}
        if commit_fails or close_fails:
            with pytest.raises(MutationUnknown):
                maintenance.expire(body)
        else:
            assert maintenance.expire(body) == {'status': 'ok', 'confirmed': True, **result}
    assert order[:2] == ['verify-app-and-maintenance-acl', 'distinct-maintenance-login']
    assert order[-1] == ('COMMIT', None)
    assert [item for item in order if isinstance(item, tuple) and 'audit_expire(' in item[0]] == [
        ('SELECT vault_metadata.audit_expire(%s,%s,%s) AS result', ('fixture', 100, dry_run))]


def test_expiration_notice_rolls_back_without_commit():
    conn = MagicMock()
    def execute(query, *args):
        if 'audit_expire(' in query:
            conn.add_notice_handler.call_args.args[0](SimpleNamespace(sqlstate='01000'))
        return SimpleNamespace(fetchone=lambda: {'result': {
            'calls': 0, 'events': 0, 'dry_run': True, 'has_more': False, 'receipt': None}})
    conn.execute.side_effect = execute

    @contextmanager
    def connected():
        yield conn

    with patch.object(maintenance, 'connection', connected), \
         patch.object(maintenance, 'maintenance_connection', connected), \
         patch.object(maintenance, 'get_settings', return_value=SimpleNamespace(metadata_backend='postgres', metadata_instance_id='fixture')), \
         patch.object(maintenance, 'validate_durability'):
        with pytest.raises(MetadataUnavailable):
            maintenance.expire({})
    statements = [c.args[0] for c in conn.execute.call_args_list]
    assert statements[-1] == 'ROLLBACK' and 'COMMIT' not in statements


@pytest.mark.parametrize('present', ['absent', 'identical', 'different'])
def test_maintenance_credential_cas_never_overwrites_existing_value(present):
    settings = SimpleNamespace(metadata_pg_database='vault_domain', audit_maintenance_role='maint',
        metadata_pg_vault_id='technical', audit_maintenance_secret_path='sql/audit-maintenance')
    value = {'host': 'postgres', 'port': '5432', 'dbname': 'vault_domain', 'user': 'maint', 'password': 'private'}
    observed = dict(value, password='different') if present == 'different' else value
    with patch.object(maintenance, 'get_settings', return_value=settings), \
         patch.object(maintenance, 'exact_kv', side_effect=MetadataAbsent('missing') if present == 'absent' else None,
                      return_value=observed), patch.object(operator, 'bao_request') as write:
        if present == 'different':
            with pytest.raises(MetadataUnavailable):
                maintenance.install_credential(value)
        else:
            assert maintenance.install_credential(value)['status'] == 'ok'
    if present == 'absent':
        write.assert_called_once_with('POST', 'technical/data/sql/audit-maintenance',
            {'options': {'cas': 0}, 'data': value})
    else:
        write.assert_not_called()


@pytest.mark.parametrize('wrong_identity,unsafe', [(False, False), (True, False), (False, True)])
def test_fresh_maintenance_connection_enforces_tls_identity_and_safe_login(wrong_identity, unsafe):
    settings = SimpleNamespace(metadata_pg_database='domain', audit_maintenance_role='maint',
        metadata_pg_vault_id='technical', audit_maintenance_secret_path='sql/audit-maintenance',
        metadata_pg_ca_file='/tls/ca.crt', metadata_sql_connect_seconds=3,
        metadata_sql_statement_seconds=5, metadata_sql_lock_seconds=2)
    credential = {'host': 'pg1,pg2,pg3', 'port': '5432', 'dbname': 'domain', 'user': 'maint', 'password': 'private'}
    raw = MagicMock()

    def execute(query, *args, **kwargs):
        if 'current_database()' in query:
            value = {'db': 'domain', 'role': 'owner' if wrong_identity else 'maint'}
        else:
            value = {'allowed': not unsafe}
        return SimpleNamespace(fetchone=lambda: value)

    raw.execute.side_effect = execute
    limiter = MagicMock()
    with patch.object(maintenance, 'get_settings', return_value=settings), \
         patch.object(maintenance, 'exact_kv', return_value=credential) as read, \
         patch.object(maintenance, 'slots', return_value=limiter), \
         patch('psycopg.connect', return_value=raw) as connect:
        if wrong_identity or unsafe:
            with pytest.raises(MetadataUnavailable):
                with maintenance.maintenance_connection():
                    pytest.fail('unsafe connection yielded')
        else:
            with maintenance.maintenance_connection() as conn:
                assert conn.conn is raw
    read.assert_called_once_with('technical', 'sql/audit-maintenance')
    assert connect.call_args.kwargs['sslmode'] == 'verify-full'
    assert connect.call_args.kwargs['sslrootcert'] == '/tls/ca.crt'
    assert connect.call_args.kwargs['target_session_attrs'] == 'read-write'
    assert connect.call_args.kwargs['user'] == 'maint'
    raw.close.assert_called_once()
    limiter.acquire.assert_called_once_with(timeout=1)
    limiter.release.assert_called_once()


@pytest.mark.parametrize('change', [{'user': 'app'}, {'dbname': 'neighbor'}, {'port': '0'}, {'extra': 'data'}])
def test_wrong_maintenance_credential_is_rejected_before_native_bao(change):
    settings = SimpleNamespace(metadata_pg_database='domain', audit_maintenance_role='maint')
    value = {'host': 'pg', 'port': '5432', 'dbname': 'domain', 'user': 'maint', 'password': 'private'} | change
    with patch.object(maintenance, 'get_settings', return_value=settings), patch.object(maintenance, 'exact_kv') as read:
        with pytest.raises(ValueError):
            maintenance.install_credential(value)
    read.assert_not_called()


@pytest.mark.parametrize('mode,key,expected', [('install', 'bootstrap', 200), ('disabled', 'bootstrap', 403),
    ('restore', 'bootstrap', 403), ('install', 'scoped-app', 401)])
def test_public_operator_expiration_requires_bootstrap_and_install_mode(mode, key, expected):
    async def exercise():
        settings = SimpleNamespace(admin_bootstrap_key='bootstrap', metadata_operator_mode=mode)
        sent = []
        with patch.object(operator, 'get_settings', return_value=settings), \
             patch.object(operator, 'offload', AsyncMock(return_value={'status': 'ok', 'confirmed': True})) as dispatch:
            await operator.handle_operator({'method': 'POST', 'path': '/admin/api/metadata-operator/audit-expire',
                'headers': [(b'authorization', ('Bearer '+key).encode())]},
                AsyncMock(return_value={'type': 'http.request', 'body': b'{}'}), AsyncMock(side_effect=sent.append))
        assert sent[0]['status'] == expected
        if expected == 200:
            dispatch.assert_awaited_once_with(operator.action, 'audit-expire', {})
            assert json.loads(sent[1]['body'])['confirmed'] is True
        else:
            dispatch.assert_not_awaited()

    asyncio.run(exercise())
