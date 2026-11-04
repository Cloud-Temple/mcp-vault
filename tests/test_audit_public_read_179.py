"""Seams publiques lecture, dépendances PG doublées ; pas une qualification native."""

import asyncio
import hashlib
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest

from mcp_vault.auth.context import current_token_info
from mcp_vault.storage import audit_service, admission
from mcp_vault.storage.audit_read import normalize_filters
from mcp_vault.storage.postgres import MetadataUnavailable, request_facts

IDENTITY = {"auth_type": "token", "permissions": ["read"], "allowed_resources": ["coffer-a"],
            "policy_id": "auditor", "client_name": "reader", "revoked": False}
POLICY = {"policy_id": "auditor", "allowed_tools": ["audit_log"], "denied_tools": [],
          "path_rules": [{"vault_pattern": "coffer-a", "permissions": ["read"], "allowed_paths": []}]}
FACTS = {"actor_hash": "a"*64, "actor_revision": 1, "policy_revisions": {"auditor": 1}}
PAGE = {"entries": [], "total": 0, "stats": {"total": 0}, "complete": True, "cursor": None}
SETTINGS = SimpleNamespace(metadata_backend="postgres", metadata_instance_id="fixture", admin_bootstrap_key="x"*64)


@pytest.mark.parametrize("filters", [{"extra": "bad"}, {"status": "CANARY"}, {"since": "bad"},
                                     {"client": "free-name"}, {"tool": "secret_*evil"}])
def test_invalid_filters_do_not_become_sql_scope(filters):
    with pytest.raises(ValueError):
        normalize_filters(filters)


def test_reader_requires_explicit_policy_and_keeps_coffer_intersection():
    async def exercise():
        token = current_token_info.set(IDENTITY)
        facts = request_facts.set(FACTS)
        try:
            store = Mock(get=Mock(return_value=POLICY))
            worker = AsyncMock(return_value=PAGE)
            with patch.object(audit_service, "get_settings", return_value=SETTINGS), \
                 patch.object(audit_service, "get_policy_store", return_value=store), \
                 patch.object(audit_service, "offload", worker):
                result = await audit_service.query()
                assert result["status"] == "ok" and result["total"] == 0
                assert worker.call_args.args[1].coffers == frozenset({"coffer-a"})
                store.get.return_value = None
                assert (await audit_service.query())["error_type"] == "access_denied"
                assert worker.await_count == 1
        finally:
            request_facts.reset(facts)
            current_token_info.reset(token)
    asyncio.run(exercise())


def test_database_failure_is_unavailable_without_backend_text_or_empty_success():
    async def exercise():
        token = current_token_info.set(IDENTITY)
        facts = request_facts.set(FACTS)
        try:
            with patch.object(audit_service, "get_settings", return_value=SETTINGS), \
                 patch.object(audit_service, "get_policy_store", return_value=Mock(get=Mock(return_value=POLICY))), \
                 patch.object(audit_service, "offload", AsyncMock(side_effect=MetadataUnavailable("PRIVATE-CANARY"))):
                result = await audit_service.query()
                assert result["error_type"] == "audit_unavailable" and result["complete"] is False
                assert "entries" not in result and "PRIVATE-CANARY" not in json.dumps(result)
        finally:
            request_facts.reset(facts)
            current_token_info.reset(token)
    asyncio.run(exercise())


def test_http_jsonl_is_finite_scoped_and_ends_with_explicit_page_marker():
    from mcp_vault.admin import api
    async def exercise():
        async def app(scope, receive, send):
            await api.handle_admin_api(scope, receive, send, None)
        async def admit(raw):
            if raw != "opaque-test":
                raise PermissionError()
            return FACTS
        store = Mock()
        store.get_by_hash.side_effect = lambda h: IDENTITY if h == hashlib.sha256(b"opaque-test").hexdigest() else None
        result = {"status": "ok", "entries": [{"client": "tok_"+"a"*16, "vault_id": "coffer-a"}],
                  "total": 2, "count": 1, "complete": False, "cursor": "opaque-next", "stats": {"total": 2}}
        with patch.object(api, "get_settings", return_value=SETTINGS), \
             patch.object(api, "get_token_store", return_value=store), \
             patch.object(admission, "admit", admit), \
             patch.object(audit_service, "query", AsyncMock(return_value=result)) as query:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://unit") as http:
                r = await http.get('/admin/api/audit?format=jsonl&limit=1&vault_id=coffer-a',
                                   headers={"Authorization": "Bearer opaque-test"})
                assert r.status_code == 200 and r.headers['cache-control'] == 'no-store'
                rows = [json.loads(line) for line in r.text.splitlines()]
                assert rows[0]['record_type'] == 'event'
                assert rows[-1]['record_type'] == 'page' and rows[-1]['complete'] is False
                assert query.call_args.kwargs['filters'] == {'vault_id': 'coffer-a'}
                denied = await http.get('/admin/api/logs', headers={"Authorization": "Bearer opaque-test"})
                assert denied.status_code == 403
                bad = await http.get('/admin/api/audit?limit=1&limit=2', headers={"Authorization": "Bearer opaque-test"})
                assert bad.status_code == 400
                assert query.await_count == 1
    asyncio.run(exercise())


def test_last_page_failure_never_claims_complete_or_reuses_consumed_cursor():
    from mcp_vault.storage.audit_read import Cursor
    async def exercise():
        token = current_token_info.set(IDENTITY)
        facts = request_facts.set(FACTS)
        first = {"entries": [{"vault_id": "coffer-a"}], "total": 2, "stats": {"total": 2},
                 "complete": False, "cursor": Cursor(1, 2, 2, 2, 1)}
        try:
            worker = AsyncMock(side_effect=[first, MetadataUnavailable("PRIVATE-LAST-PAGE")])
            with patch.object(audit_service, "get_settings", return_value=SETTINGS), \
                 patch.object(audit_service, "get_policy_store", return_value=Mock(get=Mock(return_value=POLICY))), \
                 patch.object(audit_service, "offload", worker):
                page = await audit_service.query(limit=1)
                assert page["complete"] is False and page["cursor"]
                final = await audit_service.query(limit=1, cursor=page["cursor"])
                assert final["complete"] is False and final["error_type"] == "audit_unavailable"
                assert "entries" not in final and "PRIVATE-LAST-PAGE" not in json.dumps(final)
                replay = await audit_service.query(cursor=page["cursor"])
                assert replay["error_type"] == "export_incomplete"
                assert worker.await_count == 2
        finally:
            request_facts.reset(facts)
            current_token_info.reset(token)
    asyncio.run(exercise())


def test_postgres_profile_never_initializes_or_reads_jsonl_fallback(tmp_path, monkeypatch):
    from mcp_vault import audit
    monkeypatch.setattr(audit, "get_settings", lambda: SimpleNamespace(metadata_backend="postgres",
        openbao_data_dir=str(tmp_path/'file')))
    monkeypatch.setattr(audit, "_audit_store", None)
    audit.init_audit_store()
    assert audit.get_audit_store() is None
    assert not (tmp_path/'logs').exists()
