"""Intégrité de progression et bornes, pas une preuve PG ou d'authentification HTTP."""
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest

from mcp_vault.storage.audit_contract import AuditScope
from mcp_vault.storage.audit_cursor import Cursors, context_fingerprint
from mcp_vault.storage.audit_read import Cursor, ExportIncomplete

C = "a"*64
PAGE = Cursor(1, 3, 2, 3, 2)


def test_cursor_is_one_use_opaque_and_unknown_or_forged_is_incomplete():
    registry = Cursors()
    key = registry.put(C, PAGE)
    assert len(key) == 43
    assert registry.take(key, C) == PAGE
    for invalid in (key, "forged", "b"*43):
        with pytest.raises(ExportIncomplete):
            registry.take(invalid, C)


def test_scope_or_live_identity_revision_change_cannot_continue_export():
    a, b = AuditScope("instance", frozenset({"a"})), AuditScope("instance", frozenset({"b"}))
    first = context_fingerprint(a, {"actor_hash": "a"*64, "actor_revision": 1}, {})
    for context in (context_fingerprint(b, {"actor_hash": "a"*64, "actor_revision": 1}, {}),
                    context_fingerprint(a, {"actor_hash": "a"*64, "actor_revision": 2}, {}),
                    context_fingerprint(a, {"actor_hash": "a"*64, "actor_revision": 1}, {"tool": "secret_read"})):
        registry = Cursors()
        key = registry.put(first, PAGE)
        with pytest.raises(ExportIncomplete):
            registry.take(key, context)


def test_expiry_boundary_and_capacity_are_bounded_without_fallback():
    registry = Cursors()
    with patch("mcp_vault.storage.audit_cursor.time.monotonic", return_value=0):
        keys = [registry.put(C, PAGE) for _ in range(128)]
        with pytest.raises(ExportIncomplete, match="capacity"):
            registry.put(C, PAGE)
    with patch("mcp_vault.storage.audit_cursor.time.monotonic", return_value=120):
        with pytest.raises(ExportIncomplete):
            registry.take(keys[0], C)
        assert len(registry._entries) == 0
        assert registry.put(C, PAGE)


def test_two_consumers_cannot_both_advance_the_same_cursor():
    registry = Cursors()
    key = registry.put(C, PAGE)
    def take():
        try:
            return registry.take(key, C)
        except ExportIncomplete:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        result = list(pool.map(lambda _: take(), range(2)))
    assert result.count(PAGE) == 1
    assert result.count(None) == 1


def test_restart_or_other_process_has_no_cursor_fallback():
    original = Cursors()
    key = original.put(C, PAGE)
    with pytest.raises(ExportIncomplete):
        Cursors().take(key, C)
