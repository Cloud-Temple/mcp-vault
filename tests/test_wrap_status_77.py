#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests #77 — secret_wrap_status : consultation d'état d'un wrap en LECTURE SEULE.

Le bug #77 : secret_wrap_lookup RÉVOQUE (compensation orpheline #74) ; consulter
l'état via ce tool détruit le wrap. Le fix ajoute secret_wrap_status, qui LIT
l'état sans effet de bord. Ces tests couvrent (sans OpenBao) :
  - la classification de chaque état du registre ;
  - la NON-mutation de l'entrée (référence vivante) et l'absence d'écriture/révocation ;
  - la non-exposition de l'accessor / wrap_token ;
  - le contrat minimal (expires_at seulement pour les états vivants) ;
  - l'outil MCP : admin-only + validation operation_id AVANT tout accès registre.

L'intégration OpenBao réelle (status ne détruit pas le wrap → consommable après)
est dans tests/test_wrap_status_openbao_77.py.
"""
import copy
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("MCP_SERVER_NAME", "mcp-vault-test")
os.environ.setdefault("ADMIN_BOOTSTRAP_KEY", "Test-Bootstrap-Key-2026-Pour-Tests!!")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def _run(coro):
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


def _entry(status, op="op-1", accessor="ACC-SECRET-XYZ",
           expires="2099-01-01T00:00:00+00:00"):
    """Entrée de registre réaliste (mêmes clés que register_pending/mark_active)."""
    return {
        "operation_id": op, "mission_id": "m1", "vault_id": "v", "secret_path": "web/x",
        "accessor": accessor, "status": status, "expires_at": expires,
        "created_at": "2026-01-01T00:00:00+00:00", "tenant_id": "", "expected_aud": "",
    }


def _registry_with(entries, last_load_ok=True):
    reg = MagicMock()
    reg.find_by_operation_id.return_value = entries
    reg._last_load_ok = last_load_ok
    return reg


# ── Classification des états ─────────────────────────────────────────────────

def test_status_maps_each_known_state():
    from mcp_vault.vault import wrapping as w
    for st in ("pending", "active", "consuming", "consumed", "revoked", "failed"):
        reg = _registry_with([_entry(st)])
        with patch.object(w, "get_wrap_registry", return_value=reg):
            res = _run(w.status_by_operation_id("op-1"))
        assert res["status"] == "ok" and res["state"] == st, f"{st} → {res}"


def test_status_not_found():
    from mcp_vault.vault import wrapping as w
    with patch.object(w, "get_wrap_registry", return_value=_registry_with([])):
        res = _run(w.status_by_operation_id("op-none"))
    assert res["status"] == "ok" and res["state"] == "not_found"


def test_status_ambiguous_when_multiple_entries():
    from mcp_vault.vault import wrapping as w
    reg = _registry_with([_entry("active"), _entry("revoked")])
    with patch.object(w, "get_wrap_registry", return_value=reg):
        res = _run(w.status_by_operation_id("op-1"))
    assert res["state"] == "ambiguous"
    # ne divulgue pas le compte / l'activité interne
    assert "entries_found" not in res and "count" not in res


def test_status_registry_inconsistent_on_unknown_status():
    from mcp_vault.vault import wrapping as w
    reg = _registry_with([_entry("weird_unknown_status")])
    with patch.object(w, "get_wrap_registry", return_value=reg):
        res = _run(w.status_by_operation_id("op-1"))
    assert res["state"] == "registry_inconsistent"


def test_status_backend_unavailable_when_no_registry():
    from mcp_vault.vault import wrapping as w
    with patch.object(w, "get_wrap_registry", return_value=None):
        res = _run(w.status_by_operation_id("op-1"))
    assert res["status"] == "error" and res.get("error_type") == "backend_unavailable"


# ── Robustesse (findings Codex R-diff) : panne S3 & registre corrompu ────────

def test_status_backend_unavailable_on_s3_refresh_failure():
    """
    Panne S3 effective (dernier load échoué → `_last_load_ok=False`) : la
    consultation NE doit PAS présenter un instantané périmé comme fiable — elle
    remonte `backend_unavailable` plutôt qu'un not_found/active trompeur.
    """
    from mcp_vault.vault import wrapping as w
    reg = _registry_with([_entry("active")], last_load_ok=False)
    with patch.object(w, "get_wrap_registry", return_value=reg):
        res = _run(w.status_by_operation_id("op-1"))
    assert res["status"] == "error" and res.get("error_type") == "backend_unavailable"


def test_status_registry_inconsistent_on_find_exception():
    """Une exception de find_by_operation_id (registre corrompu) → registry_inconsistent, pas d'exception MCP."""
    from mcp_vault.vault import wrapping as w
    reg = MagicMock()
    reg._last_load_ok = True
    reg.find_by_operation_id.side_effect = KeyError("operation_id")
    with patch.object(w, "get_wrap_registry", return_value=reg):
        res = _run(w.status_by_operation_id("op-1"))
    assert res["status"] == "ok" and res["state"] == "registry_inconsistent"


def test_status_registry_inconsistent_on_non_dict_entry():
    from mcp_vault.vault import wrapping as w
    with patch.object(w, "get_wrap_registry", return_value=_registry_with([None])):
        res = _run(w.status_by_operation_id("op-1"))
    assert res["state"] == "registry_inconsistent"


def test_status_survives_malformed_entry_via_real_registry():
    """
    Chemin réel : une entrée `{}` dans le registre fait lever find_by_operation_id
    (KeyError 'operation_id'). status doit renvoyer registry_inconsistent sans crasher.
    """
    from mcp_vault.vault import wrapping as w
    reg = w.WrapRegistry(MagicMock())
    reg._wraps = [{}]          # entrée corrompue (pas de clé operation_id)
    reg._cache_time = 9e18     # cache "frais" → pas de refresh S3
    reg._last_load_ok = True
    with patch.object(w, "get_wrap_registry", return_value=reg):
        res = _run(w.status_by_operation_id("op-1"))
    assert res["status"] == "ok" and res["state"] == "registry_inconsistent"


def test_status_registry_inconsistent_on_non_str_status():
    """
    Un `status` non-str (liste/dict NON hashable, int, None) ne doit pas faire
    lever `in frozenset` (TypeError) — registre corrompu → registry_inconsistent.
    """
    from mcp_vault.vault import wrapping as w
    for bad in ([], {}, 123, None):
        entry = _entry("active")
        entry["status"] = bad
        with patch.object(w, "get_wrap_registry", return_value=_registry_with([entry])):
            res = _run(w.status_by_operation_id("op-1"))
        assert res["status"] == "ok" and res["state"] == "registry_inconsistent", f"{bad!r} → {res}"


def test_registry_last_load_ok_recovers_after_successful_save():
    """
    Reprise après panne S3 : `_last_load_ok=False`, puis un `_save()` réussi (S3
    revenu) doit remettre le flag à True — sinon la consultation d'état resterait
    bloquée en backend_unavailable malgré un cache persisté et fiable.
    """
    from mcp_vault.vault import wrapping as w
    reg = w.WrapRegistry(MagicMock())
    reg._last_load_ok = False                              # panne S3 antérieure
    reg._get_s3_data = MagicMock(return_value=MagicMock())  # S3 revenu (put_object OK)
    assert reg._save() is True
    assert reg._last_load_ok is True, "un save réussi doit lever le flag de panne S3"


# ── NON-COMPLAISANCE : lecture pure (pas de mutation, pas de fuite) ──────────

def test_status_never_leaks_accessor_or_token():
    from mcp_vault.vault import wrapping as w
    reg = _registry_with([_entry("active", accessor="ACC-SECRET-XYZ")])
    with patch.object(w, "get_wrap_registry", return_value=reg):
        res = _run(w.status_by_operation_id("op-1"))
    assert "accessor" not in res and "wrap_token" not in res
    assert "ACC-SECRET-XYZ" not in str(res), "fuite de l'accessor dans la sortie !"


def test_status_does_not_mutate_registry_entry():
    """
    NON-COMPLAISANCE clé (finding Codex) : find_by_operation_id renvoie des
    RÉFÉRENCES vivantes. status_by_operation_id ne doit JAMAIS les muter (sinon
    corruption mémoire + S3 au prochain _save), ni révoquer, ni écrire.
    """
    from mcp_vault.vault import wrapping as w
    entry = _entry("active")
    before = copy.deepcopy(entry)
    reg = _registry_with([entry])
    with patch.object(w, "get_wrap_registry", return_value=reg):
        res = _run(w.status_by_operation_id("op-1"))
    # entrée intacte
    assert entry == before, "status a muté l'entrée du registre !"
    # aucune écriture ni révocation déclenchée
    reg._save.assert_not_called()
    reg.mark_revoked.assert_not_called()
    reg.mark_consumed.assert_not_called()
    reg.try_mark_consuming.assert_not_called()
    # projection NEUVE : altérer le résultat ne touche pas l'entrée
    res["state"] = "TAMPERED"
    assert entry["status"] == "active"


def test_status_expires_at_only_for_live_states():
    from mcp_vault.vault import wrapping as w
    for st in ("pending", "active", "consuming"):
        with patch.object(w, "get_wrap_registry", return_value=_registry_with([_entry(st)])):
            assert "expires_at" in _run(w.status_by_operation_id("op-1")), f"{st} devrait exposer expires_at"
    for st in ("consumed", "revoked", "failed"):
        with patch.object(w, "get_wrap_registry", return_value=_registry_with([_entry(st)])):
            assert "expires_at" not in _run(w.status_by_operation_id("op-1")), f"{st} ne devrait pas exposer expires_at"


# ── Outil MCP secret_wrap_status : autz + validation ─────────────────────────

def test_mcp_secret_wrap_status_admin_only():
    """Sans permission admin → rejet, sans jamais toucher le registre."""
    from mcp_vault.server import secret_wrap_status
    deny = {"status": "error", "message": "Permission admin requise"}
    with patch("mcp_vault.auth.context.check_admin_permission", return_value=deny), \
         patch("mcp_vault.vault.wrapping.status_by_operation_id", new=AsyncMock()) as mock_status:
        res = _run(secret_wrap_status("op-1"))
    assert res["status"] == "error"
    mock_status.assert_not_called()


def test_mcp_secret_wrap_status_rejects_invalid_operation_id():
    """operation_id invalide (newline) → rejet AVANT tout accès registre/audit (#78/D6)."""
    from mcp_vault.server import secret_wrap_status
    with patch("mcp_vault.auth.context.check_admin_permission", return_value=None), \
         patch("mcp_vault.vault.wrapping.status_by_operation_id", new=AsyncMock()) as mock_status:
        res = _run(secret_wrap_status("bad\nop"))
    assert res["status"] == "error" and res.get("error_type") == "invalid_input"
    mock_status.assert_not_called()


def test_mcp_secret_wrap_status_happy_path_calls_core():
    from mcp_vault.server import secret_wrap_status
    core_ret = {"status": "ok", "state": "active", "expires_at": "2099-01-01T00:00:00+00:00"}
    with patch("mcp_vault.auth.context.check_admin_permission", return_value=None), \
         patch("mcp_vault.vault.wrapping.status_by_operation_id",
               new=AsyncMock(return_value=core_ret)) as mock_status:
        res = _run(secret_wrap_status("op-valid-1"))
    assert res["state"] == "active"
    mock_status.assert_called_once_with("op-valid-1")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
