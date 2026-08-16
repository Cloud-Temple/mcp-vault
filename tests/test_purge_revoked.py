#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests — purge des tokens révoqués (issue #50).

Règles métier vérifiées (non-complaisant) :
- on ne purge QUE les tokens révoqués depuis plus de N jours (rétention) ;
- un token ACTIF n'est jamais purgé ;
- un token EXPIRÉ mais NON révoqué n'est jamais purgé (il doit rester visible —
  exigence explicite : « on a besoin de savoir qu'un token est expiré ») ;
- fail-close : un token révoqué sans revoked_at parseable n'est PAS purgé ;
- dry_run ne supprime rien et n'audite pas ;
- échec S3 → rollback complet (aucun token perdu) + 503 ;
- côté REST : réservé via la route, audit de CHAQUE token purgé + récap,
  validation de older_than_days, 503 + audit 'error' si S3 down.

Offline : _save / _maybe_refresh mockés, aucune dépendance S3 / Docker.
"""

import os
import sys
import json
import hashlib
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from tests.doubles_magasins import DoubleMagasin

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp_vault.auth.token_store import TokenStore
from mcp_vault.admin import api


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_store():
    settings = SimpleNamespace(
        s3_endpoint_url="http://localhost:0", s3_access_key_id="x",
        s3_secret_access_key="x", s3_bucket_name="test", s3_region_name="us-east-1",
    )
    store = TokenStore(settings)
    store._save = MagicMock(return_value=True)
    store._maybe_refresh = MagicMock()
    return store


def _tok(client, revoked=False, revoked_days_ago=None, expired=False, corrupt_revoked_at=None):
    now = datetime.now(timezone.utc)
    t = {
        "hash": hashlib.sha256(client.encode()).hexdigest(),
        "client_name": client, "permissions": ["read"], "allowed_resources": [],
        "policy_id": "", "email": "", "created_at": now.isoformat(),
        "expires_at": None, "revoked": revoked,
    }
    if expired:
        t["expires_at"] = (now - timedelta(days=1)).isoformat()
    if revoked:
        if corrupt_revoked_at is not None:
            if corrupt_revoked_at:  # valeur non parseable
                t["revoked_at"] = corrupt_revoked_at
            # sinon : pas de revoked_at du tout
        elif revoked_days_ago is not None:
            t["revoked_at"] = (now - timedelta(days=revoked_days_ago)).isoformat()
    return t


def _load(store, *tokens):
    store._tokens = {t["hash"]: t for t in tokens}


def _names(store):
    return {t["client_name"] for t in store._tokens.values()}


def _asgi_statuses(send_mock):
    return [
        c.args[0].get("status")
        for c in send_mock.call_args_list
        if c.args and isinstance(c.args[0], dict)
        and c.args[0].get("type") == "http.response.start"
    ]


# ── Store : purge_revoked ────────────────────────────────────────────────────

def test_purge_garde_actifs_recents_revoques_et_expires_non_revoques():
    store = _make_store()
    _load(store,
          _tok("old-revoked", revoked=True, revoked_days_ago=40),   # → purgé
          _tok("recent-revoked", revoked=True, revoked_days_ago=5),  # rétention → gardé
          _tok("active"),                                            # actif → gardé
          _tok("expired-not-revoked", expired=True))                # EXPIRÉ non révoqué → gardé
    res = store.purge_revoked(older_than_days=30, dry_run=False)
    assert res["status"] == "ok"
    assert res["count"] == 1
    assert _names(store) == {"recent-revoked", "active", "expired-not-revoked"}
    store._save.assert_called_once()


def test_purge_fail_close_revoked_at_absent_ou_corrompu():
    store = _make_store()
    _load(store,
          _tok("no-date", revoked=True, corrupt_revoked_at=False),       # pas de revoked_at
          _tok("bad-date", revoked=True, corrupt_revoked_at="pas-iso"))  # date illisible
    res = store.purge_revoked(older_than_days=0, dry_run=False)  # 0 = tous, mais fail-close
    assert res["count"] == 0
    assert len(store._tokens) == 2  # rien purgé
    store._save.assert_not_called()


def test_purge_dry_run_ne_supprime_rien_ni_n_ecrit():
    store = _make_store()
    _load(store, _tok("old", revoked=True, revoked_days_ago=40))
    res = store.purge_revoked(older_than_days=30, dry_run=True)
    assert res["dry_run"] is True and res["count"] == 1
    assert len(res["candidates"]) == 1
    assert res["candidates"][0]["client_name"] == "old"
    store._save.assert_not_called()
    assert len(store._tokens) == 1  # intact


def test_purge_rollback_si_save_echoue():
    store = _make_store()
    store._save = MagicMock(return_value=False)  # S3 indisponible
    _load(store, _tok("old", revoked=True, revoked_days_ago=40))
    res = store.purge_revoked(older_than_days=30, dry_run=False)
    assert res["status"] == "storage_unavailable"
    assert _names(store) == {"old"}  # rollback : le token est restauré


def test_purge_older_than_zero_purge_tous_les_revoques_datables():
    store = _make_store()
    _load(store,
          _tok("r1", revoked=True, revoked_days_ago=1),
          _tok("r2", revoked=True, revoked_days_ago=100),
          _tok("active"))
    res = store.purge_revoked(older_than_days=0, dry_run=False)
    assert res["count"] == 2
    assert _names(store) == {"active"}


def test_purge_fail_close_revoked_at_naif_sans_timezone():
    """Donnée héritée : revoked_at ISO SANS fuseau → non comparable → fail-close."""
    store = _make_store()
    t = _tok("naive", revoked=True)
    t["revoked_at"] = (datetime.now() - timedelta(days=40)).isoformat()  # naïf (pas de tz)
    _load(store, t)
    res = store.purge_revoked(older_than_days=30, dry_run=False)
    assert res["count"] == 0
    assert _names(store) == {"naive"}  # non purgé
    store._save.assert_not_called()


def test_purge_frontiere_retention():
    """Direction de la borne : dans la rétention = gardé, au-delà = purgé."""
    store = _make_store()
    _load(store,
          _tok("just-inside", revoked=True, revoked_days_ago=29),    # < 30 j → gardé
          _tok("just-outside", revoked=True, revoked_days_ago=31))   # > 30 j → purgé
    res = store.purge_revoked(older_than_days=30, dry_run=False)
    assert res["count"] == 1
    assert _names(store) == {"just-inside"}


# ── REST : _api_purge_revoked_tokens ─────────────────────────────────────────

async def test_api_purge_dry_run_200_sans_audit():
    send = AsyncMock()
    store = DoubleMagasin()
    store.purge_revoked.return_value = {"status": "ok", "dry_run": True, "count": 2,
                                        "older_than_days": 30, "candidates": []}
    with patch.object(api, "get_token_store", return_value=store), \
            patch.object(api, "log_audit") as audit:
        await api._api_purge_revoked_tokens(send, json.dumps({"dry_run": True}))
    audit.assert_not_called()
    assert 200 in _asgi_statuses(send)
    store.purge_revoked.assert_called_once_with(30, dry_run=True)


async def test_api_purge_effectif_audite_chaque_token_et_recap():
    send = AsyncMock()
    store = DoubleMagasin()
    store.purge_revoked.return_value = {
        "status": "ok", "dry_run": False, "count": 2, "older_than_days": 30,
        "purged": [
            {"client_name": "a", "hash_prefix": "aaaaaaaaaaaa", "revoked_at": "2026-01-01T00:00:00+00:00"},
            {"client_name": "b", "hash_prefix": "bbbbbbbbbbbb", "revoked_at": "2026-01-02T00:00:00+00:00"},
        ],
    }
    with patch.object(api, "get_token_store", return_value=store), \
            patch.object(api, "log_audit") as audit:
        await api._api_purge_revoked_tokens(send, json.dumps({"dry_run": False}))
    tools = [c.args[0] for c in audit.call_args_list]
    statuses = [c.args[1] for c in audit.call_args_list]
    assert tools == ["token_purge", "token_purge", "token_purge"]  # 2 deleted + 1 récap
    assert statuses.count("deleted") == 2 and "ok" in statuses
    assert 200 in _asgi_statuses(send)


@pytest.mark.parametrize("bad", [True, False, -1, "30", 1.5, 99999999])  # 99999999 > borne sup
async def test_api_purge_older_than_invalide_400(bad):
    send = AsyncMock()
    store = DoubleMagasin()
    with patch.object(api, "get_token_store", return_value=store), \
            patch.object(api, "log_audit"):
        await api._api_purge_revoked_tokens(send, json.dumps({"older_than_days": bad}))
    assert 400 in _asgi_statuses(send)
    store.purge_revoked.assert_not_called()  # rejet avant tout appel store


# ── REST : dry_run booléen STRICT (régression fail-open task_a5346701) ────────
# Jumeau de la faille fermée en #69 sur _api_purge_mission_bindings. Avant le fix,
# `dry_run = bool(data.get("dry_run", False))` coerçait toute valeur falsy non booléenne
# ([], 0, "", None) en dry_run=False → purge DESTRUCTIVE réelle qu'on croyait simuler.

@pytest.mark.parametrize("bad", [[], 0, "", None, "true", "false", 1, 1.0, {}, [1]])
async def test_api_purge_dry_run_non_bool_400_sans_purge(bad):
    """Un dry_run non booléen est REJETÉ (400) AVANT tout appel store — jamais coercé
    en purge réelle. Couvre en particulier les falsy ([], 0, "", None) qui étaient le
    vecteur exact du fail-open (bool([]) == bool(0) == False)."""
    send = AsyncMock()
    store = DoubleMagasin()
    with patch.object(api, "get_token_store", return_value=store), \
            patch.object(api, "log_audit") as audit:
        await api._api_purge_revoked_tokens(send, json.dumps({"dry_run": bad}))
    assert 400 in _asgi_statuses(send)
    store.purge_revoked.assert_not_called()  # aucune purge, même en dry_run "apparent"
    audit.assert_not_called()


async def test_api_purge_dry_run_true_reste_simulation():
    """Régression inverse : un vrai True continue de SIMULER (purge_revoked dry_run=True)."""
    send = AsyncMock()
    store = DoubleMagasin()
    store.purge_revoked.return_value = {"status": "ok", "dry_run": True, "count": 0,
                                        "older_than_days": 30, "candidates": []}
    with patch.object(api, "get_token_store", return_value=store), \
            patch.object(api, "log_audit"):
        await api._api_purge_revoked_tokens(send, json.dumps({"dry_run": True}))
    store.purge_revoked.assert_called_once_with(30, dry_run=True)


async def test_api_purge_dry_run_false_execute_la_purge():
    """Un vrai False (comportement destructif volontaire) déclenche bien la purge effective."""
    send = AsyncMock()
    store = DoubleMagasin()
    store.purge_revoked.return_value = {"status": "ok", "dry_run": False, "count": 0,
                                        "older_than_days": 30, "purged": []}
    with patch.object(api, "get_token_store", return_value=store), \
            patch.object(api, "log_audit"):
        await api._api_purge_revoked_tokens(send, json.dumps({"dry_run": False}))
    store.purge_revoked.assert_called_once_with(30, dry_run=False)


async def test_api_purge_storage_unavailable_503_et_audit_error():
    send = AsyncMock()
    store = DoubleMagasin()
    store.purge_revoked.return_value = {"status": "storage_unavailable", "count": 0,
                                        "older_than_days": 30, "message": "S3 down"}
    with patch.object(api, "get_token_store", return_value=store), \
            patch.object(api, "log_audit") as audit:
        await api._api_purge_revoked_tokens(send, json.dumps({"dry_run": False}))
    assert 503 in _asgi_statuses(send)
    assert ("token_purge", "error") in [(c.args[0], c.args[1]) for c in audit.call_args_list]


async def test_api_purge_effectif_count_zero_audit_recap_uniquement():
    """Rien à purger : exactement 1 récap ('ok', count=0), aucune ligne 'deleted'."""
    send = AsyncMock()
    store = DoubleMagasin()
    store.purge_revoked.return_value = {"status": "ok", "dry_run": False, "count": 0,
                                        "older_than_days": 30, "purged": [], "message": "rien"}
    with patch.object(api, "get_token_store", return_value=store), \
            patch.object(api, "log_audit") as audit:
        await api._api_purge_revoked_tokens(send, json.dumps({"dry_run": False}))
    assert [(c.args[0], c.args[1]) for c in audit.call_args_list] == [("token_purge", "ok")]
    assert 200 in _asgi_statuses(send)


# ── Route : garde ADMIN (403) — garantie de sécurité centrale de #50 ──────────

async def test_route_purge_refuse_non_admin_403():
    """Un token NON-admin (write) ne doit PAS pouvoir purger : la route renvoie 403
    AVANT d'atteindre le handler (garde testée au niveau du routage réel)."""
    send = AsyncMock()
    receive = AsyncMock()
    store = DoubleMagasin()
    scope = {"type": "http", "method": "POST", "path": "/admin/api/tokens/purge", "headers": []}
    token_info = {"client_name": "w", "permissions": ["write"], "allowed_resources": []}
    with patch.object(api, "get_token_store", return_value=store):
        await api._handle_admin_routes(scope, receive, send, None, token_info)
    assert 403 in _asgi_statuses(send)
    store.purge_revoked.assert_not_called()  # garde appliquée en amont du handler


async def test_route_purge_admin_atteint_le_handler():
    """Symétrique : un token admin franchit la garde et atteint le handler de purge."""
    send = AsyncMock()
    receive = AsyncMock(return_value={"type": "http.request", "body": b'{"dry_run": true}', "more_body": False})
    store = DoubleMagasin()
    store.purge_revoked.return_value = {"status": "ok", "dry_run": True, "count": 0,
                                        "older_than_days": 30, "candidates": [], "message": "ok"}
    scope = {"type": "http", "method": "POST", "path": "/admin/api/tokens/purge", "headers": []}
    token_info = {"client_name": "admin", "permissions": ["admin"], "allowed_resources": []}
    with patch.object(api, "get_token_store", return_value=store):
        await api._handle_admin_routes(scope, receive, send, None, token_info)
    assert 200 in _asgi_statuses(send)
    store.purge_revoked.assert_called_once()
