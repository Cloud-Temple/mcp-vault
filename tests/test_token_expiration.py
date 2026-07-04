#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests — validation de l'expiration des tokens à la création (issue #65).

Décision métier : tokens illimités AUTORISÉS mais EXPLICITES.
Contrat unique (TokenStore.validate_expires_in_days, partagé store + REST) :
- `0`                → jamais expirer (illimité EXPLICITE) → expires_at = None ;
- entier [1, 36500]  → durée en jours ;
- tout le reste      → REFUSÉ (ni illimité accidentel, ni TypeError/500) :
  bool (sous-classe d'int), non-int (string/float/None), négatif, > 36500.

Non-complaisant : on prouve l'ABSENCE de token créé sur entrée invalide (pas juste
un code retour) et que `"0"` (string) ne plante plus (régression TypeError).

Offline : _save / _maybe_refresh mockés, aucune dépendance S3 / Docker.
"""

import os
import sys
import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

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


def _asgi_statuses(send_mock):
    return [
        c.args[0].get("status")
        for c in send_mock.call_args_list
        if c.args and isinstance(c.args[0], dict)
        and c.args[0].get("type") == "http.response.start"
    ]


def _response_body(send_mock):
    chunks = [
        c.args[0].get("body", b"")
        for c in send_mock.call_args_list
        if c.args and isinstance(c.args[0], dict)
        and c.args[0].get("type") == "http.response.body"
    ]
    return json.loads(b"".join(chunks).decode()) if chunks else None


# Valeurs INVALIDES qui étaient précisément le vecteur du bug #65 :
# - None/-1/""/False/0.0 créaient un illimité ACCIDENTEL ;
# - "0" (string) faisait planter (TypeError → 500) ;
# - True→1j, 1.5→1,5j, 36501 accepté.
_INVALID = [-1, 36501, True, False, 1.5, 0.0, "0", "90", "abc", "", None, [], {}]


# ── Validateur pur (source unique) ───────────────────────────────────────────

@pytest.mark.parametrize("ok", [0, 1, 30, 90, 365, 36500])
def test_validate_accepte_entiers_bornes(ok):
    assert TokenStore.validate_expires_in_days(ok) is None


@pytest.mark.parametrize("bad", _INVALID)
def test_validate_refuse_les_invalides(bad):
    msg = TokenStore.validate_expires_in_days(bad)
    assert isinstance(msg, str) and "expires_in_days" in msg


def test_validate_rejette_bool_meme_si_int_like():
    # bool est sous-classe d'int : True==1 / False==0 ne doivent PAS être pris pour une durée.
    assert TokenStore.validate_expires_in_days(True) is not None
    assert TokenStore.validate_expires_in_days(False) is not None


# ── Store.create — comportement ──────────────────────────────────────────────

def test_create_zero_est_illimite_explicite():
    store = _make_store()
    res = store.create("agent-perenne", ["read"], expires_in_days=0)
    assert res.get("status") != "error"
    assert res["expires_at"] is None          # 0 = jamais expirer
    store._save.assert_called_once()


def test_create_positif_pose_une_expiration():
    store = _make_store()
    res = store.create("agent-temporaire", ["read"], expires_in_days=30)
    assert res.get("status") != "error"
    assert res["expires_at"] is not None
    delta = datetime.fromisoformat(res["expires_at"]) - datetime.now(timezone.utc)
    assert 29 <= delta.days <= 30            # ~30 jours


def test_create_defaut_90_jours():
    store = _make_store()
    res = store.create("agent-defaut", ["read"])   # expires_in_days non fourni → 90
    delta = datetime.fromisoformat(res["expires_at"]) - datetime.now(timezone.utc)
    assert 89 <= delta.days <= 90


@pytest.mark.parametrize("bad", _INVALID)
def test_create_refuse_invalide_sans_persister(bad):
    store = _make_store()
    res = store.create("agent-x", ["read"], expires_in_days=bad)
    assert res["status"] == "error" and res["error_type"] == "invalid_expiration"
    assert store._tokens == {}               # AUCUN token créé
    store._save.assert_not_called()          # pas d'écriture


def test_create_string_zero_ne_plante_pas():
    """Régression TypeError : `"0"` levait `'>' not supported between str and int`."""
    store = _make_store()
    res = store.create("agent-x", ["read"], expires_in_days="0")  # ne doit PAS lever
    assert res["status"] == "error" and res["error_type"] == "invalid_expiration"


# ── REST — _api_create_token ─────────────────────────────────────────────────

async def test_api_create_zero_ok_expiration_nulle():
    send = AsyncMock()
    store = _make_store()
    with patch.object(api, "get_token_store", return_value=store), \
            patch.object(api, "log_audit"):
        await api._api_create_token(send, json.dumps(
            {"client_name": "c", "permissions": ["read"], "expires_in_days": 0}))
    assert 201 in _asgi_statuses(send)
    assert _response_body(send)["expires_at"] is None


async def test_api_create_defaut_90_si_absent():
    send = AsyncMock()
    store = _make_store()
    with patch.object(api, "get_token_store", return_value=store), \
            patch.object(api, "log_audit"):
        await api._api_create_token(send, json.dumps(
            {"client_name": "c", "permissions": ["read"]}))
    assert 201 in _asgi_statuses(send)
    assert _response_body(send)["expires_at"] is not None   # 90 j par défaut


@pytest.mark.parametrize("bad", _INVALID)
async def test_api_create_refuse_invalide_400_sans_appel_store(bad):
    """Entrée d'expiration invalide → 400 AVANT tout store.create (ni illimité
    accidentel, ni 500). Le store est un MagicMock : on prouve qu'il n'est pas touché."""
    send = AsyncMock()
    store = MagicMock()
    with patch.object(api, "get_token_store", return_value=store), \
            patch.object(api, "log_audit") as audit:
        await api._api_create_token(send, json.dumps(
            {"client_name": "c", "permissions": ["read"], "expires_in_days": bad}))
    assert 400 in _asgi_statuses(send)
    store.create.assert_not_called()
    audit.assert_not_called()
