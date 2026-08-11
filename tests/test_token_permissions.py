#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests unitaires — validation des permissions dans TokenStore (issue #48).

Défense en profondeur : TokenStore.create() ne doit JAMAIS persister un token
dont les permissions sortent de {read, write, admin}, ni une liste vide —
indépendamment de l'appelant. Le point d'entrée HTTP /admin/api/tokens valide
déjà (SÉCURITÉ V3-03), mais le store doit être sûr par lui-même.

Non-complaisant :
- on vérifie que le refus intervient AVANT toute écriture S3 (aucun appel à
  _save) — donc l'invariant tient même si S3 est indisponible ;
- on vérifie l'absence de fuite d'état (le token rejeté n'est pas inséré en
  mémoire) ;
- on vérifie que create() et update() partagent la MÊME whitelist (la
  constante unique VALID_PERMISSIONS), pour empêcher toute divergence future.

Aucune dépendance S3 / Docker : _save et _maybe_refresh sont neutralisés.
"""

import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

# Convention du projet : mcp_vault vit dans src/ (pas d'install du package)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp_vault.auth.token_store import TokenStore


def _make_store():
    """TokenStore offline : _save mocké (détecte toute écriture S3),
    _maybe_refresh neutralisé (pas de rechargement S3)."""
    settings = SimpleNamespace(
        s3_endpoint_url="http://localhost:0",
        s3_access_key_id="x",
        s3_secret_access_key="x",
        s3_bucket_name="test-bucket",
        s3_region_name="us-east-1",
    )
    store = TokenStore(settings)
    store._save = MagicMock(return_value=True)
    store._maybe_refresh = MagicMock()
    return store


@pytest.mark.parametrize("bad_perms", [
    ["superuser"],          # flag inexistant
    ["read", "root"],       # un flag valide + un invalide
    ["ADMIN"],              # casse stricte : 'ADMIN' != 'admin'
    ["manage"],             # flag futur non câblé (ne doit pas passer en douce)
    ["read", ""],           # chaîne vide
    ["read,write"],         # piège : un seul élément mal séparé
    [{}],                   # élément non-hashable : doit refuser proprement, PAS crasher
    [["read"]],             # liste imbriquée (non-hashable)
    [123],                  # élément non-str
    ["read", None],         # None dans la liste
])
def test_create_rejette_flag_invalide(bad_perms):
    store = _make_store()
    # Ne doit JAMAIS lever (pas de TypeError sur élément non-hashable) :
    # un payload malformé doit produire un refus propre, pas un crash 500.
    result = store.create(client_name="agent", permissions=bad_perms)

    assert result["status"] == "error", f"devrait refuser {bad_perms!r}"
    # Le refus est en amont de _save : aucune écriture S3 déclenchée
    store._save.assert_not_called()
    # Aucune fuite d'état : le token n'est pas inséré
    assert store._tokens == {}


def test_create_rejette_permissions_vides():
    store = _make_store()
    result = store.create(client_name="agent", permissions=[])

    assert result["status"] == "error"
    store._save.assert_not_called()
    assert store._tokens == {}


def test_create_rejette_non_liste():
    store = _make_store()
    # Une chaîne est itérable : sans le garde isinstance, 'admin' serait
    # interprété caractère par caractère. On exige explicitement une liste.
    result = store.create(client_name="agent", permissions="admin")

    assert result["status"] == "error"
    store._save.assert_not_called()
    assert store._tokens == {}


def test_create_accepte_permissions_valides():
    store = _make_store()
    result = store.create(client_name="agent", permissions=["read", "write"])

    assert "raw_token" in result
    assert result["permissions"] == ["read", "write"]
    store._save.assert_called_once()
    assert len(store._tokens) == 1


def test_create_accepte_admin_seul():
    store = _make_store()
    result = store.create(client_name="boot", permissions=["admin"])
    assert "raw_token" in result
    assert result["permissions"] == ["admin"]


def test_update_partage_la_meme_whitelist():
    """Régression : update() valide via la MÊME constante que create().
    Un flag invalide est refusé sans écriture ni mutation."""
    store = _make_store()
    created = store.create(client_name="agent", permissions=["read"])
    full_hash = created["hash"]
    hash_prefix = full_hash[:12]
    store._save.reset_mock()

    result = store.update(hash_prefix, permissions=["superuser"])

    assert result["status"] == "error"
    store._save.assert_not_called()
    # permissions inchangées (pas de mutation partielle)
    assert store._tokens[full_hash]["permissions"] == ["read"]


def test_constante_valid_permissions_est_la_source_unique():
    """La whitelist est exactement {read, write, admin, wrap} et immuable (frozenset)."""
    assert TokenStore.VALID_PERMISSIONS == frozenset({"read", "write", "admin", "wrap"})
    assert isinstance(TokenStore.VALID_PERMISSIONS, frozenset)


def test_create_accepte_wrap_seul():
    """#115 : un token broker JIT ["wrap"] est créable (le moindre privilège
    exige de POUVOIR créer un token sans read/write/admin)."""
    store = _make_store()
    result = store.create(client_name="mcp-mission-broker", permissions=["wrap"])
    assert "raw_token" in result
    assert result["permissions"] == ["wrap"]


def test_create_rejette_variantes_de_wrap():
    """#115 : la whitelist reste stricte — pas de variantes de casse/typo."""
    store = _make_store()
    for bad in (["wrapp"], ["WRAP"], ["wrap "], ["unwrap"]):
        result = store.create(client_name="agent", permissions=bad)
        assert result["status"] == "error", f"devrait refuser {bad!r}"


def test_load_accepte_wrap_et_rejette_flag_inconnu():
    """#115 : _validate_and_normalize_token (chemin load S3) partage la même
    whitelist — un tokens.json avec "wrap" charge, un flag inconnu rejette
    (c'est aussi la preuve du comportement fail-close d'un DOWNGRADE : pour
    v0.9.2, "wrap" est précisément le flag inconnu)."""
    from mcp_vault.auth.token_store import _validate_and_normalize_token
    base = {
        "hash": "a" * 64,
        "client_name": "broker", "permissions": ["wrap"],
        "allowed_resources": ["mcp-mission"], "policy_id": "broker-jit",
        "created_at": "2026-01-01T00:00:00+00:00",
    }
    normalized = _validate_and_normalize_token(base)
    assert normalized["permissions"] == ["wrap"]

    bad = dict(base, permissions=["wrap", "superuser"])
    with pytest.raises(ValueError):
        _validate_and_normalize_token(bad)


# ── Chemin HTTP réel : _api_create_token doit refuser en 400 (pas 500) ────────

def _asgi_statuses(send_mock):
    """Extrait les status HTTP des messages ASGI http.response.start capturés."""
    return [
        c.args[0].get("status")
        for c in send_mock.call_args_list
        if c.args and isinstance(c.args[0], dict)
        and c.args[0].get("type") == "http.response.start"
    ]


@pytest.mark.parametrize("bad_perms", [["superuser"], [{}], [["read"]], [123]])
async def test_api_create_token_refuse_en_400(bad_perms):
    """Le point d'entrée admin renvoie un 400 propre (jamais 500) pour des
    permissions invalides ou malformées — store mocké non-None pour franchir
    la garde 'S3 non configuré'."""
    import json
    from unittest.mock import AsyncMock, patch
    from mcp_vault.admin import api

    send = AsyncMock()
    fake_store = MagicMock()
    body = json.dumps({"client_name": "x", "permissions": bad_perms})
    with patch.object(api, "get_token_store", return_value=fake_store):
        await api._api_create_token(send, body)

    assert 400 in _asgi_statuses(send), f"attendu 400 pour {bad_perms!r}"
    # La validation court-circuite : create() ne doit pas être appelé
    fake_store.create.assert_not_called()
