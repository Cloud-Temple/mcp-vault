#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test d'INTÉGRATION #81 — comportement KV v2 réel de list_secrets/read_secret.

Exerce les VRAIES fonctions de production (mcp_vault.vault.secrets) contre un
OpenBao réel, en injectant le client hvac connecté via get_hvac_client().

Opt-in (pattern e2e du repo, issue #64) : SKIP sauf si l'environnement fournit
  - MCP_VAULT_TEST_OPENBAO_ADDR  (ex: http://127.0.0.1:18201)
  - MCP_VAULT_TEST_OPENBAO_TOKEN (root/dev token)
Le harnais (ou un OpenBao Docker dev) pose ces variables. Sans elles → skip.

Valide empiriquement (cf. revue Codex du plan) :
  - un dossier ressort avec un '/' final ; une feuille jamais ;
  - list(sous-dossier) renvoie des clés RELATIVES ;
  - collision feuille 'collision' + dossier 'collision/child' coexistent ;
  - lire un dossier ne renvoie pas un secret ; préfixe absent → liste vide ;
  - un traversal est rejeté avant OpenBao.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

_ADDR = os.getenv("MCP_VAULT_TEST_OPENBAO_ADDR", "").strip()
_TOKEN = os.getenv("MCP_VAULT_TEST_OPENBAO_TOKEN", "").strip()

pytestmark = pytest.mark.skipif(
    not (_ADDR and _TOKEN),
    reason="OpenBao réel requis — poser MCP_VAULT_TEST_OPENBAO_ADDR + _TOKEN (test #81 e2e)",
)

_MOUNT = "nav81probe"


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


@pytest.fixture(scope="module")
def real_client():
    """OpenBao réel + arborescence de test. Nettoyage best-effort en sortie."""
    import hvac
    c = hvac.Client(url=_ADDR, token=_TOKEN)
    assert c.is_authenticated(), "token OpenBao de test invalide"

    # (re)créer le mount KV v2
    try:
        c.sys.disable_secrets_engine(path=_MOUNT)
    except Exception:
        pass
    c.sys.enable_secrets_engine(backend_type="kv", path=_MOUNT, options={"version": "2"})

    tree = {
        "bootstrap/alpha": {"v": "1"},
        "bootstrap/nested/beta": {"v": "2"},
        "mcp-teleport/gamma": {"v": "3"},
        "collision": {"v": "leaf"},          # feuille
        "collision/child": {"v": "in-dir"},  # + dossier de même nom de base
    }
    for path, data in tree.items():
        c.secrets.kv.v2.create_or_update_secret(path=path, secret=data, mount_point=_MOUNT)

    yield c

    try:
        c.sys.disable_secrets_engine(path=_MOUNT)
    except Exception:
        pass


def _patched(real_client):
    from unittest.mock import patch
    from mcp_vault.vault import secrets as sec
    return patch.object(sec, "get_hvac_client", return_value=real_client)


def test_root_listing_marks_folders_and_leaf(real_client):
    from mcp_vault.vault import secrets as sec
    with _patched(real_client):
        res = _run(sec.list_secrets(_MOUNT, ""))
    assert res["status"] == "ok"
    keys = set(res["keys"])
    # dossiers avec '/', feuille 'collision' sans '/'
    assert "bootstrap/" in keys and "mcp-teleport/" in keys
    assert "collision/" in keys, "le dossier collision/ doit apparaître"
    assert "collision" in keys, "la feuille collision doit coexister avec le dossier"


def test_subfolder_listing_is_relative(real_client):
    from mcp_vault.vault import secrets as sec
    with _patched(real_client):
        res = _run(sec.list_secrets(_MOUNT, "bootstrap"))
        res_slash = _run(sec.list_secrets(_MOUNT, "bootstrap/"))
    assert set(res["keys"]) == {"alpha", "nested/"}, "clés RELATIVES attendues"
    assert set(res_slash["keys"]) == {"alpha", "nested/"}, "slash terminal normalisé"


def test_read_leaf_ok_read_folder_not_a_secret(real_client):
    from mcp_vault.vault import secrets as sec
    with _patched(real_client):
        leaf = _run(sec.read_secret(_MOUNT, "bootstrap/alpha"))
        folder = _run(sec.read_secret(_MOUNT, "bootstrap"))
        collision_leaf = _run(sec.read_secret(_MOUNT, "collision"))
    assert leaf["status"] == "ok" and leaf["data"] == {"v": "1"}
    # lire un dossier ne renvoie pas de secret exploitable
    assert folder["status"] == "error" or not folder.get("data")
    # la feuille homonyme du dossier est bien lisible
    assert collision_leaf["status"] == "ok" and collision_leaf["data"] == {"v": "leaf"}


def test_absent_prefix_is_empty_list(real_client):
    from mcp_vault.vault import secrets as sec
    with _patched(real_client):
        res = _run(sec.list_secrets(_MOUNT, "does-not-exist"))
    assert res["status"] == "ok" and res["keys"] == [] and res["count"] == 0


def test_traversal_rejected_before_openbao(real_client):
    from mcp_vault.vault import secrets as sec
    with _patched(real_client):
        for bad in ("../sys", "bootstrap/../..", "bootstrap//"):
            res = _run(sec.list_secrets(_MOUNT, bad))
            assert res["status"] == "error", f"{bad!r} devrait être rejeté"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
