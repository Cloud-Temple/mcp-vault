#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests #81 — Navigation par dossier des secrets (console admin) + durcissements.

Couvre, SANS OpenBao réel (mocks ciblés) :
  A. _validate_secret_path canonique (segments, '.', '..', '//', slash terminal,
     newline, non-str, longueur) + message CONSTANT (anti-injection d'audit).
  B. list_secrets : validation appliquée AVANT tout appel OpenBao + normalisation
     du slash terminal (non-complaisance : un traversal ne doit jamais atteindre hvac).
  C. Routeur admin : segment "/secrets" EXACT (écarte "/secretsfoo"), listing par
     ?prefix= contrôlé, '//' non masqué.
  D. Fuite de policy (finding Codex #1) : la fiche vault ne liste plus les clés ;
     un token autorisé sur vault_info mais interdit sur secret_list ne voit rien.
  E. domId bijectif côté JS (collision 'a/b' vs 'a_b') — exécuté sous Node.

Le test d'intégration OpenBao réel est dans test_secrets_folder_nav_openbao_81.py.
"""
import json
import os
import subprocess
import sys
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("MCP_SERVER_NAME", "mcp-vault-test")
os.environ.setdefault("ADMIN_BOOTSTRAP_KEY", "Test-Bootstrap-Key-2026-Pour-Tests!!")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

_CONST_MSG = "Chemin de secret invalide"


# ─────────────────────────────────────────────────────────────────────────────
# A. _validate_secret_path — validation canonique + message constant
# ─────────────────────────────────────────────────────────────────────────────

def test_validate_path_accepts_legit():
    from mcp_vault.vault.secrets import _validate_secret_path
    for ok in ("", "bootstrap", "bootstrap/nested", "a_b-c.d", "x/y/z", "mcp-teleport"):
        assert _validate_secret_path(ok) is None, f"devrait accepter {ok!r}"


def test_validate_path_rejects_traversal_and_empty_segments():
    from mcp_vault.vault.secrets import _validate_secret_path
    # '..' et '.' comme segments, '//', slash terminal, segments vides
    for bad in ("..", ".", "foo/../bar", "foo/./bar", "bootstrap/", "bootstrap//",
                "//", "a//b", "/leading", "trailing/"):
        err = _validate_secret_path(bad)
        assert err is not None and err["status"] == "error", f"devrait rejeter {bad!r}"
        # message CONSTANT — ne reflète JAMAIS la valeur (anti-injection audit #78)
        assert err["message"] == _CONST_MSG, f"message non constant pour {bad!r}: {err}"
        assert bad not in err["message"]


def test_validate_path_rejects_newline_and_control():
    """Le '\\n' final (faille .match+$) et les chars de contrôle sont rejetés (#78/#81)."""
    from mcp_vault.vault.secrets import _validate_secret_path
    for bad in ("bootstrap/\nforged", "x\nforged", "a\tb", "a\x00b", "line1\r\nline2"):
        err = _validate_secret_path(bad)
        assert err is not None, f"devrait rejeter {bad!r}"
        assert err["message"] == _CONST_MSG


def test_validate_path_rejects_backslash_and_dotfiles_and_length():
    from mcp_vault.vault.secrets import _validate_secret_path
    assert _validate_secret_path("a\\b") is not None
    # segment commençant par '.' (dotfile) rejeté comme avant (1er char alphanum)
    assert _validate_secret_path(".hidden") is not None
    # longueur > 256
    assert _validate_secret_path("a" * 257) is not None
    assert _validate_secret_path("a" * 256) is None


def test_validate_path_rejects_non_str():
    """Contrôle de type (fail-close) : non-str → rejet, jamais un crash."""
    from mcp_vault.vault.secrets import _validate_secret_path
    for bad in (123, None, b"bytes", ["list"], {"k": "v"}):
        err = _validate_secret_path(bad)
        assert err is not None and err["message"] == _CONST_MSG, f"devrait rejeter {bad!r}"


# ─────────────────────────────────────────────────────────────────────────────
# B. list_secrets — validation AVANT OpenBao + normalisation slash terminal
# ─────────────────────────────────────────────────────────────────────────────

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


def _mock_hvac_client(keys):
    client = MagicMock()
    client.secrets.kv.v2.list_secrets.return_value = {"data": {"keys": list(keys)}}
    return client


def test_list_secrets_normalizes_trailing_slash():
    """list_secrets('bootstrap/') doit lister 'bootstrap' (slash terminal normalisé)."""
    from mcp_vault.vault import secrets as sec
    client = _mock_hvac_client(["alpha", "nested/"])
    with patch.object(sec, "get_hvac_client", return_value=client):
        res = _run(sec.list_secrets("v", "bootstrap/"))
    assert res["status"] == "ok"
    assert res["path"] == "bootstrap"  # normalisé
    client.secrets.kv.v2.list_secrets.assert_called_once_with(path="bootstrap", mount_point="v")
    assert res["keys"] == ["alpha", "nested/"]


def test_list_secrets_rejects_traversal_before_openbao():
    """NON-COMPLAISANCE : un path de traversal ne doit JAMAIS atteindre OpenBao."""
    from mcp_vault.vault import secrets as sec
    with patch.object(sec, "get_hvac_client") as mock_get:
        for bad in ("../etc", "foo/../bar", "bootstrap//", "a\nb"):
            res = _run(sec.list_secrets("v", bad))
            assert res["status"] == "error", f"{bad!r} devrait être rejeté"
            assert res["message"] == _CONST_MSG
        # get_hvac_client ne doit JAMAIS avoir été appelé (rejet avant la couche OpenBao)
        mock_get.assert_not_called()


def test_list_secrets_root_ok():
    from mcp_vault.vault import secrets as sec
    client = _mock_hvac_client(["bootstrap/", "mcp-teleport/"])
    with patch.object(sec, "get_hvac_client", return_value=client):
        res = _run(sec.list_secrets("v", ""))
    assert res["status"] == "ok" and res["count"] == 2
    client.secrets.kv.v2.list_secrets.assert_called_once_with(path="", mount_point="v")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers ASGI (repris de test_admin_path_policy.py)
# ─────────────────────────────────────────────────────────────────────────────

def _make_scope(method, path, query=b""):
    return {
        "type": "http", "method": method, "path": path,
        "query_string": query,
        "headers": [(b"authorization", b"Bearer admin-bootstrap-token")],
    }


def _make_receive(body=b"{}"):
    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}
    return receive


def _token_info(permissions=None, policy_id="p", allowed_resources=None):
    return {
        "client_name": "test-agent",
        "permissions": permissions or ["read"],
        "policy_id": policy_id,
        "allowed_resources": allowed_resources or ["test-vault"],
        "hash": "a" * 64,
    }


async def _call(scope, body=b"{}"):
    from mcp_vault.admin.api import handle_admin_api
    responses = []

    async def send(message):
        responses.append(message)

    await handle_admin_api(scope, _make_receive(body), send, mcp=None)
    status = next((r["status"] for r in responses if r.get("type") == "http.response.start"), None)
    body_bytes = b"".join(r.get("body", b"") for r in responses if r.get("type") == "http.response.body")
    return status, (json.loads(body_bytes) if body_bytes else {})


# ─────────────────────────────────────────────────────────────────────────────
# C. Routeur admin — segment exact, listing ?prefix=, '//' non masqué
# ─────────────────────────────────────────────────────────────────────────────

def test_router_secretsfoo_is_not_a_secret_read():
    """
    NON-COMPLAISANCE (finding Codex #2) : '/secretsfoo' ne doit PAS être interprété
    comme la lecture du secret 'foo'. read_secret ne doit jamais être appelé.
    """
    scope = _make_scope("GET", "/admin/api/vaults/test-vault/secretsfoo")
    with patch("mcp_vault.admin.api._get_token_info", return_value=_token_info()), \
         patch("mcp_vault.admin.api.check_policy", return_value=None), \
         patch("mcp_vault.admin.api.check_path_policy", return_value=None), \
         patch("mcp_vault.admin.api._check_vault_access", return_value=None), \
         patch("mcp_vault.admin.api._api_read_secret", new=AsyncMock()) as mock_read:
        status, _ = _run(_call(scope))
    mock_read.assert_not_called()
    assert status != 200, f"'/secretsfoo' ne doit pas aboutir à un 200, obtenu {status}"


def test_router_list_with_prefix_query():
    """GET .../secrets?prefix=bootstrap → listing contrôlé du sous-dossier 'bootstrap'."""
    scope = _make_scope("GET", "/admin/api/vaults/test-vault/secrets", query=b"prefix=bootstrap")
    with patch("mcp_vault.admin.api._get_token_info", return_value=_token_info(["read"])), \
         patch("mcp_vault.admin.api.check_policy", return_value=None), \
         patch("mcp_vault.admin.api.check_path_policy", return_value=None) as mock_cpp, \
         patch("mcp_vault.admin.api._check_vault_access", return_value=None), \
         patch("mcp_vault.admin.api._api_list_secrets", new=AsyncMock()) as mock_list:
        status, _ = _run(_call(scope))
    mock_cpp.assert_called_once_with("test-vault", "bootstrap", "read")
    mock_list.assert_called_once_with(ANY, "test-vault", "bootstrap")


def test_router_list_root_no_prefix():
    """GET .../secrets (sans prefix) → listing racine, check_path_policy(vault,'',read)."""
    scope = _make_scope("GET", "/admin/api/vaults/test-vault/secrets")
    with patch("mcp_vault.admin.api._get_token_info", return_value=_token_info(["read"])), \
         patch("mcp_vault.admin.api.check_policy", return_value=None), \
         patch("mcp_vault.admin.api.check_path_policy", return_value=None) as mock_cpp, \
         patch("mcp_vault.admin.api._check_vault_access", return_value=None), \
         patch("mcp_vault.admin.api._api_list_secrets", new=AsyncMock()) as mock_list:
        status, _ = _run(_call(scope))
    mock_cpp.assert_called_once_with("test-vault", "", "read")
    mock_list.assert_called_once_with(ANY, "test-vault", "")


def test_router_double_slash_not_masked():
    """
    '/secrets//bootstrap' : le '//' n'est pas silencieusement réduit ; le read est
    tenté sur '/bootstrap' (segment vide en tête) et rejeté par la validation.
    """
    scope = _make_scope("GET", "/admin/api/vaults/test-vault/secrets//bootstrap")
    captured = {}

    async def fake_read(send, vault_id, secret_path):
        captured["path"] = secret_path
        from mcp_vault.admin.api import _json_response
        await _json_response(send, 404, {"status": "error", "message": "x"})

    with patch("mcp_vault.admin.api._get_token_info", return_value=_token_info(["read"])), \
         patch("mcp_vault.admin.api.check_policy", return_value=None), \
         patch("mcp_vault.admin.api.check_path_policy", return_value=None), \
         patch("mcp_vault.admin.api._check_vault_access", return_value=None), \
         patch("mcp_vault.admin.api._api_read_secret", new=fake_read):
        status, _ = _run(_call(scope))
    # On ne retire qu'UN slash de séparation → il reste un segment vide en tête.
    assert captured.get("path") == "/bootstrap"


# ─────────────────────────────────────────────────────────────────────────────
# D. Fuite de policy (finding Codex #1)
# ─────────────────────────────────────────────────────────────────────────────

def test_vault_detail_no_longer_leaks_secret_keys():
    """
    La fiche vault (GET /vaults/{id}) ne renvoie plus 'secret_keys' et ne liste plus
    (list_secrets non appelé) → plus de fuite de noms via le canal vault_info.
    Elle expose root_entries_count (compteur honnête).
    """
    scope = _make_scope("GET", "/admin/api/vaults/test-vault")
    info = {"status": "ok", "vault_id": "test-vault", "description": "",
            "root_entries_count": 2, "secrets_count": 2,
            "created_at": "", "created_by": "admin", "updated_at": "", "updated_by": ""}
    with patch("mcp_vault.admin.api._get_token_info", return_value=_token_info(["read"])), \
         patch("mcp_vault.admin.api.check_policy", return_value=None), \
         patch("mcp_vault.admin.api._check_vault_access", return_value=None), \
         patch("mcp_vault.vault.spaces.get_space_info", new=AsyncMock(return_value=info)), \
         patch("mcp_vault.vault.ssh_ca.list_ssh_roles", new=AsyncMock(return_value={"status": "ok", "roles": []})), \
         patch("mcp_vault.vault.secrets.list_secrets", new=AsyncMock()) as mock_list:
        status, body = _run(_call(scope))
    assert status == 200
    assert "secret_keys" not in body, "FUITE : la fiche vault expose encore secret_keys"
    assert body.get("root_entries_count") == 2
    mock_list.assert_not_called()  # la fiche ne liste plus les secrets


def test_listing_denied_when_secret_list_policy_forbidden():
    """
    Un token autorisé sur vault_info mais INTERDIT sur secret_list : le listing
    (GET .../secrets) est refusé (403) et list_secrets n'est jamais appelé.
    """
    scope = _make_scope("GET", "/admin/api/vaults/test-vault/secrets")

    def policy(name):
        return {"status": "error", "message": "secret_list interdit"} if name == "secret_list" else None

    with patch("mcp_vault.admin.api._get_token_info", return_value=_token_info(["read"])), \
         patch("mcp_vault.admin.api.check_policy", side_effect=policy), \
         patch("mcp_vault.admin.api.check_path_policy", return_value=None), \
         patch("mcp_vault.admin.api._check_vault_access", return_value=None), \
         patch("mcp_vault.admin.api._api_list_secrets", new=AsyncMock()) as mock_list:
        status, _ = _run(_call(scope))
    assert status == 403
    mock_list.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# E. domId bijectif (JS) — collision 'a/b' vs 'a_b' (finding Codex #5)
# ─────────────────────────────────────────────────────────────────────────────

def test_js_domid_is_injective_under_node():
    """
    La fonction domId de vaults.js doit être bijective : 'a/b' et 'a_b' produisent
    des identifiants DIFFÉRENTS (l'ancienne substitution '/'→'_' collisionnait).
    Exécute la VRAIE fonction du fichier de prod sous Node. Skip si Node absent.
    """
    import shutil
    node = shutil.which("node")
    if not node:
        pytest.skip("node absent — test domId non exécutable ici")

    vaults_js = os.path.join(os.path.dirname(__file__), "..", "src", "mcp_vault", "static", "js", "vaults.js")
    harness = (
        "const fs=require('fs'),vm=require('vm');"
        "const code=fs.readFileSync(process.argv[1],'utf8');"
        "const ctx={TextEncoder,console};vm.createContext(ctx);"
        "vm.runInContext(code,ctx);"
        "const cases=[['a/b','a_b'],['collision/','collision'],['x/y','x_y']];"
        "let bad=[];"
        "for(const [p,q] of cases){"
        "  if(ctx.domId('sd',p)===ctx.domId('sd',q)) bad.push(p+'=='+q);"
        "}"
        # même chemin → même id (déterminisme)
        "if(ctx.domId('sd','a/b')!==ctx.domId('sd','a/b')) bad.push('non-deterministe');"
        # préfixe différencie feuille vs dossier au même chemin
        "if(ctx.domId('fold','a')===ctx.domId('sd','a')) bad.push('prefix-collision');"
        "console.log(JSON.stringify({bad}));"
    )
    out = subprocess.run([node, "-e", harness, vaults_js], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, f"Node a échoué : {out.stderr}"
    result = json.loads(out.stdout.strip().splitlines()[-1])
    assert result["bad"] == [], f"domId non bijectif : {result['bad']}"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
