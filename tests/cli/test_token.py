#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests CLI token — comportementaux (non-complaisant).

Vérifie que chaque commande token appelle le bon outil MCP avec les bons
arguments. Utilise run_cli_mocked() qui intercepte MCPClient.call_tool.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from . import (
    banner, section, check, check_value, check_contains,
    run_cli, run_cli_mocked,
)

_TOKEN_CREATED = {"status": "created", "token": "sk-vault-abc123", "hash_prefix": "abc123", "client_name": "agent-sre", "permissions": ["read"]}
_TOKEN_LIST    = {"status": "ok", "tokens": [{"hash_prefix": "abc123", "client_name": "agent-sre", "permissions": ["read"], "revoked": False, "expired": False}]}
_TOKEN_UPDATED = {"status": "ok", "hash_prefix": "abc123"}
_TOKEN_REVOKED = {"status": "ok", "hash_prefix": "abc123"}


def test_token():
    """Tests comportementaux token — vérifie les appels MCPClient réels."""

    banner("CLI — Tokens : tests comportementaux (non-complaisant)")

    # ── Aide ─────────────────────────────────────────────────────────────────
    section("Aide token")
    r = run_cli(["token", "--help"])
    check_value("token --help exit code", r.exit_code, 0)
    for subcmd in ["create", "list", "update", "revoke"]:
        check_contains(f"Sous-commande '{subcmd}'", r.output, subcmd)

    # ── token create ─────────────────────────────────────────────────────────
    section("token create — appelle token_update (create via admin API, pas outil MCP)")
    # Note : token create n'appelle PAS un outil MCP — il appelle l'API REST /admin/api/tokens
    # via httpx. On vérifie uniquement exit code et parsing des options.
    r = run_cli(["token", "create", "--help"])
    check_value("token create --help exit code", r.exit_code, 0)
    check_contains("Option --permissions", r.output, "--permissions")
    check_contains("Option --vaults", r.output, "--vaults")
    check_contains("Option --expires", r.output, "--expires")
    check_contains("Option --policy", r.output, "--policy")

    # ── token create --expires : contrat expiration #65 (IntRange 0..36500) ────
    section("token create --expires — validation IntRange (issue #65)")
    # Invalides rejetés par Click AVANT tout POST (exit != 0) : négatif, hors borne,
    # non-entier. Empêche l'illimité accidentel via valeur négative et le crash.
    # Contrat STRICT [0-9]+ : négatif, hors borne, non-entier, signe explicite (+5) et
    # chiffre non-ASCII (٥) sont tous rejetés — aligné sur le front (pas de coercition).
    for bad in ["-1", "36501", "abc", "1.5", "+5", "٥"]:
        r = run_cli(["token", "create", "agent-x", "--expires", bad])
        check(f"--expires {bad} rejeté (exit != 0)", r.exit_code != 0)
    # 0 = jamais expirer (illimité EXPLICITE) : accepté et transmis tel quel au POST.
    mock_resp_e = MagicMock()
    mock_resp_e.json.return_value = {"status": "created", "hash": "abc123def456",
                                     "expires_at": None, "client_name": "agent-x"}
    mock_http_e = AsyncMock()
    mock_http_e.post = AsyncMock(return_value=mock_resp_e)
    mock_http_e.__aenter__ = AsyncMock(return_value=mock_http_e)
    mock_http_e.__aexit__ = AsyncMock(return_value=None)
    with patch("httpx.AsyncClient", return_value=mock_http_e):
        r = run_cli(["token", "create", "agent-x", "--expires", "0", "--permissions", "read"])
    check_value("token create --expires 0 exit", r.exit_code, 0)
    call_json_e = mock_http_e.post.call_args[1].get("json", {}) if mock_http_e.post.call_args else {}
    check_value("expires_in_days=0 transmis au POST", call_json_e.get("expires_in_days"), 0)

    # ── token list ────────────────────────────────────────────────────────────
    section("token list — aide et options")
    r = run_cli(["token", "list", "--help"])
    check_value("Exit code", r.exit_code, 0)

    # ── token update (httpx REST, pas MCPClient) ─────────────────────────────
    # token update appelle PUT /admin/api/tokens/{hash} via httpx directement.
    # On mock httpx.AsyncClient pour capturer le body envoyé.

    section("token update --policy — body JSON contient policy_id")
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"status": "ok", "hash_prefix": "abc123"}
    mock_http = AsyncMock()
    mock_http.put = AsyncMock(return_value=mock_resp)
    mock_http.__aenter__ = AsyncMock(return_value=mock_http)
    mock_http.__aexit__ = AsyncMock(return_value=None)

    with patch("httpx.AsyncClient", return_value=mock_http):
        r = run_cli(["token", "update", "abc123", "--policy", "readonly"])
    check_value("Exit code", r.exit_code, 0)
    check("PUT appelé", mock_http.put.called)
    call_json = mock_http.put.call_args[1].get("json", {}) if mock_http.put.call_args else {}
    check_value("policy_id transmis", call_json.get("policy_id"), "readonly")
    check("hash_prefix dans URL", "abc123" in str(mock_http.put.call_args))

    section("token update --policy _remove — policy_id vide (suppression)")
    mock_resp2 = MagicMock()
    mock_resp2.json.return_value = {"status": "ok"}
    mock_http2 = AsyncMock()
    mock_http2.put = AsyncMock(return_value=mock_resp2)
    mock_http2.__aenter__ = AsyncMock(return_value=mock_http2)
    mock_http2.__aexit__ = AsyncMock(return_value=None)

    with patch("httpx.AsyncClient", return_value=mock_http2):
        r = run_cli(["token", "update", "abc123", "--policy", "_remove"])
    check_value("Exit code", r.exit_code, 0)
    call_json2 = mock_http2.put.call_args[1].get("json", {}) if mock_http2.put.call_args else {}
    check_value("policy_id vide (suppression)", call_json2.get("policy_id"), "")

    section("token update --permissions read --vaults prod-vault")
    mock_resp3 = MagicMock()
    mock_resp3.json.return_value = {"status": "ok"}
    mock_http3 = AsyncMock()
    mock_http3.put = AsyncMock(return_value=mock_resp3)
    mock_http3.__aenter__ = AsyncMock(return_value=mock_http3)
    mock_http3.__aexit__ = AsyncMock(return_value=None)

    with patch("httpx.AsyncClient", return_value=mock_http3):
        r = run_cli(["token", "update", "abc123", "--permissions", "read", "--vaults", "prod-vault"])
    check_value("Exit code", r.exit_code, 0)
    call_json3 = mock_http3.put.call_args[1].get("json", {}) if mock_http3.put.call_args else {}
    check("permissions = ['read'] transmis", call_json3.get("permissions") == ["read"])
    check("allowed_resources = ['prod-vault'] transmis", call_json3.get("allowed_resources") == ["prod-vault"])

    # ── token revoke ─────────────────────────────────────────────────────────
    section("token revoke — DELETE /admin/api/tokens/{hash} via httpx")
    mock_resp_r = MagicMock()
    mock_resp_r.json.return_value = {"status": "ok"}
    mock_http_r = AsyncMock()
    mock_http_r.delete = AsyncMock(return_value=mock_resp_r)
    mock_http_r.__aenter__ = AsyncMock(return_value=mock_http_r)
    mock_http_r.__aexit__ = AsyncMock(return_value=None)

    with patch("httpx.AsyncClient", return_value=mock_http_r):
        r = run_cli(["token", "revoke", "abc123"])
    check_value("Exit code", r.exit_code, 0)
    check("DELETE appelé", mock_http_r.delete.called)
    check("hash_prefix dans URL", "abc123" in str(mock_http_r.delete.call_args))


# ═════════════════════════════════════════════════════════════════════════════
# Contrat #65 — compléments portés depuis les tests du shell interactif (#128)
# ═════════════════════════════════════════════════════════════════════════════
#
# La section agrégée ci-dessus couvrait déjà les six valeurs invalides et le cas
# `0` (illimité explicite). Trois invariants n'étaient verrouillés que par
# `tests/cli/test_token_create_shell.py`, supprimé avec le shell : la valeur
# ABSENTE, une borne valide réellement TRANSMISE, et le défaut implicite.
#
# La protection elle-même n'a pas bougé : elle vit dans `_ExpiresDaysType`
# (`scripts/cli/commands.py`), un `click.ParamType` sans coercition. Seule la
# couverture change de surface.

def _poste_token(argv):
    """Exécute `token create` en interceptant le POST réellement émis."""
    resp = MagicMock()
    resp.json.return_value = {"status": "created", "hash": "abc123def456",
                              "expires_at": None, "client_name": "agent-x"}
    http = AsyncMock()
    http.post = AsyncMock(return_value=resp)
    http.__aenter__ = AsyncMock(return_value=http)
    http.__aexit__ = AsyncMock(return_value=None)
    with patch("httpx.AsyncClient", return_value=http):
        r = run_cli(argv)
    envoye = http.post.call_args[1].get("json", {}) if http.post.call_args else None
    return r, envoye


def test_token_create_expires_valeur_absente_ne_poste_rien():
    """
    FAIL-CLOSE : `--expires` sans valeur ne doit produire AUCUN POST. Une
    expiration devinée créerait un jeton de durée de vie différente de celle
    demandée — le cas que tout le contrat #65 cherche à empêcher.
    """
    r, envoye = _poste_token(["token", "create", "agent-x", "--expires"])
    assert r.exit_code != 0
    assert envoye is None, f"POST émis malgré une expiration absente : {envoye}"


def test_token_create_expires_borne_valide_transmise():
    """Une valeur valide doit atteindre l'API telle quelle, sans réinterprétation."""
    r, envoye = _poste_token(["token", "create", "agent-x", "--expires", "365",
                              "--permissions", "read"])
    assert r.exit_code == 0
    assert envoye.get("expires_in_days") == 365


def test_token_create_sans_expires_defaut_90():
    """
    Le défaut implicite est 90 jours, pas « illimité ». Un défaut permissif
    créerait des jetons éternels à chaque oubli de l'option.
    """
    r, envoye = _poste_token(["token", "create", "agent-x", "--permissions", "read"])
    assert r.exit_code == 0
    assert envoye.get("expires_in_days") == 90
