#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests CLI secret — comportementaux (non-complaisant).

Vérifie que chaque commande secret appelle le bon outil MCP avec les bons
arguments. Utilise run_cli_mocked() qui intercepte MCPClient.call_tool.
"""

import pytest

from . import (
    banner, section, check, check_value, check_contains,
    run_cli, run_cli_mocked,
)

_SECRET_WRITTEN  = {"status": "ok", "vault_id": "mon-vault", "path": "db/postgres", "version": 1}
_SECRET_READ     = {"status": "ok", "vault_id": "mon-vault", "path": "db/postgres", "data": {"host": "db.ct.com", "username": "admin"}, "version": 1}
_SECRET_LIST     = {"status": "ok", "vault_id": "mon-vault", "keys": ["db/postgres", "db/mysql"]}
_SECRET_DELETED  = {"status": "ok", "vault_id": "mon-vault", "path": "db/postgres"}
_SECRET_TYPES    = {"status": "ok", "types": [{"name": "login"}, {"name": "database"}]}
_SECRET_PASSWORD = {"status": "ok", "password": "Xk9#mP2!", "length": 32}
_WRAP_OK         = {"status": "ok", "wrap_token": "hvs.SENSIBLE", "accessor": "ACC1",
                    "operation_id": "op-1", "mission_id": "m-1", "expires_at": "2026-06-11T10:00:00Z"}
_REVOKE_OK       = {"status": "ok", "state": "revoked"}
_LOOKUP_OK       = {"status": "ok", "state": "revoked", "count_revoked": 1, "entries_found": 1}


def test_secret():
    """Tests comportementaux secret — vérifie les appels MCPClient réels."""

    banner("CLI — Secrets : tests comportementaux (non-complaisant)")

    # ── Aide ─────────────────────────────────────────────────────────────────
    section("Aide secret")
    r = run_cli(["secret", "--help"])
    check_value("secret --help exit code", r.exit_code, 0)
    for subcmd in ["write", "read", "list", "delete", "types", "password",
                   "wrap", "revoke-wrap", "wrap-lookup"]:
        check_contains(f"Sous-commande '{subcmd}'", r.output, subcmd)

    # ── secret write ─────────────────────────────────────────────────────────
    section("secret write — appelle secret_write avec vault_id, path, data, type")
    r, mock = run_cli_mocked(
        ["secret", "write", "mon-vault", "db/postgres",
         "-d", '{"host":"db.ct.com","username":"admin"}', "-t", "database"],
        _SECRET_WRITTEN,
    )
    check_value("Exit code", r.exit_code, 0)
    args = mock.call_args[0][1] if mock.call_args else {}
    check("secret_write appelé", mock.call_args is not None and mock.call_args[0][0] == "secret_write")
    check_value("vault_id correct", args.get("vault_id"), "mon-vault")
    check_value("path correct", args.get("path"), "db/postgres")
    check_value("secret_type correct", args.get("secret_type"), "database")  # param = secret_type, pas type
    check("data transmis", isinstance(args.get("data"), dict) and "host" in args.get("data", {}))

    section("secret write avec JSON invalide — rejeté avant appel MCP")
    r, mock = run_cli_mocked(
        ["secret", "write", "mon-vault", "db/test", "-d", "pas_du_json"],
        _SECRET_WRITTEN,
    )
    check_value("Exit code 0 (erreur affichée proprement)", r.exit_code, 0)
    check("secret_write NON appelé pour JSON invalide", not mock.called)

    # ── secret read ──────────────────────────────────────────────────────────
    section("secret read — appelle secret_read avec vault_id et path")
    r, mock = run_cli_mocked(["secret", "read", "mon-vault", "db/postgres"], _SECRET_READ)
    check_value("Exit code", r.exit_code, 0)
    args = mock.call_args[0][1] if mock.call_args else {}
    check("secret_read appelé", mock.call_args is not None and mock.call_args[0][0] == "secret_read")
    check_value("vault_id correct", args.get("vault_id"), "mon-vault")
    check_value("path correct", args.get("path"), "db/postgres")

    section("secret read -v 2 — version transmise")
    r, mock = run_cli_mocked(["secret", "read", "mon-vault", "db/postgres", "-v", "2"], _SECRET_READ)
    check_value("Exit code", r.exit_code, 0)
    args = mock.call_args[0][1] if mock.call_args else {}
    check_value("version=2 transmise", args.get("version"), 2)

    # ── secret list ───────────────────────────────────────────────────────────
    section("secret list — appelle secret_list avec vault_id")
    r, mock = run_cli_mocked(["secret", "list", "mon-vault"], _SECRET_LIST)
    check_value("Exit code", r.exit_code, 0)
    args = mock.call_args[0][1] if mock.call_args else {}
    check("secret_list appelé", mock.call_args is not None and mock.call_args[0][0] == "secret_list")
    check_value("vault_id correct", args.get("vault_id"), "mon-vault")

    # ── secret delete ─────────────────────────────────────────────────────────
    section("secret delete sans --yes — click.confirm abort (exit 1), call_tool NON appelé")
    r, mock = run_cli_mocked(["secret", "delete", "mon-vault", "db/postgres"], _SECRET_DELETED)
    check_value("Exit code 1 (abort)", r.exit_code, 1)
    check("secret_delete NON appelé sans confirmation", not mock.called)

    section("secret delete --yes — appelle secret_delete")
    r, mock = run_cli_mocked(["secret", "delete", "mon-vault", "db/postgres", "--yes"], _SECRET_DELETED)
    check_value("Exit code", r.exit_code, 0)
    args = mock.call_args[0][1] if mock.call_args else {}
    check("secret_delete appelé", mock.call_args is not None and mock.call_args[0][0] == "secret_delete")
    check_value("vault_id correct", args.get("vault_id"), "mon-vault")
    check_value("path correct", args.get("path"), "db/postgres")

    # ── secret types ──────────────────────────────────────────────────────────
    section("secret types — appelle secret_types sans args")
    r, mock = run_cli_mocked(["secret", "types"], _SECRET_TYPES)
    check_value("Exit code", r.exit_code, 0)
    check("secret_types appelé", mock.call_args is not None and mock.call_args[0][0] == "secret_types")
    check_value("Aucun argument passé", mock.call_args[0][1], {})

    # ── secret password ───────────────────────────────────────────────────────
    section("secret password -l 32 — appelle secret_generate_password avec length=32")
    r, mock = run_cli_mocked(["secret", "password", "-l", "32"], _SECRET_PASSWORD)
    check_value("Exit code", r.exit_code, 0)
    args = mock.call_args[0][1] if mock.call_args else {}
    check("secret_generate_password appelé", mock.call_args is not None and mock.call_args[0][0] == "secret_generate_password")
    check_value("length=32 transmis", args.get("length"), 32)

    section("secret password — longueur défaut (sans -l)")
    r, mock = run_cli_mocked(["secret", "password"], _SECRET_PASSWORD)
    check_value("Exit code", r.exit_code, 0)
    check("secret_generate_password appelé", mock.called)

    # ── secret wrap ───────────────────────────────────────────────────────────
    section("secret wrap — appelle secret_wrap avec binding C18")
    r, mock = run_cli_mocked(
        ["secret", "wrap", "prod", "db/pg", "--mission-id", "m-1",
         "--operation-id", "op-1", "--ttl", "600",
         "--tenant-id", "t-7", "--expected-aud", "mcp-vault:prod"],
        _WRAP_OK,
    )
    check_value("Exit code", r.exit_code, 0)
    args = mock.call_args[0][1] if mock.call_args else {}
    check("secret_wrap appelé", mock.call_args is not None and mock.call_args[0][0] == "secret_wrap")
    check_value("vault_id correct", args.get("vault_id"), "prod")
    check_value("secret_path correct", args.get("secret_path"), "db/pg")
    check_value("mission_id transmis", args.get("mission_id"), "m-1")
    check_value("operation_id transmis", args.get("operation_id"), "op-1")
    check_value("ttl_seconds transmis", args.get("ttl_seconds"), 600)
    check_value("tenant_id transmis (binding C18)", args.get("tenant_id"), "t-7")
    check_value("expected_aud transmis (binding C18)", args.get("expected_aud"), "mcp-vault:prod")

    # ── secret revoke-wrap ──────────────────────────────────────────────────────
    section("secret revoke-wrap — appelle secret_revoke_wrap avec lease_id")
    r, mock = run_cli_mocked(["secret", "revoke-wrap", "ACC-XYZ"], _REVOKE_OK)
    check_value("Exit code", r.exit_code, 0)
    args = mock.call_args[0][1] if mock.call_args else {}
    check("secret_revoke_wrap appelé", mock.call_args is not None and mock.call_args[0][0] == "secret_revoke_wrap")
    check_value("lease_id transmis", args.get("lease_id"), "ACC-XYZ")

    # ── secret wrap-lookup ──────────────────────────────────────────────────────
    section("secret wrap-lookup — transmet le COUPLE (operation_id, mission_id)")
    r, mock = run_cli_mocked(
        ["secret", "wrap-lookup", "op-42", "--mission-id", "m-42"], _LOOKUP_OK)
    check_value("Exit code", r.exit_code, 0)
    args = mock.call_args[0][1] if mock.call_args else {}
    check("secret_wrap_lookup appelé", mock.call_args is not None and mock.call_args[0][0] == "secret_wrap_lookup")
    check_value("operation_id transmis", args.get("operation_id"), "op-42")
    # Cloisonnement inter-missions : la mission DOIT être transmise. Sans cette
    # vérification, une CLI qui l'oublierait rouvrirait la révocation croisée.
    check_value("mission_id transmis", args.get("mission_id"), "m-42")

    # ── Non-complaisant : la mission est OBLIGATOIRE sur un chemin destructif ────
    section("secret wrap-lookup — refuse sans --mission-id (outil destructif)")
    r_sans, mock_sans = run_cli_mocked(["secret", "wrap-lookup", "op-42"], _LOOKUP_OK)
    check("Exit code non nul sans mission", r_sans.exit_code != 0)
    check("secret_wrap_lookup NON appelé sans mission", mock_sans.call_args is None)

    # ── secret wrap-status ──────────────────────────────────────────────────────
    section("secret wrap-status — transmet le COUPLE et exige --mission-id")
    r, mock = run_cli_mocked(
        ["secret", "wrap-status", "op-42", "--mission-id", "m-42"], _LOOKUP_OK)
    check_value("Exit code", r.exit_code, 0)
    args = mock.call_args[0][1] if mock.call_args else {}
    check("secret_wrap_status appelé", mock.call_args is not None and mock.call_args[0][0] == "secret_wrap_status")
    check_value("operation_id transmis", args.get("operation_id"), "op-42")
    check_value("mission_id transmis", args.get("mission_id"), "m-42")

    r_sans, mock_sans = run_cli_mocked(["secret", "wrap-status", "op-42"], _LOOKUP_OK)
    check("Exit code non nul sans mission (status)", r_sans.exit_code != 0)
    check("secret_wrap_status NON appelé sans mission", mock_sans.call_args is None)

    # ── Non-complaisant : wrap_token jamais dans l'affichage stdout en clair sans alerte ─
    section("secret wrap — wrap_token affiché avec alerte SENSIBLE")
    r, mock = run_cli_mocked(
        ["secret", "wrap", "prod", "db/pg", "--mission-id", "m-1", "--operation-id", "op-1"],
        _WRAP_OK,
    )
    check_contains("Alerte SENSIBLE présente", r.output, "SENSIBLE")

    # ── Erreur propagée ───────────────────────────────────────────────────────
    section("secret read — erreur propagée sans crash")
    r, mock = run_cli_mocked(
        ["secret", "read", "vault-inexistant", "path/inexistante"],
        {"status": "error", "message": "Vault non trouvé"},
    )
    check_value("Exit code 0 même en erreur", r.exit_code, 0)
    check("secret_read bien appelé", mock.called)
