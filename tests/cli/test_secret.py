#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════
  TEST CLI — Secret : write, read, list, delete, types, password
═══════════════════════════════════════════════════════════════
"""

from . import (
    banner, section, check, check_value, check_contains,
    run_cli, show_secret_result, show_types_result, show_password_result,
)


def test_secret():
    """Teste toutes les commandes secret du CLI."""

    banner("CLI — Secret (write, read, list, delete, types, password)")

    # ── secret --help ──
    section("Aide secret — groupe principal")
    r = run_cli(["secret", "--help"])
    check_value("secret --help exit code", r.exit_code, 0)
    check_contains("Mentionne '14 types'", r.output, "14 types")
    check_contains("Mentionne '1Password'", r.output, "1Password")
    for subcmd in ["write", "read", "list", "delete", "types", "password"]:
        check_contains(f"Sous-commande '{subcmd}' visible", r.output, subcmd)

    # ── secret write --help ──
    section("Aide secret write")
    r = run_cli(["secret", "write", "--help"])
    check_value("Exit code", r.exit_code, 0)
    check_contains("Argument VAULT_ID", r.output, "VAULT_ID")
    check_contains("Argument PATH", r.output, "PATH")
    check_contains("Option --data/-d requis", r.output, "--data")
    check_contains("Option --type/-t", r.output, "--type")
    check_contains("Exemple login", r.output, "login")

    # ── secret read --help ──
    section("Aide secret read")
    r = run_cli(["secret", "read", "--help"])
    check_value("Exit code", r.exit_code, 0)
    check_contains("Option --version/-v", r.output, "--version")

    # ── secret list --help ──
    section("Aide secret list")
    r = run_cli(["secret", "list", "--help"])
    check_value("Exit code", r.exit_code, 0)
    check_contains("Option --prefix/-p", r.output, "--prefix")
    check_contains("Mentionne 'pas les valeurs'", r.output, "pas les valeurs")

    # ── secret delete --help ──
    section("Aide secret delete")
    r = run_cli(["secret", "delete", "--help"])
    check_value("Exit code", r.exit_code, 0)
    check_contains("Option --yes/-y", r.output, "--yes")
    check_contains("Mentionne 'irréversible'", r.output, "irréversible")

    # ── secret types --help ──
    section("Aide secret types")
    r = run_cli(["secret", "types", "--help"])
    check_value("Exit code", r.exit_code, 0)
    check_contains("Mentionne '14 types'", r.output, "14 types")

    # ── secret password --help ──
    section("Aide secret password")
    r = run_cli(["secret", "password", "--help"])
    check_value("Exit code", r.exit_code, 0)
    check_contains("Option --length/-l", r.output, "--length")
    check_contains("Option --no-symbols", r.output, "--no-symbols")
    check_contains("Mentionne 'CSPRNG'", r.output, "CSPRNG")

    # ── Validation --data JSON invalide ──
    section("Validation JSON — --data invalide")
    r = run_cli([
        "--url", "http://localhost:0", "--token", "fake",
        "secret", "write", "test-vault", "test/key",
        "--data", "pas-du-json",
    ])
    check_contains("JSON invalide détecté", r.output, "JSON invalide")

    # ── Affichage secret read ──
    section("Affichage secret read — masquage des passwords")
    print("    [simulé] :")
    show_secret_result({
        "status": "ok", "path": "web/github", "version": 3,
        "data": {"_type": "login", "username": "admin", "password": "SuperSecret123!", "_created_at": "2026-03-23"},
    })
    check("secret read avec masquage ne crash pas", True)

    # ── Affichage secret write ──
    section("Affichage secret write")
    print("    [simulé] :")
    show_secret_result({"status": "ok", "path": "web/github", "version": 1, "type": "login"})
    check("secret write affichage OK", True)

    # ── Affichage secret list ──
    section("Affichage secret list")
    print("    [simulé] :")
    show_secret_result({"status": "ok", "vault_id": "prod", "keys": ["web/github", "db/postgres", "ssh/deploy"]})
    check("secret list affichage OK", True)

    # ── Affichage secret delete ──
    section("Affichage secret delete")
    print("    [simulé] :")
    show_secret_result({"status": "deleted", "path": "web/old-key"})
    check("secret delete affichage OK", True)

    # ── Affichage types ──
    section("Affichage secret types")
    print("    [simulé] :")
    show_types_result({"types": [
        {"type": "login", "required": ["username", "password"], "optional": ["url", "notes"]},
        {"type": "database", "required": ["host", "username", "password"], "optional": ["port", "database"]},
    ]})
    check("types affichage OK", True)

    # ── Affichage password ──
    section("Affichage password")
    print("    [simulé] :")
    show_password_result({"status": "ok", "password": "xK#9mP$2vL!qR7nW@3hJ5bY8", "length": 24})
    check("password affichage OK", True)
