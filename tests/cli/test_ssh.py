#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════
  TEST CLI — SSH CA : setup, sign, ca-key, roles, role-info
═══════════════════════════════════════════════════════════════
"""

from . import (
    banner, section, check, check_value, check_contains,
    run_cli, show_ssh_result,
)


def test_ssh():
    """Teste toutes les commandes SSH CA du CLI."""

    banner("CLI — SSH CA (setup, sign, ca-key, roles, role-info)")

    # ── ssh --help ──
    section("Aide ssh — groupe principal")
    r = run_cli(["ssh", "--help"])
    check_value("ssh --help exit code", r.exit_code, 0)
    check_contains("Mentionne 'Certificate Authority'", r.output, "Certificate Authority")
    for subcmd in ["setup", "sign", "ca-key", "roles", "role-info"]:
        check_contains(f"Sous-commande '{subcmd}' visible", r.output, subcmd)

    # ── ssh setup --help ──
    section("Aide ssh setup")
    r = run_cli(["ssh", "setup", "--help"])
    check_value("Exit code", r.exit_code, 0)
    check_contains("Argument VAULT_ID", r.output, "VAULT_ID")
    check_contains("Argument ROLE_NAME", r.output, "ROLE_NAME")
    check_contains("Option --users", r.output, "--users")
    check_contains("Option --ttl", r.output, "--ttl")
    check_contains("Option --default-user", r.output, "--default-user")

    # ── ssh sign --help ──
    section("Aide ssh sign")
    r = run_cli(["ssh", "sign", "--help"])
    check_value("Exit code", r.exit_code, 0)
    check_contains("Option --key/-k (fichier)", r.output, "--key")
    check_contains("Option --key-data (texte)", r.output, "--key-data")
    check_contains("Mentionne 'certificat éphémère'", r.output, "certificat")

    # ── ssh ca-key --help ──
    section("Aide ssh ca-key")
    r = run_cli(["ssh", "ca-key", "--help"])
    check_value("Exit code", r.exit_code, 0)
    check_contains("Mentionne 'TrustedUserCAKeys'", r.output, "TrustedUserCAKeys")

    # ── ssh roles --help ──
    section("Aide ssh roles")
    r = run_cli(["ssh", "roles", "--help"])
    check_value("Exit code", r.exit_code, 0)
    check_contains("Argument VAULT_ID", r.output, "VAULT_ID")

    # ── ssh role-info --help ──
    section("Aide ssh role-info")
    r = run_cli(["ssh", "role-info", "--help"])
    check_value("Exit code", r.exit_code, 0)
    check_contains("Argument ROLE_NAME", r.output, "ROLE_NAME")

    # ── Affichage SSH setup ──
    section("Affichage ssh setup")
    print("    [simulé] :")
    show_ssh_result({
        "status": "ok", "vault_id": "infra", "role_name": "sre-role",
        "mount_point": "ssh-ca-infra", "allowed_users": "deploy,admin",
        "default_user": "ubuntu", "ttl": "15m",
    })
    check("ssh setup affichage OK", True)

    # ── Affichage SSH roles ──
    section("Affichage ssh roles")
    print("    [simulé] :")
    show_ssh_result({"status": "ok", "vault_id": "infra", "count": 2, "roles": ["sre-role", "dev-role"]})
    check("ssh roles affichage OK", True)

    # ── Affichage SSH role-info ──
    section("Affichage ssh role-info")
    print("    [simulé] :")
    show_ssh_result({
        "status": "ok", "vault_id": "infra", "role_name": "sre-role",
        "key_type": "ca", "ttl": "900", "max_ttl": "3600",
        "default_user": "ubuntu", "allowed_users": "deploy,admin",
        "allowed_extensions": "", "allow_user_certificates": True, "allow_host_certificates": False,
    })
    check("ssh role-info affichage OK", True)

    # ── Affichage SSH ca-key ──
    section("Affichage ssh ca-key")
    print("    [simulé] :")
    show_ssh_result({
        "status": "ok", "ca_public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake...",
        "usage": "Ajouter à TrustedUserCAKeys dans sshd_config",
    })
    check("ssh ca-key affichage OK", True)
