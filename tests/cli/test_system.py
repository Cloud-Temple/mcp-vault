#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════
  TEST CLI — Commandes système : health, about, whoami
═══════════════════════════════════════════════════════════════
"""

from . import (
    banner, section, check, check_value, check_contains,
    run_cli, show_whoami_result,
)


def test_system():
    """Teste les commandes système du CLI."""

    banner("CLI — Commandes système (health, about, whoami)")

    # ── health --help ──
    section("Aide health")
    r = run_cli(["health", "--help"])
    check_value("health --help exit code", r.exit_code, 0)
    check_contains("health mentionne 'santé'", r.output, "santé")
    check_contains("health mentionne '--json'", r.output, "--json")

    # ── about --help ──
    section("Aide about")
    r = run_cli(["about", "--help"])
    check_value("about --help exit code", r.exit_code, 0)
    check_contains("about mentionne 'Informations'", r.output, "Informations")

    # ── whoami --help ──
    section("Aide whoami")
    r = run_cli(["whoami", "--help"])
    check_value("whoami --help exit code", r.exit_code, 0)
    check_contains("whoami mentionne 'Identité'", r.output, "Identité")
    check_contains("whoami mentionne 'permissions'", r.output, "permissions")

    # ── Affichage whoami avec policy ──
    section("Affichage whoami — avec policy_id")
    print("    [simulé] :")
    show_whoami_result({
        "status": "ok",
        "client_name": "agent-sre",
        "auth_type": "token",
        "permissions": ["read", "write"],
        "allowed_resources": ["prod-servers"],
        "policy_id": "readonly-paths",
    })
    check("whoami avec policy_id ne crash pas", True)

    # ── Affichage whoami owner-based ──
    section("Affichage whoami — owner-based (vaults vide)")
    print("    [simulé] :")
    show_whoami_result({
        "status": "ok",
        "client_name": "agent-dev",
        "auth_type": "token",
        "permissions": ["read", "write"],
        "allowed_resources": [],
    })
    check("whoami owner-based ne crash pas", True)

    # ── Aide racine — 3 couches de sécurité ──
    section("Aide racine — modèle de sécurité à 3 couches")
    r = run_cli(["--help"])
    check_value("--help exit code", r.exit_code, 0)
    check_contains("Aide mentionne 'Owner-based'", r.output, "Owner-based")
    check_contains("Aide mentionne 'Vault-level'", r.output, "Vault-level")
    check_contains("Aide mentionne 'Path-level'", r.output, "Path-level")

    # Vérifier que toutes les commandes principales sont listées
    section("Commandes principales visibles dans l'aide")
    for cmd in ["health", "about", "whoami", "vault", "secret", "ssh", "policy", "token", "audit", "shell"]:
        check_contains(f"Commande '{cmd}' visible", r.output, cmd)
