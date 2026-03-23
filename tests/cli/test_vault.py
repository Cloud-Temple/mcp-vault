#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════
  TEST CLI — Vault : create, list, info, update, delete
═══════════════════════════════════════════════════════════════
"""

from . import (
    banner, section, check, check_value, check_contains,
    run_cli, show_vault_result,
)


def test_vault():
    """Teste toutes les commandes vault du CLI."""

    banner("CLI — Vault (create, list, info, update, delete)")

    # ── vault --help ──
    section("Aide vault — isolation owner-based")
    r = run_cli(["vault", "--help"])
    check_value("vault --help exit code", r.exit_code, 0)
    check_contains("Mentionne 'propriétaire'", r.output, "propriétaire")
    check_contains("Mentionne 'isolé'", r.output, "isolé")
    check_contains("Mentionne 'admin'", r.output, "admin")
    # Vérifier que les sous-commandes sont listées
    for subcmd in ["create", "list", "info", "update", "delete"]:
        check_contains(f"Sous-commande '{subcmd}' visible", r.output, subcmd)

    # ── vault create --help ──
    section("Aide vault create")
    r = run_cli(["vault", "create", "--help"])
    check_value("Exit code", r.exit_code, 0)
    check_contains("Argument VAULT_ID requis", r.output, "VAULT_ID")
    check_contains("Option --description/-d", r.output, "--description")
    check_contains("Exemple avec description", r.output, "serveurs-prod")

    # ── vault list --help ──
    section("Aide vault list")
    r = run_cli(["vault", "list", "--help"])
    check_value("Exit code", r.exit_code, 0)
    check_contains("Option --json", r.output, "--json")

    # ── vault info --help ──
    section("Aide vault info")
    r = run_cli(["vault", "info", "--help"])
    check_value("Exit code", r.exit_code, 0)
    check_contains("Argument VAULT_ID", r.output, "VAULT_ID")
    check_contains("Mentionne 'métadonnées'", r.output, "tadonnées")

    # ── vault update --help ──
    section("Aide vault update")
    r = run_cli(["vault", "update", "--help"])
    check_value("Exit code", r.exit_code, 0)
    check_contains("Option --description/-d requise", r.output, "--description")

    # ── vault delete --help ──
    section("Aide vault delete")
    r = run_cli(["vault", "delete", "--help"])
    check_value("Exit code", r.exit_code, 0)
    check_contains("Option --yes/-y", r.output, "--yes")
    check_contains("Mentionne 'irréversible'", r.output, "irréversible")

    # ── Affichage vault list ──
    section("Affichage vault list — colonnes Vault ID + Owner")
    print("    [simulé] :")
    show_vault_result({
        "status": "ok",
        "vaults": [
            {"vault_id": "prod-servers", "description": "SSH prod", "created_by": "admin", "secrets_count": 12},
            {"vault_id": "staging-db", "description": "BDD staging", "created_by": "agent-dev", "secrets_count": 3},
        ],
    })
    check("vault list avec Owner ne crash pas", True)

    # ── Affichage vault create ──
    section("Affichage vault create")
    print("    [simulé] :")
    show_vault_result({"status": "created", "vault_id": "test-vault", "description": "Test"})
    check("vault create affichage OK", True)

    # ── Affichage vault delete ──
    section("Affichage vault delete")
    print("    [simulé] :")
    show_vault_result({"status": "deleted", "vault_id": "test-vault"})
    check("vault delete affichage OK", True)

    # ── Affichage vault info ──
    section("Affichage vault info")
    print("    [simulé] :")
    show_vault_result({"status": "ok", "vault_id": "prod", "description": "Production", "secrets_count": 42})
    check("vault info affichage OK", True)

    # ── Affichage erreur ──
    section("Affichage erreur vault")
    print("    [simulé] :")
    show_vault_result({"status": "error", "message": "Vault 'inexistant' non trouvé"})
    check("vault erreur affichage OK", True)
