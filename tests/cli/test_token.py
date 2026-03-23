#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════
  TEST CLI — Token : create, list, update, revoke + --policy
═══════════════════════════════════════════════════════════════
"""

from . import (
    banner, section, check, check_value, check_contains,
    run_cli, show_token_result, show_policy_result,
)


def test_token():
    """Teste toutes les commandes token du CLI."""

    banner("CLI — Token (create, list, update, revoke)")

    # ── token --help ──
    section("Aide token — owner-based par défaut")
    r = run_cli(["token", "--help"])
    check_value("token --help exit code", r.exit_code, 0)
    check_contains("Mentionne 'owner-based'", r.output, "owner-based")
    check_contains("Mentionne '--policy'", r.output, "--policy")
    for subcmd in ["create", "list", "update", "revoke"]:
        check_contains(f"Sous-commande '{subcmd}'", r.output, subcmd)

    # ── token create --help ──
    section("Aide token create — --policy et --vaults")
    r = run_cli(["token", "create", "--help"])
    check_value("Exit code", r.exit_code, 0)
    check_contains("Argument NAME", r.output, "NAME")
    check_contains("Option --permissions/-p", r.output, "--permissions")
    check_contains("Option --vaults/-s (owner-based)", r.output, "owner-based")
    check_contains("Option --policy", r.output, "--policy")
    check_contains("Option --expires/-e", r.output, "--expires")
    check_contains("Option --email", r.output, "--email")
    # Exemples pédagogiques
    check_contains("Exemple agent-sre", r.output, "agent-sre")
    check_contains("Exemple --policy readonly", r.output, "readonly")
    check_contains("Explication vaults vide", r.output, "vaults qu'il crée")

    # ── token list --help ──
    section("Aide token list")
    r = run_cli(["token", "list", "--help"])
    check_value("Exit code", r.exit_code, 0)

    # ── token update --help ──
    section("Aide token update")
    r = run_cli(["token", "update", "--help"])
    check_value("Exit code", r.exit_code, 0)
    check_contains("Argument HASH_PREFIX", r.output, "HASH_PREFIX")
    check_contains("Option --policy", r.output, "--policy")
    check_contains("Option --permissions", r.output, "--permissions")
    check_contains("Option --vaults", r.output, "--vaults")
    check_contains("Exemple _remove", r.output, "_remove")

    # ── token revoke --help ──
    section("Aide token revoke")
    r = run_cli(["token", "revoke", "--help"])
    check_value("Exit code", r.exit_code, 0)
    check_contains("Argument HASH_PREFIX", r.output, "HASH_PREFIX")

    # ═══════════════════════════════════════════════════════════════
    # Tests d'affichage des tokens
    # ═══════════════════════════════════════════════════════════════

    section("Affichage token create — avec policy")
    print("    [simulé] :")
    show_token_result({
        "status": "created",
        "raw_token": "mvt_abc123def456ghi789jkl012mno345",
        "client_name": "agent-deploy",
        "permissions": ["read", "write"],
        "allowed_resources": ["prod-app"],
        "policy_id": "readonly-paths",
        "expires_at": "2026-06-23T10:00:00",
    })
    check("token create avec policy ne crash pas", True)

    section("Affichage token create — owner-based (vaults vide)")
    print("    [simulé] :")
    show_token_result({
        "status": "created",
        "raw_token": "mvt_xyz987uvw654rst321qpo098nml765",
        "client_name": "agent-libre",
        "permissions": ["read", "write"],
        "allowed_resources": [],
        "expires_at": None,
    })
    check("token create owner-based ne crash pas", True)

    section("Affichage token list — colonne Policy + Vaults")
    print("    [simulé] :")
    show_token_result({
        "status": "ok",
        "tokens": [
            {"client_name": "admin", "permissions": ["read", "write", "admin"],
             "allowed_resources": [], "policy_id": "", "expires_at": None, "hash_prefix": "abc12345"},
            {"client_name": "agent-sre", "permissions": ["read"],
             "allowed_resources": ["prod"], "policy_id": "readonly", "expires_at": "2026-06-23", "hash_prefix": "def67890"},
            {"client_name": "agent-old", "permissions": ["read"],
             "allowed_resources": [], "policy_id": "", "expires_at": "2026-01-01",
             "hash_prefix": "ghi11111", "revoked": True},
        ],
    })
    check("token list avec Policy ne crash pas", True)

    section("Affichage token revoke")
    print("    [simulé] :")
    show_token_result({"status": "ok", "message": "Token def67890... révoqué"})
    check("token revoke affichage OK", True)

    section("Affichage token update (via show_policy_result)")
    print("    [simulé] :")
    show_policy_result({
        "status": "updated",
        "client_name": "agent-sre",
        "hash_prefix": "def67890",
        "updated_fields": ["policy_id", "permissions"],
        "policy_id": "readonly-paths",
        "permissions": ["read"],
    })
    check("token update affichage OK", True)
