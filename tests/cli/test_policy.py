#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════
  TEST CLI — Policy : create, list, get, delete + path_rules
═══════════════════════════════════════════════════════════════

  C'est le fichier le plus critique : il valide que les path_rules
  (allowed_paths, vault_pattern, permissions) sont correctement
  gérées par le CLI.
"""

import json
from . import (
    banner, section, check, check_value, check_contains, check_not_contains,
    run_cli, show_policy_result,
)


def test_policy():
    """Teste toutes les commandes policy du CLI, y compris path_rules."""

    banner("CLI — Policy (create, list, get, delete + path_rules)")

    # ── policy --help ──
    section("Aide policy — 3 niveaux d'accès")
    r = run_cli(["policy", "--help"])
    check_value("policy --help exit code", r.exit_code, 0)
    check_contains("Mentionne 'allowed_tools'", r.output, "allowed_tools")
    check_contains("Mentionne 'denied_tools'", r.output, "denied_tools")
    check_contains("Mentionne 'path_rules'", r.output, "path_rules")
    check_contains("Mentionne 'TOUJOURS prioritaires'", r.output, "TOUJOURS prioritaires")
    for subcmd in ["create", "list", "get", "delete"]:
        check_contains(f"Sous-commande '{subcmd}'", r.output, subcmd)

    # ── policy create --help ──
    section("Aide policy create — options et exemples")
    r = run_cli(["policy", "create", "--help"])
    check_value("Exit code", r.exit_code, 0)
    check_contains("Argument POLICY_ID", r.output, "POLICY_ID")
    check_contains("Option --allowed/-a", r.output, "--allowed")
    check_contains("Option --denied/-D (PRIORITAIRE)", r.output, "PRIORITAIRE")
    check_contains("Option --path-rules/-R", r.output, "--path-rules")
    check_contains("Exemple vault_pattern", r.output, "vault_pattern")
    check_contains("Exemple allowed_paths", r.output, "allowed_paths")
    check_contains("Exemple permissions", r.output, "permissions")
    check_contains("Documentation fnmatch", r.output, "fnmatch")
    # Vérifier les exemples concrets
    check_contains("Exemple readonly", r.output, "readonly")
    check_contains("Exemple no-ssh", r.output, "no-ssh")
    check_contains("Exemple team-alice", r.output, "team-alice")

    # ── policy list --help ──
    section("Aide policy list")
    r = run_cli(["policy", "list", "--help"])
    check_value("Exit code", r.exit_code, 0)

    # ── policy get --help ──
    section("Aide policy get")
    r = run_cli(["policy", "get", "--help"])
    check_value("Exit code", r.exit_code, 0)
    check_contains("Mentionne 'path rules'", r.output, "path rules")

    # ── policy delete --help ──
    section("Aide policy delete")
    r = run_cli(["policy", "delete", "--help"])
    check_value("Exit code", r.exit_code, 0)
    check_contains("Option --yes/-y", r.output, "--yes")
    check_contains("Mentionne 'irréversible'", r.output, "irréversible")

    # ═══════════════════════════════════════════════════════════════
    # Tests de validation JSON --path-rules
    # C'est ici que la sécurité se joue : le CLI doit REFUSER
    # un JSON malformé AVANT de l'envoyer au serveur.
    # ═══════════════════════════════════════════════════════════════

    section("Validation JSON — --path-rules invalide (pas du JSON)")
    r = run_cli([
        "--url", "http://localhost:0", "--token", "fake",
        "policy", "create", "test-bad",
        "--path-rules", "ceci-nest-pas-du-json",
    ])
    check_contains("JSON invalide détecté", r.output, "JSON invalide")

    section("Validation JSON — --path-rules pas un tableau")
    r = run_cli([
        "--url", "http://localhost:0", "--token", "fake",
        "policy", "create", "test-obj",
        "--path-rules", '{"vault_pattern":"*"}',
    ])
    check_contains("Doit être un tableau JSON", r.output, "tableau JSON")

    section("Validation JSON — --path-rules valide")
    valid_rules = json.dumps([{
        "vault_pattern": "shared-*",
        "permissions": ["read", "write"],
        "allowed_paths": ["shared/*", "config/*"],
    }])
    r = run_cli([
        "--url", "http://localhost:0", "--token", "fake",
        "policy", "create", "test-ok",
        "--allowed", "secret_*,vault_list",
        "--denied", "vault_delete",
        "--path-rules", valid_rules,
    ])
    check_not_contains("Pas d'erreur JSON", r.output, "JSON invalide")
    check_not_contains("Pas d'erreur tableau", r.output, "tableau JSON")

    section("Validation JSON — --path-rules complexe (2 règles)")
    complex_rules = json.dumps([
        {"vault_pattern": "prod-*", "permissions": ["read"], "allowed_paths": ["shared/*"]},
        {"vault_pattern": "dev-*", "permissions": ["read", "write"], "allowed_paths": []},
    ])
    r = run_cli([
        "--url", "http://localhost:0", "--token", "fake",
        "policy", "create", "test-complex",
        "--path-rules", complex_rules,
    ])
    check_not_contains("Pas d'erreur JSON", r.output, "JSON invalide")

    # ═══════════════════════════════════════════════════════════════
    # Tests d'affichage des policies
    # ═══════════════════════════════════════════════════════════════

    section("Affichage policy create")
    print("    [simulé] :")
    show_policy_result({
        "status": "created", "policy_id": "team-alice",
        "description": "Accès team Alice",
        "allowed_tools": ["secret_*", "vault_list"],
        "denied_tools": ["vault_delete"],
        "path_rules": [{"vault_pattern": "shared-*", "permissions": ["read"], "allowed_paths": ["shared/*"]}],
    })
    check("policy create affichage OK", True)

    section("Affichage policy list")
    print("    [simulé] :")
    show_policy_result({
        "status": "ok",
        "policies": [
            {"policy_id": "readonly", "description": "Lecture seule",
             "allowed_tools_count": 3, "denied_tools_count": 0, "path_rules_count": 0, "created_by": "admin"},
            {"policy_id": "team-alice", "description": "Team Alice",
             "allowed_tools_count": 2, "denied_tools_count": 1, "path_rules_count": 2, "created_by": "admin"},
        ],
    })
    check("policy list affichage OK", True)

    section("Affichage policy get — AVEC allowed_paths détaillés")
    print("    [simulé] :")
    show_policy_result({
        "status": "ok", "policy_id": "team-alice",
        "description": "Accès restreint chemins shared/*",
        "created_by": "admin", "created_at": "2026-03-23T10:00:00",
        "allowed_tools": ["secret_*", "vault_list"],
        "denied_tools": ["vault_delete", "ssh_*"],
        "path_rules": [
            {"vault_pattern": "shared-*", "permissions": ["read", "write"], "allowed_paths": ["shared/*", "config/*"]},
            {"vault_pattern": "private-*", "permissions": ["read"], "allowed_paths": ["public/*"]},
        ],
    })
    check("policy get avec allowed_paths ne crash pas", True)

    section("Affichage policy get — SANS path_rules")
    print("    [simulé] :")
    show_policy_result({
        "status": "ok", "policy_id": "simple-ro",
        "description": "Lecture seule, sans restriction chemin",
        "created_by": "admin", "created_at": "2026-03-23T10:00:00",
        "allowed_tools": ["secret_read", "vault_list"],
        "denied_tools": [], "path_rules": [],
    })
    check("policy get sans path_rules ne crash pas", True)

    section("Affichage policy delete")
    print("    [simulé] :")
    show_policy_result({"status": "deleted", "policy_id": "old-policy"})
    check("policy delete affichage OK", True)

    section("Affichage policy erreur")
    print("    [simulé] :")
    show_policy_result({"status": "error", "message": "Policy 'inexistante' non trouvée"})
    check("policy erreur affichage OK", True)
