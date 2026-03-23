#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════
  TEST CLI — Audit : filtres, affichage, --since
═══════════════════════════════════════════════════════════════
"""

from . import (
    banner, section, check, check_value, check_contains,
    run_cli, show_audit_result,
)


def test_audit():
    """Teste la commande audit du CLI."""

    banner("CLI — Audit (filtres, affichage)")

    # ── audit --help ──
    section("Aide audit — options de filtrage")
    r = run_cli(["audit", "--help"])
    check_value("audit --help exit code", r.exit_code, 0)
    check_contains("Option --limit/-n", r.output, "--limit")
    check_contains("Option --client/-c", r.output, "--client")
    check_contains("Option --vault/-v", r.output, "--vault")
    check_contains("Option --tool", r.output, "--tool")
    check_contains("Option --category", r.output, "--category")
    check_contains("Option --status/-s", r.output, "--status")
    check_contains("Option --since", r.output, "--since")
    # Vérifier les exemples
    check_contains("Exemple --status denied", r.output, "denied")
    check_contains("Exemple --category secret", r.output, "secret")
    check_contains("Exemple --since", r.output, "2026-03-18")

    # ═══════════════════════════════════════════════════════════════
    # Tests d'affichage
    # ═══════════════════════════════════════════════════════════════

    section("Affichage audit — événements mixtes (OK + DENIED)")
    print("    [simulé] :")
    show_audit_result({
        "status": "ok",
        "total_in_buffer": 150,
        "entries": [
            {"ts": "2026-03-23T10:05:30", "category": "secret", "tool": "secret_write",
             "client": "admin", "vault_id": "prod", "status": "ok", "detail": "Ecriture web/github"},
            {"ts": "2026-03-23T10:04:15", "category": "secret", "tool": "secret_read",
             "client": "agent-sre", "vault_id": "prod", "status": "denied",
             "detail": "Bloque par policy 'readonly'"},
            {"ts": "2026-03-23T10:03:00", "category": "vault", "tool": "vault_create",
             "client": "admin", "vault_id": "staging", "status": "created", "detail": "Vault staging cree"},
            {"ts": "2026-03-23T10:02:00", "category": "token", "tool": "token_update",
             "client": "admin", "vault_id": "", "status": "updated",
             "detail": "Token agent-sre mis a jour"},
        ],
        "stats": {
            "total": 150,
            "by_category": {"secret": 80, "vault": 30, "token": 20, "ssh": 15, "system": 5},
            "by_status": {"ok": 130, "denied": 12, "error": 5, "created": 3},
        },
    })
    check("audit avec événements mixtes ne crash pas", True)

    section("Affichage audit — aucun événement")
    print("    [simulé] :")
    show_audit_result({
        "status": "ok", "total_in_buffer": 0, "entries": [],
        "stats": {"total": 0, "by_category": {}, "by_status": {}},
    })
    check("audit vide ne crash pas", True)
