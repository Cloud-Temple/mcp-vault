#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════════════════
  🔐 TEST CLI COMPLET — MCP Vault
═══════════════════════════════════════════════════════════════════════════════

  Lance TOUS les tests CLI (parsing Click + affichage Rich) pour valider
  que chaque commande fonctionne correctement.

  Structure :
    tests/cli/test_system.py   — health, about, whoami
    tests/cli/test_vault.py    — vault create/list/info/update/delete
    tests/cli/test_secret.py   — secret write/read/list/delete/types/password
    tests/cli/test_ssh.py      — ssh setup/sign/ca-key/roles/role-info
    tests/cli/test_policy.py   — policy create/list/get/delete + path_rules
    tests/cli/test_token.py    — token create/list/update/revoke + --policy
    tests/cli/test_audit.py    — audit avec filtres

  Usage :
    python tests/test_cli_all.py              — tout tester
    python tests/test_cli_all.py --only vault — un seul groupe
    python tests/test_cli_all.py --list       — lister les groupes

  Aucun serveur nécessaire — ces tests valident le parsing et l'affichage.
═══════════════════════════════════════════════════════════════════════════════
"""

import sys
import os
import argparse

# Ajouter le répertoire racine au path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# ─────────────────────────────────────────────────────────────────────────────
# Import des modules de test
# ─────────────────────────────────────────────────────────────────────────────

from tests.cli.test_system import test_system
from tests.cli.test_vault import test_vault
from tests.cli.test_secret import test_secret
from tests.cli.test_ssh import test_ssh
from tests.cli.test_policy import test_policy
from tests.cli.test_token import test_token
from tests.cli.test_audit import test_audit
from tests.cli import print_summary, get_counters, reset_counters


# ─────────────────────────────────────────────────────────────────────────────
# Registre des tests (ordre d'exécution)
# ─────────────────────────────────────────────────────────────────────────────

TEST_REGISTRY = {
    "system": ("health, about, whoami", test_system),
    "vault":  ("vault create/list/info/update/delete", test_vault),
    "secret": ("secret write/read/list/delete/types/password", test_secret),
    "ssh":    ("ssh setup/sign/ca-key/roles/role-info", test_ssh),
    "policy": ("policy create/list/get/delete + path_rules", test_policy),
    "token":  ("token create/list/update/revoke + --policy", test_token),
    "audit":  ("audit filtres + affichage", test_audit),
}


def main():
    parser = argparse.ArgumentParser(description="Tests CLI complets — MCP Vault")
    parser.add_argument("--only", help=f"Groupe spécifique ({', '.join(TEST_REGISTRY.keys())})")
    parser.add_argument("--list", action="store_true", help="Lister les groupes disponibles")
    args = parser.parse_args()

    # ── Liste des groupes ──
    if args.list:
        print("\n  Groupes de tests CLI disponibles :\n")
        for name, (desc, _) in TEST_REGISTRY.items():
            print(f"    {name:10s} — {desc}")
        print(f"\n  Usage : python tests/test_cli_all.py --only vault\n")
        return

    # ── Banner ──
    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║    Tests CLI complets — MCP Vault                            ║")
    print("║                                                              ║")
    print("║  Valide TOUTES les commandes Click :                         ║")
    print("║    • Parsing des arguments (--help, options, JSON)           ║")
    print("║    • Affichage Rich (tableaux, panneaux, couleurs)           ║")
    print("║    • Aide pédagogique (3 couches sécurité, exemples)         ║")
    print("║                                                              ║")
    print("║  Aucun serveur nécessaire — tests hors-ligne.                ║")
    print("╚══════════════════════════════════════════════════════════════╝")

    # ── Exécuter un seul groupe ou tous ──
    if args.only:
        if args.only not in TEST_REGISTRY:
            print(f"\n  ❌ Groupe '{args.only}' inconnu.")
            print(f"  Disponibles : {', '.join(TEST_REGISTRY.keys())}")
            sys.exit(1)
        desc, func = TEST_REGISTRY[args.only]
        func()
    else:
        for name, (desc, func) in TEST_REGISTRY.items():
            func()

    # ── Résumé final ──
    print_summary()

    # ── Exit code ──
    p, f = get_counters()
    sys.exit(1 if f > 0 else 0)


if __name__ == "__main__":
    main()
