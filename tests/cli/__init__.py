#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════════════════
  Helpers partagés pour les tests CLI MCP Vault.
═══════════════════════════════════════════════════════════════════════════════

  Ce module fournit les outils communs à tous les fichiers de test CLI :
    - Compteurs PASS/FAIL
    - Fonctions d'affichage (banner, section)
    - Assertions (check, check_value, check_contains)
    - Helper run_cli pour exécuter les commandes Click avec affichage
    - Import du CLI et du CliRunner
═══════════════════════════════════════════════════════════════════════════════
"""

import os
import sys
import json

# ─────────────────────────────────────────────────────────────────────────────
# Setup : ajouter scripts/ au path pour accéder aux modules CLI
# ─────────────────────────────────────────────────────────────────────────────

_project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_scripts_dir = os.path.join(_project_root, "scripts")
if _scripts_dir not in sys.path:
    sys.path.insert(0, _scripts_dir)

# ─────────────────────────────────────────────────────────────────────────────
# Import du CLI Click et du CliRunner
# ─────────────────────────────────────────────────────────────────────────────

from click.testing import CliRunner
from cli.commands import cli

runner = CliRunner(mix_stderr=False)

# ─────────────────────────────────────────────────────────────────────────────
# Import des fonctions d'affichage
# ─────────────────────────────────────────────────────────────────────────────

from cli.display import (
    show_health_result, show_about_result, show_whoami_result,
    show_vault_result, show_secret_result,
    show_types_result, show_password_result,
    show_ssh_result, show_token_result,
    show_policy_result, show_audit_result,
)

# ─────────────────────────────────────────────────────────────────────────────
# Compteurs globaux
# ─────────────────────────────────────────────────────────────────────────────

PASS = 0
FAIL = 0


def reset_counters():
    """Remet les compteurs à zéro."""
    global PASS, FAIL
    PASS = 0
    FAIL = 0


def get_counters():
    """Retourne (PASS, FAIL)."""
    return PASS, FAIL


# ═════════════════════════════════════════════════════════════════════════════
#  Affichage — bandeaux et sections
# ═════════════════════════════════════════════════════════════════════════════

def banner(title: str):
    """Affiche un bandeau bien visible pour séparer les fichiers de test."""
    w = 70
    print()
    print("=" * w)
    print(f"  {title}")
    print("=" * w)


def section(title: str):
    """Affiche un titre de sous-section."""
    print(f"\n  ── {title} ──")


# ═════════════════════════════════════════════════════════════════════════════
#  Assertions — vérification des résultats
# ═════════════════════════════════════════════════════════════════════════════

def check(name: str, condition: bool, detail: str = "") -> bool:
    """
    Vérifie une assertion et affiche le résultat.

    Args:
        name: Description du test (ex: "policy create parse --path-rules")
        condition: True si le test passe, False sinon
        detail: Détail supplémentaire en cas d'échec

    Returns:
        True si le test passe
    """
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"    ✅ {name}")
    else:
        FAIL += 1
        msg = f"    ❌ {name}"
        if detail:
            msg += f" — {detail}"
        print(msg)
    return condition


def check_value(name: str, actual, expected, detail: str = "") -> bool:
    """Vérifie qu'une valeur est égale à l'attendue."""
    ok = actual == expected
    extra = detail or f"got={actual!r}, expected={expected!r}"
    return check(name, ok, "" if ok else extra)


def check_contains(name: str, text: str, substring: str) -> bool:
    """Vérifie qu'un texte contient une sous-chaîne."""
    ok = substring in text
    return check(name, ok, f"'{substring}' non trouvé dans la sortie" if not ok else "")


def check_not_contains(name: str, text: str, substring: str) -> bool:
    """Vérifie qu'un texte NE contient PAS une sous-chaîne."""
    ok = substring not in text
    return check(name, ok, f"'{substring}' trouvé alors qu'il ne devrait pas" if not ok else "")


# ═════════════════════════════════════════════════════════════════════════════
#  Helper CLI — exécute une commande Click avec affichage
# ═════════════════════════════════════════════════════════════════════════════

def run_cli(args: list):
    """
    Exécute une commande CLI via Click CliRunner.

    Affiche la ligne de commande AVANT l'exécution pour la traçabilité.
    Retourne l'objet Result (exit_code, output).

    Args:
        args: Liste d'arguments (ex: ["vault", "--help"])

    Returns:
        click.testing.Result
    """
    cmd_line = "mcp-vault " + " ".join(str(a) for a in args)
    print(f"    $ {cmd_line}")
    return runner.invoke(cli, args)


def print_summary():
    """Affiche le résumé final des tests."""
    total = PASS + FAIL
    print()
    print("=" * 70)
    if FAIL == 0:
        print(f"  ✅ TOUS LES TESTS PASSENT — {PASS}/{total}")
    else:
        print(f"  ❌ {FAIL} ÉCHEC(S) sur {total} tests — {PASS} OK, {FAIL} KO")
    print("=" * 70)
    print()
