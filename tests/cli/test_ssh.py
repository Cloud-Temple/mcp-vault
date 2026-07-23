#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests CLI SSH CA — comportementaux (non-complaisant).

Vérifie que chaque commande ssh appelle le bon outil MCP avec les bons
arguments. Utilise run_cli_mocked() qui intercepte MCPClient.call_tool.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock

from . import (
    banner, section, check, check_value, check_contains,
    run_cli, run_cli_mocked,
)

_SSH_SETUP_OK  = {"status": "ok", "vault_id": "mon-vault", "role_name": "sre-role", "mount_point": "ssh-ca-mon-vault", "allowed_users": "deploy", "default_user": "ubuntu", "ttl": "15m"}
_SSH_SIGNED_OK = {"status": "ok", "signed_key": "ssh-rsa-cert-v01@openssh.com AAAA...", "serial_number": "12:34", "ttl": "30m"}
_SSH_CA_KEY_OK = {"status": "ok", "vault_id": "mon-vault", "public_key": "ssh-ed25519 AAAA...", "usage": "Ajouter dans TrustedUserCAKeys"}
_SSH_ROLES_OK  = {"status": "ok", "vault_id": "mon-vault", "roles": ["sre-role", "dev-role"], "count": 2}
_SSH_ROLE_INFO = {"status": "ok", "vault_id": "mon-vault", "role_name": "sre-role", "key_type": "ca", "ttl": "15m", "allowed_users": "deploy", "default_user": "ubuntu"}


def test_ssh():
    """Tests comportementaux SSH CA — vérifie les appels MCPClient réels."""

    banner("CLI — SSH CA : tests comportementaux (non-complaisant)")

    # ── Aide ─────────────────────────────────────────────────────────────────
    section("Aide ssh")
    r = run_cli(["ssh", "--help"])
    check_value("ssh --help exit code", r.exit_code, 0)
    for subcmd in ["setup", "sign", "request", "profiles", "ca-key", "roles", "role-info"]:
        check_contains(f"Sous-commande '{subcmd}'", r.output, subcmd)

    # ── ssh setup ────────────────────────────────────────────────────────────
    section("ssh setup — appelle ssh_ca_setup avec tous les args")
    r, mock = run_cli_mocked(
        ["ssh", "setup", "mon-vault", "sre-role", "--users", "deploy", "--ttl", "15m", "--default-user", "ubuntu"],
        _SSH_SETUP_OK,
    )
    check_value("Exit code", r.exit_code, 0)
    args = mock.call_args[0][1] if mock.call_args else {}
    check("ssh_ca_setup appelé", mock.call_args is not None and mock.call_args[0][0] == "ssh_ca_setup")
    check_value("vault_id correct", args.get("vault_id"), "mon-vault")
    check_value("role_name correct", args.get("role_name"), "sre-role")
    check_value("allowed_users correct", args.get("allowed_users"), "deploy")
    check_value("ttl correct", args.get("ttl"), "15m")
    check_value("default_user correct", args.get("default_user"), "ubuntu")

    section("ssh setup — valeurs par défaut (sans options)")
    r, mock = run_cli_mocked(["ssh", "setup", "mon-vault", "sre-role"], _SSH_SETUP_OK)
    check_value("Exit code", r.exit_code, 0)
    args = mock.call_args[0][1] if mock.call_args else {}
    check_value("allowed_users défaut = '*'", args.get("allowed_users"), "*")
    check_value("default_user défaut = 'ubuntu'", args.get("default_user"), "ubuntu")
    check_value("ttl défaut = '30m'", args.get("ttl"), "30m")

    # ── ssh sign --key-data ───────────────────────────────────────────────────
    section("ssh sign --key-data — appelle ssh_sign_key")
    r, mock = run_cli_mocked(
        ["ssh", "sign", "mon-vault", "sre-role", "--key-data", "ssh-ed25519 AAAA...", "--ttl", "15m"],
        _SSH_SIGNED_OK,
    )
    check_value("Exit code", r.exit_code, 0)
    args = mock.call_args[0][1] if mock.call_args else {}
    check("ssh_sign_key appelé", mock.call_args is not None and mock.call_args[0][0] == "ssh_sign_key")
    check_value("vault_id correct", args.get("vault_id"), "mon-vault")
    check_value("role_name correct", args.get("role_name"), "sre-role")
    check_value("public_key correct", args.get("public_key"), "ssh-ed25519 AAAA...")
    check_value("ttl correct", args.get("ttl"), "15m")

    section("ssh sign sans --key ni --key-data — erreur CLI (pas d'appel MCP)")
    r, mock = run_cli_mocked(["ssh", "sign", "mon-vault", "sre-role"], _SSH_SIGNED_OK)
    check_value("Exit code reste 0 (erreur affichée proprement)", r.exit_code, 0)
    check("ssh_sign_key NON appelé sans clé", not mock.called)

    # ── ssh request opérateur JIT ────────────────────────────────────────────
    section("ssh request — aucun attribut de certificat libre n'est transmis")
    r, mock = run_cli_mocked(
        ["ssh", "request", "bastion-prod", "--key-data", "ssh-ed25519 AAAA...",
         "--reason", "maintenance autorisée", "--json"],
        {"status": "ok", "serial_number": "42"},
    )
    check_value("Exit code", r.exit_code, 0)
    args = mock.call_args[0][1] if mock.call_args else {}
    check("ssh_request_operator_access appelé",
          mock.call_args is not None and mock.call_args[0][0] == "ssh_request_operator_access")
    check_value("profile_id correct", args.get("profile_id"), "bastion-prod")
    check_value("public_key correcte", args.get("public_key"), "ssh-ed25519 AAAA...")
    check_value("reason correct", args.get("reason"), "maintenance autorisée")
    check_value("champs transmis fermés", set(args), {"profile_id", "public_key", "reason"})

    section("ssh profiles — liste les profils du bearer courant")
    r, mock = run_cli_mocked(
        ["ssh", "profiles", "--json"],
        {"status": "ok", "profiles": [], "count": 0},
    )
    check_value("Exit code", r.exit_code, 0)
    check("ssh_operator_access_profiles appelé",
          mock.call_args is not None and mock.call_args[0][0] == "ssh_operator_access_profiles")
    check_value("aucun argument libre", mock.call_args[0][1] if mock.call_args else None, {})

    # ── ssh ca-key ────────────────────────────────────────────────────────────
    section("ssh ca-key — appelle ssh_ca_public_key")
    r, mock = run_cli_mocked(["ssh", "ca-key", "mon-vault"], _SSH_CA_KEY_OK)
    check_value("Exit code", r.exit_code, 0)
    check("ssh_ca_public_key appelé", mock.call_args is not None and mock.call_args[0][0] == "ssh_ca_public_key")
    check_value("vault_id correct", mock.call_args[0][1].get("vault_id") if mock.call_args else None, "mon-vault")

    # ── ssh roles ────────────────────────────────────────────────────────────
    section("ssh roles — appelle ssh_ca_list_roles")
    r, mock = run_cli_mocked(["ssh", "roles", "mon-vault"], _SSH_ROLES_OK)
    check_value("Exit code", r.exit_code, 0)
    check("ssh_ca_list_roles appelé", mock.call_args is not None and mock.call_args[0][0] == "ssh_ca_list_roles")
    check_value("vault_id correct", mock.call_args[0][1].get("vault_id") if mock.call_args else None, "mon-vault")

    # ── ssh role-info ────────────────────────────────────────────────────────
    section("ssh role-info — appelle ssh_ca_role_info avec vault_id + role_name")
    r, mock = run_cli_mocked(["ssh", "role-info", "mon-vault", "sre-role"], _SSH_ROLE_INFO)
    check_value("Exit code", r.exit_code, 0)
    args = mock.call_args[0][1] if mock.call_args else {}
    check("ssh_ca_role_info appelé", mock.call_args is not None and mock.call_args[0][0] == "ssh_ca_role_info")
    check_value("vault_id correct", args.get("vault_id"), "mon-vault")
    check_value("role_name correct", args.get("role_name"), "sre-role")

    # ── Erreur propagée ───────────────────────────────────────────────────────
    section("ssh ca-key — erreur serveur propagée sans crash CLI")
    r, mock = run_cli_mocked(
        ["ssh", "ca-key", "vault-inexistant"],
        {"status": "error", "message": "Vault non trouvé"},
    )
    check_value("Exit code 0 même en erreur", r.exit_code, 0)
    check("ssh_ca_public_key bien appelé", mock.called)


@pytest.mark.asyncio
async def test_shell_request_preserves_quoted_reason_and_closed_contract():
    """Le shell utilise shlex : un motif multi-mots reste un seul argument."""
    from cli.shell import cmd_ssh

    client = MagicMock()
    client.call_tool = AsyncMock(return_value={"status": "ok", "serial_number": "42"})
    await cmd_ssh(
        client,
        'request bastion-prod --key-data "ssh-ed25519 AAAA..." '
        '--reason "maintenance autorisée par ticket"',
        json_output=True,
    )
    client.call_tool.assert_awaited_once_with(
        "ssh_request_operator_access",
        {
            "profile_id": "bastion-prod",
            "public_key": "ssh-ed25519 AAAA...",
            "reason": "maintenance autorisée par ticket",
        },
    )
