# -*- coding: utf-8 -*-
"""
Tests #115 — permission dédiée non-admin `wrap` pour le broker JIT mcp-mission.

Matrice de sécurité (critères d'acceptation de la revue de plan Codex, 4 rounds) :

A. check_wrap_permission (context.py) :
   - token absent / read / write → refus ; admin → OK ;
   - wrap SANS allowed_resources → refus ; SANS policy_id → refus ;
   - policy sans allowed_tools explicites (policy « vide » permissive) → refus ;
   - PolicyStore absent ou indisponible → refus fail-close observable.

B. Évaluation STRICTE des chemins (PolicyStore.is_wrap_path_strictly_allowed) :
   - aucune path_rule matchante → refus (inversion du défaut permissif) ;
   - allowed_paths=[] → refus ; chemin hors patterns → refus ;
   - MÊME first-match-wins que is_path_allowed (règle générique placée avant
     une règle restrictive GAGNE — pinné pour interdire toute divergence PDP/PEP).

C. Verrou wrap-only (enforce_wrap_only_token) :
   - un token ["wrap"] est confiné aux 4 outils du broker — y compris si une
     policy mal configurée autorise secret_read (le verrou PRÉCÈDE la policy) ;
   - composites read+wrap / write+wrap ne sont PAS wrap-only ;
   - token absent → jamais traité wrap-only (ni admin).

D. Ordre des gardes sur les 4 outils MCP : check_policy AVANT
   check_wrap_permission (denied_tools/allowed_tools de la policy priment).

E. Scoping du registre (wrapping.py) : un token wrap ne voit/révoque que les
   entrées de son périmètre vault+chemins ; hors scope = not_found SANS appel
   OpenBao ; entrée malformée invisible pour un non-admin ; une entrée
   invisible n'est JAMAIS mutée même si elle partage l'accessor d'une visible ;
   contexte absent = fail-close.

F. REST admin-plane : un token wrap-only reçoit 403 sur TOUT /admin/api/*.

Preuve RED : sur main pré-#115, les 4 outils exigent check_admin_permission —
le test pivot « un token wrap peut wrapper » (test_wrap_token_can_wrap_in_scope)
échoue AVANT le correctif ; chaque verrou (C, E) n'existe pas avant lui.
"""

import asyncio
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("MCP_SERVER_NAME", "mcp-vault-test")
os.environ.setdefault("ADMIN_BOOTSTRAP_KEY", "Test-Bootstrap-Key-2026-Pour-Tests!!")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tests.conftest import auth_context, admin_auth_context  # noqa: E402


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# =============================================================================
# Identités de test
# =============================================================================

def _wrap_token(allowed=("mcp-mission",), policy_id="broker-jit", perms=("wrap",)):
    return {
        "client_name": "mcp-mission-broker",
        "permissions": list(perms),
        "allowed_resources": list(allowed),
        "policy_id": policy_id,
    }


def _read_token():
    return {"client_name": "reader", "permissions": ["read"],
            "allowed_resources": ["mcp-mission"], "policy_id": ""}


# =============================================================================
# Fake PolicyStore — duck-typé sur l'API réelle, sémantique RÉELLE exercée via
# la vraie classe quand c'est le sujet du test (section B).
# =============================================================================

def _real_policy_store(policies: dict):
    """PolicyStore réel, cache injecté, disponible, sans S3."""
    from mcp_vault.auth.policies import PolicyStore
    store = PolicyStore.__new__(PolicyStore)
    store._policies = policies
    store._available = True
    store._last_error = ""
    store._maybe_refresh = lambda: None
    return store


BROKER_POLICY = {
    "broker-jit": {
        "policy_id": "broker-jit",
        "allowed_tools": ["secret_wrap", "secret_revoke_wrap",
                          "secret_wrap_lookup", "secret_wrap_status"],
        "denied_tools": [],
        "path_rules": [
            {"vault_pattern": "mcp-mission", "permissions": ["read"],
             "allowed_paths": ["missions/*"]},
        ],
    },
}


def _patch_store(policies):
    return patch("mcp_vault.auth.policies.get_policy_store",
                 return_value=_real_policy_store(policies))


# =============================================================================
# A — check_wrap_permission
# =============================================================================

def test_wrap_permission_requires_auth():
    from mcp_vault.auth.context import check_wrap_permission
    err = check_wrap_permission()
    assert err and "Authentification" in err["message"]


def test_wrap_permission_rejects_read_write_tokens():
    from mcp_vault.auth.context import check_wrap_permission
    for perms in (["read"], ["write"], ["read", "write"]):
        with auth_context({"client_name": "c", "permissions": perms,
                           "allowed_resources": ["v"], "policy_id": "p"}):
            err = check_wrap_permission()
        assert err and "wrap" in err["message"], f"{perms} devrait être refusé"


def test_wrap_permission_admin_bypass():
    from mcp_vault.auth.context import check_wrap_permission
    with admin_auth_context():
        assert check_wrap_permission() is None


def test_wrap_permission_requires_nonempty_allowlist():
    """F3 (round 2) : pas de fallback owner-based pour un token wrap."""
    from mcp_vault.auth.context import check_wrap_permission
    for allowed in ([], None, "not-a-list"):
        ti = _wrap_token()
        ti["allowed_resources"] = allowed
        with auth_context(ti), _patch_store(BROKER_POLICY):
            err = check_wrap_permission()
        assert err and "allow-list" in err["message"], f"{allowed!r} devrait être refusé"


def test_wrap_permission_requires_policy_id():
    from mcp_vault.auth.context import check_wrap_permission
    for pid in ("", None, 123):
        ti = _wrap_token(policy_id=pid)
        with auth_context(ti), _patch_store(BROKER_POLICY):
            err = check_wrap_permission()
        assert err and "policy" in err["message"].lower(), f"{pid!r} devrait être refusé"


def test_wrap_permission_rejects_empty_policy():
    """R2-F1 : une policy VALIDE mais vide (allowed_tools=[]) est permissive
    via is_tool_allowed — elle doit être refusée au runtime pour un token wrap."""
    from mcp_vault.auth.context import check_wrap_permission
    empty_policy = {"broker-jit": {"policy_id": "broker-jit", "allowed_tools": [],
                                   "denied_tools": [], "path_rules": []}}
    with auth_context(_wrap_token()), _patch_store(empty_policy):
        err = check_wrap_permission()
    assert err and "allowed_tools" in err["message"]


def test_wrap_permission_rejects_missing_policy():
    from mcp_vault.auth.context import check_wrap_permission
    with auth_context(_wrap_token(policy_id="ghost")), _patch_store(BROKER_POLICY):
        err = check_wrap_permission()
    assert err is not None


def test_wrap_permission_fail_close_without_store():
    from mcp_vault.auth.context import check_wrap_permission
    with auth_context(_wrap_token()), \
         patch("mcp_vault.auth.policies.get_policy_store", return_value=None):
        err = check_wrap_permission()
    assert err and err.get("error_type") == "policy_store_unavailable"


def test_wrap_permission_fail_close_on_store_outage():
    from mcp_vault.auth.context import check_wrap_permission
    from mcp_vault.auth.policies import PolicyStoreUnavailable
    store = MagicMock()
    store.has_explicit_allowed_tools.side_effect = PolicyStoreUnavailable("panne S3")
    with auth_context(_wrap_token()), \
         patch("mcp_vault.auth.policies.get_policy_store", return_value=store):
        err = check_wrap_permission()
    assert err and err.get("error_type") == "policy_store_unavailable"


def test_wrap_permission_ok_with_full_provisioning():
    from mcp_vault.auth.context import check_wrap_permission
    with auth_context(_wrap_token()), _patch_store(BROKER_POLICY):
        assert check_wrap_permission() is None


# =============================================================================
# B — Évaluation stricte des chemins
# =============================================================================

def test_strict_path_no_matching_rule_is_denied():
    """Inversion du défaut permissif : pas de règle = pas de droit."""
    store = _real_policy_store(BROKER_POLICY)
    assert store.is_wrap_path_strictly_allowed("broker-jit", "autre-vault", "missions/x") is False
    # Référence : la sémantique LAX autorise ce même cas (pin de la différence)
    assert store.is_path_allowed("broker-jit", "autre-vault", "missions/x", "read") is True


def test_strict_path_empty_allowed_paths_is_denied():
    policies = {
        "p": {"policy_id": "p", "allowed_tools": ["secret_wrap"], "denied_tools": [],
              "path_rules": [{"vault_pattern": "v", "permissions": ["read"],
                              "allowed_paths": []}]},
    }
    store = _real_policy_store(policies)
    assert store.is_wrap_path_strictly_allowed("p", "v", "n-importe-quoi") is False
    # Référence LAX : autorisé (pin de la différence)
    assert store.is_path_allowed("p", "v", "n-importe-quoi", "read") is True


def test_strict_path_in_and_out_of_patterns():
    store = _real_policy_store(BROKER_POLICY)
    assert store.is_wrap_path_strictly_allowed("broker-jit", "mcp-mission", "missions/db") is True
    assert store.is_wrap_path_strictly_allowed("broker-jit", "mcp-mission", "prive/db") is False


def test_strict_path_first_match_wins_like_lax():
    """PIN du first-match : une règle générique placée AVANT une règle
    restrictive gagne — sémantique existante reproduite à l'identique,
    aucune divergence PDP/PEP (exigence Codex round 3/C1)."""
    policies = {
        "p": {"policy_id": "p", "allowed_tools": ["secret_wrap"], "denied_tools": [],
              "path_rules": [
                  {"vault_pattern": "*", "permissions": ["read"], "allowed_paths": ["*"]},
                  {"vault_pattern": "v", "permissions": ["read"], "allowed_paths": ["seulement/ceci"]},
              ]},
    }
    store = _real_policy_store(policies)
    # La générique matche d'abord → tout chemin passe (comme en LAX)
    assert store.is_wrap_path_strictly_allowed("p", "v", "hors/perimetre") is True
    assert store.is_path_allowed("p", "v", "hors/perimetre", "read") is True


def test_strict_path_rule_without_read_permission_is_denied():
    policies = {
        "p": {"policy_id": "p", "allowed_tools": ["secret_wrap"], "denied_tools": [],
              "path_rules": [{"vault_pattern": "v", "permissions": [],
                              "allowed_paths": ["*"]}]},
    }
    store = _real_policy_store(policies)
    assert store.is_wrap_path_strictly_allowed("p", "v", "x") is False


def test_has_explicit_allowed_tools():
    store = _real_policy_store(BROKER_POLICY)
    assert store.has_explicit_allowed_tools("broker-jit") is True
    assert store.has_explicit_allowed_tools("ghost") is False
    store2 = _real_policy_store({"e": {"policy_id": "e", "allowed_tools": [],
                                       "denied_tools": [], "path_rules": []}})
    assert store2.has_explicit_allowed_tools("e") is False


# =============================================================================
# C — Verrou wrap-only
# =============================================================================

def test_wrap_only_locked_out_of_other_tools():
    from mcp_vault.auth.context import enforce_wrap_only_token, WRAP_ONLY_ALLOWED_TOOLS
    denied_tools = ["secret_read", "secret_list", "secret_write", "secret_delete",
                    "vault_create", "vault_list", "vault_info", "vault_update",
                    "vault_delete", "ssh_sign_key", "ssh_ca_setup", "pki_ca_setup",
                    "policy_create", "token_update", "audit_log", "system_health",
                    "system_about", "secret_types", "secret_generate_password",
                    "secret_consume"]
    with auth_context(_wrap_token()):
        for tool in denied_tools:
            assert enforce_wrap_only_token(tool) is not None, f"{tool} devrait être refusé"
        for tool in WRAP_ONLY_ALLOWED_TOOLS:
            assert enforce_wrap_only_token(tool) is None, f"{tool} devrait passer"


def test_wrap_only_lock_precedes_policy_evaluation():
    """Une policy MAL CONFIGURÉE qui autorise secret_read ne doit PAS élargir
    le périmètre d'un token wrap-only : le verrou précède la policy."""
    from mcp_vault.auth.context import check_policy
    generous = {"broker-jit": {"policy_id": "broker-jit",
                               "allowed_tools": ["secret_read", "secret_wrap"],
                               "denied_tools": [], "path_rules": []}}
    with auth_context(_wrap_token()), _patch_store(generous):
        err = check_policy("secret_read")
    assert err is not None and "wrap" in err["message"]


def test_composites_are_not_wrap_only():
    from mcp_vault.auth.context import is_wrap_only_token, enforce_wrap_only_token
    for perms in (["read", "wrap"], ["write", "wrap"], ["admin", "wrap"]):
        ti = _wrap_token(perms=perms)
        assert is_wrap_only_token(ti) is False, perms
        with auth_context(ti):
            assert enforce_wrap_only_token("secret_read") is None, perms


def test_absent_context_is_neither_wrap_only_nor_admin():
    from mcp_vault.auth.context import enforce_wrap_only_token, is_wrap_only_token
    assert is_wrap_only_token(None) is False
    assert enforce_wrap_only_token("secret_read") is None  # comportement no-auth inchangé


def test_wrap_only_lock_is_wired_into_handlers_without_check_policy():
    """MUTATION-PROOF (revue pré-commit F3) : appelle les VRAIS handlers MCP
    sans check_policy avec une identité wrap-only et prouve que le délégué
    n'est JAMAIS invoqué — supprimer l'appel enforce_wrap_only_token dans un
    handler fait échouer ce test (le délégué patché serait appelé)."""
    from mcp_vault import server

    cases = [
        # (handler coroutine factory, chemin du délégué à patcher)
        (lambda: server.system_health(),
         "mcp_vault.openbao.lifecycle.get_vault_status"),
        (lambda: server.secret_types(),
         "mcp_vault.vault.types.list_types"),
        (lambda: server.secret_generate_password(),
         "mcp_vault.vault.types.generate_password"),
        (lambda: server.secret_consume(wrap_token="wt", operation_id="op-1",
                                       mission_token="mt"),
         "mcp_vault.vault.wrapping.consume_wrap_secret"),
        (lambda: server.ssh_operator_access_profiles(),
         "mcp_vault.ssh_operator.list_operator_access_profiles"),
        (lambda: server.ssh_request_operator_access(
            profile_id="p", public_key="ssh-ed25519 AAA", reason="test"),
         "mcp_vault.ssh_operator.request_operator_ssh_access"),
    ]
    with auth_context(_wrap_token()):
        for make_coro, delegate_path in cases:
            delegate = MagicMock()
            with patch(delegate_path, new=delegate):
                res = _run(make_coro())
            assert res["status"] == "error" and "wrap" in res["message"], \
                f"{delegate_path} : refus wrap-only attendu, obtenu {res}"
            delegate.assert_not_called()
        # system_about n'a pas de délégué patchable : le refus suffit (aucune
        # métadonnée d'infra dans la réponse).
        res = _run(server.system_about())
        assert res["status"] == "error" and "wrap" in res["message"]
        assert "openbao_addr" not in res and "platform" not in res


# =============================================================================
# D — Ordre des gardes sur les outils MCP
# =============================================================================

def test_read_token_denied_on_all_four_tools():
    from mcp_vault import server
    tools = [
        (server.secret_wrap, dict(vault_id="mcp-mission", secret_path="missions/x",
                                  mission_id="m", operation_id="op-1")),
        (server.secret_revoke_wrap, dict(lease_id="ACC1")),
        (server.secret_wrap_lookup, dict(operation_id="op-1", mission_id="m")),
        (server.secret_wrap_status, dict(operation_id="op-1", mission_id="m")),
    ]
    with auth_context(_read_token()), _patch_store(BROKER_POLICY):
        for fn, kwargs in tools:
            res = _run(fn(**kwargs))
            assert res["status"] == "error" and "wrap" in res["message"], \
                f"{fn.__name__} devrait refuser un token read : {res}"


def test_policy_allowlist_without_wrap_tool_denies():
    """R3-F1 : allowed_tools non vide SANS secret_wrap → refus PAR LA POLICY
    (check_policy avant check_wrap_permission)."""
    from mcp_vault import server
    policies = {"broker-jit": {"policy_id": "broker-jit",
                               "allowed_tools": ["secret_wrap_status"],
                               "denied_tools": [], "path_rules": BROKER_POLICY["broker-jit"]["path_rules"]}}
    with auth_context(_wrap_token()), _patch_store(policies):
        res = _run(server.secret_wrap(vault_id="mcp-mission", secret_path="missions/x",
                                      mission_id="m", operation_id="op-1"))
    assert res["status"] == "error"
    assert "refusé par la policy" in res["message"], f"attendu refus policy : {res}"


def test_policy_denied_tools_takes_precedence():
    """R3-F1 : denied_tools=['secret_wrap'] prime sur tout le reste."""
    from mcp_vault import server
    policies = {"broker-jit": dict(BROKER_POLICY["broker-jit"],
                                   denied_tools=["secret_wrap"])}
    with auth_context(_wrap_token()), _patch_store(policies):
        res = _run(server.secret_wrap(vault_id="mcp-mission", secret_path="missions/x",
                                      mission_id="m", operation_id="op-1"))
    assert res["status"] == "error"
    assert "refusé par la policy" in res["message"]


def test_wrap_token_can_wrap_in_scope():
    """TEST PIVOT (RED sur main pré-#115 : check_admin_permission refusait).
    Un token ["wrap"] correctement provisionné crée un wrap dans son périmètre."""
    from mcp_vault import server

    async def fake_wrap_secret(vault_id, secret_path, mission_id, operation_id,
                               ttl_seconds, tenant_id="", expected_aud=""):
        return {"status": "ok", "wrap_token": "s.XYZ", "accessor": "ACC",
                "vault_id": vault_id, "secret_path": secret_path}

    with auth_context(_wrap_token()), _patch_store(BROKER_POLICY), \
         patch("mcp_vault.vault.wrapping.wrap_secret", new=fake_wrap_secret), \
         patch("mcp_vault.server.settings") as mock_settings:
        mock_settings.enforce_mission_token_validation = False
        mock_settings.mission_jwks_url = ""
        res = _run(server.secret_wrap(vault_id="mcp-mission",
                                      secret_path="missions/db",
                                      mission_id="m-1", operation_id="op-1"))
    assert res["status"] == "ok", f"le broker wrap doit passer : {res}"


def test_wrap_token_denied_out_of_vault_and_out_of_path():
    from mcp_vault import server
    with auth_context(_wrap_token()), _patch_store(BROKER_POLICY), \
         patch("mcp_vault.server.settings") as mock_settings:
        mock_settings.enforce_mission_token_validation = False
        mock_settings.mission_jwks_url = ""
        # Hors allow-list de vaults (check_access)
        res = _run(server.secret_wrap(vault_id="autre-vault", secret_path="missions/db",
                                      mission_id="m", operation_id="op-1"))
        assert res["status"] == "error" and "autre-vault" in res["message"]
        # Dans le vault, hors allowed_paths (évaluation STRICTE)
        res2 = _run(server.secret_wrap(vault_id="mcp-mission", secret_path="prive/db",
                                       mission_id="m", operation_id="op-2"))
        assert res2["status"] == "error" and "stricte" in res2["message"]


def test_wrap_token_with_policy_without_path_rule_is_denied():
    """R2-F1 : policy avec allowed_tools OK mais path_rules=[] → l'évaluation
    stricte refuse (pas de règle = pas de droit), là où la lax autoriserait."""
    from mcp_vault import server
    policies = {"broker-jit": {"policy_id": "broker-jit",
                               "allowed_tools": ["secret_wrap"], "denied_tools": [],
                               "path_rules": []}}
    with auth_context(_wrap_token()), _patch_store(policies), \
         patch("mcp_vault.server.settings") as mock_settings:
        mock_settings.enforce_mission_token_validation = False
        mock_settings.mission_jwks_url = ""
        res = _run(server.secret_wrap(vault_id="mcp-mission", secret_path="missions/db",
                                      mission_id="m", operation_id="op-1"))
    assert res["status"] == "error" and "stricte" in res["message"]


def test_mission_jwt_denied_on_wrap_tools():
    from mcp_vault import server
    mission_ti = {"client_name": "mission-x", "permissions": [],
                  "allowed_resources": ["mcp-mission"], "policy_id": "",
                  "auth_type": "mission_jwt", "mission_id": "m-1"}
    with auth_context(mission_ti):
        for fn, kwargs in [
            (server.secret_wrap, dict(vault_id="mcp-mission", secret_path="x",
                                      mission_id="m", operation_id="op-1")),
            (server.secret_revoke_wrap, dict(lease_id="ACC1")),
            (server.secret_wrap_lookup, dict(operation_id="op-1", mission_id="m")),
            (server.secret_wrap_status, dict(operation_id="op-1", mission_id="m")),
        ]:
            res = _run(fn(**kwargs))
            assert res["status"] == "error" and "mission" in res["message"], \
                f"{fn.__name__} devrait refuser une identité mission : {res}"


def test_admin_token_unchanged_on_wrap_tools():
    """Rétrocompat : un admin (même avec une policy qui ne liste pas les outils
    wrap) passe toujours — check_policy bypass admin (Codex A2)."""
    from mcp_vault import server
    core = AsyncMock(return_value={"status": "ok", "state": "not_found"})
    with admin_auth_context(), \
         patch("mcp_vault.vault.wrapping.status_by_operation_id", new=core):
        res = _run(server.secret_wrap_status("op-1", "m"))
    assert res["status"] == "ok"
    core.assert_called_once()


# =============================================================================
# E — Scoping du registre (primitives)
# =============================================================================

def _entry(op_id, accessor, status, vault="mcp-mission", path="missions/db"):
    return {"operation_id": op_id, "accessor": accessor, "mission_id": "m",
            "vault_id": vault, "secret_path": path, "created_at": "",
            "expires_at": "2099-01-01T00:00:00+00:00", "status": status}


def _mem_registry(entries):
    from mcp_vault.vault.wrapping import WrapRegistry

    class InMemoryRegistry(WrapRegistry):
        def __init__(self):
            self._wraps = list(entries)
            import asyncio
            from mcp_vault.store_refresh import Freshness
            self.freshness = Freshness()
            self.freshness.mark_success()  # instantané frais (#123)
            self._last_load_ok = getattr(self, '_last_load_ok', True)
            self.refresh_lock = asyncio.Lock()
            self._last_load_ok = True
            self.saved = 0

        def load(self):
            pass

        def _save(self):
            self.saved += 1
            return True

    return InMemoryRegistry()


def _patch_wrapping(registry, client=None):
    from contextlib import ExitStack
    stack = ExitStack()
    stack.enter_context(patch("mcp_vault.vault.wrapping.get_wrap_registry",
                              return_value=registry))
    c = client or MagicMock()
    stack.enter_context(patch("mcp_vault.vault.wrapping._get_client", return_value=c))
    cfg = MagicMock(); cfg.openbao_addr = "http://127.0.0.1:8200"
    stack.enter_context(patch("mcp_vault.vault.wrapping._get_config", return_value=cfg))
    return stack, c


def test_registry_out_of_vault_scope_is_not_found_and_openbao_untouched():
    from mcp_vault.vault import wrapping as w
    reg = _mem_registry([_entry("op-1", "ACC1", "active", vault="autre-vault")])
    stack, client = _patch_wrapping(reg)
    with stack, auth_context(_wrap_token()), _patch_store(BROKER_POLICY):
        res = _run(w.revoke_wrap("ACC1"))
        assert res["state"] == "not_found"
        res2 = _run(w.lookup_and_revoke_by_operation_id("op-1", "m"))
        assert res2["state"] == "not_found"
        res3 = _run(w.status_by_operation_id("op-1", "m"))
        assert res3["state"] == "not_found"
    client.auth.token.revoke_accessor.assert_not_called()
    assert reg.saved == 0, "aucune mutation ne doit être persistée"
    assert reg._wraps[0]["status"] == "active", "l'entrée hors scope ne doit pas muter"


def test_registry_cross_path_same_vault_is_not_found():
    """F1 (round 1) : même vault, chemin hors policy → invisible (DoS cross-path fermé)."""
    from mcp_vault.vault import wrapping as w
    reg = _mem_registry([_entry("op-1", "ACC1", "active", path="prive/root-cred")])
    stack, client = _patch_wrapping(reg)
    with stack, auth_context(_wrap_token()), _patch_store(BROKER_POLICY):
        assert _run(w.revoke_wrap("ACC1"))["state"] == "not_found"
        assert _run(w.lookup_and_revoke_by_operation_id("op-1", "m"))["state"] == "not_found"
        assert _run(w.status_by_operation_id("op-1", "m"))["state"] == "not_found"
    client.auth.token.revoke_accessor.assert_not_called()


def test_registry_in_scope_revocable_by_wrap_token():
    from mcp_vault.vault import wrapping as w
    reg = _mem_registry([_entry("op-1", "ACC1", "active")])
    stack, client = _patch_wrapping(reg)
    with stack, auth_context(_wrap_token()), _patch_store(BROKER_POLICY):
        res = _run(w.revoke_wrap("ACC1"))
    assert res["state"] == "revoked"
    client.auth.token.revoke_accessor.assert_called_once_with(accessor="ACC1")
    assert reg._wraps[0]["status"] == "revoked"


def test_registry_shared_accessor_invisible_entry_never_mutated():
    """R2-F2 : deux entrées partagent l'accessor (registre incohérent) — seule
    l'entrée VISIBLE est mutée, l'invisible reste intacte."""
    from mcp_vault.vault import wrapping as w
    visible = _entry("op-1", "ACCX", "active")
    invisible = _entry("op-2", "ACCX", "active", vault="autre-vault")
    reg = _mem_registry([visible, invisible])
    stack, client = _patch_wrapping(reg)
    with stack, auth_context(_wrap_token()), _patch_store(BROKER_POLICY):
        res = _run(w.revoke_wrap("ACCX"))
    assert res["state"] == "revoked"
    assert reg._wraps[0]["status"] == "revoked"
    assert reg._wraps[1]["status"] == "active", "entrée invisible mutée !"


def test_registry_malformed_entries_invisible_for_non_admin():
    """R2-F2/R3 : None/{}/types cassés AVANT une entrée valide → aucun crash,
    non-admin voit not_found pour l'op malformée, l'entrée valide reste servie."""
    from mcp_vault.vault import wrapping as w
    reg = _mem_registry([None, {}, {"operation_id": 42},
                         _entry("op-ok", "ACCOK", "active")])
    stack, client = _patch_wrapping(reg)
    with stack, auth_context(_wrap_token()), _patch_store(BROKER_POLICY):
        assert _run(w.status_by_operation_id("op-ok", "m"))["state"] == "active"
        assert _run(w.status_by_operation_id("op-ghost", "m"))["state"] == "not_found"
        assert _run(w.revoke_wrap("ACC-GHOST"))["state"] == "not_found"
    client.auth.token.revoke_accessor.assert_not_called()


def test_registry_admin_still_sees_registry_inconsistent_on_malformed():
    """Comportement historique admin préservé : entrée malformée n'importe où
    dans le registre → registry_inconsistent sur status."""
    from mcp_vault.vault import wrapping as w
    reg = _mem_registry([{}, _entry("op-ok", "ACCOK", "active")])
    stack, _ = _patch_wrapping(reg)
    with stack, admin_auth_context():
        res = _run(w.status_by_operation_id("op-ok", "m"))
    assert res["state"] == "registry_inconsistent"


def test_registry_absent_context_is_fail_close():
    """None n'est JAMAIS admin : sans identité, rien n'est visible."""
    from mcp_vault.vault import wrapping as w
    reg = _mem_registry([_entry("op-1", "ACC1", "active")])
    stack, client = _patch_wrapping(reg)
    with stack:
        assert _run(w.revoke_wrap("ACC1"))["state"] == "not_found"
        assert _run(w.lookup_and_revoke_by_operation_id("op-1", "m"))["state"] == "not_found"
        assert _run(w.status_by_operation_id("op-1", "m"))["state"] == "not_found"
    client.auth.token.revoke_accessor.assert_not_called()


def test_registry_admin_sees_everything():
    from mcp_vault.vault import wrapping as w
    reg = _mem_registry([_entry("op-1", "ACC1", "active", vault="nimporte")])
    stack, client = _patch_wrapping(reg)
    with stack, admin_auth_context():
        res = _run(w.revoke_wrap("ACC1"))
    assert res["state"] == "revoked"
    client.auth.token.revoke_accessor.assert_called_once()


def test_registry_perime_detecte_et_s3_outage_detected():
    """R3-F2, réécrit pour #123 : la consultation ne présente jamais un
    instantané douteux comme fiable.

    ⚠️ La version d'origine exigeait que `_maybe_refresh` RECHARGE quand le cache
    était expiré. Ce chargement était un GET S3 SYNCHRONE dans la boucle — le gel
    de #110 — et il a été déplacé dans le rafraîchisseur de fond (prouvé dans
    `tests/test_store_refresh_123.py`). Ce qui doit rester vrai ici, et qui est
    la raison d'être de R3-F2, c'est la CONSÉQUENCE : un instantané qu'on n'a pas
    pu rafraîchir ne doit pas être servi comme un état sûr.

    Deux chemins y mènent désormais, tous deux vérifiés : la péremption constatée
    en mémoire, et l'échec de chargement déjà enregistré.
    """
    from mcp_vault.vault import wrapping as w
    reg = _mem_registry([_entry("op-1", "ACC1", "active")])
    reg.load = MagicMock(side_effect=AssertionError(
        "la consultation ne doit JAMAIS charger depuis la boucle (#123)"))
    reg.freshness._last_success -= reg.CACHE_TTL + 1  # personne n'a rechargé
    stack, _ = _patch_wrapping(reg)
    with stack, admin_auth_context():
        res_perime = _run(w.status_by_operation_id("op-1", "m"))
    assert reg._last_load_ok is False, "la péremption n'a pas été constatée"
    assert (res_perime["status"] == "error"
            and res_perime.get("error_type") == "backend_unavailable"), res_perime

    reg2 = _mem_registry([_entry("op-1", "ACC1", "active")])
    reg2._last_load_ok = False
    stack2, _ = _patch_wrapping(reg2)
    with stack2, admin_auth_context():
        res = _run(w.status_by_operation_id("op-1", "m"))
    assert res["status"] == "error" and res.get("error_type") == "backend_unavailable"


def test_registry_fail_close_on_s3_refresh_failure_for_revoke_and_lookup():
    """BLOQUANT revue pré-commit : après un refresh S3 en échec
    (_last_load_ok=False), AUCUNE décision destructive ne doit être prise sur
    le cache ambigu — ni appel OpenBao, ni _save (qui écraserait un état S3
    plus récent en last-write-wins). Le broker doit retenter."""
    from mcp_vault.vault import wrapping as w
    reg = _mem_registry([_entry("op-1", "ACC1", "active")])
    reg._last_load_ok = False
    stack, client = _patch_wrapping(reg)
    with stack, admin_auth_context():
        res = _run(w.revoke_wrap("ACC1"))
        assert res["status"] == "error" and res.get("error_type") == "backend_unavailable", res
        res2 = _run(w.lookup_and_revoke_by_operation_id("op-1", "m"))
        assert res2["status"] == "error" and res2.get("error_type") == "backend_unavailable", res2
    client.auth.token.revoke_accessor.assert_not_called()
    assert reg.saved == 0, "aucune écriture ne doit persister un cache ambigu"
    assert reg._wraps[0]["status"] == "active"


def test_registry_lookup_duplicated_accessor_failure_counts_nothing():
    """Revue pré-commit R2 (MAJEUR) : deux entrées actives partageant un
    accessor + échec OpenBao 5xx → partial_revocation avec count_revoked=0
    (aucune entrée du groupe comptée), UN SEUL appel OpenBao, aucune mutation,
    aucun _save. En cas de succès : count_revoked=2 en un seul appel."""
    from mcp_vault.vault import wrapping as w

    def _two_dupes():
        return _mem_registry([
            _entry("op-1", "ACC-DUP", "active"),
            _entry("op-1", "ACC-DUP", "active"),
        ])

    # Échec OpenBao 5xx (message sans marqueur idempotent ni 400/404)
    reg = _two_dupes()
    failing = MagicMock()
    failing.auth.token.revoke_accessor.side_effect = Exception("connection reset 503")
    stack, client = _patch_wrapping(reg, client=failing)
    with stack, admin_auth_context():
        res = _run(w.lookup_and_revoke_by_operation_id("op-1", "m"))
    assert res["status"] == "error" and res.get("error_type") == "partial_revocation", res
    assert res["count_revoked"] == 0, f"aucune entrée ne doit être comptée : {res}"
    failing.auth.token.revoke_accessor.assert_called_once()
    assert all(e["status"] == "active" for e in reg._wraps)
    assert reg.saved == 0

    # Succès : les 2 entrées comptées, un seul appel OpenBao, toutes marquées
    reg2 = _two_dupes()
    stack2, client2 = _patch_wrapping(reg2)
    with stack2, admin_auth_context():
        res2 = _run(w.lookup_and_revoke_by_operation_id("op-1", "m"))
    assert res2["status"] == "ok" and res2["count_revoked"] == 2, res2
    client2.auth.token.revoke_accessor.assert_called_once()
    assert all(e["status"] == "revoked" for e in reg2._wraps)


def test_registry_lookup_counts_only_visible_entries():
    """Multi-entrées d'un même operation_id sur 2 vaults : seuls les visibles
    sont comptés/révoqués — pas de fuite d'existence via entries_found."""
    from mcp_vault.vault import wrapping as w
    reg = _mem_registry([
        _entry("op-1", "ACC-A", "active"),
        _entry("op-1", "ACC-B", "active", vault="autre-vault"),
    ])
    stack, client = _patch_wrapping(reg)
    with stack, auth_context(_wrap_token()), _patch_store(BROKER_POLICY):
        res = _run(w.lookup_and_revoke_by_operation_id("op-1", "m"))
    assert res["entries_found"] == 1, "l'entrée hors scope ne doit pas être comptée"
    assert res["count_revoked"] == 1
    assert reg._wraps[1]["status"] == "active", "l'entrée hors scope ne doit pas être révoquée"


# =============================================================================
# F — REST admin-plane
# =============================================================================

def _asgi_statuses(send_mock):
    return [
        c.args[0].get("status")
        for c in send_mock.call_args_list
        if c.args and isinstance(c.args[0], dict)
        and c.args[0].get("type") == "http.response.start"
    ]


@pytest.mark.parametrize("path,method", [
    ("/admin/api/health", "GET"),
    ("/admin/api/whoami", "GET"),
    ("/admin/api/generate-password", "GET"),
    ("/admin/api/pki/status", "GET"),
    ("/admin/api/pki/roles", "GET"),
    ("/admin/api/tokens", "GET"),
])
def test_rest_admin_plane_denies_wrap_only(path, method):
    """F2 (round 1) : 403 uniforme sur TOUT /admin/api/* pour un wrap-only,
    y compris les routes historiquement « tout token »."""
    from mcp_vault.admin import api

    send = AsyncMock()
    receive = AsyncMock(return_value={"type": "http.request", "body": b"", "more_body": False})
    scope = {"type": "http", "path": path, "method": method, "headers": []}
    _run(api._handle_admin_routes(scope, receive, send, MagicMock(), _wrap_token()))
    statuses = _asgi_statuses(send)
    assert statuses and statuses[0] == 403, f"{path} devrait renvoyer 403 : {statuses}"


def test_rest_post_ssh_operator_access_denied_without_reading_body():
    """Revue pré-commit F3 : le 403 wrap-only précède TOUTE lecture du body —
    receive ne doit jamais être attendu sur le POST ssh/operator-access."""
    from mcp_vault.admin import api

    send = AsyncMock()
    receive = AsyncMock(return_value={"type": "http.request", "body": b"{}",
                                      "more_body": False})
    scope = {"type": "http", "path": "/admin/api/ssh/operator-access",
             "method": "POST", "headers": []}
    _run(api._handle_admin_routes(scope, receive, send, MagicMock(), _wrap_token()))
    statuses = _asgi_statuses(send)
    assert statuses and statuses[0] == 403, f"attendu 403 : {statuses}"
    receive.assert_not_awaited()


def test_rest_admin_plane_read_token_unchanged():
    """Non-régression : un token read garde l'accès aux routes « tout token »."""
    from mcp_vault.admin import api

    send = AsyncMock()
    receive = AsyncMock(return_value={"type": "http.request", "body": b"", "more_body": False})
    scope = {"type": "http", "path": "/admin/api/whoami", "method": "GET", "headers": []}
    _run(api._handle_admin_routes(scope, receive, send, MagicMock(), _read_token()))
    statuses = _asgi_statuses(send)
    assert statuses and statuses[0] == 200, f"whoami read devrait rester 200 : {statuses}"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
