"""Contrats purs avant raccord PG ; aucune preuve d'écriture durable déduite."""

import copy
import json
from uuid import uuid4

import pytest

from mcp_vault.storage.audit_contract import AuditScope, audit_scope, project_entry


def reader():
    return {"permissions": ["read"], "allowed_resources": ["coffer-a", "coffer-b"], "policy_id": "auditor"}


def policy(rules=None):
    return {"policy_id": "auditor", "allowed_tools": ["audit_log"], "denied_tools": [], "path_rules": rules if rules is not None else [
        {"vault_pattern": "coffer-a", "permissions": ["read"], "allowed_paths": []}]}


def event(**changes):
    return {"instance_id": "vault179", "actor_ref": "tok_" + "a"*16,
            "call_id": str(uuid4()), "tool": "secret_read", "phase": "public_terminal",
            "outcome": "completed", "vault_id": "coffer-a", "tenant_id": None,
            "created_at": "2026-10-15T00:00:00Z", "expires_at": "2027-10-15T00:00:00Z",
            "duration_ms": 4.2, **changes}


def test_existing_policy_projection_requires_explicit_whole_coffer_grant():
    scope = audit_scope("vault179", reader(), policy())
    assert scope.coffers == frozenset({"coffer-a"})
    assert scope.permits(event())
    assert not scope.permits(event(vault_id="coffer-b"))
    assert not scope.permits(event(instance_id="other"))
    assert not scope.permits(event(tenant_id="tenant-private"))
    assert not scope.permits(event(vault_id=""))
    assert not scope.permits(event(mission_id="mission-without-tenant"))


@pytest.mark.parametrize("rules", [[],
    [{"vault_pattern": "coffer-*", "permissions": ["read"], "allowed_paths": ["*"]}],
    [{"vault_pattern": "coffer-*", "permissions": ["read"], "allowed_paths": ["db/*"]}],
    [{"vault_pattern": "coffer-*", "permissions": [], "allowed_paths": []}],
    [{"vault_pattern": "coffer-*", "permissions": ["read"]}],
    [{"vault_pattern": "coffer-a", "permissions": [], "allowed_paths": []},
     {"vault_pattern": "coffer-a", "permissions": ["read"], "allowed_paths": []}],
])
def test_absent_limited_or_first_denied_rule_never_expands_audit(rules):
    with pytest.raises(PermissionError):
        audit_scope("vault179", reader(), policy(rules))


@pytest.mark.parametrize("change", [
    {"allowed_tools": []}, {"allowed_tools": ["*"]}, {"denied_tools": ["audit_*"]},
    {"path_rules": "all"}, {"denied_tools": "none"}, {"policy_id": "unrelated"},
])
def test_policy_corruption_missing_capability_and_deny_precedence(change):
    with pytest.raises(PermissionError):
        audit_scope("vault179", reader(), {**policy(), **change})


@pytest.mark.parametrize("identity", [
    {"permissions": "admin"}, {"permissions": ["read"], "allowed_resources": []},
    {"permissions": ["wrap"], "allowed_resources": ["coffer-a"]},
    {"permissions": ["admin"], "auth_type": "mission_jwt"},
])
def test_no_identity_upgrade_or_mission_jwt_audit(identity):
    with pytest.raises(PermissionError):
        audit_scope("vault179", identity, policy())


def test_projection_never_copies_legacy_detail_results_or_secrets():
    source = event(detail="password=CANARY", data={"secret": "CANARY"}, raw_token="CANARY",
                   client_name="CANARY", error="CANARY", headers={"Authorization": "CANARY"})
    before = copy.deepcopy(source)
    view = project_entry(source, audit_scope("vault179", reader(), policy()))
    assert "CANARY" not in json.dumps(view)
    assert view["client"] == "tok_" + "a"*16
    assert view["detail"] == ""
    assert source == before
    assert project_entry(source, AuditScope("other", None)) is None


def test_admin_keeps_existing_instance_scope_and_validated_correlations():
    scope = audit_scope("vault179", {"permissions": ["admin"]}, None)
    view = project_entry(event(tenant_id="tenant-a", mission_id="mission-a"), scope)
    assert view["tenant_id"] == "tenant-a"
    assert project_entry(event(instance_id="other"), scope) is None


@pytest.mark.parametrize("change", [
    {"actor_ref": "raw-token-SECRET"}, {"tool": "secret\nforged"},
    {"duration_ms": float("nan")}, {"duration_ms": True}, {"duration_ms": -1},
    {"created_at": "2026-10-15T00:00:00"}, {"call_id": "malformed"},
    {"mission_id": "bad\nreference"}, {"phase": "successful-internal-step"},
])
def test_invalid_stored_data_is_not_published(change):
    with pytest.raises(ValueError):
        project_entry(event(**change), AuditScope("vault179", None))


def test_anonymous_event_is_admin_only_even_on_authorized_coffer():
    anonymous = event(actor_ref="anonymous")
    assert project_entry(anonymous, audit_scope("vault179", reader(), policy())) is None
    assert project_entry(anonymous, audit_scope("vault179", {"permissions": ["admin"]}, None))["client"] == "anonymous"


@pytest.mark.parametrize("permissions", [["read", "wrap"], ["admin", "wrap"]])
def test_wrap_flag_with_existing_read_or_admin_keeps_local_permission(permissions):
    identity = {**reader(), "permissions": permissions}
    assert audit_scope("vault179", identity, policy()).permits(event())


def test_invalid_timestamp_exception_never_contains_input():
    with pytest.raises(ValueError) as raised:
        project_entry(event(created_at="SECRET-CANARY-invalid-date"), AuditScope("vault179", None))
    assert str(raised.value) == "audit timestamp invalid"


def test_internal_steps_keep_only_validated_uuid_correlations():
    step = str(uuid4())
    view = project_entry(event(phase="sql_step_committed", step_id=step, mutation_id=step), AuditScope("vault179", None))
    assert view["step_id"] == view["mutation_id"] == step
    with pytest.raises(ValueError, match="^audit step invalid$"):
        project_entry(event(step_id="SECRET-CANARY"), AuditScope("vault179", None))
