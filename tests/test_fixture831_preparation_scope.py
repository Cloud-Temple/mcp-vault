"""Plan831 R2 §2.2 et P3-2 : union Mission + préparation831 en mode snapshot.

PG substitué par une connexion qui évalue le périmètre avec `permits` du vrai
scope ; aucune base, Bao ou banc. La trace préparatoire elle-même (writer A2)
n'est pas couverte ici.
"""

import hashlib
from contextlib import contextmanager
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest

from mcp_vault.storage import audit_read, hub_vault_activity
from mcp_vault.storage.audit_contract import TOOLS, project_entry
from mcp_vault.storage.audit_read import ExportIncomplete
from mcp_vault.storage.fixture831_preparation import (
    PREPARATION_TOOL,
    MissionHubAuditScope,
    PreparationAuditScope,
)
from mcp_vault.storage.hub_vault_activity import MissionAuditScope
from mcp_vault.tool_catalog import MCP_TOOL_NAMES

from tests.test_hub_vault_activity_842 import hub  # noqa: F401  (fixture ASGI réelle)

ARGS = ("vault842", frozenset({"coffer-a", "coffer-b"}), "tenant-a", "mis_00831001")
NOW = datetime(2026, 10, 16, tzinfo=timezone.utc)
MISSION_ACTOR = "mission_" + "a" * 16
OPERATOR_ACTOR = "operator_" + "b" * 16


def row(seq, *, actor=MISSION_ACTOR, tool="secret_read", **change):
    base = dict(instance_id="vault842", call_id=str(uuid4()), actor_ref=actor, tool=tool,
                vault_id="coffer-a", tenant_id="tenant-a", mission_id="mis_00831001",
                operation_id=None, seq=seq, phase="public_terminal", outcome="completed",
                duration_ms=1, created_at=NOW, expires_at=NOW, step_id=None, mutation_id=None)
    base.update(change)
    return base


def test_mission_scope_class_and_sql_branch_are_byte_identical():
    import inspect

    source = inspect.getsource(hub_vault_activity)
    start = source.index("@dataclass(frozen=True)\nclass MissionAuditScope")
    cls = source[start:source.index("\n\n\ndef local_scope", start)]
    assert hashlib.sha256(cls.encode()).hexdigest() == (
        "efa00a80dba4128aecefc33b17202582b7fac4e40d0f806a6effc7d614d370b3")
    source = inspect.getsource(audit_read)
    start = source.index("    from .hub_vault_activity import MissionAuditScope\n    if isinstance(scope, MissionAuditScope):")
    end = source.index("scope.mission_id]\n", start) + len("scope.mission_id]\n")
    assert hashlib.sha256(source[start:end].encode()).hexdigest() == (
        "ee128c4550b113b186840d7181653308629d0ca719808e9e7b088477e2e83555")
    clauses, _ = audit_read.where_scope(MissionAuditScope(*ARGS))
    assert "left(c.actor_ref,8)='mission_'" in clauses and not any("operator_" in c for c in clauses)


def test_preparation_tool_is_internal_audit_identifier_only():
    assert PREPARATION_TOOL in TOOLS and PREPARATION_TOOL not in MCP_TOOL_NAMES


@pytest.mark.parametrize("candidate,mission,preparation", [
    (row(1), True, False),
    (row(1, actor=OPERATOR_ACTOR, tool=PREPARATION_TOOL), False, True),
    (row(1, actor=OPERATOR_ACTOR, tool="secret_read"), False, False),
    (row(1, actor=OPERATOR_ACTOR, tool="token_create"), False, False),
    (row(1, actor="operator_" + "b" * 15, tool=PREPARATION_TOOL), False, False),
    (row(1, actor="tok_" + "a" * 16, tool=PREPARATION_TOOL), False, False),
    (row(1, actor="anonymous", tool=PREPARATION_TOOL), False, False),
    (row(1, actor=OPERATOR_ACTOR, tool=PREPARATION_TOOL, tenant_id="tenant-b"), False, False),
    (row(1, actor=OPERATOR_ACTOR, tool=PREPARATION_TOOL, mission_id="mis_00831002"), False, False),
    (row(1, actor=OPERATOR_ACTOR, tool=PREPARATION_TOOL, vault_id="coffer-z"), False, False),
    (row(1, actor=OPERATOR_ACTOR, tool=PREPARATION_TOOL, instance_id="other"), False, False),
    (row(1, actor=OPERATOR_ACTOR, tool=PREPARATION_TOOL, tenant_id=None, mission_id=None), False, False),
])
def test_union_permits_exactly_mission_or_closed_preparation(candidate, mission, preparation):
    assert MissionAuditScope(*ARGS).permits(candidate) is mission
    assert PreparationAuditScope(*ARGS).permits(candidate) is preparation
    assert MissionHubAuditScope(*ARGS).permits(candidate) is (mission or preparation)


def test_union_sql_keeps_mission_values_and_inlines_closed_tool():
    clauses, values = audit_read.where_scope(MissionHubAuditScope(*ARGS))
    assert clauses == [
        "c.instance_id=%s", "c.vault_id=ANY(%s)",
        "(left(c.actor_ref,8)='mission_' OR (left(c.actor_ref,9)='operator_' AND c.tool='fixture831_prepare_read'))",
        "c.tenant_id=%s", "c.mission_id=%s"]
    assert values == ["vault842", ["coffer-a", "coffer-b"], "tenant-a", "mis_00831001"]
    clauses, _ = audit_read.where_scope(PreparationAuditScope(*ARGS))
    assert "(left(c.actor_ref,9)='operator_' AND c.tool='fixture831_prepare_read')" in clauses
    assert not any("mission_'" in clause for clause in clauses)
    with pytest.raises(PermissionError):
        audit_read.where_scope(MissionHubAuditScope("vault842", frozenset(), "tenant-a", "mis_00831001"))


def snapshot_connection(rows, scope, state):
    """Évalue le périmètre avec le vrai `permits` ; vérifie que le SQL est celui du snapshot."""

    class Conn:
        def execute(self, sql, params=None):
            values = []
            if "audit_revision" in sql:
                state["global_revision_reads"] += 1
                values = [dict(revision=state["revision"])]
            elif "max(seq)" in sql:
                values = [dict(upper=max(r["seq"] for r in rows))]
            elif "JOIN vault_metadata.audit_events" in sql:
                assert "c.tool='fixture831_prepare_read'" in sql
                matching = [r for r in rows if scope.permits(r) and r["seq"] <= params[4]]
                if sql.startswith("SELECT count"):
                    assert " AS snapshot_hi" in sql, "union lue hors mode snapshot"
                    digests = [hashlib.sha256(str(r["seq"]).encode()).digest() for r in matching]
                    values = [dict(total=len(matching),
                                   snapshot_hi=sum(int.from_bytes(d[:8], "big", signed=True) for d in digests),
                                   snapshot_lo=sum(int.from_bytes(d[8:16], "big", signed=True) for d in digests))]
                elif "GROUP BY" in sql:
                    values = []
                else:
                    values = sorted((r for r in matching if r["seq"] < params[-2]),
                                    key=lambda r: r["seq"], reverse=True)[: params[-1]]
            elif sql == "COMMIT" and state.get("after_commit"):
                action, state["after_commit"] = state["after_commit"], None
                action()
            return SimpleNamespace(fetchall=lambda: values, fetchone=lambda: values[0] if values else None)

    @contextmanager
    def connected():
        yield Conn()

    return connected


@pytest.fixture
def union(monkeypatch):
    scope = MissionHubAuditScope(*ARGS)
    rows = [row(3), row(5, actor=OPERATOR_ACTOR, tool=PREPARATION_TOOL),
            row(6, actor=OPERATOR_ACTOR, tool="token_create"), row(7, actor="tok_" + "c" * 16,
                                                                    tenant_id=None, mission_id=None)]
    state = dict(revision=1, global_revision_reads=0)
    monkeypatch.setattr(audit_read, "connection", snapshot_connection(rows, scope, state))
    monkeypatch.setattr(audit_read, "revalidate_actor", lambda conn: None)
    return SimpleNamespace(scope=scope, rows=rows, state=state)


def test_union_page_counts_both_kinds_in_snapshot_mode(union):
    page = audit_read.read_page(union.scope, limit=10)
    assert page["total"] == 2 and page["complete"] is True
    assert [(e["client"], e["tool"], e["category"]) for e in page["entries"]] == [
        (OPERATOR_ACTOR, PREPARATION_TOOL, "fixture831"), (MISSION_ACTOR, "secret_read", "secret")]
    assert union.state["global_revision_reads"] == 0  # pas de révision globale : empreinte de membres


def test_union_pagination_ignores_foreign_changes_but_detects_membership_replacement(union):
    first = audit_read.read_page(union.scope, limit=1)
    assert first["total"] == 2 and first["cursor"] is not None
    union.rows.append(row(9, actor=OPERATOR_ACTOR, tool="token_create"))  # hors union
    union.state["revision"] += 5
    assert audit_read.read_page(union.scope, limit=1, cursor=first["cursor"])["complete"] is True
    first = audit_read.read_page(union.scope, limit=1)
    preparation = next(r for r in union.rows if r["tool"] == PREPARATION_TOOL)
    union.rows.remove(preparation)
    union.rows.append({**preparation, "seq": 4, "call_id": str(uuid4())})  # même compte, autre membre
    with pytest.raises(ExportIncomplete, match="audit_export_changed"):
        audit_read.read_page(union.scope, limit=1, cursor=first["cursor"])


def test_union_membership_checked_again_after_commit(union):
    preparation = next(r for r in union.rows if r["tool"] == PREPARATION_TOOL)
    union.state["after_commit"] = lambda: union.rows.remove(preparation)
    with pytest.raises(ExportIncomplete, match="audit_export_changed"):
        audit_read.read_page(union.scope, limit=10)


def test_project_entry_refuses_preparation_row_outside_union():
    candidate = row(1, actor=OPERATOR_ACTOR, tool=PREPARATION_TOOL)
    assert project_entry(candidate, MissionAuditScope(*ARGS)) is None
    assert project_entry(candidate, MissionHubAuditScope(*ARGS))["tool"] == PREPARATION_TOOL


async def test_hub_delegated_read_uses_union_scope(hub, monkeypatch):  # noqa: F811
    seen = []
    real = audit_read.read_page

    def spy(scope, **kwargs):
        seen.append(scope)
        return real(scope, **kwargs)

    monkeypatch.setattr(hub_vault_activity, "read_page", spy)
    result = await hub.call()
    assert result.status_code == 200, result.text
    assert [type(scope) for scope in seen] == [MissionHubAuditScope]
    assert (seen[0].tenant_id, seen[0].mission_id) == ("tenant-a", "mis_00842001")
