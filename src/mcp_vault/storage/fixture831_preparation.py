"""Périmètre d'audit de la préparation831 (plan831 R1 A2, R2 §2.2).

Une trace de préparation est un Call `operator_*` dont l'outil interne fermé est
`fixture831_prepare_read`, corrélé à l'instance, aux coffres, au tenant et au
MID. Ce module ne lit et n'écrit rien : il définit le périmètre de lecture.
`MissionAuditScope` et sa branche SQL restent identiques à l'octet près.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .audit_contract import AuditScope, TOOLS
from .hub_vault_activity import MissionAuditScope

PREPARATION_TOOL = "fixture831_prepare_read"
OPERATOR = re.compile(r"operator_[0-9a-f]{16}\Z")
if PREPARATION_TOOL not in TOOLS:  # pragma: no cover - garde de cohérence à l'import
    raise RuntimeError("preparation tool outside audit allowlist")
_PREPARATION_SQL = (
    "(left(c.actor_ref,9)='operator_' AND c.tool='" + PREPARATION_TOOL + "')"
)


@dataclass(frozen=True)
class PreparationAuditScope(AuditScope):
    tenant_id: str
    mission_id: str

    def permits(self, row):
        actor = row.get("actor_ref")
        return (
            row.get("instance_id") == self.instance
            and row.get("vault_id") in self.coffers
            and isinstance(actor, str)
            and OPERATOR.fullmatch(actor) is not None
            and row.get("tool") == PREPARATION_TOOL
            and row.get("tenant_id") == self.tenant_id
            and row.get("mission_id") == self.mission_id
        )

    def where(self):
        return _where(self, _PREPARATION_SQL)


@dataclass(frozen=True)
class MissionHubAuditScope(AuditScope):
    """Union lue par le Hub : traces Mission OU préparation831 du même MID."""

    tenant_id: str
    mission_id: str

    def parts(self):
        args = (self.instance, self.coffers, self.tenant_id, self.mission_id)
        return MissionAuditScope(*args), PreparationAuditScope(*args)

    def permits(self, row):
        mission, preparation = self.parts()
        return mission.permits(row) or preparation.permits(row)

    def where(self):
        return _where(self, "(left(c.actor_ref,8)='mission_' OR " + _PREPARATION_SQL + ")")


def _where(scope, actor_clause):
    if not scope.coffers:
        raise PermissionError("audit scope denied")
    clauses = [
        "c.instance_id=%s",
        "c.vault_id=ANY(%s)",
        actor_clause,
        "c.tenant_id=%s",
        "c.mission_id=%s",
    ]
    values = [scope.instance, sorted(scope.coffers), scope.tenant_id, scope.mission_id]
    return clauses, values


SNAPSHOT_SCOPES = (PreparationAuditScope, MissionHubAuditScope)
