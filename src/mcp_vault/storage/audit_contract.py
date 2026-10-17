"""Projection et périmètre d'audit #179 ; aucun accès réseau ou persistance.

Les entrées d'identité/policy viennent exclusivement de l'authentification
fraîche du service. Ce module ne transforme pas une entrée HTTP en identité.
"""

import fnmatch
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

from ..tool_catalog import MCP_TOOL_NAMES
from ..vault_ids import is_valid_vault_id

TOOLS = MCP_TOOL_NAMES | {
    "token_create", "token_revoke", "token_purge", "policy_create", "policy_delete",
    "mission_binding_create", "mission_binding_delete", "mission_binding_purge",
    "bearer_auth", "mission_pep", "audit_expire",
    "token_list", "mission_binding_list", "mission_binding_get", "pki_ca_status",
}
PHASES = frozenset({"admission", "sql_step_committed", "bao_step_outcome", "compensation_outcome", "public_terminal"})
OUTCOMES = frozenset({"admitted", "denied", "confirmed", "failed", "unknown", "completed", "incomplete"})
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
ACTOR = re.compile(r"(?:anonymous|(?:tok|mission|operator)_[0-9a-f]{16})\Z")


@dataclass(frozen=True)
class AuditScope:
    instance: str
    coffers: frozenset[str] | None  # None : administrateur local authentifié.

    def permits(self, row):
        if row.get("instance_id") != self.instance:
            return False
        if self.coffers is None:
            return True
        # Un token opaque local n'authentifie aucun tenant Mission.
        return (row.get("actor_ref") != "anonymous" and row.get("vault_id") in self.coffers
                and row.get("tenant_id") is None and row.get("mission_id") is None)


def audit_scope(instance, identity, policy):
    """Projection conservative de la policy existante, sans modifier ses gardes."""
    if not isinstance(instance, str) or not IDENT.fullmatch(instance):
        raise PermissionError("audit scope invalid")
    if not isinstance(identity, dict) or identity.get("auth_type") in {"mission_jwt", "hub_vault_read"}:
        raise PermissionError("audit scope denied")
    permissions = identity.get("permissions")
    if not isinstance(permissions, list) or not all(isinstance(p, str) for p in permissions):
        raise PermissionError("audit scope denied")
    if "wrap" in permissions and not set(permissions) & {"read", "write", "admin"}:
        raise PermissionError("audit scope denied")
    if "admin" in permissions:
        return AuditScope(instance, None)
    resources = identity.get("allowed_resources")
    if ("read" not in permissions or not isinstance(resources, list) or not resources
            or not all(isinstance(v, str) and is_valid_vault_id(v) for v in resources)
            or not isinstance(policy, dict) or not isinstance(identity.get("policy_id"), str)
            or not identity["policy_id"] or policy.get("policy_id") != identity["policy_id"]):
        raise PermissionError("audit scope denied")
    allowed, denied, rules = (policy.get(k) for k in ("allowed_tools", "denied_tools", "path_rules"))
    if (not isinstance(allowed, list) or "audit_log" not in allowed
            or not all(isinstance(v, str) for v in allowed)
            or not isinstance(denied, list) or not all(isinstance(v, str) for v in denied)
            or any(fnmatch.fnmatchcase("audit_log", pattern) for pattern in denied)
            or not isinstance(rules, list)):
        raise PermissionError("audit scope denied")
    visible = set()
    for coffer in resources:
        for rule in rules:
            if (not isinstance(rule, dict) or not isinstance(rule.get("vault_pattern"), str)
                    or not isinstance(rule.get("permissions"), list)
                    or not all(isinstance(p, str) for p in rule["permissions"])
                    or not isinstance(rule.get("allowed_paths"), list)):
                raise PermissionError("audit scope invalid")
            if fnmatch.fnmatchcase(coffer, rule["vault_pattern"]):
                if not rule["allowed_paths"] and set(rule["permissions"]) & {"read", "write", "admin"}:
                    visible.add(coffer)
                break  # Première règle, même si elle refuse.
    if not visible:
        raise PermissionError("audit scope denied")
    return AuditScope(instance, frozenset(visible))


def _utc(value):
    try:
        if isinstance(value, str):
            if len(value) > 64:
                raise ValueError()
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if not isinstance(value, datetime) or value.utcoffset() != timezone.utc.utcoffset(value):
            raise ValueError()
        return value.isoformat()
    except (ValueError, TypeError, OverflowError):
        raise ValueError("audit timestamp invalid") from None


def _uuid(value, diagnostic="audit identifier invalid"):
    try:
        return str(UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        raise ValueError(diagnostic) from None


def project_entry(row, scope):
    """Allowlist positive ; aucun détail/exception/payload hérité n'est exporté."""
    if not scope.permits(row):
        return None
    actor, tool, phase, outcome = (row.get(k) for k in ("actor_ref", "tool", "phase", "outcome"))
    duration = row.get("duration_ms", 0)
    if (not isinstance(actor, str) or not ACTOR.fullmatch(actor)
            or not isinstance(tool, str) or tool not in TOOLS
            or not isinstance(phase, str) or phase not in PHASES
            or not isinstance(outcome, str) or outcome not in OUTCOMES
            or isinstance(duration, bool) or not isinstance(duration, (int, float))
            or not math.isfinite(duration) or duration < 0):
        raise ValueError("audit entry invalid")
    coffer = row.get("vault_id", "")
    if not isinstance(coffer, str) or (coffer and not is_valid_vault_id(coffer)):
        raise ValueError("audit entry invalid")
    result = {
        "call_id": _uuid(row.get("call_id")),
        "ts": _utc(row["created_at"]), "expires_at": _utc(row["expires_at"]),
        "client": actor, "tool": tool, "phase": phase, "status": outcome,
        "category": tool.split("_", 1)[0], "vault_id": coffer,
        "detail": "", "duration_ms": duration,
    }
    # Corrélateurs validés, jamais une chaîne detail libre.
    for key in ("tenant_id", "mission_id", "operation_id"):
        value = row.get(key)
        if value is not None:
            if not isinstance(value, str) or not IDENT.fullmatch(value):
                raise ValueError("audit correlation invalid")
            result[key] = value
    for key in ("step_id", "mutation_id"):
        if row.get(key) is not None:
            result[key] = _uuid(row[key], "audit step invalid")
    return result
