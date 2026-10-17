"""Lecture propriétaire842 ; badge, binding et sujet cumulés, aucune écriture métier."""

from __future__ import annotations

import fnmatch
import time
from dataclasses import dataclass

from ..auth.context import current_token_info
from ..auth.token_store import TokenStore
from ..config import get_settings
from .admission import load_facts, preload_owners
from .audit_contract import AuditScope, _utc, audit_scope
from .audit_cursor import context_fingerprint, cursors
from .audit_read import read_page
from .postgres import (
    MetadataUnavailable,
    connection,
    offload,
    request_facts,
    revalidate_actor,
)


@dataclass(frozen=True)
class MissionAuditScope(AuditScope):
    tenant_id: str
    mission_id: str

    def permits(self, row):
        return (
            row.get("instance_id") == self.instance
            and row.get("vault_id") in self.coffers
            and isinstance(row.get("actor_ref"), str)
            and row["actor_ref"].startswith("mission_")
            and row.get("tenant_id") == self.tenant_id
            and row.get("mission_id") == self.mission_id
        )


def local_scope(claims, facts):
    cfg = get_settings()
    token = facts["token"].get_by_hash(facts.get("actor_hash"))
    binding = facts["binding"].resolve(claims["tenant_id"])
    if (
        not token
        or token.get("revoked")
        or TokenStore._is_expired(token)
        or set(token.get("permissions", [])) != {"read"}
        or not token.get("allowed_resources")
        or not binding
        or not binding.get("enabled")
        or binding.get("instance_id") != cfg.metadata_instance_id
    ):
        raise PermissionError("local access refused")
    opaque = dict(token, auth_type="token")
    policy_id = token.get("policy_id", "")
    policy = facts["policy"].get(policy_id) if policy_id else None
    granted = audit_scope(cfg.metadata_instance_id, opaque, policy).coffers
    # metadata tool must be allowed by the same local token policy, not by context JWT.
    if (
        not policy
        or set(policy.get("allowed_tools", [])) != {"audit_log", "vault_metadata_batch"}
        or any(
            fnmatch.fnmatchcase("vault_metadata_batch", p)
            for p in policy.get("denied_tools", [])
        )
    ):
        raise PermissionError("local metadata refused")
    binding_policy_id = binding.get("policy_id", "")
    if binding_policy_id:
        bpolicy = facts["policy"].get(binding_policy_id)
        bound = dict(
            token,
            policy_id=binding_policy_id,
            allowed_resources=binding["allowed_resources"],
        )
        binding_granted = audit_scope(cfg.metadata_instance_id, bound, bpolicy).coffers
        if (
            not bpolicy
            or "vault_metadata_batch" not in bpolicy.get("allowed_tools", [])
            or any(
                fnmatch.fnmatchcase("vault_metadata_batch", p)
                for p in bpolicy.get("denied_tools", [])
            )
        ):
            raise PermissionError("binding metadata refused")
    else:
        binding_granted = frozenset(binding["allowed_resources"])
    coffers = granted & binding_granted
    if (
        not coffers
        or len(coffers) > cfg.metadata_batch_max_ids
        or "read" not in binding["permissions"]
    ):
        raise PermissionError("local coffer scope refused")
    return MissionAuditScope(
        cfg.metadata_instance_id,
        frozenset(coffers),
        claims["tenant_id"],
        claims["mission_id"],
    ), opaque


def revalidate():
    with connection() as conn:
        revalidate_actor(conn)


async def query(raw_opaque, claims, body, validate):
    facts = await offload(load_facts, raw_opaque, claims["tenant_id"])
    scope, opaque = local_scope(claims, facts)
    facts["hub_binding_required"] = True
    identity = dict(
        opaque,
        auth_type="hub_vault_read",
        tenant_id=scope.tenant_id,
        mission_id=scope.mission_id,
    )
    marker = request_facts.set(facts)
    actor_marker = current_token_info.set(identity)
    try:
        await validate()
        await offload(revalidate)
        # Fresh target metadata only; PG absence never becomes an empty coffer.
        await preload_owners(sorted(scope.coffers), batch=True)
        metadata = []
        for vid in sorted(scope.coffers):
            owner = facts["owners"][vid]
            dates = {
                key: _utc(owner[key])
                for key in ("created_at", "updated_at")
                if key in owner
            }
            metadata.append(dict(vault_id=vid, state="available", **dates))
        bound = {
            key: facts.get(key)
            for key in (
                "actor_hash",
                "actor_revision",
                "policy_revisions",
                "actor_binding",
                "binding_revision",
            )
        }
        # Stable between fresh jtis; includes verified user/Mission and every local revision.
        bound.update(
            subject=claims["sub"],
            tenant_id=scope.tenant_id,
            mission_id=scope.mission_id,
        )
        context = context_fingerprint(scope, bound, {})
        internal = cursors.take(body["cursor"], context) if body.get("cursor") else None
        page = await offload(
            read_page, scope, limit=body["limit"], cursor=internal, filters={}
        )
        await validate()
        # The HTTP callback can wait while local token/binding/policy authority changes.
        await offload(revalidate)
        if time.time() >= claims["exp"]:
            raise PermissionError("delegation expired")
        cursor = cursors.put(context, page["cursor"]) if page["cursor"] else None
        from datetime import datetime, timezone

        return dict(
            status="ok",
            source="vault_owner",
            mission_id=scope.mission_id,
            tenant_id=scope.tenant_id,
            read_at=datetime.now(timezone.utc).isoformat(),
            vaults=metadata,
            entries=page["entries"],
            count=len(page["entries"]),
            total=page["total"],
            complete=page["complete"],
            next_cursor=cursor,
            coverage="complete" if page["complete"] else "partial",
        )
    except MetadataUnavailable as exc:
        if exc.reason in {
            "actor_changed",
            "binding_changed",
            "binding_expired",
            "binding_missing",
            "policy_changed",
        }:
            raise PermissionError("local authority changed") from exc
        raise
    finally:
        current_token_info.reset(actor_marker)
        request_facts.reset(marker)
