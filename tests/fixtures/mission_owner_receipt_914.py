"""Frozen copy of the Mission owner receipt contract, mcp-mission #914.

Copied verbatim (no edit, extracted by AST) from the Cloud-Temple/mcp-mission
#914 branch at d51d230e (base 3afd31a1 plus the zero-activity Vault receipt),
committed 17/10/2026.
src/mcp_mission/storage/retention_policy.py (instant),
src/mcp_mission/auth/retention_proof.py (OWNERS, RetentionClaim),
src/mcp_mission/storage/retention_coordination.py (REMOTE_OWNERS, _canonical,
_digest, aggregate validators, validate_owner_receipt, owners_ready).
Refresh it from the merged #914 revision; never adapt it to make Vault pass.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID


def instant(value):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return None
    if not isinstance(value, datetime) or value.utcoffset() is None:
        return None
    return value.astimezone(timezone.utc)


OWNERS = frozenset({"mission", "agent", "teleport", "vault", "tools"})


@dataclass(frozen=True)
class RetentionClaim:
    owner: str
    tenant_id: str
    mission_id: str
    root_agent_id: str
    claim_id: str
    claim_revision: int
    terminal_at: str
    retain_until: str
    manifest_sha256: str

    def __post_init__(self):
        if (not isinstance(self.owner, str) or self.owner not in OWNERS
                or type(self.claim_revision) is not int or self.claim_revision < 1
                or any(not isinstance(v, str) or not v or len(v.encode()) > 256
                       for v in (self.tenant_id, self.mission_id))
                or not isinstance(self.root_agent_id, str) or len(self.root_agent_id.encode()) > 256
                or self.owner == "agent" and not self.root_agent_id):
            raise ValueError("retention scope refused")
        try:
            if str(UUID(self.claim_id)) != self.claim_id:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise ValueError("retention claim refused") from None
        ended, until = instant(self.terminal_at), instant(self.retain_until)
        if (ended is None or until is None or until < ended + timedelta(days=365)
                or not isinstance(self.manifest_sha256, str) or len(self.manifest_sha256) != 64
                or any(c not in "0123456789abcdef" for c in self.manifest_sha256)):
            raise ValueError("retention closure refused")

    def identity(self):
        # Stable across short-lived proof renewals, without copying any payload.
        return {"owner": self.owner, "tenant_id": self.tenant_id, "mission_id": self.mission_id,
                "root_agent_id": self.root_agent_id, "claim_id": self.claim_id,
                "claim_revision": self.claim_revision,
                "terminal_at": instant(self.terminal_at).isoformat(),
                "retain_until": instant(self.retain_until).isoformat(),
                "manifest_sha256": self.manifest_sha256}

    def fingerprint(self):
        return hashlib.sha256(json.dumps(self.identity(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


REMOTE_OWNERS = OWNERS - {"mission"}


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


def _digest(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


VAULT_AGGREGATES = ("vault_audit_calls", "vault_audit_events", "vault_binding_references",
                    "vault_wrap_references")


TOOLS_AGGREGATES = ("tools_activity_calls", "tools_activity_events", "tools_file_dependencies")


def _aggregate_id(value):
    # sha256 of the owner's sorted (COLLATE "C") inventory; the owner keeps the list.
    return value.startswith("sha256:") and _digest(value[7:])


def _validate_aggregates(refs, kinds, root, label):
    # The shared budget is 1000 for all owners: one fixed reference per kind,
    # in the producer's order, revision = count (int >= 0, checked by the caller).
    if ([ref["kind"] for ref in refs] != list(kinds)
            or any(not _aggregate_id(ref["id"]) or ref["root_agent_id"] != root for ref in refs)):
        raise ValueError(label + " retirement reference refused")
    return [ref["revision"] for ref in refs]


EMPTY_AGGREGATE = "sha256:" + hashlib.sha256(b"[]").hexdigest()


def _validate_vault_references(refs, claim):
    # Vault #846 (004_retirement.sql) has no native Agent root: root stays empty,
    # the claim identity above binds it. Same invariants as Vault validate_envelope.
    # A Mission without Vault activity gets four zero counts: its closure blocks
    # any later correlation, so zero is proven, and each carries the digest of [].
    calls, events, bindings, _ = _validate_aggregates(refs, VAULT_AGGREGATES, "", "Vault")
    if any((ref["revision"] == 0) != (ref["id"] == EMPTY_AGGREGATE) for ref in refs):
        raise ValueError("Vault retirement reference refused")
    if events < calls or calls == 0 and events != 0 or bindings > 1:
        raise ValueError("Vault audit inventory incomplete")


def _validate_tools_references(refs, claim):
    # Tools #846 binds every retired call to the claim root (empty root: zero calls).
    _validate_aggregates(refs, TOOLS_AGGREGATES, claim.root_agent_id, "Tools")


def validate_owner_receipt(value, claim):
    """Only the maintenance CLI imports this small post-COMMIT owner envelope.

    SQL maintenance authority is separate from the inspection JWT. UNKNOWN and
    truncated inventories never become receipts; a later SELECT is not an ACK.
    """
    expected = set(claim.identity()) | {"state", "inventory_complete", "operation_id", "receipt_sha256",
                                        "references", "contracts"}
    if (not isinstance(value, dict) or set(value) != expected or claim.owner not in REMOTE_OWNERS
            or any(value.get(key) != actual for key, actual in claim.identity().items())
            or value["state"] != "retired_confirmed" or value["inventory_complete"] is not True
            or not _digest(value["receipt_sha256"])):
        raise ValueError("confirmed scoped retention receipt required")
    try:
        if str(UUID(value["operation_id"])) != value["operation_id"]:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise ValueError("retention operation receipt required") from None
    refs = value["references"]
    if not isinstance(refs, list) or len(refs) > 1000:
        raise ValueError("bounded retention references required")
    seen = set()
    for ref in refs:
        if (not isinstance(ref, dict) or set(ref) != {"kind", "id", "revision", "root_agent_id"}
                or any(not isinstance(ref[key], str) or not ref[key] or len(ref[key].encode()) > 256
                       for key in ("kind", "id"))
                or type(ref["revision"]) is not int or ref["revision"] < 0
                or not isinstance(ref["root_agent_id"], str) or len(ref["root_agent_id"].encode()) > 256):
            raise ValueError("retention reference refused")
        if ref['root_agent_id'] and ref['root_agent_id'] != claim.root_agent_id:
            raise ValueError("retention root refused")
        identity = (ref["kind"], ref["id"], ref["revision"], ref["root_agent_id"])
        if identity in seen:
            raise ValueError("duplicate retention reference")
        seen.add(identity)
    if claim.owner == "vault":
        _validate_vault_references(refs, claim)
    if claim.owner == "tools":
        _validate_tools_references(refs, claim)
    if claim.owner == "teleport":
        allowed = {"teleport_task", "teleport_observation", "teleport_mission_tombstone",
                   "teleport_intent_anchor", "teleport_segment_anchor"}
        tombstone = {"kind": "teleport_mission_tombstone", "id": claim.mission_id,
                     "revision": claim.claim_revision, "root_agent_id": claim.root_agent_id}
        if (any(ref["kind"] not in allowed for ref in refs)
                or [ref for ref in refs if ref["kind"] == "teleport_mission_tombstone"] != [tombstone]):
            raise ValueError("complete Teleport owner retirement receipt required")
    # Missing/unqualified dependencies are explicit, not silently ignored.
    required = {"agent": {"events389": "v1", "access391": "v1", "costs390": "v1", "recovery845": "v1"},
                "teleport": {"audit366": "v1", "holds846": "v1"}, "vault": {"audit179": "v1", "holds846": "v1"},
                "tools": {"activity31": "v1", "files843": "v1", "recovery845": "v1", "holds846": "v1"}}
    if value["contracts"] != required[claim.owner]:
        raise ValueError("retention owner contract incomplete")
    if len(_canonical(value).encode()) > 262144:
        raise ValueError("retention receipt too large")
    return value


def owners_ready(receipts, claims):
    if receipts is None:
        return False
    try:
        if (set(receipts) != {"format", "owners"} or type(receipts["format"]) is not int or receipts["format"] != 1
                or set(receipts["owners"]) != OWNERS or receipts["owners"]["mission"] != {"state": "local"}
                or set(claims) != REMOTE_OWNERS):
            return False
        count = 0
        for owner in REMOTE_OWNERS:
            value = validate_owner_receipt(receipts["owners"][owner], claims[owner])
            count += len(value["references"])
        return count <= 1000
    except (ValueError, KeyError, TypeError, AttributeError):
        return False
