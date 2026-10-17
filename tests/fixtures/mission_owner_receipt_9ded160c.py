"""Frozen copy of the Mission owner receipt contract, mcp-mission 9ded160c.

Copied verbatim (no edit) from Cloud-Temple/mcp-mission 9ded160cd9f638714dd894a46e516a1664516299:
src/mcp_mission/storage/retention_policy.py (instant),
src/mcp_mission/auth/retention_proof.py (OWNERS, RetentionClaim),
src/mcp_mission/storage/retention_coordination.py (REMOTE_OWNERS, _canonical,
_digest, _validate_vault_references, validate_owner_receipt, owners_ready).
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


def _validate_vault_references(refs, claim):
    # Frozen Vault SQL004 emits four types. References have no native Agent
    # root; the global claim identity above still binds its canonical root.
    calls = {ref['id'] for ref in refs if ref['kind'] == 'audit_call'}
    for ref in refs:
        kind, identifier, revision = ref['kind'], ref['id'], ref['revision']
        if ref['root_agent_id'] != '' or kind not in {
            'audit_call', 'audit_event', 'binding_reference', 'wrap_reference'
        }:
            raise ValueError('Vault retirement reference refused')
        if kind in {'audit_call', 'audit_event'}:
            if revision != 0:
                raise ValueError('Vault immutable audit revision refused')
            call_id, separator, seq = identifier.rpartition(':') if kind == 'audit_event' else (identifier, '', '')
            try:
                if str(UUID(call_id)) != call_id:
                    raise ValueError()
            except (ValueError, AttributeError):
                raise ValueError('Vault audit identity refused') from None
            if kind == 'audit_event' and (
                not separator or not seq.isascii() or not seq.isdecimal()
                or not 1 <= int(seq) <= 9223372036854775807 or str(int(seq)) != seq or call_id not in calls
            ):
                raise ValueError('Vault audit event reference incomplete')
        elif revision < 1:
            raise ValueError('Vault mutable reference revision refused')
        elif kind == 'binding_reference' and identifier != claim.tenant_id:
            raise ValueError('Vault binding scope refused')
        elif kind == 'wrap_reference':
            suffix = ':' + claim.mission_id
            if not identifier.endswith(suffix) or not identifier[:-len(suffix)]:
                raise ValueError('Vault wrap scope refused')


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

