"""Python twin of vault_metadata.audit_retirement_references (004_retirement.sql).

The PG17 fixture compares both on the real stored inventory. Unit tests use it
to build receipts with the exact SQL shape; they do not prove the SQL itself.
"""

import hashlib
import json

SOURCES = (
    ("vault_audit_calls", "audit_call"),
    ("vault_audit_events", "audit_event"),
    ("vault_binding_references", "binding_reference"),
    ("vault_wrap_references", "wrap_reference"),
)


def aggregate(inventory):
    known = {source for _, source in SOURCES}
    if any(ref["kind"] not in known for ref in inventory):
        raise ValueError("retirement inventory incomplete")
    refs = []
    for kind, source in SOURCES:
        # COLLATE "C" on UTF-8 is byte order, which equals code point order.
        items = sorted(
            f"{ref['id']}@{ref['revision']}" for ref in inventory if ref["kind"] == source
        )
        # jsonb::text of a string array: '["a", "b"]', non-ASCII kept as is.
        text = json.dumps(items, ensure_ascii=False)
        refs.append(
            {
                "kind": kind,
                "id": "sha256:" + hashlib.sha256(text.encode()).hexdigest(),
                "revision": len(items),
                "root_agent_id": "",
            }
        )
    return refs


def inventory(calls, events_per_call=1, tenant="tenant-a", binding=1, wraps=()):
    """Exhaustive SQL inventory rows, in the same four source kinds."""
    from uuid import uuid4

    refs = []
    seq = 0
    for _ in range(calls):
        call = str(uuid4())
        refs.append({"kind": "audit_call", "id": call, "revision": 0, "root_agent_id": ""})
        for _ in range(events_per_call):
            seq += 1
            refs.append(
                {"kind": "audit_event", "id": f"{call}:{seq}", "revision": 0, "root_agent_id": ""}
            )
    if binding:
        refs.append(
            {"kind": "binding_reference", "id": tenant, "revision": binding, "root_agent_id": ""}
        )
    for wrap_id, revision in wraps:
        refs.append(
            {"kind": "wrap_reference", "id": wrap_id, "revision": revision, "root_agent_id": ""}
        )
    return refs
