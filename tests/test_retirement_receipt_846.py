"""846 P2: the Vault owner receipt fits Mission's shared 1000-reference budget.

Mission 9ded160c bounds the SUM of the four remote owner receipts to 1000
references (owners_ready, record_owner_receipt). A per-id Vault receipt made
any Mission above ~1000 audit rows impossible to finalize. The receipt now
carries four aggregated references; the exhaustive inventory stays in Vault.

The Mission side is a verbatim frozen copy of 9ded160c. Its Vault branch
(_validate_vault_references) only knows the four per-id kinds, so the
aggregated receipt needs the #914 change proposed below. The SQL aggregate
itself is checked against PG17 by tests/fixtures/retirement_846_pg.py.
"""

import json
import random
import re

import pytest

from mcp_vault.storage import retirement_maintenance as owner
from mcp_vault.storage.postgres import MetadataUnavailable
from tests.fixtures import mission_owner_receipt_9ded160c as mission
from tests.fixtures.vault_receipt_846 import aggregate, inventory

OPERATION = "22222222-2222-4222-8222-222222222222"
CONTRACTS = {
    "agent": {"events389": "v1", "access391": "v1", "costs390": "v1", "recovery845": "v1"},
    "teleport": {"audit366": "v1", "holds846": "v1"},
    "vault": {"audit179": "v1", "holds846": "v1"},
    "tools": {"activity31": "v1", "files843": "v1", "recovery845": "v1", "holds846": "v1"},
}
AGGREGATES = (
    "vault_audit_calls",
    "vault_audit_events",
    "vault_binding_references",
    "vault_wrap_references",
)


def proposed_validate_vault_references(refs, claim):
    """Proposed replacement of _validate_vault_references for mcp-mission #914."""
    if [ref["kind"] for ref in refs] != list(AGGREGATES) or any(
        ref["root_agent_id"] != "" or not re.fullmatch(r"sha256:[0-9a-f]{64}", ref["id"])
        for ref in refs
    ):
        raise ValueError("Vault retirement reference refused")
    calls, events, bindings, _ = (ref["revision"] for ref in refs)
    if calls < 1 or events < calls or bindings > 1:
        raise ValueError("Vault audit inventory incomplete")


def claim(owner_name):
    return mission.RetentionClaim(
        owner_name,
        "tenant-a",
        "mission-a",
        "root-a",
        "11111111-1111-4111-8111-111111111111",
        3,
        "2024-01-01T00:00:00+00:00",
        "2025-01-02T00:00:00+00:00",
        "a" * 64,
    )


def receipt(owner_name, refs):
    return claim(owner_name).identity() | {
        "state": "retired_confirmed",
        "inventory_complete": True,
        "operation_id": OPERATION,
        "receipt_sha256": "b" * 64,
        "references": refs,
        "contracts": CONTRACTS[owner_name],
    }


def other_owners():
    tombstone = {
        "kind": "teleport_mission_tombstone",
        "id": "mission-a",
        "revision": 3,
        "root_agent_id": "root-a",
    }
    tools = [
        {"kind": kind, "id": "sha256:" + "c" * 64, "revision": 7000, "root_agent_id": "root-a"}
        for kind in ("tools_activity_calls", "tools_activity_events", "tools_file_dependencies")
    ]
    return {
        "agent": receipt("agent", []),
        "teleport": receipt("teleport", [tombstone]),
        "tools": receipt("tools", tools),
    }


def mission_receipts(vault_value):
    owners = other_owners() | {"vault": vault_value, "mission": {"state": "local"}}
    return {"format": 1, "owners": owners}


def claims():
    return {name: claim(name) for name in mission.REMOTE_OWNERS}


def large_inventory():
    # 2500 calls with two events each: 5000 Vault audit events for one Mission.
    return inventory(calls=2500, events_per_call=2, wraps=[("op-1:mission-a", 2)])


def test_vault_receipt_for_5000_events_is_four_references():
    rows = large_inventory()
    refs = aggregate(rows)
    assert [ref["revision"] for ref in refs] == [2500, 5000, 1, 1]
    value = receipt("vault", refs)
    assert owner.validate_envelope(value, claim("vault").identity(), OPERATION) is value
    assert len(json.dumps(value).encode()) < 4096


def test_aggregate_is_order_free_and_binds_every_id_and_revision():
    rows = large_inventory()
    reference = aggregate(rows)
    shuffled = rows[:]
    random.Random(846).shuffle(shuffled)
    assert aggregate(shuffled) == reference
    for index, field, value in [
        (1, "id", rows[1]["id"][:-1] + "9"),
        (-2, "revision", 2),
        (-1, "id", "op-2:mission-a"),
    ]:
        changed = [dict(ref) for ref in rows]
        changed[index][field] = value
        assert aggregate(changed) != reference
    with pytest.raises(ValueError):
        aggregate(rows + [{"kind": "coffer", "id": "x", "revision": 1, "root_agent_id": ""}])


def test_frozen_9ded160c_refuses_the_aggregated_vault_receipt():
    """Tripwire: 9ded160c still needs the #914 Vault branch. Refresh both together."""
    value = receipt("vault", aggregate(large_inventory()))
    with pytest.raises(ValueError, match="Vault retirement reference refused"):
        mission.validate_owner_receipt(value, claim("vault"))


def test_per_id_receipt_at_5000_events_never_finalizes_on_9ded160c():
    rows = large_inventory()
    with pytest.raises(ValueError, match="bounded retention references required"):
        mission.validate_owner_receipt(receipt("vault", rows), claim("vault"))
    # Even under the per-receipt cap, the shared budget refuses it.
    partial = inventory(calls=499, events_per_call=1)
    assert len(partial) == 999
    mission.validate_owner_receipt(receipt("vault", partial), claim("vault"))
    assert mission.owners_ready(mission_receipts(receipt("vault", partial)), claims()) is False


def test_mission_with_5000_vault_events_finalizes_with_the_914_branch(monkeypatch):
    monkeypatch.setattr(
        mission, "_validate_vault_references", proposed_validate_vault_references
    )
    value = receipt("vault", aggregate(large_inventory()))
    assert mission.validate_owner_receipt(value, claim("vault")) is value
    assert mission.owners_ready(mission_receipts(value), claims()) is True


@pytest.mark.parametrize(
    "mutation", ["legacy_per_id", "missing_kind", "foreign_root", "no_calls", "two_bindings"]
)
def test_proposed_914_branch_stays_closed(monkeypatch, mutation):
    monkeypatch.setattr(
        mission, "_validate_vault_references", proposed_validate_vault_references
    )
    refs = aggregate(inventory(calls=2))
    if mutation == "legacy_per_id":
        refs = inventory(calls=2)
    if mutation == "missing_kind":
        refs.pop()
    if mutation == "foreign_root":
        refs[0]["root_agent_id"] = "root-a"
    if mutation == "no_calls":
        refs[0]["revision"] = 0
    if mutation == "two_bindings":
        refs[2]["revision"] = 2
    with pytest.raises(ValueError):
        mission.validate_owner_receipt(receipt("vault", refs), claim("vault"))


def test_vault_and_proposed_mission_validators_agree(monkeypatch):
    monkeypatch.setattr(
        mission, "_validate_vault_references", proposed_validate_vault_references
    )
    base = aggregate(inventory(calls=3, events_per_call=2))
    cases = [base]
    for index in range(4):
        for revision in (0, 1, 2, 7):
            refs = [dict(ref) for ref in base]
            refs[index]["revision"] = revision
            cases.append(refs)
    for refs in cases:
        value = receipt("vault", refs)
        try:
            owner.validate_envelope(value, claim("vault").identity(), OPERATION)
            vault_ok = True
        except MetadataUnavailable:
            vault_ok = False
        try:
            mission.validate_owner_receipt(value, claim("vault"))
            mission_ok = True
        except ValueError:
            mission_ok = False
        assert vault_ok is mission_ok, refs
