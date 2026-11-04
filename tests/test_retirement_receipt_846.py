"""846: the Vault owner receipt fits Mission's shared budget, even at zero.

Mission bounds the SUM of the four remote owner receipts to 1000 references
and waits for a Vault receipt for EVERY claim. The receipt carries four
aggregated references; the exhaustive inventory stays in Vault. When no Vault
audit is retained for the scope at closure (the common case), the receipt has
four zero counts, each bound to the digest of the empty list: the closure
refuses any later correlation.

The Mission side is a verbatim frozen copy of #914 (mission_owner_receipt_914).
The SQL aggregate itself is checked against PG17 by tests/fixtures/retirement_846_pg.py.
"""

import json
import random

import pytest

from mcp_vault.storage import retirement_maintenance as owner
from mcp_vault.storage.postgres import MetadataUnavailable
from tests.fixtures import mission_owner_receipt_914 as mission
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


def test_frozen_914_finalizes_a_mission_with_5000_vault_events():
    value = receipt("vault", aggregate(large_inventory()))
    assert mission.validate_owner_receipt(value, claim("vault")) is value
    assert mission.owners_ready(mission_receipts(value), claims()) is True


def test_per_id_receipt_is_refused_at_any_size():
    with pytest.raises(ValueError, match="bounded retention references required"):
        mission.validate_owner_receipt(receipt("vault", large_inventory()), claim("vault"))
    with pytest.raises(ValueError, match="Vault retirement reference refused"):
        mission.validate_owner_receipt(receipt("vault", inventory(calls=2)), claim("vault"))


@pytest.mark.parametrize("binding", [1, 0])
def test_mission_that_never_called_vault_gets_a_finalizable_empty_receipt(binding):
    refs = aggregate(inventory(calls=0, binding=binding))
    assert [ref["revision"] for ref in refs] == [0, 0, binding, 0]
    assert sum(ref["id"] == owner.EMPTY_AGGREGATE for ref in refs) == 4 - binding
    value = receipt("vault", refs)
    assert owner.validate_envelope(value, claim("vault").identity(), OPERATION) is value
    assert mission.validate_owner_receipt(value, claim("vault")) is value
    assert mission.owners_ready(mission_receipts(value), claims()) is True


@pytest.mark.parametrize(
    "mutation",
    [
        "legacy_per_id",
        "missing_kind",
        "foreign_root",
        "two_bindings",
        "events_without_calls",
        "zero_with_digest",
        "count_with_empty_digest",
    ],
)
def test_vault_and_frozen_mission_both_refuse(mutation):
    refs = aggregate(inventory(calls=2))
    if mutation == "legacy_per_id":
        refs = inventory(calls=2)
    if mutation == "missing_kind":
        refs.pop()
    if mutation == "foreign_root":
        refs[0]["root_agent_id"] = "root-a"
    if mutation == "two_bindings":
        refs[2]["revision"] = 2
    if mutation == "events_without_calls":
        refs[0] = dict(refs[0], revision=0, id=owner.EMPTY_AGGREGATE)
    if mutation == "zero_with_digest":
        refs[3] = dict(refs[3], id="sha256:" + "d" * 64)  # no wrap, revision 0
    if mutation == "count_with_empty_digest":
        refs[3] = dict(refs[3], revision=1)
    value = receipt("vault", refs)
    with pytest.raises(ValueError):
        mission.validate_owner_receipt(value, claim("vault"))
    with pytest.raises(MetadataUnavailable):
        owner.validate_envelope(value, claim("vault").identity(), OPERATION)


def test_vault_and_frozen_mission_validators_agree():
    base = aggregate(inventory(calls=3, events_per_call=2))
    cases = [base, aggregate(inventory(calls=0)), aggregate(inventory(calls=0, binding=0))]
    for index in range(4):
        for revision in (0, 1, 2, 7):
            for bound in (True, False):
                refs = [dict(ref) for ref in base]
                refs[index]["revision"] = revision
                if bound and revision == 0:
                    refs[index]["id"] = owner.EMPTY_AGGREGATE
                cases.append(refs)
    verdicts = []
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
        verdicts.append(vault_ok)
    # Not a vacuous agreement: both sides accept and refuse real cases.
    assert 0 < sum(verdicts) < len(verdicts)
