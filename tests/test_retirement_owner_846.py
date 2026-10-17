"""Owner API gates and post-wait/COMMIT boundaries. Real SQL is a separate fixture."""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest

from mcp_vault.storage import retirement_maintenance as owner
from mcp_vault.storage.postgres import MetadataUnavailable, MutationUnknown
from tests.fixtures.vault_receipt_846 import aggregate, inventory
from tests.test_retention_owner_846 import settings


def identity():
    return {
        "owner": "vault",
        "tenant_id": "tenant-a",
        "mission_id": "mission-a",
        "root_agent_id": "root-a",
        "claim_id": str(uuid4()),
        "claim_revision": 3,
        "terminal_at": "2024-01-01T00:00:00+00:00",
        "retain_until": "2025-01-01T00:00:00+00:00",
        "manifest_sha256": "a" * 64,
    }


def envelope(ident, op):
    return ident | {
        "state": "retired_confirmed",
        "inventory_complete": True,
        "operation_id": op,
        "receipt_sha256": "a" * 64,
        "references": aggregate(inventory(calls=1)),
        "contracts": {"audit179": "v1", "holds846": "v1"},
    }


@pytest.mark.parametrize(
    "mutation",
    [
        "unknown",
        "incomplete",
        "revision",
        "kind",
        "root",
        "payload",
        "duplicate",
        "short_digest",
        "order",
        "id_format",
        "no_calls",
        "events_below_calls",
        "per_id_legacy",
        "missing_kind",
        "short_id",
        "wrong_prefix",
        "negative_revision",
        "bool_revision",
        "events_without_calls",
        "zero_count_with_list_digest",
        "count_with_empty_digest",
    ],
)
def test_no_partial_or_forged_reference_envelope(mutation):
    ident = identity()
    op = str(uuid4())
    value = envelope(ident, op)
    if mutation == "unknown":
        value["state"] = "unknown"
    if mutation == "incomplete":
        value["inventory_complete"] = False
    if mutation == "revision":
        value["references"][2]["revision"] = 2
    if mutation == "kind":
        value["references"][0]["kind"] = "coffer_deleted"
    if mutation == "root":
        value["references"][0]["root_agent_id"] = "foreign"
    if mutation == "payload":
        value["payload"] = "forbidden"
    if mutation == "duplicate":
        value["references"].append(dict(value["references"][0]))
    if mutation == "short_digest":
        value["receipt_sha256"] = "bad"
    if mutation == "order":
        value["references"][0], value["references"][1] = (
            value["references"][1],
            value["references"][0],
        )
    if mutation == "id_format":
        value["references"][0]["id"] = "sha256:" + "A" * 64
    if mutation == "no_calls":
        value["references"][0]["revision"] = 0
        value["references"][1]["revision"] = 0
    if mutation == "events_below_calls":
        value["references"][0]["revision"] = 2
    if mutation == "per_id_legacy":
        value["references"] = inventory(calls=1)
    if mutation == "missing_kind":
        value["references"].pop()
    if mutation == "short_id":
        value["references"][0]["id"] = value["references"][0]["id"][:-1]
    if mutation == "wrong_prefix":
        value["references"][0]["id"] = "sha512:" + value["references"][0]["id"][7:]
    if mutation == "negative_revision":
        value["references"][3]["revision"] = -1
    if mutation == "bool_revision":
        value["references"][3]["revision"] = True
    if mutation == "events_without_calls":
        value["references"][0]["revision"] = 0
        value["references"][0]["id"] = owner.EMPTY_AGGREGATE
    if mutation == "zero_count_with_list_digest":
        value["references"][3]["id"] = value["references"][0]["id"]
    if mutation == "count_with_empty_digest":
        value["references"][3]["revision"] = 1
    with pytest.raises(MetadataUnavailable):
        owner.validate_envelope(value, ident, op)


@pytest.mark.parametrize(
    "failure",
    [
        None,
        "callback_revoked",
        "callback_unavailable",
        "identity_changed",
        "expired_after_lock",
        "commit",
        "close",
        "notice",
    ],
)
def test_public_retire_rechecks_after_lock_and_ack_only_after_commit_close(
    monkeypatch, failure
):
    ident = identity()
    op = str(uuid4())
    expiry = datetime.now(timezone.utc) + timedelta(seconds=20)
    trace = []
    live_calls = 0
    handler = None
    value = {
        "has_more": False,
        "lot": {"calls": [str(uuid4())], "events": [], "receipt": str(uuid4())},
        "result": envelope(ident, op),
    }

    class Conn:
        def add_notice_handler(self, fn):
            nonlocal handler
            handler = fn

        def execute(self, query, params=()):
            trace.append(query)
            if query == "COMMIT":
                if failure == "commit":
                    raise OSError("ACK lost")
                if failure == "notice":
                    handler(SimpleNamespace(sqlstate="01000"))
            if "retirement_batch" in query:
                assert live_calls == 2
            return SimpleNamespace(fetchone=lambda: {"result": value})

    @contextmanager
    def app():
        trace.append("verify-app-schema")
        yield SimpleNamespace(
            execute=lambda *args: SimpleNamespace(fetchall=lambda: [{"version": 4}])
        )

    @contextmanager
    def maintenance():
        trace.append("maintenance")
        yield Conn()
        trace.append("close")
        if failure == "close":
            raise MetadataUnavailable("close_unconfirmed")

    def live(*args):
        nonlocal live_calls
        live_calls += 1
        trace.append("callback")
        if live_calls == 2:
            assert "SELECT vault_metadata.audit_retirement_lock(%s,%s,%s,%s)" in trace
            assert not any("retirement_batch" in item for item in trace)
            if failure == "callback_revoked":
                raise ValueError("revoked")
            if failure == "callback_unavailable":
                raise MetadataUnavailable("retention_authority_unavailable")
            if failure == "identity_changed":
                return ident | {"claim_revision": 4}, expiry
            if failure == "expired_after_lock":
                # Both identity and expiry remain the same; actual final clock check must reject.
                monkeypatch.setattr(
                    owner, "datetime", SimpleNamespace(now=lambda *unused: expiry)
                )
        return ident, expiry

    monkeypatch.setattr(owner, "get_settings", settings)
    monkeypatch.setattr(owner, "connection", app)
    monkeypatch.setattr(owner, "maintenance_connection", maintenance)
    monkeypatch.setattr(owner, "validate_durability", lambda *args: None)
    monkeypatch.setattr(owner, "live", live)

    def call():
        return owner.action(
            "audit-retention-retire",
            {
                "proof": "opaque-test",
                "operation_id": op,
                "batch": 20,
                "confirm": "audit-retention-retire",
            },
        )

    if failure:
        expected = (
            MutationUnknown
            if failure in {"commit", "close", "notice"}
            else (ValueError, MetadataUnavailable)
        )
        with pytest.raises(expected):
            call()
    else:
        result = call()
        assert result["purge_confirmed"] and result["inventory_complete"]
        assert trace[-2:] == ["COMMIT", "close"]
    if failure in {
        "callback_revoked",
        "callback_unavailable",
        "identity_changed",
        "expired_after_lock",
    }:
        assert trace[-1] == "ROLLBACK"
        assert not any("retirement_batch" in item for item in trace)


@pytest.mark.parametrize("binding", [1, 0])
def test_closed_scope_without_calls_has_a_valid_empty_envelope(binding):
    ident = identity()
    op = str(uuid4())
    value = envelope(ident, op)
    value["references"] = aggregate(inventory(calls=0, binding=binding))
    assert owner.validate_envelope(value, ident, op) is value
    # The final batch of such a scope deletes nothing: no lot, no 179 receipt.
    final = {"has_more": False, "lot": None, "result": value}
    assert owner.validate_result("audit-retention-retire", final, ident, op) is value


@pytest.mark.parametrize("change", ["has_more", "no_result", "calls_in_envelope"])
def test_a_missing_lot_is_only_the_final_zero_call_batch(change):
    ident = identity()
    op = str(uuid4())
    value = envelope(ident, op)
    value["references"] = aggregate(inventory(calls=0))
    result = {"has_more": False, "lot": None, "result": value}
    if change == "has_more":
        # Consistent with has_more on its own: only the missing lot is wrong.
        result["has_more"] = True
        result["result"] = None
    if change == "no_result":
        result["result"] = None
    if change == "calls_in_envelope":
        result["result"] = envelope(ident, op)  # one call, valid on its own
        owner.validate_envelope(result["result"], ident, op)
    with pytest.raises(MetadataUnavailable, match="retirement_batch_invalid"):
        owner.validate_result("audit-retention-retire", result, ident, op)


def test_partial_batch_is_never_an_owner_ack():
    ident = identity()
    op = str(uuid4())
    partial = {
        "has_more": True,
        "lot": {"calls": [str(uuid4())], "events": [], "receipt": str(uuid4())},
        "result": None,
    }
    assert owner.validate_result("audit-retention-retire", partial, ident, op) is None
    partial["has_more"] = False
    with pytest.raises(MetadataUnavailable):
        owner.validate_result("audit-retention-retire", partial, ident, op)


def test_inventory_does_not_become_ack_even_for_a_committed_observation():
    ident = identity()
    op = str(uuid4())
    observed = {
        "state": "committed",
        "inventory": envelope(ident, op)["references"],
        "lots": [],
    }
    assert (
        owner.validate_result("audit-retention-inventory", observed, ident, op) is None
    )


def test_canonical_identity_preserves_the_existing_v3_digest_for_unicode():
    import hashlib
    import json
    from mcp_vault.storage.retention_proof import canonical_identity, fingerprint

    value = identity() | {"tenant_id": "tenant-é", "mission_id": "mission-東京"}
    expected = json.dumps(value, sort_keys=True, separators=(",", ":"))
    assert canonical_identity(value) == expected
    assert fingerprint(value) == hashlib.sha256(expected.encode()).hexdigest()
    assert json.loads(expected) == value


def test_upgrade_is_explicit_and_source_v3_only():
    from unittest.mock import Mock
    from mcp_vault.storage.audit_retirement_schema import install
    from mcp_vault.storage.operator import action

    for version in [1, 2, 4]:
        conn = Mock()
        conn.execute.return_value.fetchall.return_value = [{"version": version}]
        with pytest.raises(
            MetadataUnavailable, match="retirement_upgrade_source_invalid"
        ):
            install(conn, SimpleNamespace())
        assert conn.execute.call_count == 1
    with pytest.raises(ValueError, match="Explicit retirement upgrade required"):
        action("audit-retirement-upgrade", {})
