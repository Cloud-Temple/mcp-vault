"""Finite refs-only owner retirement; UNKNOWN never permits a mutation replay."""

from datetime import datetime, timezone
import hashlib
from uuid import UUID

from ..config import get_settings
from .audit_maintenance import maintenance_connection
from .postgres import (
    MetadataUnavailable,
    MutationUnknown,
    connection,
    validate_durability,
)
from .retention_proof import canonical_identity, live

# One aggregated reference per source kind, in SQL order (COLLATE "C"). The
# exhaustive inventory stays in vault_metadata.audit_mission_retirements.
KINDS = (
    "vault_audit_calls",
    "vault_audit_events",
    "vault_binding_references",
    "vault_wrap_references",
)
# jsonb '[]'::text is "[]": the id of every empty category, and of no other.
EMPTY_AGGREGATE = "sha256:" + hashlib.sha256(b"[]").hexdigest()


def validate_envelope(value, identity, operation):
    expected = set(identity) | {
        "state",
        "inventory_complete",
        "operation_id",
        "receipt_sha256",
        "references",
        "contracts",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or any(value.get(k) != v for k, v in identity.items())
        or value["operation_id"] != operation
        or value["state"] != "retired_confirmed"
        or value["inventory_complete"] is not True
        or value["contracts"] != {"audit179": "v1", "holds846": "v1"}
    ):
        raise MetadataUnavailable("retirement_result_invalid")
    digest = value["receipt_sha256"]
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(c not in "0123456789abcdef" for c in digest)
    ):
        raise MetadataUnavailable("retirement_result_invalid")
    refs = value["references"]
    if not isinstance(refs, list) or len(refs) != len(KINDS):
        raise MetadataUnavailable("retirement_inventory_incomplete")
    counts = {}
    for kind, ref in zip(KINDS, refs):
        if (
            not isinstance(ref, dict)
            or set(ref) != {"kind", "id", "revision", "root_agent_id"}
            or ref["kind"] != kind
            or not isinstance(ref["id"], str)
            or len(ref["id"]) != 71
            or not ref["id"].startswith("sha256:")
            or any(c not in "0123456789abcdef" for c in ref["id"][7:])
            or type(ref["revision"]) is not int
            or ref["revision"] < 0
            or ref["root_agent_id"] != ""
            or (ref["revision"] == 0) != (ref["id"] == EMPTY_AGGREGATE)
        ):
            raise MetadataUnavailable("retirement_reference_invalid")
        counts[kind] = ref["revision"]
    # Every call has a terminal event, every event belongs to a call of the
    # scope, the tenant binding key is unique. Zero calls is a closed scope
    # that never called Vault: the closure, not this count, proves it.
    if (
        counts["vault_audit_events"] < counts["vault_audit_calls"]
        or counts["vault_audit_calls"] == 0
        and counts["vault_audit_events"] != 0
        or counts["vault_binding_references"] > 1
    ):
        raise MetadataUnavailable("retirement_inventory_incomplete")
    import json

    if len(json.dumps(value, sort_keys=True).encode()) > 262144:
        raise MetadataUnavailable("retirement_inventory_incomplete")
    return value


def validate_result(name, result, identity, operation):
    if name.endswith("inventory"):
        if set(result) != {"state", "inventory", "lots"} or result["state"] not in {
            "prepared",
            "committed",
        }:
            raise MetadataUnavailable("retirement_inventory_invalid")
        refs = result["inventory"]
        # Reuse the exact reference validator; this is NOT returned as an ACK.
        validate_envelope(
            identity
            | {
                "state": "retired_confirmed",
                "inventory_complete": True,
                "operation_id": operation,
                "receipt_sha256": "0" * 64,
                "references": refs,
                "contracts": {"audit179": "v1", "holds846": "v1"},
            },
            identity,
            operation,
        )
        if not isinstance(result["lots"], list):
            raise MetadataUnavailable("retirement_inventory_invalid")
        return None
    if name.endswith("retire"):
        if (
            set(result) != {"has_more", "lot", "result"}
            or type(result["has_more"]) is not bool
        ):
            raise MetadataUnavailable("retirement_batch_invalid")
        lot = result["lot"]
        if lot is None:
            # Only the final batch of a closed scope without any call has no
            # lot; its envelope must then carry zero calls (checked below).
            if result["has_more"]:
                raise MetadataUnavailable("retirement_batch_invalid")
        elif (
            not isinstance(lot, dict)
            or set(lot) != {"calls", "events", "receipt"}
            or not isinstance(lot["calls"], list)
            or not 1 <= len(lot["calls"]) <= 500
            or not isinstance(lot["events"], list)
        ):
            raise MetadataUnavailable("retirement_batch_invalid")
        try:
            if lot is not None and (
                str(UUID(lot["receipt"])) != lot["receipt"]
                or any(str(UUID(cid)) != cid for cid in lot["calls"])
                or len(set(lot["calls"])) != len(lot["calls"])
            ):
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise MetadataUnavailable("retirement_batch_invalid") from None
        if result["has_more"] != (result["result"] is None):
            raise MetadataUnavailable("retirement_batch_invalid")
    elif (
        set(result) != {"state", "result", "lots", "retain_until"}
        or result["state"] not in {"prepared", "committed"}
        or (result["state"] == "committed") != (result["result"] is not None)
    ):
        raise MetadataUnavailable("retirement_receipt_invalid")
    envelope = result["result"]
    if envelope is None:
        return None
    validate_envelope(envelope, identity, operation)
    if (
        name.endswith("retire")
        and result["lot"] is None
        and envelope["references"][0]["revision"] != 0
    ):
        raise MetadataUnavailable("retirement_batch_invalid")
    return envelope


def action(name, body):
    s = get_settings()
    if (
        not s.audit_mission_retention_enabled
        or s.metadata_backend != "postgres"
        or s.metadata_operator_mode != "install"
    ):
        raise MetadataUnavailable("retention_profile_disabled")
    names = {
        "audit-retention-inventory",
        "audit-retention-retire",
        "audit-retention-receipt",
    }
    required = {"proof", "operation_id"} | (
        {"confirm", "batch"} if name == "audit-retention-retire" else set()
    )
    if name not in names or not isinstance(body, dict) or set(body) != required:
        raise ValueError("Explicit retirement action required")
    operation = str(UUID(body["operation_id"]))
    if operation != body["operation_id"]:
        raise ValueError("Canonical operation UUID required")
    if name.endswith("retire") and (
        body["confirm"] != name
        or type(body["batch"]) is not int
        or not 1 <= body["batch"] <= 500
    ):
        raise ValueError("Explicit bounded retirement required")
    with connection() as app:
        if app.execute(
            "SELECT version FROM vault_metadata.schema_version"
        ).fetchall() != [{"version": 4}]:
            raise MetadataUnavailable("retirement_schema_required")
    identity, expiry = live(s, body["proof"])
    scope = (
        s.metadata_instance_id,
        identity["tenant_id"],
        identity["mission_id"],
        operation,
    )
    committing = False
    try:
        with maintenance_connection() as conn:
            notices = []
            conn.add_notice_handler(lambda notice: notices.append(notice.sqlstate))
            try:
                conn.execute("BEGIN")
                validate_durability(conn)
                if name.endswith("receipt"):
                    row = conn.execute(
                        "SELECT vault_metadata.audit_retirement_receipt(%s,%s,%s,%s) AS result",
                        scope,
                    ).fetchone()
                    fresh, fresh_expiry = live(s, body["proof"])
                    if fresh != identity or fresh_expiry != expiry:
                        raise ValueError("Retention claim changed")
                else:
                    # These locks do NOT touch global audit_revision. A canonical
                    # opaque credential SecretRead in the callback can still audit
                    # its own uncorrelated call; no security mutation is requested.
                    conn.execute(
                        "SELECT vault_metadata.audit_retirement_lock(%s,%s,%s,%s)",
                        scope,
                    )
                    fresh, fresh_expiry = live(s, body["proof"])
                    if fresh != identity or fresh_expiry != expiry:
                        raise ValueError("Retention claim changed")
                    if datetime.now(timezone.utc) >= expiry:
                        raise ValueError("Retention proof expired")
                    from psycopg.types.json import Jsonb

                    params = (
                        s.metadata_instance_id,
                        Jsonb(identity),
                        operation,
                        canonical_identity(identity),
                        expiry,
                    )
                    if name.endswith("inventory"):
                        row = conn.execute(
                            "SELECT vault_metadata.audit_retirement_prepare(%s,%s,%s,%s,%s) AS result",
                            params,
                        ).fetchone()
                    else:
                        row = conn.execute(
                            "SELECT vault_metadata.audit_retirement_batch(%s,%s,%s,%s,%s,%s) AS result",
                            (*params, body["batch"]),
                        ).fetchone()
                if not row or not isinstance(row["result"], dict) or notices:
                    raise MetadataUnavailable("retirement_not_confirmed")
                result = row["result"]
                envelope = validate_result(name, result, identity, operation)
                if datetime.now(timezone.utc) >= expiry:
                    raise ValueError("Retention proof expired")
                committing = True
                conn.execute("COMMIT")
                if notices:
                    raise MetadataUnavailable("retirement_notice")
            except BaseException as exc:
                if committing:
                    raise MutationUnknown(operation) from exc
                conn.execute("ROLLBACK")
                raise
    except MetadataUnavailable as exc:
        if committing or exc.reason == "close_unconfirmed":
            raise MutationUnknown(operation) from exc
        raise
    # Only the exact durable receipt is exposed; inventory/partial lots are NOT
    # final Mission ACKs, even when their local transaction is confirmed.
    return {
        "status": "ok",
        "confirmed": True,
        "observation_only": name.endswith("receipt"),
        "purge_confirmed": envelope is not None,
        "inventory_complete": envelope is not None,
        "operation_id": operation,
        "result": result,
    }
