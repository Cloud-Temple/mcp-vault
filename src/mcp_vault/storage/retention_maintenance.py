"""Local metadata-operator closure/status, separate from application credentials."""

from datetime import datetime, timezone

from ..config import get_settings
from .audit_maintenance import maintenance_connection
from .postgres import (
    MetadataUnavailable,
    MutationUnknown,
    connection,
    validate_durability,
)
from .retention_proof import fingerprint, live


def action(name, body):
    settings = get_settings()
    if (
        not settings.audit_mission_retention_enabled
        or settings.metadata_backend != "postgres"
        or settings.metadata_operator_mode not in {"install", "retention-only"}
    ):
        raise MetadataUnavailable("retention_profile_disabled")
    if (
        name not in {"audit-retention-close", "audit-retention-status"}
        or not isinstance(body, dict)
        or set(body) != ({"proof", "confirm"} if name.endswith("close") else {"proof"})
        or name.endswith("close")
        and body["confirm"] != name
    ):
        raise ValueError("Explicit retention action required")
    with connection():  # The existing app path checks schema3 and both role ACLs.
        pass
    identity, expiry = live(settings, body["proof"])
    scope = (
        settings.metadata_instance_id,
        identity["tenant_id"],
        identity["mission_id"],
    )
    if name == "audit-retention-status":
        with maintenance_connection() as conn:
            conn.execute("BEGIN READ ONLY")
            row = conn.execute(
                "SELECT vault_metadata.audit_mission_status(%s,%s,%s) AS result", scope
            ).fetchone()
            conn.execute("ROLLBACK")
        if datetime.now(timezone.utc) >= expiry:
            raise ValueError("Retention proof expired")
        # This is an observation, never a reconstructed post-COMMIT receipt.
        return {
            "status": "ok",
            "observation_only": True,
            "purge_confirmed": False,
            "inventory_complete": False,
            "result": row["result"],
        }
    committing = False
    try:
        with maintenance_connection() as conn:
            notices = []
            conn.add_notice_handler(lambda notice: notices.append(notice.sqlstate))
            try:
                conn.execute("BEGIN")
                validate_durability(conn)
                row = conn.execute(
                    "SELECT vault_metadata.audit_close_mission(%s,%s,%s,%s,%s,%s,%s,%s,%s) AS result",
                    (
                        *scope,
                        identity["claim_id"],
                        identity["claim_revision"],
                        identity["terminal_at"],
                        identity["retain_until"],
                        fingerprint(identity),
                        expiry,
                    ),
                ).fetchone()
                if row != {"result": True} or notices:
                    raise MetadataUnavailable("retention_closure_not_confirmed")
                # The routine rechecks fresh PG time after its real scope/row
                # waits. Deadline expiry after execute still rolls back fully.
                if datetime.now(timezone.utc) >= expiry:
                    raise ValueError("Retention proof expired")
                committing = True
                conn.execute("COMMIT")
                if notices:
                    raise MetadataUnavailable("retention_closure_notice")
            except BaseException as exc:
                if committing:
                    raise MutationUnknown(identity["claim_id"]) from exc
                conn.execute("ROLLBACK")
                raise
    except MetadataUnavailable as exc:
        if exc.reason == "close_unconfirmed":
            raise MutationUnknown(identity["claim_id"]) from exc
        raise
    # A closure ACK is not a retired inventory. Wraps/audit/receipt references
    # still need their scoped retirement before Mission may import a final ACK.
    return {
        "status": "ok",
        "confirmed": True,
        "closure": identity,
        "purge_confirmed": False,
        "inventory_complete": False,
        "state": "protected",
    }
