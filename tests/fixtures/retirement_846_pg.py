"""NOT automatically executed. Fresh network-none PG17 only, after recipe review.

Usage: python tests/fixtures/retirement_846_pg.py --socket /private/socket --report /private/result.json
The runner owns creation/removal of the exact isolated container. No production DSN.
"""

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys
import threading
import time
from types import SimpleNamespace
from uuid import uuid4

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from mcp_vault.storage import audit_schema, audit_retirement_schema
from mcp_vault.storage.retention_proof import canonical_identity, fingerprint
from mcp_vault.storage.retirement_maintenance import validate_envelope


def run(socket, report):
    def connect(
        user="postgres", dbname="v846_retirement", application_name="v846r_fixture"
    ):
        return psycopg.connect(
            host=str(socket),
            dbname=dbname,
            user=user,
            autocommit=True,
            row_factory=dict_row,
            application_name=application_name,
            connect_timeout=2,
            options="-c statement_timeout=5000 -c lock_timeout=4000",
        )

    cfg = SimpleNamespace(
        metadata_pg_owner_role="v846r_owner",
        metadata_pg_app_role="v846r_app",
        metadata_pg_provisioner_role="v846r_install",
        audit_maintenance_role="v846r_maint",
        metadata_instance_id="v846r",
        audit_retention_days=365,
        audit_mission_retention_enabled=True,
    )
    checks = []
    with connect(dbname="postgres") as conn:
        assert (
            conn.execute("SHOW server_version_num")
            .fetchone()["server_version_num"]
            .startswith("17")
        )
        for role, login in [
            ("v846r_owner", "NOLOGIN"),
            ("v846r_app", "LOGIN"),
            ("v846r_install", "LOGIN"),
            ("v846r_maint", "LOGIN"),
        ]:
            # Closed literals only, no configurable target cluster/role.
            conn.execute(f"CREATE ROLE {role} {login} NOINHERIT")
        conn.execute("CREATE DATABASE v846_retirement OWNER v846r_owner")
        conn.execute("REVOKE ALL ON DATABASE v846_retirement FROM PUBLIC")
        conn.execute(
            "GRANT CONNECT ON DATABASE v846_retirement TO v846r_app,v846r_maint"
        )
    schema = Path(audit_retirement_schema.SOURCE).parent
    with connect() as conn, conn.transaction():
        conn.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
        conn.execute("SET LOCAL ROLE v846r_owner")
        conn.execute((schema / "001.sql").read_text())
        conn.execute(
            "ALTER DEFAULT PRIVILEGES IN SCHEMA vault_metadata GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO v846r_app"
        )
        conn.execute("GRANT USAGE ON SCHEMA vault_metadata TO v846r_app")
        audit_schema.install(conn, cfg)
        audit_retirement_schema.install(conn, cfg)
        # Read the REAL PG17 catalog before calling the product verifier. NOT
        # NULL attributes are not pg_constraint rows on this pinned major.
        catalog = conn.execute("""SELECT conname,contype,convalidated FROM pg_constraint
            WHERE conrelid='vault_metadata.audit_mission_retirements'::regclass
            ORDER BY contype,conname""").fetchall()
        catalog_path = report.with_name(report.stem + ".constraints.private.json")
        fd = os.open(catalog_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump({"major": 17, "constraints": catalog}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        observed_types = {
            kind: sum(row["contype"] == kind for row in catalog)
            for kind in ("c", "p", "u", "f")
        }
        assert observed_types == {"c": 5, "p": 1, "u": 1, "f": 1}
        assert all(row["convalidated"] for row in catalog)
        # This invocation failed with the predecessor's expected count of nine.
        audit_schema.verify(conn, cfg)
    checks.append("pg17_catalog_five_checks_pk_unique_fk_then_real_product_verify")
    claim = str(uuid4())
    op = str(uuid4())
    now = datetime.now(timezone.utc)
    ident = {
        "owner": "vault",
        "tenant_id": "a",
        "mission_id": "mission-a",
        "root_agent_id": "root-a",
        "claim_id": claim,
        "claim_revision": 1,
        "terminal_at": (now - timedelta(days=366)).isoformat(),
        "retain_until": (now - timedelta(days=1)).isoformat(),
        "manifest_sha256": "a" * 64,
    }
    calls = {}
    with connect("v846r_app") as conn:
        for mission in ["mission-a", "mission-a", "mission-b", "mission-unknown"]:
            cid = str(uuid4())
            calls.setdefault(mission, []).append(cid)
            conn.execute(
                "INSERT INTO vault_metadata.audit_calls(instance_id,call_id,actor_ref,tool,tenant_id,mission_id) VALUES('v846r',%s,'anonymous','secret_read','a',%s)",
                (cid, mission),
            )
            conn.execute(
                "INSERT INTO vault_metadata.audit_events(instance_id,call_id,phase,step_id,outcome) VALUES('v846r',%s,'public_terminal','00000000-0000-0000-0000-000000000000',%s)",
                (cid, "unknown" if mission == "mission-unknown" else "completed"),
            )
    with connect() as conn:
        conn.execute(
            "UPDATE vault_metadata.audit_calls SET created_at=clock_timestamp()-interval '500 days',expires_at=clock_timestamp()-interval '135 days'"
        )
        # Synthetic age seed, NOT a year of observed operation.
        conn.execute(
            "INSERT INTO vault_metadata.mission_bindings VALUES('v846r','a',NULL,%s,1)",
            (
                Jsonb(
                    {
                        "tenant_id": "a",
                        "instance_id": "v846r",
                        "enabled": True,
                        "allowed_resources": ["coffer-shared"],
                        "permissions": ["read"],
                        "policy_id": "",
                        "expires_at": None,
                    }
                ),
            ),
        )
    with connect("v846r_maint") as conn, conn.transaction():
        assert conn.execute(
            "SELECT vault_metadata.audit_close_mission('v846r','a','mission-a',%s,1,%s,%s,%s,clock_timestamp()+interval '20 seconds') AS ok",
            (claim, ident["terminal_at"], ident["retain_until"], fingerprint(ident)),
        ).fetchone()["ok"]
        value = conn.execute(
            "SELECT vault_metadata.audit_expire('v846r',100,false) AS result"
        ).fetchone()["result"]
        assert value["calls"] == 0
    checks.append("legacy_sweep_cannot_erase_correlated_inventory")
    params = (
        "v846r",
        Jsonb(ident),
        op,
        canonical_identity(ident),
        now + timedelta(seconds=30),
    )
    with connect("v846r_maint") as conn, conn.transaction():
        value = conn.execute(
            "SELECT vault_metadata.audit_retirement_prepare(%s,%s,%s,%s,%s) AS result",
            params,
        ).fetchone()["result"]
        assert value["state"] == "prepared" and len(value["inventory"]) == 5
    with connect("v846r_maint") as conn, conn.transaction():
        first = conn.execute(
            "SELECT vault_metadata.audit_retirement_batch(%s,%s,%s,%s,%s,1) AS result",
            params,
        ).fetchone()["result"]
        assert (
            first["has_more"]
            and first["result"] is None
            and len(first["lot"]["calls"]) == 1
        )
    with connect("v846r_maint") as conn, conn.transaction():
        final = conn.execute(
            "SELECT vault_metadata.audit_retirement_batch(%s,%s,%s,%s,%s,1) AS result",
            params,
        ).fetchone()["result"]
        assert not final["has_more"]
        validate_envelope(final["result"], ident, op)
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM vault_metadata.audit_mission_retirements WHERE operation_id=%s",
            (op,),
        ).fetchone()
        actual_calls = [cid for lot in row["lots"] for cid in lot["calls"]]
        assert set(actual_calls) == set(calls["mission-a"])
        assert all(
            conn.execute(
                "SELECT 1 FROM vault_metadata.audit_calls WHERE call_id=%s",
                (lot["receipt"],),
            ).fetchone()
            for lot in row["lots"]
        )
        assert row["receipt_retain_until"] >= row["committed_at"] + timedelta(days=365)
        assert (
            conn.execute(
                "SELECT count(*) AS n FROM vault_metadata.audit_calls WHERE mission_id='mission-b'"
            ).fetchone()["n"]
            == 1
        )
        assert (
            conn.execute(
                "SELECT revision FROM vault_metadata.mission_bindings WHERE tenant_id='a'"
            ).fetchone()["revision"]
            == 1
        )
    checks.append(
        "real_two_commits_returning_ids_annual_receipt_and_shared_b_preserved"
    )
    with connect("v846r_maint") as conn:
        try:
            with conn.transaction():
                conn.execute(
                    "SELECT vault_metadata.audit_retirement_batch(%s,%s,%s,%s,%s,1)",
                    params,
                )
        except psycopg.Error:
            pass
        else:
            raise AssertionError("repeat final operation accepted")
    checks.append("committed_operation_not_replayed")
    protected_identity = ident | {
        "mission_id": "mission-unknown",
        "claim_id": str(uuid4()),
    }
    with connect("v846r_maint") as conn, conn.transaction():
        conn.execute(
            "SELECT vault_metadata.audit_close_mission('v846r','a','mission-unknown',%s,1,%s,%s,%s,clock_timestamp()+interval '20 seconds')",
            (
                protected_identity["claim_id"],
                protected_identity["terminal_at"],
                protected_identity["retain_until"],
                fingerprint(protected_identity),
            ),
        )
    with connect("v846r_maint") as conn:
        try:
            with conn.transaction():
                conn.execute(
                    "SELECT vault_metadata.audit_retirement_prepare(%s,%s,%s,%s,clock_timestamp()+interval '20 seconds')",
                    (
                        "v846r",
                        Jsonb(protected_identity),
                        str(uuid4()),
                        canonical_identity(protected_identity),
                    ),
                )
        except psycopg.Error as exc:
            assert "audit outcome protected" in str(exc)
        else:
            raise AssertionError("UNKNOWN audit was retired")
    checks.append("unknown_audit_blocks_prepare_without_ack")
    for role in ["v846r_app", "v846r_maint"]:
        with connect(role) as conn:
            for statement in [
                "SELECT * FROM vault_metadata.audit_mission_retirements",
                "UPDATE vault_metadata.audit_mission_retirements SET state='committed'",
            ]:
                try:
                    conn.execute(statement)
                except psycopg.errors.InsufficientPrivilege:
                    pass
                else:
                    raise AssertionError("receipt direct privilege leaked")
    checks.append("maintenance_and_app_no_direct_receipt_read_or_dml")
    # Expiry AFTER a real advisory lock wait; no retirement row or effect allowed.
    claim2 = str(uuid4())
    ident2 = ident | {"mission_id": "mission-b", "claim_id": claim2}
    with connect("v846r_maint") as conn, conn.transaction():
        conn.execute(
            "SELECT vault_metadata.audit_close_mission('v846r','a','mission-b',%s,1,%s,%s,%s,clock_timestamp()+interval '20 seconds')",
            (
                claim2,
                ident2["terminal_at"],
                ident2["retain_until"],
                fingerprint(ident2),
            ),
        )
    outcome = []
    start = threading.Event()

    def waiting():
        with connect("v846r_maint", application_name="v846r_waiter") as waiter:
            start.set()
            try:
                with waiter.transaction():
                    waiter.execute(
                        "SELECT vault_metadata.audit_retirement_prepare(%s,%s,%s,%s,%s)",
                        (
                            "v846r",
                            Jsonb(ident2),
                            str(uuid4()),
                            canonical_identity(ident2),
                            datetime.now(timezone.utc) + timedelta(seconds=0.5),
                        ),
                    )
            except psycopg.Error:
                outcome.append("refused")
            else:
                outcome.append("accepted")

    with connect() as blocker:
        blocker.execute("BEGIN")
        blocker.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(jsonb_build_array('v846r','a','mission-b')::text,846))"
        )
        worker = threading.Thread(target=waiting)
        worker.start()
        assert start.wait(2)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            observed = blocker.execute(
                "SELECT count(*) AS n FROM pg_stat_activity WHERE application_name='v846r_waiter' AND wait_event_type='Lock'"
            ).fetchone()["n"]
            if observed == 1:
                break
            time.sleep(0.01)
        else:
            raise AssertionError("real waiter lock not observed")
        time.sleep(0.8)
        blocker.execute("COMMIT")
        worker.join(6)
        assert not worker.is_alive()
    assert outcome == ["refused"]
    checks.append("expiry_after_real_lock_wait_rollback")
    # The callback's canonical credential-read audit must not depend on our locks.
    with connect("v846r_maint") as held:
        held.execute("BEGIN")
        held.execute(
            "SELECT vault_metadata.audit_retirement_lock('v846r','a','mission-b',%s)",
            (str(uuid4()),),
        )
        with connect("v846r_app") as callback:
            callback.execute(
                "INSERT INTO vault_metadata.audit_calls(instance_id,call_id,actor_ref,tool) VALUES('v846r',%s,'tok_0000000000000000','secret_read')",
                (str(uuid4()),),
            )
        held.execute("ROLLBACK")
    checks.append(
        "uncorrelated_opaque_credential_audit_can_commit_while_scope_locks_held"
    )
    # Recheck owner verification as observer, exact structure and restricted roles.
    with connect() as conn:
        audit_schema.verify(conn, cfg)
    checks.append("verify_after_retirement")
    return {
        "confirmed": True,
        "checks": checks,
        "groups": len(checks),
        "synthetic_dates": True,
        "not_tls_or_mcp": True,
        "no_native_claim_callback_qualification": True,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    assert args.socket.is_dir() and args.socket.is_absolute()
    result = run(args.socket, args.report)
    fd = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(result, stream)
        stream.flush()
        os.fsync(stream.fileno())
