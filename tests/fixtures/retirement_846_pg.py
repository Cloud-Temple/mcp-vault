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
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from mcp_vault.storage import audit_schema, audit_retirement_schema
from mcp_vault.storage.retention_proof import canonical_identity, fingerprint
from mcp_vault.storage.retirement_maintenance import (
    EMPTY_AGGREGATE,
    validate_envelope,
    validate_result,
)
from tests.fixtures.vault_receipt_846 import aggregate


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
        assert observed_types == {"c": 6, "p": 1, "u": 1, "f": 1}
        assert all(row["convalidated"] for row in catalog)
        # The real PG17 catalog proves nine constraints; the reviewed count of
        # eight in predecessor156e33e was incorrect. Preserve that failed run.
        audit_schema.verify(conn, cfg)
    checks.append("pg17_catalog_six_checks_pk_unique_fk_then_real_product_verify")
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
        assert value["state"] == "prepared"
    with connect() as conn:
        stored = conn.execute(
            "SELECT inventory FROM vault_metadata.audit_mission_retirements WHERE operation_id=%s",
            (op,),
        ).fetchone()["inventory"]
    # Exhaustive stored inventory, aggregated reply equal to the Python twin.
    assert len(stored) == 5
    assert value["inventory"] == aggregate(stored)
    assert [r["revision"] for r in value["inventory"]] == [2, 2, 1, 0]
    checks.append("stored_inventory_exhaustive_reply_aggregated_sql_equals_python")
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
        assert final["result"]["references"] == aggregate(stored)
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
    # 846 P2: above the former 1000-reference cap, a Mission still retires to
    # one four-reference receipt. 2500 calls x 2 events = 5000 events.
    claim3 = str(uuid4())
    ident3 = ident | {"mission_id": "mission-large", "claim_id": claim3}
    large = [str(uuid4()) for _ in range(2500)]
    with connect("v846r_app") as conn, conn.transaction(), conn.cursor() as cur:
        cur.executemany(
            "INSERT INTO vault_metadata.audit_calls(instance_id,call_id,actor_ref,tool,tenant_id,mission_id) VALUES('v846r',%s,'anonymous','secret_read','a','mission-large')",
            [(cid,) for cid in large],
        )
        for phase, outcome in [("admission", "admitted"), ("public_terminal", "completed")]:
            cur.executemany(
                "INSERT INTO vault_metadata.audit_events(instance_id,call_id,phase,step_id,outcome) VALUES('v846r',%s,%s,'00000000-0000-0000-0000-000000000000',%s)",
                [(cid, phase, outcome) for cid in large],
            )
    with connect() as conn:
        conn.execute(
            "UPDATE vault_metadata.audit_calls SET created_at=clock_timestamp()-interval '500 days',expires_at=clock_timestamp()-interval '135 days' WHERE mission_id='mission-large'"
        )
    with connect("v846r_maint") as conn, conn.transaction():
        conn.execute(
            "SELECT vault_metadata.audit_close_mission('v846r','a','mission-large',%s,1,%s,%s,%s,clock_timestamp()+interval '20 seconds')",
            (claim3, ident3["terminal_at"], ident3["retain_until"], fingerprint(ident3)),
        )
    op3 = str(uuid4())

    def large_params():
        return ("v846r", Jsonb(ident3), op3, canonical_identity(ident3),
                datetime.now(timezone.utc) + timedelta(seconds=25))

    with connect("v846r_maint") as conn, conn.transaction():
        value = conn.execute(
            "SELECT vault_metadata.audit_retirement_prepare(%s,%s,%s,%s,%s) AS result",
            large_params(),
        ).fetchone()["result"]
    assert [r["revision"] for r in value["inventory"]] == [2500, 5000, 1, 0]
    durations = []
    result = None
    for _ in range(6):
        started = time.monotonic()
        with connect("v846r_maint") as conn, conn.transaction():
            step = conn.execute(
                "SELECT vault_metadata.audit_retirement_batch(%s,%s,%s,%s,%s,500) AS result",
                large_params(),
            ).fetchone()["result"]
        durations.append(round(time.monotonic() - started, 3))
        if not step["has_more"]:
            result = step["result"]
            break
    assert result is not None and len(durations) == 5, durations
    validate_envelope(result, ident3, op3)
    with connect() as conn:
        row = conn.execute(
            "SELECT state,inventory,lots FROM vault_metadata.audit_mission_retirements WHERE operation_id=%s",
            (op3,),
        ).fetchone()
        assert row["state"] == "committed" and len(row["inventory"]) == 7501
        assert result["references"] == aggregate(row["inventory"])
        assert sorted(c for lot in row["lots"] for c in lot["calls"]) == sorted(large)
        assert sum(len(lot["events"]) for lot in row["lots"]) == 5000
        assert conn.execute(
            "SELECT count(*) AS n FROM vault_metadata.audit_calls WHERE mission_id='mission-large'"
        ).fetchone()["n"] == 0
    checks.append("mission_5000_events_five_batches_four_reference_receipt")
    # 846 P2: no Vault audit retained for the scope at closure, the common case. Mission waits
    # for a Vault receipt for every claim. No hold exists before closure; the
    # closure creates it, then refuses any correlated call or wrap, and the
    # receipt carries four zero counts bound to the digest of the empty list.
    claim4 = str(uuid4())
    ident4 = ident | {"mission_id": "mission-silent", "claim_id": claim4}
    with connect() as conn:
        assert conn.execute(
            "SELECT count(*) AS n FROM vault_metadata.audit_mission_holds WHERE mission_id='mission-silent'"
        ).fetchone()["n"] == 0
    with connect("v846r_maint") as conn, conn.transaction():
        assert conn.execute(
            "SELECT vault_metadata.audit_close_mission('v846r','a','mission-silent',%s,1,%s,%s,%s,clock_timestamp()+interval '20 seconds') AS ok",
            (claim4, ident4["terminal_at"], ident4["retain_until"], fingerprint(ident4)),
        ).fetchone()["ok"]
    for statement, args in [
        (
            "INSERT INTO vault_metadata.audit_calls(instance_id,call_id,actor_ref,tool,tenant_id,mission_id) VALUES('v846r',%s,'anonymous','secret_read','a','mission-silent')",
            (str(uuid4()),),
        ),
        ("SELECT vault_metadata.audit_wrap_admit('v846r','a','mission-silent')", ()),
    ]:
        with connect("v846r_app") as conn:
            try:
                conn.execute(statement, args)
            except psycopg.errors.InsufficientPrivilege as exc:
                assert "closed mission" in str(exc)
            else:
                raise AssertionError("closed silent Mission admitted a correlation")
    with connect() as conn:
        expire_receipts = conn.execute(
            "SELECT count(*) AS n FROM vault_metadata.audit_calls WHERE tool='audit_expire'"
        ).fetchone()["n"]
    op4 = str(uuid4())

    def silent_params():
        return ("v846r", Jsonb(ident4), op4, canonical_identity(ident4),
                datetime.now(timezone.utc) + timedelta(seconds=25))

    with connect("v846r_maint") as conn, conn.transaction():
        value = conn.execute(
            "SELECT vault_metadata.audit_retirement_prepare(%s,%s,%s,%s,%s) AS result",
            silent_params(),
        ).fetchone()["result"]
    assert value["state"] == "prepared"
    assert [r["revision"] for r in value["inventory"]] == [0, 0, 1, 0]
    with connect("v846r_maint") as conn, conn.transaction():
        step = conn.execute(
            "SELECT vault_metadata.audit_retirement_batch(%s,%s,%s,%s,%s,1) AS result",
            silent_params(),
        ).fetchone()["result"]
    assert step["has_more"] is False and step["lot"] is None
    assert validate_result("audit-retention-retire", step, ident4, op4) == step["result"]
    empty = [ref for ref in step["result"]["references"] if ref["revision"] == 0]
    assert len(empty) == 3 and {ref["id"] for ref in empty} == {EMPTY_AGGREGATE}
    with connect() as conn:
        row = conn.execute(
            "SELECT state,inventory,lots,committed_at,receipt_retain_until FROM vault_metadata.audit_mission_retirements WHERE operation_id=%s",
            (op4,),
        ).fetchone()
        assert row["state"] == "committed" and row["lots"] == []
        assert step["result"]["references"] == aggregate(row["inventory"])
        assert row["receipt_retain_until"] >= row["committed_at"] + timedelta(days=365)
        assert conn.execute(
            "SELECT count(*) AS n FROM vault_metadata.audit_calls WHERE tool='audit_expire'"
        ).fetchone()["n"] == expire_receipts
    with connect("v846r_maint") as conn:
        try:
            with conn.transaction():
                conn.execute(
                    "SELECT vault_metadata.audit_retirement_batch(%s,%s,%s,%s,%s,1)",
                    silent_params(),
                )
        except psycopg.Error as exc:
            assert "already committed" in str(exc)
        else:
            raise AssertionError("repeat silent operation accepted")
    # Without closure, the same empty scope stays protected: no hold, no row.
    ident5 = ident | {"mission_id": "mission-never-closed", "claim_id": str(uuid4())}
    op5 = str(uuid4())
    with connect("v846r_maint") as conn:
        try:
            with conn.transaction():
                conn.execute(
                    "SELECT vault_metadata.audit_retirement_prepare(%s,%s,%s,%s,%s)",
                    ("v846r", Jsonb(ident5), op5, canonical_identity(ident5),
                     datetime.now(timezone.utc) + timedelta(seconds=25)),
                )
        except psycopg.Error:
            pass
        else:
            raise AssertionError("unclosed empty scope prepared")
    with connect() as conn:
        assert conn.execute(
            "SELECT count(*) AS n FROM vault_metadata.audit_mission_retirements WHERE operation_id=%s",
            (op5,),
        ).fetchone()["n"] == 0
    checks.append("mission_without_vault_activity_closure_creates_hold_empty_receipt_no_lot")
    # 846 P3-1: the zero receipt is safe only because audit_fill_call and
    # audit_close_mission serialise on the same advisory 846 scope lock. Two
    # real connections, the wait proven in pg_locks (not by sleeping).
    def scope_wait(observer, waiter_pid, holder_pid, mission):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            row = observer.execute(
                """SELECT count(*) AS n, pg_blocking_pids(%s) AS blockers
                FROM pg_locks l, (SELECT hashtextextended(
                  jsonb_build_array('v846r','a',%s::text)::text,846) AS k) x
                WHERE l.pid=%s AND l.locktype='advisory' AND NOT l.granted
                AND l.objsubid=1 AND l.classid::bigint=((x.k>>32)&4294967295)
                AND l.objid::bigint=(x.k&4294967295)""",
                (waiter_pid, mission, waiter_pid),
            ).fetchone()
            if row["n"] == 1:
                assert row["blockers"] == [holder_pid], row["blockers"]
                held = observer.execute(
                    """SELECT count(*) AS n FROM pg_locks l, (SELECT hashtextextended(
                      jsonb_build_array('v846r','a',%s::text)::text,846) AS k) x
                    WHERE l.pid=%s AND l.locktype='advisory' AND l.granted
                    AND l.objsubid=1 AND l.classid::bigint=((x.k>>32)&4294967295)
                    AND l.objid::bigint=(x.k&4294967295)""",
                    (mission, holder_pid),
                ).fetchone()["n"]
                assert held == 1
                return
            time.sleep(0.01)
        raise AssertionError("advisory 846 scope wait not observed in pg_locks")

    def close_args(identity):
        return (
            identity["mission_id"],
            identity["claim_id"],
            identity["terminal_at"],
            identity["retain_until"],
            fingerprint(identity),
        )

    close_sql = (
        "SELECT vault_metadata.audit_close_mission('v846r','a',%s,%s,1,%s,%s,%s,"
        "clock_timestamp()+interval '20 seconds') AS ok"
    )
    call_sql = (
        "INSERT INTO vault_metadata.audit_calls(instance_id,call_id,actor_ref,tool,tenant_id,mission_id)"
        " VALUES('v846r',%s,'anonymous','secret_read','a',%s)"
    )
    event_sql = (
        "INSERT INTO vault_metadata.audit_events(instance_id,call_id,phase,step_id,outcome)"
        " VALUES('v846r',%s,'public_terminal','00000000-0000-0000-0000-000000000000','completed')"
    )

    def run_waiter(target, started, outcome, sql_text, args, role):
        try:
            with connect(role, application_name="v846r_race") as conn:
                target["pid"] = conn.info.backend_pid
                started.set()
                with conn.transaction():
                    conn.execute(sql_text, args)
        except psycopg.Error as exc:
            outcome.append(("refused", exc.sqlstate, str(exc)))
        else:  # any other failure leaves outcome empty: the main thread asserts
            outcome.append(("accepted", None, ""))

    # (a) Correlated call first: closure waits, then sees the call; no zero.
    ident6 = ident | {"mission_id": "mission-race-call", "claim_id": str(uuid4())}
    race_call = str(uuid4())
    waiter, started, outcome = {}, threading.Event(), []
    with connect("v846r_app") as holder, connect() as observer:
        holder.execute("BEGIN")
        holder.execute(call_sql, (race_call, "mission-race-call"))
        holder.execute(event_sql, (race_call,))
        worker = threading.Thread(
            target=run_waiter,
            args=(waiter, started, outcome, close_sql, close_args(ident6), "v846r_maint"),
        )
        worker.start()
        assert started.wait(2)
        scope_wait(observer, waiter["pid"], holder.info.backend_pid, "mission-race-call")
        assert worker.is_alive() and outcome == []
        holder.execute("COMMIT")
        worker.join(6)
        assert not worker.is_alive()
    assert outcome == [("accepted", None, "")], outcome
    op6 = str(uuid4())

    def race_params():
        return ("v846r", Jsonb(ident6), op6, canonical_identity(ident6),
                datetime.now(timezone.utc) + timedelta(seconds=25))

    with connect("v846r_maint") as conn, conn.transaction():
        value = conn.execute(
            "SELECT vault_metadata.audit_retirement_prepare(%s,%s,%s,%s,%s) AS result",
            race_params(),
        ).fetchone()["result"]
    assert value["state"] == "prepared"
    assert [r["revision"] for r in value["inventory"]] == [1, 1, 1, 0]
    with connect() as conn:
        conn.execute(
            "UPDATE vault_metadata.audit_calls SET created_at=clock_timestamp()-interval '500 days',expires_at=clock_timestamp()-interval '135 days' WHERE mission_id='mission-race-call'"
        )
    with connect("v846r_maint") as conn, conn.transaction():
        step = conn.execute(
            "SELECT vault_metadata.audit_retirement_batch(%s,%s,%s,%s,%s,500) AS result",
            race_params(),
        ).fetchone()["result"]
    assert step["has_more"] is False and step["lot"]["calls"] == [race_call]
    assert validate_result("audit-retention-retire", step, ident6, op6) == step["result"]
    calls_ref = [r for r in step["result"]["references"] if r["kind"] == "vault_audit_calls"]
    assert len(calls_ref) == 1 and calls_ref[0]["revision"] == 1
    assert calls_ref[0]["id"] != EMPTY_AGGREGATE
    # (b) Closure first: the correlated call waits, then is refused 42501.
    ident7 = ident | {"mission_id": "mission-race-close", "claim_id": str(uuid4())}
    waiter, started, outcome = {}, threading.Event(), []
    with connect("v846r_maint") as holder, connect() as observer:
        holder.execute("BEGIN")
        assert holder.execute(close_sql, close_args(ident7)).fetchone()["ok"]
        worker = threading.Thread(
            target=run_waiter,
            args=(waiter, started, outcome, call_sql, (str(uuid4()), "mission-race-close"), "v846r_app"),
        )
        worker.start()
        assert started.wait(2)
        scope_wait(observer, waiter["pid"], holder.info.backend_pid, "mission-race-close")
        assert worker.is_alive() and outcome == []
        holder.execute("COMMIT")
        worker.join(6)
        assert not worker.is_alive()
    assert len(outcome) == 1 and outcome[0][:2] == ("refused", "42501"), outcome
    assert "closed mission audit correlation" in outcome[0][2]
    with connect() as conn:
        assert conn.execute(
            "SELECT count(*) AS n FROM vault_metadata.audit_calls WHERE mission_id='mission-race-close'"
        ).fetchone()["n"] == 0
    with connect("v846r_maint") as conn, conn.transaction():
        value = conn.execute(
            "SELECT vault_metadata.audit_retirement_prepare(%s,%s,%s,%s,%s) AS result",
            ("v846r", Jsonb(ident7), str(uuid4()), canonical_identity(ident7),
             datetime.now(timezone.utc) + timedelta(seconds=25)),
        ).fetchone()["result"]
    assert [r["revision"] for r in value["inventory"]] == [0, 0, 1, 0]
    checks.append("race_two_connections_pg_locks_call_first_counted_close_first_42501")
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
        "large_batch_seconds": durations,
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
