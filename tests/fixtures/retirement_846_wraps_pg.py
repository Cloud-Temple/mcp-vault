"""Explicit owner fixture only. Never pytest-discovered or imported by ASGI.

New PG17 + Bao, no TLS/JWT/C18/global retirement claim. No root credential
arguments: this process initializes its own Bao and retains root only in memory.
"""

import argparse
import asyncio
from contextlib import contextmanager
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import secrets
import sys
from uuid import uuid4

import hvac
import psycopg
from psycopg.rows import dict_row

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from retirement_846_wrap_support import (
    Journal,
    bao_http_receipts,
    bootstrap_owner,
    drop_unwrap_once,
    loopback_url,
    read_policy,
    save,
)

INSTANCE = "wrap846"
DB = "wrap846_db"
MOUNT = "wrap846-technical"
COFFER = "wrap846-business"
TENANT = "wrap846-tenant"
AUD = "wrap846-audience"
CANARY = {"value": "fixture846-public-canary"}


def connect(socket, db=DB):
    return psycopg.connect(
        host=str(socket),
        user="postgres",
        dbname=db,
        autocommit=True,
        row_factory=dict_row,
        connect_timeout=2,
        options="-c statement_timeout=5000 -c lock_timeout=2000",
    )


def configure(socket, url, directory):
    # No ambient credential/config source is used. Credentials below are NEW test
    # material generated only when this explicitly authorized child is executed.
    for key in list(os.environ):
        if key.startswith(("PG", "METADATA_", "AUDIT_", "OPENBAO_", "S3_")):
            raise ValueError("ambient backend configuration refused")
    values = {
        "METADATA_BACKEND": "postgres",
        "METADATA_INSTANCE_ID": INSTANCE,
        "METADATA_PG_VAULT_ID": MOUNT,
        "METADATA_PG_SECRET_PATH": "sql/app",
        "METADATA_PG_PROVISIONER_SECRET_PATH": "sql/install",
        "METADATA_PG_DATABASE": DB,
        "METADATA_PG_OWNER_ROLE": "wrap846_owner",
        "METADATA_PG_APP_ROLE": "wrap846_app",
        "METADATA_PG_PROVISIONER_ROLE": "wrap846_install",
        "METADATA_PG_CA_FILE": str(directory / "unused-unix-ca.pem"),
        "METADATA_OPERATOR_MODE": "install",
        "METADATA_PG_DURABILITY": "standalone",
        "AUDIT_MAINTENANCE_ROLE": "wrap846_maint",
        "AUDIT_MAINTENANCE_SECRET_PATH": "sql/maintenance",
        "AUDIT_MISSION_RETENTION_ENABLED": "true",
        "AUDIT_RETENTION_DAYS": "365",
        "OPENBAO_ADDR": loopback_url(url),
        "ENFORCE_MISSION_TOKEN_VALIDATION": "false",
        "ADMIN_BOOTSTRAP_KEY": secrets.token_urlsafe(40),
    }
    os.environ.update(values)
    from mcp_vault.config import get_settings

    get_settings.cache_clear()
    return get_settings()


@contextmanager
def actor(raw, tenant=TENANT):
    from mcp_vault.auth.context import current_token_info
    from mcp_vault.auth.middleware import AuthMiddleware
    from mcp_vault.storage.admission import load_facts
    from mcp_vault.storage.postgres import request_facts

    facts = request_facts.set(load_facts(raw, tenant))
    identity = None
    try:
        resolved = AuthMiddleware(None)._validate_token(raw)
        if not resolved or resolved.get("auth_type") != "token":
            raise PermissionError("real opaque actor resolution failed")
        identity = current_token_info.set(resolved)
        yield resolved
    finally:
        if identity is not None:
            current_token_info.reset(identity)
        request_facts.reset(facts)


async def run_owned(socket, url, report, client, journal, http):
    directory = report.parent
    from mcp_vault.openbao.manager import set_hvac_client
    from mcp_vault.storage import operator, postgres
    from mcp_vault.storage import stores
    from mcp_vault.storage.audit_maintenance import maintenance_connection
    from mcp_vault.auth import token_store, policies, mission_bindings
    from mcp_vault.vault import wrapping
    from mcp_vault.storage.reader import exact_kv

    set_hvac_client(client)
    groups = []
    wraps = {}  # private memory only; known cleanup tracking below
    dead = set()
    child_tokens = []

    def sql(label, statement, params=(), db=DB):
        def execute():
            with connect(socket, db) as conn:
                return conn.execute(statement, params).fetchall()

        return journal.call(label, execute)

    def install_pg():
        with connect(socket, "postgres") as conn:
            if not str(
                conn.execute("SHOW server_version_num").fetchone()["server_version_num"]
            ).startswith("17"):
                raise ValueError("PG major")
            for role, login in [
                ("wrap846_owner", "NOLOGIN"),
                ("wrap846_app", "LOGIN"),
                ("wrap846_install", "LOGIN"),
                ("wrap846_maint", "LOGIN"),
            ]:
                conn.execute(f"CREATE ROLE {role} {login} NOINHERIT")
            conn.execute("GRANT wrap846_owner TO wrap846_install WITH INHERIT FALSE")
            conn.execute("CREATE DATABASE wrap846_db OWNER wrap846_owner")
            conn.execute("REVOKE ALL ON DATABASE wrap846_db FROM PUBLIC")
            conn.execute(
                "GRANT CONNECT ON DATABASE wrap846_db TO wrap846_app,wrap846_install,wrap846_maint"
            )
        with connect(socket) as conn:
            conn.execute("ALTER SCHEMA public OWNER TO wrap846_owner")
            conn.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
        return {
            "confirmed": True,
            "transport": "isolated unix trust, NOT TLS/password proof",
        }

    journal.call("sql-new-domain", install_pg)
    assert (
        journal.call("operator-vault", lambda: operator.action("vault", {}))["status"]
        == "ok"
    )
    credentials = {
        kind: {
            "host": str(socket),
            "port": "5432",
            "dbname": DB,
            "user": role,
            "password": secrets.token_urlsafe(24),
        }
        for kind, role in (
            ("app", "wrap846_app"),
            ("provisioner", "wrap846_install"),
            ("maintenance", "wrap846_maint"),
        )
    }
    for label, body in [
        ("connections", {k: credentials[k] for k in ("app", "provisioner")}),
        ("audit-maintenance-connection", credentials["maintenance"]),
        ("schema-init", {}),
        ("audit-retirement-upgrade", {"confirm": "audit-retirement-upgrade"}),
    ]:
        received = journal.call(
            "operator-" + label,
            lambda label=label, body=body: operator.action(label, body),
        )
        assert received["status"] == "ok"
    raw = secrets.token_urlsafe(32)
    initial = journal.call(
        "operator-initial-admin",
        lambda: operator.action(
            "initial-admin",
            {
                "token_hash": hashlib.sha256(raw.encode()).hexdigest(),
                "client_name": "wrap846-owner",
                "mutation_id": str(uuid4()),
            },
        ),
    )
    assert initial["status"] == "ok"
    token_store.init_token_store()
    policies.init_policy_store()
    mission_bindings.init_mission_binding_store()
    wrapping.init_wrap_registry()
    from mcp_vault import server

    # Real scoped child READ credentials, independent app/maintenance. No root
    # returned from this process or placed in any file. Their negative probes are
    # exact official Bao API calls, not simulated permission decisions.
    for kind, path in (("app", "sql/app"), ("maintenance", "sql/maintenance")):
        name = "wrap846-read-" + kind
        journal.call(
            "child-policy-" + kind,
            lambda name=name, path=path: client.sys.create_or_update_policy(
                name=name, policy=read_policy(MOUNT, path)
            ),
        )
        answer = journal.call(
            "child-token-" + kind,
            lambda name=name: client.auth.token.create(
                policies=[name], ttl="10m", no_default_policy=True
            ),
        )
        token = answer["auth"]["client_token"]
        child_tokens.append(token)
        scoped = hvac.Client(url=url, token=token, timeout=(1, 2))
        set_hvac_client(scoped)
        try:
            observed = journal.call(
                "child-read-" + kind, lambda path=path: exact_kv(MOUNT, path)
            )
            assert observed == credentials["app" if kind == "app" else "maintenance"]
            if kind == "maintenance":

                def maint_identity():
                    with maintenance_connection() as conn:
                        return conn.execute("SELECT current_user AS role").fetchone()

                assert (
                    journal.call("child-maint-pg", maint_identity)["role"]
                    == "wrap846_maint"
                )
            for suffix in ("sys/mounts", MOUNT + "/data/sql/install"):
                journal.before("child-denied-" + kind + "-" + suffix.replace("/", "-"))
                try:
                    scoped.read(suffix)
                except hvac.exceptions.Forbidden:
                    journal.received(
                        "child-denied-" + kind + "-" + suffix.replace("/", "-"),
                        {"exception": "Forbidden"},
                    )
                else:
                    raise AssertionError("child policy unexpectedly privileged")
        finally:
            set_hvac_client(client)

    async def business(label, fn):
        with actor(raw):
            result = await journal.acall(label, fn)
        return result

    assert (await business("business-vault", lambda: server.vault_create(COFFER)))[
        "status"
    ] == "created"
    assert (
        await business(
            "business-write", lambda: server.secret_write(COFFER, "canary", CANARY)
        )
    )["status"] == "ok"
    # Compare the actual product envelope, including its typed enrichment.
    expected_canary = journal.call(
        "business-read-owner",
        lambda: client.secrets.kv.v2.read_secret_version(
            path="canary", mount_point=COFFER
        ),
    )["data"]["data"]
    assert all(expected_canary[k] == v for k, v in CANARY.items())
    binding = await business(
        "binding-create",
        lambda: mission_bindings.get_mission_binding_store().acreate(
            TENANT, [COFFER], ["read"]
        ),
    )
    assert binding["status"] == "created"

    async def wrap(label, mission, path="canary"):
        op = "op-" + label
        result = await business(
            "wrap-" + label,
            lambda: server.secret_wrap(
                COFFER,
                path,
                mission,
                op,
                ttl_seconds=300,
                tenant_id=TENANT,
                expected_aud=AUD,
            ),
        )
        if result.get("status") == "ok":
            wraps[label] = (op, mission, result)
        return result

    def snapshot(label, op, mission):
        return sql(
            label,
            "SELECT operation_id,mission_id,status,revision,payload FROM vault_metadata.wrap_registry WHERE instance_id=%s AND operation_id=%s AND mission_id=%s",
            (INSTANCE, op, mission),
        )

    def inventory(label, mission, tenant=TENANT, instance=INSTANCE, protected=False):
        journal.before(label)
        with connect(socket) as conn:
            conn.execute("BEGIN")
            try:
                conn.execute("SET LOCAL ROLE wrap846_owner")
                conn.execute(
                    "SELECT vault_metadata.audit_retirement_lock(%s,%s,%s,%s)",
                    (instance, tenant, mission, str(uuid4())),
                )
                refs = conn.execute(
                    "SELECT vault_metadata.audit_retirement_inventory(%s,%s,%s) AS refs",
                    (instance, tenant, mission),
                ).fetchone()["refs"]
            except psycopg.Error as exc:
                # Preserve actual SQLSTATE + message before negative assertion.
                journal.received(label, {"sqlstate": exc.sqlstate, "message": str(exc)})
                if not protected or "wrap outcome protected" not in str(exc):
                    raise
                return None
            finally:
                conn.execute("ROLLBACK")
        journal.received(label, {"refs": refs, "not_public_final_ack": True})
        if protected:
            raise AssertionError("protected wrap accepted by inventory")
        return refs

    def receipts(label, op, mission, kind):
        rows = sql(
            label,
            "SELECT mutation_id,kind,target,phase,database_result FROM vault_metadata.operation_receipts WHERE instance_id=%s AND kind=%s AND target->>'business_operation_id'=%s AND target->>'mission_id'=%s ORDER BY mutation_id",
            (INSTANCE, kind, op, mission),
        )
        assert len(rows) == 1 and rows[0]["database_result"] == "committed"
        return rows[0]

    async def consume(label, token_label=None):
        op, mission, _ = wraps[label]
        source_token = wraps[token_label or label][2]["wrap_token"]
        return await business(
            "consume-" + label,
            lambda: wrapping.consume_wrap_secret(
                source_token,
                op,
                mission,
                tenant_id=TENANT,
                expected_aud=AUD,
                enforce=True,
            ),
        )

    async def resolve(label, receipt, raw_actor=raw, target=None):
        with actor(raw_actor):
            result = journal.call(
                label,
                lambda: postgres.resolve_receipt(
                    str(receipt["mutation_id"]),
                    receipt["kind"],
                    receipt["target"] if target is None else target,
                    initial_confirmation="confirmed",
                ),
            )
        return result

    completed = False
    try:
        # W01: ACK unwrap, native CAS revision and exact canonical receipt.
        assert (await wrap("c", "mission-a"))["status"] == "ok"
        op, mission, _ = wraps["c"]
        snapshot("c-active", op, mission)
        start = len(http)
        consumed = await consume("c")
        assert any(
            e["path"] == "/v1/sys/wrapping/unwrap" and e.get("status") == 200
            for e in http[start:]
        )
        assert (
            consumed["status"] == "ok" and consumed["data"]["data"] == expected_canary
        )
        dead.add("c")
        row_c = snapshot("c-consumed", op, mission)[0]
        receipt_c = receipts("c-receipt", op, mission, "wrap:mark_consumed")
        assert row_c["status"] == "consumed"
        assert [[op, mission], row_c["revision"]] in receipt_c["target"][
            "result_revisions"
        ]
        assert (await resolve("c-resolve", receipt_c))["effect_observed"] is True
        groups.append("W01_real_unwrap_consumed_native_revision_receipt")

        # W02: real first revoke_accessor ACK, never accept already_revoked.
        assert (await wrap("r", "mission-a"))["status"] == "ok"
        op, mission, _ = wraps["r"]
        start = len(http)
        revoked = await business(
            "r-revoke", lambda: wrapping.lookup_and_revoke_by_operation_id(op, mission)
        )
        assert any(
            e["path"] == "/v1/auth/token/revoke-accessor" and e.get("status") == 204
            for e in http[start:]
        )
        assert revoked["status"] == "ok" and revoked["state"] == "revoked"
        dead.add("r")
        row_r = snapshot("r-revoked", op, mission)[0]
        receipt_r = receipts("r-receipt", op, mission, "wrap:mark_entries_revoked")
        assert row_r["status"] == "revoked"
        assert [[op, mission], row_r["revision"]] in receipt_r["target"][
            "result_revisions"
        ]
        assert (await resolve("r-resolve", receipt_r))["effect_observed"] is True
        groups.append("W02_real_accessor_revoke_and_canonical_receipt")

        # W03: shared binding A/B, exact refs, wrong scope cannot become a final ACK.
        assert (await wrap("b", "mission-b"))["status"] == "ok"
        refs = inventory("a-inventory", "mission-a")
        actual_refs = {
            (r["id"], r["revision"]) for r in refs if r["kind"] == "wrap_reference"
        }
        assert actual_refs == {
            (r["operation_id"] + ":" + r["mission_id"], r["revision"])
            for r in (row_c, row_r)
        }
        assert any(r["kind"] == "binding_reference" and r["id"] == TENANT for r in refs)
        inventory("wrong-tenant-protected", "mission-a", tenant="other", protected=True)
        assert not any(
            r["kind"] == "wrap_reference"
            for r in inventory("wrong-mid-empty-not-ack", "other")
        )
        assert (
            inventory("wrong-instance-empty-not-ack", "mission-a", instance="other")
            == []
        )
        neighbor = await consume("b")
        assert (
            neighbor["status"] == "ok" and neighbor["data"]["data"] == expected_canary
        )
        dead.add("b")
        groups.append("W03_scope_refs_shared_binding_neighbor_preserved")

        # W04: real actor lookup and receipt tuple mismatch; negative TX only.
        changed = copy.deepcopy(receipt_c["target"])
        changed["result_revisions"][0][1] += 1
        assert (await resolve("bad-revision-resolver", receipt_c, target=changed))[
            "status"
        ] == "inaccessible"
        changed = copy.deepcopy(receipt_c["target"])
        changed["business_operation_id"] = "foreign"
        assert (await resolve("bad-operation-resolver", receipt_c, target=changed))[
            "status"
        ] == "inaccessible"
        changed = copy.deepcopy(receipt_c["target"])
        changed["mission_id"] = "foreign"
        assert (await resolve("bad-mid-resolver", receipt_c, target=changed))[
            "status"
        ] == "inaccessible"
        other = await business(
            "other-actor-create",
            lambda: token_store.get_token_store().acreate(
                "wrap846-other", ["read"], allowed_resources=[COFFER], expires_in_days=1
            ),
        )
        assert (
            await resolve(
                "other-actor-resolver", receipt_c, raw_actor=other["raw_token"]
            )
        )["status"] == "inaccessible"
        journal.before("negative-revision-tx")
        with connect(socket) as conn:
            conn.execute("BEGIN")
            try:
                conn.execute("SET LOCAL ROLE wrap846_owner")
                changed_row = conn.execute(
                    "UPDATE vault_metadata.wrap_registry SET revision=revision+1 WHERE instance_id=%s AND operation_id='op-c' AND mission_id='mission-a' RETURNING revision",
                    (INSTANCE,),
                ).fetchone()
                journal.received("negative-revision-change", changed_row)
                try:
                    conn.execute(
                        "SELECT vault_metadata.audit_retirement_inventory(%s,%s,'mission-a')",
                        (INSTANCE, TENANT),
                    )
                except psycopg.Error as exc:
                    journal.received(
                        "negative-revision-inventory",
                        {"sqlstate": exc.sqlstate, "message": str(exc)},
                    )
                    assert "wrap outcome protected" in str(exc)
                else:
                    raise AssertionError("revision without writer receipt accepted")
            finally:
                conn.execute("ROLLBACK")
        assert snapshot("c-after-rollback", "op-c", "mission-a")[0] == row_c
        assert inventory("a-after-rollback", "mission-a") == refs
        groups.append("W04_real_provenance_actor_tuple_and_rollback_guard")

        # W05: real pending writer, active/consuming CAS, actual missing Bao path.
        with actor(raw):
            registry = stores.PGWrap(("operation", "op-p", "mission-p"))
            pending = journal.call(
                "p-register",
                lambda: registry.register_pending(
                    "op-p",
                    "mission-p",
                    COFFER,
                    "canary",
                    300,
                    tenant_id=TENANT,
                    expected_aud=AUD,
                ),
            )
        assert pending is True
        inventory("p-protected", "mission-p", protected=True)
        assert (await wrap("s", "mission-s"))["status"] == "ok"
        inventory("s-active-protected", "mission-s", protected=True)
        with actor(raw):
            registry = stores.PGWrap(("operation", "op-s", "mission-s"))
            assert journal.call(
                "s-cas-consuming",
                lambda: registry.try_mark_consuming("op-s", "mission-s"),
            )
        inventory("s-consuming-protected", "mission-s", protected=True)
        start = len(http)
        failed = await wrap("f", "mission-f", "missing")
        assert any(
            e["path"] == "/v1/" + COFFER + "/data/missing" and e.get("status") == 404
            for e in http[start:]
        )
        assert failed["status"] == "error"
        assert snapshot("f-failed", "op-f", "mission-f")[0]["status"] == "failed"
        inventory("f-protected", "mission-f", protected=True)
        groups.append("W05_pending_active_consuming_failed_protected")

        # W06: actual unwrap ACK hidden by finite relay; native UNKNOWN remains.
        assert (await wrap("u", "mission-u"))["status"] == "ok"
        relay_journal = Journal(directory / "relay")
        original_config = wrapping._get_config
        with drop_unwrap_once(url, wraps["u"][2]["wrap_token"], relay_journal) as (
            relay,
            state,
        ):
            # Only the library's unwrap destination changes; PG credentials and
            # owner client still resolve against the real Bao. No fake response.
            wrapping._get_config = lambda: original_config().model_copy(
                update={"openbao_addr": relay}
            )
            try:
                unknown = await consume("u")
            finally:
                wrapping._get_config = original_config
        journal.received("u-relay-state", state)
        assert (
            state["forwards"] == 1 and state["status"] == 200 and state["error"] is None
        )
        assert unknown.get("error_type") == "consume_outcome_unknown"
        assert (
            snapshot("u-unknown", "op-u", "mission-u")[0]["status"]
            == "consume_outcome_unknown"
        )
        inventory("u-protected", "mission-u", protected=True)
        dead.add("u")  # only relay's captured real unwrap200, NOT the client result
        groups.append("W06_lost_real_unwrap_ack_unknown_not_replayed")

        # W07: dead token C against I, I's actual accessor still owned, not dead.
        assert (await wrap("i", "mission-i"))["status"] == "ok"
        start = len(http)
        unusable = await consume("i", token_label="c")
        assert any(
            e["path"] == "/v1/sys/wrapping/unwrap" and e.get("status") == 400
            for e in http[start:]
        )
        assert unusable.get("error_type") == "wrap_unusable"
        assert snapshot("i-unusable", "op-i", "mission-i")[0]["status"] == "unusable"
        inventory("i-protected", "mission-i", protected=True)
        groups.append("W07_real_invalid_token_unusable_does_not_prove_accessor_dead")

        # W08: native binding writer revision, then close A before future wrap.
        # Canonical binding store has create/delete, no update/upsert. Its PG
        # deletion is a tombstone; recreation retains and increments revision.
        assert (
            await business(
                "binding-remove",
                lambda: mission_bindings.get_mission_binding_store().adelete(TENANT),
            )
            is True
        )
        refreshed = await business(
            "binding-recreate",
            lambda: mission_bindings.get_mission_binding_store().acreate(
                TENANT, [COFFER], ["read"], created_by="wrap846-owner-r2"
            ),
        )
        assert refreshed["status"] == "created"
        updated = inventory("a-binding-updated", "mission-a")
        old_binding = next(r for r in refs if r["kind"] == "binding_reference")
        new_binding = next(r for r in updated if r["kind"] == "binding_reference")
        assert new_binding["revision"] > old_binding["revision"]
        # Original B was consumed before update. A NEW B wrap proves current
        # neighbor functionality without replaying an old tuple.
        assert (await wrap("b2", "mission-b"))["status"] == "ok"
        answer_b = await consume("b2")
        assert (
            answer_b["status"] == "ok" and answer_b["data"]["data"] == expected_canary
        )
        dead.add("b2")
        now = datetime.now(timezone.utc)
        from mcp_vault.storage.retention_proof import fingerprint

        closure = {
            "owner": "vault",
            "tenant_id": TENANT,
            "mission_id": "mission-a",
            "root_agent_id": "",
            "claim_id": str(uuid4()),
            "claim_revision": 1,
            "terminal_at": (now - timedelta(days=366)).isoformat(),
            "retain_until": (now - timedelta(days=1)).isoformat(),
            "manifest_sha256": hashlib.sha256(
                b"fixture-only-not-a-Mission-claim"
            ).hexdigest(),
        }
        journal.received(
            "a-closure-input",
            {
                "identity": closure,
                "proof_sha256": fingerprint(closure),
                "synthetic_sql_fixture_not_live_claim": True,
            },
        )

        def close_a():
            with maintenance_connection() as conn:
                return conn.execute(
                    "SELECT vault_metadata.audit_close_mission(%s,%s,'mission-a',%s,1,%s,%s,%s,clock_timestamp()+interval '20 seconds') AS closed",
                    (
                        INSTANCE,
                        TENANT,
                        closure["claim_id"],
                        closure["terminal_at"],
                        closure["retain_until"],
                        fingerprint(closure),
                    ),
                ).fetchone()

        assert journal.call("a-close-routine", close_a)["closed"]
        start = len(http)
        denied = await wrap("closed-a", "mission-a")
        count = {
            "wrap_reads": sum(
                e["method"] == "GET" and e["path"] == "/v1/" + COFFER + "/data/canary"
                for e in http[start:]
            )
        }
        journal.received("a-admission-bao-count", count)
        assert denied["status"] == "error" and count["wrap_reads"] == 0
        assert snapshot("a-closed-not-inserted", "op-closed-a", "mission-a") == []
        groups.append(
            "W08_binding_revision_and_closed_admission_before_bao_neighbor_positive"
        )

        # Before final assertion capture actual refs-only state and hashes.
        final_refs = inventory("a-final-refs", "mission-a")
        final_report = {
            "confirmed": True,
            "groups": groups,
            "group_count": len(groups),
            "a_refs": final_refs,
            "canary_equal": True,
            "scope": "real Bao + isolated PG only; no TLS/JWT/C18/public retire with wraps",
            "root_material_exported": False,
            "fixture_only_config_redirection": "unwrap fault only",
            "closure_authority": "synthetic metadata through native owner SQL routine, NOT live Mission claim",
        }
        completed = True
    finally:
        # No blind business mutation after unknown. Known live accessors only,
        # direct owner API; consumed/revoked/ACK-lost real200 excluded explicitly.
        try:
            if completed:
                for label, (_, _, answer) in wraps.items():
                    if label not in dead:
                        journal.call(
                            "cleanup-accessor-" + label,
                            lambda answer=answer: client.auth.token.revoke_accessor(
                                answer["accessor"]
                            ),
                        )
                for n, token in enumerate(child_tokens):
                    journal.call(
                        "cleanup-child-" + str(n),
                        lambda token=token: client.auth.token.revoke(token),
                    )
                # Root stays here; revoke-self has no root value serialized.
                journal.call(
                    "cleanup-owner-self", lambda: client.auth.token.revoke_self()
                )
            else:
                journal.received(
                    "cleanup-business-held",
                    {
                        "no_retry": True,
                        "reason": "unexpected result; parent removes dedicated ephemeral containers only",
                    },
                )
        finally:
            client.token = None
            set_hvac_client(None)
    save(report, final_report)


async def run(socket, url, report):
    journal = Journal(report.parent / "receipts")
    configure(socket, url, report.parent)
    journal.before("bootstrap-owner")
    client = bootstrap_owner(url, hvac.Client)
    journal.received(
        "bootstrap-owner",
        {
            "newly_initialized": True,
            "unsealed": True,
            "init_material_not_serialized": True,
        },
    )
    try:
        with bao_http_receipts(url, journal) as http:
            await run_owned(socket, url, report, client, journal, http)
    finally:
        # Also covers preconditions/operator failures before W01's cleanup block.
        client.token = None
        from mcp_vault.openbao.manager import set_hvac_client

        set_hvac_client(None)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--bao-url", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    if (
        not args.socket.is_absolute()
        or not args.socket.is_dir()
        or not args.report.is_absolute()
        or args.report.exists()
    ):
        raise ValueError("new private paths required")
    asyncio.run(run(args.socket, args.bao_url, args.report))


if __name__ == "__main__":
    main()
