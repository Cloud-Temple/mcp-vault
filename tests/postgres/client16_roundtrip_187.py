"""Small real PG16/client16 compatibility check; no Vault/API/service lifecycle.

Run explicitly in pg-operator against tests/postgres/compose.yml, on a fresh
engine only. PG password/CA and output directory are private fixture mounts.
This checks client/archive/transaction semantics, not standalone acceptance.
"""

import json
import os
import secrets
import subprocess
import zlib
from pathlib import Path
from types import SimpleNamespace

import standalone_pg as api
from psycopg import sql
from standalone_pg_files import Journal
from standalone_pg_sql import KINDS, connection, provision


def main():
    directory = Path(os.environ["CLIENT187_DIRECTORY"])
    ca = os.environ["CLIENT187_CA"]
    password = Path(os.environ["CLIENT187_PASSWORD_FILE"]).read_text().strip()
    admin = {
        "host": "postgres",
        "port": "5432",
        "dbname": "postgres",
        "user": "postgres",
        "password": password,
    }
    roles = {kind: "client187_" + kind for kind in ("owner", *KINDS)}
    infra = {**admin, "user": "client187_infra", "password": secrets.token_urlsafe(32)}
    with connection(admin, ca) as conn:
        assert int(conn.execute("SHOW server_version_num").fetchone()[0]) // 10000 == 16
        conn.execute(
            sql.SQL(
                "CREATE ROLE client187_infra LOGIN NOINHERIT NOSUPERUSER CREATEDB CREATEROLE PASSWORD {}"
            ).format(sql.Literal(infra["password"]))
        )
    values = {"infra": infra} | {
        kind: {
            **admin,
            "dbname": "client187_source",
            "user": role,
            "password": secrets.token_urlsafe(32),
        }
        for kind, role in roles.items()
        if kind != "owner"
    }
    cfg = {"roles": roles, "pg_ca_file": ca, "carrier_dir": str(directory / "carriers")}
    provision(
        SimpleNamespace(
            database="client187_source",
            pg_ca_file=ca,
            **{k + "_role": v for k, v in roles.items()},
        ),
        values,
    )
    with connection(values["backup"], ca) as conn:  # noqa: SIM117 - reset role before connection closes
        with api.as_role(conn, roles["owner"]):
            conn.execute("CREATE SCHEMA vault_metadata")
            conn.execute("CREATE TABLE vault_metadata.schema_version(version int)")
            conn.execute("INSERT INTO vault_metadata.schema_version VALUES (2)")
            conn.execute(
                "CREATE TABLE vault_metadata.audit_events(id bigint GENERATED ALWAYS AS IDENTITY, payload jsonb)"
            )
            conn.execute("ALTER SEQUENCE vault_metadata.audit_events_id_seq CACHE 32")
            conn.execute(
                "INSERT INTO vault_metadata.audit_events(payload) VALUES ('{\"revoked\":true}')"
            )
            conn.execute(
                sql.SQL("GRANT USAGE ON SCHEMA vault_metadata TO {}").format(
                    sql.Identifier(roles["app"])
                )
            )
            conn.execute(
                sql.SQL(
                    "GRANT SELECT ON ALL TABLES IN SCHEMA vault_metadata TO {}"
                ).format(sql.Identifier(roles["app"]))
            )
            before_sequence = conn.execute(
                "SELECT last_value,is_called,log_cnt FROM vault_metadata.audit_events_id_seq"
            ).fetchone()
    with api.control(cfg, values) as conn:
        api.freeze(conn, "client187_source", roles, infra["user"], sealed=False)
    baseline = api.fingerprint(cfg, values, "client187_source")
    tools = api.pg_tools(cfg, values)
    journal = Journal(cfg)
    archive = directory / "source.dump"
    journal.run(
        "dump-frozen",
        lambda: {
            "archive": api.pg_tool(
                cfg, values, "client187_source", "dump", archive, tools
            ),
            "tool_versions": tools["versions"],
        },
    )
    api.check_restore_archive(journal, archive, tools)
    with api.control(cfg, values) as conn:
        for name in ("client187_copy", "client187_failed"):
            api.create_database(conn, name, roles, infra["user"], private=True)
        api.freeze(conn, "client187_source", roles, infra["user"], sealed=True)
    api.pg_tool(cfg, values, "client187_copy", "restore", archive, tools)
    assert api.fingerprint(cfg, values, "client187_copy") == baseline
    with connection(values["backup"], ca, "client187_copy") as conn:  # noqa: SIM117 - reset role before connection closes
        with api.as_role(conn, roles["owner"]):
            after_sequence = conn.execute(
                "SELECT last_value,is_called,log_cnt FROM vault_metadata.audit_events_id_seq"
            ).fetchone()
    assert before_sequence[:2] == after_sequence[:2]
    assert before_sequence[2] > 0 and after_sequence[2] == 0
    # Corrupt an actual compressed data block, leaving the TOC readable.
    # Truncating a trailing TOC suffix may still leave a fully restorable dump.
    payload = bytearray(archive.read_bytes())
    compressed = payload.index(b"\x78\x9c")
    assert b'"revoked"' in zlib.decompress(payload[compressed:])
    payload[compressed + 2] ^= 0xFF
    broken = directory / "corrupt-data.dump"
    broken.write_bytes(payload)
    broken.chmod(0o600)
    assert (
        subprocess.run(
            [tools["restore"], "--list", str(broken)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        == 0
    )
    failed_cfg = {**cfg, "carrier_dir": str(directory / "failed-carriers")}
    failed_journal = Journal(failed_cfg)
    try:
        failed_journal.run(
            "restore-frozen",
            lambda: api.pg_tool(
                cfg, values, "client187_failed", "restore", broken, tools
            ),
        )
    except ValueError:
        pass
    else:
        raise AssertionError("Corrupt compressed data must fail the actual restore")
    assert failed_journal.exists("restore-frozen.intent") and not failed_journal.exists(
        "restore-frozen.ack"
    )
    assert api.fingerprint(cfg, values, "client187_failed", empty=True)["tables"] == []
    with api.control(cfg, values) as conn:
        assert (
            api.db_observation(conn, "client187_source")["allow_connections"] is False
        )
    print(
        json.dumps(
            {
                "result": "PASS",
                "tools": tools["versions"],
                "archive": api.archive_hash(archive),
                "logical_data_acl_equal": True,
                "source_sequence": before_sequence,
                "copy_sequence": after_sequence,
                "failed_restore_rolled_back": True,
                "failed_restore_ack": False,
                "source_not_reopened": True,
            }
        )
    )


if __name__ == "__main__":
    main()
