"""Explicit disposable PG16 fixture: v3 dump/restore and direct ACL comparisons.

No Vault/API acceptance claim. Uses the real product schema installers and public
SQL helpers; parent code is loaded only to demonstrate the original RED.
"""

import importlib.util
import json
import os
import secrets
from pathlib import Path
from types import SimpleNamespace

import standalone_pg as api
from psycopg import sql
from psycopg.rows import dict_row
from standalone_pg_sql import KINDS, connection, provision

from mcp_vault.storage import audit_schema


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
    roles = {k: "acl187_" + k for k in ("owner", *KINDS)}
    infra = {**admin, "user": "acl187_infra", "password": secrets.token_urlsafe(32)}
    with connection(admin, ca) as conn:
        version = conn.execute("SHOW server_version").fetchone()[0]
        assert int(conn.execute("SHOW server_version_num").fetchone()[0]) // 10000 == 16
        conn.execute(
            sql.SQL(
                "CREATE ROLE acl187_infra LOGIN NOINHERIT NOSUPERUSER CREATEDB CREATEROLE PASSWORD {}"
            ).format(sql.Literal(infra["password"]))
        )
        conn.execute("CREATE ROLE acl187_neighbor NOLOGIN")
    values = {"infra": infra} | {
        k: {
            **admin,
            "dbname": "acl187_source",
            "user": roles[k],
            "password": secrets.token_urlsafe(32),
        }
        for k in KINDS
    }
    cfg = {"roles": roles, "pg_ca_file": ca}
    provision(
        SimpleNamespace(
            database="acl187_source",
            pg_ca_file=ca,
            **{k + "_role": v for k, v in roles.items()},
        ),
        values,
    )
    with connection(values["backup"], ca) as conn, api.as_role(conn, roles["owner"]):
        conn.execute(
            Path(audit_schema.__file__)
            .with_name("schema")
            .joinpath("001.sql")
            .read_text(),
            prepare=False,
        )
        conn.execute(
            sql.SQL("GRANT USAGE ON SCHEMA vault_metadata TO {}").format(
                sql.Identifier(roles["app"])
            )
        )
        conn.execute(
            sql.SQL(
                "ALTER DEFAULT PRIVILEGES IN SCHEMA vault_metadata GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO {}"
            ).format(sql.Identifier(roles["app"]))
        )
        conn.row_factory = dict_row
        settings = SimpleNamespace(
            metadata_pg_owner_role=roles["owner"],
            metadata_pg_app_role=roles["app"],
            metadata_pg_provisioner_role=roles["provisioner"],
            audit_maintenance_role=roles["maintenance"],
            metadata_instance_id="fixture",
            audit_retention_days=30,
            audit_mission_retention_enabled=True,
        )
        with conn.transaction():
            audit_schema.install(conn, settings)
        assert conn.execute(
            "SELECT version FROM vault_metadata.schema_version"
        ).fetchone() == {"version": 3}
    spec = importlib.util.spec_from_file_location(
        "parent_operator", "/parent_operator.py"
    )
    assert spec is not None and spec.loader is not None
    parent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(parent)
    with connection(values["backup"], ca) as conn, api.as_role(conn, roles["owner"]):
        # Both edges below are owner grants, so the initial dump needs no
        # SET SESSION AUTHORIZATION to a delegated grantor.
        conn.execute("GRANT USAGE ON SCHEMA vault_metadata TO acl187_restore")
        conn.execute("CREATE TABLE vault_metadata.acl_probe(id int)")
        conn.execute(
            sql.SQL(
                "GRANT SELECT ON vault_metadata.acl_probe TO {} WITH GRANT OPTION"
            ).format(sql.Identifier(roles["restore"]))
        )
        conn.execute(
            "CREATE VIEW vault_metadata.acl_view AS SELECT id FROM vault_metadata.acl_probe"
        )
        conn.execute(
            "CREATE MATERIALIZED VIEW vault_metadata.acl_materialized AS SELECT id FROM vault_metadata.acl_probe"
        )
        conn.execute(
            "CREATE FUNCTION vault_metadata.acl_function() RETURNS integer LANGUAGE sql AS 'SELECT 1'"
        )
        assert conn.execute(
            "SELECT pg_get_userbyid(a.grantor) FROM pg_class c,LATERAL aclexplode(c.relacl) a WHERE c.oid='vault_metadata.acl_probe'::regclass AND a.grantee='acl187_app'::regrole AND a.privilege_type='SELECT'"
        ).fetchall() == [(roles["owner"],)]
        conn.execute("CREATE SEQUENCE vault_metadata.acl_sequence")
        source_old = parent.structure_signature(conn, roles["owner"])
        source_new = api.structure_signature(conn, roles["owner"])
        source_acl = conn.execute(
            "SELECT relacl::text FROM pg_class WHERE oid='vault_metadata.audit_mission_holds'::regclass"
        ).fetchone()[0]
    before = api.fingerprint(cfg, values, "acl187_source")
    with api.control(cfg, values) as conn:
        api.freeze(conn, "acl187_source", roles, infra["user"], sealed=False)
    tools = api.pg_tools(cfg, values)
    archive = directory / "v3.dump"
    archive_digest = api.pg_tool(cfg, values, "acl187_source", "dump", archive, tools)
    with api.control(cfg, values) as conn:
        api.create_database(conn, "acl187_copy", roles, infra["user"], private=True)
        api.freeze(conn, "acl187_source", roles, infra["user"], sealed=True)
    api.pg_tool(cfg, values, "acl187_copy", "restore", archive, tools)
    assert api.fingerprint(cfg, values, "acl187_copy") == before
    checks = []
    with connection(admin, ca, "acl187_copy") as conn:
        copy_acl = conn.execute(
            "SELECT relacl::text FROM pg_class WHERE oid='vault_metadata.audit_mission_holds'::regclass"
        ).fetchone()[0]
        assert source_acl is not None and copy_acl is None
        assert parent.structure_signature(conn, roles["owner"]) != source_old
        assert api.structure_signature(conn, roles["owner"]) == source_new
        checks.extend(["parent_RED_NULL_owner", "GREEN_v3_full_dump_restore"])

        class Rollback(Exception):
            pass

        def change(name, statements, *, equal=False, role=None):
            try:
                with conn.transaction():
                    if role:
                        conn.execute(
                            sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(role))
                        )
                    for statement in statements:
                        conn.execute(statement)
                    actual = api.structure_signature(conn, roles["owner"])
                    assert (actual == source_new) is equal, name
                    raise Rollback()
            except Rollback:
                checks.append(name)
            assert api.structure_signature(conn, roles["owner"]) == source_new

        change(
            "sequence_default_type",
            ["GRANT ALL ON SEQUENCE vault_metadata.acl_sequence TO acl187_owner"],
            equal=True,
            role=roles["owner"],
        )
        change(
            "function_default_type",
            [
                "GRANT ALL ON FUNCTION vault_metadata.acl_function() TO acl187_owner",
                "GRANT EXECUTE ON FUNCTION vault_metadata.acl_function() TO PUBLIC",
            ],
            equal=True,
            role=roles["owner"],
        )
        change(
            "table_neighbor",
            ["GRANT SELECT ON vault_metadata.audit_mission_holds TO acl187_neighbor"],
        )
        change(
            "PUBLIC", ["GRANT SELECT ON vault_metadata.audit_mission_holds TO PUBLIC"]
        )
        change(
            "grant_option",
            [
                "GRANT SELECT ON vault_metadata.acl_probe TO acl187_app WITH GRANT OPTION"
            ],
        )
        change(
            "owner", ["ALTER TABLE vault_metadata.acl_probe OWNER TO acl187_neighbor"]
        )
        change(
            "empty_not_NULL",
            ["REVOKE ALL ON vault_metadata.audit_mission_holds FROM acl187_owner"],
        )
        change(
            "sequence_type",
            [
                "GRANT USAGE ON SEQUENCE vault_metadata.audit_events_seq_seq TO acl187_neighbor"
            ],
        )
        change(
            "function_PUBLIC_default",
            ["REVOKE EXECUTE ON FUNCTION vault_metadata.acl_function() FROM PUBLIC"],
        )
        change("schema", ["GRANT USAGE ON SCHEMA vault_metadata TO acl187_neighbor"])
        change("view", ["GRANT SELECT ON vault_metadata.acl_view TO acl187_neighbor"])
        change(
            "materialized_view",
            ["GRANT SELECT ON vault_metadata.acl_materialized TO acl187_neighbor"],
        )
        change(
            "default_schema",
            [
                "ALTER DEFAULT PRIVILEGES FOR ROLE acl187_owner IN SCHEMA vault_metadata GRANT SELECT ON TABLES TO acl187_neighbor"
            ],
        )
        change(
            "default_global",
            [
                "ALTER DEFAULT PRIVILEGES FOR ROLE acl187_owner GRANT USAGE ON SEQUENCES TO acl187_neighbor"
            ],
        )
        change(
            "default_empty_parent",
            [
                "ALTER DEFAULT PRIVILEGES FOR ROLE acl187_owner REVOKE ALL ON FUNCTIONS FROM PUBLIC,acl187_owner"
            ],
        )
        # Same grants, different aclitem insertion order. Owner remains grantor.
        change(
            "acl_order",
            [
                "REVOKE SELECT,INSERT,UPDATE,DELETE ON vault_metadata.acl_probe FROM acl187_app",
                "GRANT SELECT,INSERT,UPDATE,DELETE ON vault_metadata.acl_probe TO acl187_app",
            ],
            equal=True,
            role=roles["owner"],
        )
        # Real delegated grant on Copy versus the real owner grant on Source.
        # This deliberately calls structure_signature, never pg_restore.
        try:
            with conn.transaction():
                conn.execute("SET LOCAL ROLE acl187_owner")
                conn.execute(
                    "REVOKE SELECT ON vault_metadata.acl_probe FROM acl187_app"
                )
                conn.execute("RESET ROLE")
                conn.execute("SET LOCAL ROLE acl187_restore")
                conn.execute("GRANT SELECT ON vault_metadata.acl_probe TO acl187_app")
                grantors = conn.execute(
                    "SELECT pg_get_userbyid(a.grantor) FROM pg_class c,LATERAL aclexplode(c.relacl) a WHERE c.oid='vault_metadata.acl_probe'::regclass AND a.grantee='acl187_app'::regrole AND a.privilege_type='SELECT'"
                ).fetchall()
                assert grantors == [(roles["restore"],)]
                assert api.structure_signature(conn, roles["owner"]) != source_new
                raise Rollback()
        except Rollback:
            checks.append("direct_real_delegated_grantor")
    with api.control(cfg, values) as conn:
        assert api.db_observation(conn, "acl187_source")["allow_connections"] is False
    assert api.archive_hash(archive) == archive_digest
    print(
        json.dumps(
            {
                "result": "PASS",
                "server_version": version,
                "tools": tools["versions"],
                "archive": archive_digest,
                "source_holds_acl": source_acl,
                "copy_holds_acl": copy_acl,
                "checks": checks,
                "source_not_reopened": True,
            }
        )
    )


if __name__ == "__main__":
    main()
