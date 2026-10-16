"""Explicit optional v3->v4 install; no app DDL or broad maintenance grants."""

from pathlib import Path
import re

from .postgres import MetadataUnavailable

SOURCE = Path(__file__).with_name("schema") / "004_retirement.sql"
ROUTINES = {
    "audit_retirement_identity_hash(text)": None,
    "audit_retirement_lock(text,text,text,uuid)": "maintenance",
    "audit_retirement_inventory(text,text,text)": None,
    "audit_retirement_prepare(text,jsonb,uuid,text,timestamp with time zone)": "maintenance",
    "audit_retirement_batch(text,jsonb,uuid,text,timestamp with time zone,integer)": "maintenance",
    "audit_retirement_receipt(text,text,text,uuid)": "maintenance",
    "audit_wrap_admit(text,text,text)": "app",
    "audit_expire_bound(text,text,text,integer,boolean)": "maintenance",
}


def install(conn, settings):
    from psycopg import sql

    if conn.execute("SELECT version FROM vault_metadata.schema_version").fetchall() != [
        {"version": 3}
    ]:
        raise MetadataUnavailable("retirement_upgrade_source_invalid")
    conn.execute(SOURCE.read_text(), prepare=False)
    conn.execute(
        sql.SQL(
            "REVOKE ALL ON vault_metadata.audit_mission_retirements FROM PUBLIC,{},{}"
        ).format(
            sql.Identifier(settings.metadata_pg_app_role),
            sql.Identifier(settings.audit_maintenance_role),
        )
    )
    for name, role in ROUTINES.items():
        signature = sql.SQL("vault_metadata." + name)
        conn.execute(
            sql.SQL("REVOKE ALL ON FUNCTION {} FROM PUBLIC,{},{}").format(
                signature,
                sql.Identifier(settings.metadata_pg_app_role),
                sql.Identifier(settings.audit_maintenance_role),
            )
        )
        if role:
            grantee = (
                settings.metadata_pg_app_role
                if role == "app"
                else settings.audit_maintenance_role
            )
            conn.execute(
                sql.SQL("GRANT EXECUTE ON FUNCTION {} TO {}").format(
                    signature, sql.Identifier(grantee)
                )
            )


def verify(conn, settings):
    table = conn.execute("""SELECT pg_get_userbyid(c.relowner) AS owner,c.relrowsecurity AS rls,
        EXISTS(SELECT 1 FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
        WHERE a.grantee<>c.relowner) AS foreign_acl,
        EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0
        AND NOT a.attisdropped AND a.attacl IS NOT NULL) AS column_acl
        FROM pg_class c WHERE c.oid=to_regclass('vault_metadata.audit_mission_retirements')""").fetchone()
    if table != {
        "owner": settings.metadata_pg_owner_role,
        "rls": False,
        "foreign_acl": False,
        "column_acl": False,
    }:
        raise MetadataUnavailable("retirement_receipt_rights_invalid")
    columns = conn.execute("""SELECT attname,format_type(atttypid,atttypmod) AS type,attnotnull
        FROM pg_attribute WHERE attrelid='vault_metadata.audit_mission_retirements'::regclass
        AND attnum>0 AND NOT attisdropped ORDER BY attnum""").fetchall()
    wanted = [
        ("instance_id", "text", True),
        ("operation_id", "uuid", True),
        ("tenant_id", "text", True),
        ("mission_id", "text", True),
        ("identity", "jsonb", True),
        ("proof_sha256", "text", True),
        ("inventory", "jsonb", True),
        ("state", "text", True),
        ("lots", "jsonb", True),
        ("result", "jsonb", False),
        ("committed_at", "timestamp with time zone", False),
        ("receipt_retain_until", "timestamp with time zone", False),
    ]
    if [(r["attname"], r["type"], r["attnotnull"]) for r in columns] != wanted:
        raise MetadataUnavailable("retirement_receipt_schema_invalid")
    constraints = conn.execute("""SELECT count(*) AS n,bool_and(convalidated) AS valid
        FROM pg_constraint WHERE conrelid='vault_metadata.audit_mission_retirements'::regclass""").fetchone()
    if constraints != {"n": 9, "valid": True}:
        raise MetadataUnavailable("retirement_receipt_constraints_invalid")
    # Exact stored bodies and role ACLs; no SELECT on payloads for maintenance.
    for signature, role in ROUTINES.items():
        name = signature.split("(")[0]
        body = re.search(
            r"CREATE (?:OR REPLACE )?FUNCTION vault_metadata\."
            + name
            + r"\(.*?AS \$\$(.*?)\$\$;",
            SOURCE.read_text(),
            re.S,
        )
        row = conn.execute(
            """SELECT p.prosrc,p.prosecdef,p.proconfig,pg_get_userbyid(p.proowner) AS owner,
            EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
              WHERE a.grantee NOT IN (p.proowner,%s::regrole,%s::regrole)) AS foreign_acl,
            has_function_privilege(%s,p.oid,'EXECUTE') AS app,
            has_function_privilege(%s,p.oid,'EXECUTE') AS maintenance
            FROM pg_proc p WHERE p.oid=to_regprocedure(%s)""",
            (
                settings.metadata_pg_app_role,
                settings.audit_maintenance_role,
                settings.metadata_pg_app_role,
                settings.audit_maintenance_role,
                "vault_metadata." + signature,
            ),
        ).fetchone()
        if (
            body is None
            or row is None
            or row["prosrc"] != body[1]
            or not row["prosecdef"]
            or row["proconfig"] != ["search_path=pg_catalog"]
            or row["owner"] != settings.metadata_pg_owner_role
            or row["foreign_acl"]
            or row["app"] is not (role == "app")
            or row["maintenance"] is not (role == "maintenance")
        ):
            raise MetadataUnavailable("retirement_receipt_routine_invalid")
