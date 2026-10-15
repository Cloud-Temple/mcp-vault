"""Finite optional Mission retention extension; no application maintenance ACL."""
from pathlib import Path
import re

from .postgres import MetadataUnavailable

SOURCE = Path(__file__).with_name("schema") / "003_retention.sql"
ROUTINES = {
    "audit_fill_call()": False,
    "audit_retention_expired(text,text,text)": False,
    "audit_close_mission(text,text,text,uuid,bigint,timestamptz,timestamptz,text,timestamptz)": True,
    "audit_mission_status(text,text,text)": True,
    "audit_expire(text,integer,boolean)": True,
    "audit_expire_bound(text,text,text,integer,boolean)": True,
}


def install(conn, settings):
    from psycopg import sql
    if conn.execute("SELECT version FROM vault_metadata.schema_version").fetchall() != [{"version": 2}]:
        raise MetadataUnavailable("retention_upgrade_source_invalid")
    conn.execute(SOURCE.read_text(), prepare=False)
    conn.execute(sql.SQL("REVOKE ALL ON vault_metadata.audit_mission_holds FROM PUBLIC,{},{}").format(
        sql.Identifier(settings.metadata_pg_app_role), sql.Identifier(settings.audit_maintenance_role)))
    for name, maintenance in ROUTINES.items():
        signature = sql.SQL("vault_metadata." + name)
        conn.execute(sql.SQL("REVOKE ALL ON FUNCTION {} FROM PUBLIC,{},{}").format(
            signature, sql.Identifier(settings.metadata_pg_app_role), sql.Identifier(settings.audit_maintenance_role)))
        if maintenance:
            conn.execute(sql.SQL("GRANT EXECUTE ON FUNCTION {} TO {}").format(
                signature, sql.Identifier(settings.audit_maintenance_role)))


def verify(conn, settings):
    table = conn.execute("""SELECT pg_get_userbyid(c.relowner) AS owner,c.relrowsecurity AS rls,
        EXISTS(SELECT 1 FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
          WHERE a.grantee<>c.relowner) AS foreign_acl,
        EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0
          AND NOT a.attisdropped AND a.attacl IS NOT NULL) AS column_acl
        FROM pg_class c WHERE c.oid=to_regclass('vault_metadata.audit_mission_holds')""").fetchone()
    if table != {"owner": settings.metadata_pg_owner_role, "rls": False,
                 "foreign_acl": False, "column_acl": False}:
        raise MetadataUnavailable("retention_hold_rights_invalid")
    columns = conn.execute("""SELECT attname,format_type(atttypid,atttypmod) AS type,attnotnull
        FROM pg_attribute WHERE attrelid='vault_metadata.audit_mission_holds'::regclass
          AND attnum>0 AND NOT attisdropped ORDER BY attnum""").fetchall()
    wanted = [("instance_id", "text", True), ("tenant_id", "text", True), ("mission_id", "text", True),
              ("claim_id", "uuid", False), ("closure_revision", "bigint", False),
              ("terminal_at", "timestamp with time zone", False),
              ("retain_until", "timestamp with time zone", False), ("proof_sha256", "text", False)]
    if [(r["attname"], r["type"], r["attnotnull"]) for r in columns] != wanted:
        raise MetadataUnavailable("retention_hold_schema_invalid")
    constraints = conn.execute("""SELECT count(*) AS n,bool_and(convalidated) AS valid
        FROM pg_constraint WHERE conrelid='vault_metadata.audit_mission_holds'::regclass""").fetchone()
    if constraints != {"n": 4, "valid": True}:
        raise MetadataUnavailable("retention_hold_constraints_invalid")
    source = SOURCE.read_text()
    for signature, maintenance in ROUTINES.items():
        name = signature.split("(")[0]
        body = re.search(r"CREATE (?:OR REPLACE )?FUNCTION vault_metadata\." + name
                         + r"\(.*?AS \$\$(.*?)\$\$;", source, re.S)
        actual = conn.execute("""SELECT p.prosrc,p.prosecdef,p.proconfig,pg_get_userbyid(p.proowner) AS owner,
          EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
           WHERE a.grantee NOT IN (p.proowner,%s::regrole)) AS foreign_acl,
          has_function_privilege(%s,p.oid,'EXECUTE') AS app,
          has_function_privilege(%s,p.oid,'EXECUTE') AS maintenance
          FROM pg_proc p WHERE p.oid=to_regprocedure(%s)""",
          (settings.audit_maintenance_role, settings.metadata_pg_app_role, settings.audit_maintenance_role,
           "vault_metadata." + signature)).fetchone()
        if (body is None or actual is None or actual["prosrc"] != body[1]
                or not actual["prosecdef"] or actual["proconfig"] != ["search_path=pg_catalog"]
                or actual["owner"] != settings.metadata_pg_owner_role or actual["foreign_acl"]
                or actual["app"] or actual["maintenance"] is not maintenance):
            raise MetadataUnavailable("retention_hold_routine_invalid")
