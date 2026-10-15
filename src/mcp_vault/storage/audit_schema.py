"""Schéma audit v2 et ACL effectives ; voie owner opérateur, aucune création de rôle."""

from pathlib import Path

from .postgres import MetadataUnavailable

TABLES = ("audit_retention_policy", "audit_revision", "audit_calls", "audit_events")
FUNCTIONS = ("audit_fill_call()", "audit_fill_event()", "audit_bump_revision()",
             "audit_expire(text,integer,boolean)")


def install(conn, settings):
    """À l'intérieur de la transaction owner déjà validée, depuis v1 seulement."""
    from psycopg import sql
    names = (settings.metadata_pg_owner_role, settings.metadata_pg_app_role,
             settings.metadata_pg_provisioner_role, settings.audit_maintenance_role)
    if len(set(names)) != 4:
        raise MetadataUnavailable("audit_roles_invalid")
    maintenance = conn.execute("""SELECT rolcanlogin AND NOT (rolsuper OR rolcreatedb OR
        rolcreaterole OR rolreplication OR rolbypassrls) AS allowed FROM pg_roles WHERE rolname=%s""",
        (settings.audit_maintenance_role,)).fetchone()
    if not maintenance or not maintenance["allowed"]:
        raise MetadataUnavailable("audit_maintenance_invalid")
    if conn.execute("SELECT version FROM vault_metadata.schema_version").fetchall() != [{"version": 1}]:
        raise MetadataUnavailable("audit_upgrade_source_invalid")
    source_owner = conn.execute("SELECT pg_get_userbyid(nspowner) AS owner FROM pg_namespace WHERE nspname='vault_metadata'").fetchone()
    if not source_owner or source_owner["owner"] != settings.metadata_pg_owner_role:
        raise MetadataUnavailable("audit_upgrade_source_invalid")
    conn.execute(Path(__file__).with_name("schema").joinpath("002_audit.sql").read_text(), prepare=False)
    for table in TABLES:
        conn.execute(sql.SQL("REVOKE ALL ON vault_metadata.{} FROM {},{},PUBLIC").format(
            sql.Identifier(table), sql.Identifier(settings.metadata_pg_app_role),
            sql.Identifier(settings.audit_maintenance_role)))
    conn.execute(sql.SQL("GRANT SELECT ON vault_metadata.audit_retention_policy,vault_metadata.audit_revision TO {}").format(
        sql.Identifier(settings.metadata_pg_app_role)))
    conn.execute(sql.SQL("GRANT SELECT,INSERT ON vault_metadata.audit_calls,vault_metadata.audit_events TO {}").format(
        sql.Identifier(settings.metadata_pg_app_role)))
    conn.execute(sql.SQL("GRANT USAGE ON SEQUENCE vault_metadata.audit_events_seq_seq TO {}").format(
        sql.Identifier(settings.metadata_pg_app_role)))
    conn.execute(sql.SQL("GRANT USAGE ON SCHEMA vault_metadata TO {}").format(sql.Identifier(settings.audit_maintenance_role)))
    conn.execute(sql.SQL("GRANT EXECUTE ON FUNCTION vault_metadata.audit_expire(text,integer,boolean) TO {}").format(
        sql.Identifier(settings.audit_maintenance_role)))
    conn.execute("INSERT INTO vault_metadata.audit_retention_policy VALUES(%s,%s)",
                 (settings.metadata_instance_id, settings.audit_retention_days))
    if getattr(settings, "audit_mission_retention_enabled", False):
        from .audit_retention_schema import install as install_retention
        install_retention(conn, settings)
    verify(conn, settings)


def verify(conn, settings):
    """À l'installation et à chaque connexion app ; pas de réparation implicite."""
    app, maintenance, owner = (settings.metadata_pg_app_role, settings.audit_maintenance_role,
                               settings.metadata_pg_owner_role)
    version = conn.execute("SELECT version FROM vault_metadata.schema_version").fetchall()
    if (version not in ([{"version": 2}], [{"version": 3}])
            or getattr(settings, "audit_mission_retention_enabled", False) and version != [{"version": 3}]):
        raise MetadataUnavailable("audit_schema_invalid")
    policy = conn.execute("SELECT retention_days FROM vault_metadata.audit_retention_policy WHERE instance_id=%s",
                          (settings.metadata_instance_id,)).fetchone()
    if not policy or policy["retention_days"] != settings.audit_retention_days:
        raise MetadataUnavailable("audit_retention_mismatch")
    for role in (app, maintenance):
        attributes = conn.execute("""SELECT NOT rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls
            OR EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid) AS unsafe
            FROM pg_roles r WHERE rolname=%s""", (role,)).fetchone()
        if not attributes or attributes["unsafe"]:
            raise MetadataUnavailable("audit_rights_invalid")
        ddl = conn.execute("""SELECT has_database_privilege(%s,current_database(),'CREATE')
            OR has_database_privilege(%s,current_database(),'TEMP')
            OR has_schema_privilege(%s,'vault_metadata','CREATE')
            OR has_schema_privilege(%s,'public','CREATE') AS unsafe""", (role,)*4).fetchone()
        if ddl["unsafe"]:
            raise MetadataUnavailable("audit_rights_invalid")
        for table in TABLES:
            for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"):
                expected = role == app and (privilege == "SELECT" or
                           privilege == "INSERT" and table in {"audit_calls", "audit_events"})
                observed = conn.execute("SELECT has_table_privilege(%s,%s,%s) AS allowed",
                    (role, "vault_metadata."+table, privilege)).fetchone()["allowed"]
                if observed is not expected:
                    raise MetadataUnavailable("audit_rights_invalid")
    other_access = conn.execute("""SELECT EXISTS(SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid=c.relnamespace
        CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']) privilege
        WHERE n.nspname='vault_metadata' AND c.relkind IN ('r','p')
        AND has_table_privilege(%s,c.oid,privilege)) AS unsafe""", (maintenance,)).fetchone()
    if other_access["unsafe"]:
        raise MetadataUnavailable("audit_maintenance_invalid")
    public = conn.execute("""SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace,
        LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a
        WHERE n.nspname='vault_metadata' AND c.relname=ANY(%s) AND a.grantee=0) AS unsafe""",
        (list(TABLES),)).fetchone()
    if public["unsafe"]:
        raise MetadataUnavailable("audit_rights_invalid")
    for role in (app, maintenance):
        for privilege in ("USAGE", "SELECT", "UPDATE"):
            observed = conn.execute("SELECT has_sequence_privilege(%s,'vault_metadata.audit_events_seq_seq',%s) AS allowed",
                (role, privilege)).fetchone()["allowed"]
            if observed is not (role == app and privilege == "USAGE"):
                raise MetadataUnavailable("audit_rights_invalid")
    for name in FUNCTIONS:
        function = conn.execute("""SELECT p.prosecdef,pg_get_userbyid(p.proowner) AS owner,p.proconfig,
            EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
            WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public
            FROM pg_proc p WHERE p.oid=to_regprocedure(%s)""", ("vault_metadata."+name,)).fetchone()
        if (not function or not function["prosecdef"] or function["owner"] != owner
                or function["proconfig"] != ["search_path=pg_catalog"] or function["public"]):
            raise MetadataUnavailable("audit_routine_invalid")
        for role in (app, maintenance):
            observed = conn.execute("SELECT has_function_privilege(%s,%s,'EXECUTE') AS allowed",
                (role, "vault_metadata."+name)).fetchone()["allowed"]
            if observed is not (role == maintenance and name.startswith("audit_expire(")):
                raise MetadataUnavailable("audit_routine_invalid")
    constraints = conn.execute("""SELECT c.relname,count(*) AS n,bool_and(k.convalidated) AS valid
        FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='vault_metadata'
        AND c.relname=ANY(%s) GROUP BY c.relname ORDER BY c.relname""", (list(TABLES),)).fetchall()
    expected = {"audit_calls": 4, "audit_events": 9, "audit_retention_policy": 2, "audit_revision": 2}
    if ({r["relname"]: r["n"] for r in constraints} != expected
            or any(not r["valid"] for r in constraints)):
        raise MetadataUnavailable("audit_constraints_invalid")
    triggers = conn.execute("""SELECT t.tgname,t.tgenabled,pg_get_userbyid(p.proowner) AS owner,
        p.proname,c.relname FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid
        JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='vault_metadata' AND c.relname=ANY(%s) AND NOT t.tgisinternal""", (list(TABLES),)).fetchall()
    wanted = {("audit_call_dates", "audit_fill_call", "audit_calls"),
              ("audit_event_dates", "audit_fill_event", "audit_events"),
              ("audit_call_revision", "audit_bump_revision", "audit_calls"),
              ("audit_event_revision", "audit_bump_revision", "audit_events")}
    if ({(r["tgname"],r["proname"],r["relname"]) for r in triggers} != wanted
            or any(r["tgenabled"] != "O" or r["owner"] != owner for r in triggers)):
        raise MetadataUnavailable("audit_triggers_invalid")
    ownership = conn.execute("""SELECT count(*) AS n,bool_and(pg_get_userbyid(c.relowner)=%s) AS allowed
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='vault_metadata' AND c.relname=ANY(%s)""", (owner, list(TABLES))).fetchone()
    if ownership != {"n": 4, "allowed": True}:
        raise MetadataUnavailable("audit_owner_invalid")
    if version == [{"version": 3}]:
        # Disabling coordination never downgrades an installed protection.
        from .audit_retention_schema import verify as verify_retention
        verify_retention(conn, settings)
