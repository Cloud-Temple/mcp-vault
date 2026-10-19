"""SQL infrastructure fini pour un domaine déclaré ; aucun SQL fourni par l'usager.

Les connexions reçues viennent exclusivement du mount natif réservé, après auth.
L'identité infra n'est pas superuser ; CREATEDB/CREATEROLE restent cluster-wide.
"""

import re
from contextlib import contextmanager

import psycopg
from psycopg import sql

KINDS = ("app", "provisioner", "maintenance", "backup", "restore")


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", value):
        raise ValueError("Identifiant non canonique")
    return value


def validate_credentials(values, database, roles):
    if set(values) != {"infra", *KINDS} or len(set(roles.values())) != 6:
        raise ValueError("Six rôles distincts requis")
    for role in roles.values():
        identifier(role)
    for kind, value in values.items():
        if (
            set(value) != {"host", "port", "dbname", "user", "password"}
            or not all(isinstance(v, str) and v for v in value.values())
            or not value["port"].isdigit()
            or not 1 <= int(value["port"]) <= 65535
        ):
            raise ValueError("Credential non canonique")
        if kind != "infra" and (
            value["dbname"] != database or value["user"] != roles[kind]
        ):
            raise ValueError("Credential hors domaine")
        if (value["host"], value["port"]) != (
            values["infra"]["host"],
            values["infra"]["port"],
        ):
            raise ValueError("Instance SQL différente")
    if values["infra"]["user"] in roles.values():
        raise ValueError("Infra distincte requise")


@contextmanager
def connection(value, ca, database=None):
    options = dict(value)
    if database is not None:
        options["dbname"] = identifier(database)
    with psycopg.connect(
        **options,
        sslmode="verify-full",
        sslrootcert=ca,
        connect_timeout=3,
        autocommit=True,
        options="-c statement_timeout=5000 -c lock_timeout=2000",
    ) as conn:
        yield conn


def preflight(conn):
    if int(conn.execute("SHOW server_version_num").fetchone()[0]) < 160000:
        raise ValueError("Syntaxe membership : serveur PG16+ mesuré requis")
    row = conn.execute(
        "SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=current_user"
    ).fetchone()
    if not row or tuple(row) != (False, True, True, False, False):
        raise ValueError("Infra NON superuser CREATEDB/CREATEROLE requise")


@contextmanager
def as_role(conn, role):
    conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(identifier(role))))
    try:
        yield
    finally:
        conn.execute("RESET ROLE")


def provision(args, values):
    roles = {kind: getattr(args, kind + "_role") for kind in ("owner", *KINDS)}
    database = identifier(args.database)
    validate_credentials(values, database, roles)
    with connection(values["infra"], args.pg_ca_file) as conn:
        preflight(conn)
        if (
            conn.execute(
                "SELECT 1 FROM pg_roles WHERE rolname=ANY(%s)", (list(roles.values()),)
            ).fetchone()
            or conn.execute(
                "SELECT 1 FROM pg_database WHERE datname=%s", (database,)
            ).fetchone()
        ):
            raise ValueError("Collision : aucune reprise automatique")
        with conn.transaction():
            conn.execute(
                sql.SQL(
                    "CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
                ).format(sql.Identifier(roles["owner"]))
            )
            for kind in KINDS:
                conn.execute(
                    sql.SQL(
                        "CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD {}"
                    ).format(
                        sql.Identifier(roles[kind]),
                        sql.Literal(values[kind]["password"]),
                    )
                )
            infra = values["infra"]["user"]
            # Sens infra -> rôles A ; jamais app/maintenance -> owner.
            for kind in ("provisioner", "backup", "restore"):
                conn.execute(
                    sql.SQL(
                        "GRANT {} TO {} WITH ADMIN FALSE, INHERIT FALSE, SET TRUE"
                    ).format(
                        sql.Identifier(roles["owner"]), sql.Identifier(roles[kind])
                    )
                )
            for role in roles.values():
                conn.execute(
                    sql.SQL("GRANT {} TO {} WITH INHERIT FALSE, SET TRUE").format(
                        sql.Identifier(role), sql.Identifier(infra)
                    )
                )
        create_database(conn, database, roles, infra, private=False)
    with connection(values["infra"], args.pg_ca_file, database) as conn:  # noqa: SIM117 - role reset before connection close
        with as_role(conn, roles["owner"]):
            conn.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
            conn.execute("ALTER DEFAULT PRIVILEGES REVOKE ALL ON TABLES FROM PUBLIC")
    return {"status": "ok", "action": "provision", "domain": database}


def create_database(conn, database, roles, infra, *, private):
    conn.execute(
        sql.SQL("CREATE DATABASE {} OWNER {} TEMPLATE template0").format(
            sql.Identifier(identifier(database)), sql.Identifier(roles["owner"])
        )
    )
    # Le même grantor owner sera utilisé pour les futurs REVOKE.
    with as_role(conn, roles["owner"]):
        conn.execute(
            sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(
                sql.Identifier(database)
            )
        )
        allowed = [infra, roles["backup"], roles["restore"]]
        if not private:
            allowed += [roles[kind] for kind in ("app", "provisioner", "maintenance")]
        for role in allowed:
            conn.execute(
                sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                    sql.Identifier(database), sql.Identifier(role)
                )
            )


def db_observation(conn, database):
    """Catalogue complet, y compris grantors ; jamais seulement le code de GRANT."""
    row = conn.execute(
        "SELECT oid,datdba,datallowconn FROM pg_database WHERE datname=%s", (database,)
    ).fetchone()
    if not row:
        raise ValueError("Base absente")
    acl = conn.execute(
        """SELECT a.grantor,a.grantee,a.privilege_type,a.is_grantable
        FROM pg_database d,LATERAL aclexplode(COALESCE(d.datacl,acldefault('d',d.datdba))) a
        WHERE d.datname=%s ORDER BY 1,2,3,4""",
        (database,),
    ).fetchall()
    sessions = conn.execute(
        "SELECT pid,usesysid,usename FROM pg_stat_activity WHERE datname=%s AND pid<>pg_backend_pid() ORDER BY pid",
        (database,),
    ).fetchall()
    return {
        "oid": row[0],
        "owner": row[1],
        "allow_connections": row[2],
        "acl": [list(x) for x in acl],
        "sessions": [list(x) for x in sessions],
    }


def role_oids(conn, roles):
    rows = conn.execute(
        "SELECT rolname,oid FROM pg_roles WHERE rolname=ANY(%s)", (list(roles),)
    ).fetchall()
    if len(rows) != len(roles):
        raise ValueError("Rôles manquants")
    return dict(rows)


def domain_roles(conn, roles, infra):
    """Refuser les privilèges/memberships voisins avant toute action sur une base."""
    names = [*roles.values(), infra]
    oids = role_oids(conn, names)
    rows = conn.execute(
        """SELECT rolname,rolcanlogin,rolinherit,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls
        FROM pg_roles WHERE rolname=ANY(%s)""",
        (list(roles.values()),),
    ).fetchall()
    if len(rows) != 6:
        raise ValueError("Rôles incomplets")
    for name, login, inherit, *dangerous in rows:
        if any(dangerous) or login != (name != roles["owner"]) or (login and inherit):
            raise ValueError("Rôle domaine trop privilégié")
    memberships = conn.execute(
        """SELECT pg_get_userbyid(member),pg_get_userbyid(roleid),admin_option,inherit_option,set_option
        FROM pg_auth_members WHERE member=ANY(%s) ORDER BY 1,2""",
        (list(oids.values()),),
    ).fetchall()
    expected = {
        (roles[kind], roles["owner"], False, False, True)
        for kind in ("provisioner", "backup", "restore")
    }
    actual = set()
    for member, parent, admin, inherit, can_set in memberships:
        if member == infra:
            if parent not in roles.values() or inherit or not can_set:
                raise ValueError("Infra membre hors domaine ou héritage interdit")
        else:
            actual.add((member, parent, admin, inherit, can_set))
    if actual != expected:
        raise ValueError("Memberships domaine non conformes")
    return oids


def assert_closed(conn, database, roles, infra, *, sealed):
    observation = db_observation(conn, database)
    oids = role_oids(conn, [*roles.values(), infra])
    allowed = {oids[roles["owner"]]}
    if not sealed:
        allowed |= {oids[roles["backup"]], oids[infra]}
    if observation["allow_connections"] == sealed:
        raise ValueError("ALLOW_CONNECTIONS incohérent")
    if any(
        grantee not in allowed or grantor != observation["owner"] or grantable
        for grantor, grantee, privilege, grantable in observation["acl"]
        if privilege == "CONNECT" and grantee != observation["owner"]
    ):
        raise ValueError("CONNECT résiduel/grantor étranger")
    if any(grantee == 0 for _, grantee, _, _ in observation["acl"]):
        raise ValueError("PUBLIC résiduel")
    if any(
        grantee != observation["owner"] and privilege != "CONNECT"
        for _, grantee, privilege, _ in observation["acl"]
    ):
        raise ValueError("Privilège base hors propriétaire")
    if observation["sessions"]:
        raise ValueError("Sessions résiduelles")
    # Les droits effectifs incluent memberships ; datacl seul ne suffit pas.
    for kind in ("app", "provisioner", "maintenance", "restore"):
        if conn.execute(
            "SELECT has_database_privilege(%s,%s,'CONNECT')", (roles[kind], database)
        ).fetchone()[0]:
            raise ValueError("CONNECT effectif résiduel")
    return observation


def drain(conn, database, roles, *, preserve_backup):
    # Ne jamais tuer un PID inconnu, voisin, superuser, ou backup encore actif.
    rows = db_observation(conn, database)["sessions"]
    allowed = {
        roles[kind] for kind in KINDS if not (preserve_backup and kind == "backup")
    }
    if any(name not in allowed for _, _, name in rows):
        raise ValueError("Session étrangère : arrêt sans signal")
    for pid, _, name in rows:
        with as_role(conn, name):
            if not conn.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid=%s AND datname=%s AND usename=current_user",
                (pid, database),
            ).fetchone()[0]:
                raise ValueError("Drain non confirmé")


def freeze(conn, database, roles, infra, *, sealed=False):
    before = db_observation(conn, database)
    if before["owner"] != domain_roles(conn, roles, infra)[roles["owner"]]:
        raise ValueError("Base voisine/propriétaire étranger")
    with as_role(conn, roles["owner"]):
        conn.execute(
            sql.SQL("REVOKE CONNECT ON DATABASE {} FROM PUBLIC").format(
                sql.Identifier(database)
            )
        )
        for kind in (
            KINDS if sealed else ("app", "provisioner", "maintenance", "restore")
        ):
            conn.execute(
                sql.SQL("REVOKE CONNECT ON DATABASE {} FROM {}").format(
                    sql.Identifier(database), sql.Identifier(roles[kind])
                )
            )
        if sealed:
            conn.execute(
                sql.SQL("REVOKE CONNECT ON DATABASE {} FROM {}").format(
                    sql.Identifier(database), sql.Identifier(infra)
                )
            )
            conn.execute(
                sql.SQL("ALTER DATABASE {} ALLOW_CONNECTIONS false").format(
                    sql.Identifier(database)
                )
            )
    drain(conn, database, roles, preserve_backup=not sealed)
    before[
        "sessions"
    ] = []  # Le constat de retour porte ACL/ALLOW, jamais les anciens PID.
    return before, assert_closed(conn, database, roles, infra, sealed=sealed)
