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
    roles = list(roles)
    rows = conn.execute(
        "SELECT rolname,oid FROM pg_roles WHERE rolname=ANY(%s)", (list(roles),)
    ).fetchall()
    if (
        len(rows) != len(roles)
        or len(set(roles)) != len(roles)
        or any(
            len(row) != 2
            or type(row[0]) is not str
            or type(row[1]) is not int
            or row[1] <= 0
            for row in rows
        )
        or {row[0] for row in rows} != set(roles)
        or len({row[1] for row in rows}) != len(roles)
    ):
        raise ValueError("Rôles manquants")
    return dict(rows)


def domain_roles(conn, roles, infra):
    """Refuser les privilèges/memberships voisins avant toute action sur une base."""
    names = [*roles.values(), infra]
    oids = role_oids(conn, names)
    if conn.execute("SELECT session_user,current_user").fetchone() != (infra, infra):
        raise ValueError("Identité infra de session non confirmée")
    # PG16 BOOTSTRAP_SUPERUSERID est une identité système, jamais un nom/ID fourni
    # par operator.json. Relire son nom réel et son attribut superuser au catalogue.
    bootstrap = conn.execute(
        "SELECT oid,rolname,rolsuper FROM pg_roles WHERE oid=10 /* standalone:bootstrap-grantor */"
    ).fetchall()
    if (
        len(bootstrap) != 1
        or len(bootstrap[0]) != 3
        or type(bootstrap[0][0]) is not int
        or bootstrap[0][0] != 10
        or type(bootstrap[0][1]) is not str
        or not bootstrap[0][1]
        or bootstrap[0][2] is not True
        or 10 in oids.values()
        or bootstrap[0][1] in names
    ):
        raise ValueError("Grantor bootstrap PG16 non confirmé")
    bootstrap_oid, bootstrap_name, _ = bootstrap[0]
    rows = conn.execute(
        """SELECT rolname,rolcanlogin,rolinherit,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls
        FROM pg_roles WHERE rolname=ANY(%s)""",
        (names,),
    ).fetchall()
    if (
        len(rows) != 7
        or any(
            len(row) != 8
            or type(row[0]) is not str
            or any(type(flag) is not bool for flag in row[1:])
            for row in rows
        )
        or {row[0] for row in rows} != set(names)
    ):
        raise ValueError("Rôles incomplets")
    for name, login, inherit, *dangerous in rows:
        if name == infra:
            if not login or dangerous != [False, True, True, False, False]:
                raise ValueError(
                    "Infra trop privilégiée ou sans autorité de préparation"
                )
            continue
        if any(dangerous) or login != (name != roles["owner"]) or (login and inherit):
            raise ValueError("Rôle domaine trop privilégié")
    memberships = conn.execute(
        """SELECT m.member,mr.rolname,m.roleid,pr.rolname,m.grantor,gr.rolname,
            m.admin_option,m.inherit_option,m.set_option
        FROM pg_auth_members m
        LEFT JOIN pg_roles mr ON mr.oid=m.member
        LEFT JOIN pg_roles pr ON pr.oid=m.roleid
        LEFT JOIN pg_roles gr ON gr.oid=m.grantor
        WHERE m.member=ANY(%s) OR m.roleid=ANY(%s)
        ORDER BY m.member,m.roleid,m.grantor""",
        (list(oids.values()), list(oids.values())),
    ).fetchall()
    expected = {
        (oids[roles[kind]], oids[roles["owner"]], oids[infra], False, False, True)
        for kind in ("provisioner", "backup", "restore")
    }
    for role in roles.values():
        expected |= {
            (oids[infra], oids[role], bootstrap_oid, True, False, False),
            (oids[infra], oids[role], oids[infra], False, False, True),
        }
    identities = {oid: name for name, oid in oids.items()}
    identities[bootstrap_oid] = bootstrap_name
    actual = set()
    for row in memberships:
        if (
            len(row) != 9
            or any(type(row[i]) is not int or row[i] <= 0 for i in (0, 2, 4))
            or any(type(row[i]) is not bool for i in (6, 7, 8))
            or any(
                type(row[i + 1]) is not str or identities.get(row[i]) != row[i + 1]
                for i in (0, 2, 4)
            )
        ):
            raise ValueError("Identité/type de membership ou grantor non confirmé")
        member, _, parent, _, grantor, _, admin, inherit, can_set = row
        actual.add((member, parent, grantor, admin, inherit, can_set))
    if actual != expected or len(memberships) != len(expected):
        raise ValueError("Memberships/grantors domaine non conformes")
    # L'ADMIN bootstrap et le SET du self-grant sont deux lignes indépendantes.
    # Vérifier aussi la capacité effective avant owner/CREATE DATABASE ou drain.
    for role in roles.values():
        effective = conn.execute(
            "SELECT pg_has_role(session_user,%s,'SET')", (role,)
        ).fetchone()
        if not effective or len(effective) != 1 or effective[0] is not True:
            raise ValueError("Capacité SET infra non confirmée")
    for kind in ("app", "maintenance"):
        effective = conn.execute(
            "SELECT pg_has_role(%s,%s,'SET')", (roles[kind], roles["owner"])
        ).fetchone()
        if not effective or len(effective) != 1 or effective[0] is not False:
            raise ValueError("SET owner interdit pour app/maintenance")
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
