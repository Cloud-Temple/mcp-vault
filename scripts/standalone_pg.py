#!/usr/bin/env python3
"""Opérations standalone bornées. Ne démarre aucun service automatiquement.

Préparer Bao, son unseal et son auth native AVANT toute SQL. --vault-ca-file
(operator.json: vault_ca_file) n'a aucun effet TLS sur Bao HTTP loopback.
Une intention sans ACK interdit le rejeu. Les tests natifs restent indispensables.
"""

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import uuid
from contextlib import contextmanager
from datetime import UTC
from pathlib import Path
from types import SimpleNamespace

import httpx
from psycopg import sql
from standalone_pg_files import (
    Journal,
    canonical,
    load_config,
    private_directory,
    private_read,
    private_write,
)
from standalone_pg_native import Native
from standalone_pg_sql import (
    KINDS,
    as_role,
    assert_closed,
    connection,
    create_database,
    db_observation,
    domain_roles,
    freeze,
    preflight,
    provision,
    role_oids,
    validate_credentials,
)


def source_context(config):
    return "copy" if config["context"] == "return" else "source_fresh"


def read_values(native, config, context=None):
    context = context or config["context"]
    domain = config["domains"][context]
    values = {"infra": native.read(config["infra_path"])}
    values.update({kind: native.read(domain["paths"][kind]) for kind in KINDS})
    validate_credentials(values, domain["database"], config["roles"])
    if values["infra"]["dbname"] in {d["database"] for d in config["domains"].values()}:
        raise ValueError(
            "Base de contrôle distincte des trois bases du domaine requise"
        )
    if values["infra"]["user"] in config["roles"].values():
        raise ValueError("Infra distincte requise")
    if values["infra"]["host"] != config["tls"]["host"]:
        raise ValueError("Host utilisé différent du SAN configuré")
    return values


def settings(config, context=None):
    """Même Settings et fichier que le serveur, dans un contexte d'env propre."""
    from dotenv import dotenv_values

    path = Path(config["settings_file"])
    private_read(path)
    os.chdir(path.parent)
    safe = {key: os.environ[key] for key in ("PATH", "PYTHONPATH") if key in os.environ}
    os.environ.clear()
    os.environ.update(safe)
    for key, value in dotenv_values(path).items():
        if value is not None:
            os.environ[key] = value
    from mcp_vault.config import get_settings

    get_settings.cache_clear()
    value = get_settings()
    domain = config["domains"][context or config["context"]]
    expected = {
        "metadata_backend": "postgres",
        "metadata_instance_id": config["instance"],
        "metadata_pg_vault_id": config["mount"],
        "metadata_pg_database": domain["database"],
        "metadata_pg_ca_file": config["pg_ca_file"],
        "metadata_pg_secret_path": domain["paths"]["app"],
        "metadata_pg_provisioner_secret_path": domain["paths"]["provisioner"],
        "audit_maintenance_secret_path": domain["paths"]["maintenance"],
        "metadata_pg_owner_role": config["roles"]["owner"],
        "metadata_pg_app_role": config["roles"]["app"],
        "metadata_pg_provisioner_role": config["roles"]["provisioner"],
        "audit_maintenance_role": config["roles"]["maintenance"],
        "metadata_pg_durability": "standalone",
    }
    if any(
        getattr(value, key) != expected_value
        for key, expected_value in expected.items()
    ):
        raise ValueError("Settings différentes du domaine déclaré")
    if value.openbao_addr.rstrip("/") != config["vault_url"].rstrip("/"):
        raise ValueError("Bao différent des Settings applicatives")
    if (
        private_read(config["bootstrap_file"]).decode().strip()
        != value.admin_bootstrap_key
    ):
        raise ValueError("Clé opérateur différente des Settings")
    return value


def product(config, action, body=None):
    # Les deux actions Copy sont les seules accessibles à install().
    key = private_read(config["bootstrap_file"]).decode().strip()
    with httpx.Client(
        verify=config["product_ca_file"] or True,
        timeout=httpx.Timeout(40, connect=3),
        follow_redirects=False,
    ) as client:
        method = "GET" if action == "status" else "POST"
        response = client.request(
            method,
            config["product_url"].rstrip("/")
            + "/admin/api/metadata-operator/"
            + action,
            headers={"Authorization": "Bearer " + key},
            json=body or {},
        )
        if len(response.content) > 65536:
            raise ValueError("Réponse opérateur hors borne")
        value = response.json()
        if response.status_code != 200 or value.get("status") != "ok":
            raise ValueError("Action opérateur non confirmée")
        return value


def mode(config, expected):
    value = product(config, "status")
    if value.get("mode") != expected or value.get("openbao_ready") is not True:
        raise ValueError("Mode/Bao non confirmé")
    return value


@contextmanager
def control(config, values):
    with connection(values["infra"], config["pg_ca_file"]) as conn:
        identity = conn.execute(
            "SELECT current_database(),session_user,current_user"
        ).fetchone()
        if identity != (
            values["infra"]["dbname"],
            values["infra"]["user"],
            values["infra"]["user"],
        ):
            raise ValueError("Base de contrôle/identité infra différente")
        preflight(conn)
        yield conn


def fingerprint(config, values, database, *, empty=False):
    """Empreinte privée des données ET séquences, pas leur contenu dans les preuves."""
    with connection(values["backup"], config["pg_ca_file"], database) as conn:  # noqa: SIM117 - transaction scope stays explicit
        with conn.transaction():
            conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            with as_role(conn, config["roles"]["owner"]):
                tables = conn.execute("""SELECT c.relname,c.relkind FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                    WHERE n.nspname='vault_metadata' AND c.relkind IN ('r','S') ORDER BY 1""").fetchall()
                if empty and tables:
                    raise ValueError("Copie non vierge")
                result = []
                for name, kind in tables:
                    if kind == "S":
                        # setval restaure l'état logique, pas le cache/WAL log_cnt.
                        rows = conn.execute(
                            sql.SQL(
                                "SELECT last_value,is_called FROM vault_metadata.{}"
                            ).format(sql.Identifier(name))
                        ).fetchall()
                        if (
                            len(rows) != 1
                            or len(rows[0]) != 2
                            or type(rows[0][0]) is not int
                            or type(rows[0][1]) is not bool
                        ):
                            raise ValueError("État logique de séquence non confirmé")
                        payload = [list(rows[0])]
                    elif kind == "r":
                        rows = conn.execute(
                            sql.SQL(
                                "SELECT to_jsonb(t)::text FROM vault_metadata.{} t ORDER BY to_jsonb(t)::text"
                            ).format(sql.Identifier(name))
                        ).fetchall()
                        payload = [r[0] for r in rows]
                    else:
                        raise ValueError("Type de relation inattendu")
                    result.append(
                        [
                            name,
                            kind,
                            hashlib.sha256(canonical(payload)).hexdigest(),
                        ]
                    )
                version = (
                    []
                    if not tables
                    else conn.execute(
                        "SELECT version FROM vault_metadata.schema_version"
                    ).fetchall()
                )
                return {
                    "tables": result,
                    "versions": [r[0] for r in version],
                    "structure_sha256": structure_signature(
                        conn, config["roles"]["owner"]
                    ),
                }


def structure_signature(conn, owner):
    """Comparer les ACL et définitions logiques, sans comparer les OID physiques."""

    def acl(expression):
        # A scalar subquery preserves the object even when its ACL is empty.
        # LEFT JOIN preserves unresolved roles so validation refuses them.
        return f"""(SELECT COALESCE(jsonb_agg(jsonb_build_array(
            g.rolname, CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE 'ROLE' END,
            CASE WHEN a.grantee=0 THEN '' ELSE r.rolname END,
            a.privilege_type,a.is_grantable)
            ORDER BY g.rolname COLLATE "C",a.grantee=0,r.rolname COLLATE "C",
                     a.privilege_type COLLATE "C",a.is_grantable),'[]'::jsonb)
            FROM aclexplode({expression}) a
            LEFT JOIN pg_roles g ON g.oid=a.grantor
            LEFT JOIN pg_roles r ON r.oid=a.grantee)"""

    queries = (
        (
            "schema",
            f"""SELECT nspname,(SELECT rolname FROM pg_roles WHERE oid=nspowner),{acl("COALESCE(nspacl,acldefault('n',nspowner))")} FROM pg_namespace WHERE nspname='vault_metadata' ORDER BY 1""",
            None,
        ),
        (
            "relations",
            f"""SELECT c.relname,c.relkind,(SELECT rolname FROM pg_roles WHERE oid=c.relowner),{acl("COALESCE(c.relacl,CASE WHEN c.relkind='S' THEN acldefault('s',c.relowner) ELSE acldefault('r',c.relowner) END)")} FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='vault_metadata' AND c.relkind IN ('r','S','v','m','f') ORDER BY 1,2""",
            None,
        ),
        (
            "columns",
            "SELECT c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,pg_get_expr(d.adbin,d.adrelid) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum WHERE n.nspname='vault_metadata' ORDER BY 1,2",
            None,
        ),
        (
            "constraints",
            "SELECT c.relname,k.conname,pg_get_constraintdef(k.oid,true) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='vault_metadata' ORDER BY 1,2",
            None,
        ),
        (
            "functions",
            f"""SELECT p.proname,pg_get_function_identity_arguments(p.oid),(SELECT rolname FROM pg_roles WHERE oid=p.proowner),{acl("COALESCE(p.proacl,acldefault('f',p.proowner))")},pg_get_functiondef(p.oid) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='vault_metadata' ORDER BY 1,2""",
            None,
        ),
        (
            "triggers",
            "SELECT c.relname,t.tgname,pg_get_triggerdef(t.oid,true) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='vault_metadata' AND NOT t.tgisinternal ORDER BY 1,2",
            None,
        ),
        (
            "defaults",
            f"""SELECT (SELECT rolname FROM pg_roles WHERE oid=d.defaclrole),COALESCE(n.nspname,''),d.defaclobjtype,{acl("d.defaclacl")} FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace WHERE d.defaclrole=(SELECT oid FROM pg_roles WHERE rolname=%s) AND (d.defaclnamespace=0 OR n.nspname='vault_metadata') ORDER BY 1,2,3""",
            (owner,),
        ),
    )
    observed = []
    for kind, query, parameters in queries:
        rows = conn.execute(
            "/* standalone:structure:" + kind + " */ " + query, parameters
        ).fetchall()
        acl_index = {"schema": 2, "relations": 3, "functions": 3, "defaults": 3}.get(
            kind
        )
        if acl_index is not None:
            for row in rows:
                owner_index = 1 if kind == "schema" else 0 if kind == "defaults" else 2
                if not isinstance(row[owner_index], str) or not row[owner_index]:
                    raise ValueError("Owner PostgreSQL non résolu")
                for grant in row[acl_index]:
                    if (
                        len(grant) != 5
                        or not isinstance(grant[0], str)
                        or not grant[0]
                        or grant[1] not in ("PUBLIC", "ROLE")
                        or not isinstance(grant[2], str)
                        or (grant[1] == "ROLE" and not grant[2])
                        or (grant[1] == "PUBLIC" and grant[2] != "")
                        or not isinstance(grant[3], str)
                        or not grant[3]
                        or type(grant[4]) is not bool
                    ):
                        raise ValueError("Identité ou ACL PostgreSQL non résolue")
        observed.append([kind, [list(row) for row in rows]])
    return hashlib.sha256(canonical(observed)).hexdigest()


def archive_hash(path):
    private_directory(Path(path).parent)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        import stat

        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_mode & 0o077
            or info.st_uid != os.geteuid()
        ):
            raise ValueError("Archive privée requise")
        checksum = hashlib.sha256()
        size = 0
        while chunk := stream.read(1048576):
            checksum.update(chunk)
            size += len(chunk)
    if not size:
        raise ValueError("Archive vide")
    return {"sha256": checksum.hexdigest(), "size": size}


def pg_tools(config, values):
    """Même majeure pour ce transfert même-instance ; auth/KV déjà établies."""
    with control(config, values) as conn:
        server_major = (
            int(conn.execute("SHOW server_version_num").fetchone()[0]) // 10000
        )
    paths = {}
    versions: dict[str, int | str] = {"server_major": server_major}
    environment = {"PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C"}
    for kind, executable in (("dump", "pg_dump"), ("restore", "pg_restore")):
        path = shutil.which(executable, path=environment["PATH"])
        if path is None:
            raise ValueError("Clients PostgreSQL requis avant opération")
        path = os.path.abspath(path)
        try:
            result = subprocess.run(
                [path, "--version"],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            raise ValueError("Version client PostgreSQL non confirmée") from None
        match = re.fullmatch(
            re.escape(executable) + r" \(PostgreSQL\) ([0-9]+\.[0-9]+)(?: [^\n]*)?\n?",
            result.stdout,
        )
        if result.returncode or not match:
            raise ValueError("Version client PostgreSQL non confirmée")
        major = int(match[1].split(".")[0])
        if major != server_major:
            raise ValueError("Clients PostgreSQL incompatibles avec le serveur")
        paths[kind] = path
        versions[kind + "_major"] = major
        versions[kind + "_version"] = match[1]
    return {**paths, "versions": versions}


def check_restore_archive(journal, archive, tools):
    dumped = journal.confirmed("dump-frozen")
    if archive_hash(archive) != dumped["archive"]:
        raise ValueError("Archive altérée/non admissible")
    versions = dumped.get("tool_versions")
    if not isinstance(versions, dict) or set(versions) != set(tools["versions"]):
        raise ValueError("Versions productrices de l'archive absentes")
    major = tools["versions"]["server_major"]
    if any(
        type(versions[k]) is not int or versions[k] != major
        for k in ("server_major", "dump_major", "restore_major")
    ):
        raise ValueError("Majeure productrice de l'archive incompatible")
    for kind in ("dump", "restore"):
        version = versions[kind + "_version"]
        if not isinstance(version, str) or not re.fullmatch(
            str(major) + r"\.[0-9]+", version
        ):
            raise ValueError("Version productrice de l'archive invalide")
    try:
        result = subprocess.run(
            [tools["restore"], "--list", str(archive)],
            env={"PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C"},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise ValueError("Lisibilité de l'archive non confirmée") from None
    if result.returncode:
        raise ValueError("Archive illisible par le client contrôlé")


def pg_tool(config, values, database, action, archive, tools):
    kind = "backup" if action == "dump" else "restore"
    value = values[kind]
    # Aucun héritage PGSERVICE/PGOPTIONS/PGPASSFILE/DSN ou secrets S3.
    environment = {
        "PATH": os.environ.get("PATH", os.defpath),
        "PGHOST": value["host"],
        "PGPORT": value["port"],
        "PGDATABASE": database,
        "PGUSER": value["user"],
        "PGPASSWORD": value["password"],
        "PGSSLMODE": "verify-full",
        "PGSSLROOTCERT": config["pg_ca_file"],
        "PGCONNECT_TIMEOUT": "3",
    }
    if action == "dump":
        private_directory(Path(archive).parent)
        descriptor = os.open(
            archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "wb") as output:
            result = subprocess.run(
                [
                    tools["dump"],
                    "--format=custom",
                    "--no-password",
                    "--role=" + config["roles"]["owner"],
                ],
                env=environment,
                stdout=output,
                stderr=subprocess.DEVNULL,
                timeout=120,
                check=False,
            )
            output.flush()
            os.fsync(output.fileno())
    else:
        result = subprocess.run(
            [
                tools["restore"],
                "--dbname=" + database,
                "--single-transaction",
                "--exit-on-error",
                "--no-password",
                "--role=" + config["roles"]["owner"],
                str(archive),
            ],
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=120,
            check=False,
        )
    if result.returncode:
        raise ValueError("Commande PG non confirmée")
    return archive_hash(archive)


def install(config, journal, native, credentials_dir):
    mode(config, "install")
    directory = Path(credentials_dir)
    values = {
        kind: json.loads(private_read(directory / (kind + ".json")))
        for kind in ("infra", *KINDS)
    }
    domain = config["domains"][config["context"]]
    validate_credentials(values, domain["database"], config["roles"])
    if config["context"] == "source_fresh":
        journal.run("install-mount", lambda: product(config, "vault"))
    else:
        # Tous les chemins restent dans M. Aucune création de mount en Copy/Return.
        source = read_values(native, config, source_context(config))
        for kind in KINDS:
            if {k: v for k, v in values[kind].items() if k != "dbname"} != {
                k: v for k, v in source[kind].items() if k != "dbname"
            }:
                raise ValueError(
                    "Rôles/mots de passe Source/Copy doivent être identiques"
                )
        if values["infra"] != source["infra"]:
            raise ValueError("Infra changée")
    journal.run(
        "install-connections",
        lambda: product(
            config, "connections", {k: values[k] for k in ("app", "provisioner")}
        ),
    )
    journal.run(
        "install-maintenance",
        lambda: product(config, "audit-maintenance-connection", values["maintenance"]),
    )
    for kind in ("infra", "backup", "restore"):
        path = config["infra_path"] if kind == "infra" else domain["paths"][kind]
        journal.run(
            "install-native-" + kind,
            lambda k=kind, p=path: native.put_new(p, values[k]) or {"confirmed": True},
        )
    # Relire toutes les autorités KV avant tout connect, jamais les fichiers d'entrée.
    read_values(native, config)
    return {
        "status": "ok",
        "next": "provision-fresh"
        if config["context"] == "source_fresh"
        else "restart-private-restore",
    }


def provision_fresh(config, journal, native):
    if config["context"] != "source_fresh":
        raise ValueError("Aucun DDL/seed en Copy/Return")
    mode(config, "install")
    for step in (
        "install-connections",
        "install-maintenance",
        "install-native-infra",
        "install-native-backup",
        "install-native-restore",
    ):
        journal.confirmed(step)
    values = read_values(native, config)
    options = SimpleNamespace(
        database=config["domains"]["source_fresh"]["database"],
        pg_ca_file=config["pg_ca_file"],
        **{k + "_role": v for k, v in config["roles"].items()},
    )
    token = private_read(config["initial_admin_file"]).decode().strip()
    if not token:
        raise ValueError("Bearer initial vide")
    body = {
        "token_hash": hashlib.sha256(token.encode()).hexdigest(),
        "client_name": config["client_name"],
        "mutation_id": str(uuid.uuid4()),
    }
    # Sauvegarder l'intention publique de seed, sans bearer, pour la route de constat.
    journal.write("seed-witness", body)
    journal.run("provision", lambda: provision(options, values))
    journal.run("schema-init", lambda: product(config, "schema-init"))
    journal.run("initial-admin", lambda: product(config, "initial-admin", body))
    return {"status": "ok", "next": "verify then restart disabled"}


def copy_action(
    config, journal, native, action, archive=None, decision=None, tools=None
):
    if config["context"] == "source_fresh":
        raise ValueError("Contexte Copy/Return requis")
    mode(config, "restore")
    values, source = (
        read_values(native, config),
        read_values(native, config, source_context(config)),
    )
    roles, infra = config["roles"], values["infra"]["user"]
    target_db = config["domains"][config["context"]]["database"]
    source_db = config["domains"][source_context(config)]["database"]
    if values["infra"] != source["infra"]:
        raise ValueError("Instance/identité infra changée")
    for kind in KINDS:
        if {k: v for k, v in values[kind].items() if k != "dbname"} != {
            k: v for k, v in source[kind].items() if k != "dbname"
        }:
            raise ValueError("Identités de restauration modifiées")
    with control(config, values) as conn:
        if action == "create-copy":
            if conn.execute(
                "SELECT 1 FROM pg_database WHERE datname=%s", (target_db,)
            ).fetchone():
                raise ValueError("Collision Copy")
            oids = domain_roles(conn, roles, infra)
            source_observed = db_observation(conn, source_db)
            if source_observed["owner"] != oids[roles["owner"]]:
                raise ValueError("Source hors domaine")
            create_database(conn, target_db, roles, infra, private=True)
            with connection(values["infra"], config["pg_ca_file"], target_db) as target:  # noqa: SIM117 - role reset before connection close
                with as_role(target, roles["owner"]):
                    target.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
                    target.execute(
                        "ALTER DEFAULT PRIVILEGES REVOKE ALL ON TABLES FROM PUBLIC"
                    )
            return {
                "copy": db_observation(conn, target_db),
                "roles": oids,
                "empty": fingerprint(config, values, target_db, empty=True),
            }
        created = journal.confirmed("create-copy")
        current = db_observation(conn, target_db)
        if (
            current["oid"] != created["copy"]["oid"]
            or domain_roles(conn, roles, infra) != created["roles"]
        ):
            raise ValueError("OID/identité Copy changée")
        if action == "freeze-source":
            before, closed = freeze(conn, source_db, roles, infra)
            return {
                "before": before,
                "frozen": closed,
                "content": fingerprint(config, source, source_db),
            }
        frozen = journal.confirmed("freeze-source")
        if db_observation(conn, source_db)["oid"] != frozen["frozen"]["oid"]:
            raise ValueError("OID Source changé après gel")
        if action == "dump-frozen":
            assert_closed(conn, source_db, roles, infra, sealed=False)
            before = fingerprint(config, source, source_db)
            if before != frozen["content"]:
                raise ValueError("Source a changé depuis le gel")
            result = pg_tool(config, source, source_db, "dump", archive, tools)
            if fingerprint(config, source, source_db) != before:
                raise ValueError("Source a changé pendant le dump")
            assert_closed(conn, source_db, roles, infra, sealed=False)
            return {
                "archive": result,
                # Sibling: archive_hash equality must remain exact.
                "tool_versions": tools["versions"],
                "source_oid": frozen["frozen"]["oid"],
                "content": before,
            }
        dumped = journal.confirmed("dump-frozen")
        if action == "seal-source":
            if fingerprint(config, source, source_db) != dumped["content"]:
                raise ValueError("Source modifiée après dump")
            _, closed = freeze(conn, source_db, roles, infra, sealed=True)
            return {"sealed": closed}
        sealed = journal.confirmed("seal-source")
        observed = assert_closed(conn, source_db, roles, infra, sealed=True)
        if observed != sealed["sealed"]:
            raise ValueError("Source scellée modifiée")
        if action == "restore-frozen":
            if archive_hash(archive) != dumped["archive"]:
                raise ValueError("Archive altérée/non admissible")
            if fingerprint(config, values, target_db, empty=True) != created["empty"]:
                raise ValueError("Copy non vierge")
            if db_observation(conn, target_db) != created["copy"]:
                raise ValueError("ACL/sessions Copy changées")
            pg_tool(config, values, target_db, "restore", archive, tools)
            content = fingerprint(config, values, target_db)
            if content != dumped["content"]:
                raise ValueError("Restore différent de Source")
            return {"content": content, "copy": db_observation(conn, target_db)}
        if action == "open-copy-private":
            journal.confirmed("record-copy-mutation")
            journal.confirmed("verify-copy")
            if db_observation(conn, target_db) != created["copy"]:
                raise ValueError("Copy ouverte/modifiée avant décision")
            with as_role(conn, roles["owner"]):
                for kind in ("app", "provisioner", "maintenance"):
                    conn.execute(
                        sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                            sql.Identifier(target_db), sql.Identifier(roles[kind])
                        )
                    )
            after = db_observation(conn, target_db)
            oids = created["roles"]
            expected = sorted(
                created["copy"]["acl"]
                + [
                    [after["owner"], oids[roles[kind]], "CONNECT", False]
                    for kind in ("app", "provisioner", "maintenance")
                ]
            )
            if after["acl"] != expected or after["sessions"]:
                raise ValueError("Ouverture privée non confirmée")
            return {
                "copy": after,
                "old_source_forbidden": True,
                "next": "private tests; restart disabled and verify-disabled before exposure",
            }
        if action in {"verify-copy", "decide-copy", "reopen-source-zero"}:
            baseline = zero_copy(config, journal, conn, values, created, dumped)
            if action == "verify-copy":
                return baseline
            if decision == "private-tests":
                raise ValueError(
                    "Marquer record-copy-mutation AVANT toute ouverture/appel"
                )
            if action == "decide-copy":
                return {"decision": "rollback-zero", "proof": baseline}
            # Action NOMMÉE de réouverture de l'ancienne Source, zéro mutation prouvé.
            journal.confirmed("decide-copy")
            if config["context"] == "return":
                raise ValueError("Ancienne Source interdite après mutation Copy")
            _, copy_closed = freeze(conn, target_db, roles, infra, sealed=True)
            before = frozen["before"]
            allowed = role_oids(conn, [*roles.values(), infra])
            if any(
                grantor != before["owner"]
                or grantee not in allowed.values()
                or grantable
                or privilege not in {"CONNECT", "CREATE", "TEMPORARY"}
                for grantor, grantee, privilege, grantable in before["acl"]
            ):
                raise ValueError("ACL Source initiale inadmissible")
            with as_role(conn, roles["owner"]):
                conn.execute(
                    sql.SQL("ALTER DATABASE {} ALLOW_CONNECTIONS true").format(
                        sql.Identifier(source_db)
                    )
                )
                for grantor, grantee, privilege, grantable in before["acl"]:
                    if privilege == "CONNECT" and grantee != before["owner"]:
                        role = next(
                            name for name, oid in allowed.items() if oid == grantee
                        )
                        conn.execute(
                            sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                                sql.Identifier(source_db), sql.Identifier(role)
                            )
                        )
            after = db_observation(conn, source_db)
            if after != before:
                raise ValueError("Réouverture Source non confirmée")
            return {
                "source": after,
                "copy": copy_closed,
                "next": "restart Source disabled, same current Bao",
            }
    raise ValueError("Action inconnue")


def zero_copy(config, journal, conn, values, created, dumped):
    """Aucune absence de fichier seule ne prouve zéro mutation."""
    if journal.exists("record-copy-mutation.intent"):
        raise ValueError(
            "Copy dirty/UNKNOWN : ancienne Source interdite ; transfert frais vers Return"
        )
    # Une seule intention UNKNOWN admissible : restore, avec état réel contrôlé.
    for path in journal.directory.glob("*.intent.json"):
        name = path.name.removesuffix(".intent.json")
        if name not in {
            "restore-frozen",
            "verify-copy",
            "decide-copy",
            "reopen-source-zero",
        } and not journal.exists(name + ".ack"):
            raise ValueError("Intention UNKNOWN")
    database = config["domains"][config["context"]]["database"]
    observed = db_observation(conn, database)
    if observed != created["copy"] or observed["sessions"]:
        raise ValueError("Copy ACL/exposition/session non fermée")
    content = fingerprint(config, values, database)
    if journal.exists("restore-frozen.ack"):
        expected = journal.confirmed("restore-frozen")["content"]
    else:
        # Échec restore : transaction totalement annulée OU résultat complet stable.
        # UNKNOWN partiel, sessions, dirty ou ACL changées : refus, jamais supposition.
        if not journal.exists("restore-frozen.intent"):
            raise ValueError("Restore non entrepris")
        expected = content if content in (created["empty"], dumped["content"]) else None
    if expected is None or content != expected:
        raise ValueError("Zéro mutation Copy non prouvé")
    if fingerprint(config, values, database) != content:
        raise ValueError("Copy instable")
    return {
        "zero_business_mutation": True,
        "content": content,
        "copy": observed,
        "restore_ack": journal.exists("restore-frozen.ack"),
    }


def prepare_files(config):
    """Générer un jeu TLS neuf ; jamais remplacer une clé/CA existante."""
    import ipaddress
    from datetime import datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    tls = config["tls"]
    directory = Path(tls["directory"])
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    server = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "standalone PG private CA")]
    )
    now = datetime.now(UTC)
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .sign(key, hashes.SHA256())
    )
    san: x509.GeneralName
    try:
        san = x509.IPAddress(ipaddress.ip_address(tls["host"]))
    except ValueError:
        san = x509.DNSName(tls["host"])
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, tls["host"])]))
        .issuer_name(name)
        .public_key(server.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([san]), False)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), False
        )
        .sign(key, hashes.SHA256())
    )
    for filename, value in (("ca.key", key), ("server.key", server)):
        private_write(
            directory / filename,
            value.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
    private_write(directory / "ca.crt", ca.public_bytes(serialization.Encoding.PEM))
    private_write(
        directory / "server.crt", cert.public_bytes(serialization.Encoding.PEM)
    )
    for filename in ("server.key", "server.crt"):
        os.chown(directory / filename, tls["pg_uid"], tls["pg_gid"])
    return {
        "status": "ok",
        "next": "install read-only CA for app UID; server key 0600 for measured PG UID",
    }


def prepare_engine(config, native, directory):
    if config["context"] != "source_fresh" or config["topology"] != "local":
        raise ValueError("Moteur local neuf seulement")
    values = read_values(native, config)
    infra = values["infra"]
    from standalone_pg_sql import identifier

    identifier(infra["user"])
    if infra["dbname"] != "postgres":
        raise ValueError("Base de contrôle locale postgres requise")
    path = Path(directory)
    path.mkdir(mode=0o700, parents=False, exist_ok=False)
    statement = (
        sql.SQL(
            "CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER CREATEDB CREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD {};\nGRANT CONNECT ON DATABASE postgres TO {};\n"
        )
        .format(
            sql.Identifier(infra["user"]),
            sql.Literal(infra["password"]),
            sql.Identifier(infra["user"]),
        )
        .as_string()
    )
    private_write(path / "init.sql", statement.encode())
    private_write(
        path / "pg_hba.conf",
        (
            "# Unix bootstrap privé dans le conteneur moteur uniquement.\n"
            "local all all trust\n"
            "hostnossl all all 0.0.0.0/0 reject\n"
            "hostnossl all all ::/0 reject\n"
            "hostssl all all 0.0.0.0/0 scram-sha-256\n"
            "hostssl all all ::/0 scram-sha-256\n"
        ).encode(),
    )
    private_write(path / "engine.password", secrets.token_urlsafe(48).encode())
    for filename in ("init.sql", "engine.password", "pg_hba.conf"):
        os.chown(path / filename, config["tls"]["pg_uid"], config["tls"]["pg_gid"])
    return {
        "status": "ok",
        "next": "start exactly one local PG with prepared private files",
    }


def verify_disabled(config):
    current = settings(config)
    if current.metadata_operator_mode != "disabled":
        raise ValueError("Settings disabled requises")
    key = private_read(config["bootstrap_file"]).decode().strip()
    with httpx.Client(
        verify=config["product_ca_file"] or True, timeout=10, follow_redirects=False
    ) as client:
        response = client.get(
            config["product_url"].rstrip("/") + "/admin/api/metadata-operator/status",
            headers={"Authorization": "Bearer " + key},
        )
        if response.status_code != 403 or response.json() != {
            "status": "error",
            "message": "Action opérateur refusée",
        }:
            raise ValueError("Fermeture opérateur non confirmée")
        response = client.get(config["product_url"].rstrip("/") + "/health")
        if response.status_code != 200:
            raise ValueError("Readiness non confirmée")
    return {"status": "ok", "next": "qualify public contracts before exposure"}


def execute(options):
    config = load_config(options.config)
    if options.action == "prepare-files":
        return prepare_files(config)
    journal = Journal(config)
    settings(
        config,
        source_context(config) if options.action == "reopen-source-zero" else None,
    )
    native = Native(config)
    try:
        if options.action == "status":
            return product(config, "status")
        if options.action == "install":
            if not options.credentials_dir:
                raise ValueError("Répertoire credentials privés requis")
            return install(config, journal, native, options.credentials_dir)
        if options.action == "prepare-engine":
            if not options.engine_dir:
                raise ValueError("Répertoire moteur privé requis")
            return journal.run(
                options.action,
                lambda: prepare_engine(config, native, options.engine_dir),
            )
        if options.action == "provision-fresh":
            return provision_fresh(config, journal, native)
        if options.action == "verify":
            read_values(native, config)
            return product(config, "verify-connections")
        if options.action == "verify-disabled":
            read_values(native, config)
            return verify_disabled(config)
        if options.action == "record-copy-mutation":
            if config["context"] == "source_fresh":
                raise ValueError("Copy/Return requis")
            journal.confirmed("verify-copy")
            restored = journal.confirmed("restore-frozen")
            if restored["content"] != journal.confirmed("dump-frozen")["content"]:
                raise ValueError("Restauration complète non confirmée")
            return journal.run(
                options.action, lambda: {"dirty": True, "old_source_forbidden": True}
            )
        if options.action in {"dump-frozen", "restore-frozen"} and not options.archive:
            raise ValueError("Archive explicite requise")
        if options.action == "decide-copy" and options.decision != "rollback-zero":
            raise ValueError("Seule décision sans mutation : rollback-zero")
        tools = None
        if options.action in {
            "create-copy",
            "freeze-source",
            "dump-frozen",
            "restore-frozen",
        }:
            if config["context"] == "source_fresh":
                raise ValueError("Contexte Copy/Return requis")
            tools = pg_tools(config, read_values(native, config))
            if options.action == "restore-frozen":
                check_restore_archive(journal, options.archive, tools)
        return journal.run(
            options.action,
            lambda: copy_action(
                config,
                journal,
                native,
                options.action,
                options.archive,
                options.decision,
                tools,
            ),
        )
    finally:
        native.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=(
            "prepare-files",
            "status",
            "install",
            "prepare-engine",
            "provision-fresh",
            "verify",
            "verify-disabled",
            "create-copy",
            "freeze-source",
            "dump-frozen",
            "seal-source",
            "restore-frozen",
            "verify-copy",
            "record-copy-mutation",
            "open-copy-private",
            "decide-copy",
            "reopen-source-zero",
        ),
    )
    parser.add_argument("--config", required=True)
    parser.add_argument("--credentials-dir")
    parser.add_argument("--archive")
    parser.add_argument("--engine-dir")
    parser.add_argument("--decision", choices=("rollback-zero",))
    options = parser.parse_args()
    try:
        result = execute(options)
        # Ne pas publier les carriers, ACL/OID/digests privés ou réponses natives.
        public = {
            "status": "ok",
            "action": options.action,
            "next": result.get("next", "inspect private carriers"),
        }
        if options.action == "status":
            public.update(
                {
                    key: result.get(key)
                    for key in ("mode", "openbao_ready", "metadata_readiness")
                }
            )
        if options.action == "verify":
            public["metadata_readiness"] = "not_probed"
        print(json.dumps(public))
        return 0
    except Exception:  # noqa: BLE001 - boundary redacts credentials/backend exceptions
        print(
            json.dumps(
                {
                    "status": "unknown",
                    "action": options.action,
                    "message": "Arrêt ; conserver les carriers, constater sans rejouer",
                }
            )
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
