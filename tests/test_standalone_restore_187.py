"""Finite restore CLI with SQL/HTTP/process transports replaced, no helpers replaced."""

import copy
import json
import re
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from tests.test_standalone_acl_187 import Catalog
from tests.test_standalone_operator_187 import private, synthetic_config


class Cluster:
    def __init__(self, roles):
        source = Catalog()
        source.roles = roles
        source.oids = {
            name: i + 16384 for i, name in enumerate([*roles.values(), "infra_a"])
        }
        source.owner = source.oids[roles["owner"]]
        source.acl = {
            (source.owner, oid, "CONNECT", False) for oid in source.oids.values()
        }
        self.roles, self.oids = roles, source.oids
        self.databases = {"source_a": source}
        self.data = {
            "source_a": {
                "schema_version": ['{"version":2}'],
                "tokens": ["revoked-current"],
                "audit_events": ['{"seq":1,"outcome":"confirmed"}'],
            }
        }
        self.schema_acl = {"source_a": "owner-private/app-usage"}
        self.sequences = {
            "source_a": {
                "audit_events_seq_seq": {
                    "last_value": 1,
                    "log_cnt": 32,
                    "is_called": True,
                }
            }
        }
        self.identity_database = None
        self.trace = []
        self.neighbor = {"database": "neighbor_b", "contents": "untouched"}

    def connect(self, **kw):
        assert kw["sslmode"] == "verify-full" and kw["connect_timeout"] == 3
        assert kw["user"] in self.oids
        self.trace.append(("connect", kw["dbname"], kw["user"]))
        return Connection(self, kw["dbname"], kw["user"])


class Connection:
    def __init__(self, cluster, database, user="infra_a"):
        self.cluster, self.database, self.rows = cluster, database, []
        self.login_user = self.current_user = user

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def transaction(self):
        return nullcontext()

    def execute(self, statement, params=None):
        cluster = self.cluster
        text = statement if isinstance(statement, str) else statement.as_string()
        self.rows = []
        cluster.trace.append((text, params))
        if text.startswith("CREATE DATABASE"):
            names = re.findall('"([^"]+)"', text)
            name = names[0]
            assert name not in cluster.databases and names[1] == cluster.roles["owner"]
            assert text.endswith("TEMPLATE template0")
            model = copy.deepcopy(cluster.databases["source_a"])
            model.acl = {
                (model.owner, model.owner, "CONNECT", False),
                (model.owner, 0, "CONNECT", False),
            }
            model.sessions, model.allow = [], True
            cluster.databases[name], cluster.data[name] = model, {}
            cluster.schema_acl[name] = None
            cluster.sequences[name] = {}
        elif text.startswith("SELECT 1 FROM pg_database"):
            self.rows = [(1,)] if params[0] in cluster.databases else []
        elif text.startswith("SET ROLE"):
            self.current_user = re.findall('"([^"]+)"', text)[0]
        elif text == "RESET ROLE":
            self.current_user = self.login_user
        elif text.startswith("SELECT current_database(),session_user,current_user"):
            self.rows = [
                (
                    cluster.identity_database or self.database,
                    self.login_user,
                    self.current_user,
                )
            ]
        elif text.startswith(
            ("REVOKE ALL ON SCHEMA", "ALTER DEFAULT PRIVILEGES", "SET TRANSACTION")
        ):
            pass
        elif text.startswith("/* standalone:structure:"):
            kind = text.split("*/")[0].split(":")[-1].strip()
            if kind == "schema" and cluster.schema_acl[self.database] is not None:
                self.rows = [
                    (
                        "vault_metadata",
                        cluster.roles["owner"],
                        [
                            [
                                cluster.roles["owner"],
                                "ROLE",
                                cluster.roles["app"],
                                cluster.schema_acl[self.database],
                                False,
                            ]
                        ],
                    )
                ]
            elif kind == "relations":
                self.rows = [
                    (
                        name,
                        "r",
                        cluster.roles["owner"],
                        [
                            [
                                cluster.roles["owner"],
                                "ROLE",
                                cluster.roles["app"],
                                "SELECT",
                                False,
                            ]
                        ],
                    )
                    for name in sorted(cluster.data[self.database])
                ] + [
                    (
                        name,
                        "S",
                        cluster.roles["owner"],
                        [
                            [
                                cluster.roles["owner"],
                                "ROLE",
                                cluster.roles["owner"],
                                "USAGE",
                                False,
                            ]
                        ],
                    )
                    for name in sorted(cluster.sequences[self.database])
                ]
        elif text.startswith("SELECT c.relname,c.relkind"):
            self.rows = sorted(
                [(name, "r") for name in cluster.data[self.database]]
                + [(name, "S") for name in cluster.sequences[self.database]]
            )
        elif text.startswith("SELECT to_jsonb"):
            name = re.findall('"([^"]+)"', text)[0]
            if name in cluster.sequences[self.database]:
                self.rows = [
                    (
                        json.dumps(
                            cluster.sequences[self.database][name], sort_keys=True
                        ),
                    )
                ]
            else:
                self.rows = [
                    (row,) for row in sorted(cluster.data[self.database][name])
                ]
        elif text.startswith("SELECT last_value,is_called"):
            name = re.findall('"([^"]+)"', text)[0]
            sequence = cluster.sequences[self.database][name]
            self.rows = [(sequence["last_value"], sequence["is_called"])]
        elif text == "SELECT version FROM vault_metadata.schema_version":
            self.rows = [
                (json.loads(row)["version"],)
                for row in cluster.data[self.database]["schema_version"]
            ]
        else:
            target = next(
                (
                    v
                    for v in params or ()
                    if isinstance(v, str) and v in cluster.databases
                ),
                self.database,
            )
            quoted = re.findall('"([^"]+)"', text)
            if quoted and quoted[0] in cluster.databases:
                target = quoted[0]
            model = cluster.databases.get(target, cluster.databases["source_a"])
            model.user = self.current_user
            model.login_user = self.login_user
            if text.startswith("GRANT CONNECT"):
                assert self.current_user == cluster.roles["owner"]
                model.acl.add((model.owner, cluster.oids[quoted[1]], "CONNECT", False))
            elif text.startswith("REVOKE ALL ON DATABASE"):
                assert self.current_user == cluster.roles["owner"]
                model.acl = {a for a in model.acl if a[1] != 0}
            elif text.endswith("ALLOW_CONNECTIONS true"):
                assert self.current_user == cluster.roles["owner"]
                model.allow = True
            else:
                # Catalog handles the exact ACL/role queries and refuses unknown SQL.
                translated = text.replace('"' + target + '"', '"source_a"')
                arguments = (
                    tuple("source_a" if v == target else v for v in params)
                    if params
                    else None
                )
                model.execute(translated, arguments)
                self.rows = list(model.rows)
                if text.startswith("SELECT oid,datdba") and target != "source_a":
                    self.rows = [
                        (
                            100 * (list(cluster.databases).index(target) + 1),
                            model.owner,
                            model.allow,
                        )
                    ]
        return self

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


@pytest.mark.parametrize(
    "difference",
    [
        "cache-only",
        "last-value",
        "called",
        "audit-data",
        "schema-acl",
        "version",
        "invalid-called-type",
    ],
)
def test_sequence_restore_setval_compares_logical_state(
    tmp_path, monkeypatch, difference
):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    import psycopg
    import standalone_pg as operator

    config = synthetic_config(tmp_path)
    cluster = Cluster(config["roles"])
    cluster.databases["copy_a"] = copy.deepcopy(cluster.databases["source_a"])
    cluster.data["copy_a"] = copy.deepcopy(cluster.data["source_a"])
    cluster.schema_acl["copy_a"] = cluster.schema_acl["source_a"]
    cluster.sequences["copy_a"] = copy.deepcopy(cluster.sequences["source_a"])
    cluster.sequences["copy_a"]["audit_events_seq_seq"]["log_cnt"] = 0
    if difference == "last-value":
        cluster.sequences["copy_a"]["audit_events_seq_seq"]["last_value"] = 2
    elif difference in {"called", "invalid-called-type"}:
        cluster.sequences["copy_a"]["audit_events_seq_seq"]["is_called"] = (
            False if difference == "called" else 1
        )
    elif difference == "audit-data":
        cluster.data["copy_a"]["audit_events"] = ['{"seq":1,"outcome":"unknown"}']
    elif difference == "schema-acl":
        cluster.schema_acl["copy_a"] = "PUBLIC=USAGE"
    elif difference == "version":
        cluster.data["copy_a"]["schema_version"] = ['{"version":3}']
    monkeypatch.setattr(psycopg, "connect", cluster.connect)
    values = {
        "backup": {
            "host": "pg.example",
            "port": "5432",
            "dbname": "source_a",
            "user": config["roles"]["backup"],
            "password": "synthetic",
        }
    }
    source = operator.fingerprint(config, values, "source_a")
    if difference == "invalid-called-type":
        with pytest.raises(ValueError, match="séquence"):
            operator.fingerprint(config, values, "copy_a")
    else:
        restored = operator.fingerprint(config, values, "copy_a")
        assert (source == restored) == (difference == "cache-only")
    assert any("audit_events_seq_seq" in str(row) for row in cluster.trace)


def test_control_rejects_another_database_scope_before_mutations(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    import psycopg
    import standalone_pg as operator

    config = synthetic_config(tmp_path)
    cluster = Cluster(config["roles"])
    cluster.identity_database = "neighbor_b"
    monkeypatch.setattr(psycopg, "connect", cluster.connect)
    values = {
        "infra": {
            "host": "pg.example",
            "port": "5432",
            "dbname": "postgres",
            "user": "infra_a",
            "password": "synthetic",
        }
    }
    with pytest.raises(ValueError, match="contrôle"), operator.control(config, values):
        pytest.fail("Wrong control scope accepted")
    assert not any(
        str(row[0]).startswith(("CREATE", "ALTER", "REVOKE", "GRANT"))
        for row in cluster.trace
    )


@pytest.mark.parametrize(
    "execution,topology",
    [
        ("compose", "local"),
        ("compose", "external"),
        ("python", "local"),
        ("python", "external"),
    ],
)
@pytest.mark.parametrize(
    "branch",
    [
        "zero",
        "dirty",
        "failed-zero",
        "failed-partial",
        "bad-create-copy",
        "bad-freeze-source",
        "bad-dump-frozen",
        "bad-restore-frozen",
        "missing-tool",
        "version-timeout",
        "mixed-tools",
        "invalid-version",
        "corrupt-archive",
        "unreadable-archive",
        "foreign-producer",
        "missing-producer",
    ],
)
def test_freeze_dump_seal_restore_zero_and_dirty_guard(
    tmp_path, monkeypatch, execution, topology, branch
):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    import psycopg
    import standalone_pg as operator
    from standalone_pg_files import Journal

    config = synthetic_config(tmp_path)
    config.update(execution=execution, topology=topology)
    # Catalog's fixed names keep the neighboring database outside the target tuple.
    config["roles"] = Catalog().roles
    config["domains"]["source_fresh"]["database"] = "source_a"
    config["domains"]["copy"]["database"] = "copy_a"
    config["domains"]["return"]["database"] = "return_a"
    private(tmp_path / "bootstrap", "synthetic-bootstrap")
    private(tmp_path / "token", "synthetic-native")
    domain = config["domains"]["copy"]
    settings = {
        "METADATA_BACKEND": "postgres",
        "METADATA_INSTANCE_ID": config["instance"],
        "METADATA_PG_VAULT_ID": config["mount"],
        "METADATA_PG_DATABASE": domain["database"],
        "METADATA_PG_SECRET_PATH": domain["paths"]["app"],
        "METADATA_PG_PROVISIONER_SECRET_PATH": domain["paths"]["provisioner"],
        "AUDIT_MAINTENANCE_SECRET_PATH": domain["paths"]["maintenance"],
        "METADATA_PG_CA_FILE": config["pg_ca_file"],
        "ADMIN_BOOTSTRAP_KEY": "synthetic-bootstrap",
        "METADATA_OPERATOR_MODE": "restore",
    }
    settings.update(
        {
            (
                "AUDIT_MAINTENANCE_ROLE"
                if k == "maintenance"
                else "METADATA_PG_" + k.upper() + "_ROLE"
            ): v
            for k, v in config["roles"].items()
            if k in {"owner", "app", "provisioner", "maintenance"}
        }
    )
    private(tmp_path / ".env", "\n".join(k + "=" + v for k, v in settings.items()))
    private(tmp_path / "operator.json", json.dumps(config))
    monkeypatch.setattr("os.environ", {})
    monkeypatch.chdir(tmp_path)
    cluster = Cluster(config["roles"])
    stored = {
        config["infra_path"]: {
            "host": "pg.example",
            "port": "5432",
            "dbname": "postgres",
            "user": "infra_a",
            "password": "synthetic",
        }
    }
    for domain in config["domains"].values():
        for kind, path in domain["paths"].items():
            stored[path] = {
                "host": "pg.example",
                "port": "5432",
                "dbname": domain["database"],
                "user": config["roles"][kind],
                "password": "synthetic",
            }
    native = SimpleNamespace(read=lambda path: copy.deepcopy(stored[path]))
    monkeypatch.setattr(psycopg, "connect", cluster.connect)
    original_http = httpx.Client

    def status(request):
        if request.url.path == "/v1/auth/token/lookup-self":
            cluster.trace.append(("native-auth",))
            return httpx.Response(200, json={"data": {}})
        if request.url.path.startswith("/v1/technical_a/data/"):
            return httpx.Response(
                200,
                json={
                    "data": {
                        "data": stored[
                            request.url.path.removeprefix("/v1/technical_a/data/")
                        ]
                    }
                },
            )
        assert request.url.path == "/admin/api/metadata-operator/status"
        return httpx.Response(
            200, json={"status": "ok", "mode": "restore", "openbao_ready": True}
        )

    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **kw: original_http(transport=httpx.MockTransport(status), **kw),
    )

    current_action = [None]
    monkeypatch.setattr(
        "shutil.which",
        lambda name, **kw: (
            None
            if branch == "missing-tool" and name == "pg_restore"
            else "/tools/" + name
        ),
    )

    def process(argv, **kw):
        tool = Path(argv[0]).name
        assert argv[0] == "/tools/" + tool
        if "--version" in argv:
            assert set(kw["env"]) <= {"PATH", "LC_ALL"}
            assert Path(argv[0]).is_absolute()
            if branch == "version-timeout":
                import subprocess

                raise subprocess.TimeoutExpired(argv, 5)
            major = (
                17
                if branch == "bad-" + str(current_action[0])
                or (branch == "mixed-tools" and tool == "pg_restore")
                else 16
            )
            output = (
                "unparseable"
                if branch == "invalid-version"
                else f"{tool} (PostgreSQL) {major}.{'15' if tool == 'pg_dump' else '14'} (Debian)\n"
            )
            return SimpleNamespace(returncode=0, stdout=output)
        if "--list" in argv:
            assert set(kw["env"]) <= {"PATH", "LC_ALL"}
            assert "--dbname" not in " ".join(argv)
            return SimpleNamespace(returncode=int(branch == "unreadable-archive"))
        assert kw["env"]["PGPASSWORD"] == "synthetic"
        assert kw["env"]["PGSSLMODE"] == "verify-full"
        assert "--role=a_owner" in argv
        assert "AWS_SECRET_ACCESS_KEY" not in kw["env"]
        database = kw["env"]["PGDATABASE"]
        origin = config["domains"][operator.source_context(config)]["database"]
        if tool == "pg_dump":
            assert cluster.databases[origin].allow
            assert not any(
                a[1] == cluster.oids["a_app"] for a in cluster.databases[origin].acl
            )
            kw["stdout"].write(
                json.dumps(
                    {
                        "data": cluster.data[database],
                        "schema_acl": cluster.schema_acl[database],
                        "sequences": cluster.sequences[database],
                    }
                ).encode()
            )
            # Model a cache/checkpoint change between the before/after stable reads.
            # No last_value/is_called, audit row, version or ACL changes.
            for sequence in cluster.sequences[database].values():
                sequence["log_cnt"] = 0
        else:
            assert not cluster.databases[origin].allow
            assert "--single-transaction" in argv and "--exit-on-error" in argv
            if branch == "failed-zero":
                raise TimeoutError(
                    "No ACK; strict actual-empty predicates must still be observed"
                )
            restored = json.loads(Path(argv[-1]).read_bytes())
            cluster.data[database], cluster.schema_acl[database] = (
                restored["data"],
                restored["schema_acl"],
            )
            cluster.sequences[database] = {
                name: {**value, "log_cnt": 0}
                for name, value in restored["sequences"].items()
            }
            if branch == "failed-partial":
                cluster.sequences[database]["audit_events_seq_seq"]["last_value"] += 1
                cluster.data[database]["audit_events"] += [
                    '{"seq":2,"outcome":"unknown"}'
                ]
                raise TimeoutError("Unknown restore with actual divergence")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(operator.subprocess, "run", process)
    journal = Journal(config)
    archive = tmp_path / "archive.dump"

    def run(action, decision=None):
        current_action[0] = action
        return operator.execute(
            SimpleNamespace(
                config=str(tmp_path / "operator.json"),
                action=action,
                archive=str(archive),
                decision=decision,
                credentials_dir=None,
                engine_dir=None,
            )
        )

    def rejected_before_intent(action):
        state = copy.deepcopy((cluster.data, cluster.schema_acl, cluster.sequences))
        databases = {
            name: (db.allow, set(db.acl)) for name, db in cluster.databases.items()
        }
        with pytest.raises(ValueError):
            run(action)
        assert not journal.exists(action + ".intent")
        assert state == (cluster.data, cluster.schema_acl, cluster.sequences)
        assert databases == {
            name: (db.allow, set(db.acl)) for name, db in cluster.databases.items()
        }
        assert (
            next(
                row[0] for row in cluster.trace if row[0] in {"connect", "native-auth"}
            )
            == "native-auth"
        )
        from mcp_vault.config import get_settings

        get_settings.cache_clear()

    if branch in {
        "bad-create-copy",
        "missing-tool",
        "version-timeout",
        "mixed-tools",
        "invalid-version",
    }:
        rejected_before_intent("create-copy")
        return
    run("create-copy")
    # Impossible to dump before confirmed SourceFrozen.
    with pytest.raises(FileNotFoundError):
        operator.copy_action(config, journal, native, "dump-frozen", str(archive))
    if branch == "bad-freeze-source":
        rejected_before_intent("freeze-source")
        return
    run("freeze-source")
    if branch == "bad-dump-frozen":
        rejected_before_intent("dump-frozen")
        assert not archive.exists()
        return
    run("dump-frozen")
    dumped = journal.confirmed("dump-frozen")
    assert set(dumped["archive"]) == {"sha256", "size"}
    run("seal-source")
    if branch == "corrupt-archive":
        archive.write_bytes(b"corrupt")
    if branch in {"foreign-producer", "missing-producer"}:
        if branch == "foreign-producer":
            dumped["tool_versions"]["dump_major"] = 17
        else:
            dumped.pop("tool_versions", None)
        private(
            Path(config["carrier_dir"]) / "dump-frozen.ack.json", json.dumps(dumped)
        )
    if branch in {
        "bad-restore-frozen",
        "corrupt-archive",
        "unreadable-archive",
        "foreign-producer",
        "missing-producer",
    }:
        rejected_before_intent("restore-frozen")
        assert not cluster.databases["source_a"].allow
        return
    # Absence de fichier restore : jamais une preuve permettant rollback-zero.
    with pytest.raises(ValueError, match="Restore non entrepris"):
        operator.copy_action(config, journal, native, "verify-copy", str(archive))
    if branch.startswith("failed-"):
        with pytest.raises(TimeoutError):
            run("restore-frozen")
    else:
        run("restore-frozen")
        original_acl = cluster.schema_acl["copy_a"]
        cluster.schema_acl["copy_a"] = "PUBLIC=USAGE"
        with pytest.raises(ValueError, match="non prouvé"):
            operator.copy_action(config, journal, native, "verify-copy", str(archive))
        cluster.schema_acl["copy_a"] = original_acl
    if branch == "failed-partial":
        with pytest.raises(ValueError, match="non prouvé"):
            run("verify-copy")
        with pytest.raises(ValueError, match="non prouvé"):
            operator.copy_action(
                config, journal, native, "decide-copy", str(archive), "rollback-zero"
            )
        assert journal.exists("restore-frozen.intent") and not journal.exists(
            "restore-frozen.ack"
        )
        assert not cluster.databases["source_a"].allow
        from mcp_vault.config import get_settings

        get_settings.cache_clear()
        return
    if branch in {"zero", "failed-zero"}:
        monkeypatch.setattr(
            "shutil.which",
            lambda *a, **kw: pytest.fail(
                "Zero proof/reopen must not require dump tools"
            ),
        )
    baseline = run("verify-copy")
    assert baseline["zero_business_mutation"]
    if branch != "failed-zero":
        assert cluster.data["copy_a"] == cluster.data["source_a"]
        assert cluster.data["copy_a"]["tokens"] == ["revoked-current"]
        assert cluster.sequences["copy_a"]["audit_events_seq_seq"]["log_cnt"] == 0
    assert cluster.neighbor == {"database": "neighbor_b", "contents": "untouched"}
    assert (
        next(row[0] for row in cluster.trace if row[0] in {"connect", "native-auth"})
        == "native-auth"
    )
    if branch in {"zero", "failed-zero"}:
        run("decide-copy", "rollback-zero")
        settings.update(
            METADATA_PG_DATABASE="source_a",
            METADATA_PG_SECRET_PATH=config["domains"]["source_fresh"]["paths"]["app"],
            METADATA_PG_PROVISIONER_SECRET_PATH=config["domains"]["source_fresh"][
                "paths"
            ]["provisioner"],
            AUDIT_MAINTENANCE_SECRET_PATH=config["domains"]["source_fresh"]["paths"][
                "maintenance"
            ],
        )
        private(tmp_path / ".env", "\n".join(k + "=" + v for k, v in settings.items()))
        run("reopen-source-zero")
        assert cluster.databases["source_a"].allow
        assert not cluster.databases["copy_a"].allow
        assert cluster.data["source_a"]["tokens"] == ["revoked-current"]
    else:
        run("record-copy-mutation")
        with pytest.raises(ValueError, match="dirty"):
            operator.copy_action(
                config, journal, native, "decide-copy", str(archive), "rollback-zero"
            )
        run("open-copy-private")
        # Simulated product mutation AND current revocation after the dirty marker.
        cluster.data["copy_a"]["tokens"] += [
            "positive-copy-mutation",
            "current-revocation",
        ]
        cluster.data["copy_a"]["audit_events"] += ['{"seq":2,"outcome":"confirmed"}']
        cluster.sequences["copy_a"]["audit_events_seq_seq"].update(
            last_value=2, log_cnt=27
        )
        config.update(context="return", carrier_dir=str(tmp_path / "carriers_return"))
        settings.update(
            METADATA_PG_DATABASE="return_a",
            METADATA_PG_SECRET_PATH=config["domains"]["return"]["paths"]["app"],
            METADATA_PG_PROVISIONER_SECRET_PATH=config["domains"]["return"]["paths"][
                "provisioner"
            ],
            AUDIT_MAINTENANCE_SECRET_PATH=config["domains"]["return"]["paths"][
                "maintenance"
            ],
        )
        private(tmp_path / ".env", "\n".join(k + "=" + v for k, v in settings.items()))
        private(tmp_path / "operator.json", json.dumps(config))
        archive = tmp_path / "fresh-copy.dump"
        for action in (
            "create-copy",
            "freeze-source",
            "dump-frozen",
            "seal-source",
            "restore-frozen",
            "verify-copy",
        ):
            run(action)
        assert cluster.data["return_a"]["tokens"] == [
            "revoked-current",
            "positive-copy-mutation",
            "current-revocation",
        ]
        assert (
            cluster.data["return_a"]["audit_events"]
            == cluster.data["copy_a"]["audit_events"]
        )
        assert cluster.sequences["return_a"]["audit_events_seq_seq"] == {
            "last_value": 2,
            "log_cnt": 0,
            "is_called": True,
        }
        assert (
            not cluster.databases["source_a"].allow
            and not cluster.databases["copy_a"].allow
        )
    from mcp_vault.config import get_settings

    get_settings.cache_clear()
