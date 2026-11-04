"""Pure operator contracts; transports are replaced, never a running service."""

import importlib.util
import json
import os
import sys
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def helper():
    spec = importlib.util.spec_from_file_location(
        "pg187", ROOT / "scripts/pg_operator.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def args():
    return SimpleNamespace(
        action="provision",
        infra_mount="technical",
        infra_path="ops/infra",
        domain_mount="technical",
        app_path="source/app",
        provisioner_path="source/provisioner",
        maintenance_path="source/maintenance",
        backup_path="ops/backup",
        restore_path="ops/restore",
        database="domain_a",
        owner_role="a_owner",
        app_role="a_app",
        provisioner_role="a_prov",
        maintenance_role="a_maint",
        backup_role="a_backup",
        restore_role="a_restore",
        pg_ca_file="ca",
    )


class FakeConnection:
    def __init__(self, collision=None):
        self.statements = []
        self.collision = collision
        self.row = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def transaction(self):
        return nullcontext()

    def execute(self, query, parameters=None):
        text = query if isinstance(query, str) else query.as_string()
        self.statements.append((text, parameters))
        self.row = None
        if "server_version_num" in text:
            self.row = (160000,)
        if "rolsuper,rolcreatedb,rolcreaterole" in text:
            self.row = (False, True, True, False, False)
        if "pg_roles WHERE rolname=ANY" in text and self.collision in parameters[0]:
            self.row = (1,)
        return self

    def fetchone(self):
        return self.row


def run_provision(monkeypatch, collision=None, invalid_maintenance=False):
    import psycopg

    module, options, conn, calls = helper(), args(), FakeConnection(collision), []
    names = {
        options.app_path: options.app_role,
        options.provisioner_path: options.provisioner_role,
        options.maintenance_path: options.maintenance_role,
        options.backup_path: options.backup_role,
        options.restore_path: options.restore_role,
        options.infra_path: "infra",
    }

    def native(options, mount, path):
        calls.append(path)
        return {
            "host": "pg.test",
            "port": "5432",
            "dbname": "wrong"
            if invalid_maintenance and path == options.maintenance_path
            else options.database,
            "user": names[path],
            "password": "synthetic",
        }

    monkeypatch.setattr(module, "native_connection", native)
    monkeypatch.setattr(psycopg, "connect", lambda **kw: calls.append("SQL") or conn)
    return module, options, conn, calls


def test_provision_includes_maintenance_before_schema(monkeypatch):
    module, options, conn, calls = run_provision(monkeypatch)
    module.operation(options)
    assert options.maintenance_path in calls[: calls.index("SQL")]
    sql = "\n".join(text for text, _ in conn.statements)
    assert 'CREATE ROLE "a_maint" LOGIN NOINHERIT' in sql
    assert 'CREATE ROLE "a_backup" LOGIN NOINHERIT' in sql
    assert "INHERIT FALSE" in sql and "SET TRUE" in sql and "ADMIN FALSE" in sql
    assert 'GRANT "a_owner" TO "a_app"' not in sql
    assert 'GRANT "a_owner" TO "a_maint"' not in sql


def test_maintenance_collision_precedes_any_creation(monkeypatch):
    module, options, conn, _calls = run_provision(monkeypatch, collision="a_maint")
    with pytest.raises(ValueError):
        module.operation(options)
    assert not any(text.startswith("CREATE") for text, _ in conn.statements)


def test_invalid_maintenance_precedes_sql(monkeypatch):
    module, options, _conn, calls = run_provision(monkeypatch, invalid_maintenance=True)
    with pytest.raises(ValueError):
        module.operation(options)
    assert "SQL" not in calls


def test_public_helper_refuses_unreserved_separate_mount_before_auth(monkeypatch):
    module = helper()
    options = args()
    options.infra_mount = "unreserved"
    monkeypatch.setattr(
        module,
        "native_connection",
        lambda *a: pytest.fail("Must refuse before reading another mount"),
    )
    with pytest.raises(ValueError, match="réservé"):
        module.operation(options)


@pytest.fixture
def operator(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    import standalone_pg

    return standalone_pg


def synthetic_config(tmp_path):
    roles = {
        kind: "a_" + kind
        for kind in ("owner", "app", "provisioner", "maintenance", "backup", "restore")
    }
    domains = {
        context: {
            "database": "a_" + context,
            "paths": {kind: context + "/" + kind for kind in roles if kind != "owner"},
        }
        for context in ("source_fresh", "copy", "return")
    }
    return {
        "context": "copy",
        "execution": "python",
        "topology": "external",
        "instance": "instance_a",
        "mount": "technical_a",
        "roles": roles,
        "domains": domains,
        "infra_path": "ops/infra",
        "settings_file": str(tmp_path / ".env"),
        "compose_env_file": str(tmp_path / "compose.env"),
        "carrier_dir": str(tmp_path / "carriers"),
        "vault_url": "http://127.0.0.1:8200",
        "vault_ca_file": "",
        "auth": {"mode": "token_file", "token_file": str(tmp_path / "token")},
        "product_url": "https://vault.example",
        "product_ca_file": "",
        "pg_ca_file": str(tmp_path / "ca.crt"),
        "bootstrap_file": str(tmp_path / "bootstrap"),
        "initial_admin_file": str(tmp_path / "admin"),
        "client_name": "operator_a",
        "tls": {
            "directory": str(tmp_path / "tls"),
            "host": "pg.example",
            "pg_uid": os.geteuid(),
            "pg_gid": os.getegid(),
        },
    }


def private(path, value):
    path.write_text(value)
    path.chmod(0o600)


@pytest.mark.parametrize(
    "mutation",
    ["unknown", "context", "path", "database", "remote-http", "fallback", "same-env"],
)
def test_invalid_config_no_transport(operator, tmp_path, mutation):
    from standalone_pg_files import load_config

    config = synthetic_config(tmp_path)
    if mutation == "unknown":
        config["dsn"] = "forbidden"
    elif mutation == "context":
        del config["context"]
    elif mutation == "path":
        config["domains"]["copy"]["paths"]["app"] = config["domains"]["source_fresh"][
            "paths"
        ]["app"]
    elif mutation == "database":
        config["domains"]["copy"]["database"] = config["domains"]["source_fresh"][
            "database"
        ]
    elif mutation == "remote-http":
        config["vault_url"] = "http://bao.example:8200"
    elif mutation == "fallback":
        config["auth"]["mode"] = "existing_bootstrap"
    else:
        config["compose_env_file"] = config["settings_file"]
    path = tmp_path / "operator.json"
    private(path, json.dumps(config))
    with pytest.raises(ValueError):
        load_config(path)


@pytest.mark.parametrize("symlink", [False, True])
def test_private_file_modes_and_symlinks(operator, tmp_path, symlink):
    from standalone_pg_files import private_read, private_write

    path = tmp_path / "secret"
    if symlink:
        private(tmp_path / "target", "synthetic")
        path.symlink_to(tmp_path / "target")
        with pytest.raises(OSError):
            private_read(path)
    else:
        path.write_text("synthetic")
        path.chmod(0o644)
        with pytest.raises(ValueError):
            private_read(path)
    with pytest.raises(FileExistsError):
        private_write(path, b"replacement")


def test_journal_unknown_never_redispatches_and_binding_is_exact(operator, tmp_path):
    from standalone_pg_files import Journal

    config = synthetic_config(tmp_path)
    journal, effects = Journal(config), []

    def lost_ack():
        effects.append("effect")
        raise TimeoutError()

    with pytest.raises(TimeoutError):
        journal.run("schema-init", lost_ack)
    with pytest.raises(FileExistsError):
        journal.run("schema-init", lost_ack)
    assert effects == ["effect"]
    with pytest.raises(FileNotFoundError):
        journal.confirmed("schema-init")
    config["mount"] = "different_mount"
    with pytest.raises(ValueError):
        Journal(config)


@pytest.mark.parametrize("denied", [False, True])
def test_native_real_kv_envelope_auth_first(operator, tmp_path, monkeypatch, denied):
    import httpx
    from standalone_pg_native import Native

    config = synthetic_config(tmp_path)
    private(tmp_path / "token", "native-synthetic")
    paths, original = [], httpx.Client

    def request(req):
        paths.append(req.url.path)
        if req.url.path.endswith("lookup-self"):
            return httpx.Response(403 if denied else 200, json={"data": {}})
        return httpx.Response(200, json={"data": {"data": {"host": "pg.example"}}})

    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **kw: original(transport=httpx.MockTransport(request), **kw),
    )
    if denied:
        with pytest.raises(ValueError):
            Native(config)
        assert paths == ["/v1/auth/token/lookup-self"]
    else:
        native = Native(config)
        assert native.read("copy/app") == {"host": "pg.example"}
        assert paths == ["/v1/auth/token/lookup-self", "/v1/technical_a/data/copy/app"]
        native.close()
        assert native.token == ""


def test_token_file_refusal_has_no_bootstrap_fallback(operator, tmp_path, monkeypatch):
    import standalone_pg_native
    from standalone_pg_native import native_token

    config = synthetic_config(tmp_path)
    monkeypatch.setattr(
        standalone_pg_native.subprocess, "run", lambda *a, **kw: pytest.fail("fallback")
    )
    with pytest.raises(FileNotFoundError):
        native_token(config)


def test_bootstrap_discards_keys_uses_real_app_settings(
    operator, tmp_path, monkeypatch
):
    import standalone_pg_bootstrap

    from mcp_vault.config import get_settings
    from mcp_vault.openbao import lifecycle

    private(
        tmp_path / ".env",
        "ADMIN_BOOTSTRAP_KEY=synthetic-bootstrap\nS3_BUCKET_NAME=synthetic-bucket\n",
    )
    envelope = {
        "root_token": "native-root",
        "keys": ["must-disappear"],
        "keys_base64": ["must-disappear"],
    }
    observed = []

    def download():
        observed.append(
            (get_settings().s3_bucket_name, get_settings().admin_bootstrap_key)
        )
        return envelope

    monkeypatch.setattr(os, "environ", {})
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(lifecycle, "_download_encrypted_keys_from_s3", download)
    try:
        assert standalone_pg_bootstrap.load_root(tmp_path / ".env") == "native-root"
        assert envelope == {}
        assert observed == [("synthetic-bucket", "synthetic-bootstrap")]
    finally:
        get_settings.cache_clear()


def test_tls_files_real_san_and_modes_without_service(operator, tmp_path):
    from cryptography import x509

    config = synthetic_config(tmp_path)
    operator.prepare_files(config)
    directory = tmp_path / "tls"
    certificate = x509.load_pem_x509_certificate(
        (directory / "server.crt").read_bytes()
    )
    assert certificate.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.DNSName) == ["pg.example"]
    assert (directory.stat().st_mode & 0o777) == 0o700
    assert all((p.stat().st_mode & 0o777) == 0o600 for p in directory.iterdir())
    with pytest.raises(FileExistsError):
        operator.prepare_files(config)


def test_copy_install_actual_dispatcher_only_connections_and_maintenance(
    operator, tmp_path, monkeypatch
):
    from standalone_pg_files import Journal

    config = synthetic_config(tmp_path)
    options = config["domains"]["copy"]
    directory = tmp_path / "credentials"
    directory.mkdir(mode=0o700)
    values = {
        kind: {
            "host": "pg.example",
            "port": "5432",
            "dbname": "postgres" if kind == "infra" else options["database"],
            "user": "infra_a" if kind == "infra" else config["roles"][kind],
            "password": "synthetic",
        }
        for kind in ("infra", *operator.KINDS)
    }
    for kind, value in values.items():
        private(directory / (kind + ".json"), json.dumps(value))
    stored = {config["infra_path"]: values["infra"]}
    for kind in operator.KINDS:
        stored[config["domains"]["source_fresh"]["paths"][kind]] = {
            **values[kind],
            "dbname": "a_source_fresh",
        }

    class Bao:
        def read(self, path):
            return stored[path]

        def put_new(self, path, value):
            if path in stored:
                assert stored[path] == value
            stored[path] = value

    calls = []

    def product(config, action, body=None):
        calls.append(action)
        if action == "connections":
            for kind in body:
                stored[options["paths"][kind]] = body[kind]
        elif action == "audit-maintenance-connection":
            stored[options["paths"]["maintenance"]] = body
        else:
            pytest.fail("Copy dispatcher escaped its two install actions")
        return {"status": "ok"}

    monkeypatch.setattr(operator, "mode", lambda *a: None)
    monkeypatch.setattr(operator, "product", product)
    operator.install(config, Journal(config), Bao(), directory)
    assert calls == ["connections", "audit-maintenance-connection"]
    with pytest.raises(ValueError, match="DDL/seed"):
        operator.provision_fresh(config, Journal(config), Bao())


@pytest.mark.parametrize(
    "mutation", ["none", "dirty", "acl", "partial", "unstable", "unrelated-unknown"]
)
def test_restore_unknown_needs_real_zero_predicates(
    operator, tmp_path, monkeypatch, mutation
):
    from standalone_pg_files import Journal

    config, created = (
        synthetic_config(tmp_path),
        {
            "copy": {"oid": 12, "sessions": [], "acl": []},
            "empty": {"tables": [], "versions": []},
        },
    )
    journal = Journal(config)
    journal.write("restore-frozen.intent", {"binding": journal.binding})
    if mutation == "dirty":
        journal.write("record-copy-mutation.intent", {"binding": journal.binding})
    if mutation == "unrelated-unknown":
        journal.write("install-connections.intent", {"binding": journal.binding})
    observation = {
        **created["copy"],
        **({"acl": ["unexpected"]} if mutation == "acl" else {}),
    }
    monkeypatch.setattr(operator, "db_observation", lambda *a: observation)
    contents = iter([created["empty"], {"tables": ["changed"], "versions": []}])
    monkeypatch.setattr(
        operator,
        "fingerprint",
        lambda *a: (
            next(contents)
            if mutation == "unstable"
            else {"tables": ["partial"], "versions": []}
            if mutation == "partial"
            else created["empty"]
        ),
    )
    if mutation == "none":
        assert (
            operator.zero_copy(
                config,
                journal,
                None,
                {},
                created,
                {"content": {"tables": ["full"], "versions": [2]}},
            )["restore_ack"]
            is False
        )
    else:
        with pytest.raises(ValueError):
            operator.zero_copy(
                config,
                journal,
                None,
                {},
                created,
                {"content": {"tables": ["full"], "versions": [2]}},
            )


def test_same_mount_reservation_in_copy_guards_every_path(
    operator, tmp_path, monkeypatch
):
    from mcp_vault import reserved_metadata

    config = synthetic_config(tmp_path)
    monkeypatch.setattr(
        reserved_metadata,
        "get_settings",
        lambda: SimpleNamespace(
            metadata_backend="postgres", metadata_pg_vault_id=config["mount"]
        ),
    )
    for domain in config["domains"].values():
        for path in domain["paths"].values():
            assert (
                reserved_metadata.target_error(config["mount"])["error_type"]
                == "access_denied"
            ), path
    assert reserved_metadata.target_error("neighbor_b") is None
    # L'ancienne proposition à deux mounts ne protège effectivement pas Source.
    monkeypatch.setattr(
        reserved_metadata,
        "get_settings",
        lambda: SimpleNamespace(
            metadata_backend="postgres", metadata_pg_vault_id="different_mount"
        ),
    )
    assert reserved_metadata.target_error(config["mount"]) is None


def test_engine_preparation_is_finite_private_and_native_only(
    operator, tmp_path, monkeypatch
):
    config = synthetic_config(tmp_path)
    config.update(context="source_fresh", topology="local")
    values = {
        config["infra_path"]: {
            "host": "pg.example",
            "port": "5432",
            "dbname": "postgres",
            "user": "infra_a",
            "password": "synthetic",
        }
    }
    domain = config["domains"]["source_fresh"]
    for kind in operator.KINDS:
        values[domain["paths"][kind]] = {
            "host": "pg.example",
            "port": "5432",
            "dbname": domain["database"],
            "user": config["roles"][kind],
            "password": "synthetic",
        }
    reads = []

    def native(path):
        reads.append(path)
        return values[path]

    monkeypatch.setattr(
        operator,
        "connection",
        lambda *a, **kw: pytest.fail("No SQL during file preparation"),
    )
    operator.prepare_engine(config, SimpleNamespace(read=native), tmp_path / "engine")
    assert set(reads) == set(values)
    directory = tmp_path / "engine"
    assert {p.name for p in directory.iterdir()} == {
        "init.sql",
        "engine.password",
        "pg_hba.conf",
    }
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in directory.iterdir())
    statement = (directory / "init.sql").read_text()
    assert (
        'CREATE ROLE "infra_a" LOGIN NOINHERIT NOSUPERUSER CREATEDB CREATEROLE'
        in statement
    )
    assert 'GRANT CONNECT ON DATABASE postgres TO "infra_a"' in statement
    hba = (directory / "pg_hba.conf").read_text()
    assert "hostnossl all all 0.0.0.0/0 reject" in hba
    assert "hostssl all all 0.0.0.0/0 scram-sha-256" in hba
    with pytest.raises(FileExistsError):
        operator.prepare_engine(config, SimpleNamespace(read=native), directory)


def test_public_cli_help_and_unknown_action_do_not_open_transport(
    operator, monkeypatch, capsys
):
    monkeypatch.setattr(
        operator,
        "Native",
        lambda *a: pytest.fail("No transport on parser-only actions"),
    )
    monkeypatch.setattr(sys, "argv", ["standalone_pg.py", "--help"])
    with pytest.raises(SystemExit) as result:
        operator.main()
    assert result.value.code == 0
    assert "reopen-source-zero" in capsys.readouterr().out
    monkeypatch.setattr(
        sys, "argv", ["standalone_pg.py", "schema-init", "--config", "absent"]
    )
    with pytest.raises(SystemExit) as result:
        operator.main()
    assert result.value.code == 2


def test_private_file_in_mutable_public_directory_is_refused(operator, tmp_path):
    from standalone_pg_files import private_read

    directory = tmp_path / "public"
    directory.mkdir(mode=0o777)
    directory.chmod(0o777)
    private(directory / "token", "synthetic")
    with pytest.raises(ValueError, match="0700"):
        private_read(directory / "token")


def test_missing_initial_bearer_stops_before_any_sql(operator, tmp_path, monkeypatch):
    import httpx
    import psycopg
    from standalone_pg_files import Journal

    config = synthetic_config(tmp_path)
    config["context"] = "source_fresh"
    private(tmp_path / "bootstrap", "synthetic")
    original = httpx.Client
    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **kw: original(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200, json={"status": "ok", "mode": "install", "openbao_ready": True}
                )
            ),
            **kw,
        ),
    )
    monkeypatch.setattr(
        psycopg,
        "connect",
        lambda **kw: pytest.fail("SQL reached before initial bearer validation"),
    )
    journal = Journal(config)
    for step in (
        "install-connections",
        "install-maintenance",
        "install-native-infra",
        "install-native-backup",
        "install-native-restore",
    ):
        journal.run(step, lambda: {"confirmed": True})
    domain = config["domains"]["source_fresh"]
    stored = {
        config["infra_path"]: {
            "host": "pg.example",
            "port": "5432",
            "dbname": "postgres",
            "user": "infra_a",
            "password": "synthetic",
        }
    }
    for kind in operator.KINDS:
        stored[domain["paths"][kind]] = {
            "host": "pg.example",
            "port": "5432",
            "dbname": domain["database"],
            "user": config["roles"][kind],
            "password": "synthetic",
        }
    with pytest.raises(FileNotFoundError) as error:
        operator.provision_fresh(
            config, journal, SimpleNamespace(read=lambda path: stored[path])
        )
    assert error.value.filename == config["initial_admin_file"]
    assert not journal.exists("provision.intent")
