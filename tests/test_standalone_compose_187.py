"""Recipe wiring only. This does not run Compose, a daemon or TLS."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_external_base_mounts_pg_ca_without_local_engine():
    base = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    app = base["services"]["mcp-vault"]
    assert any("/run/pg-ca.crt:ro" in value for value in app["volumes"])
    assert "postgres" not in base["services"]
    assert app["build"]["target"] == "production"


def test_override_has_one_private_persistent_engine():
    override = yaml.safe_load((ROOT / "docker-compose.postgres.yml").read_text())
    pg = override["services"]["postgres"]
    assert "ports" not in pg and "healthcheck" not in pg
    assert len([v for v in pg["volumes"] if "/var/lib/postgresql/data" in v]) == 1
    assert not override["services"].get("mcp-vault", {}).get("depends_on")


def test_operator_installs_versioned_signed_clients_without_changing_production():
    text = (Path(__file__).parents[1] / "Dockerfile").read_text()
    production, tail = text.split("FROM production AS pg-operator", 1)
    operator = tail.split("FROM python:", 1)[0]
    assert "postgresql-client-16" in operator
    assert "Signed-By:" in operator and "ACCC4CF8.asc" in operator
    assert '"$VERSION_CODENAME"' in operator and "dpkg --print-architecture" in operator
    assert 'ENV PATH="/usr/lib/postgresql/16/bin:${PATH}"' in operator
    assert "dpkg-query -W postgresql-client-16 libpq5" in operator
    assert "postgresql-client" not in production
