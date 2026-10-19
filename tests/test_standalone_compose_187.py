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
