"""Pre-SQL gates only; actual holds/locks need the fresh PostgreSQL fixture."""
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from mcp_vault.config import Settings
from mcp_vault.storage import audit_schema
from mcp_vault.storage.audit_retention_schema import install
from mcp_vault.storage.postgres import MetadataUnavailable


def profile(**updates):
    return Settings(_env_file=None, **{
        "metadata_backend": "postgres", "metadata_instance_id": "vault846",
        "metadata_pg_vault_id": "technical846", "metadata_pg_database": "vault846",
        "metadata_pg_owner_role": "vault846_owner", "metadata_pg_app_role": "vault846_app",
        "metadata_pg_provisioner_role": "vault846_install", "metadata_pg_ca_file": "/private/ca.crt",
        "metadata_pg_secret_path": "sql/app", "metadata_pg_provisioner_secret_path": "sql/install",
        "audit_mission_retention_enabled": True, **updates})


def test_annual_pg_hold_profile_and_default_off_are_explicit():
    assert Settings(_env_file=None).audit_mission_retention_enabled is False
    assert profile().audit_mission_retention_enabled is True


@pytest.mark.parametrize("updates", [{"metadata_backend": "s3"}, {"audit_retention_days": 364}])
def test_a_hold_cannot_be_enabled_over_non_pg_or_shorter_audit(updates):
    with pytest.raises(ValueError, match="annual PostgreSQL audit"):
        profile(**updates)


@pytest.mark.parametrize("version", [1, 3])
def test_extension_replay_or_wrong_source_refused_before_ddl(version):
    conn = Mock()
    conn.execute.return_value.fetchall.return_value = [{"version": version}]
    with pytest.raises(MetadataUnavailable, match="retention_upgrade_source_invalid"):
        install(conn, SimpleNamespace())
    assert conn.execute.call_count == 1


def test_enabling_against_v2_does_not_silently_accept_missing_protection():
    conn = Mock()
    conn.execute.return_value.fetchall.return_value = [{"version": 2}]
    settings = SimpleNamespace(metadata_pg_app_role="app", metadata_pg_owner_role="owner",
                               audit_maintenance_role="maintenance", audit_mission_retention_enabled=True)
    with pytest.raises(MetadataUnavailable, match="audit_schema_invalid"):
        audit_schema.verify(conn, settings)
    assert conn.execute.call_count == 1
