"""Refus opérateur avant DDL ; les ACL PostgreSQL restent à qualifier en fixture."""
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from mcp_vault.storage import audit_schema
from mcp_vault.storage.postgres import MetadataUnavailable


def settings(**updates):
    return SimpleNamespace(**({"metadata_pg_owner_role": "owner", "metadata_pg_app_role": "app",
        "metadata_pg_provisioner_role": "installer", "audit_maintenance_role": "maintenance"} | updates))


def test_distinct_maintenance_role_is_required_before_sql():
    conn = Mock()
    with pytest.raises(MetadataUnavailable, match="audit_roles_invalid"):
        audit_schema.install(conn, settings(audit_maintenance_role="app"))
    conn.execute.assert_not_called()


@pytest.mark.parametrize("row", [None, {"allowed": False}])
def test_missing_or_privileged_maintenance_role_cannot_install(row):
    conn = Mock()
    conn.execute.return_value.fetchone.return_value = row
    with pytest.raises(MetadataUnavailable, match="audit_maintenance_invalid"):
        audit_schema.install(conn, settings())
    assert conn.execute.call_count == 1
    assert "FROM pg_roles" in conn.execute.call_args.args[0]


def test_repeated_upgrade_is_rejected_before_ddl():
    conn = Mock()
    conn.execute.return_value.fetchone.return_value = {"allowed": True}
    conn.execute.return_value.fetchall.return_value = [{"version": 2}]
    with pytest.raises(MetadataUnavailable, match="audit_upgrade_source_invalid"):
        audit_schema.install(conn, settings())
    assert conn.execute.call_count == 2
    assert not any("CREATE" in str(c.args[0]) for c in conn.execute.call_args_list)


def test_runtime_never_accepts_old_schema_as_audit_ready():
    conn = Mock()
    conn.execute.return_value.fetchall.return_value = [{"version": 1}]
    with pytest.raises(MetadataUnavailable, match="audit_schema_invalid"):
        audit_schema.verify(conn, settings())
    assert conn.execute.call_count == 1
