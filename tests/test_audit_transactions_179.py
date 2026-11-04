"""Contrats de confirmation ; les doubles ne prouvent aucune persistance PG."""

import time
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from mcp_vault.storage import audit_pg as audit
from mcp_vault.storage.postgres import MetadataUnavailable, MutationUnknown


def call():
    return audit.Call("00000000-0000-0000-0000-000000000001", "test", "tok_"+"a"*16,
                      "secret_read", "coffer-a", None, None, None, time.monotonic())


class Conn:
    def __init__(self, behavior="normal"):
        self.behavior, self.statements, self.handler = behavior, [], None
        self.end = time.monotonic()+10

    def fetchone(self):
        return None

    def add_notice_handler(self, handler):
        self.handler = handler

    def execute(self, query, params=None):
        self.statements.append(query)
        if query == "COMMIT":
            if self.behavior == "transport":
                raise OSError("PRIVATE-CANARY transport")
            if self.behavior == "notice":
                self.handler(SimpleNamespace(sqlstate="57014"))
        return self


@contextmanager
def connected(conn):
    yield conn


@pytest.mark.parametrize("behavior", ["transport", "notice"])
def test_commit_transport_or_notice_is_unknown_and_never_replayed(behavior):
    conn = Conn(behavior)
    with patch.object(audit, "connection", lambda: connected(conn)), \
         patch.object(audit, "validate_durability"), patch.object(audit, "get_settings", return_value=SimpleNamespace(metadata_sql_cancel_seconds=2)):
        op = Mock(return_value="business-observation")
        with pytest.raises(MutationUnknown) as error:
            audit._write(call(), time.monotonic()+30, op)
    assert op.call_count == 1
    assert conn.statements == ["BEGIN", "COMMIT"]
    assert error.value.mutation_id == call().call_id
    assert "PRIVATE-CANARY" not in str(error.value)


def test_expired_queued_worker_opens_no_connection_or_operation():
    with patch.object(audit, "connection") as connect:
        op = Mock()
        with pytest.raises(MetadataUnavailable, match="audit_dispatch_expired"):
            audit._write(call(), time.monotonic()-1, op)
        connect.assert_not_called()
        op.assert_not_called()


def test_failure_before_commit_rolls_back_and_never_reports_confirmed():
    conn = Conn()
    with patch.object(audit, "connection", lambda: connected(conn)), \
         patch.object(audit, "validate_durability"), patch.object(audit, "get_settings", return_value=SimpleNamespace(metadata_sql_cancel_seconds=2)):
        op = Mock(side_effect=MetadataUnavailable("audit_insertion_rejected"))
        with pytest.raises(MetadataUnavailable, match="audit_insertion_rejected"):
            audit._write(call(), time.monotonic()+30, op)
    assert conn.statements == ["BEGIN", "ROLLBACK"]


def test_anonymous_admission_cannot_open_a_business_effect():
    item = call()
    anonymous = audit.Call(item.call_id, item.instance, "anonymous", item.tool, item.vault_id, None, None, None, item.started)
    with patch.object(audit, "connection") as connect:
        with pytest.raises(MetadataUnavailable, match="audit_actor_missing"):
            audit._admit(anonymous, "admitted", time.monotonic()+30)
        connect.assert_not_called()



def test_selected_pre_auth_hash_is_not_an_authenticated_actor():
    facts = {"actor_hash": "a"*64, "actor_revision": 1}
    with patch.object(audit, "request_facts", Mock(get=lambda: facts)), \
         patch.object(audit, "current_token_info", Mock(get=lambda: None)), \
         patch.object(audit, "get_settings", return_value=SimpleNamespace(metadata_instance_id="test")):
        item = audit.make_call("bearer_auth")
    assert item.actor_ref == "anonymous"
    assert item.tenant_id is item.mission_id is None


def test_denial_of_revoked_token_can_be_recorded_without_authorizing_revalidation():
    item = call()
    denied = audit.Call(item.call_id, item.instance, "anonymous", "bearer_auth", "", None, None, None, item.started)
    conn = Conn()
    with patch.object(audit, "connection", lambda: connected(conn)), \
         patch.object(audit, "validate_durability"), \
         patch.object(audit, "get_settings", return_value=SimpleNamespace(metadata_instance_id="test", metadata_sql_cancel_seconds=2)), \
         patch.object(audit, "revalidate_actor", side_effect=MetadataUnavailable("revoked")) as validate:
        audit._admit(denied, "denied", time.monotonic()+30)
    validate.assert_not_called()
    assert conn.statements[-1] == "COMMIT"
    assert any("INSERT INTO vault_metadata.audit_calls" in query for query in conn.statements)


def test_authorizing_admission_still_revalidates_before_any_insert():
    conn = Conn()
    with patch.object(audit, "connection", lambda: connected(conn)), \
         patch.object(audit, "validate_durability"), \
         patch.object(audit, "get_settings", return_value=SimpleNamespace(metadata_sql_cancel_seconds=2)), \
         patch.object(audit, "revalidate_actor", side_effect=MetadataUnavailable("revoked")) as validate:
        with pytest.raises(MetadataUnavailable, match="revoked"):
            audit._admit(call(), "admitted", time.monotonic()+30)
    validate.assert_called_once()
    assert conn.statements == ["BEGIN", "ROLLBACK"]


def test_immutable_event_observation_requires_no_update_privilege():
    conn = Conn()
    with patch.object(audit, "get_settings", return_value=SimpleNamespace(metadata_instance_id="test")):
        assert audit.record_step(conn, call(), "admission", "admitted") is True
    assert len(conn.statements) == 2
    assert "SELECT outcome,mutation_id" in conn.statements[0]
    assert "FOR SHARE" not in conn.statements[0]
    assert "FOR UPDATE" not in conn.statements[0]
    assert "INSERT INTO vault_metadata.audit_events" in conn.statements[1]
