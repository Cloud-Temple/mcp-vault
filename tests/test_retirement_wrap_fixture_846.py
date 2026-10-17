"""Software-only checks; NO PG, Docker, Bao bootstrap or real credentials.

The small local HTTP server is a synthetic transport witness, not native proof.
Native W01..W08 remain subject to the separately reviewed explicit recipe.
"""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import inspect
import json
from pathlib import Path
import sys
import threading
from types import SimpleNamespace

import hvac
import pytest
import requests

FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(FIXTURES))
from retirement_846_wrap_support import (  # noqa: E402
    Journal,
    bao_http_receipts,
    bootstrap_owner,
    drop_unwrap_once,
    loopback_url,
    read_policy,
)


@contextmanager
def transport_backend(status=200):
    observed = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            observed.append((self.path, self.headers.get("X-Vault-Token")))
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            body = json.dumps(
                {"data": {"data": {"value": "unit-canary"}, "metadata": {"version": 1}}}
            ).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:" + str(server.server_port), observed
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
        assert not thread.is_alive()


def test_capture_precedes_caller_assertion_and_is_exclusive_private(tmp_path):
    journal = Journal(tmp_path / "receipts")
    answer = journal.call("native-writer", lambda: {"unexpected": True})
    with pytest.raises(AssertionError):
        assert answer.get("status") == "ok"
    received = journal.directory / "native-writer.received.private.json"
    assert json.loads(received.read_text()) == {"unexpected": True}
    assert received.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        journal.call("native-writer", lambda: pytest.fail("must not redispatch"))


def test_capture_exception_type_without_sensitive_text(tmp_path):
    journal = Journal(tmp_path / "receipts")

    def fail():
        raise RuntimeError("unit-private-message")

    with pytest.raises(RuntimeError):
        journal.call("unknown", fail)
    assert json.loads(
        (journal.directory / "unknown.received.private.json").read_text()
    ) == {"exception_type": "RuntimeError"}
    assert "unit-private-message" not in "".join(
        p.read_text() for p in journal.directory.iterdir()
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1:1",
        "http://localhost:1",
        "http://example.org:8200",
        "http://127.0.0.1:1/v1",
        "http://user:pass@127.0.0.1:1",
        "http://127.0.0.1:1?q=x",
    ],
)
def test_bootstrap_rejects_other_authorities_before_client_creation(url):
    with pytest.raises(ValueError):
        bootstrap_owner(url, lambda **_: pytest.fail("no client on invalid authority"))


def test_owner_initialization_is_memory_only_no_child_parameter(tmp_path):
    events = []

    class Sys:
        def is_initialized(self):
            events.append("is_initialized")
            return False

        def initialize(self, **kwargs):
            events.append(("initialize", kwargs))
            return {
                "root_token": "unit-root-only-memory",
                "keys": ["unit-unseal-only-memory"],
            }

        def submit_unseal_key(self, key):
            events.append(("unseal", key))

        def is_sealed(self):
            return False

    client = SimpleNamespace(sys=Sys(), token=None)
    resolved = bootstrap_owner("http://127.0.0.1:18200", lambda **_: client)
    assert resolved is client and resolved.token == "unit-root-only-memory"
    assert events == [
        "is_initialized",
        ("initialize", {"secret_shares": 1, "secret_threshold": 1}),
        ("unseal", "unit-unseal-only-memory"),
    ]
    assert list(tmp_path.iterdir()) == []
    assert set(inspect.signature(bootstrap_owner).parameters) == {
        "url",
        "client_factory",
    }


def test_existing_bao_never_initialized():
    client = SimpleNamespace(
        sys=SimpleNamespace(
            is_initialized=lambda: True,
            initialize=lambda **_: pytest.fail("must not initialize existing server"),
        )
    )
    with pytest.raises(ValueError, match="preexisting"):
        bootstrap_owner("http://127.0.0.1:18200", lambda **_: client)


def test_children_read_one_exact_path_no_list_sys_or_auth():
    policy = read_policy("wrap846-technical", "sql/app")
    assert policy == 'path "wrap846-technical/data/sql/app" { capabilities = ["read"] }'
    assert "*" not in policy and '"list"' not in policy
    for bad in ("sql/*", 'sql/app" { }', "../sql/app", "sql/install/extra"):
        with pytest.raises(ValueError):
            read_policy("wrap846-technical", bad)


@pytest.mark.skipif(
    not isinstance(getattr(hvac, "__file__", None), str),
    reason="real hvac transport unavailable; no stub transport proof",
)
def test_real_hvac_transport_loses_ack_once_and_second_cannot_forward(tmp_path):
    journal = Journal(tmp_path / "relay")
    with transport_backend() as (backend, observed):
        with drop_unwrap_once(backend, "unit-wrap", journal) as (relay, state):
            real_client = hvac.Client(url=relay, token="unit-wrap", timeout=(1, 1))
            with pytest.raises(requests.ConnectionError):
                real_client.sys.unwrap()
            assert state == {"forwards": 1, "status": 200, "error": None}
            assert observed == [("/v1/sys/wrapping/unwrap", "unit-wrap")]
            body = json.loads(
                (journal.directory / "unwrap-forward.received.private.json").read_text()
            )
            assert body["status"] == 200 and json.loads(body["body"])["data"][
                "data"
            ] == {"value": "unit-canary"}
            # Response loss isn't a successful client unwrap or a safe retry.
            assert (
                requests.post(
                    relay + "/v1/sys/wrapping/unwrap",
                    headers={"X-Vault-Token": "unit-wrap"},
                    timeout=1,
                ).status_code
                == 409
            )
            assert len(observed) == 1


def test_relay_refuses_foreign_token_path_and_get_without_forward(tmp_path):
    with transport_backend() as (backend, observed):
        with drop_unwrap_once(backend, "unit-wrap", Journal(tmp_path / "relay")) as (
            relay,
            state,
        ):
            assert requests.get(relay + "/v1/sys/init", timeout=1).status_code == 403
            assert (
                requests.post(
                    relay + "/v1/sys/wrapping/unwrap",
                    headers={"X-Vault-Token": "foreign"},
                    timeout=1,
                ).status_code
                == 403
            )
            assert (
                requests.post(
                    relay + "/v1/sys/mounts",
                    headers={"X-Vault-Token": "unit-wrap"},
                    timeout=1,
                ).status_code
                == 403
            )
            assert observed == [] and state["forwards"] == 0


@pytest.mark.skipif(
    not isinstance(getattr(hvac, "__file__", None), str),
    reason="real hvac transport unavailable; no stub transport proof",
)
def test_backend_non200_never_becomes_lost_success(tmp_path):
    with transport_backend(503) as (backend, _):
        with drop_unwrap_once(backend, "unit-wrap", Journal(tmp_path / "relay")) as (
            relay,
            state,
        ):
            with pytest.raises(requests.ConnectionError):
                hvac.Client(url=relay, token="unit-wrap", timeout=(1, 1)).sys.unwrap()
            assert state["status"] == 503  # W06 requires 200 and stops otherwise


def test_http_ack_observer_captures_native_status_without_auth_headers(tmp_path):
    journal = Journal(tmp_path / "observe")
    original = requests.Session.send
    with transport_backend() as (backend, _):
        with bao_http_receipts(backend, journal) as events:
            response = requests.post(
                backend + "/v1/sys/wrapping/unwrap",
                headers={"X-Vault-Token": "unit-owner-never-capture"},
                timeout=1,
            )
            assert response.status_code == 200
            assert events == [
                {
                    "method": "POST",
                    "path": "/v1/sys/wrapping/unwrap",
                    "wrapped_request": False,
                    "status": 200,
                }
            ]
            raw = (journal.directory / "http-000.received.private.json").read_text()
            assert "unit-owner-never-capture" not in raw and '"status": 200' in raw
            with pytest.raises(ValueError, match="init/query"):
                requests.post(backend + "/v1/sys/init", timeout=1)
    assert requests.Session.send is original


def test_actual_product_write_and_unwrap_envelope_not_flattened():
    from mcp_vault.vault.types import enrich_secret_data
    from mcp_vault.vault.wrapping import _usable_kv2_secret

    pairs = enrich_secret_data("custom", {"value": "unit-canary"})
    actual_shape = {"data": {"data": pairs, "metadata": {"version": 1}}}
    consumed = _usable_kv2_secret(actual_shape)
    assert (
        consumed == actual_shape["data"] and consumed["data"]["value"] == "unit-canary"
    )
    assert _usable_kv2_secret({"data": {"data": None, "metadata": {}}}) is None


def test_actual_store_binding_replacement_requires_delete_then_create():
    # Product contract witness, no save/database mock posing as a native result.
    from mcp_vault.auth.mission_bindings import MissionBindingStore
    from mcp_vault.config import Settings

    cfg = Settings(_env_file=None)
    store = MissionBindingStore(cfg)
    store._maybe_refresh = lambda: None
    store._available = True
    store._bindings = {"wrap846-tenant": {"tenant_id": "wrap846-tenant"}}
    result = store.create("wrap846-tenant", ["wrap846-business"], ["read"])
    assert result["status"] == "error" and "existe déjà" in result["message"]


def test_native_entrypoints_signatures_accept_exact_fixture_arguments():
    from mcp_vault import server
    from mcp_vault.vault import wrapping
    from mcp_vault.auth.mission_bindings import MissionBindingStore

    inspect.signature(server.secret_wrap).bind(
        "wrap846-business",
        "canary",
        "mission-a",
        "op-c",
        ttl_seconds=300,
        tenant_id="wrap846-tenant",
        expected_aud="aud",
    )
    inspect.signature(wrapping.consume_wrap_secret).bind(
        "unit-wrap",
        "op-c",
        "mission-a",
        tenant_id="wrap846-tenant",
        expected_aud="aud",
        enforce=True,
    )
    inspect.signature(wrapping.lookup_and_revoke_by_operation_id).bind(
        "op-r", "mission-a"
    )
    inspect.signature(MissionBindingStore.create).bind(
        None, "wrap846-tenant", ["wrap846-business"], ["read"], created_by="owner-r2"
    )


def test_fixture_import_has_no_effect_and_no_root_cli_input():
    spec = importlib.util.spec_from_file_location(
        "wrap846_fixture_contract", FIXTURES / "retirement_846_wraps_pg.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert set(inspect.signature(module.run).parameters) == {"socket", "url", "report"}
    assert loopback_url("http://127.0.0.1:18200/") == "http://127.0.0.1:18200"
