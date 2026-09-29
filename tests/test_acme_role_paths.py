"""Proxy ACME lié à un rôle et préservation du contrat au second setup.

Le vrai middleware et le vrai setup sont exercés, sans backend ni secret réel.
"""

import copy
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from mcp_vault.pki_middleware import PkiMiddleware
from mcp_vault.vault.pki_ca import setup_pki_ca


ROLE_BASE = "/v1/_sys_pki_int/roles/dbaas-servers/acme"
ORDER_ID = "084788ef-6553-41ba-9583-6c123f205161"


async def proxy_call(path, method="POST", query=b"", backend_status=200):
    calls, events = [], []
    body = b'{"protected":"unchanged","payload":"","signature":"unchanged"}'

    def backend(request):
        calls.append(request)
        return httpx.Response(backend_status, content=b"unaltered-response", headers={
            "Content-Type": "application/json",
            "Replay-Nonce": "test-nonce",
            "Location": "https://vault.example.test" + ROLE_BASE + "/account/" + ORDER_ID,
            "Link": '<https://vault.example.test' + ROLE_BASE + '/directory>;rel="index"',
        })

    async def inner(scope, receive, send):
        await send({"type": "http.response.start", "status": 404, "headers": []})
        await send({"type": "http.response.body", "body": b"inner-app"})

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(event):
        events.append(event)

    original_client = httpx.AsyncClient

    def mock_client(**kwargs):
        return original_client(transport=httpx.MockTransport(backend), **kwargs)

    scope = {
        "type": "http", "path": path, "method": method, "query_string": query,
        "headers": [(b"content-type", b"application/jose+json"),
                    (b"authorization", b"Bearer do-not-forward"),
                    (b"x-vault-token", b"do-not-forward"),
                    (b"cookie", b"do-not-forward")],
    }
    with patch("mcp_vault.pki_middleware.httpx.AsyncClient", side_effect=mock_client), \
         patch("mcp_vault.pki_middleware.get_settings",
               return_value=MagicMock(openbao_addr="http://127.0.0.1:8200")):
        await PkiMiddleware(inner)(scope, receive, send)
    return calls, events, body


@pytest.mark.parametrize("suffix,method", [
    ("directory", "GET"), ("new-nonce", "HEAD"), ("new-nonce", "GET"),
    ("new-account", "POST"), (f"account/{ORDER_ID}", "POST"),
    ("new-order", "POST"), ("orders", "POST"),
    (f"order/{ORDER_ID}", "POST"), (f"order/{ORDER_ID}/finalize", "POST"),
    (f"order/{ORDER_ID}/cert", "POST"), (f"authorization/{ORDER_ID}", "POST"),
    (f"challenge/{ORDER_ID}/dns-01", "POST"),
    (f"challenge/{ORDER_ID}/http-01", "POST"),
    (f"challenge/{ORDER_ID}/tls-alpn-01", "POST"), ("revoke-cert", "POST"),
])
async def test_native_role_client_paths_preserve_wire_contract(suffix, method):
    path = f"{ROLE_BASE}/{suffix}"
    calls, events, body = await proxy_call(path, method)
    assert len(calls) == 1
    request = calls[0]
    assert str(request.url) == "http://127.0.0.1:8200" + path
    assert request.method == method and request.content == body
    assert request.headers["content-type"] == "application/jose+json"
    for name in ("authorization", "x-vault-token", "cookie"):
        assert name not in request.headers
    assert events[0]["status"] == 200
    headers = dict(events[0]["headers"])
    assert headers[b"replay-nonce"] == b"test-nonce"
    assert headers[b"location"].decode() == "https://vault.example.test" + ROLE_BASE + "/account/" + ORDER_ID
    assert headers[b"link"].decode() == '<https://vault.example.test' + ROLE_BASE + '/directory>;rel="index"'
    assert events[1]["body"] == b"unaltered-response"


@pytest.mark.parametrize("path", [
    "/v1/sys/mounts", "/v1/_sys_pki_int/config/acme", "/v1/_sys_pki_int/roles/dbaas-servers",
    "/v1/_sys_pki_root/roles/dbaas-servers/acme/directory",
    ROLE_BASE + "/new-eab", ROLE_BASE + "/eab", ROLE_BASE + "/eab/key-id",
    ROLE_BASE + "/../config", ROLE_BASE + "//directory", ROLE_BASE + "/directory\n",
    ROLE_BASE + "/%2e%2e/config", ROLE_BASE + "/%252e%252e/config",
    ROLE_BASE + "/order/../config", ROLE_BASE + "/order/abc%2f..%2fnew-eab",
    ROLE_BASE.replace("dbaas-servers", "../acme") + "/directory",
    ROLE_BASE.replace("dbaas-servers", "name..suffix") + "/directory",
    ROLE_BASE.replace("dbaas-servers", "%2e%2e") + "/directory",
    ROLE_BASE.replace("dbaas-servers", "*") + "/directory",
    ROLE_BASE.replace("dbaas-servers", "name/other") + "/directory",
])
async def test_other_api_and_noncanonical_paths_never_reach_openbao(path):
    calls, events, _ = await proxy_call(path)
    assert calls == []
    assert events[0]["status"] in (400, 404)


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "TRACE"])
async def test_role_proxy_rejects_non_acme_methods(method):
    calls, events, _ = await proxy_call(ROLE_BASE + "/directory", method)
    assert calls == []
    assert events[0]["status"] == 405


async def test_role_proxy_uses_existing_query_validation():
    calls, events, _ = await proxy_call(ROLE_BASE + "/new-order", query=b"x=../config")
    assert calls == [] and events[0]["status"] == 400


async def test_backend_role_rejection_is_not_masked():
    calls, events, _ = await proxy_call(ROLE_BASE + "/new-account", backend_status=403)
    assert len(calls) == 1 and events[0]["status"] == 403


def setup_client(config):
    client = MagicMock()
    client.read.return_value = config
    client.write.return_value = {"data": {"certificate": "", "csr": "test-csr", "imported_issuers": []}}
    return client


async def run_setup(client):
    with patch("mcp_vault.vault.pki_ca._get_hvac_client", return_value=client), \
         patch("mcp_vault.s3_sync.upload_to_s3", new_callable=AsyncMock, return_value=True):
        return await setup_pki_ca(lab_mode=False, allowed_domains=["example.test"])


def acme_payload(client):
    writes = [call.kwargs for call in client.write.call_args_list
              if call.args == ("_sys_pki_int/config/acme",)]
    assert len(writes) == 1
    return writes[0]


async def test_setup_preserves_only_explicit_roles_and_is_idempotent():
    original = {"data": {"allowed_roles": ["acme-servers", "dbaas-servers", "another-role", "dbaas-servers"]}}
    state = copy.deepcopy(original)
    client = setup_client(state)
    for _ in range(2):
        client.reset_mock()
        client.read.return_value = state
        input_config = copy.deepcopy(state)
        result = await run_setup(client)
        assert result["status"] == "ok"
        payload = acme_payload(client)
        assert payload == {
            "enabled": True, "default_directory_policy": "role:acme-servers",
            "allowed_roles": ["acme-servers", "dbaas-servers", "another-role"],
            "allowed_issuers": ["*"], "eab_policy": "new-account-required",
        }
        assert client.method_calls[0] == ("read", ("_sys_pki_int/config/acme",), {})
        role_writes = [call.args[0] for call in client.write.call_args_list if "/roles/" in call.args[0]]
        assert role_writes == ["_sys_pki_int/roles/acme-servers"]
        client.list.assert_not_called()
        client.delete.assert_not_called()
        assert state == input_config
        state = {"data": copy.deepcopy(payload)}


@pytest.mark.parametrize("config", [None, {"data": {"allowed_roles": ["*"]}}])
async def test_new_setup_does_not_promote_default_wildcard(config):
    client = setup_client(config)
    assert (await run_setup(client))["status"] == "ok"
    assert acme_payload(client)["allowed_roles"] == ["acme-servers"]


@pytest.mark.parametrize("config", [
    {}, {"data": None}, {"data": {}}, {"data": {"allowed_roles": "dbaas-servers"}},
    {"data": {"allowed_roles": []}}, {"data": {"allowed_roles": [None]}},
    {"data": {"allowed_roles": [""]}}, {"data": {"allowed_roles": ["*", "dbaas-servers"]}},
])
async def test_unknown_existing_config_stops_before_mutation(config):
    client = setup_client(config)
    assert (await run_setup(client))["status"] == "error"
    client.write.assert_not_called()
    client._adapter.post.assert_not_called()
    client.sys.enable_secrets_engine.assert_not_called()


async def test_config_read_failure_cannot_erase_roles():
    client = setup_client(None)
    client.read.side_effect = RuntimeError("read unavailable")
    assert (await run_setup(client))["status"] == "error"
    client.write.assert_not_called()
    client._adapter.post.assert_not_called()
    client.sys.enable_secrets_engine.assert_not_called()
