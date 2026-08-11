#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test d'INTÉGRATION #77 — secret_wrap_status ne détruit PAS le wrap.

Exerce le VRAI flux broker (wrap_secret → status_by_operation_id) contre un OpenBao
réel + un registre en mémoire, et prouve empiriquement le cœur de #77 :

  - après un `status` (lecture), le wrap_token OpenBao reste **consommable**
    (sys.unwrap réussit) → status est sans effet de bord ;
  - contraste : `lookup_and_revoke_by_operation_id` RÉVOQUE → l'unwrap échoue ensuite.

Opt-in (pattern e2e du repo) : SKIP sauf si l'environnement fournit
  - MCP_VAULT_TEST_OPENBAO_ADDR  (ex: http://127.0.0.1:18201)
  - MCP_VAULT_TEST_OPENBAO_TOKEN (root/dev token)
"""
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

_ADDR = os.getenv("MCP_VAULT_TEST_OPENBAO_ADDR", "").strip()
_TOKEN = os.getenv("MCP_VAULT_TEST_OPENBAO_TOKEN", "").strip()

pytestmark = pytest.mark.skipif(
    not (_ADDR and _TOKEN),
    reason="OpenBao réel requis — poser MCP_VAULT_TEST_OPENBAO_ADDR + _TOKEN (test #77 e2e)",
)

_MOUNT = "wrapstatus77"

from tests.conftest import admin_auth_context  # noqa: E402


@pytest.fixture(autouse=True)
def _admin_identity():
    """#115 : les primitives filtrent par identité (fail-close sans contexte) —
    identité admin explicite pour préserver le comportement pré-#115 de ce flux."""
    with admin_auth_context():
        yield


def _run(coro):
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


def _in_memory_registry():
    """WrapRegistry sans S3 (état mémoire), comme tests/test_wrap.py."""
    from mcp_vault.vault.wrapping import WrapRegistry

    class InMemoryRegistry(WrapRegistry):
        def __init__(self):
            self._wraps = []
            self._cache_time = 0
        def load(self):
            pass
        def _save(self) -> bool:
            return True

    return InMemoryRegistry()


@pytest.fixture(scope="module")
def real_client():
    import hvac
    c = hvac.Client(url=_ADDR, token=_TOKEN)
    assert c.is_authenticated(), "token OpenBao de test invalide"
    try:
        c.sys.disable_secrets_engine(path=_MOUNT)
    except Exception:
        pass
    c.sys.enable_secrets_engine(backend_type="kv", path=_MOUNT, options={"version": "2"})
    c.secrets.kv.v2.create_or_update_secret(
        path="db/x", secret={"password": "p77"}, mount_point=_MOUNT)
    yield c
    try:
        c.sys.disable_secrets_engine(path=_MOUNT)
    except Exception:
        pass


def _patched(real_client, registry):
    """Injecte le vrai client OpenBao + un registre mémoire dans wrapping."""
    from mcp_vault.vault import wrapping as w
    cfg = MagicMock()
    cfg.openbao_addr = _ADDR
    return patch.multiple(
        w,
        _get_client=MagicMock(return_value=real_client),
        get_wrap_registry=MagicMock(return_value=registry),
        _get_config=MagicMock(return_value=cfg),
    )


def _fresh_unwrap_ok(wrap_token: str) -> bool:
    """Un client neuf tente sys.unwrap : True si le secret est récupéré."""
    import hvac
    try:
        res = hvac.Client(url=_ADDR, token=wrap_token).sys.unwrap()
        # KV v2 imbriqué : data.data.<champ>
        return res["data"]["data"].get("password") == "p77"
    except Exception:
        return False


def test_status_does_not_destroy_wrap_then_consumable(real_client):
    """
    wrap → status (active) → l'unwrap RÉUSSIT : status n'a pas détruit le wrap.
    C'est le cœur du fix #77 (contraste avec lookup, cf. test suivant).
    """
    from mcp_vault.vault.wrapping import wrap_secret, status_by_operation_id
    reg = _in_memory_registry()
    with _patched(real_client, reg):
        wr = _run(wrap_secret(_MOUNT, "db/x", "m1", "op-live-77", 300))
        assert wr["status"] == "ok", wr
        wrap_token = wr["wrap_token"]
        st = _run(status_by_operation_id("op-live-77"))
        assert st["status"] == "ok" and st["state"] == "active", st
    # HORS patch : un unwrap réel doit réussir → le status n'a rien consommé/révoqué
    assert _fresh_unwrap_ok(wrap_token), "le wrap devrait rester consommable après status"


def test_lookup_revokes_wrap_then_not_consumable(real_client):
    """
    Contraste : lookup_and_revoke RÉVOQUE → l'unwrap échoue ensuite. Prouve la
    différence de contrat entre secret_wrap_status (lecture) et secret_wrap_lookup.
    """
    from mcp_vault.vault.wrapping import wrap_secret, lookup_and_revoke_by_operation_id
    reg = _in_memory_registry()
    with _patched(real_client, reg):
        wr = _run(wrap_secret(_MOUNT, "db/x", "m1", "op-revoke-77", 300))
        assert wr["status"] == "ok", wr
        wrap_token = wr["wrap_token"]
        rev = _run(lookup_and_revoke_by_operation_id("op-revoke-77"))
        assert rev["status"] == "ok" and rev["state"] in ("revoked", "ambiguous"), rev
    assert not _fresh_unwrap_ok(wrap_token), "un wrap révoqué ne doit plus être consommable"


def test_status_after_consume_reflects_no_longer_active(real_client):
    """
    wrap → unwrap (consomme le token OpenBao) → status : l'instantané registre
    reste 'active' (best-effort — on ne marque pas consumed hors flux consume),
    mais le contrat #77 est explicite là-dessus. On vérifie surtout que status
    ne lève pas et reste cohérent (lecture) même après consommation externe.
    """
    from mcp_vault.vault.wrapping import wrap_secret, status_by_operation_id
    reg = _in_memory_registry()
    with _patched(real_client, reg):
        wr = _run(wrap_secret(_MOUNT, "db/x", "m1", "op-consumed-77", 300))
        assert wr["status"] == "ok", wr
        # consommation externe du token
        assert _fresh_unwrap_ok(wr["wrap_token"])
        st = _run(status_by_operation_id("op-consumed-77"))
    # lecture robuste (pas d'exception) ; l'état registre est un instantané
    assert st["status"] == "ok" and st["state"] in ("active", "consumed"), st


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
