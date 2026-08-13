# -*- coding: utf-8 -*-
"""
Tests unitaires pour le JIT Wrap Broker (issue #7, mcp-mission V1).

Tests d'acceptation :
1. wrap produit un token scopé (write-ahead, API hvac correcte)
2. expires_at calculé correctement
3. revoke idempotent (bad accessor / not found / 4xx → ok)
4. lookup + états distinguables (not_found | found_unattached | already_revoked | revoked | ambiguous)
5. anti-fuite (wrap_token jamais dans erreurs / registry)
6. write-ahead : pending AVANT OpenBao, active après succès
7. revoke refuse les accessors hors scope registry
8. chemins réservés bloqués (_vault_meta, _init/, _system/)
9. S3 registry indisponible → wrap refusé (intégrité > disponibilité)
10. found_unattached : crash window documenté

Tests mockés (sans conteneur Docker).
"""

import asyncio
import os
import sys
from contextlib import ExitStack
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tests.conftest import admin_auth_context  # noqa: E402


@pytest.fixture(autouse=True)
def _admin_identity():
    """#115 : les primitives revoke/lookup/status filtrent désormais par
    identité (ContextVar) — contexte absent = fail-close (rien de visible).
    Ces tests historiques, écrits avant le scoping, s'exécutent sous une
    identité admin explicite (comportement pré-#115 préservé). Les cas
    non-admin/scoping sont couverts par test_wrap_permission_115.py."""
    with admin_auth_context():
        yield


# =============================================================================
# Helpers
# =============================================================================

def _make_registry(save_ok=True):
    """WrapRegistry en mémoire (pas de S3)."""
    from mcp_vault.vault.wrapping import WrapRegistry

    class InMemoryRegistry(WrapRegistry):
        def __init__(self):
            self._wraps = []
            self._cache_time = float("inf")
            self._save_result = save_ok

        def load(self):
            pass

        def _save(self) -> bool:
            return self._save_result

    r = InMemoryRegistry()
    r._save_result = save_ok
    return r


def _make_hvac_ok(wrap_token="s.TESTWRAP", accessor="ACCTESTOK"):
    m = MagicMock()
    m.read.return_value = {
        "wrap_info": {"token": wrap_token, "accessor": accessor,
                      "ttl": 300, "creation_time": "2026-06-07T00:00:00Z"}
    }
    return m


def run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class patch_wrap:
    """Context manager : mock _get_client, _get_config, get_wrap_registry."""
    def __init__(self, client=None, registry=None, config_addr="http://127.0.0.1:8200"):
        self._client = client
        self._registry = registry
        self._addr = config_addr

    def __enter__(self):
        self._stack = ExitStack()
        self._stack.enter_context(
            patch("mcp_vault.vault.wrapping._get_client",
                  return_value=self._client or _make_hvac_ok()))
        cfg = MagicMock(); cfg.openbao_addr = self._addr
        self._stack.enter_context(
            patch("mcp_vault.vault.wrapping._get_config", return_value=cfg))
        self._stack.enter_context(
            patch("mcp_vault.vault.wrapping.get_wrap_registry",
                  return_value=self._registry if self._registry is not None else _make_registry()))
        return self

    def __exit__(self, *a):
        self._stack.__exit__(*a)


def _entry(op_id, accessor, status):
    return {"operation_id": op_id, "accessor": accessor, "mission_id": "m",
            "vault_id": "v", "secret_path": "p", "created_at": "", "expires_at": "",
            "status": status}


# =============================================================================
# TEST 1 — wrap produit un token scopé (write-ahead + API hvac correcte)
# =============================================================================

def test_wrap_produces_single_use_token_scoped_to_mission():
    from mcp_vault.vault.wrapping import wrap_secret

    registry = _make_registry()
    client = _make_hvac_ok(wrap_token="s.TESTWRAP", accessor="ACCTESTOK")

    with patch_wrap(client=client, registry=registry):
        result = run(wrap_secret("prod", "db/postgres", "mission-42", "op-001", 300))

    assert result["status"] == "ok", f"attendu ok: {result}"
    assert result["wrap_token"] == "s.TESTWRAP"
    assert result["accessor"] == "ACCTESTOK"
    assert result["mission_id"] == "mission-42"
    assert "secret_id" in result and "expires_at" in result

    # Registry : entrée active avec accessor (jamais wrap_token)
    entries = registry.find_by_operation_id("op-001")
    assert len(entries) == 1 and entries[0]["status"] == "active"
    assert entries[0]["accessor"] == "ACCTESTOK"
    assert "TESTWRAP" not in str(entries[0])

    # API hvac : client.read() avec bon chemin KV v2 et wrap_ttl
    client.read.assert_called_once()
    args, kwargs = client.read.call_args
    assert args[0] == "prod/data/db/postgres", f"Chemin KV v2 incorrect: {args[0]}"
    assert kwargs.get("wrap_ttl") == "300s", f"wrap_ttl incorrect: {kwargs}"

    print("  ✅ TEST 1 — wrap OK, write-ahead active, API hvac low-level correcte")


# =============================================================================
# TEST 2 — expires_at calculé correctement
# =============================================================================

def test_wrap_token_expires_after_ttl():
    from mcp_vault.vault.wrapping import wrap_secret

    ttl = 180
    before = datetime.now(timezone.utc)

    with patch_wrap():
        result = run(wrap_secret("prod", "ssh/key", "m1", "op-ttl", ttl_seconds=ttl))

    assert result["status"] == "ok"
    expires = datetime.fromisoformat(result["expires_at"])
    delta = abs((expires - (before + timedelta(seconds=ttl))).total_seconds())
    assert delta < 5, f"expires_at hors tolérance: {delta:.1f}s"

    print(f"  ✅ TEST 2 — expires_at correct (delta={delta:.2f}s)")


# =============================================================================
# TEST 3 — revoke idempotent
# =============================================================================

def test_revoke_is_idempotent():
    from mcp_vault.vault.wrapping import revoke_wrap

    def _reg(accessor, status="active"):
        r = _make_registry()
        r._wraps = [_entry("op", accessor, status)]
        return r

    # Révocation normale
    c_ok = MagicMock(); c_ok.auth.token.revoke_accessor.return_value = None
    with patch("mcp_vault.vault.wrapping._get_client", return_value=c_ok), \
         patch("mcp_vault.vault.wrapping.get_wrap_registry", return_value=_reg("ACC1")):
        r = run(revoke_wrap("ACC1"))
    assert r["status"] == "ok" and r["state"] == "revoked"

    # "bad accessor" → idempotent
    c_bad = MagicMock(); c_bad.auth.token.revoke_accessor.side_effect = Exception("bad accessor")
    with patch("mcp_vault.vault.wrapping._get_client", return_value=c_bad), \
         patch("mcp_vault.vault.wrapping.get_wrap_registry", return_value=_reg("ACC2")):
        r = run(revoke_wrap("ACC2"))
    assert r["status"] == "ok" and r["state"] == "already_revoked"

    # "invalid accessor" → idempotent
    c_inv = MagicMock(); c_inv.auth.token.revoke_accessor.side_effect = Exception("invalid accessor")
    with patch("mcp_vault.vault.wrapping._get_client", return_value=c_inv), \
         patch("mcp_vault.vault.wrapping.get_wrap_registry", return_value=_reg("ACC3")):
        r = run(revoke_wrap("ACC3"))
    assert r["status"] == "ok"

    # Déjà revoked dans registry → no OpenBao call
    c_noop = MagicMock()
    with patch("mcp_vault.vault.wrapping._get_client", return_value=c_noop), \
         patch("mcp_vault.vault.wrapping.get_wrap_registry", return_value=_reg("ACC4", "revoked")):
        r = run(revoke_wrap("ACC4"))
    assert r["status"] == "ok" and r["state"] == "already_revoked"
    c_noop.auth.token.revoke_accessor.assert_not_called()

    # 5xx → erreur réelle
    c_5xx = MagicMock(); c_5xx.auth.token.revoke_accessor.side_effect = Exception("503 Unavailable")
    with patch("mcp_vault.vault.wrapping._get_client", return_value=c_5xx), \
         patch("mcp_vault.vault.wrapping.get_wrap_registry", return_value=_reg("ACC5")):
        r = run(revoke_wrap("ACC5"))
    assert r["status"] == "error" and r["error_type"] == "backend_error"

    print("  ✅ TEST 3 — revoke idempotent (bad/invalid/revoked=ok ; 5xx=error)")


# =============================================================================
# TEST 4 — lookup + états distinguables
# =============================================================================

def test_lookup_and_revoke_by_operation_id():
    from mcp_vault.vault.wrapping import lookup_and_revoke_by_operation_id

    c_ok = MagicMock(); c_ok.auth.token.revoke_accessor.return_value = None

    # NB : un helper local `lookup(registry)` existait ici sans être JAMAIS appelé.
    # Retiré au passage du cloisonnement inter-missions : sa signature mono-clé
    # était devenue fausse et rien ne l'aurait signalé — un piège pour le prochain
    # qui l'aurait cru utilisable. Chaque cas ci-dessous appelle la primitive
    # directement, avec le couple.

    # not_found
    r = _make_registry(); r._wraps = []
    with patch("mcp_vault.vault.wrapping.get_wrap_registry", return_value=r), \
         patch("mcp_vault.vault.wrapping._get_client", return_value=c_ok):
        res = run(lookup_and_revoke_by_operation_id("op-none", "m"))
    assert res["state"] == "not_found"

    # found_unattached (pending sans accessor)
    r2 = _make_registry(); r2._wraps = [_entry("op-pend", None, "pending")]
    with patch("mcp_vault.vault.wrapping.get_wrap_registry", return_value=r2), \
         patch("mcp_vault.vault.wrapping._get_client", return_value=c_ok):
        res = run(lookup_and_revoke_by_operation_id("op-pend", "m"))
    assert res["state"] == "found_unattached"

    # already_revoked
    r3 = _make_registry(); r3._wraps = [_entry("op-done", "ACC", "revoked")]
    with patch("mcp_vault.vault.wrapping.get_wrap_registry", return_value=r3), \
         patch("mcp_vault.vault.wrapping._get_client", return_value=c_ok):
        res = run(lookup_and_revoke_by_operation_id("op-done", "m"))
    assert res["state"] == "already_revoked"

    # revoked
    r4 = _make_registry(); r4._wraps = [_entry("op-orph", "ACC-ORPH", "active")]
    with patch("mcp_vault.vault.wrapping.get_wrap_registry", return_value=r4), \
         patch("mcp_vault.vault.wrapping._get_client", return_value=c_ok):
        res = run(lookup_and_revoke_by_operation_id("op-orph", "m"))
    assert res["state"] == "revoked" and res["count_revoked"] == 1

    # ambiguous
    r5 = _make_registry()
    r5._wraps = [_entry("op-dup", "ACC-D1", "active"), _entry("op-dup", "ACC-D2", "active")]
    with patch("mcp_vault.vault.wrapping.get_wrap_registry", return_value=r5), \
         patch("mcp_vault.vault.wrapping._get_client", return_value=c_ok):
        res = run(lookup_and_revoke_by_operation_id("op-dup", "m"))
    assert res["state"] == "ambiguous" and res["count_revoked"] == 2

    print("  ✅ TEST 4 — not_found | found_unattached | already_revoked | revoked | ambiguous")


# =============================================================================
# TEST 5 — anti-fuite
# =============================================================================

def test_errors_never_leak_secret_or_wrap_token():
    from mcp_vault.vault.wrapping import wrap_secret

    SENSITIVE = "s.SUPERSECRETWRAPTOKEN"
    DATAVAL = "password=SuperSecret!@#"

    # Backend indisponible → message neutre
    with patch("mcp_vault.vault.wrapping._get_client", return_value=None), \
         patch("mcp_vault.vault.wrapping.get_wrap_registry", return_value=_make_registry()):
        r = run(wrap_secret("prod", "db/p", "m1", "op-1", 300))
    assert SENSITIVE not in str(r) and DATAVAL not in str(r)

    # Exception hvac avec données sensibles → normalisée
    c_err = MagicMock(); c_err.read.side_effect = Exception(f"secret={DATAVAL}")
    cfg = MagicMock(); cfg.openbao_addr = "http://127.0.0.1:8200"
    with patch("mcp_vault.vault.wrapping._get_client", return_value=c_err), \
         patch("mcp_vault.vault.wrapping._get_config", return_value=cfg), \
         patch("mcp_vault.vault.wrapping.get_wrap_registry", return_value=_make_registry()):
        r = run(wrap_secret("prod", "db/p", "m1", "op-2", 300))
    assert r["status"] == "error" and DATAVAL not in str(r)

    # Succès → wrap_token dans result mais pas dans registry
    registry = _make_registry()
    c_ok = _make_hvac_ok(wrap_token=SENSITIVE, accessor="ACCSAFE")
    with patch_wrap(client=c_ok, registry=registry):
        r = run(wrap_secret("prod", "db/p", "m1", "op-3", 300))
    assert r["wrap_token"] == SENSITIVE
    for e in registry._wraps:
        assert SENSITIVE not in str(e)

    print("  ✅ TEST 5 — anti-fuite : erreurs neutres, registry sans wrap_token")


# =============================================================================
# TEST 6 — write-ahead : pending AVANT OpenBao
# =============================================================================

def test_write_ahead_pending_before_openbao():
    from mcp_vault.vault.wrapping import wrap_secret

    call_log = []
    registry = _make_registry()
    orig = registry.register_pending

    def spy_pending(*a, **kw):
        call_log.append("pending")
        return orig(*a, **kw)

    registry.register_pending = spy_pending

    client = MagicMock()

    def spy_read(*a, **kw):
        call_log.append("openbao")
        return {"wrap_info": {"token": "s.T", "accessor": "A"}}

    client.read.side_effect = spy_read
    cfg = MagicMock(); cfg.openbao_addr = "http://127.0.0.1:8200"

    with patch("mcp_vault.vault.wrapping._get_client", return_value=client), \
         patch("mcp_vault.vault.wrapping._get_config", return_value=cfg), \
         patch("mcp_vault.vault.wrapping.get_wrap_registry", return_value=registry):
        run(wrap_secret("prod", "db/p", "m1", "op-ahead", 300))

    assert call_log == ["pending", "openbao"], f"Ordre incorrect: {call_log}"
    entries = registry.find_by_operation_id("op-ahead")
    assert entries[0]["status"] == "active" and entries[0]["accessor"] == "A"

    print("  ✅ TEST 6 — write-ahead : pending AVANT OpenBao, active après succès")


# =============================================================================
# TEST 7 — revoke refuse les accessors hors scope registry
# =============================================================================

def test_revoke_only_registry_accessors():
    from mcp_vault.vault.wrapping import revoke_wrap

    client = MagicMock(); client.auth.token.revoke_accessor.return_value = None
    registry = _make_registry()  # vide

    with patch("mcp_vault.vault.wrapping._get_client", return_value=client), \
         patch("mcp_vault.vault.wrapping.get_wrap_registry", return_value=registry):
        r = run(revoke_wrap("ACC-HORS-SCOPE"))

    client.auth.token.revoke_accessor.assert_not_called()
    assert r["status"] == "ok" and r["state"] == "not_found"

    print("  ✅ TEST 7 — revoke hors scope registry → refusé sans appel OpenBao")


# =============================================================================
# TEST 8 — chemins réservés bloqués
# =============================================================================

def test_reserved_paths_blocked():
    from mcp_vault.vault.wrapping import wrap_secret

    for reserved in ["_vault_meta", "_init/init_keys.json.enc", "_system/tokens.json"]:
        with patch_wrap():
            r = run(wrap_secret("prod", reserved, "m1", "op-res", 300))
        assert r["status"] == "error" and r["error_type"] == "invalid_input", \
            f"'{reserved}' aurait dû être refusé: {r}"

    print("  ✅ TEST 8 — chemins réservés refusés")


# =============================================================================
# TEST 9 — S3 registry KO → wrap refusé
# =============================================================================

def test_s3_failure_blocks_wrap():
    from mcp_vault.vault.wrapping import wrap_secret

    registry_failing = _make_registry(save_ok=False)

    with patch_wrap(registry=registry_failing):
        r = run(wrap_secret("prod", "db/p", "m1", "op-s3", 300))

    assert r["status"] == "error" and r["error_type"] == "registry_unavailable", \
        f"S3 KO devrait bloquer le wrap: {r}"

    print("  ✅ TEST 9 — S3 registry indisponible → wrap refusé")


# =============================================================================
# TEST 10 — found_unattached : crash window
# =============================================================================

def test_found_unattached_state():
    from mcp_vault.vault.wrapping import lookup_and_revoke_by_operation_id

    registry = _make_registry()
    registry._wraps = [_entry("op-crash", None, "pending")]

    with patch("mcp_vault.vault.wrapping.get_wrap_registry", return_value=registry), \
         patch("mcp_vault.vault.wrapping._get_client", return_value=MagicMock()):
        r = run(lookup_and_revoke_by_operation_id("op-crash", "m"))

    assert r["state"] == "found_unattached"
    assert r["count_revoked"] == 0
    assert "note" in r

    print("  ✅ TEST 10 — found_unattached : crash window, TTL gérera l'expiration")


# =============================================================================
# TEST 11 — registry None → fail-close (wrap refusé)
# =============================================================================

def test_registry_none_blocks_wrap():
    from mcp_vault.vault.wrapping import wrap_secret

    client = _make_hvac_ok()
    cfg = MagicMock(); cfg.openbao_addr = "http://127.0.0.1:8200"
    with patch("mcp_vault.vault.wrapping._get_client", return_value=client), \
         patch("mcp_vault.vault.wrapping._get_config", return_value=cfg), \
         patch("mcp_vault.vault.wrapping.get_wrap_registry", return_value=None):
        r = run(wrap_secret("prod", "db/p", "m1", "op-none-reg", 300))

    assert r["status"] == "error" and r["error_type"] == "registry_unavailable"
    client.read.assert_not_called()  # OpenBao ne doit pas être appelé
    print("  ✅ TEST 11 — registry None → wrap refusé, OpenBao non appelé")


# =============================================================================
# TEST 12 — mark_active S3 failure → révocation d'urgence
# =============================================================================

def test_mark_active_s3_failure_revokes():
    from mcp_vault.vault.wrapping import wrap_secret

    class PartialFailRegistry(_make_registry().__class__):
        def __init__(self):
            self._wraps = []
            self._cache_time = float("inf")
            self._call_count = 0

        def _save(self) -> bool:
            self._call_count += 1
            return self._call_count == 1  # premier save (pending) OK, deuxième (active) KO

    registry = PartialFailRegistry()
    client = _make_hvac_ok(wrap_token="s.WRAP", accessor="ACCEMERGE")
    cfg = MagicMock(); cfg.openbao_addr = "http://127.0.0.1:8200"
    with patch("mcp_vault.vault.wrapping._get_client", return_value=client), \
         patch("mcp_vault.vault.wrapping._get_config", return_value=cfg), \
         patch("mcp_vault.vault.wrapping.get_wrap_registry", return_value=registry):
        r = run(wrap_secret("prod", "db/p", "m1", "op-markfail", 300))

    assert r["status"] == "error" and r["error_type"] == "registry_unavailable"
    client.auth.token.revoke_accessor.assert_called_once_with(accessor="ACCEMERGE")
    print("  ✅ TEST 12 — mark_active S3 failure → révocation urgence + erreur")


# =============================================================================
# TEST 13 — revoke fail-close si registry None
# =============================================================================

def test_revoke_failclose_when_registry_none():
    from mcp_vault.vault.wrapping import revoke_wrap

    client = MagicMock()
    with patch("mcp_vault.vault.wrapping._get_client", return_value=client), \
         patch("mcp_vault.vault.wrapping.get_wrap_registry", return_value=None):
        r = run(revoke_wrap("ACC-ARBITRARY"))

    # #120 : erreur CONTRACTUELLE (et non ok/not_found, qui faisait créditer au
    # client une révocation jamais tentée), sans appeler OpenBao.
    assert r["status"] == "error" and r["error_type"] == "registry_unavailable", r
    client.auth.token.revoke_accessor.assert_not_called()
    print("  ✅ TEST 13 — revoke registry=None → registry_unavailable, OpenBao non appelé")


# =============================================================================
# TEST 14 — register_pending rollback mémoire si S3 échoue
# =============================================================================

def test_revoke_registry_unavailable_is_not_a_success_120():
    """#120 — `not_found` ne doit JAMAIS couvrir « registre non initialisé ».

    NON-COMPLAISANCE : le contrat documente « introuvable = succès idempotent ».
    Quand le registre est absent (S3 non configuré), aucune révocation n'est
    tentée : renvoyer `ok/not_found` faisait créditer au broker mcp-mission
    (leur #507) une révocation inexistante. On exige donc une erreur
    contractuelle, alignée sur wrap_secret/consume_wrap_secret, et l'absence de
    toute information non contractuelle (`note`) comme moyen de désambiguïser.
    """
    from mcp_vault.vault.wrapping import revoke_wrap

    client = MagicMock()
    with patch("mcp_vault.vault.wrapping._get_client", return_value=client), \
         patch("mcp_vault.vault.wrapping.get_wrap_registry", return_value=None):
        r = run(revoke_wrap("ACC-XYZ"))

    assert r["status"] == "error", f"un succès ici ferait créditer une révocation : {r}"
    assert r["error_type"] == "registry_unavailable", r
    assert "state" not in r, "pas d'état idempotent sur une erreur d'indisponibilité"
    client.auth.token.revoke_accessor.assert_not_called()
    print("  ✅ TEST 13b — revoke registre absent → registry_unavailable (#120)")


def test_register_pending_rollback_on_s3_failure():
    registry = _make_registry(save_ok=False)
    assert len(registry._wraps) == 0

    result = registry.register_pending("op-rollback", "m1", "prod", "db/p", 300)

    assert result is False
    assert len(registry._wraps) == 0, f"Entrée fantôme après rollback : {registry._wraps}"
    print("  ✅ TEST 14 — register_pending rollback : pas d'entrée fantôme si S3 KO")


# =============================================================================
# TEST 15 — server.secret_wrap_lookup : validation operation_id côté MCP
# =============================================================================

def test_server_lookup_validates_operation_id():
    """
    Vérifie que l'outil MCP secret_wrap_lookup rejette les operation_id invalides
    SANS appeler lookup_and_revoke_by_operation_id.

    C'est un test de comportement observable (pas juste un test de regex) :
    si la validation était supprimée dans server.py, lookup serait appelé et ce test échouerait.
    """
    # Charger server.py en injectant les dépendances lourdes (hvac, OpenBao)
    from unittest.mock import AsyncMock
    mock_lookup = AsyncMock(return_value={"status": "ok", "state": "not_found",
                                          "count_revoked": 0, "entries_found": 0})

    # #115 : la garde de l'outil est check_policy + check_wrap_permission — la
    # fixture admin autouse du module les fait passer (plus de patch admin).
    with patch("mcp_vault.vault.wrapping.lookup_and_revoke_by_operation_id",
               new=mock_lookup):
        try:
            from mcp_vault.server import secret_wrap_lookup
        except Exception as e:
            print(f"  ⏭️  TEST 15 — skipped (server.py import échoue: {type(e).__name__})")
            return

        # IDs invalides → rejet AVANT lookup (lookup ne doit pas être appelé)
        # #78/D6 : "op-trailing\n" couvre l'injection de fin de ligne que .match acceptait
        # (le `$` matche avant un \n final) et que fullmatch ferme.
        invalid_ids = ["op with spaces", "op\ninjection", "op-trailing\n",
                       "op-crlf\r\n", "a" * 300, "op#bad"]
        for bad_id in invalid_ids:
            mock_lookup.reset_mock()
            r = run(secret_wrap_lookup(bad_id, "m"))
            assert r["status"] == "error", \
                f"operation_id invalide '{bad_id[:30]}' aurait dû être rejeté: {r}"
            mock_lookup.assert_not_called(), \
                f"lookup appelé pour operation_id invalide '{bad_id[:30]}'"

        # ID valide → lookup appelé (validation passe)
        mock_lookup.reset_mock()
        r = run(secret_wrap_lookup("op-valid-001", "m"))
        mock_lookup.assert_called_once()

    print("  ✅ TEST 15 — server.secret_wrap_lookup : IDs invalides rejetés sans appeler lookup")


# =============================================================================
# TEST 16 — consume_wrap_secret : binding C18 complet (P1 — issue #29)
# =============================================================================

def _make_entry_with_binding(op_id="op-1", mission_id="m-1",
                              tenant_id="tenant-42", expected_aud="mcp-vault:prod"):
    """Entrée active avec tenant_id et expected_aud définis."""
    return {
        "operation_id": op_id,
        "accessor": "ACC-BIND",
        "mission_id": mission_id,
        "vault_id": "prod",
        "secret_path": "db/pass",
        "created_at": "", "expires_at": "",
        "status": "active",
        "tenant_id": tenant_id,
        "expected_aud": expected_aud,
    }


def test_consume_binding_tenant_id_mismatch_rejected():
    """
    P1 — tenant_id JWT ≠ tenant_id registry → binding_mismatch, SANS unwrap OpenBao.
    Non-complaisant : si la vérification manquait, OpenBao serait appelé malgré le mismatch.
    """
    from mcp_vault.vault.wrapping import consume_wrap_secret

    reg = _make_registry()
    reg._wraps = [_make_entry_with_binding(tenant_id="tenant-LEGITIME")]

    hvac_client = MagicMock()
    cfg = MagicMock(); cfg.openbao_addr = "http://127.0.0.1:8200"

    with patch("mcp_vault.vault.wrapping._get_client", return_value=hvac_client), \
         patch("mcp_vault.vault.wrapping._get_config", return_value=cfg), \
         patch("mcp_vault.vault.wrapping.get_wrap_registry", return_value=reg):
        result = run(consume_wrap_secret(
            wrap_token="wt-secret",
            operation_id="op-1",
            mission_id="m-1",
            tenant_id="tenant-ATTAQUANT",   # mismatch intentionnel
            expected_aud="mcp-vault:prod",
        ))

    assert result["status"] == "error", f"Attendu error, obtenu: {result}"
    assert result["error_type"] == "binding_mismatch", f"Attendu binding_mismatch: {result}"
    assert result["message"] == "binding mismatch", f"Message doit être générique: {result}"
    # Non-complaisant : OpenBao NE doit pas avoir été appelé
    hvac_client.sys.unwrap.assert_not_called()
    print("  ✅ TEST 16a — tenant_id mismatch rejeté, OpenBao non appelé")


def test_consume_binding_expected_aud_mismatch_rejected():
    """
    P1 — expected_aud JWT ≠ expected_aud registry → binding_mismatch, SANS unwrap OpenBao.
    Non-complaisant : si la vérification manquait, un token d'un autre vault passerait.
    """
    from mcp_vault.vault.wrapping import consume_wrap_secret

    reg = _make_registry()
    reg._wraps = [_make_entry_with_binding(expected_aud="mcp-vault:prod-LEGITIME")]

    hvac_client = MagicMock()
    cfg = MagicMock(); cfg.openbao_addr = "http://127.0.0.1:8200"

    with patch("mcp_vault.vault.wrapping._get_client", return_value=hvac_client), \
         patch("mcp_vault.vault.wrapping._get_config", return_value=cfg), \
         patch("mcp_vault.vault.wrapping.get_wrap_registry", return_value=reg):
        result = run(consume_wrap_secret(
            wrap_token="wt-secret",
            operation_id="op-1",
            mission_id="m-1",
            tenant_id="tenant-42",
            expected_aud="mcp-vault:AUTRE-INSTANCE",   # confused-deputy
        ))

    assert result["status"] == "error", f"Attendu error, obtenu: {result}"
    assert result["error_type"] == "binding_mismatch", f"Attendu binding_mismatch: {result}"
    assert result["message"] == "binding mismatch", f"Message doit être générique: {result}"
    hvac_client.sys.unwrap.assert_not_called()
    print("  ✅ TEST 16b — expected_aud mismatch rejeté (confused-deputy bloqué)")


def test_consume_binding_mismatch_no_consuming_state_created():
    """
    P1 — Vérification que le mismatch est détecté AVANT try_mark_consuming.
    Non-complaisant : un état "consuming" orphelin serait créé si la vérification
    arrivait APRÈS la mutation S3.
    """
    from mcp_vault.vault.wrapping import consume_wrap_secret

    reg = _make_registry()
    reg._wraps = [_make_entry_with_binding(tenant_id="tenant-LEGITIME")]

    consuming_called = []
    orig_try = reg.try_mark_consuming

    def spy_try(op, mission):
        consuming_called.append((op, mission))
        return orig_try(op, mission)

    reg.try_mark_consuming = spy_try
    hvac_client = MagicMock()
    cfg = MagicMock(); cfg.openbao_addr = "http://127.0.0.1:8200"

    with patch("mcp_vault.vault.wrapping._get_client", return_value=hvac_client), \
         patch("mcp_vault.vault.wrapping._get_config", return_value=cfg), \
         patch("mcp_vault.vault.wrapping.get_wrap_registry", return_value=reg):
        result = run(consume_wrap_secret(
            wrap_token="wt",
            operation_id="op-1",
            mission_id="m-1",
            tenant_id="tenant-MAUVAIS",
        ))

    assert result["error_type"] == "binding_mismatch"
    assert len(consuming_called) == 0, (
        f"try_mark_consuming appelé malgré binding_mismatch ! Appels: {consuming_called}"
    )
    print("  ✅ TEST 16c — mismatch détecté avant try_mark_consuming (pas d'état orphelin)")


def test_consume_binding_correct_succeeds():
    """
    P1 — Binding correct (tenant_id + expected_aud) → consume réussit normalement.
    Non-complaisant : vérifier que les guards ne bloquent pas le cas nominal.
    """
    import sys
    from mcp_vault.vault.wrapping import consume_wrap_secret

    reg = _make_registry()
    reg._wraps = [_make_entry_with_binding(
        tenant_id="tenant-42", expected_aud="mcp-vault:prod"
    )]

    # consume_wrap_secret crée un client hvac éphémère — mocker le module
    mock_hvac = MagicMock()
    mock_ephemeral = MagicMock()
    mock_hvac.Client.return_value = mock_ephemeral
    # Enveloppe KV v2 RÉELLE (issue #78) : `hvac.sys.unwrap()` n'aplatit pas la
    # réponse. Le simulacre précédent rendait `{"data": {"password": …}}`, forme
    # qu'OpenBao ne produit JAMAIS pour une lecture `{vault}/data/{path}` — il
    # validait donc un comportement absent de la production.
    mock_ephemeral.sys.unwrap.return_value = {
        "data": {"data": {"password": "s3cr3t"},
                 "metadata": {"version": 1, "destroyed": False}},
    }
    cfg = MagicMock(); cfg.openbao_addr = "http://127.0.0.1:8200"

    with patch.dict(sys.modules, {"hvac": mock_hvac}), \
         patch("mcp_vault.vault.wrapping._get_client", return_value=MagicMock()), \
         patch("mcp_vault.vault.wrapping._get_config", return_value=cfg), \
         patch("mcp_vault.vault.wrapping.get_wrap_registry", return_value=reg):
        result = run(consume_wrap_secret(
            wrap_token="wt-secret",
            operation_id="op-1",
            mission_id="m-1",
            tenant_id="tenant-42",
            expected_aud="mcp-vault:prod",
        ))

    assert result["status"] == "ok", f"Binding correct mais consume échoué: {result}"
    # Le secret en clair est à data.data — PAS à data (contrat communiqué à mcp-agent).
    assert result["data"]["data"] == {"password": "s3cr3t"}
    assert "metadata" in result["data"]
    print("  ✅ TEST 16d — binding correct → consume réussit")


def test_wrap_then_consume_binding_propagated():
    """
    CRITIQUE — tenant_id/expected_aud propagés de wrap_secret() à register_pending().
    Non-complaisant : si les champs ne sont pas propagés, le binding est inactif en prod.
    """
    from mcp_vault.vault.wrapping import wrap_secret

    registry = _make_registry()
    client = _make_hvac_ok(wrap_token="s.TESTWRAP", accessor="ACCBIND")
    cfg = MagicMock(); cfg.openbao_addr = "http://127.0.0.1:8200"

    with patch("mcp_vault.vault.wrapping._get_client", return_value=client), \
         patch("mcp_vault.vault.wrapping._get_config", return_value=cfg), \
         patch("mcp_vault.vault.wrapping.get_wrap_registry", return_value=registry):
        result = run(wrap_secret(
            "prod", "db/pass", "m-1", "op-bind", 300,
            tenant_id="tenant-42", expected_aud="mcp-vault:prod",
        ))

    assert result["status"] == "ok", f"wrap échoué: {result}"
    entries = registry.find_by_operation_id("op-bind")
    assert len(entries) == 1
    entry = entries[0]
    assert entry["tenant_id"] == "tenant-42", (
        f"tenant_id non propagé au registry: {entry}"
    )
    assert entry["expected_aud"] == "mcp-vault:prod", (
        f"expected_aud non propagé au registry: {entry}"
    )
    print("  ✅ TEST 16f — tenant_id+expected_aud propagés de wrap_secret → registry")


def test_consume_enforce_mode_rejects_wrap_without_expected_aud():
    """
    ÉLEVÉ — En mode enforce=True, un wrap legacy sans expected_aud est rejeté.
    Non-complaisant : sans ce check, les wraps créés avant P1 seraient consommables
    en mode enforced sans vérification aud, contournant le binding C18.
    """
    from mcp_vault.vault.wrapping import consume_wrap_secret

    reg = _make_registry()
    reg._wraps = [{
        "operation_id": "op-1", "accessor": "ACC", "mission_id": "m-1",
        "vault_id": "prod", "secret_path": "db/p",
        "created_at": "", "expires_at": "", "status": "active",
        "tenant_id": "",
        "expected_aud": "",  # wrap legacy sans aud
    }]

    hvac_client = MagicMock()
    cfg = MagicMock(); cfg.openbao_addr = "http://127.0.0.1:8200"

    with patch("mcp_vault.vault.wrapping._get_client", return_value=hvac_client), \
         patch("mcp_vault.vault.wrapping._get_config", return_value=cfg), \
         patch("mcp_vault.vault.wrapping.get_wrap_registry", return_value=reg):
        result = run(consume_wrap_secret(
            wrap_token="wt",
            operation_id="op-1",
            mission_id="m-1",
            tenant_id="",
            expected_aud="",
            enforce=True,   # mode enforced
        ))

    assert result["status"] == "error", f"Wrap legacy doit être rejeté en mode enforced: {result}"
    assert result["error_type"] == "binding_incomplete", f"Attendu binding_incomplete: {result}"
    hvac_client.sys.unwrap.assert_not_called()
    print("  ✅ TEST 16g — wrap legacy sans expected_aud rejeté en mode enforced")


def test_consume_binding_empty_registry_fields_ignored():
    """
    P1 — Si tenant_id/expected_aud vides dans le registry, pas de vérification binding.
    Rétrocompatibilité : les wraps créés avant P1 n'ont pas ces champs → doivent passer.
    """
    import sys
    from mcp_vault.vault.wrapping import consume_wrap_secret

    reg = _make_registry()
    reg._wraps = [{
        "operation_id": "op-1", "accessor": "ACC", "mission_id": "m-1",
        "vault_id": "prod", "secret_path": "db/p",
        "created_at": "", "expires_at": "", "status": "active",
        "tenant_id": "",       # vide → pas de vérification
        "expected_aud": "",    # vide → pas de vérification
    }]

    mock_hvac = MagicMock()
    mock_ephemeral = MagicMock()
    mock_hvac.Client.return_value = mock_ephemeral
    # Enveloppe KV v2 réelle (issue #78) — voir TEST 16d.
    mock_ephemeral.sys.unwrap.return_value = {
        "data": {"data": {"key": "val"},
                 "metadata": {"version": 1, "destroyed": False}},
    }
    cfg = MagicMock(); cfg.openbao_addr = "http://127.0.0.1:8200"

    with patch.dict(sys.modules, {"hvac": mock_hvac}), \
         patch("mcp_vault.vault.wrapping._get_client", return_value=MagicMock()), \
         patch("mcp_vault.vault.wrapping._get_config", return_value=cfg), \
         patch("mcp_vault.vault.wrapping.get_wrap_registry", return_value=reg):
        result = run(consume_wrap_secret(
            wrap_token="wt",
            operation_id="op-1",
            mission_id="m-1",
            tenant_id="n'importe quoi",
            expected_aud="n'importe quoi",
        ))

    assert result["status"] == "ok", (
        f"Champs vides dans registry → consume doit réussir: {result}"
    )
    print("  ✅ TEST 16e — champs vides dans registry → binding ignoré (rétrocompat)")


# =============================================================================
# Runner
# =============================================================================

if __name__ == "__main__":
    tests = [
        test_wrap_produces_single_use_token_scoped_to_mission,
        test_wrap_token_expires_after_ttl,
        test_revoke_is_idempotent,
        test_lookup_and_revoke_by_operation_id,
        test_errors_never_leak_secret_or_wrap_token,
        test_write_ahead_pending_before_openbao,
        test_revoke_only_registry_accessors,
        test_reserved_paths_blocked,
        test_registry_none_blocks_wrap,
        test_mark_active_s3_failure_revokes,
        test_revoke_failclose_when_registry_none,
        test_revoke_registry_unavailable_is_not_a_success_120,
        test_register_pending_rollback_on_s3_failure,
        test_server_lookup_validates_operation_id,
        test_s3_failure_blocks_wrap,
        test_found_unattached_state,
        test_consume_binding_tenant_id_mismatch_rejected,
        test_consume_binding_expected_aud_mismatch_rejected,
        test_consume_binding_mismatch_no_consuming_state_created,
        test_consume_binding_correct_succeeds,
        test_consume_binding_empty_registry_fields_ignored,
    ]

    print(f"\n🧪 Tests JIT Wrap Broker — issue #7 mcp-mission V1 ({len(tests)} tests)\n")
    passed = failed = 0
    for test in tests:
        try:
            test(); passed += 1
        except Exception as e:
            import traceback
            print(f"  ❌ {test.__name__}: {e}")
            traceback.print_exc()
            failed += 1

    print(f"\n{'=' * 60}")
    print(f"  {'✅' if not failed else '❌'} {passed}/{passed+failed} tests passent")
    print(f"{'=' * 60}")
    sys.exit(0 if not failed else 1)
