# -*- coding: utf-8 -*-
"""
Tests du MissionBindingStore (issue #69 — PR2 : octroi de périmètre vault local).

Non-complaisant — on prouve les invariants de sécurité, pas la couverture :

  - Contrat permissions STRICT : un binding ne peut valoir que ['read'] ou
    ['read','write']. Un binding 'write-only' / vide / 'admin' est REFUSÉ au store
    (car il n'existe pas de check_read_permission → sinon la lecture passerait).
  - allowed_resources = vrais vault_id (regex), non vides, dédupliqués, sans '*'.
  - tenant_id URL-safe, 'purge' réservé (routes /{id} non ambiguës).
  - Intégrité référentielle policy_id (refus si inexistant).
  - Fail-close : binding désactivé / expiré / date corrompue → non résolu.
  - État observable (BLOQUANT-2) : panne S3 / JSON corrompu → available=False,
    runtime lève (→503), mutations refusées SANS écriture (anti-écrasement), cache conservé.
  - Rollback mémoire si _save() échoue (create / delete / purge).

Aucune dépendance S3 / Docker : le client S3 est mocké au niveau _get_s3_data.
"""

import os
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

# Convention du projet : mcp_vault vit dans src/ (pas d'install du package)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp_vault.auth.mission_bindings import (
    MissionBindingStore,
    MissionBindingStoreUnavailable,
    _RETRY_AFTER_ERROR_SECONDS,
    _encode_instance_id,
    normalize_permissions,
    validate_allowed_resources,
    validate_tenant_id,
)

INSTANCE = "mcp-vault:test:v1"


def _make_store(offline: bool = True) -> MissionBindingStore:
    """Store avec S3 neutralisé (validation pure). _save détecte toute écriture."""
    settings = SimpleNamespace(
        s3_endpoint_url="http://localhost:0",
        s3_bucket_name="test-bucket",
        resolved_mission_aud=INSTANCE,
    )
    store = MissionBindingStore(settings)
    if offline:
        store._save = MagicMock(return_value=True)
        store._maybe_refresh = MagicMock()
        store._available = True
    return store


class _Body:
    def __init__(self, data: bytes):
        self._data = data

    def read(self) -> bytes:
        return self._data


def _fake_s3(get_return: bytes = None, get_exc: Exception = None, put_ok: bool = True):
    client = MagicMock()
    if get_exc is not None:
        client.get_object.side_effect = get_exc
    else:
        client.get_object.return_value = {"Body": _Body(get_return)}
    if put_ok:
        client.put_object.return_value = {}
    else:
        client.put_object.side_effect = Exception("S3 unreachable")
    return client


def _valid_binding_args(**over):
    args = dict(tenant_id="acme", allowed_resources=["prod"], permissions=["read"])
    args.update(over)
    return args


# =============================================================================
# normalize_permissions — contrat STRICT (BLOQUANT-1)
# =============================================================================

class TestNormalizePermissions:
    def test_read_only_accepted(self):
        assert normalize_permissions(["read"]) == ["read"]

    def test_read_write_accepted(self):
        assert normalize_permissions(["read", "write"]) == ["read", "write"]

    def test_order_insensitive(self):
        assert normalize_permissions(["write", "read"]) == ["read", "write"]

    def test_duplicates_normalized(self):
        assert normalize_permissions(["read", "read"]) == ["read"]

    @pytest.mark.parametrize("bad", [
        [],                    # vide → laisserait lire sans droit explicite
        ["write"],             # write-only → laisserait lire (pas de check_read_permission)
        ["admin"],             # admin interdit aux missions
        ["read", "admin"],     # admin interdit même avec read
        ["read", "write", "admin"],
        ["manage"],            # flag inconnu
        ["READ"],              # casse stricte
        "read",                # non-liste
        None,
        [1],                   # non-str
    ])
    def test_rejected(self, bad):
        assert normalize_permissions(bad) is None


# =============================================================================
# validate_allowed_resources (MAJEUR-3)
# =============================================================================

class TestValidateAllowedResources:
    def test_valid(self):
        res, msg = validate_allowed_resources(["prod", "staging-1", "app_x"])
        assert res == ["prod", "staging-1", "app_x"] and msg == ""

    @pytest.mark.parametrize("bad", [
        [],                    # vide
        "prod",                # non-liste
        ["*"],                 # passe-partout (exclu par regex)
        ["a/b"],               # séparateur de path
        ["a b"],               # espace
        ["-bad"],              # ne commence pas par alphanum
        ["ok", "ok"],          # doublon
        ["ok", 123],           # non-str
        [""],                  # vide
    ])
    def test_rejected(self, bad):
        res, msg = validate_allowed_resources(bad)
        assert res is None and msg

    def test_too_many_rejected(self):
        res, msg = validate_allowed_resources([f"v{i}" for i in range(200)])
        assert res is None and "max" in msg


# =============================================================================
# validate_tenant_id (MAJEUR-2)
# =============================================================================

class TestValidateTenantId:
    @pytest.mark.parametrize("ok", ["acme", "acme:prod", "a.b-c_d", "Tenant1"])
    def test_valid(self, ok):
        valid, _ = validate_tenant_id(ok)
        assert valid

    @pytest.mark.parametrize("bad", [
        "",             # vide
        "purge",        # segment de route réservé
        "a/b",          # slash → route ambiguë
        "a b",          # espace
        "a%2Fb",        # % encodé
        "-lead",        # ne commence pas par alphanum
        123,            # non-str
        None,
    ])
    def test_rejected(self, bad):
        valid, msg = validate_tenant_id(bad)
        assert not valid and msg


# =============================================================================
# create — validations défense-en-profondeur + rollback
# =============================================================================

class TestCreate:
    def test_nominal(self):
        store = _make_store()
        r = store.create(**_valid_binding_args(permissions=["read", "write"]))
        assert r["status"] == "created"
        assert r["instance_id"] == INSTANCE
        assert r["permissions"] == ["read", "write"]
        assert r["allowed_resources"] == ["prod"]
        assert store._bindings["acme"]["tenant_id"] == "acme"

    def test_reject_write_only_permissions(self):
        store = _make_store()
        r = store.create(**_valid_binding_args(permissions=["write"]))
        assert r["status"] == "error" and r["error_type"] == "invalid_permissions"
        assert "acme" not in store._bindings          # pas de fuite d'état
        store._save.assert_not_called()               # refus AVANT écriture

    def test_reject_admin_permissions(self):
        store = _make_store()
        r = store.create(**_valid_binding_args(permissions=["read", "admin"]))
        assert r["status"] == "error"
        store._save.assert_not_called()

    def test_reject_empty_allowed_resources(self):
        store = _make_store()
        r = store.create(**_valid_binding_args(allowed_resources=[]))
        assert r["status"] == "error"
        store._save.assert_not_called()

    def test_reject_wildcard_resource(self):
        store = _make_store()
        r = store.create(**_valid_binding_args(allowed_resources=["*"]))
        assert r["status"] == "error"
        store._save.assert_not_called()

    def test_reject_reserved_tenant(self):
        store = _make_store()
        r = store.create(**_valid_binding_args(tenant_id="purge"))
        assert r["status"] == "error"
        store._save.assert_not_called()

    def test_reject_duplicate_tenant(self):
        store = _make_store()
        assert store.create(**_valid_binding_args())["status"] == "created"
        r = store.create(**_valid_binding_args(allowed_resources=["other"]))
        assert r["status"] == "error" and "existe déjà" in r["message"]

    def test_reject_bad_expires_at(self):
        store = _make_store()
        r = store.create(**_valid_binding_args(expires_at="not-a-date"))
        assert r["status"] == "error"
        store._save.assert_not_called()

    def test_reject_unknown_policy_id(self):
        store = _make_store()
        fake_ps = MagicMock()
        fake_ps.get.return_value = None  # policy inexistante
        with patch("mcp_vault.auth.policies.get_policy_store", return_value=fake_ps):
            r = store.create(**_valid_binding_args(policy_id="ghost"))
        assert r["status"] == "error" and "inexistant" in r["message"]
        store._save.assert_not_called()

    def test_accept_existing_policy_id(self):
        store = _make_store()
        fake_ps = MagicMock()
        fake_ps.get.return_value = {"policy_id": "real"}
        with patch("mcp_vault.auth.policies.get_policy_store", return_value=fake_ps):
            r = store.create(**_valid_binding_args(policy_id="real"))
        assert r["status"] == "created" and r["policy_id"] == "real"

    def test_rollback_on_save_failure(self):
        store = _make_store()
        store._save = MagicMock(return_value=False)  # S3 KO
        r = store.create(**_valid_binding_args())
        assert r["status"] == "error" and r["error_type"] == "storage_unavailable"
        assert "acme" not in store._bindings          # rollback effectif


# =============================================================================
# resolve — runtime PEP (fail-close)
# =============================================================================

class TestResolve:
    def _seed(self, store, **over):
        b = {
            "instance_id": INSTANCE, "tenant_id": "acme", "policy_id": "",
            "allowed_resources": ["prod"], "permissions": ["read"],
            "enabled": True, "expires_at": None,
        }
        b.update(over)
        store._bindings[b["tenant_id"]] = b
        return b

    def test_active_binding_resolved(self):
        store = _make_store()
        self._seed(store)
        got = store.resolve("acme")
        assert got is not None and got["allowed_resources"] == ["prod"]

    def test_absent_returns_none(self):
        store = _make_store()
        assert store.resolve("nobody") is None

    def test_disabled_returns_none(self):
        store = _make_store()
        self._seed(store, enabled=False)
        assert store.resolve("acme") is None

    def test_expired_returns_none(self):
        store = _make_store()
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        self._seed(store, expires_at=past)
        assert store.resolve("acme") is None

    def test_corrupt_expires_at_returns_none(self):
        store = _make_store()
        self._seed(store, expires_at="garbage")
        assert store.resolve("acme") is None  # fail-close

    def test_foreign_instance_ignored(self):
        store = _make_store()
        self._seed(store, instance_id="mcp-vault:OTHER:v1")
        assert store.resolve("acme") is None  # anti-fuite cross-instance

    def test_future_expiry_resolved(self):
        store = _make_store()
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        self._seed(store, expires_at=future)
        assert store.resolve("acme") is not None

    def test_unavailable_raises(self):
        store = _make_store()
        store._maybe_refresh = MagicMock()
        store._available = False
        store._last_error = "S3 GET: EndpointConnectionError"
        with pytest.raises(MissionBindingStoreUnavailable):
            store.resolve("acme")


# =============================================================================
# delete
# =============================================================================

class TestDelete:
    def test_delete_ok(self):
        store = _make_store()
        store.create(**_valid_binding_args())
        assert store.delete("acme") is True
        assert "acme" not in store._bindings

    def test_delete_not_found(self):
        store = _make_store()
        assert store.delete("nobody") is False

    def test_delete_rollback_on_save_failure(self):
        store = _make_store()
        store.create(**_valid_binding_args())
        store._save = MagicMock(return_value=False)
        assert store.delete("acme") == "storage_error"
        assert "acme" in store._bindings  # rollback : toujours présent

    def test_delete_when_unavailable(self):
        store = _make_store()
        store._maybe_refresh = MagicMock()
        store._available = False
        assert store.delete("acme") == "storage_unavailable"
        store._save.assert_not_called()


# =============================================================================
# purge — fail-close date, dry_run, rollback
# =============================================================================

class TestPurge:
    def _seed_expired(self, store, tid, days_ago):
        exp = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
        store._bindings[tid] = {
            "instance_id": INSTANCE, "tenant_id": tid, "policy_id": "",
            "allowed_resources": ["v"], "permissions": ["read"],
            "enabled": True, "expires_at": exp,
        }

    def test_dry_run_destroys_nothing(self):
        store = _make_store()
        self._seed_expired(store, "old", 60)
        r = store.purge(older_than_days=30, dry_run=True)
        assert r["status"] == "ok" and r["count"] == 1
        assert "old" in store._bindings  # rien supprimé
        store._save.assert_not_called()

    def test_purge_removes_expired(self):
        store = _make_store()
        self._seed_expired(store, "old", 60)
        r = store.purge(older_than_days=30)
        assert r["status"] == "ok" and r["count"] == 1
        assert "old" not in store._bindings

    def test_retention_respected(self):
        store = _make_store()
        self._seed_expired(store, "recent", 5)  # expiré mais dans la rétention 30j
        r = store.purge(older_than_days=30)
        assert r["count"] == 0 and "recent" in store._bindings

    def test_never_expiring_not_purged(self):
        store = _make_store()
        store._bindings["forever"] = {
            "instance_id": INSTANCE, "tenant_id": "forever", "policy_id": "",
            "allowed_resources": ["v"], "permissions": ["read"],
            "enabled": True, "expires_at": None,
        }
        r = store.purge(older_than_days=0)
        assert r["count"] == 0 and "forever" in store._bindings

    def test_corrupt_date_not_purged(self):
        store = _make_store()
        store._bindings["bad"] = {
            "instance_id": INSTANCE, "tenant_id": "bad", "policy_id": "",
            "allowed_resources": ["v"], "permissions": ["read"],
            "enabled": True, "expires_at": "garbage",
        }
        r = store.purge(older_than_days=0)
        assert r["count"] == 0 and "bad" in store._bindings  # fail-close

    def test_purge_rollback_on_save_failure(self):
        store = _make_store()
        self._seed_expired(store, "old", 60)
        store._save = MagicMock(return_value=False)
        r = store.purge(older_than_days=30)
        assert r["error_type"] == "storage_unavailable"
        assert "old" in store._bindings  # rollback

    def test_purge_when_unavailable(self):
        store = _make_store()
        store._maybe_refresh = MagicMock()
        store._available = False
        r = store.purge()
        assert r["error_type"] == "storage_unavailable"
        store._save.assert_not_called()


# =============================================================================
# load — état observable (BLOQUANT-2)
# =============================================================================

class TestLoadState:
    def test_load_valid(self):
        store = _make_store(offline=False)
        body = b'{"instance_id":"' + INSTANCE.encode() + b'","bindings":[' \
               b'{"instance_id":"' + INSTANCE.encode() + b'","tenant_id":"acme",' \
               b'"allowed_resources":["prod"],"permissions":["read"],"enabled":true,' \
               b'"expires_at":null}]}'
        store._get_s3_data = MagicMock(return_value=_fake_s3(get_return=body))
        store.load()
        assert store.available is True
        assert "acme" in store._bindings

    def test_load_nosuchkey_is_empty_available(self):
        store = _make_store(offline=False)
        exc = Exception("An error occurred (NoSuchKey) when calling GetObject")
        store._get_s3_data = MagicMock(return_value=_fake_s3(get_exc=exc))
        store.load()
        assert store.available is True and store._bindings == {}

    def test_load_network_error_is_unavailable_and_preserves_cache(self):
        store = _make_store(offline=False)
        store._bindings = {"acme": {"instance_id": INSTANCE, "tenant_id": "acme",
                                    "allowed_resources": ["prod"], "permissions": ["read"],
                                    "enabled": True, "expires_at": None}}
        exc = Exception("EndpointConnectionError: could not connect")
        store._get_s3_data = MagicMock(return_value=_fake_s3(get_exc=exc))
        store.load()
        assert store.available is False and store.last_error
        assert "acme" in store._bindings  # cache conservé, PAS écrasé par du vide

    def test_load_corrupt_json_is_unavailable_and_preserves_cache(self):
        store = _make_store(offline=False)
        store._bindings = {"acme": {"instance_id": INSTANCE, "tenant_id": "acme",
                                    "allowed_resources": ["prod"], "permissions": ["read"],
                                    "enabled": True, "expires_at": None}}
        store._get_s3_data = MagicMock(return_value=_fake_s3(get_return=b"{ this is not json"))
        store.load()
        assert store.available is False
        assert "acme" in store._bindings  # anti-écrasement destructeur

    def test_retry_faster_than_ttl_after_error(self):
        """Après une panne, _maybe_refresh retente à _RETRY_AFTER_ERROR_SECONDS, pas au TTL."""
        import time as _t
        store = _make_store(offline=False)
        store._available = False
        store._cache_time = _t.time() - (_RETRY_AFTER_ERROR_SECONDS + 1)
        load_calls = {"n": 0}
        store.load = MagicMock(side_effect=lambda: load_calls.__setitem__("n", load_calls["n"] + 1))
        store._maybe_refresh()
        assert load_calls["n"] == 1  # a retenté bien avant 300s


# =============================================================================
# get / list_all / count — vue admin + filtre instance
# =============================================================================

class TestAdminViews:
    def test_get_and_list_filter_instance(self):
        store = _make_store()
        store.create(**_valid_binding_args())
        store._bindings["foreign"] = {"instance_id": "mcp-vault:OTHER:v1",
                                      "tenant_id": "foreign", "allowed_resources": ["x"],
                                      "permissions": ["read"], "enabled": True, "expires_at": None}
        listed = {b["tenant_id"] for b in store.list_all()}
        assert "acme" in listed and "foreign" not in listed
        assert store.get("foreign") is None
        assert store.get("acme")["tenant_id"] == "acme"

    def test_get_unavailable_raises(self):
        store = _make_store()
        store._maybe_refresh = MagicMock()
        store._available = False
        with pytest.raises(MissionBindingStoreUnavailable):
            store.get("acme")

    def test_count_active_only(self):
        store = _make_store()
        store.create(**_valid_binding_args(tenant_id="a"))
        store.create(**_valid_binding_args(tenant_id="b", enabled=False))
        assert store.count() == 1  # b désactivé non compté


# =============================================================================
# _encode_instance_id — noms de fichiers S3 sûrs et distincts
# =============================================================================

class TestEncodeInstanceId:
    def test_url_safe(self):
        enc = _encode_instance_id("mcp-vault:prod:v1")
        assert "/" not in enc and ":" not in enc and " " not in enc

    def test_distinct_for_distinct_instances(self):
        assert _encode_instance_id("a:b") != _encode_instance_id("a_b")  # anti-collision
