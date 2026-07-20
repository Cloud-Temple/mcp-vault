# -*- coding: utf-8 -*-
"""
Tests du PolicyStore — fail-close sur panne S3 détectée après TTL (issue #86 Lot 3).

Non-complaisant — on prouve les invariants de sécurité, pas la couverture :

  - Panne/corruption S3 détectée après TTL → available=False ; is_tool_allowed()/
    is_path_allowed()/get()/list_all()/get_vault_permissions() lèvent
    PolicyStoreUnavailable, JAMAIS une policy périmée servie silencieusement
    (POC exact du finding #86/3).
  - Validation stricte au chargement ET à la création : une policy corrompue ou
    incomplète ne devient JAMAIS permissive par défaut (bug historique corrigé :
    une path_rule sans "permissions" défaultait à ["read","write","admin"] au
    lieu de ["read"] seul).
  - TOCTOU éliminé : is_tool_allowed()/is_path_allowed() lisent self._policies
    directement après _ensure_available(), sans un second self.get() qui
    referait son propre refresh désynchronisé.
  - create()/delete()/_save() : refus/marquage invalide cohérents ; rollback
    mémoire si _save() échoue ; erreur de sérialisation LOCALE ≠ panne S3.
  - Bug historique corrigé (round 4) : `if pstore and not pstore.get(policy_id)`
    acceptait SILENCIEUSEMENT un policy_id non vérifié quand pstore était None
    (admin/api.py token create/update, server.py token_update,
    mission_bindings.py create).
  - Round 1 diff review (2 bloquants) : `permissions` non hachable (TypeError
    non capturé par load()) ; `allowed_tools or []` masquait toute valeur
    falsy non-None (ex. False) en policy permissive.
  - Round 2 diff review (garde de type policy_id + exceptions brutes) :
    `policy_id` falsy non-str (ex. False) sautait la vérification de référence
    aux 5 sites qui la font (admin/api.py token create/update + mission
    binding, server.py token_update, mission_bindings.py create) — un token/
    binding était créé avec une référence jamais vérifiée. `PolicyStore.create()`
    crashait (AttributeError) sur un policy_id non-str ; get()/is_tool_allowed()/
    is_path_allowed() crashaient (TypeError) sur un policy_id non hachable ;
    `_api_create_policy()` laissait remonter JSON invalide/top-level non-objet.

  HORS SCOPE explicite (documenté, PAS fermé par ce lot) : la race d'écriture
  multi-instance générale (issue #51/#13) — deux instances qui écrivent
  concurremment SANS aucune panne. Ce lot ferme le sous-cas « panne/corruption
  détectée », pas cette race structurelle (nécessite un vrai CAS/ETag S3).

Aucune dépendance S3 / Docker : le client S3 est mocké au niveau _get_s3_data.
"""

import asyncio
import json
import os
import sys
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Convention du projet : mcp_vault vit dans src/ (pas d'install du package)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp_vault.auth.policies import (
    PolicyStore,
    PolicyStoreUnavailable,
    _RETRY_AFTER_ERROR_SECONDS,
    _validate_and_normalize_policy,
)


def _run(coro):
    return asyncio.run(coro)


def _make_store(offline: bool = True) -> PolicyStore:
    """Store avec S3 neutralisé (tests de logique pure). _save détecte toute écriture."""
    settings = SimpleNamespace(s3_endpoint_url="http://localhost:0", s3_bucket_name="test-bucket")
    store = PolicyStore(settings)
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


def _client_error(code="NoSuchKey", status=404):
    """Fabrique un vrai botocore ClientError (la détection ne se fie plus à str(e))."""
    from botocore.exceptions import ClientError
    return ClientError(
        {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}},
        "GetObject",
    )


def _policy(**over):
    """Policy conforme minimale (surchargeable pour forger des cas invalides)."""
    p = {"policy_id": "p1", "description": "", "allowed_tools": [], "denied_tools": [],
         "path_rules": []}
    p.update(over)
    return p


def _file_bytes(policies):
    return json.dumps({"policies": policies}).encode()


def _asgi_statuses(send_mock):
    """Status HTTP des messages ASGI http.response.start capturés."""
    return [
        c.args[0].get("status")
        for c in send_mock.call_args_list
        if c.args and isinstance(c.args[0], dict)
        and c.args[0].get("type") == "http.response.start"
    ]


# =============================================================================
# _validate_and_normalize_policy — non permissif par défaut (BLOQUANT round 4)
# =============================================================================

class TestValidateAndNormalizePolicy:
    def test_valid_minimal_policy_normalized(self):
        norm = _validate_and_normalize_policy(_policy())
        assert norm["policy_id"] == "p1"
        assert norm["allowed_tools"] == []
        assert norm["path_rules"] == []

    def test_not_a_dict_rejected(self):
        with pytest.raises(ValueError):
            _validate_and_normalize_policy(["not", "a", "dict"])

    def test_missing_policy_id_rejected(self):
        p = _policy()
        del p["policy_id"]
        with pytest.raises(ValueError):
            _validate_and_normalize_policy(p)

    def test_empty_policy_id_rejected(self):
        with pytest.raises(ValueError):
            _validate_and_normalize_policy(_policy(policy_id=""))

    @pytest.mark.parametrize("field", ["allowed_tools", "denied_tools", "path_rules"])
    def test_required_field_absent_rejected(self, field):
        p = _policy()
        del p[field]
        with pytest.raises(ValueError):
            _validate_and_normalize_policy(p)

    def test_allowed_tools_non_string_element_rejected(self):
        with pytest.raises(ValueError):
            _validate_and_normalize_policy(_policy(allowed_tools=["ok", 123]))

    def test_path_rule_not_a_dict_rejected(self):
        with pytest.raises(ValueError):
            _validate_and_normalize_policy(_policy(path_rules=["not-a-dict"]))

    def test_path_rule_empty_vault_pattern_rejected(self):
        """Contre-exemple round 4 : vault_pattern="" est une str mais ne matche
        rien — is_path_allowed() finirait par autoriser (fail-open silencieux
        via la règle "aucune règle matchante = pas de restriction"). Rejeté."""
        with pytest.raises(ValueError):
            _validate_and_normalize_policy(_policy(path_rules=[{"vault_pattern": ""}]))

    def test_path_rule_missing_permissions_normalized_to_read_only(self):
        """RÉGRESSION CENTRALE (bug historique) : permissions absentes doit
        devenir ["read"] SEUL — jamais ["read","write","admin"] (l'ancien
        défaut d'is_path_allowed(), qui accordait write/admin par surprise)."""
        norm = _validate_and_normalize_policy(_policy(path_rules=[{"vault_pattern": "prod-*"}]))
        assert norm["path_rules"][0]["permissions"] == ["read"]

    def test_path_rule_invalid_permissions_value_rejected(self):
        with pytest.raises(ValueError):
            _validate_and_normalize_policy(
                _policy(path_rules=[{"vault_pattern": "p", "permissions": ["superadmin"]}]))

    def test_path_rule_empty_permissions_list_rejected(self):
        with pytest.raises(ValueError):
            _validate_and_normalize_policy(
                _policy(path_rules=[{"vault_pattern": "p", "permissions": []}]))

    def test_path_rule_allowed_paths_non_string_rejected(self):
        with pytest.raises(ValueError):
            _validate_and_normalize_policy(
                _policy(path_rules=[{"vault_pattern": "p", "allowed_paths": [123]}]))

    def test_path_rule_permissions_non_hashable_element_raises_valueerror_not_typeerror(self):
        """BLOQUANT round 1 diff review : `permissions` contenant un élément non
        hachable (ex. liste imbriquée) faisait lever TypeError par `p in
        _VALID_PERMISSIONS` (non capturé par load(), qui ne catche que
        ValueError) — 500 brut au lieu du refus structuré. Doit lever
        ValueError proprement, comme toute autre valeur de permissions invalide."""
        with pytest.raises(ValueError):
            _validate_and_normalize_policy(
                _policy(path_rules=[{"vault_pattern": "p", "permissions": [["read"]]}]))

    def test_does_not_mutate_input(self):
        p = _policy(path_rules=[{"vault_pattern": "x"}])
        original = json.dumps(p)
        _validate_and_normalize_policy(p)
        assert json.dumps(p) == original


# =============================================================================
# load() — atomique, tout-ou-rien, distinction NoSuchKey vs vraie panne
# =============================================================================

class TestLoad:
    def test_nosuchkey_is_nominal_empty_store(self):
        store = PolicyStore(SimpleNamespace(s3_bucket_name="b"))
        store._get_s3_data = MagicMock(return_value=_fake_s3(get_exc=_client_error("NoSuchKey")))
        store.load()
        assert store.available is True
        assert store.last_error == ""
        assert store.count() == 0

    def test_client_error_wrong_code_containing_404_is_outage_not_absence(self):
        """Piège round 1/2 : un message contenant '404' mais Error.Code != NoSuchKey
        est une VRAIE panne, pas l'absence nominale du fichier."""
        store = PolicyStore(SimpleNamespace(s3_bucket_name="b"))
        store._get_s3_data = MagicMock(
            return_value=_fake_s3(get_exc=_client_error("InternalError", status=404)))
        store.load()
        assert store.available is False

    def test_network_error_marks_invalid_cache_preserved(self):
        store = PolicyStore(SimpleNamespace(s3_bucket_name="b"))
        store._policies = {"old": _policy(policy_id="old")}
        store._get_s3_data = MagicMock(return_value=_fake_s3(get_exc=Exception("boom")))
        store.load()
        assert store.available is False
        assert store._policies == {"old": _policy(policy_id="old")}, "cache NON écrasé"

    def test_json_invalid_marks_invalid(self):
        store = PolicyStore(SimpleNamespace(s3_bucket_name="b"))
        store._get_s3_data = MagicMock(return_value=_fake_s3(get_return=b"{not json"))
        store.load()
        assert store.available is False

    def test_deeply_nested_json_marks_invalid_not_crash(self):
        """Cohérent avec le fix TokenStore (issue #86) : un JSON profondément
        imbriqué (`[`×2000 `]`×2000) lève RecursionError, PAS ValueError — un
        except trop étroit laisserait cette exception non gérée remonter."""
        store = PolicyStore(SimpleNamespace(s3_bucket_name="b"))
        pathological = ("[" * 2000 + "]" * 2000).encode()
        store._get_s3_data = MagicMock(return_value=_fake_s3(get_return=pathological))
        store.load()  # ne doit lever AUCUNE exception
        assert store.available is False

    def test_top_level_empty_object_is_invalid_not_empty_store(self):
        """Contre-exemple round 4 : {} ne doit PAS être traité comme store vide —
        seul NoSuchKey l'est."""
        store = PolicyStore(SimpleNamespace(s3_bucket_name="b"))
        store._get_s3_data = MagicMock(return_value=_fake_s3(get_return=b"{}"))
        store.load()
        assert store.available is False

    def test_top_level_wrong_type_is_invalid(self):
        store = PolicyStore(SimpleNamespace(s3_bucket_name="b"))
        store._get_s3_data = MagicMock(
            return_value=_fake_s3(get_return=json.dumps({"policies": "not-a-list"}).encode()))
        store.load()
        assert store.available is False

    def test_one_invalid_policy_invalidates_whole_load(self):
        """Tout-ou-rien (confirmé round 4) : une policy corrompue invalide TOUT
        le chargement — jamais un chargement partiel qui ferait confiance à un
        fichier déclaré corrompu."""
        store = PolicyStore(SimpleNamespace(s3_bucket_name="b"))
        good = _policy(policy_id="good")
        bad = _policy(policy_id="bad", path_rules=[{"vault_pattern": ""}])
        store._get_s3_data = MagicMock(return_value=_fake_s3(get_return=_file_bytes([good, bad])))
        store.load()
        assert store.available is False
        assert store.count() == 0  # rien n'est chargé, y compris "good"

    def test_duplicate_policy_id_invalidates_load(self):
        """Round 4 : la compréhension dict naïve écraserait silencieusement un
        doublon — détecté et rejeté explicitement."""
        store = PolicyStore(SimpleNamespace(s3_bucket_name="b"))
        p1 = _policy(policy_id="dup", allowed_tools=["a"])
        p2 = _policy(policy_id="dup", allowed_tools=["b"])
        store._get_s3_data = MagicMock(return_value=_fake_s3(get_return=_file_bytes([p1, p2])))
        store.load()
        assert store.available is False

    def test_load_permissions_non_hashable_marks_invalid_not_crash(self):
        """BLOQUANT round 1 diff review : reproduit le crash exact via load() —
        un blob S3 avec permissions=[["read"]] ne doit JAMAIS faire remonter une
        exception non gérée hors de load() ; le store doit passer available=False
        de façon observable, comme toute autre policy corrompue."""
        store = PolicyStore(SimpleNamespace(s3_bucket_name="b"))
        corrupted = _policy(path_rules=[{"vault_pattern": "p", "permissions": [["read"]]}])
        store._get_s3_data = MagicMock(return_value=_fake_s3(get_return=_file_bytes([corrupted])))
        store.load()  # ne doit lever AUCUNE exception
        assert store.available is False

    def test_successful_load_resets_available_and_last_error(self):
        store = PolicyStore(SimpleNamespace(s3_bucket_name="b"))
        store._available = False
        store._last_error = "ancienne panne"
        store._get_s3_data = MagicMock(
            return_value=_fake_s3(get_return=_file_bytes([_policy()])))
        store.load()
        assert store.available is True
        assert store.last_error == ""


# =============================================================================
# is_tool_allowed / is_path_allowed — POC du finding, TOCTOU, défaut permissif
# =============================================================================

class TestIsToolAllowedIsPathAllowed:
    def test_poc_outage_after_ttl_raises_never_serves_stale_policy(self):
        """POC EXACT du finding #86/3 : policy permissive en cache, TTL dépassé,
        S3 en panne → is_tool_allowed() DOIT lever, jamais retourner True sur
        l'ancien cache."""
        store = _make_store(offline=False)
        store._policies = {"p": _policy(policy_id="p", allowed_tools=[])}  # tout permis
        store._cache_time = time.time() - 301  # TTL (300s) dépassé
        store._get_s3_data = MagicMock(return_value=_fake_s3(get_exc=Exception("S3 down")))
        with pytest.raises(PolicyStoreUnavailable):
            store.is_tool_allowed("p", "vault_delete")

    def test_before_ttl_still_serves_cache_normally(self):
        """Non-régression : avant expiration du TTL, comportement inchangé."""
        store = _make_store()
        store._policies = {"p": _policy(policy_id="p", allowed_tools=[])}
        store._cache_time = time.time()
        assert store.is_tool_allowed("p", "vault_delete") is True

    def test_is_path_allowed_defensive_default_is_read_only_not_admin(self):
        """RÉGRESSION CENTRALE — défense en profondeur : MÊME si une policy en
        cache a un path_rule SANS "permissions" (ne devrait plus arriver via
        load()/create(), mais teste la ligne de code elle-même), is_path_allowed()
        ne doit JAMAIS défaulter à write/admin.
        SABOTAGE (vérifié manuellement) : remplacer le défaut ["read"] par
        ["read","write","admin"] dans is_path_allowed() fait passer les
        assertions write/admin à True → ce test devient RED."""
        store = _make_store()
        store._policies = {
            "p": {
                "policy_id": "p", "allowed_tools": [], "denied_tools": [],
                "path_rules": [{"vault_pattern": "prod-*", "allowed_paths": []}],  # PAS de "permissions"
            }
        }
        store._cache_time = time.time()
        assert store.is_path_allowed("p", "prod-1", "x", "read") is True
        assert store.is_path_allowed("p", "prod-1", "x", "write") is False
        assert store.is_path_allowed("p", "prod-1", "x", "admin") is False

    def test_toctou_absent_single_refresh_per_call(self):
        """TOCTOU (round 1/2) : is_tool_allowed()/is_path_allowed() ne doivent
        PAS rappeler self.get() après _ensure_available() (2e refresh
        désynchronisé, réouvrant la fenêtre de fail-open)."""
        store = _make_store()
        store._policies = {"p": _policy(policy_id="p", allowed_tools=[])}
        store._cache_time = time.time()
        with patch.object(PolicyStore, "get") as mock_get:
            store.is_tool_allowed("p", "vault_delete")
            mock_get.assert_not_called()
        with patch.object(PolicyStore, "get") as mock_get:
            store.is_path_allowed("p", "v", "path", "read")
            mock_get.assert_not_called()

    def test_deleted_policy_fail_close(self):
        store = _make_store()
        store._cache_time = time.time()
        assert store.is_tool_allowed("gone", "vault_delete") is False
        assert store.is_path_allowed("gone", "v", "p", "read") is False


# =============================================================================
# create() / delete() / _save() — refus, rollback, distinction sérialisation/PUT
# =============================================================================

class TestCreateAndDelete:
    def test_create_refused_when_unavailable_no_write_attempted(self):
        store = _make_store()
        store._available = False
        store._last_error = "panne simulée"
        result = store.create("newpol")
        assert result["status"] == "error"
        assert result["error_type"] == "policy_store_unavailable"
        store._save.assert_not_called()

    def test_delete_refused_when_unavailable_no_write_attempted(self):
        store = _make_store()
        store._policies = {"p": _policy(policy_id="p")}
        store._available = False
        result = store.delete("p")
        assert result == "policy_store_unavailable"
        store._save.assert_not_called()
        assert "p" in store._policies  # rien supprimé

    def test_create_rejects_invalid_path_rule_before_any_write(self):
        store = _make_store()
        result = store.create("p", path_rules=[{"vault_pattern": ""}])
        assert result["status"] == "error"
        store._save.assert_not_called()
        assert "p" not in store._policies

    def test_create_defaults_missing_permissions_to_read_only(self):
        store = _make_store()
        result = store.create("p", path_rules=[{"vault_pattern": "prod-*"}])
        assert result["status"] == "created"
        assert result["path_rules"][0]["permissions"] == ["read"]

    def test_create_rejects_falsy_non_none_allowed_tools(self):
        """BLOQUANT round 1 diff review : `allowed_tools or []` blanchissait
        SILENCIEUSEMENT toute valeur falsy (False, 0, "") en [] AVANT validation
        — [] signifie "tous les outils autorisés" (is_tool_allowed). Un
        allowed_tools=False (erreur de saisie/type) créait donc une policy
        PERMISSIVE TOTALE au lieu d'être rejeté. Doit être un refus explicite."""
        store = _make_store()
        result = store.create("p", allowed_tools=False)
        assert result["status"] == "error"
        assert "p" not in store._policies
        store._save.assert_not_called()

    def test_create_rejects_duplicate_policy_id(self):
        store = _make_store()
        store._policies = {"p": _policy(policy_id="p")}
        store._cache_time = time.time()
        result = store.create("p")
        assert result["status"] == "error"
        assert "existe déjà" in result["message"]

    def test_save_put_failure_marks_store_invalid(self):
        store = PolicyStore(SimpleNamespace(s3_bucket_name="b"))
        store._get_s3_data = MagicMock(return_value=_fake_s3(put_ok=False))
        ok = store._save()
        assert ok is False
        assert store.available is False

    def test_save_local_serialization_error_does_not_mark_invalid(self):
        """Distinction round 4 : une erreur de sérialisation LOCALE (bug de code)
        ne prouve PAS que S3 est en panne — ne doit PAS marquer le store invalide.
        (json.dumps(..., default=str) stringifie la plupart des objets sans
        erreur ; seule une référence circulaire déclenche une vraie ValueError
        AVANT tout appel réseau — le cas qui isole vraiment ce chemin.)"""
        store = PolicyStore(SimpleNamespace(s3_bucket_name="b"))
        circular = {}
        circular["self"] = circular
        store._policies = {"p": circular}
        ok = store._save()
        assert ok is False
        assert store.available is True  # PAS marqué invalide

    def test_create_put_failure_rolls_back_memory_and_marks_unavailable(self):
        store = PolicyStore(SimpleNamespace(s3_bucket_name="b"))
        store._cache_time = time.time()  # fraîche : _maybe_refresh() ne relance pas load()
        store._get_s3_data = MagicMock(return_value=_fake_s3(put_ok=False))
        result = store.create("p")
        assert result["status"] == "error"
        assert result["error_type"] == "policy_store_unavailable"
        assert "p" not in store._policies  # rollback mémoire
        assert store.available is False  # marqué invalide par _save()

    def test_delete_put_failure_rolls_back(self):
        store = PolicyStore(SimpleNamespace(s3_bucket_name="b"))
        store._policies = {"p": _policy(policy_id="p")}
        store._cache_time = time.time()
        store._get_s3_data = MagicMock(return_value=_fake_s3(put_ok=False))
        result = store.delete("p")
        assert result == "storage_error"
        assert "p" in store._policies  # rollback


# =============================================================================
# get() / list_all() / get_vault_permissions() — lèvent si indisponible
# =============================================================================

class TestGetListAll:
    def test_get_raises_when_unavailable(self):
        store = _make_store()
        store._available = False
        with pytest.raises(PolicyStoreUnavailable):
            store.get("p")

    def test_list_all_raises_when_unavailable(self):
        store = _make_store()
        store._available = False
        with pytest.raises(PolicyStoreUnavailable):
            store.list_all()

    def test_get_vault_permissions_propagates_unavailable(self):
        """round 4 : conservée SANS garde de code supplémentaire — hérite de
        l'exception via son appel interne à get()."""
        store = _make_store()
        store._available = False
        with pytest.raises(PolicyStoreUnavailable):
            store.get_vault_permissions("p", "v")

    def test_get_returns_none_for_missing_policy_when_available(self):
        store = _make_store()
        store._cache_time = time.time()
        assert store.get("nope") is None

    def test_list_all_returns_summary_when_available(self):
        store = _make_store()
        store._policies = {"p": _policy(policy_id="p", description="d")}
        store._cache_time = time.time()
        result = store.list_all()
        assert result == [{
            "policy_id": "p", "description": "d",
            "allowed_tools_count": 0, "denied_tools_count": 0, "path_rules_count": 0,
            "created_at": "", "created_by": "",
        }]


# =============================================================================
# Retry accéléré / récupération
# =============================================================================

class TestRetryAndRecovery:
    def test_no_retry_before_accelerated_delay(self):
        store = PolicyStore(SimpleNamespace(s3_bucket_name="b"))
        store._mark_invalid("panne")
        store._get_s3_data = MagicMock(side_effect=AssertionError("ne doit PAS être appelé avant le délai"))
        store._maybe_refresh()
        assert store.available is False

    def test_recovers_after_accelerated_delay(self):
        store = PolicyStore(SimpleNamespace(s3_bucket_name="b"))
        store._mark_invalid("panne")
        store._cache_time = time.time() - (_RETRY_AFTER_ERROR_SECONDS + 1)
        store._get_s3_data = MagicMock(
            return_value=_fake_s3(get_return=_file_bytes([_policy()])))
        store._maybe_refresh()
        assert store.available is True
        assert store.last_error == ""
        assert store.count() == 1


# =============================================================================
# Helper REST centralisé — 403 (refus ordinaire) vs 503 (store indisponible)
# =============================================================================

class TestPolicyErrorResponseHelper:
    """Consommé par les 18 sites REST check_policy()/check_path_policy() (14 + 4,
    confirmé par exploration réelle du code, round 4) — mapping homogène."""

    def test_ordinary_refusal_is_403(self):
        from mcp_vault.admin.api import _policy_error_response
        send = AsyncMock()
        _run(_policy_error_response(send, {"status": "error", "message": "Bloqué par la policy"}))
        assert _asgi_statuses(send) == [403]

    def test_store_unavailable_is_503(self):
        from mcp_vault.admin.api import _policy_error_response
        send = AsyncMock()
        _run(_policy_error_response(
            send, {"status": "error", "error_type": "policy_store_unavailable", "message": "indisponible"}))
        assert _asgi_statuses(send) == [503]


# =============================================================================
# context.py — check_policy / check_path_policy / can_read_vault_content
# =============================================================================

class TestContextIntegration:
    """Ne doivent JAMAIS laisser PolicyStoreUnavailable se propager, ni fail-open
    silencieusement."""

    def test_check_policy_catches_unavailable(self):
        from mcp_vault.auth import context as ctx
        store = MagicMock()
        store.is_tool_allowed.side_effect = PolicyStoreUnavailable("panne")
        tok = {"permissions": ["read"], "policy_id": "p", "client_name": "c"}
        h = ctx.current_token_info.set(tok)
        try:
            with patch("mcp_vault.auth.policies.get_policy_store", return_value=store), \
                 patch("mcp_vault.audit.log_audit") as mock_audit:
                result = ctx.check_policy("vault_delete")
        finally:
            ctx.current_token_info.reset(h)
        assert result["status"] == "error"
        assert result["error_type"] == "policy_store_unavailable"
        mock_audit.assert_called_once()

    def test_check_path_policy_catches_unavailable(self):
        from mcp_vault.auth import context as ctx
        store = MagicMock()
        store.is_path_allowed.side_effect = PolicyStoreUnavailable("panne")
        tok = {"permissions": ["read"], "policy_id": "p", "client_name": "c"}
        h = ctx.current_token_info.set(tok)
        try:
            with patch("mcp_vault.auth.policies.get_policy_store", return_value=store), \
                 patch("mcp_vault.audit.log_audit") as mock_audit:
                result = ctx.check_path_policy("v", "secret/x", "read")
        finally:
            ctx.current_token_info.reset(h)
        assert result["status"] == "error"
        assert result["error_type"] == "policy_store_unavailable"
        mock_audit.assert_called_once()

    def test_can_read_vault_content_false_when_unavailable_no_audit(self):
        """Silencieux (pas d'audit) — cohérent avec le comportement documenté de
        can_read_vault_content() (pas de faux 'denied')."""
        from mcp_vault.auth import context as ctx
        store = MagicMock()
        store.is_tool_allowed.side_effect = PolicyStoreUnavailable("panne")
        tok = {"permissions": ["read"], "policy_id": "p", "client_name": "c"}
        h = ctx.current_token_info.set(tok)
        try:
            with patch("mcp_vault.auth.policies.get_policy_store", return_value=store), \
                 patch("mcp_vault.audit.log_audit") as mock_audit:
                result = ctx.can_read_vault_content("v")
                mock_audit.assert_not_called()
        finally:
            ctx.current_token_info.reset(h)
        assert result is False


# =============================================================================
# Bug historique corrigé (round 4) : policy_id non vérifiable ≠ accepté silencieux
# =============================================================================

class TestPolicyIdReferenceGuards:
    """`if pstore and not pstore.get(policy_id)` acceptait SILENCIEUSEMENT un
    policy_id quand pstore était None (store absent). Corrigé aux 4 call-sites :
    admin/api.py (token create/update), server.py (token_update),
    mission_bindings.py (create)."""

    def test_api_create_token_rejects_when_policy_store_absent(self):
        from mcp_vault.admin import api
        send = AsyncMock()
        body = json.dumps({"client_name": "c", "policy_id": "p"})
        tstore = MagicMock()
        with patch.object(api, "get_token_store", return_value=tstore), \
             patch("mcp_vault.auth.policies.get_policy_store", return_value=None):
            _run(api._api_create_token(send, body))
        assert _asgi_statuses(send) == [400]
        tstore.create.assert_not_called()  # AUCUNE création avec une réf non vérifiée

    def test_api_create_token_503_when_policy_store_unavailable(self):
        from mcp_vault.admin import api
        send = AsyncMock()
        body = json.dumps({"client_name": "c", "policy_id": "p"})
        tstore = MagicMock()
        pstore = MagicMock()
        pstore.get.side_effect = PolicyStoreUnavailable("panne")
        with patch.object(api, "get_token_store", return_value=tstore), \
             patch("mcp_vault.auth.policies.get_policy_store", return_value=pstore):
            _run(api._api_create_token(send, body))
        assert _asgi_statuses(send) == [503]
        tstore.create.assert_not_called()

    def test_api_update_token_rejects_when_policy_store_absent(self):
        from mcp_vault.admin import api
        send = AsyncMock()
        body = json.dumps({"policy_id": "p"})
        tstore = MagicMock()
        with patch.object(api, "get_token_store", return_value=tstore), \
             patch("mcp_vault.auth.policies.get_policy_store", return_value=None):
            _run(api._api_update_token(send, "abc123def456", body))
        assert _asgi_statuses(send) == [400]
        tstore.update.assert_not_called()

    def test_mcp_token_update_rejects_when_policy_store_absent(self):
        import mcp_vault.server as server
        tstore = MagicMock()
        with patch("mcp_vault.auth.token_store.get_token_store", return_value=tstore), \
             patch("mcp_vault.auth.context.check_admin_permission", return_value=None), \
             patch("mcp_vault.auth.policies.get_policy_store", return_value=None):
            result = _run(server.token_update("abc123def456", policy_id="p"))
        assert result["status"] == "error"
        tstore.update.assert_not_called()

    def test_mission_binding_create_rejects_when_policy_store_unavailable(self):
        from mcp_vault.auth.mission_bindings import MissionBindingStore
        store = MissionBindingStore(SimpleNamespace(
            s3_endpoint_url="http://x", s3_bucket_name="b", resolved_mission_aud="inst"))
        store._maybe_refresh = MagicMock()
        store._available = True
        pstore = MagicMock()
        pstore.get.side_effect = PolicyStoreUnavailable("panne")
        with patch("mcp_vault.auth.policies.get_policy_store", return_value=pstore):
            result = store.create(tenant_id="acme", allowed_resources=["prod"],
                                   permissions=["read"], policy_id="p")
        assert result["status"] == "error"
        assert result["error_type"] == "policy_store_unavailable"


# =============================================================================
# Round 2 diff review : policy_id falsy non-str = référence sautée silencieusement
# =============================================================================

class TestPolicyIdFalsyNonStringRejected:
    """BLOQUANT round 2 : `if policy_id:` traite `False` comme "pas de policy" —
    la vérification de référence est sautée, mais la valeur malformée est quand
    même persistée/utilisée, produisant un token/binding SANS restriction alors
    qu'une référence (même invalide) avait été fournie. Les 5 sites doivent
    REJETER explicitement un policy_id non-str plutôt que de le traiter comme
    absent."""

    def test_api_create_token_rejects_boolean_policy_id(self):
        from mcp_vault.admin import api
        send = AsyncMock()
        body = json.dumps({"client_name": "c", "policy_id": False})
        tstore = MagicMock()
        with patch.object(api, "get_token_store", return_value=tstore):
            _run(api._api_create_token(send, body))
        assert _asgi_statuses(send) == [400]
        tstore.create.assert_not_called()

    def test_api_update_token_rejects_boolean_policy_id(self):
        from mcp_vault.admin import api
        send = AsyncMock()
        body = json.dumps({"policy_id": False})
        tstore = MagicMock()
        with patch.object(api, "get_token_store", return_value=tstore):
            _run(api._api_update_token(send, "abc123def456", body))
        assert _asgi_statuses(send) == [400]
        tstore.update.assert_not_called()

    def test_mcp_token_update_rejects_boolean_policy_id(self):
        import mcp_vault.server as server
        tstore = MagicMock()
        with patch("mcp_vault.auth.token_store.get_token_store", return_value=tstore), \
             patch("mcp_vault.auth.context.check_admin_permission", return_value=None):
            result = _run(server.token_update("abc123def456", policy_id=False))
        assert result["status"] == "error"
        tstore.update.assert_not_called()

    def test_mission_binding_create_rejects_boolean_policy_id(self):
        from mcp_vault.auth.mission_bindings import MissionBindingStore
        store = MissionBindingStore(SimpleNamespace(
            s3_endpoint_url="http://x", s3_bucket_name="b", resolved_mission_aud="inst"))
        store._maybe_refresh = MagicMock()
        store._available = True
        store._save = MagicMock(return_value=True)
        result = store.create(tenant_id="acme", allowed_resources=["prod"],
                               permissions=["read"], policy_id=False)
        assert result["status"] == "error"
        store._save.assert_not_called()

    def test_api_create_mission_binding_rejects_boolean_policy_id_not_silently_empty(self):
        """Round 2 : l'ancien `data.get("policy_id", "") or ""` transformait
        `false` en "" (binding créé SANS policy). Doit désormais rejeter."""
        from mcp_vault.admin import api
        send = AsyncMock()
        body = json.dumps({"tenant_id": "acme", "allowed_resources": ["prod"],
                            "permissions": ["read"], "policy_id": False})
        bstore = MagicMock()
        with patch("mcp_vault.auth.mission_bindings.get_mission_binding_store", return_value=bstore):
            _run(api._api_create_mission_binding(send, body))
        bstore.create.assert_called_once()
        assert bstore.create.call_args.kwargs["policy_id"] is False, \
            "la valeur brute doit être transmise au store (qui la validera), pas blanchie en '' silencieusement"


# =============================================================================
# Round 2 diff review : exceptions brutes sur entrée malformée (policy_id, JSON)
# =============================================================================

class TestRawExceptionsOnMalformedInput:
    """BLOQUANT round 2 (finding 5) : une entrée malformée (policy_id non-str/
    non hachable, JSON invalide/non-objet) ne doit JAMAIS crasher avec une
    exception Python brute — toujours un refus structuré (ValueError capturé,
    dict d'erreur, ou fail-close silencieux cohérent)."""

    def test_get_non_string_policy_id_returns_none_not_crash(self):
        store = _make_store()
        store._cache_time = time.time()
        assert store.get(["not", "hashable"]) is None

    def test_is_tool_allowed_non_string_policy_id_returns_false_not_crash(self):
        store = _make_store()
        store._cache_time = time.time()
        assert store.is_tool_allowed(["not", "hashable"], "vault_delete") is False

    def test_is_path_allowed_non_string_policy_id_returns_false_not_crash(self):
        store = _make_store()
        store._cache_time = time.time()
        assert store.is_path_allowed({"not": "hashable"}, "v", "p", "read") is False

    def test_store_create_non_string_policy_id_rejected_not_crash(self):
        store = _make_store()
        result = store.create(123)
        assert result["status"] == "error"
        store._save.assert_not_called()

    def test_api_create_policy_invalid_json_returns_400_not_crash(self):
        from mcp_vault.admin import api
        send = AsyncMock()
        pstore = MagicMock()
        with patch("mcp_vault.auth.policies.get_policy_store", return_value=pstore):
            _run(api._api_create_policy(send, b"not json"))
        assert _asgi_statuses(send) == [400]
        pstore.create.assert_not_called()

    def test_api_create_policy_top_level_array_returns_400_not_crash(self):
        from mcp_vault.admin import api
        send = AsyncMock()
        pstore = MagicMock()
        with patch("mcp_vault.auth.policies.get_policy_store", return_value=pstore):
            _run(api._api_create_policy(send, json.dumps([1, 2, 3]).encode()))
        assert _asgi_statuses(send) == [400]
        pstore.create.assert_not_called()

    def test_api_create_policy_non_string_policy_id_returns_400_not_crash(self):
        from mcp_vault.admin import api
        send = AsyncMock()
        pstore = MagicMock()
        body = json.dumps({"policy_id": 123})
        with patch("mcp_vault.auth.policies.get_policy_store", return_value=pstore):
            _run(api._api_create_policy(send, body))
        assert _asgi_statuses(send) == [400]
        pstore.create.assert_not_called()

    def test_api_create_token_top_level_array_returns_400_not_crash(self):
        from mcp_vault.admin import api
        send = AsyncMock()
        tstore = MagicMock()
        with patch.object(api, "get_token_store", return_value=tstore):
            _run(api._api_create_token(send, json.dumps([1, 2, 3]).encode()))
        assert _asgi_statuses(send) == [400]
        tstore.create.assert_not_called()

    def test_api_update_token_top_level_array_returns_400_not_crash(self):
        from mcp_vault.admin import api
        send = AsyncMock()
        tstore = MagicMock()
        with patch.object(api, "get_token_store", return_value=tstore):
            _run(api._api_update_token(send, "abc123def456", json.dumps([1, 2, 3]).encode()))
        assert _asgi_statuses(send) == [400]
        tstore.update.assert_not_called()

    def test_api_create_mission_binding_top_level_array_returns_400_not_crash(self):
        from mcp_vault.admin import api
        send = AsyncMock()
        bstore = MagicMock()
        with patch("mcp_vault.auth.mission_bindings.get_mission_binding_store", return_value=bstore):
            _run(api._api_create_mission_binding(send, json.dumps([1, 2, 3]).encode()))
        assert _asgi_statuses(send) == [400]
        bstore.create.assert_not_called()

    def test_policy_store_delete_non_string_policy_id_returns_false_not_crash(self):
        store = _make_store()
        store._cache_time = time.time()
        assert store.delete(["not", "hashable"]) is False
        store._save.assert_not_called()

    def test_load_rejects_policy_id_out_of_format_or_length(self):
        """Alignement round 3 : load() applique désormais la MÊME contrainte de
        format/longueur que create() (pas seulement le type) — cohérence réelle
        de la « validation partagée » annoncée."""
        store = PolicyStore(SimpleNamespace(s3_bucket_name="b"))
        too_long = _policy(policy_id="x" * 65)
        store._get_s3_data = MagicMock(return_value=_fake_s3(get_return=_file_bytes([too_long])))
        store.load()
        assert store.available is False


# =============================================================================
# Round 3 diff review : le PEP runtime doit fail-close sur un token_info corrompu
# =============================================================================

class TestCorruptedTokenPolicyIdFailsClosedAtPEP:
    """BLOQUANT PRINCIPAL round 3 : les gardes de création (round 2) protègent
    la CRÉATION de nouvelles entrées, mais PAS un token_info DÉJÀ EN MÉMOIRE
    (chargé depuis S3 sans validation de type dans TokenStore, ou corrompu
    d'une autre façon) portant un policy_id falsy non-str. check_policy()/
    check_path_policy()/can_read_vault_content() DOIVENT fail-close sur cette
    donnée corrompue au dernier point de décision, indépendamment de la façon
    dont elle serait arrivée là — c'est le vrai rempart, pas seulement la
    création."""

    def _token(self, **over):
        tok = {"permissions": ["read"], "policy_id": False, "client_name": "c"}
        tok.update(over)
        return tok

    def test_check_policy_fails_closed_on_boolean_policy_id(self):
        """POC EXACT round 3 : un token_info avec policy_id=False (donnée
        corrompue) ne doit PAS être traité comme "pas de policy" (autorisé)."""
        from mcp_vault.auth import context as ctx
        h = ctx.current_token_info.set(self._token())
        try:
            with patch("mcp_vault.auth.policies.get_policy_store") as mock_gps:
                result = ctx.check_policy("vault_delete")
                mock_gps.assert_not_called()  # ne doit même pas consulter le store
        finally:
            ctx.current_token_info.reset(h)
        assert result is not None
        assert result["status"] == "error"

    def test_check_path_policy_fails_closed_on_boolean_policy_id(self):
        from mcp_vault.auth import context as ctx
        h = ctx.current_token_info.set(self._token())
        try:
            with patch("mcp_vault.auth.policies.get_policy_store") as mock_gps:
                result = ctx.check_path_policy("v", "secret/x", "read")
                mock_gps.assert_not_called()
        finally:
            ctx.current_token_info.reset(h)
        assert result is not None
        assert result["status"] == "error"

    def test_can_read_vault_content_fails_closed_on_boolean_policy_id(self):
        from mcp_vault.auth import context as ctx
        h = ctx.current_token_info.set(self._token())
        try:
            with patch("mcp_vault.auth.policies.get_policy_store") as mock_gps:
                result = ctx.can_read_vault_content("v")
                mock_gps.assert_not_called()
        finally:
            ctx.current_token_info.reset(h)
        assert result is False

    def test_legitimate_empty_policy_id_still_means_no_restriction(self):
        """Non-régression : policy_id absent/"" reste le sentinel légitime
        "pas de policy" (tout autorisé) — la garde ne doit fermer QUE le cas
        type invalide, pas le cas légitime."""
        from mcp_vault.auth import context as ctx
        h = ctx.current_token_info.set(self._token(policy_id=""))
        try:
            assert ctx.check_policy("vault_delete") is None
            assert ctx.check_path_policy("v", "secret/x", "read") is None
            assert ctx.can_read_vault_content("v") is True
        finally:
            ctx.current_token_info.reset(h)
