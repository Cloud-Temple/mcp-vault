# -*- coding: utf-8 -*-
"""
Tests du TokenStore — durcissement validation permissions/allowed_resources
(issue #86, extension Lot 3).

Non-complaisant — on prouve l'invariant de sécurité, pas la couverture :

  - BUG CENTRAL (élévation de privilège) : `update()` validait `permissions`
    par `all(isinstance(p, str) and p in VALID_PERMISSIONS for p in
    permissions)` SANS vérifier au préalable que `permissions` est une
    LISTE. Un dict `{"admin": True}` itéré donne ses CLÉS ("admin", une str
    valide) → la validation acceptait à tort ce dict, stocké tel quel. Au
    moment de la décision (`context.py`, `"admin" in token_info.get(
    "permissions", [])`), `"admin" in {"admin": True}` teste l'appartenance
    d'une clé de dict → True → le token devenait ADMIN TOTAL.
  - Même bug via un `tokens.json` corrompu chargé par `load()` avec
    `permissions: "admin"` (string) → `"admin" in "admin"` (sous-chaîne).
  - `create()` avait le même défaut sur `allowed_resources` (`or []`
    masquait toute valeur falsy non-None).
  - `update()` n'avait AUCUNE validation sur `allowed_resources`.
  - Validation stricte partagée (create()/update()/load()) via
    `_validate_permissions`/`_validate_allowed_resources` — jamais une
    resaisie locale divergente.
  - `update()` valide AVANT tout effet de bord (refresh, résolution de hash).
  - `load()` : tout-ou-rien (cohérent avec PolicyStore), hash dupliqué
    détecté, format hash strict (SHA-256 hex 64 minuscules), compat
    historique policy_id absent → "".

  LIMITE EXPLICITE (documentée, PAS fermée par ce lot) : `available`/
  `last_error` sont diagnostiques seulement — `get_by_hash()` continue de
  servir le cache périmé après une panne S3 détectée (y compris après une
  révocation distante). Résidu séparé, impact opérationnel plus large
  (deny-all bearer), hors scope ici.

Aucune dépendance S3 / Docker : le client S3 est mocké au niveau _get_s3_data.
"""

import json
import os
import sys
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp_vault.auth.token_store import (
    TokenStore,
    _RETRY_AFTER_ERROR_SECONDS,
    _validate_allowed_resources,
    _validate_and_normalize_token,
    _validate_permissions,
)

_VALID_HASH = "a" * 64


def _make_store(offline: bool = True) -> TokenStore:
    """Store avec S3 neutralisé (tests de logique pure). _save détecte toute écriture."""
    settings = SimpleNamespace(s3_endpoint_url="http://localhost:0", s3_bucket_name="test-bucket")
    store = TokenStore(settings)
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
    from botocore.exceptions import ClientError
    return ClientError(
        {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}},
        "GetObject",
    )


def _token(**over):
    """Token conforme minimal (surchargeable pour forger des cas invalides)."""
    t = {"hash": _VALID_HASH, "client_name": "c", "permissions": ["read"],
         "allowed_resources": [], "policy_id": "", "revoked": False}
    t.update(over)
    return t


def _file_bytes(tokens):
    return json.dumps({"tokens": tokens}).encode()


# =============================================================================
# Helpers de validation partagés
# =============================================================================

class TestValidatePermissions:
    def test_valid_list_accepted(self):
        val, err = _validate_permissions(["read", "write"])
        assert val == ["read", "write"]
        assert err == ""

    def test_dict_rejected_not_silently_accepted_via_key_iteration(self):
        """RÉGRESSION CENTRALE : un dict {"admin": True} ne doit JAMAIS passer —
        itérer sur ses clés donnerait "admin" (une str valide) si on ne
        vérifiait pas isinstance(list) en premier."""
        val, err = _validate_permissions({"admin": True})
        assert val is None
        assert err

    def test_string_rejected_not_silently_accepted_via_char_iteration(self):
        """Un `permissions="admin"` (string) ne doit pas passer — itérer sur
        les caractères ('a','d','m','i','n') échoue déjà au test d'appartenance
        (aucun n'est dans VALID_PERMISSIONS), mais on verrouille explicitement
        le type list."""
        val, err = _validate_permissions("admin")
        assert val is None

    def test_empty_list_rejected(self):
        val, err = _validate_permissions([])
        assert val is None

    def test_invalid_value_rejected(self):
        val, err = _validate_permissions(["read", "superadmin"])
        assert val is None


class TestValidateAllowedResources:
    def test_valid_list_accepted(self):
        val, err = _validate_allowed_resources(["v1", "v2"])
        assert val == ["v1", "v2"]

    def test_empty_list_accepted(self):
        """Liste vide = owner-based, légitime (pas d'erreur)."""
        val, err = _validate_allowed_resources([])
        assert val == []

    def test_false_rejected_not_silently_empty(self):
        """RÉGRESSION : `False` ne doit PAS être silencieusement traité comme []."""
        val, err = _validate_allowed_resources(False)
        assert val is None

    def test_non_string_element_rejected(self):
        val, err = _validate_allowed_resources(["v1", 123])
        assert val is None


# =============================================================================
# _validate_and_normalize_token
# =============================================================================

class TestValidateAndNormalizeToken:
    def test_valid_minimal_token_normalized(self):
        norm = _validate_and_normalize_token(_token())
        assert norm["hash"] == _VALID_HASH
        assert norm["permissions"] == ["read"]

    def test_not_a_dict_rejected(self):
        with pytest.raises(ValueError):
            _validate_and_normalize_token(["not", "a", "dict"])

    def test_hash_wrong_length_rejected(self):
        with pytest.raises(ValueError):
            _validate_and_normalize_token(_token(hash="abc"))

    def test_hash_uppercase_rejected(self):
        with pytest.raises(ValueError):
            _validate_and_normalize_token(_token(hash="A" * 64))

    def test_permissions_dict_rejected(self):
        with pytest.raises(ValueError):
            _validate_and_normalize_token(_token(permissions={"admin": True}))

    def test_allowed_resources_false_rejected(self):
        with pytest.raises(ValueError):
            _validate_and_normalize_token(_token(allowed_resources=False))

    def test_policy_id_absent_normalized_to_empty_string(self):
        """Compat historique : les tokens antérieurs à l'ajout des policies
        n'ont pas ce champ du tout."""
        raw = _token()
        del raw["policy_id"]
        norm = _validate_and_normalize_token(raw)
        assert norm["policy_id"] == ""

    def test_policy_id_remove_sentinel_normalized(self):
        norm = _validate_and_normalize_token(_token(policy_id="_remove"))
        assert norm["policy_id"] == ""

    def test_revoked_non_bool_rejected(self):
        with pytest.raises(ValueError):
            _validate_and_normalize_token(_token(revoked="false"))

    def test_expires_at_naive_datetime_rejected(self):
        """Une date ISO sans timezone est parseable mais casse la comparaison
        aware/naive lors de _is_expired()."""
        with pytest.raises(ValueError):
            _validate_and_normalize_token(_token(expires_at="2026-01-01T00:00:00"))

    def test_expires_at_aware_datetime_accepted(self):
        norm = _validate_and_normalize_token(_token(expires_at="2026-01-01T00:00:00+00:00"))
        assert norm["expires_at"] == "2026-01-01T00:00:00+00:00"

    def test_expires_at_none_accepted(self):
        norm = _validate_and_normalize_token(_token(expires_at=None))
        assert norm["expires_at"] is None

    def test_does_not_mutate_input(self):
        raw = _token()
        original = json.dumps(raw)
        _validate_and_normalize_token(raw)
        assert json.dumps(raw) == original


# =============================================================================
# load() — atomique, tout-ou-rien
# =============================================================================

class TestLoad:
    def test_nosuchkey_is_nominal_empty_store(self):
        store = TokenStore(SimpleNamespace(s3_bucket_name="b"))
        store._get_s3_data = MagicMock(return_value=_fake_s3(get_exc=_client_error("NoSuchKey")))
        store.load()
        assert store.available is True
        assert store.count() == 0

    def test_network_error_marks_invalid_cache_preserved(self):
        store = TokenStore(SimpleNamespace(s3_bucket_name="b"))
        store._tokens = {_VALID_HASH: _token()}
        store._get_s3_data = MagicMock(return_value=_fake_s3(get_exc=Exception("boom")))
        store.load()
        assert store.available is False
        assert store._tokens == {_VALID_HASH: _token()}

    def test_top_level_empty_object_is_invalid_not_empty_store(self):
        store = TokenStore(SimpleNamespace(s3_bucket_name="b"))
        store._get_s3_data = MagicMock(return_value=_fake_s3(get_return=b"{}"))
        store.load()
        assert store.available is False

    def test_deeply_nested_json_marks_invalid_not_crash(self):
        """BLOQUANT round diff review : un JSON profondément imbriqué (`[`×2000
        `]`×2000) lève RecursionError, PAS ValueError — un except trop étroit
        laisse cette exception non gérée remonter jusqu'à get_by_hash()/
        l'authentification bearer au lieu de fail-close proprement."""
        store = TokenStore(SimpleNamespace(s3_bucket_name="b"))
        pathological = ("[" * 2000 + "]" * 2000).encode()
        store._get_s3_data = MagicMock(return_value=_fake_s3(get_return=pathological))
        store.load()  # ne doit lever AUCUNE exception
        assert store.available is False

    def test_one_corrupted_token_invalidates_whole_load(self):
        """Tout-ou-rien : un token avec permissions="admin" invalide TOUT le
        chargement — jamais un token corrompu chargé, même partiellement."""
        store = TokenStore(SimpleNamespace(s3_bucket_name="b"))
        good = _token(hash="b" * 64)
        bad = _token(hash="c" * 64, permissions="admin")
        store._get_s3_data = MagicMock(return_value=_fake_s3(get_return=_file_bytes([good, bad])))
        store.load()
        assert store.available is False
        assert store.count() == 0

    def test_duplicate_hash_invalidates_load(self):
        store = TokenStore(SimpleNamespace(s3_bucket_name="b"))
        t1 = _token(client_name="a")
        t2 = _token(client_name="b")
        store._get_s3_data = MagicMock(return_value=_fake_s3(get_return=_file_bytes([t1, t2])))
        store.load()
        assert store.available is False

    def test_remove_sentinel_migrated_and_repersisted(self):
        store = TokenStore(SimpleNamespace(s3_bucket_name="b"))
        legacy = _token(policy_id="_remove")
        fake_s3 = _fake_s3(get_return=_file_bytes([legacy]))
        store._get_s3_data = MagicMock(return_value=fake_s3)
        store.load()
        assert store.available is True
        assert store._tokens[_VALID_HASH]["policy_id"] == ""
        fake_s3.put_object.assert_called_once()  # re-persisté

    def test_successful_load_resets_available_and_last_error(self):
        store = TokenStore(SimpleNamespace(s3_bucket_name="b"))
        store._available = False
        store._last_error = "ancienne panne"
        store._get_s3_data = MagicMock(return_value=_fake_s3(get_return=_file_bytes([_token()])))
        store.load()
        assert store.available is True
        assert store.last_error == ""


# =============================================================================
# create() — allowed_resources durci
# =============================================================================

class TestCreateHardening:
    def test_create_rejects_falsy_non_none_allowed_resources(self):
        """RÉGRESSION : `allowed_resources or []` (round policies.py 1) —
        même bug ici. `allowed_resources=False` doit être rejeté, pas
        silencieusement transformé en []."""
        store = _make_store()
        result = store.create("c", ["read"], allowed_resources=False)
        assert result["status"] == "error"
        store._save.assert_not_called()

    def test_create_rejects_permissions_dict(self):
        store = _make_store()
        result = store.create("c", {"admin": True})
        assert result["status"] == "error"
        store._save.assert_not_called()

    def test_create_none_allowed_resources_defaults_to_empty_list(self):
        """Non-régression : absence de allowed_resources → [] (comportement historique)."""
        store = _make_store()
        result = store.create("c", ["read"])
        assert result["allowed_resources"] == []


# =============================================================================
# update() — LE bug central (élévation de privilège) + validation avant effet de bord
# =============================================================================

class TestUpdateHardening:
    def test_update_rejects_permissions_dict_no_bypass(self):
        """POC EXACT du bug round 4 : {"permissions": {"admin": True}} ne doit
        PLUS être accepté — sinon le token stocke ce dict, et
        "admin" in token_info["permissions"] devient True au moment de la
        décision (test d'appartenance de clé de dict)."""
        store = _make_store()
        store._tokens = {_VALID_HASH: _token()}
        result = store.update(_VALID_HASH, permissions={"admin": True})
        assert result["status"] == "error"
        assert store._tokens[_VALID_HASH]["permissions"] == ["read"], \
            "le token ne doit PAS avoir été muté"

    def test_update_rejects_allowed_resources_false(self):
        store = _make_store()
        store._tokens = {_VALID_HASH: _token()}
        result = store.update(_VALID_HASH, allowed_resources=False)
        assert result["status"] == "error"

    def test_update_rejects_non_string_policy_id(self):
        store = _make_store()
        store._tokens = {_VALID_HASH: _token()}
        result = store.update(_VALID_HASH, policy_id=123)
        assert result["status"] == "error"

    def test_update_validates_before_any_side_effect(self):
        """Un payload invalide ne doit déclencher NI refresh NI résolution de
        hash NI mutation — validation en tout premier."""
        store = _make_store()
        store._tokens = {_VALID_HASH: _token()}
        store.update(_VALID_HASH, permissions={"admin": True})
        store._maybe_refresh.assert_not_called()
        store._save.assert_not_called()

    def test_update_legitimate_values_still_works(self):
        """Non-régression : mise à jour légitime continue de fonctionner."""
        store = _make_store()
        store._tokens = {_VALID_HASH: _token()}
        result = store.update(_VALID_HASH, permissions=["read", "write"],
                               allowed_resources=["v1"], policy_id="p1")
        assert result["status"] == "updated"
        assert store._tokens[_VALID_HASH]["permissions"] == ["read", "write"]
        assert store._tokens[_VALID_HASH]["allowed_resources"] == ["v1"]
        assert store._tokens[_VALID_HASH]["policy_id"] == "p1"

    def test_update_remove_sentinel_still_clears_policy(self):
        store = _make_store()
        store._tokens = {_VALID_HASH: _token(policy_id="p1")}
        result = store.update(_VALID_HASH, policy_id="_remove")
        assert result["status"] == "updated"
        assert store._tokens[_VALID_HASH]["policy_id"] == ""


# =============================================================================
# Retry accéléré (diagnostique)
# =============================================================================

class TestCopyOnWrite:
    """#123 : une mutation non persistée ne doit RIEN changer à ce qui est servi.

    ⚠️ Trou de couverture trouvé PAR MUTATION, pas par relecture : publier le
    candidat avant la confirmation du PUT ne faisait rougir aucun test. C'est
    pourtant le chemin le plus critique du magasin — l'ancien code portait un
    rollback explicite commenté « une révocation non persistée est CRITIQUE ».
    """

    def test_une_revocation_NON_PERSISTEE_ne_revoque_rien_en_memoire(self):
        store = TokenStore(SimpleNamespace(s3_bucket_name="b"))
        jeton = _token()
        publie_avant = {jeton["hash"]: jeton}
        store._tokens = publie_avant
        store.freshness.mark_success()
        store._get_s3_data = MagicMock(return_value=_fake_s3(put_ok=False))

        res = store.revoke(jeton["hash"][:12])

        assert res["status"] == "storage_unavailable", res
        assert store._tokens[jeton["hash"]]["revoked"] is False, (
            "le jeton apparaît révoqué alors que l'écriture a échoué : au "
            "redémarrage il redeviendrait valide, et l'exploitant aurait cru la "
            "révocation faite")
        # La référence publiée est INCHANGÉE : aucun état intermédiaire n'a été
        # publié, pas seulement « le contenu final est bon ».
        assert store._tokens is publie_avant

    def test_une_creation_NON_PERSISTEE_n_authentifie_pas(self):
        """Le symétrique, dans le sens qui ouvre l'accès : un token créé mais non
        écrit ne doit jamais authentifier — il disparaîtrait au redémarrage."""
        store = TokenStore(SimpleNamespace(s3_bucket_name="b"))
        store.freshness.mark_success()
        store._get_s3_data = MagicMock(return_value=_fake_s3(put_ok=False))

        res = store.create(client_name="agent", permissions=["read"])

        assert res.get("error_type") == "storage_unavailable", res
        assert store._tokens == {}, "un token non persisté est servi en mémoire"


class TestRetryTiming:
    """⚠️ #123 : la cadence de re-tentative a changé de PROPRIÉTAIRE.

    Elle n'est plus portée par `_maybe_refresh` — qui ne charge plus rien — mais
    par le rafraîchisseur de fond, et elle est prouvée dans
    `tests/test_store_refresh_123.py`. Ce qui est vérifié ici, c'est ce qui reste
    vrai du magasin : le point de décision ne touche jamais le réseau, quel que
    soit son état.
    """

    def test_le_point_de_decision_n_appelle_JAMAIS_S3(self):
        store = TokenStore(SimpleNamespace(s3_bucket_name="b"))
        store._mark_invalid("panne")
        store._get_s3_data = MagicMock(side_effect=AssertionError(
            "S3 appelé depuis le point de décision — c'est le gel de #110"))
        store._maybe_refresh()
        assert store.available is False
        # Le chemin réellement emprunté à chaque requête authentifiée.
        assert store.get_by_hash("inexistant") is None

    def test_un_instantane_PERIME_est_signale_sans_bloquer_le_bearer(self):
        """La POSTURE de ce magasin est inchangée par #123 : `available` reste
        DIAGNOSTIQUE. Un instantané périmé doit être visible — pour la sonde et
        l'exploitant — sans se mettre à refuser l'authentification, ce qui serait
        un changement de comportement bien plus large (deny-all bearer pendant
        une panne S3) et reste hors périmètre, cf. docstring du module."""
        store = TokenStore(SimpleNamespace(s3_bucket_name="b"))
        jeton = _token()
        store._tokens = {jeton["hash"]: jeton}
        store.freshness.mark_success()
        store.freshness._last_success -= store.CACHE_TTL + 1
        store._maybe_refresh()
        assert store.available is False              # signalé
        assert store.get_by_hash(jeton["hash"]) is not None  # mais toujours servi
