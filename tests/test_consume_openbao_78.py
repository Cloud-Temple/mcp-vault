#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test d'INTÉGRATION #78 — le flux `wrap_secret → consume_wrap_secret` contre un
OpenBao RÉEL.

## Pourquoi ce test est un critère d'acceptation, pas un confort

Le défaut de forme de #78 était INVISIBLE aux simulacres : ceux de `test_wrap.py`
rendaient un payload APLATI (`{"data": {"password": …}}`), forme qu'OpenBao ne
produit jamais pour une lecture KV v2. La garde « secret vide » testait donc un
comportement absent de la production, où l'enveloppe réelle
(`{"data": {"data": …, "metadata": …}}`) porte TOUJOURS `metadata` et n'est donc
jamais vide.

Seul un moteur réel prouve la forme. `test_wrap_status_openbao_77.py` l'atteste
déjà indirectement, mais il unwrap avec un client neuf — il ne traverse PAS
`consume_wrap_secret`, donc il ne couvre pas le chemin de #78.

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
    reason="OpenBao réel requis — poser MCP_VAULT_TEST_OPENBAO_ADDR + _TOKEN (test #78 e2e)",
)

_MOUNT = "consume78"

from tests.conftest import admin_auth_context  # noqa: E402


@pytest.fixture(autouse=True)
def _admin_identity():
    with admin_auth_context():
        yield


def _run(coro):
    import asyncio
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _in_memory_registry():
    from mcp_vault.vault.wrapping import WrapRegistry

    class InMemoryRegistry(WrapRegistry):
        def __init__(self):
            self._wraps = []
            self._cache_time = float("inf")
            self._last_load_ok = True

        def load(self):
            pass

        def _maybe_refresh(self):
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
        path="db/plein", secret={"password": "p78"}, mount_point=_MOUNT)
    yield c
    # Le nettoyage NE DOIT PAS être avalé (relevé en revue) : un mount résiduel
    # ferait porter les exécutions suivantes sur un état pollué, et un banc qui
    # cache son propre échec de teardown ne contrôle rien. Le montage initial,
    # lui, tolère l'absence (`disable` avant `enable`) — c'est une pré-condition,
    # pas une vérification.
    c.sys.disable_secrets_engine(path=_MOUNT)


def _patched(real_client, registry):
    from mcp_vault.vault import wrapping as w
    cfg = MagicMock()
    cfg.openbao_addr = _ADDR
    return patch.multiple(
        w,
        _get_client=MagicMock(return_value=real_client),
        get_wrap_registry=MagicMock(return_value=registry),
        _get_config=MagicMock(return_value=cfg),
    )


def _statut(registry, op):
    return next(e["status"] for e in registry._wraps if e["operation_id"] == op)


# =============================================================================
# 1) Cas nominal — la FORME réelle de la sortie, prouvée par le moteur
# =============================================================================

def test_flux_reel_rend_l_enveloppe_kv2_et_marque_consomme(real_client):
    """
    Preuve empirique du contrat de sortie : `result["data"]` est l'ENVELOPPE
    (`data` + `metadata`), et le secret en clair est à `result["data"]["data"]`.

    Ce test est la seule chose qui empêche de « corriger » le code en aplatissant
    la réponse : un simulacre peut mentir sur cette forme, OpenBao non.
    """
    from mcp_vault.vault.wrapping import wrap_secret, consume_wrap_secret

    reg = _in_memory_registry()
    op = "op-live-78-plein"
    with _patched(real_client, reg):
        wr = _run(wrap_secret(_MOUNT, "db/plein", "m78", op, 300))
        assert wr["status"] == "ok", wr

        res = _run(consume_wrap_secret(
            wrap_token=wr["wrap_token"], operation_id=op, mission_id="m78"))

    assert res["status"] == "ok", res
    assert res["data"]["data"] == {"password": "p78"}, (
        f"forme de sortie inattendue contre OpenBao réel : {res['data']!r}")
    assert "metadata" in res["data"], (
        "l'enveloppe KV v2 doit porter metadata — c'est précisément ce qui la "
        "rend TOUJOURS non vide, et qui rendait la garde inatteignable")
    assert _statut(reg, op) == "consumed"


def test_le_jeton_est_bien_a_usage_unique_contre_le_moteur(real_client):
    """
    Après une consommation réussie, le jeton est mort côté OpenBao. Un second
    appel doit produire un verdict TERMINAL, jamais « réessayer ».
    """
    from mcp_vault.vault.wrapping import wrap_secret, consume_wrap_secret

    reg = _in_memory_registry()
    op = "op-live-78-rejeu"
    with _patched(real_client, reg):
        wr = _run(wrap_secret(_MOUNT, "db/plein", "m78", op, 300))
        assert _run(consume_wrap_secret(
            wrap_token=wr["wrap_token"], operation_id=op,
            mission_id="m78"))["status"] == "ok"

        # Le registre est en `consumed` : le rejeu est arrêté par le registre.
        rejeu = _run(consume_wrap_secret(
            wrap_token=wr["wrap_token"], operation_id=op, mission_id="m78"))

    assert rejeu["status"] == "error", rejeu
    assert rejeu["error_type"] == "already_consumed", rejeu
    assert "ne pas réessayer" in rejeu["message"].lower() or \
           "déjà" in rejeu["message"].lower(), rejeu


def test_un_jeton_mort_est_classe_terminal_par_le_moteur_reel(real_client):
    """
    CŒUR DU FINDING 3, contre le moteur réel. Un wrap_token révoqué côté OpenBao
    doit produire `wrap_unusable` — pas `backend_error` « réessayer », et surtout
    pas un retour à `active`.

    C'est le cas qui échappait au mapping historique : OpenBao répond **400**, là
    où le code ne testait que 403/404.
    """
    from mcp_vault.vault.wrapping import wrap_secret, consume_wrap_secret

    reg = _in_memory_registry()
    op = "op-live-78-mort"
    with _patched(real_client, reg):
        wr = _run(wrap_secret(_MOUNT, "db/plein", "m78", op, 300))
        assert wr["status"] == "ok", wr
        # Tuer le jeton DANS le dos du registre : il le croit encore `active`.
        # Même primitive que la production (`_revoke_accessor_selected`).
        real_client.auth.token.revoke_accessor(accessor=wr["accessor"])

        res = _run(consume_wrap_secret(
            wrap_token=wr["wrap_token"], operation_id=op, mission_id="m78"))

    assert res["status"] == "error", res
    # STRICT (relevé en revue) : accepter aussi `consume_outcome_unknown` ne
    # prouverait que « terminal », pas la CLASSIFICATION annoncée par le finding
    # 3. OpenBao 2.5.1 répond 400 avec son motif exact pour un jeton révoqué :
    # le verdict attendu est donc `wrap_unusable`, et rien d'autre.
    assert res["error_type"] == "wrap_unusable", (
        f"classification non prouvée contre le moteur réel : {res!r}")
    assert _statut(reg, op) == "unusable", (
        f"un jeton révoqué côté OpenBao doit être figé `unusable` — "
        f"statut {_statut(reg, op)!r}")
    assert "ne pas réessayer" in res["message"].lower(), res


# =============================================================================
# 2) Le défaut de forme — un secret sans paire exploitable, contre le moteur
# =============================================================================

def test_secret_sans_paire_ne_sort_pas_en_succes(real_client):
    """
    LE CAS QUE LES SIMULACRES NE POUVAIENT PAS PRODUIRE.

    Un secret KV v2 sans aucune paire : l'enveloppe existe (elle porte
    `metadata`), mais il n'y a rien à utiliser. Avant le correctif, la garde
    testait l'enveloppe externe — toujours vraie — donc le coffre répondait
    `status: "ok"` et l'appelant lisait « succès » sans credential.

    Le jeton a été présenté à OpenBao : il est brûlé, donc `consumed` et
    non réessayable.
    """
    from mcp_vault.vault.wrapping import wrap_secret, consume_wrap_secret

    real_client.secrets.kv.v2.create_or_update_secret(
        path="db/vide", secret={}, mount_point=_MOUNT)

    reg = _in_memory_registry()
    op = "op-live-78-vide"
    with _patched(real_client, reg):
        wr = _run(wrap_secret(_MOUNT, "db/vide", "m78", op, 300))
        assert wr["status"] == "ok", wr

        res = _run(consume_wrap_secret(
            wrap_token=wr["wrap_token"], operation_id=op, mission_id="m78"))

    assert res["status"] == "error", (
        f"un secret sans paire est sorti en SUCCÈS contre OpenBao réel : {res!r}")
    assert res["error_type"] == "empty_secret", res
    assert _statut(reg, op) == "consumed", (
        f"le jeton a été présenté à OpenBao, il est brûlé — statut "
        f"{_statut(reg, op)!r}")
