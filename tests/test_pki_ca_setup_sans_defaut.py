#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
`pki_ca_setup` (outil MCP) — aucun défaut silencieux (issue #128).

## Origine — la surface qui compte, et celle que j'avais failli oublier

Le défaut de #128 a d'abord été corrigé sur la CLI
(`tests/cli/test_pki_setup_mode_explicite.py`). **La CLI n'est appelée par aucun
script du dépôt** : seule la documentation la mentionne. L'outil MCP, lui, est la
surface réellement utilisée par la plateforme — et il portait les MÊMES défauts :

    lab_mode: bool = True
    allowed_domains: str = "*.lesur.lan,lesur.lan"

⚠️ **Un appel SANS ARGUMENT — le cas naturel pour un appelant qui veut
« installer la PKI » — rétrogradait une production saine.** Mesuré sur la
production le 20/08/2026 (`GET /admin/api/pki/status`, jeton de lecture seule) :
`eab_policy=new-account-required`, domaines `internal.agentic.cloud-temple.app`.
Les deux écritures de `setup_pki_ca` sont **inconditionnelles** :

| Écriture | Effet d'un appel sans argument |
| --- | --- |
| `roles/acme-servers` (`allowed_domains`) | écrasé par `*.lesur.lan` ⇒ plus aucun certificat émissible pour les vrais domaines |
| `config/acme` (`eab_policy`) | `new-account-required` → `not-required` ⇒ **enrôlement ACME ouvert** |

L'ancienne docstring annonçait « Idempotent ». C'était vrai de la CRÉATION des
autorités, faux de ces deux écritures — un mot qui affirmait autre chose que le
fait, exactement la faute que #78 nous a apprise.

## Ce qui est verrouillé ici

- `lab_mode` et `allowed_domains` n'ont **aucun défaut** ⇒ ils sont `required`
  dans le schéma MCP. C'est la seule chose qui empêche l'appel sans argument ;
- une liste de domaines qui se réduit à du vide est **refusée**, et
  `setup_pki_ca` n'est **jamais atteint** ;
- les valeurs explicites sont transmises **telles quelles** — `lab_mode=False`
  doit arriver `False`, puisque c'est lui seul qui produit
  `eab_policy=new-account-required`.

## Pourquoi on assertionne sur la signature

Le décorateur `@mcp.tool()` rend la fonction nue : il n'y a pas d'objet-schéma à
interroger. Le schéma JSON exposé aux clients MCP est **dérivé** de la signature,
et un paramètre sans défaut y devient `required`. La signature EST donc le
contrat, et c'est le seul endroit où l'affirmer.
"""

import inspect
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

_src = str(Path(__file__).resolve().parents[1] / "src")
if _src not in sys.path:
    sys.path.insert(0, _src)

from mcp_vault import server


# ─────────────────────────────────────────────────────────────────────────────
# Le contrat : aucun défaut sur les deux paramètres qui décident de la sécurité
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("param", ["lab_mode", "allowed_domains"])
def test_parametre_sans_defaut_donc_requis_dans_le_schema(param):
    sig = inspect.signature(server.pki_ca_setup)
    assert param in sig.parameters, f"{param} a disparu de la signature"
    assert sig.parameters[param].default is inspect.Parameter.empty, (
        f"{param} a repris une valeur par défaut "
        f"({sig.parameters[param].default!r}) : il redevient optionnel dans le "
        "schéma MCP, et un appel sans argument peut de nouveau rétrograder la "
        "production (domaines de laboratoire + enrôlement ACME ouvert)"
    )


def test_leaf_ttl_reste_optionnel():
    """
    Garde-fou inversé : la correction ne doit pas rendre TOUT obligatoire.

    `leaf_ttl` ne décide d'aucune politique de sécurité — le rendre obligatoire
    serait une friction gratuite. Ce test échoue si quelqu'un « durcit » au-delà
    de ce que le défaut justifiait.
    """
    sig = inspect.signature(server.pki_ca_setup)
    assert sig.parameters["leaf_ttl"].default == "720h"


# ─────────────────────────────────────────────────────────────────────────────
# Comportement : domaines vides refusés AVANT toute écriture
# ─────────────────────────────────────────────────────────────────────────────

async def _appel(lab_mode, allowed_domains):
    """Exécute l'outil avec les gardes d'autorisation neutralisées.

    Retourne (résultat, appels_à_setup_pki_ca).

    ⚠️ Test ASYNCHRONE natif, et c'est délibéré. Le premier jet enveloppait
    l'appel dans `asyncio.run()` : les huit tests passaient en isolation et la
    SUITE COMPLÈTE se bloquait au-delà de dix minutes. `asyncio.run` ferme la
    boucle globale, ce qui casse les tests suivants — le projet l'avait déjà
    documenté dans `test_pki._run` (issue #36) et je ne l'avais pas cherché.
    `pytest.ini` porte `asyncio_mode = auto` : un `async def` suffit, et rien ne
    ferme de boucle.
    """
    appels = []

    async def _faux_setup(lab, domaines, ttl):
        appels.append({"lab_mode": lab, "domaines": domaines, "ttl": ttl})
        return {"status": "ok"}

    with patch("mcp_vault.auth.context.check_policy", return_value=None), \
         patch("mcp_vault.auth.context.check_admin_permission", return_value=None), \
         patch("mcp_vault.vault.pki_ca.setup_pki_ca", _faux_setup):
        res = await server.pki_ca_setup(lab_mode=lab_mode,
                                        allowed_domains=allowed_domains)
    return res, appels


@pytest.mark.parametrize("domaines", ["", "   ", ",", " , , "])
async def test_domaines_vides_refuses_sans_aucune_ecriture(domaines):
    res, appels = await _appel(False, domaines)

    assert res.get("status") == "error", f"{domaines!r} accepté : {res!r}"
    assert res.get("error_type") == "invalid_input"
    assert appels == [], (
        f"{domaines!r} a atteint setup_pki_ca : le rôle ACME aurait été réécrit "
        "avec une liste de domaines vide"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Transmission fidèle — c'est lab_mode qui décide de la politique d'enrôlement
# ─────────────────────────────────────────────────────────────────────────────

async def test_prod_transmis_tel_quel():
    res, appels = await _appel(False, "internal.agentic.cloud-temple.app, *.internal.agentic.cloud-temple.app")

    assert len(appels) == 1, (
        f"Un appel attendu, {len(appels)} observé(s) — sans cette assertion, un "
        "simulacre muet rendrait ce fichier vert sans rien exercer"
    )
    assert appels[0]["lab_mode"] is False, (
        "lab_mode=False est la SEULE chose qui produit "
        "eab_policy=new-account-required, donc l'enrôlement sur invitation"
    )
    assert appels[0]["domaines"] == [
        "internal.agentic.cloud-temple.app",
        "*.internal.agentic.cloud-temple.app",
    ], "les domaines doivent arriver découpés et détrimés, sans perte ni ajout"


async def test_lab_transmis_tel_quel():
    res, appels = await _appel(True, "*.lesur.lan,lesur.lan")

    assert len(appels) == 1
    assert appels[0]["lab_mode"] is True
    assert appels[0]["domaines"] == ["*.lesur.lan", "lesur.lan"]


async def test_aucun_domaine_de_laboratoire_n_est_ajoute_par_le_code():
    """
    Garde-fou inversé : le code ne doit JAMAIS compléter la liste fournie.

    Vérifier seulement « prod fonctionne » resterait vert si le code ajoutait
    silencieusement `*.lesur.lan` à côté des domaines demandés — ce qui
    rouvrirait l'émission pour un domaine que personne n'a nommé.
    """
    _, appels = await _appel(False, "mcp.cloud-temple.app")
    assert appels[0]["domaines"] == ["mcp.cloud-temple.app"]
    assert not any("lesur" in d for d in appels[0]["domaines"])
