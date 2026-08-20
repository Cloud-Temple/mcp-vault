#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
`pki setup` — aucun défaut silencieux sur l'installation d'une AC (issue #128).

## Origine

`pki setup` installe l'autorité de certification à laquelle toute la plateforme
fait confiance. Le drapeau de mode valait `--lab` PAR DÉFAUT, et ce mode décide
de la **politique d'enrôlement ACME** :

| Mode | `eab_policy` | Qui obtient un certificat |
| --- | --- | --- |
| `--lab` (ancien défaut) | `not-required` | toute machine passant la vérification de nom |
| `--prod` | `new-account-required` | seulement sur invitation d'un administrateur |

Le mode décidait AUSSI des domaines autorisés (`*.lesur.lan` en laboratoire), et
l'option `--domains` de la CLI portait ces mêmes domaines en valeur par défaut.

**Le défaut mesuré, déjà consigné au CHANGELOG** : une option à valeur chaîne
avale l'option suivante. `pki setup --ttl --prod` donne donc `ttl="--prod"`, le
drapeau n'est jamais vu, et l'ancien défaut posait une AC en enrôlement LIBRE
**sans rien dire**. Combiné à des `--domains` fournis à la main, on obtenait la
pire combinaison : de VRAIS domaines et l'enrôlement libre — tout avait l'air
correct.

## Ce qui est verrouillé ici

Le remède n'est pas « un défaut plus sûr » : c'est l'**absence** de défaut. Rendre
le choix obligatoire transforme l'option avalée en **erreur** au lieu d'un mode
permissif silencieux.

- mode absent → **aucun appel réseau** ;
- `--domains` absent ou vide → **aucun appel réseau** ;
- l'option avalée (`--ttl --prod`) → **aucun appel réseau** ;
- `--lab` / `--prod` explicites → **un** appel, avec le `lab_mode` demandé ;
- ⚠️ **la règle écrite à l'envers** : aucun domaine de laboratoire ne doit
  atteindre le réseau à moins d'avoir été tapé. Un test qui vérifie seulement
  « le refus se produit » resterait vert si un défaut permissif revenait sous un
  autre nom.

## Où l'on intercepte, et pourquoi là

On remplace `MCPClient` et on enregistre les appels d'outil réellement tentés.
C'est l'**absence** d'appel `pki_ca_setup` qui prouve qu'aucune AC n'a été
installée — un code de retour non nul ne le prouverait pas, Click en renvoie un
pour n'importe quelle raison, y compris après un appel déjà parti.

⚠️ **Ce que cette frontière prouve et ne prouve pas.** Le premier jet interceptait
`httpx.AsyncClient`, comme `test_purge_destructive.py`. Ça ne marche pas ici :
`call_tool` passe par le SDK MCP (Streamable HTTP + SSE), pas par un `post()`
direct — les cas passants ne voyaient donc AUCUN appel, et trois tests
échouaient. La bonne frontière est `MCPClient` : la garde vit dans le rappel
Click, **strictement en amont** de tout transport, et le défaut de #128 est un
défaut d'analyse d'arguments. Ce fichier ne dit donc rien du transport, et il
n'a pas à en dire quelque chose.

Symétriquement, les cas passants assertionnent qu'il y a **exactement un** appel :
sans cela, un simulacre muet rendrait toute la classe verte sans rien exercer.
"""

import os
import sys
from unittest.mock import patch

import pytest
from click.testing import CliRunner

_scripts = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
if _scripts not in sys.path:
    sys.path.insert(0, _scripts)

from cli.commands import cli

_JETON_TEST = "jeton-de-test-non-secret"


class _Enregistreur:
    """Faux `MCPClient` : enregistre chaque appel d'outil TENTÉ.

    Enregistre aussi l'URL et le jeton reçus : un appel parti vers la mauvaise
    cible, ou sans authentification, ne doit pas passer pour un succès.
    """

    appels = []          # partagé — remis à zéro par `_run`

    def __init__(self, url, token):
        self.url = url
        self.token = token

    async def call_tool(self, nom, arguments, on_progress=None):
        _Enregistreur.appels.append({
            "outil": nom, "arguments": arguments,
            "url": self.url, "token": self.token,
        })
        return {"status": "ok", "lab_mode": arguments.get("lab_mode")}


def _run(argv):
    _Enregistreur.appels = []
    with patch("cli.commands.MCPClient", _Enregistreur):
        res = CliRunner().invoke(cli, ["--token", _JETON_TEST] + argv)
    return _Enregistreur.appels, res


def _setups(appels):
    """Ne retient que les tentatives d'installation d'AC."""
    return [a for a in appels if a["outil"] == "pki_ca_setup"]


# ─────────────────────────────────────────────────────────────────────────────
# Refus — et la preuve est l'ABSENCE d'appel réseau
# ─────────────────────────────────────────────────────────────────────────────

def test_mode_absent_aucun_appel_reseau():
    """Sans --lab ni --prod : refus, et AUCUNE AC installée."""
    appels, res = _run(["pki", "setup", "--domains", "mcp.cloud-temple.app"])

    assert res.exit_code != 0
    assert _setups(appels) == [], (
        "Une AC a été installée sans mode explicite : "
        f"{len(_setups(appels))} appel(s) émis"
    )
    assert "--lab" in res.output and "--prod" in res.output, (
        "Le message doit NOMMER les deux choix — un refus qui n'indique pas quoi "
        f"taper renvoie l'opérateur à la devinette. Sortie : {res.output!r}"
    )


def test_option_avalee_par_ttl_aucun_appel_reseau():
    """
    ⚠️ LE cas de régression : `--ttl --prod` fait avaler `--prod` comme valeur.

    Hier : `ttl="--prod"`, mode retombé sur le défaut `--lab`, AC posée en
    enrôlement LIBRE sans un mot. Aujourd'hui : erreur, rien d'émis.
    """
    appels, res = _run(["pki", "setup", "--domains", "mcp.cloud-temple.app",
                      "--ttl", "--prod"])

    assert res.exit_code != 0
    assert _setups(appels) == [], (
        "L'option avalée a laissé passer une installation d'AC — c'est "
        "exactement le défaut de #128"
    )


def test_domaines_absents_aucun_appel_reseau():
    """Sans --domains : refus, et aucun domaine deviné."""
    appels, res = _run(["pki", "setup", "--prod"])

    assert res.exit_code != 0
    assert _setups(appels) == []
    assert "--domains" in res.output


def test_domaines_vides_aucun_appel_reseau():
    """`--domains ''` et `--domains '   '` sont refusés comme une absence."""
    for valeur in ("", "   "):
        appels, res = _run(["pki", "setup", "--prod", "--domains", valeur])
        assert res.exit_code != 0, f"--domains {valeur!r} accepté"
        assert _setups(appels) == [], f"--domains {valeur!r} a déclenché un appel"


# ─────────────────────────────────────────────────────────────────────────────
# Cas passants — un appel EXACTEMENT, et le mode demandé transmis
# ─────────────────────────────────────────────────────────────────────────────

def test_lab_explicite_transmet_lab_mode_vrai():
    appels, res = _run(["pki", "setup", "--lab",
                      "--domains", "*.lesur.lan,lesur.lan"])

    assert res.exit_code == 0, res.output
    assert len(_setups(appels)) == 1, (
        f"Un appel attendu, {len(_setups(appels))} émis — sans cette assertion, un "
        "simulacre muet rendrait toute cette classe verte sans rien exercer"
    )
    args = _setups(appels)[0]["arguments"]
    assert args["lab_mode"] is True
    assert args["allowed_domains"] == "*.lesur.lan,lesur.lan"


def test_prod_explicite_transmet_lab_mode_faux():
    appels, res = _run(["pki", "setup", "--prod",
                      "--domains", "mcp.cloud-temple.app", "--ttl", "720h"])

    assert res.exit_code == 0, res.output
    assert len(_setups(appels)) == 1
    args = _setups(appels)[0]["arguments"]
    assert args["lab_mode"] is False, (
        "lab_mode=False est ce qui donne eab_policy=new-account-required : "
        "c'est la seule chose qui exige une invitation pour obtenir un certificat"
    )
    assert args["leaf_ttl"] == "720h"


# ─────────────────────────────────────────────────────────────────────────────
# La règle écrite à l'envers — bloquer SAUF si explicitement tapé
# ─────────────────────────────────────────────────────────────────────────────

def test_aucun_domaine_de_laboratoire_n_atteint_le_reseau_sans_etre_tape():
    """
    ⚠️ Garde-fou inversé.

    Vérifier « le refus se produit » resterait vert si un défaut permissif
    revenait sous un autre nom. On vérifie donc la propriété RÉELLE : sur toutes
    les invocations qui ne tapent PAS `lesur.lan`, aucun POST ne doit le porter.
    """
    invocations = [
        ["pki", "setup"],
        ["pki", "setup", "--prod"],
        ["pki", "setup", "--lab"],
        ["pki", "setup", "--domains", "mcp.cloud-temple.app"],
        ["pki", "setup", "--prod", "--domains", "mcp.cloud-temple.app"],
        ["pki", "setup", "--prod", "--domains", "mcp.cloud-temple.app", "--ttl", "--lab"],
    ]
    for argv in invocations:
        appels, _ = _run(argv)
        for appel in _setups(appels):
            domaines = appel["arguments"].get("allowed_domains", "")
            assert "lesur.lan" not in domaines, (
                f"{argv} a fait partir un domaine de laboratoire non demandé : "
                f"{domaines!r}"
            )


def test_prod_ne_peut_pas_etre_obtenu_par_defaut():
    """
    Symétrique du précédent : aucune invocation SANS `--prod` ne doit produire
    `lab_mode=False`. Verrouille contre un « défaut plus sûr » qui remplacerait
    l'absence de défaut — ce qui recréerait le même mode de défaillance à
    l'envers (une décision prise par le code au lieu de l'opérateur).
    """
    appels, _ = _run(["pki", "setup", "--lab", "--domains", "x.fr"])
    assert _setups(appels)[0]["arguments"]["lab_mode"] is True

    for argv in (["pki", "setup", "--domains", "x.fr"],
                 ["pki", "setup", "--domains", "x.fr", "--ttl", "--prod"]):
        appels, _ = _run(argv)
        assert _setups(appels) == [], f"{argv} a émis un appel sans mode explicite"
