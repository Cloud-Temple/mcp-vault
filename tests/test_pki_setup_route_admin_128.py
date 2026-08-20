#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
`POST /admin/api/pki/setup` — aucun défaut silencieux (issue #128, 3ᵉ surface).

## Origine — la surface que j'avais failli oublier deux fois

Le défaut de #128 vit sur **trois** surfaces, découvertes l'une après l'autre :

1. la **CLI** `pki setup` — corrigée d'abord… et qu'aucun script du dépôt n'appelle ;
2. l'**outil MCP** `pki_ca_setup` — la surface que la plateforme utilise ;
3. **cette route HTTP** — la plus permissive des trois.

Chacune a été trouvée en cherchant la **classe** du défaut après avoir corrigé
l'occurrence précédente. La leçon est là, pas dans le correctif.

## Ce que cette route permettait

    lab_mode = data.get("lab_mode", True)          # défaut PERMISSIF
    raw_domains = data.get("allowed_domains")      # absent → None
    # ... None n'étant pas une str, allowed_domains restait None, et
    # setup_pki_ca traduisait None en ["*.lesur.lan", "lesur.lan"]

⇒ **Un POST au corps VIDE (`{}`) suffisait à rétrograder une production saine**, les deux
écritures de `setup_pki_ca` étant INCONDITIONNELLES :

| Écriture | Effet |
| --- | --- |
| `roles/acme-servers` | domaines réels écrasés par `*.lesur.lan` ⇒ plus aucun certificat émissible |
| `config/acme` | `eab_policy` de `new-account-required` à `not-required` ⇒ **enrôlement ACME ouvert** |

Aucune validation n'existait : ni corps illisible, ni domaines vides, ni `lab_mode`
non booléen. La console web, elle, envoie toujours les deux champs — **c'est la route nue
qui était exposée**, et elle n'a pas besoin de la console pour être appelée.

État de la production relevé le 20/08/2026 (`GET /admin/api/pki/status`, jeton de lecture
seule) : `eab_policy=new-account-required`. Le correctif est **préventif**.

## Ce qui est verrouillé ici

La propriété vérifiée n'est pas « un 400 est renvoyé » mais **« `setup_pki_ca` n'est jamais
attendu »** : c'est l'absence d'appel qui prouve qu'aucune AC n'a été touchée. Un code de
retour ne le prouverait pas — il peut arriver après l'écriture.

⚠️ Cas qui mérite son propre test : `lab_mode: "false"` (la CHAÎNE). Sous l'ancien code,
`data.get("lab_mode", True)` la transmettait telle quelle, et une chaîne non vide est
**vraie** en Python — un appelant qui croyait demander la production obtenait
l'enrôlement libre. Exiger un booléen réel est la seule chose qui ferme ce cas.
"""

import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

_src = str(Path(__file__).resolve().parents[1] / "src")
if _src not in sys.path:
    sys.path.insert(0, _src)


# ─────────────────────────────────────────────────────────────── harnais ASGI

def _collecteur():
    messages: list[dict] = []

    async def send(message: dict) -> None:
        messages.append(message)

    return messages, send


def _corps(payload):
    raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    livre = False

    async def receive():
        nonlocal livre
        if livre:
            return {"type": "http.request", "body": b"", "more_body": False}
        livre = True
        return {"type": "http.request", "body": raw, "more_body": False}

    return receive


def _reponse(messages):
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    raw = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    return status, json.loads(raw)


_ADMIN = {"client_name": "test-128", "permissions": ["admin"], "allowed_resources": []}
_LECTEUR = {"client_name": "test-128-ro", "permissions": ["read"], "allowed_resources": []}


async def _post(payload, token_info=None):
    """POST /admin/api/pki/setup ; retourne (status, corps, mock setup_pki_ca)."""
    from mcp_vault.admin.api import _handle_admin_routes

    messages, send = _collecteur()
    scope = {"path": "/admin/api/pki/setup", "method": "POST", "query_string": b""}
    with patch("mcp_vault.vault.pki_ca.setup_pki_ca",
               new_callable=AsyncMock) as setup:
        setup.return_value = {"status": "ok"}
        await _handle_admin_routes(scope, _corps(payload), send, None,
                                   token_info or _ADMIN)
    status, corps = _reponse(messages)
    return status, corps, setup


# ───────────────────────────────────── refus, et AUCUNE écriture d'autorité

async def test_corps_vide_refuse_sans_toucher_l_autorite():
    """⚠️ LE cas de régression : `{}` rétrogradait la production."""
    status, corps, setup = await _post({})

    assert status == 400, f"corps vide accepté ({status}) : {corps!r}"
    setup.assert_not_awaited()


async def test_lab_mode_absent_refuse():
    status, _c, setup = await _post({"allowed_domains": "mcp.cloud-temple.app"})
    assert status == 400
    setup.assert_not_awaited()


async def test_domaines_absents_refuses():
    status, _c, setup = await _post({"lab_mode": False})
    assert status == 400
    setup.assert_not_awaited()


@pytest.mark.parametrize("domaines", ["", "   ", ",", " , , ", [], ["  "], None, 42])
async def test_domaines_vides_ou_mal_types_refuses(domaines):
    status, _c, setup = await _post({"lab_mode": False, "allowed_domains": domaines})
    assert status == 400, f"{domaines!r} accepté"
    setup.assert_not_awaited()


@pytest.mark.parametrize("valeur", ["false", "true", 0, 1, None, "prod", []])
async def test_lab_mode_non_booleen_refuse(valeur):
    """
    ⚠️ `"false"` est une CHAÎNE non vide, donc VRAIE en Python : sous l'ancien
    code, un appelant qui croyait demander la production obtenait l'enrôlement
    libre. Seul un booléen réel est accepté.
    """
    status, _c, setup = await _post({"lab_mode": valeur,
                                     "allowed_domains": "mcp.cloud-temple.app"})
    assert status == 400, f"lab_mode={valeur!r} accepté"
    setup.assert_not_awaited()


async def test_corps_json_illisible_refuse_ET_NOMME_SA_CAUSE():
    """
    ⚠️ Test renforcé après un banc de mutations : la version faible de ce test
    (400 + aucun appel) laissait passer la mutation « corps illisible retombe sur
    `{}` ». Elle est indétectable de l'extérieur, car la garde sur `lab_mode`
    renvoie alors 400 aussi : la propriété de SÉCURITÉ tient dans les deux cas.

    Ce qui change, c'est la CAUSE annoncée — et un corps illisible n'est pas un
    champ manquant. Annoncer l'un pour l'autre envoie l'opérateur corriger la
    mauvaise chose ; c'est la discipline de #154 et #86 appliquée ici.
    """
    status, corps, setup = await _post(b"{ceci n'est pas du json")

    assert status == 400
    setup.assert_not_awaited()

    msg = corps.get("message", "").lower()
    assert "json" in msg or "illisible" in msg, (
        f"la cause réelle (corps illisible) n'est pas nommée : {corps!r}"
    )
    assert "lab_mode` est requis" not in corps.get("message", ""), (
        "un corps illisible est annoncé comme un champ manquant — l'opérateur "
        "corrigerait la mauvaise chose"
    )


async def test_champ_manquant_nomme_LE_CHAMP_et_pas_le_json():
    """Symétrique : un JSON valide mais incomplet doit nommer le CHAMP."""
    status, corps, setup = await _post({"allowed_domains": "mcp.cloud-temple.app"})

    assert status == 400
    setup.assert_not_awaited()
    assert "lab_mode" in corps.get("message", ""), (
        f"le champ manquant n'est pas nommé : {corps!r}"
    )


async def test_sans_permission_admin_aucune_ecriture():
    """La rétrogradation ne doit pas être atteignable sans droit administrateur."""
    status, _c, setup = await _post(
        {"lab_mode": True, "allowed_domains": "*.lesur.lan"}, token_info=_LECTEUR)
    assert status == 403
    setup.assert_not_awaited()


# ───────────────────────────────────────────── transmission fidèle

async def test_corps_complet_transmet_les_valeurs_demandees():
    status, _c, setup = await _post({
        "lab_mode": False,
        "allowed_domains": "internal.agentic.cloud-temple.app, *.internal.agentic.cloud-temple.app",
        "leaf_ttl": "768h",
    })

    assert status == 200
    setup.assert_awaited_once()
    lab, domaines, ttl = setup.await_args.args
    assert lab is False, (
        "lab_mode=False est la SEULE chose qui produit eab_policy="
        "new-account-required, donc l'enrôlement sur invitation"
    )
    assert domaines == ["internal.agentic.cloud-temple.app",
                        "*.internal.agentic.cloud-temple.app"]
    assert ttl == "768h"


async def test_liste_json_acceptee_comme_une_chaine_virgulee():
    status, _c, setup = await _post({"lab_mode": True,
                                     "allowed_domains": ["a.lan", " b.lan "]})
    assert status == 200
    assert setup.await_args.args[1] == ["a.lan", "b.lan"]


# ───────────────────────────────── garde-fou inversé : rien n'est complété

@pytest.mark.parametrize("payload", [
    {},
    {"lab_mode": True},
    {"lab_mode": False},
    {"allowed_domains": "mcp.cloud-temple.app"},
    {"lab_mode": "false", "allowed_domains": "mcp.cloud-temple.app"},
    {"lab_mode": True, "allowed_domains": ""},
])
async def test_aucun_domaine_de_laboratoire_n_atteint_l_autorite_sans_etre_demande(payload):
    """
    Vérifier « un 400 se produit » resterait vert si un défaut permissif revenait
    sous un autre nom. On vérifie la propriété RÉELLE : sur toute requête qui ne
    nomme pas `lesur.lan`, aucun appel ne doit le porter.
    """
    _s, _c, setup = await _post(payload)
    for appel in setup.await_args_list:
        domaines = appel.args[1] or []
        assert not any("lesur" in str(d) for d in domaines), (
            f"{payload!r} a fait partir un domaine de laboratoire non demandé : {domaines!r}"
        )
