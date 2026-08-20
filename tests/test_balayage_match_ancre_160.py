#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Balayage des `.match()` sur motif ancré — la CLASSE, pas l'occurrence (issue #160).

## Origine

`mcp-mission` publie #582 : une garde en `.match()` au lieu de `.fullmatch()`
laissait `x` et `x\\n` passer comme deux valeurs distinctes. Leur remède : « une
ligne, **plus balayage des autres `.match()` ancrés** ».

⚠️ **Nous avions rencontré ce défaut un mois plus tôt** (#78/D6, `is_safe_id`),
corrigé l'occurrence… et **jamais balayé**. Le balayage a trouvé **dix sites**
d'appel pour sept motifs, dont quatre sur la **surface ACME non authentifiée**.

## Ce que le balayage a mesuré — et ce n'était PAS une faille

Sur `^…$` avec `.match()`, Python accepte un `\\n` **final** — et rien d'autre :
`x\\r\\n` échoue, `x\\nX` échoue. Aucune charge ne peut donc suivre le saut de
ligne : **pas d'injection d'en-tête, pas de découpe de requête**. Et httpx refuse
de toute façon une URL contenant un caractère non imprimable.

## Le résidu RÉEL, qui est la vraie raison de ce lot

Une requête `GET /acme/directory%0A` (le `path` ASGI est décodé) franchissait la
garde, mourait dans le client HTTP, tombait dans un `except Exception` unique et
recevait **`502 "PKI backend unavailable"`** avec un `ERROR` nommant OpenBao —
**alors qu'OpenBao n'avait jamais été contacté**.

⇒ Un appelant **non authentifié** pouvait, avec une requête forgée, faire émettre
à notre service une fausse panne de tiers. Toute supervision branchée sur ce
statut ou cette ligne devenait un **générateur d'alarme déclenchable de
l'extérieur** — l'inverse exact de ce que v0.17.0 a apporté à `mcp-agent`.
Même faute que #86, #152 et #154 : ne jamais présenter un fait sur l'appelant
comme l'indisponibilité d'un tiers.

## Ce qui est verrouillé ici

- la garde refuse le saut de ligne final sur les **quatre** sites ACME, **sans
  appeler l'amont** ;
- une URL refusée par notre client rend **400**, une panne de connexion rend
  **502** — la distinction est testée dans les deux sens ;
- ⚠️ **garde-fou inversé** : les valeurs légitimes (domaines réels de production,
  TTL, numéros de série) passent **à l'identique**. `fullmatch` ne doit rien
  resserrer d'autre ;
- ⚠️ **garde de CLASSE** : plus aucun `.match()` sur motif ancré dans `src/`, et
  le motif de numéro de série n'existe qu'en **un seul** exemplaire. C'est cette
  garde, pas les correctifs, qui empêche le défaut de revenir.
"""

import os
import re
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
os.environ.setdefault("MCP_SERVER_NAME", "mcp-vault-test")

_SRC = Path(__file__).resolve().parents[1] / "src" / "mcp_vault"


# ───────────────────────────────────────────── GARDES DE CLASSE

def test_plus_aucun_match_sur_motif_ancre_dans_src():
    """
    ⚠️ LA garde de ce lot. Les correctifs ferment dix sites ; ce test empêche le
    onzième. Sans lui, on aurait corrigé l'occurrence — encore une fois.
    """
    coupables = []
    for f in _SRC.rglob("*.py"):
        for n, ligne in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"\.match\(", ligne) and "fullmatch" not in ligne:
                coupables.append(f"{f.relative_to(_SRC)}:{n}: {ligne.strip()}")
    assert not coupables, (
        "`.match()` sur un motif ancré accepte un saut de ligne FINAL (#78/D6, "
        "#160). Utiliser `.fullmatch()` :\n  " + "\n  ".join(coupables))


def test_le_motif_de_numero_de_serie_n_existe_qu_une_fois():
    """
    Deux copies d'un validateur = deux occasions de divergence. C'est la cause
    exacte qui avait rouvert #78 (trois copies d'un motif d'identifiant avaient
    divergé). Le motif vivait en double : `pki_ca.py` et `admin/api.py`.
    """
    litteral = r"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2})+"
    porteurs = [str(f.relative_to(_SRC)) for f in _SRC.rglob("*.py")
                if litteral in f.read_text(encoding="utf-8")]
    assert porteurs == ["vault/pki_ca.py"], (
        f"motif de numéro de série dupliqué : {porteurs}")


# ─────────────────────── SURFACE ACME NON AUTHENTIFIÉE (bout en bout)

def _scope(path, query=b""):
    return {"type": "http", "method": "GET", "path": path,
            "headers": [], "query_string": query}


async def _receive():
    return {"type": "http.request", "body": b"", "more_body": False}


def _send():
    events = []

    async def send(e):
        events.append(e)
    return send, events


def _statut(events):
    return next(e["status"] for e in events if e["type"] == "http.response.start")


def _client_amont(reponse=None, leve=None):
    """Faux httpx.AsyncClient ; `appels` compte les requêtes RÉELLEMENT émises."""
    appels = []

    async def request(*a, **k):
        appels.append((a, k))
        if leve is not None:
            raise leve
        return reponse

    inst = AsyncMock()
    inst.request = request
    cls = MagicMock()
    cls.return_value.__aenter__ = AsyncMock(return_value=inst)
    cls.return_value.__aexit__ = AsyncMock(return_value=None)
    return cls, appels


def _reponse_ok():
    r = MagicMock()
    r.status_code, r.content, r.headers = 200, b"{}", {"content-type": "application/json"}
    return r


@pytest.mark.parametrize("chemin", [
    "/acme/directory\n",                      # URL courte
    "/v1/_sys_pki_int/acme/directory\n",      # URL longue générée par OpenBao
])
async def test_saut_de_ligne_final_refuse_sans_appeler_l_amont(chemin):
    """Ce qu'un `GET /acme/directory%0A` produit : le `path` ASGI est décodé."""
    from mcp_vault.pki_middleware import PkiMiddleware

    interne = []

    async def app(s, r, snd):
        interne.append(True)

    cls, appels = _client_amont(_reponse_ok())
    send, events = _send()
    with patch("mcp_vault.pki_middleware.httpx.AsyncClient", cls):
        await PkiMiddleware(app)(_scope(chemin), _receive, send)

    assert _statut(events) == 400, f"accepté : {events!r}"
    assert appels == [], "OpenBao a été contacté pour une requête invalide"
    assert not interne


async def test_query_string_a_saut_de_ligne_refusee_sans_appeler_l_amont():
    from mcp_vault.pki_middleware import PkiMiddleware

    cls, appels = _client_amont(_reponse_ok())
    send, events = _send()
    with patch("mcp_vault.pki_middleware.httpx.AsyncClient", cls):
        await PkiMiddleware(AsyncMock())(
            _scope("/acme/directory", query=b"a=1\n"), _receive, send)

    assert _statut(events) == 400
    assert appels == []


async def test_une_requete_ACME_legitime_est_toujours_proxifiee():
    """⚠️ Garde-fou inversé : `fullmatch` ne doit rien resserrer d'autre."""
    from mcp_vault.pki_middleware import PkiMiddleware

    cls, appels = _client_amont(_reponse_ok())
    send, events = _send()
    with patch("mcp_vault.pki_middleware.httpx.AsyncClient", cls):
        await PkiMiddleware(AsyncMock())(_scope("/acme/directory"), _receive, send)

    assert _statut(events) == 200, f"requête légitime cassée : {events!r}"
    assert len(appels) == 1


# ────────── 400 CONTRE 502 : notre requête invalide n'est pas leur panne

async def test_url_refusee_par_notre_client_rend_400_et_non_une_panne_de_tiers():
    """
    ⚠️ LE résidu réel de #160. L'ancien `except Exception` unique répondait
    « PKI backend unavailable » pour une requête que NOUS avons refusé d'émettre.
    """
    import httpx
    from mcp_vault.pki_middleware import PkiMiddleware

    cls, appels = _client_amont(leve=httpx.InvalidURL("caractère non imprimable"))
    send, events = _send()
    with patch("mcp_vault.pki_middleware.httpx.AsyncClient", cls):
        await PkiMiddleware(AsyncMock())(_scope("/acme/directory"), _receive, send)

    assert _statut(events) == 400, (
        "une URL refusée par notre propre client est annoncée comme une panne "
        f"d'OpenBao : {events!r}")
    corps = b"".join(e.get("body", b"") for e in events
                     if e["type"] == "http.response.body")
    assert b"backend" not in corps.lower(), (
        f"le message accuse le backend : {corps!r}")


async def test_une_vraie_panne_de_connexion_rend_TOUJOURS_502():
    """
    Symétrique, et il compte autant : distinguer les causes ne doit pas faire
    disparaître le 502 légitime. Sans ce test, tout renvoyer en 400 passerait.
    """
    import httpx
    from mcp_vault.pki_middleware import PkiMiddleware

    cls, _ = _client_amont(leve=httpx.ConnectError("connexion refusée"))
    send, events = _send()
    with patch("mcp_vault.pki_middleware.httpx.AsyncClient", cls):
        await PkiMiddleware(AsyncMock())(_scope("/acme/directory"), _receive, send)

    assert _statut(events) == 502, f"la vraie panne n'est plus signalée : {events!r}"


# ─────────────────── LES MOTIFS : refus du saut de ligne, légitimes préservés

def test_les_motifs_refusent_le_saut_de_ligne_final():
    from mcp_vault.vault.pki_ca import (_DOMAIN_PATTERN, _SERIAL_NUMBER_PATTERN,
                                        _TTL_PATTERN)
    from mcp_vault.auth.token_store import _HASH_RE

    h = "a" * 64
    for motif, valeur in ((_TTL_PATTERN, "720h"), (_DOMAIN_PATTERN, "mcp.cloud-temple.app"),
                          (_SERIAL_NUMBER_PATTERN, "05:bc:04"), (_HASH_RE, h)):
        assert motif.fullmatch(valeur), f"valeur légitime refusée : {valeur!r}"
        assert not motif.fullmatch(valeur + "\n"), (
            f"saut de ligne final accepté sur {valeur!r}")
        assert motif.match(valeur + "\n"), (
            "prémisse du lot invalidée : `.match()` n'accepte plus le \\n final, "
            "ce test ne prouve donc plus rien")


@pytest.mark.parametrize("domaine", [
    "internal.agentic.cloud-temple.app",
    "*.internal.agentic.cloud-temple.app",
    "*.lesur.lan", "lesur.lan", "mcp.cloud-temple.app",
])
def test_les_domaines_REELS_de_production_passent_toujours(domaine):
    """⚠️ Garde-fou inversé : resserrer ces motifs casserait l'installation PKI."""
    from mcp_vault.vault.pki_ca import _DOMAIN_PATTERN
    assert _DOMAIN_PATTERN.fullmatch(domaine), (
        f"domaine de production refusé : {domaine!r}")
