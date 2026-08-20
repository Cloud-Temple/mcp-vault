#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Un motif d'outil qui ne désigne rien est refusé À L'ÉCRITURE (issue #128).

## Le défaut

`allowed_tools` / `denied_tools` nomment des outils par motif `fnmatch`. La
validation vérifiait seulement qu'il s'agissait de **chaînes**. Une faute de
frappe — `ssx_*` au lieu de `ssh_*` — était donc acceptée, enregistrée, et ne
protégeait **rien**. Sans message.

⚠️ **Cas réel en production**, trouvé le 19/08/2026 : la policy
`judilibre-prod-api-key-readonly` porte un motif *denied* `token_create`, absent
du catalogue — l'outil qui existe, `token_update`, n'était donc pas couvert.
Aucun dommage : `token_update` exige la permission `admin`, contrôlée
indépendamment de toute policy. **De la chance, pas de la conception.**

⚠️ Une validation **lexicale** ne ferme pas le trou : `ssx_*` est irréprochable
(alphanumérique, joker bien placé) et totalement inopérant. Seule la
correspondance au **catalogue réel** l'attrape.

## L'asymétrie, qui est le cœur de ce lot

| Moment | Comportement | Pourquoi |
| --- | --- | --- |
| `create()` — écriture | **refus** | un humain est devant son clavier et peut corriger |
| `load()` — chargement | **avertissement seul** | refuser ici ferait d'un renommage d'outil une indisponibilité du Policy Store AU DÉMARRAGE — la faute `extra="forbid"` corrigée dans #86 |

Un test qui ne vérifierait que le refus laisserait passer un durcissement du
chargement, c'est-à-dire une panne au boot pour un défaut qui n'expose rien de
plus qu'avant. **Les deux moitiés sont testées, et la seconde compte autant.**

## La dérive du catalogue

`MCP_TOOL_NAMES` est une liste explicite (impossible de lire `server.py` depuis
`auth/policies.py` : cycle d'import). Une liste tenue à la main dérive — c'est le
risque réel de ce lot, et `test_le_catalogue_ne_derive_pas_de_server` le ferme en
comparant à l'ensemble des `@mcp.tool()`. Sans ce test, le module serait un piège
de plus.
"""

import json
import logging
import os
import re
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp_vault.auth.policies import PolicyStore
from mcp_vault.tool_catalog import (
    MCP_TOOL_NAMES,
    inoperative_patterns,
    pattern_designates_a_tool,
)

_RACINE = os.path.join(os.path.dirname(__file__), "..")


def _store():
    """Store avec S3 neutralisé — `_save` détecte toute écriture réelle."""
    settings = SimpleNamespace(s3_endpoint_url="http://localhost:0",
                               s3_bucket_name="test-bucket")
    s = PolicyStore(settings)
    s._save = MagicMock(return_value=True)
    s._maybe_refresh = MagicMock()
    s._available = True
    return s


class _Body:
    def __init__(self, data): self._data = data
    def read(self): return self._data


def _s3(payload: bytes):
    client = MagicMock()
    client.get_object.return_value = {"Body": _Body(payload)}
    return client


# ─────────────────────────────────────────── la dérive du catalogue

async def test_le_catalogue_ne_derive_pas_de_server():
    """
    ⚠️ LE test qui rend ce module utilisable. Sans lui, `MCP_TOOL_NAMES` serait
    une liste à jour aujourd'hui et fausse dans trois mois — et un catalogue
    faux refuserait des motifs légitimes ou laisserait passer des motifs morts.

    ⚠️ On interroge le REGISTRE RÉEL de FastMCP, pas le texte source. Le premier
    jet lisait `server.py` avec une regex `@mcp.tool()\n async def` ; la revue
    adversariale a montré qu'elle ne voit pas `@mcp.tool(name=...)`, un outil
    synchrone, un décorateur empilé, ni un `add_tool()` programmatique — le test
    restait vert alors qu'un motif légitime serait refusé. Le registre, lui, est
    ce que le serveur expose vraiment : toute forme de déclaration y figure.
    """
    from mcp_vault.server import mcp

    reels = {o.name for o in await mcp.list_tools()}

    assert reels, "registre FastMCP vide — l'API d'introspection a changé"
    manquants = reels - MCP_TOOL_NAMES
    fantomes = MCP_TOOL_NAMES - reels
    assert not manquants, (
        f"outils exposés absents du catalogue : {sorted(manquants)} — leurs "
        "motifs légitimes seraient REFUSÉS à l'écriture")
    assert not fantomes, (
        f"catalogue citant des outils inexistants : {sorted(fantomes)} — des "
        "motifs morts seraient ACCEPTÉS")


# ─────────────────────────────────────────── le prédicat

@pytest.mark.parametrize("motif,attendu", [
    ("ssh_*", True),            # famille réelle
    ("ssx_*", False),           # ⚠️ la faute de frappe : lexicalement parfaite
    ("token_create", False),    # ⚠️ le cas RÉEL de production
    ("token_update", True),     # l'outil qui existe vraiment
    ("vault_delete", True),
    ("*", True),
    ("secret_*", True),
    ("vault_?ist", True),        # joker '?' — fnmatch complet, pas juste un préfixe
    ("vault_[lp]ist", True),     # classe '[seq]'
    ("vault_?iste", False),      # même forme, aucun outil : la garde tient
    ("secret_[xyz]*", False),
    ("", False),
    ("   ", False),
    ("SSH_*", False),           # fnmatch est sensible à la casse ici
    (None, False),
    (42, False),
])
def test_le_predicat_distingue_un_motif_operant(motif, attendu):
    assert pattern_designates_a_tool(motif) is attendu


def test_entree_non_iterable_ne_leve_pas():
    """La validation de TYPE reste le travail du validateur de policy."""
    assert inoperative_patterns(None) == []
    assert inoperative_patterns("ssh_*") == []


# ─────────────────────────────────── ÉCRITURE : refus, et rien n'est persisté

def test_le_cas_reel_de_production_est_refuse():
    """`denied_tools=["token_create"]` — la policy vue en production."""
    s = _store()
    r = s.create(policy_id="judilibre-readonly", denied_tools=["token_create"])

    assert r["status"] == "error", r
    assert "token_create" in r["message"], (
        f"le motif fautif n'est pas nommé : {r!r} — l'opérateur ne saurait pas "
        "lequel corriger")
    s._save.assert_not_called()
    assert "judilibre-readonly" not in s._policies


def test_faute_de_frappe_lexicalement_valide_refusee():
    s = _store()
    r = s.create(policy_id="p", allowed_tools=["ssx_*"])
    assert r["status"] == "error"
    assert "ssx_*" in r["message"]
    s._save.assert_not_called()


def test_les_deux_listes_sont_verifiees():
    for champ in ("allowed_tools", "denied_tools"):
        s = _store()
        r = s.create(policy_id="p", **{champ: ["nexiste_pas"]})
        assert r["status"] == "error", f"{champ} non vérifié"
        s._save.assert_not_called()


def test_motifs_valides_acceptes():
    s = _store()
    r = s.create(policy_id="p", allowed_tools=["ssh_*", "vault_list"],
                 denied_tools=["vault_delete"])
    assert r["status"] == "created", r
    s._save.assert_called_once()


def test_listes_vides_toujours_acceptees():
    """
    Garde-fou inversé : « allow-list vide = tout autorisé » est un choix
    DOCUMENTÉ, pas le défaut corrigé ici. Le refuser casserait toutes les
    policies existantes sans traiter la cause.
    """
    s = _store()
    assert s.create(policy_id="p").get("status") == "created"
    s._save.assert_called_once()   # l'écriture a réellement eu lieu
    assert "p" in s._policies


# ────────────────────── CHARGEMENT : avertir, JAMAIS refuser (l'asymétrie)

def test_une_policy_deja_persistee_a_motif_mort_se_CHARGE_QUAND_MEME(caplog):
    """
    ⚠️ La moitié qui compte autant que le refus. Refuser ici rendrait le Policy
    Store indisponible AU DÉMARRAGE dès qu'un outil est renommé — pour un défaut
    qui n'expose rien de plus qu'avant (leçon `extra="forbid"` de #86).
    """
    s = _store()
    s._maybe_refresh = MagicMock()
    charge = json.dumps({"policies": [{
        "policy_id": "heritee",
        "description": "policy d'hier, motif devenu mort",
        "allowed_tools": [], "denied_tools": ["token_create"], "path_rules": [],
    }]}).encode()
    s._get_s3_data = MagicMock(return_value=_s3(charge))

    with caplog.at_level(logging.WARNING, logger="mcp-vault.policy-store"):
        s.load()

    assert "heritee" in s._policies, (
        "la policy a été REFUSÉE au chargement — un renommage d'outil "
        "deviendrait une panne au démarrage")
    assert s._available is True, "le Policy Store est devenu indisponible"
    assert s._policies["heritee"]["denied_tools"] == ["token_create"], (
        "le motif a été silencieusement réécrit : la donnée persistée doit être "
        "chargée telle quelle, seul l'avertissement change")

    messages = " ".join(r.getMessage() for r in caplog.records)
    assert "token_create" in messages and "heritee" in messages, (
        f"aucun avertissement nommant la policy et le motif : {messages!r}")


def test_chargement_sans_motif_mort_n_avertit_pas(caplog):
    """
    ⚠️ Un avertissement émis à chaque chargement serait du bruit, et le bruit
    est un défaut : il fait ignorer les vrais. On vérifie donc aussi le SILENCE.
    """
    s = _store()
    s._maybe_refresh = MagicMock()
    charge = json.dumps({"policies": [{
        "policy_id": "saine", "description": "",
        "allowed_tools": ["ssh_*"], "denied_tools": ["vault_delete"],
        "path_rules": [],
    }]}).encode()
    s._get_s3_data = MagicMock(return_value=_s3(charge))

    with caplog.at_level(logging.WARNING, logger="mcp-vault.policy-store"):
        s.load()

    assert "saine" in s._policies
    assert caplog.records == [], (
        "un chargement sain doit être SILENCIEUX. Filtrer sur le libellé "
        f"laisserait passer un avertissement reformulé : {[r.getMessage() for r in caplog.records]!r}")


# ─────────── BOUT EN BOUT : les deux surfaces d'écriture atteignent la garde

async def test_l_outil_MCP_policy_create_refuse_un_motif_mort():
    """
    ⚠️ Ajouté après la revue adversariale. Les tests précédents appellent
    `PolicyStore.create()` en direct : ils prouvent que la GARDE fonctionne, pas
    que les surfaces d'écriture y arrivent. Je le savais en lisant le code — la
    revue a eu raison de me demander de le MESURER, parce que « j'ai lu le code »
    est exactement l'erreur qui m'a fait rater deux surfaces sur le lot #128
    précédent.
    """
    from unittest.mock import patch as _p
    from mcp_vault import server

    s = _store()
    with _p("mcp_vault.auth.context.check_admin_permission", return_value=None), \
         _p("mcp_vault.auth.policies.get_policy_store", return_value=s):
        r = await server.policy_create(policy_id="p", denied_tools=["token_create"])

    assert r.get("status") == "error", f"l'outil MCP a accepté un motif mort : {r!r}"
    assert "token_create" in str(r.get("message", ""))
    s._save.assert_not_called()


async def test_la_route_admin_refuse_un_motif_mort():
    """Même preuve pour `POST /admin/api/policies`, la surface de la console."""
    from unittest.mock import patch as _p
    from mcp_vault.admin.api import _handle_admin_routes

    messages: list = []

    async def send(m):
        messages.append(m)

    payload = json.dumps({"policy_id": "p", "denied_tools": ["token_create"]}).encode()
    livre = False

    async def receive():
        nonlocal livre
        if livre:
            return {"type": "http.request", "body": b"", "more_body": False}
        livre = True
        return {"type": "http.request", "body": payload, "more_body": False}

    s = _store()
    scope = {"path": "/admin/api/policies", "method": "POST", "query_string": b""}
    token_info = {"client_name": "t", "permissions": ["admin"], "allowed_resources": []}
    with _p("mcp_vault.auth.policies.get_policy_store", return_value=s), \
         _p("mcp_vault.auth.context.get_current_client_name", return_value="t"):
        await _handle_admin_routes(scope, receive, send, None, token_info)

    statut = next(m["status"] for m in messages if m["type"] == "http.response.start")
    corps = json.loads(b"".join(m.get("body", b"") for m in messages
                               if m["type"] == "http.response.body"))
    assert statut >= 400, f"la route a accepté un motif mort ({statut}) : {corps!r}"
    assert "token_create" in str(corps.get("message", ""))
    s._save.assert_not_called()
