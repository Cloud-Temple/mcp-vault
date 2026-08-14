# -*- coding: utf-8 -*-
"""
Contrat MCP des signatures d'outils — la preuve sur laquelle repose l'ordre de
déploiement de v0.12.0.

## Pourquoi ce banc existe

v0.12.0 rend `mission_id` OBLIGATOIRE sur `secret_wrap_lookup` et
`secret_wrap_status` (cloisonnement inter-missions). La question posée par
`agentic-platform` était : faut-il une fenêtre de maintenance pour basculer Vault
et le broker `mcp-mission` ensemble ?

**Réponse : non, et elle tient à UNE propriété observée et verrouillée de notre
pile MCP/FastMCP** (`mcp==1.26.0`, identique entre v0.11.0 et v0.12.0) — et non à
une garantie normative du protocole MCP : un paramètre
surnuméraire est **ignoré**, un paramètre requis manquant est **refusé**. Une
release Mission qui envoie TOUJOURS `mission_id` fonctionne donc contre l'ancienne
version du coffre (paramètre ignoré) comme contre la nouvelle. D'où l'ordre
retenu : Mission d'abord, Vault ensuite, sans arrêt de service.

⚠️ Cette propriété n'était établie que par une **mesure manuelle**, et la
plateforme l'a relevé : elle a demandé à `mcp-mission` de produire le test durable,
faute de l'avoir chez nous. C'était notre affirmation, sur notre couche — ce banc
la ramène de notre côté.

## Ce que ce banc couvre, et ce qu'il ne couvre PAS

Il exerce le **vrai chemin d'invocation** : une session client MCP en mémoire émet
un `tools/call` réel, et l'on observe le `CallToolResult` rendu. Les schémas sont
lus via l'**API publique** `list_tools()`, donc la surface effectivement annoncée
aux appelants.

Il ne couvre pas les ruptures de transport ou de version de protocole : une montée
de `mcp` qui changerait la négociation, la sérialisation ou le cadrage des erreurs
peut casser la compatibilité **sans** faire échouer ces tests. Ils protègent la
propriété de tolérance aux paramètres, pas la compatibilité protocolaire dans son
ensemble.

Mesuré avec `mcp==1.26.0` (verrou de v0.12.0).
"""

import pytest

from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_connected_server_and_client_session


def _serveur_deux_signatures():
    """Un serveur portant l'ANCIENNE et la NOUVELLE signature, plus un témoin
    d'exécution : il prouve si le corps de l'outil a tourné, et avec quoi.

    Le témoin est le cœur du banc. Sans lui, un refus FABRIQUÉ par le corps de
    l'outil (donc après y être entré) serait indiscernable d'un refus à la
    validation — or c'est cette distinction qui borne les dégâts.
    """
    srv = FastMCP("contrat-signatures")
    vus: list = []

    @srv.tool()
    async def ancienne_signature(operation_id: str) -> dict:
        vus.append(("ancienne", operation_id))
        return {"status": "ok", "operation_id": operation_id}

    @srv.tool()
    async def nouvelle_signature(operation_id: str, mission_id: str) -> dict:
        vus.append(("nouvelle", operation_id, mission_id))
        return {"status": "ok"}

    return srv, vus


# =============================================================================
# 1) LE VRAI CHEMIN PROTOCOLAIRE — tools/call via une session client en mémoire
# =============================================================================

class TestToleranceAuxParametresParLeProtocole:

    async def test_un_parametre_surnumeraire_est_IGNORE(self):
        """
        LA PROPRIÉTÉ CENTRALE — c'est elle qui permet de déployer le broker AVANT
        le coffre : un broker déjà migré envoie `mission_id` à une ancienne
        version, qui l'ignore au lieu de refuser l'appel.

        ⚠️ Si ce test tombe, l'ordre « Mission d'abord » communiqué par écrit à
        `agentic-platform` et à `mcp-mission` devient FAUX : il faut les prévenir,
        pas seulement corriger le test.
        """
        srv, vus = _serveur_deux_signatures()
        async with create_connected_server_and_client_session(srv) as session:
            res = await session.call_tool(
                "ancienne_signature",
                {"operation_id": "op-1", "mission_id": "m-1"})

        assert res.isError is False, (
            f"un paramètre surnuméraire a été REFUSÉ par le protocole : {res!r}")
        assert vus == [("ancienne", "op-1")], (
            f"le corps n'a pas reçu exactement l'argument attendu : {vus!r}")

    async def test_un_parametre_requis_manquant_est_REFUSE_avant_le_corps(self):
        """
        L'AUTRE MOITIÉ DE LA PREUVE : elle borne les dégâts si un ancien broker
        appelle la nouvelle signature. Le refus intervient à la validation des
        arguments — **le corps ne tourne pas**, donc aucune écriture de registre,
        aucun appel au coffre, aucune révocation.

        C'est cette forme d'échec que nous avons annoncée à Mission : une erreur
        d'invocation MCP (`isError`), pas une enveloppe métier `{status: error}`.
        """
        srv, vus = _serveur_deux_signatures()
        async with create_connected_server_and_client_session(srv) as session:
            res = await session.call_tool("nouvelle_signature",
                                          {"operation_id": "op-1"})

        assert res.isError is True, (
            f"un argument requis manquant n'a PAS été refusé : {res!r}")
        assert vus == [], (
            f"le corps de l'outil a été exécuté malgré un argument requis "
            f"manquant : {vus!r}")

    async def test_la_nouvelle_signature_fonctionne_nominalement(self):
        """ANTI-COMPLAISANCE : sans ce test, un serveur qui refuserait TOUT
        passerait les deux précédents."""
        srv, vus = _serveur_deux_signatures()
        async with create_connected_server_and_client_session(srv) as session:
            res = await session.call_tool(
                "nouvelle_signature",
                {"operation_id": "op-1", "mission_id": "m-1"})

        assert res.isError is False, res
        assert vus == [("nouvelle", "op-1", "m-1")]


# =============================================================================
# 2) LE CONTRAT PUBLIÉ DE NOS OUTILS — via l'API publique list_tools()
# =============================================================================

class TestContratPublieDesOutilsWrap:
    """
    Le bloc précédent établit la propriété du PROTOCOLE sur des outils
    synthétiques. Celui-ci porte sur les outils réellement annoncés par notre
    serveur — sinon on prouverait une propriété générique sans prouver que NOTRE
    contrat s'en sert.

    Les listes attendues sont figées **à la main**, jamais dérivées du schéma
    qu'on contrôle : les dériver reviendrait à comparer le code à lui-même.
    """

    # (outil → paramètres requis attendus). Figé à la main, volontairement.
    ATTENDU = {
        "secret_wrap_lookup": ["operation_id", "mission_id"],
        "secret_wrap_status": ["operation_id", "mission_id"],
        "secret_wrap": ["vault_id", "secret_path", "mission_id", "operation_id"],
        "secret_revoke_wrap": ["lease_id"],
        "secret_consume": ["wrap_token", "operation_id", "mission_token"],
    }

    async def _schemas(self):
        """Surface PUBLIÉE : ce que `tools/list` annonce réellement."""
        from mcp_vault.server import mcp
        return {t.name: (t.inputSchema or {}) for t in await mcp.list_tools()}

    @pytest.mark.parametrize("outil", sorted(ATTENDU))
    async def test_les_parametres_requis_sont_exactement_ceux_du_contrat(self, outil):
        schemas = await self._schemas()
        assert outil in schemas, f"outil {outil!r} non annoncé par tools/list"
        requis = schemas[outil].get("required", [])

        assert sorted(requis) == sorted(self.ATTENDU[outil]), (
            f"{outil} : requis={sorted(requis)}, "
            f"contrat={sorted(self.ATTENDU[outil])} — toute évolution de cette "
            f"liste est une RUPTURE pour mcp-mission, à annoncer AVANT livraison")

    async def test_les_deux_outils_cloisonnes_exigent_bien_la_mission(self):
        """
        Redondant avec le test paramétré, et c'est VOULU : c'est l'assertion que
        cite la note de déploiement. Rendre `mission_id` optionnel rouvrirait la
        révocation inter-missions comme comportement PAR DÉFAUT sur un outil
        destructif — le défaut corrigé en v0.12.0.
        """
        schemas = await self._schemas()
        for outil in ("secret_wrap_lookup", "secret_wrap_status"):
            assert "mission_id" in schemas[outil].get("required", []), (
                f"{outil} n'exige plus mission_id — le cloisonnement "
                f"inter-missions est rouvert")

    async def test_secret_consume_n_expose_PAS_mission_id(self):
        """
        POINT DE CONTRAT, et sa justification exacte — corrigée en revue.

        `secret_consume` n'expose pas `mission_id` : la mission est **extraite du
        claim** du jeton de mission, donc PROUVÉE, pas déclarée par l'appelant.

        ⚠️ Formulation à ne pas durcir : ajouter ce paramètre ne créerait pas
        mécaniquement un contournement du binding C18 — le handler continuerait
        d'extraire la mission du claim. Le risque réel est une **double source
        d'identité** dans le contrat : deux valeurs pouvant divergir, dont un
        appelant pourrait croire que la sienne fait foi. C'est cette ambiguïté
        que ce test interdit.
        """
        schemas = await self._schemas()
        requis = schemas["secret_consume"].get("required", [])
        proprietes = schemas["secret_consume"].get("properties", {})

        assert "mission_id" not in requis, (
            "secret_consume exige mission_id : la mission doit rester prouvée "
            "par le jeton")
        assert "mission_id" not in proprietes, (
            "secret_consume accepte mission_id en paramètre — double source "
            "d'identité dans le contrat")
        assert "mission_token" in requis
