# -*- coding: utf-8 -*-
"""
Contrat MCP des signatures d'outils — la preuve dont dépend l'ordre de déploiement
de v0.12.0.

v0.12.0 rend `mission_id` OBLIGATOIRE sur `secret_wrap_lookup` et
`secret_wrap_status`. Faut-il une fenêtre de maintenance pour basculer Vault et le
broker `mcp-mission` ensemble ? Non — et cela tient à une propriété **observée et
verrouillée de notre pile MCP/FastMCP** (`mcp==1.26.0`, identique entre v0.11.0 et
v0.12.0), pas à une garantie normative du protocole : un paramètre surnuméraire est
IGNORÉ, un paramètre requis manquant est REFUSÉ. Une release Mission qui envoie
toujours `mission_id` fonctionne donc contre les deux versions.

Le banc exerce le vrai chemin d'invocation — session client MCP en mémoire,
`tools/call` réel — et lit les schémas par l'API publique `list_tools()`.

Il ne couvre PAS les ruptures de transport ou de version de protocole : une montée
de `mcp` changeant la négociation ou le cadrage des erreurs peut casser la
compatibilité sans faire échouer ces tests.
"""

import pytest

from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_connected_server_and_client_session


def _serveur_deux_signatures():
    """Ancienne et nouvelle signature, plus un témoin d'exécution.

    Sans le témoin, un refus FABRIQUÉ par le corps de l'outil serait
    indiscernable d'un refus à la validation — or c'est cette distinction qui
    borne les dégâts.
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
        """LA PROPRIÉTÉ CENTRALE : elle permet de déployer le broker AVANT le
        coffre.

        ⚠️ Si ce test tombe, l'ordre « Mission d'abord » communiqué par écrit à
        `agentic-platform` et à `mcp-mission` devient FAUX : il faut les
        PRÉVENIR, pas seulement corriger le test.
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
        """Borne les dégâts si un ancien broker appelle la nouvelle signature :
        le corps ne tourne pas, donc aucune écriture, aucun appel au coffre,
        aucune révocation. Forme annoncée à Mission : erreur d'invocation MCP
        (`isError`), pas une enveloppe métier.
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
    """Les outils réellement annoncés par notre serveur, et non des outils
    synthétiques. Listes attendues figées À LA MAIN : les dériver du schéma
    reviendrait à comparer le code à lui-même.
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
        """Rendre `mission_id` optionnel rouvrirait la révocation inter-missions
        comme comportement PAR DÉFAUT sur un outil destructif."""
        schemas = await self._schemas()
        for outil in ("secret_wrap_lookup", "secret_wrap_status"):
            assert "mission_id" in schemas[outil].get("required", []), (
                f"{outil} n'exige plus mission_id — le cloisonnement "
                f"inter-missions est rouvert")

    async def test_secret_consume_n_expose_PAS_mission_id(self):
        """La mission est extraite du claim, donc PROUVÉE et non déclarée.

        ⚠️ Ajouter ce paramètre ne contournerait pas mécaniquement le binding C18
        — le handler lirait toujours le claim. Le risque est une DOUBLE SOURCE
        d'identité dans le contrat, dont un appelant croirait que la sienne fait
        foi. C'est cette ambiguïté que le test interdit.
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
