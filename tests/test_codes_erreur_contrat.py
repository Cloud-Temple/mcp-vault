# -*- coding: utf-8 -*-
"""
Codes d'erreur du contrat de wrapping — ce que l'appelant peut en DÉDUIRE.

Deux défauts de contrat relevés en produisant la matrice demandée par
`mcp-mission` et `mcp-agent`.

**1. `registry_unavailable` mentait sur un chemin.** Il annonce « rien n'a été
créé », et c'est vrai de deux de ses trois origines. La troisième — échec de
`mark_active` — survient APRÈS qu'OpenBao a créé le wrap. L'appelant y lisait
« provisionnement propre, rien à compenser » alors qu'une ressource pouvait
rester active jusqu'à son TTL, sans qu'il en ait l'accessor.

Deux codes distincts le remplacent, et la frontière est l'issue de la révocation
d'urgence — **la seule chose qui décide s'il reste quelque chose à compenser** :

- `wrap_created_revoked`  — révocation CONFIRMÉE, rien ne survit ;
- `wrap_created_orphaned` — révocation NON confirmée, la ressource peut vivre
  jusqu'au TTL et n'est pas compensable.

Cette information n'était disponible que dans un log serveur : l'appelant devait
traiter les deux cas comme une fuite de provision possible.

**2. Des refus rendaient une enveloppe SANS `error_type`.** `ttl_seconds` hors
plage, et tous les refus d'autorisation. Un appelant qui clé sur `error_type` y
lisait `None`.

Tests mockés (pas de conteneur). Stub hvac : `tests/conftest.py`.
"""
import asyncio
import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp.shared.memory import create_connected_server_and_client_session

OP = "op-codes"
MISSION = "mission-codes"
ACC = "ACC-CREE"


def run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _registre(entrees=(), *, echec_a_partir_de=0):
    """Registre en mémoire qui COMPTE ses sauvegardes.

    `echec_a_partir_de` = numéro de sauvegarde (1-indexé) à partir duquel
    `_save()` échoue. Faire échouer TOUTES les sauvegardes ferait échouer
    `register_pending` : on mesurerait alors le refus d'enregistrer, jamais
    l'échec de `mark_active` — qui est le seul chemin où le wrap EXISTE déjà.
    """
    from mcp_vault.vault.wrapping import WrapRegistry

    class EnMemoire(WrapRegistry):
        def __init__(self):
            self._wraps = [dict(e) for e in entrees]
            self._cache_time = float("inf")
            self._last_load_ok = True
            self.sauvegardes = 0

        def load(self):
            pass

        def _maybe_refresh(self):
            pass

        def _save(self) -> bool:
            self.sauvegardes += 1
            return not (echec_a_partir_de and self.sauvegardes >= echec_a_partir_de)

    return EnMemoire()


def _wrap(registre, *, revocation_leve=False, ttl=300):
    """`wrap_secret` avec un OpenBao qui CRÉE le wrap.

    `revocation_leve` fait échouer la révocation d'urgence — c'est l'unique
    variable qui doit séparer les deux nouveaux codes.
    """
    from mcp_vault.vault import wrapping as w
    client = MagicMock()
    client.read.return_value = {"wrap_info": {"token": "s.WRAPTOKEN", "accessor": ACC}}
    if revocation_leve:
        client.auth.token.revoke_accessor.side_effect = RuntimeError("OpenBao injoignable")
    cfg = SimpleNamespace(openbao_addr="http://127.0.0.1:8200")
    with patch.object(w, "get_wrap_registry", return_value=registre), \
         patch.object(w, "_get_client", return_value=client), \
         patch.object(w, "_get_config", return_value=cfg):
        return run(w.wrap_secret("mcp-mission", "missions/db", MISSION, OP, ttl)), client


@pytest.fixture(autouse=True)
def _identite_admin():
    from tests.conftest import admin_auth_context
    with admin_auth_context():
        yield


# =============================================================================
# 1) LE CHEMIN QUI MENTAIT — wrap créé, persistance impossible
# =============================================================================

class TestWrapCreeMaisNonPersiste:

    def test_revocation_confirmee_annonce_qu_il_n_y_a_RIEN_a_compenser(self):
        # 1re sauvegarde (register_pending) OK, 2e (mark_active) échoue : le wrap
        # existe déjà côté OpenBao quand la persistance lâche.
        registre = _registre(echec_a_partir_de=2)
        r, client = _wrap(registre)

        assert r["status"] == "error", r
        assert r["error_type"] == "wrap_created_revoked", r
        assert registre.sauvegardes == 2, (
            f"{registre.sauvegardes} sauvegarde(s) : un chemin allant droit à "
            f"l'erreur sans tenter `mark_active` resterait vert")
        client.auth.token.revoke_accessor.assert_called_once_with(accessor=ACC)

    def test_revocation_NON_confirmee_annonce_une_ressource_possiblement_active(self):
        registre = _registre(echec_a_partir_de=2)
        r, client = _wrap(registre, revocation_leve=True, ttl=900)

        assert r["error_type"] == "wrap_created_orphaned", r
        client.auth.token.revoke_accessor.assert_called_once_with(accessor=ACC)
        assert "900" in r["message"], (
            f"le TTL borne la ressource orpheline : c'est la seule chose que "
            f"l'appelant peut opposer au temps — message={r['message']!r}")

    @pytest.mark.parametrize("revocation_leve", [False, True])
    def test_ni_jeton_ni_accessor_ne_sortent_sur_ce_chemin(self, revocation_leve):
        """Le jeton n'est pas remis (provision non corrélée), et l'accessor non
        plus : l'exposer laisserait croire à une compensation possible alors que
        l'entrée de registre n'existe pas."""
        r, _ = _wrap(_registre(echec_a_partir_de=2), revocation_leve=revocation_leve)

        assert "wrap_token" not in r, "un jeton non compensable a été remis"
        assert "accessor" not in r, r
        assert "s.WRAPTOKEN" not in repr(r), f"jeton présent dans la réponse : {r!r}"


# =============================================================================
# 2) ANTI-COMPLAISANCE — les origines HONNÊTES gardent leur code
# =============================================================================

class TestLesOriginesHonnetesGardentRegistryUnavailable:
    """Renommer les trois origines aurait « corrigé » le défaut en détruisant
    l'information vraie : dans deux cas sur trois, rien n'a été créé."""

    def test_registre_non_configure_reste_registry_unavailable_sans_appel(self):
        from mcp_vault.vault import wrapping as w
        client = MagicMock()
        cfg = SimpleNamespace(openbao_addr="http://127.0.0.1:8200")
        with patch.object(w, "get_wrap_registry", return_value=None), \
             patch.object(w, "_get_client", return_value=client), \
             patch.object(w, "_get_config", return_value=cfg):
            r = run(w.wrap_secret("mcp-mission", "missions/db", MISSION, OP, 300))

        assert r["error_type"] == "registry_unavailable", r
        client.read.assert_not_called()

    def test_intention_non_enregistrable_reste_registry_unavailable_sans_appel(self):
        # La 1re sauvegarde échoue : `register_pending` refuse, donc rien ne part.
        registre = _registre(echec_a_partir_de=1)
        r, client = _wrap(registre)

        assert r["error_type"] == "registry_unavailable", r
        assert not client.read.called, (
            "OpenBao a été appelé alors que l'intention n'est pas persistée : "
            "le write-ahead ne protège plus rien")


# =============================================================================
# 2 bis) LE DÉFAUT QUI RESTE OUVERT — épinglé, pas corrigé
# =============================================================================

class TestReponseIncompleteApresAppel:
    """Une réponse OpenBao sans `wrap_info` exploitable rend `backend_error`, et
    l'intention passe `failed` — donc la clé REDEVIENT REJOUABLE alors qu'un wrap
    a pu être créé sans que nous en ayons l'accessor.

    ⚠️ Ce test ÉPINGLE le comportement actuel, il ne l'approuve pas. Le défaut est
    signalé aux deux équipes clientes avec la seule protection disponible : ne pas
    rejouer la même clé. Le fermer exige une transition persistée — sans elle, une
    clé bloquée l'est DÉFINITIVEMENT (rien ne libère une clé), ce qui échangerait
    un incident rare contre un incident fréquent. Lot distinct, arbitrage
    propriétaire.

    Sans cet épinglage, une « correction » silencieuse de ce chemin passerait
    inaperçue alors qu'elle changerait le contrat annoncé.
    """

    def _wrap_reponse(self, reponse):
        from mcp_vault.vault import wrapping as w
        registre = _registre()
        client = MagicMock()
        client.read.return_value = reponse
        cfg = SimpleNamespace(openbao_addr="http://127.0.0.1:8200")
        with patch.object(w, "get_wrap_registry", return_value=registre), \
             patch.object(w, "_get_client", return_value=client), \
             patch.object(w, "_get_config", return_value=cfg):
            return run(w.wrap_secret("mcp-mission", "missions/db", MISSION, OP, 300)), registre

    @pytest.mark.parametrize("reponse, cas", [
        ({}, "aucun wrap_info"),
        ({"wrap_info": {"token": "s.WT", "accessor": ""}}, "accessor vide"),
        ({"wrap_info": {"token": "", "accessor": "ACC"}}, "jeton vide"),
    ])
    def test_reponse_incomplete_rend_backend_error_et_libere_la_cle(self, reponse, cas):
        r, registre = self._wrap_reponse(reponse)

        assert r["error_type"] == "backend_error", (f"{cas} : {r!r}")
        assert "wrap_token" not in r, f"{cas} : jeton remis sur un chemin d'erreur"
        # L'intention est `failed`, donc `has_pending` ne bloque plus : c'est
        # PRÉCISÉMENT le défaut documenté. Si cette assertion tombe, le contrat
        # annoncé aux clients a changé — il faut les prévenir, pas ajuster le test.
        assert registre._wraps[0]["status"] == "failed", (
            f"{cas} : état {registre._wraps[0]['status']!r} — le défaut de rejeu "
            f"documenté aux équipes clientes a changé de forme")

    def test_le_rejeu_de_la_cle_est_EFFECTIVEMENT_possible_apres_failed(self):
        """Le défaut n'est pas déduit d'un état de registre : il est EXERCÉ.

        Épingler `status == "failed"` prouve l'état, pas la conséquence. Ici un
        second `wrap_secret` sur la MÊME clé aboutit et appelle OpenBao une
        seconde fois — c'est la création du second wrap, le premier restant
        orphelin.
        """
        from mcp_vault.vault import wrapping as w
        registre = _registre()
        client = MagicMock()
        cfg = SimpleNamespace(openbao_addr="http://127.0.0.1:8200")
        with patch.object(w, "get_wrap_registry", return_value=registre), \
             patch.object(w, "_get_client", return_value=client), \
             patch.object(w, "_get_config", return_value=cfg):
            client.read.return_value = {}                      # réponse incomplète
            r1 = run(w.wrap_secret("mcp-mission", "missions/db", MISSION, OP, 300))
            client.read.return_value = {                        # 2e essai : OpenBao répond
                "wrap_info": {"token": "s.SECOND", "accessor": "ACC-2"}}
            r2 = run(w.wrap_secret("mcp-mission", "missions/db", MISSION, OP, 300))

        assert r1["error_type"] == "backend_error", r1
        assert r2["status"] == "ok", (
            f"le rejeu est refusé : le défaut documenté aux équipes clientes "
            f"n'existe plus sous cette forme — {r2!r}")
        assert client.read.call_count == 2, (
            "un second wrap n'a pas été créé : l'assertion ci-dessus passerait "
            "sur un chemin qui n'appelle pas OpenBao")

    def test_apres_failed_la_compensation_n_affirme_PAS_une_revocation(self):
        """Le piège opérationnel : c'est `secret_wrap_lookup` que l'appelant
        utilise pour compenser. Il rendait `already_revoked` sur une entrée
        `failed` — il AFFIRMAIT une révocation qui n'a jamais eu lieu, alors
        qu'un wrap peut être vivant et inconnu. Même famille de mensonge que
        celle fermée par #78 pour les états terminaux.
        """
        from mcp_vault.vault import wrapping as w
        registre = _registre([{
            "operation_id": OP, "mission_id": MISSION, "accessor": None,
            "vault_id": "mcp-mission", "secret_path": "missions/db",
            "created_at": "", "expires_at": "2099-01-01T00:00:00+00:00",
            "status": "failed",
        }])
        client = MagicMock()
        with patch.object(w, "get_wrap_registry", return_value=registre), \
             patch.object(w, "_get_client", return_value=client):
            r = run(w.lookup_and_revoke_by_operation_id(OP, MISSION))

        assert r["state"] != "already_revoked", (
            "la compensation affirme une révocation inexistante sur une "
            "intention dont le wrap peut être vivant")
        assert r["state"] == "found_unattached", r
        assert r["count_revoked"] == 0, r
        client.auth.token.revoke_accessor.assert_not_called()


# =============================================================================
# 3) LES ENVELOPPES QUI N'AVAIENT PAS DE CODE
# =============================================================================

class TestEnveloppesSansErrorType:

    def _appel_mcp(self, ttl):
        """Appelle l'OUTIL (pas la primitive) avec un espion sur le cœur.

        L'espion est posé sur `wrapping.wrap_secret` et non sur un attribut de
        `server` : l'outil importe le cœur DANS son corps, donc au moment de
        l'appel. Patcher `server` échouerait — l'attribut n'y existe pas.
        """
        from mcp_vault import server
        coeur = AsyncMock(return_value={"status": "ok", "wrap_token": "s.X"})
        with patch("mcp_vault.vault.wrapping.wrap_secret", new=coeur):
            r = run(server.secret_wrap(
                vault_id="mcp-mission", secret_path="missions/db",
                mission_id=MISSION, operation_id=OP, ttl_seconds=ttl))
        return r, coeur

    @pytest.mark.parametrize("ttl", [59, 3601, 0, -1])
    def test_ttl_hors_plage_porte_desormais_un_code(self, ttl):
        r, coeur = self._appel_mcp(ttl)

        assert r["status"] == "error", r
        assert r.get("error_type") == "invalid_input", (
            f"ttl={ttl} : enveloppe d'erreur sans code exploitable — "
            f"un appelant qui clé sur `error_type` y lit {r.get('error_type')!r}")
        assert not coeur.called, (
            "le refus doit précéder le cœur : sinon l'effet externe annoncé "
            "« absent » dans la matrice est faux")

    def test_aucune_garde_partagee_de_context_py_ne_refuse_sans_code(self):
        """Test STRUCTUREL, et c'est volontaire : il vaut pour les refus FUTURS.

        Les gardes de `context.py` sont partagées par les 37 outils ; les énumérer
        une par une laisserait passer la prochaine, qui repartirait sans code.

        ⚠️ PORTÉE, à ne pas surestimer — le nom de ce test dit `context.py`, pas
        « tous les refus du serveur ». Des refus de VALIDATION propres à des
        outils hors périmètre wrapping en sortent encore sans code
        (`secret_list`, surfaces `/admin/api`). La matrice publiée borne la
        promesse aux gardes d'autorisation ; l'élargir est un lot distinct.

        Il ne détecte pas non plus un refus construit hors littéral (helper,
        variable, guillemets simples) : c'est un filet de régression, pas une
        preuve d'exhaustivité.
        """
        source = Path("src/mcp_vault/auth/context.py").read_text(encoding="utf-8")
        sans_code = []
        for m in re.finditer(r'return \{[^}]*"status": "error"[^}]*\}', source, re.S):
            if '"error_type"' not in m.group(0):
                sans_code.append(source[:m.start()].count("\n") + 1)

        assert not sans_code, (
            f"refus sans `error_type` aux lignes {sans_code} de context.py — "
            f"l'appelant ne peut pas les classer")

    def test_les_refus_d_autorisation_rendent_un_code_de_la_taxonomie_fermee(self):
        """Un code par refus ne suffit pas : une valeur inventée à chaque site
        rendrait le contrat aussi indevinable qu'une absence de code."""
        source = Path("src/mcp_vault/auth/context.py").read_text(encoding="utf-8")
        attendus = {"unauthenticated", "permission_denied", "access_denied",
                    "invalid_input", "invalid_token", "policy_store_unavailable"}
        vus = set(re.findall(r'"error_type": "(\w+)"', source))

        assert vus <= attendus, (
            f"codes hors taxonomie publiée : {sorted(vus - attendus)}")


# =============================================================================
# 4) LA FORME DE TRANSPORT — sur NOTRE outil, par le vrai chemin protocolaire
# =============================================================================

class TestFormeDeTransport:
    """Nous avons écrit aux deux équipes : « tous nos codes métier arrivent en
    ENVELOPPE, `isError = false` ». Le vérifier sur un outil FABRIQUÉ pour le test
    ne prouverait que le comportement de FastMCP — il resterait vert si
    `secret_wrap` perdait ses codes. Le banc traverse donc le VRAI outil, avec un
    OpenBao et un registre simulés positionnés sur le chemin corrigé.
    """

    async def _appel_protocolaire(self, *, revocation_leve):
        from mcp_vault import server
        from mcp_vault.vault import wrapping as w
        from tests.conftest import admin_auth_context

        registre = _registre(echec_a_partir_de=2)
        client = MagicMock()
        client.read.return_value = {
            "wrap_info": {"token": "s.WRAPTOKEN", "accessor": ACC}}
        if revocation_leve:
            client.auth.token.revoke_accessor.side_effect = RuntimeError("injoignable")
        cfg = SimpleNamespace(openbao_addr="http://127.0.0.1:8200")

        with admin_auth_context(), \
             patch.object(w, "get_wrap_registry", return_value=registre), \
             patch.object(w, "_get_client", return_value=client), \
             patch.object(w, "_get_config", return_value=cfg), \
             patch("mcp_vault.auth.context.check_path_policy", return_value=None):
            async with create_connected_server_and_client_session(server.mcp) as session:
                return await session.call_tool("secret_wrap", {
                    "vault_id": "mcp-mission", "secret_path": "missions/db",
                    "mission_id": MISSION, "operation_id": OP, "ttl_seconds": 300})

    @pytest.mark.parametrize("revocation_leve, code", [
        (False, "wrap_created_revoked"),
        (True, "wrap_created_orphaned"),
    ])
    async def test_le_code_arrive_en_enveloppe_pas_en_erreur_de_protocole(
            self, revocation_leve, code):
        res = await self._appel_protocolaire(revocation_leve=revocation_leve)

        assert res.isError is False, (
            f"{code} remonte en erreur de protocole : un appelant qui lit "
            f"`isError` ne verra jamais la charge, contrairement à ce que nous "
            f"avons publié")
        charge = res.content[0].text
        assert code in charge, f"code absent de la charge utile : {charge!r}"
        assert "s.WRAPTOKEN" not in charge, (
            f"le jeton traverse le protocole sur un chemin d'erreur : {charge!r}")
