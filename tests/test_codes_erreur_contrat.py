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
# 2 bis) LE DÉFAUT DE REJEU — FERMÉ en v0.13.0
# =============================================================================

class TestReponseIncompleteApresAppel:
    """Une réponse OpenBao sans `wrap_info` exploitable rend `backend_error` et
    marque l'intention `failed`. Jusqu'en v0.12.1 la clé REDEVENAIT REJOUABLE
    alors qu'un wrap avait pu être créé sans que nous en ayons l'accessor : un
    rejeu créait une SECONDE enveloppe pendant que la première pouvait vivre.

    ⚠️ v0.13.0 bloque la clé sur `failed` comme sur `pending`, avec un code
    DISTINCT (`operation_failed`) — les deux états portent des informations
    différentes et les fondre reproduirait le défaut #78.

    L'arbitrage qui nous retenait est tombé le 15/08/2026 : `mcp-mission` a prouvé
    par lecture de code qu'aucun chemin métier ne rejoue une clé, puis a rendu ce
    cas TERMINAL dans son propre contrat. Bloquer ne leur coûte donc rien, là où
    le rejeu leur violait leur invariant « au plus une enveloppe active ».

    Le blocage est DÉFINITIF (rien ne libère une clé) : c'est l'échange assumé.
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
        assert registre._wraps[0]["status"] == "failed", (
            f"{cas} : état {registre._wraps[0]['status']!r} — l'intention doit "
            f"rester `failed`, c'est elle qui bloque désormais la clé")

    def test_le_rejeu_de_la_cle_est_REFUSE_apres_failed(self):
        """La fermeture n'est pas déduite d'un état de registre : elle est EXERCÉE.

        Épingler `status == "failed"` prouve l'état, pas la conséquence. Ici un
        second `wrap_secret` sur la MÊME clé doit être refusé **et n'appeler
        OpenBao qu'une seule fois** — c'est l'absence du second wrap qui est la
        propriété de sécurité, pas le code rendu.
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
            client.read.return_value = {                        # 2e essai : OpenBao répondrait
                "wrap_info": {"token": "s.SECOND", "accessor": "ACC-2"}}
            r2 = run(w.wrap_secret("mcp-mission", "missions/db", MISSION, OP, 300))

        assert r1["error_type"] == "backend_error", r1
        assert r2["error_type"] == "operation_failed", (
            f"le rejeu a été accepté : le second wrap est créé alors que le "
            f"premier peut vivre sans accessor — {r2!r}")
        assert "wrap_token" not in r2, f"jeton remis sur un rejeu refusé : {r2!r}"
        assert client.read.call_count == 1, (
            f"OpenBao a été appelé {client.read.call_count} fois : le refus doit "
            f"précéder tout appel, sinon un second wrap existe malgré l'erreur")
        assert len(registre._wraps) == 1, (
            f"une seconde intention a été écrite : {registre._wraps!r}")

    @staticmethod
    def _wrap_sur_etat(status, accessor=None):
        """Tente un `wrap_secret` sur une clé portant DÉJÀ une entrée `status`."""
        from mcp_vault.vault import wrapping as w
        registre = _registre([{
            "operation_id": OP, "mission_id": MISSION, "accessor": accessor,
            "vault_id": "mcp-mission", "secret_path": "missions/db",
            "created_at": "", "expires_at": "2099-01-01T00:00:00+00:00",
            "status": status,
        }])
        client = MagicMock()
        client.read.return_value = {"wrap_info": {"token": "s.NEW", "accessor": "ACC-NEW"}}
        cfg = SimpleNamespace(openbao_addr="http://127.0.0.1:8200")
        with patch.object(w, "get_wrap_registry", return_value=registre), \
             patch.object(w, "_get_client", return_value=client), \
             patch.object(w, "_get_config", return_value=cfg):
            r = run(w.wrap_secret("mcp-mission", "missions/db", MISSION, OP, 300))
        return r, client, registre

    @pytest.mark.parametrize("status, code, accessor", [
        ("pending",                 "operation_pending",   None),
        ("failed",                  "operation_failed",    None),
        ("active",                  "operation_revocable", "ACC-1"),
        ("consuming",               "operation_revocable", "ACC-1"),
        ("consume_outcome_unknown", "operation_revocable", "ACC-1"),
        ("revoked",                 "operation_terminated", "ACC-1"),
        ("consumed",                "operation_terminated", "ACC-1"),
        ("unusable",                "operation_terminated", "ACC-1"),
    ])
    def test_tout_etat_NON_TENU_POUR_MORT_bloque_la_cle_avant_tout_appel(
            self, status, code, accessor):
        """⚠️ `active` est le pire cas à laisser passer : la provision est VIVANTE
        et NOMMABLE, donc un rejeu produit deux enveloppes sous une même clé —
        l'invariant que l'appelant s'interdit.

        ⚠️ `consume_outcome_unknown` doit bloquer AUSSI, bien qu'il soit rangé
        parmi les états terminaux de consommation : OpenBao a pu consommer le
        jeton avant que la réponse ne se perde, donc le jeton PEUT ENCORE VIVRE.
        Une première version de ce lot le laissait passer.

        Les codes distinguent trois informations (#78 : ne jamais fondre un fait
        et une ignorance) : `pending` on ignore si OpenBao a été appelé ;
        `failed` l'appel a eu lieu, ressource possible mais SANS accessor ;
        `operation_revocable` une ressource peut vivre ET porte un accessor. Ce
        dernier est nommé d'après ce que l'appelant PEUT FAIRE, pas d'après un
        état de registre — sinon il mentirait sur `consume_outcome_unknown`.
        """
        r, client, registre = self._wrap_sur_etat(status, accessor)

        assert r["error_type"] == code, f"état {status!r} : {r!r}"
        assert not client.read.called, (
            f"OpenBao appelé malgré une entrée {status!r} : un second wrap existe")
        assert "wrap_token" not in r, f"jeton remis sur un refus : {r!r}"
        assert len(registre._wraps) == 1, (
            f"une seconde intention a été écrite pour {status!r} : {registre._wraps!r}")

    @pytest.mark.parametrize("status", ["revoked", "consumed", "unusable"])
    def test_v0_14_0_ces_trois_etats_NE_LIBERENT_PLUS_la_cle(self, status):
        """⚠️ RENVERSEMENT ASSUMÉ — en v0.13.0 ces trois états libéraient la clé.

        Ils la bloquent depuis v0.14.0. La libération n'existait que pour la
        reprise « révoquer puis recréer » de `mcp-mission`, qu'ils ont retirée de
        leur conception le 15/08/2026 ; la plateforme a ensuite établi par
        lecture du registre de production qu'aucun autre composant ne portait de
        jeton `wrap`.

        ⚠️ C'était aussi le dernier chemin d'exploitation de #140 : un jeton
        ÉTRANGER présenté à `secret_consume` marque l'entrée `unusable` — donc
        libérait une clé dont le wrap réel était vivant. Si ce test tombe, ce
        chemin est rouvert.
        """
        r, client, _ = self._wrap_sur_etat(status, accessor="ACC-1")

        assert r["error_type"] == "operation_terminated", (
            f"l'état {status!r} a LIBÉRÉ la clé : chemin #140 rouvert — {r!r}")
        assert not client.read.called, "OpenBao appelé sur une clé déjà servie"

    def test_la_garde_ne_porte_QUE_sur_la_creation(self):
        """La condition posée par `mcp-mission`, et sans laquelle ils seraient
        enfermés : révocation, statut et compensation doivent rester ouverts sur
        une clé engagée. Vérifié par le seul moyen qui ne ment pas — le nombre
        d'appelants de la garde dans le code de production.
        """
        import inspect
        from mcp_vault.vault import wrapping as w

        src = inspect.getsource(w)
        appels = src.count("blocking_intent_status(")
        assert appels == 2, (
            f"{appels} occurrences de `blocking_intent_status(` (1 définition + "
            f"1 appel attendus). Un appel supplémentaire fermerait un verbe que "
            f"`mcp-mission` doit garder ouvert sur une clé engagée.")
        assert "registry.blocking_intent_status(" in src.split("async def wrap_secret")[1], (
            "l'unique appel n'est plus dans `wrap_secret` : la garde a changé de "
            "périmètre")

    def test_une_entree_CORROMPUE_bloque_au_lieu_de_liberer(self):
        """Une entrée illisible est une raison de REFUSER, jamais d'autoriser.

        La garde de v0.13.0 écartait les entrées malformées via
        `_entry_well_formed` : une entrée abîmée rouvrait donc la clé, ce qui
        reconstruisait exactement le trou que v0.14.0 ferme.
        """
        from mcp_vault.vault import wrapping as w
        registre = _registre([{
            "operation_id": OP, "mission_id": MISSION, "accessor": "ACC-1",
            "vault_id": "mcp-mission", "secret_path": "missions/db",
            "created_at": "", "expires_at": "2099-01-01T00:00:00+00:00",
            "status": {"corrompu": True},          # statut non-str
        }])
        client = MagicMock()
        cfg = SimpleNamespace(openbao_addr="http://127.0.0.1:8200")
        with patch.object(w, "get_wrap_registry", return_value=registre), \
             patch.object(w, "_get_client", return_value=client), \
             patch.object(w, "_get_config", return_value=cfg):
            r = run(w.wrap_secret("mcp-mission", "missions/db", MISSION, OP, 300))

        assert r["error_type"] == "registry_inconsistent", (
            f"une entrée corrompue a LIBÉRÉ la clé : {r!r}")
        assert not client.read.called, "OpenBao appelé malgré une entrée illisible"

    def test_un_etat_INCONNU_bloque_lui_aussi(self):
        """Plus aucune liste libératoire : un état ajouté demain bloque, point.

        En v0.13.0 il fallait un raisonnement — « bloquer sauf si présent dans la
        liste libératoire ». En v0.14.0 la propriété est directe : toute entrée
        bloque. Ce test la vérifie sur un état absent de la taxonomie, pour
        qu'un ajout futur ne puisse pas creuser un trou en silence.
        """
        r, client, _ = self._wrap_sur_etat("etat_futur_inconnu", accessor="ACC-1")

        assert r["status"] == "error", (
            f"un état inconnu a LIBÉRÉ la clé au lieu de la bloquer : {r!r}")
        assert not client.read.called, "OpenBao appelé sur un état inconnu"

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
