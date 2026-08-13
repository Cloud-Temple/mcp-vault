# -*- coding: utf-8 -*-
"""
Issue #78, findings 2 et 3 — la consommation d'un wrap ne peut plus mentir.

## Le défaut, et pourquoi les deux findings sont indissociables

`consume_wrap_secret` passe l'entrée de `active` à `consuming` (CAS), puis
appelle `sys.unwrap()`. Sur **toute** exception, l'ancien code appelait
`rollback_consuming()` → retour à `active`, puis classait l'erreur par recherche
de sous-chaîne dans `str(e)` :

- `403`/`forbidden`/`bad token` → `invalid_wrap_token`
- `404`/`not found`            → `wrap_expired`
- sinon                        → `backend_error`, « réessayer »

Deux défauts, dont l'effet combiné est le vrai problème :

**F2** — le retour à `active` est indémontrable. Une fois l'appel parti, OpenBao
a pu consommer le jeton avant que la réponse ne se perde. Le registre annonçait
alors « disponible » une provision peut-être définitivement brûlée.

**F3** — OpenBao répond **400** (« wrapping token is not valid or does not
exist ») pour un jeton invalide, expiré ou déjà consommé. Le mapping ne testait
que 403/404 : le cas réel tombait donc en `backend_error`.

**Combinés** : un jeton mort produisait « réessayer » ET un registre qui le
déclarait actif. Soit une boucle de retry sur un jeton qui ne pourra jamais
aboutir, cautionnée par le registre.

## Le contrat désormais

Après le CAS, **aucun retour à `active`**. Deux états terminaux :

- `unusable` — OpenBao affirme le jeton mort → `wrap_unusable`, non-réessayable ;
- `consume_outcome_unknown` — issue indéterminée → même nom, non-réessayable.

Et `empty_secret` n'est plus un rollback : si OpenBao a répondu, le jeton a été
présenté et traité → `consumed`.

Tests mockés (pas de conteneur). Stub hvac : `tests/conftest.py`.
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import patch

import pytest

OP = "op-78"
MISSION = "mission-78"
MSG_MORT = "wrapping token is not valid or does not exist"


def run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _registre(echec_a_partir_de: int = 0):
    """Registre en mémoire portant une entrée `active` prête à consommer.

    `echec_a_partir_de` = numéro de sauvegarde (1-indexé, montage compris) à
    partir duquel `_save()` échoue ; 0 = jamais.

    Le montage consomme DEUX sauvegardes (`register_pending`, `mark_active`), le
    CAS la troisième, la transition terminale la quatrième. Faire échouer
    aveuglément toutes les sauvegardes ferait échouer le CAS lui-même — le test
    mesurerait alors le refus d'entrer en consommation, pas la persistance de
    l'état terminal.
    """
    from mcp_vault.vault.wrapping import WrapRegistry

    class EnMemoire(WrapRegistry):
        def __init__(self):
            self._wraps = []
            self._cache_time = float("inf")
            self._last_load_ok = True
            self.sauvegardes = 0

        def load(self):
            pass

        def _maybe_refresh(self):
            pass

        def _save(self) -> bool:
            self.sauvegardes += 1
            if echec_a_partir_de and self.sauvegardes >= echec_a_partir_de:
                return False
            return True

    r = EnMemoire()
    r.register_pending(OP, MISSION, "vault-a", "chemin/cle", 300)
    r.mark_active(OP, "accessor-xyz")
    return r


class ClientFactice:
    """Remplace `hvac.Client` DANS wrapping : le vrai chemin est exercé."""

    def __init__(self, reponse=None, exception=None):
        self.reponse = reponse
        self.exception = exception
        self.appels = 0

    def __call__(self, url=None, token=None, **_kw):
        return SimpleNamespace(sys=SimpleNamespace(unwrap=self._unwrap))

    def _unwrap(self):
        self.appels += 1
        if self.exception:
            raise self.exception
        return self.reponse


def _consommer(registre, client):
    """Exécute `consume_wrap_secret` avec le registre et le client fournis."""
    from mcp_vault.vault import wrapping

    import hvac

    # `wrapping` fait `import hvac as _hvac` DANS la fonction : on remplace donc
    # l'attribut sur le module lui-même, pas sur `wrapping`.
    settings = SimpleNamespace(openbao_addr="http://127.0.0.1:8200")
    with patch.object(wrapping, "get_wrap_registry", return_value=registre), \
         patch.object(wrapping, "_get_config", return_value=settings), \
         patch.object(wrapping, "_get_client", return_value=object()), \
         patch.object(hvac, "Client", client):
        return run(wrapping.consume_wrap_secret(
            wrap_token="wt-xxx", operation_id=OP, mission_id=MISSION))


def _statut(registre):
    return next(e["status"] for e in registre._wraps if e["operation_id"] == OP)


# =============================================================================
# 1) Le jeton mort — F3 : le cas RÉEL d'OpenBao est un 400
# =============================================================================

class TestJetonMort:

    def test_400_openbao_est_classe_mort_et_non_reessayable(self):
        """
        CŒUR DE F3. RED avant le correctif : ce cas tombait en `backend_error`
        « réessayer », et le registre repassait à `active`.
        """
        import hvac

        registre = _registre()
        exc = hvac.exceptions.InvalidRequest(errors=[MSG_MORT])
        r = _consommer(registre, ClientFactice(exception=exc))

        assert r["error_type"] == "wrap_unusable", r
        assert "réessayer" not in r["message"].lower() or "ne pas réessayer" in r["message"].lower()
        assert _statut(registre) == "unusable"

    def test_403_et_404_ne_sont_PAS_des_certitudes(self):
        """
        Retiré en revue de diff : 403/404 ne prouvent que le code HTTP, pas le
        sort du jeton. Un proxy, un routage ou un namespace erroné, ou un refus
        d'infrastructure lèvent les mêmes classes AVEC un wrap encore vivant.

        Les classer « mort » ferait jeter une provision valide. Le faux
        « indéterminé » coûte un reprovisionnement ; le faux « mort » coûte
        l'abandon de ce qui marchait.
        """
        import hvac

        for cls in (hvac.exceptions.Forbidden, hvac.exceptions.InvalidPath):
            registre = _registre()
            r = _consommer(registre, ClientFactice(exception=cls("refus")))
            assert r["error_type"] == "consume_outcome_unknown", (cls, r)
            assert _statut(registre) == "consume_outcome_unknown"

    def test_la_classification_ne_depend_pas_du_texte_de_l_exception(self):
        """
        Non-complaisance : une exception QUELCONQUE dont le texte contient
        « 403 » ne doit PAS être classée morte. L'ancien mapping le faisait.
        """
        registre = _registre()
        r = _consommer(registre, ClientFactice(
            exception=RuntimeError("connexion perdue (code 403 dans le texte)")))

        assert r["error_type"] == "consume_outcome_unknown", r
        assert _statut(registre) == "consume_outcome_unknown"

    def test_un_400_inattendu_reste_indetermine(self):
        """Un 400 seul ne prouve rien sur le sort du jeton."""
        import hvac

        registre = _registre()
        exc = hvac.exceptions.InvalidRequest(errors=["paramètre invalide"])
        r = _consommer(registre, ClientFactice(exception=exc))

        assert r["error_type"] == "consume_outcome_unknown", r
        assert _statut(registre) == "consume_outcome_unknown"


# =============================================================================
# 2) L'issue indéterminée — F2 : plus jamais de retour à `active`
# =============================================================================

class TestIssueIndeterminee:

    @pytest.mark.parametrize("exc", [
        TimeoutError("délai dépassé"),
        ConnectionError("réseau coupé"),
        OSError("socket fermée"),
        RuntimeError("500 Internal Server Error"),
    ])
    def test_aucun_echec_ambigu_ne_ramene_a_active(self, exc):
        """
        CŒUR DE F2. RED avant le correctif : chacun de ces cas remettait
        l'entrée à `active`.
        """
        registre = _registre()
        r = _consommer(registre, ClientFactice(exception=exc))

        assert _statut(registre) != "active", (
            f"{type(exc).__name__} a réinscrit le wrap comme disponible")
        assert _statut(registre) == "consume_outcome_unknown"
        assert r["error_type"] == "consume_outcome_unknown"

    def test_le_message_n_invite_pas_a_reessayer(self):
        """L'ancien message disait « réessayer » sur un jeton peut-être brûlé."""
        registre = _registre()
        r = _consommer(registre, ClientFactice(exception=TimeoutError("t")))

        msg = r["message"].lower()
        assert "ne pas réessayer" in msg
        assert "provisionner un nouveau wrap" in msg


# =============================================================================
# 3) `empty_secret` — même famille de défaut
# =============================================================================

class TestSecretVide:

    def test_une_reponse_vide_marque_consomme_pas_actif(self):
        """
        OpenBao a RÉPONDU : le jeton a été présenté et traité, il est brûlé.
        L'ancien code faisait un rollback vers `active` — doublement faux.
        """
        registre = _registre()
        r = _consommer(registre, ClientFactice(reponse={"data": {}}))

        assert r["error_type"] == "empty_secret", r
        assert _statut(registre) == "consumed"
        assert _statut(registre) != "active"


# =============================================================================
# 4) Le rejeu — un état terminal ne doit pas relancer un unwrap
# =============================================================================

class TestRejeu:

    @pytest.mark.parametrize("terminal,attendu", [
        ("unusable", "wrap_unusable"),
        ("consume_outcome_unknown", "consume_outcome_unknown"),
    ])
    def test_un_retry_sur_etat_terminal_ne_rappelle_pas_openbao(self, terminal, attendu):
        registre = _registre()
        for e in registre._wraps:
            e["status"] = terminal

        client = ClientFactice(reponse={"data": {"k": "v"}})
        r = _consommer(registre, client)

        assert r["error_type"] == attendu, r
        assert client.appels == 0, "un second unwrap a été tenté sur un état terminal"

    def test_un_etat_terminal_n_est_pas_annonce_already_consumed(self):
        """`already_consumed` affirmerait une consommation ABOUTIE."""
        registre = _registre()
        for e in registre._wraps:
            e["status"] = "consume_outcome_unknown"

        r = _consommer(registre, ClientFactice(reponse={"data": {"k": "v"}}))
        assert r["error_type"] != "already_consumed", r


# =============================================================================
# 5) Échec de persistance — fail-close, jamais une invitation à réessayer
# =============================================================================

class TestPersistanceEnEchec:

    def test_s3_en_echec_apres_le_cas_ne_ramene_pas_a_active(self):
        """
        La transition terminale ne peut pas être persistée (4e sauvegarde) :
        l'état mémoire ne doit PAS repasser à `active`, et le client ne doit pas
        être invité à réessayer.
        """
        registre = _registre(echec_a_partir_de=4)
        r = _consommer(registre, ClientFactice(exception=TimeoutError("t")))

        assert _statut(registre) == "consume_outcome_unknown"
        assert _statut(registre) != "active"
        assert r["error_type"] == "consume_outcome_unknown"

    def test_le_rollback_AVANT_le_cas_reste_legitime(self):
        """
        Nuance essentielle, découverte en écrivant le test précédent : si la
        sauvegarde du CAS échoue, RIEN n'a été envoyé à OpenBao. Le retour à
        `active` est alors la seule réponse correcte — le wrap est réellement
        toujours disponible.

        #78 supprime le rollback APRÈS l'appel, jamais celui d'avant.
        """
        registre = _registre(echec_a_partir_de=3)   # le CAS échoue
        client = ClientFactice(reponse={"data": {"data": {"k": "v"}}})
        r = _consommer(registre, client)

        assert client.appels == 0, "OpenBao a été appelé malgré un CAS non persisté"
        assert _statut(registre) == "active"
        assert r["error_type"] == "already_consuming"


# =============================================================================
# 6) Le chemin nominal reste intact
# =============================================================================

class TestCheminNominal:

    def test_un_unwrap_reussi_donne_toujours_le_secret(self):
        """Non-complaisance : le durcissement ne doit pas casser le cas qui marche."""
        registre = _registre()
        r = _consommer(registre, ClientFactice(
            reponse={"data": {"data": {"cle": "valeur"}, "metadata": {}}}))

        assert r["status"] == "ok", r
        assert r["data"]["data"]["cle"] == "valeur"
        assert _statut(registre) == "consumed"


# =============================================================================
# 7) La révocation ne doit pas confondre « terminal » et « révoqué »
# =============================================================================

class TestRevocationSurEtatTerminal:
    """
    Ajouté après un test de mutation : la garde existait mais AUCUN test ne la
    couvrait. Un « 0 échec » sous mutation signale une protection non couverte,
    pas une protection inutile.
    """

    def _revoquer(self, registre):
        from mcp_vault.vault import wrapping

        with patch.object(wrapping, "get_wrap_registry", return_value=registre), \
             patch.object(wrapping, "_caller_is_admin", return_value=True):
            return run(wrapping.lookup_and_revoke_by_operation_id(OP))

    @pytest.mark.parametrize("terminal", ["unusable", "consume_outcome_unknown"])
    def test_un_etat_terminal_n_est_pas_annonce_already_revoked(self, terminal):
        """
        `already_revoked` affirmerait une révocation ATTESTÉE. Or `unusable`
        constate un jeton mort côté OpenBao, et `consume_outcome_unknown` ne
        constate rien du tout — dans les deux cas, personne n'a révoqué.
        """
        registre = _registre()
        for e in registre._wraps:
            e["status"] = terminal

        r = self._revoquer(registre)

        # `status: error` DÉLIBÉRÉ : un appelant qui assimile tout `status: ok`
        # à « compensation achevée » conclurait à tort que la ressource est
        # neutralisée. Relevé en revue de diff.
        assert r["status"] == "error", r
        assert r["error_type"] == "consume_terminal", r
        assert r.get("state") != "already_revoked", r
        assert r["count_revoked"] == 0
        assert r["count_consume_terminal"] == 1, r


    def test_cas_mixte_terminal_plus_revoque_ne_dit_pas_tout_revoque(self):
        """
        Relevé en revue : avec UNE entrée terminale et UNE réellement révoquée,
        l'ancien code répondait `already_revoked` — affirmant que TOUT l'avait
        été. Une seule entrée non attestée suffit à interdire cette conclusion.
        """
        registre = _registre()
        base = dict(registre._wraps[0])
        base["status"] = "revoked"
        registre._wraps.append(base)
        registre._wraps[0]["status"] = "unusable"

        r = self._revoquer(registre)

        assert r["status"] == "error", r
        assert r["error_type"] == "consume_terminal", r
        assert r["count_already_revoked"] == 1, r
        assert r["count_consume_terminal"] == 1, r
        assert "aucune révocation" not in r["message"].lower(), (
            "le message nie une révocation qui a pourtant eu lieu")

    def test_une_entree_reellement_revoquee_reste_already_revoked(self):
        """Non-complaisance : la garde ne doit pas avaler le cas légitime."""
        registre = _registre()
        for e in registre._wraps:
            e["status"] = "revoked"

        r = self._revoquer(registre)
        assert r["state"] == "already_revoked", r


# =============================================================================
# 8) La consultation d'état doit reconnaître les deux nouveaux états
# =============================================================================

class TestConsultationEtat:
    """
    Ajouté après une seconde mutation non détectée : retirer les nouveaux états
    de l'énumération reconnue les faisait passer pour un registre corrompu
    (`registry_inconsistent`) — sans qu'aucun test ne s'en aperçoive.
    """

    def _consulter(self, registre):
        from mcp_vault.vault import wrapping

        with patch.object(wrapping, "get_wrap_registry", return_value=registre), \
             patch.object(wrapping, "_caller_is_admin", return_value=True):
            return run(wrapping.status_by_operation_id(OP))

    @pytest.mark.parametrize("terminal", ["unusable", "consume_outcome_unknown"])
    def test_l_etat_terminal_est_restitue_tel_quel(self, terminal):
        registre = _registre()
        for e in registre._wraps:
            e["status"] = terminal

        r = self._consulter(registre)

        assert r["state"] == terminal, r
        assert r["state"] != "registry_inconsistent", (
            "l'état terminal n'est pas dans l'énumération reconnue")

    @pytest.mark.parametrize("terminal", ["unusable", "consume_outcome_unknown"])
    def test_aucun_expires_at_sur_un_etat_terminal(self, terminal):
        """`expires_at` n'est indicatif que pour les états VIVANTS."""
        registre = _registre()
        for e in registre._wraps:
            e["status"] = terminal

        r = self._consulter(registre)
        assert "expires_at" not in r, r


# =============================================================================
# 9) Durabilité de l'état terminal — un `consuming` qui traîne n'est pas anodin
# =============================================================================

class TestConsumingResiduel:
    """
    Relevé en revue de diff : si la transition terminale ne peut pas être
    PERSISTÉE, S3 conserve `consuming`. Après rechargement, l'ancien code
    répondait `already_consuming` indéfiniment — ce qui laisse croire à une
    concurrence passagère, alors que l'issue est en réalité inconnue.
    """

    def test_un_consuming_residuel_donne_issue_indeterminee(self):
        registre = _registre()
        for e in registre._wraps:
            e["status"] = "consuming"       # état retrouvé après reload

        client = ClientFactice(reponse={"data": {"data": {"k": "v"}}})
        r = _consommer(registre, client)

        assert r["error_type"] == "consume_outcome_unknown", r
        assert client.appels == 0, "un unwrap a été tenté sur un consuming résiduel"

    def test_le_cas_non_persiste_reste_reessayable(self):
        """
        Non-complaisance : ne pas transformer TOUT échec de CAS en issue
        indéterminée. Quand la persistance du CAS échoue, l'entrée revient à
        `active` — rien n'est parti, un nouvel essai est légitime.
        """
        registre = _registre(echec_a_partir_de=3)
        client = ClientFactice(reponse={"data": {"data": {"k": "v"}}})
        r = _consommer(registre, client)

        assert r["error_type"] == "already_consuming", r
        assert _statut(registre) == "active"
        assert client.appels == 0




class TestRevocationMixteTerminalEtActif:
    """
    Relevé au 3e tour de revue : la garde ne s'exécutait QUE si aucune entrée
    active n'existait. Avec une entrée terminale ET une active, le code révoquait
    l'active et rendait un succès — un consommateur non adapté y aurait lu une
    compensation achevée, alors qu'une entrée restait non attestée.
    """

    def _revoquer_reel(self, registre, echec=False):
        """
        Exerce le VRAI `_revoke_accessor_selected` avec un client OpenBao
        factice — le faux de la première version ne reproduisait pas la
        mutation réelle (relevé en revue : avec un accessor partagé,
        l'implémentation marque TOUTE la sélection visible).
        """
        from types import SimpleNamespace

        from mcp_vault.vault import wrapping

        def _revoke(accessor=None):
            if echec:
                raise RuntimeError("OpenBao indisponible")

        client = SimpleNamespace(auth=SimpleNamespace(
            token=SimpleNamespace(revoke_accessor=_revoke)))

        with patch.object(wrapping, "get_wrap_registry", return_value=registre), \
             patch.object(wrapping, "_caller_is_admin", return_value=True), \
             patch.object(wrapping, "_get_client", return_value=client):
            return run(wrapping.lookup_and_revoke_by_operation_id(OP))

    def _monter_terminal_plus_actif(self):
        registre = _registre()
        actif = dict(registre._wraps[0])
        actif["mission_id"] = "autre-mission"
        actif["status"] = "active"
        registre._wraps.append(actif)
        registre._wraps[0]["status"] = "unusable"
        return registre

    def test_terminal_plus_actif_ne_sort_pas_en_succes(self):
        registre = self._monter_terminal_plus_actif()
        r = self._revoquer_reel(registre)

        assert r["status"] == "error", r
        assert r["error_type"] == "consume_terminal", r
        assert r["count_consume_terminal"] == 1, r
        assert r["count_revoked"] >= 1, "la révocation légitime doit rester comptée"

    def test_l_entree_terminale_n_est_pas_mutee_en_revoked(self):
        """
        L'accessor est PARTAGÉ entre les deux entrées : la révocation réelle
        marque toute la sélection visible. L'entrée terminale ne doit pas
        pour autant devenir `revoked` — ce serait affirmer une révocation.
        """
        registre = self._monter_terminal_plus_actif()
        self._revoquer_reel(registre)

        statuts = sorted(e["status"] for e in registre._wraps)
        assert "unusable" in statuts, statuts
        assert statuts.count("revoked") == 1, statuts

    def test_echec_de_revocation_signale_aussi_le_terminal(self):
        """
        Relevé en revue : `partial_revocation` renvoyait sans compteurs. Un
        appelant lisait « réessayer » sans savoir qu'une entrée est figée sur
        un état terminal, qu'aucun retry ne résoudra.
        """
        registre = self._monter_terminal_plus_actif()
        r = self._revoquer_reel(registre, echec=True)

        assert r["error_type"] == "partial_revocation", r
        assert r["count_consume_terminal"] == 1, r
        assert "count_already_revoked" in r, r
        assert "terminal" in r["message"].lower(), r
