# -*- coding: utf-8 -*-
"""
Issue #103 — `/health` annonçait `healthy` alors qu'OpenBao était indisponible.

## Le défaut, tel qu'il a été relevé

`HealthCheckMiddleware._health_response` renvoyait un LITTÉRAL :

    {"status": "healthy", "service": ..., "version": ..., "transport": ...}

Il ne consultait rien. Un conteneur démarré en mode dégradé — journal
« ⚠️ Démarrage en mode dégradé (OpenBao indisponible) » — répondait donc
`healthy` au `HEALTHCHECK` Docker, qui le rapportait sain. Le service affirmait
une garantie qu'il ne tenait pas.

La seule fonction de vérification, `openbao.manager.health_check()`, faisait par
ailleurs un appel hvac SYNCHRONE, sans timeout, dans la boucle d'événements : la
brancher naïvement sur un endpoint public aurait recréé le défaut de
disponibilité que #110/#122 corrigent.

## Ce que ces tests prouvent

1. Le corps ne peut plus mentir : `healthy` exige DEUX termes réunis.
2. Le corps public reste sobre — vocabulaire fermé, aucun diagnostic.
3. La sonde ne peut pas geler la boucle ni se multiplier sous rafale.
4. `/healthz` ne sonde JAMAIS — c'est la porte de sortie qui évite qu'un futur
   autoheal redémarre en boucle un coffre scellé.

## Choix de couture (important pour la valeur de ces tests)

On remplace `hvac.Client` **vu par `manager`**, et non la sonde. Le chemin réel
est donc exercé de bout en bout : `_probe_openbao_blocking` → `run_blocking`
(offload) → single-flight → échéance de l'appelant → prédicat
`availability_status` → middleware ASGI. Patcher `availability_status`
directement aurait produit des tests qui passent même si la mécanique est
cassée.
"""

import asyncio
import json
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from mcp_vault import lifecycle
from mcp_vault.openbao import manager

DETAIL_SENSIBLE = "https://openbao.interne.example:8200 — token hvs.SECRET42"


def _run(coro):
    return asyncio.run(coro)


def _settings(timeout=2):
    return SimpleNamespace(
        mcp_server_name="mcp-vault",
        openbao_addr="http://127.0.0.1:8200",
        openbao_health_timeout=timeout,
        s3_endpoint_url="",
    )


class SondeFactice:
    """
    Remplace `hvac.Client` DANS `manager`.

    `read_health_status` est volontairement BLOQUANTE (`time.sleep`) : c'est ce
    qui permet de prouver l'offload — si l'appel restait dans la boucle, un
    témoin asyncio concurrent ne progresserait pas.
    """

    def __init__(self, reponse=None, exception=None, delai=0.0):
        self.reponse = reponse
        self.exception = exception
        self.delai = delai
        self.constructions = 0      # une construction = une sonde réelle
        self.timeouts_recus = []

    def __call__(self, url=None, timeout=None, **_kw):
        self.constructions += 1
        self.timeouts_recus.append(timeout)
        return SimpleNamespace(
            sys=SimpleNamespace(read_health_status=self._lire)
        )

    def _lire(self, method=None):
        if self.delai:
            time.sleep(self.delai)
        if self.exception:
            raise self.exception
        return self.reponse


SAIN = {"sealed": False, "initialized": True}
SCELLE = {"sealed": True, "initialized": True}
NON_INITIALISE = {"sealed": False, "initialized": False}


class Harnais:
    """Monte `HealthCheckMiddleware` sur un aval qui COMPTE son passage."""

    def __init__(self, sonde, timeout=2):
        from mcp_vault.auth.middleware import HealthCheckMiddleware

        self.aval_atteint = 0
        self.sonde = sonde
        self.settings = _settings(timeout)

        async def aval(scope, receive, send):
            self.aval_atteint += 1
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"{}"})

        self.mw = HealthCheckMiddleware(aval)

    async def appel_async(self, path):
        events = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(ev):
            events.append(ev)

        await self.mw({"type": "http", "path": path, "headers": []}, receive, send)
        return events

    def appel(self, path):
        return _run(self._sous_patch(self.appel_async(path)))

    async def _sous_patch(self, coro):
        with patch.object(manager.hvac, "Client", self.sonde), \
             patch("mcp_vault.openbao.manager.get_settings", return_value=self.settings), \
             patch("mcp_vault.auth.middleware.get_settings", return_value=self.settings):
            return await coro

    def lance(self, coro_factory):
        """Exécute une coroutine arbitraire sous les mêmes patchs."""
        return _run(self._sous_patch(coro_factory()))

    @staticmethod
    def statut(events):
        for ev in events:
            if ev["type"] == "http.response.start":
                return ev["status"]
        return None

    @staticmethod
    def corps(events):
        for ev in events:
            if ev["type"] == "http.response.body":
                return json.loads(ev["body"]) if ev["body"] else {}
        return None


@pytest.fixture(autouse=True)
def _etat_demarrage_propre():
    """
    `_startup_ready` est un état de MODULE. Sans réarmement, un test qui le pose
    contaminerait les suivants — et un test de latch passerait pour de mauvaises
    raisons.
    """
    lifecycle.mark_startup_starting()
    yield
    lifecycle.mark_startup_starting()


# =============================================================================
# 1) Le mensonge lui-même — le cœur de l'issue
# =============================================================================

class TestLeCorpsNePeutPlusMentir:

    def test_openbao_injoignable_jamais_healthy(self):
        """RED sans le correctif : le littéral renvoyait `healthy` quoi qu'il arrive."""
        lifecycle.mark_startup_ready()
        h = Harnais(SondeFactice(exception=ConnectionRefusedError("refus")))
        events = h.appel("/health")

        assert h.corps(events)["status"] != "healthy"
        assert h.corps(events)["status"] == lifecycle.HEALTH_UNAVAILABLE
        assert h.statut(events) == 503

    def test_openbao_scelle_est_un_etat_distinct_et_nomme(self):
        """Le besoin d'exploitation : savoir de l'extérieur qu'il faut desceller."""
        lifecycle.mark_startup_ready()
        h = Harnais(SondeFactice(reponse=SCELLE))
        events = h.appel("/health")

        assert h.corps(events)["status"] == lifecycle.HEALTH_SEALED
        assert h.statut(events) == 503

    def test_openbao_sain_et_demarrage_abouti_donne_healthy_200(self):
        lifecycle.mark_startup_ready()
        sonde = SondeFactice(reponse=SAIN)
        h = Harnais(sonde)
        events = h.appel("/health")

        assert h.corps(events)["status"] == lifecycle.HEALTH_HEALTHY
        assert h.statut(events) == 200
        # Le corps seul ne prouve rien : sans cette assertion, un littéral
        # `healthy` réintroduit passerait le test.
        assert sonde.constructions == 1, "la sonde réelle n'a pas été appelée"

    def test_openbao_non_initialise_est_indisponible(self):
        lifecycle.mark_startup_ready()
        h = Harnais(SondeFactice(reponse=NON_INITIALISE))
        events = h.appel("/health")

        assert h.corps(events)["status"] == lifecycle.HEALTH_UNAVAILABLE
        assert h.statut(events) == 503

    def test_ready_porte_le_meme_contrat_que_health(self):
        lifecycle.mark_startup_ready()
        h = Harnais(SondeFactice(exception=OSError("panne")))
        events = h.appel("/ready")

        assert h.statut(events) == 503
        assert h.corps(events)["status"] == lifecycle.HEALTH_UNAVAILABLE


# =============================================================================
# 2) Le second terme du prédicat — une sonde verte ne suffit pas
# =============================================================================

class TestPredicatADeuxTermes:

    def test_sonde_verte_sans_demarrage_abouti_reste_indisponible(self):
        """
        OpenBao répond parfaitement, mais `vault_startup()` n'a pas abouti
        (restauration S3 ambiguë, magasins non chargés). Le service ne peut pas
        garantir qu'il sert un état correct.
        """
        # `mark_startup_ready()` volontairement NON appelé.
        h = Harnais(SondeFactice(reponse=SAIN))
        events = h.appel("/health")

        assert h.corps(events)["status"] == lifecycle.HEALTH_UNAVAILABLE
        assert h.statut(events) == 503

    def test_scelle_prime_sur_le_demarrage_non_abouti(self):
        """`sealed` est l'information ACTIONNABLE : elle reste vraie dans les deux cas."""
        h = Harnais(SondeFactice(reponse=SCELLE))
        events = h.appel("/health")

        assert h.corps(events)["status"] == lifecycle.HEALTH_SEALED

    def test_etat_latche_puis_rearme_par_une_nouvelle_generation(self):
        """
        Après un démarrage manqué, une sonde verte ne DOIT PAS promouvoir l'état.
        Seule une nouvelle génération ayant abouti le fait.
        """
        sonde = SondeFactice(reponse=SAIN)
        h = Harnais(sonde)

        assert h.corps(h.appel("/health"))["status"] == lifecycle.HEALTH_UNAVAILABLE

        # Nouvelle génération de lifespan, cette fois aboutie.
        lifecycle.mark_startup_starting()
        lifecycle.mark_startup_ready()
        assert h.corps(h.appel("/health"))["status"] == lifecycle.HEALTH_HEALTHY

        # Une génération suivante qui échoue REDESCEND l'état.
        lifecycle.mark_startup_starting()
        assert h.corps(h.appel("/health"))["status"] == lifecycle.HEALTH_UNAVAILABLE


# =============================================================================
# 2b) Les magasins configurés font partie de la disponibilité
# =============================================================================

class TestFraicheurDesMagasins:

    @staticmethod
    def _magasin(*, frais: bool):
        from mcp_vault.store_refresh import Freshness

        magasin = SimpleNamespace(CACHE_TTL=300.0, freshness=Freshness())
        if frais:
            magasin.freshness.mark_success()
        return magasin

    @pytest.mark.parametrize("chemin", ["/health", "/ready"])
    def test_un_seul_magasin_stale_suffit_a_refuser_la_disponibilite(self, chemin):
        """RED : OpenBao + latch ne suffisent pas si une décision lit un état périmé."""
        from mcp_vault import store_refresh

        lifecycle.mark_startup_ready()
        magasins = [
            ("token", self._magasin(frais=True)),
            ("policy", self._magasin(frais=False)),
        ]
        h = Harnais(SondeFactice(reponse=SAIN))

        with patch.object(store_refresh, "_magasins", return_value=magasins):
            events = h.appel(chemin)

        assert h.statut(events) == 503
        assert h.corps(events)["status"] == lifecycle.HEALTH_UNAVAILABLE

    def test_tous_les_magasins_doivent_etre_frais(self):
        """Rendre frais un store ne doit pas masquer qu'un autre reste périmé."""
        from mcp_vault import store_refresh

        lifecycle.mark_startup_ready()
        token = self._magasin(frais=False)
        policy = self._magasin(frais=False)
        h = Harnais(SondeFactice(reponse=SAIN))

        token.freshness.mark_success()
        with patch.object(
            store_refresh, "_magasins", return_value=[("token", token), ("policy", policy)]
        ):
            events = h.appel("/health")

        assert h.statut(events) == 503
        assert h.corps(events)["status"] == lifecycle.HEALTH_UNAVAILABLE

    def test_le_vrai_refresher_retablit_la_disponibilite_sans_redemarrage(self):
        """Le correctif doit préserver la récupération autonome déjà architecturée."""
        from mcp_vault import store_refresh

        lifecycle.mark_startup_ready()
        token = self._magasin(frais=True)

        class MagasinRecuperable:
            CACHE_TTL = 300.0

            def __init__(self):
                self.freshness = store_refresh.Freshness()
                self.refresh_lock = asyncio.Lock()
                self.chargements = 0

            def load(self):
                self.chargements += 1
                self.freshness.mark_success()

        policy = MagasinRecuperable()
        h = Harnais(SondeFactice(reponse=SAIN))

        async def scenario():
            with patch.object(
                store_refresh,
                "_magasins",
                return_value=[("token", token), ("policy", policy)],
            ):
                avant = await h.appel_async("/health")
                await store_refresh.StoreRefresher("policy", policy)._refresh_once()
                apres = await h.appel_async("/health")
            return avant, apres

        avant, apres = h.lance(scenario)

        assert h.statut(avant) == 503
        assert h.corps(avant)["status"] == lifecycle.HEALTH_UNAVAILABLE
        assert policy.chargements == 1
        assert h.statut(apres) == 200
        assert h.corps(apres)["status"] == lifecycle.HEALTH_HEALTHY

    def test_un_instantane_ancien_devient_indisponible(self):
        """La garde couvre aussi une péremption après succès, pas seulement le boot."""
        from mcp_vault import store_refresh

        lifecycle.mark_startup_ready()
        token = self._magasin(frais=True)
        token.freshness._last_success -= token.CACHE_TTL + 1
        h = Harnais(SondeFactice(reponse=SAIN))

        with patch.object(store_refresh, "_magasins", return_value=[("token", token)]):
            events = h.appel("/health")

        assert h.statut(events) == 503
        assert h.corps(events)["status"] == lifecycle.HEALTH_UNAVAILABLE

    def test_aucun_magasin_configure_conserve_le_mode_standalone(self):
        """Un Vault sans stores S3 ne doit pas devenir indisponible par défaut."""
        from mcp_vault import store_refresh

        lifecycle.mark_startup_ready()
        h = Harnais(SondeFactice(reponse=SAIN))

        with patch.object(store_refresh, "_magasins", return_value=[]):
            events = h.appel("/health")

        assert h.statut(events) == 200
        assert h.corps(events)["status"] == lifecycle.HEALTH_HEALTHY

    def test_la_sonde_de_fraicheur_ne_declenche_aucun_chargement(self):
        """La readiness lit la mémoire ; elle ne doit jamais devenir un appel S3."""
        from mcp_vault import store_refresh

        lifecycle.mark_startup_ready()
        token = self._magasin(frais=True)
        token.load = lambda: (_ for _ in ()).throw(
            AssertionError("load() appelé depuis /health")
        )
        h = Harnais(SondeFactice(reponse=SAIN))

        with patch.object(store_refresh, "_magasins", return_value=[("token", token)]), \
             patch.object(
                 store_refresh,
                 "run_blocking",
                 side_effect=AssertionError("run_blocking() appelé depuis /health"),
             ):
            events = h.appel("/health")

        assert h.statut(events) == 200
        assert h.corps(events)["status"] == lifecycle.HEALTH_HEALTHY

    def test_un_rapport_inexploitable_echoue_ferme_sans_fuite(self):
        """Une erreur d'observation ne doit devenir ni 500, ni diagnostic public."""
        from mcp_vault import store_refresh

        lifecycle.mark_startup_ready()
        h = Harnais(SondeFactice(reponse=SAIN))

        with patch.object(
            store_refresh, "_magasins", side_effect=RuntimeError(DETAIL_SENSIBLE)
        ):
            events = h.appel("/health")

        assert h.statut(events) == 503
        assert h.corps(events)["status"] == lifecycle.HEALTH_UNAVAILABLE
        assert DETAIL_SENSIBLE not in json.dumps(h.corps(events))


# =============================================================================
# 3) `/healthz` — liveness, jamais de sonde
# =============================================================================

class TestLivenessNeSondeJamais:

    def test_healthz_reste_200_quand_tout_est_en_panne(self):
        lifecycle.mark_startup_starting()
        h = Harnais(SondeFactice(exception=ConnectionRefusedError("refus")))
        events = h.appel("/healthz")

        assert h.statut(events) == 200

    def test_healthz_n_appelle_pas_la_sonde_meme_si_elle_bloque(self):
        """
        Garde anti-piège-latent. Si `/healthz` sondait, une sonde bloquante le
        ralentirait — et un autoheal branché dessus redémarrerait un coffre
        SCELLÉ, ce qui ne le descelle pas.
        """
        sonde = SondeFactice(reponse=SAIN, delai=5.0)
        h = Harnais(sonde)

        debut = time.monotonic()
        events = h.appel("/healthz")
        duree = time.monotonic() - debut

        assert h.statut(events) == 200
        assert sonde.constructions == 0, "/healthz a sondé OpenBao"
        assert duree < 1.0, f"/healthz a attendu la sonde ({duree:.2f}s)"

    def test_healthz_n_emprunte_pas_le_vocabulaire_de_disponibilite(self):
        """
        Dire `healthy` sur `/healthz` pendant que `/health` dit `sealed` serait
        une contradiction entre deux surfaces du même service.
        """
        h = Harnais(SondeFactice(reponse=SCELLE))
        corps = h.corps(h.appel("/healthz"))

        assert corps["status"] == lifecycle.HEALTH_ALIVE
        assert corps["status"] not in {lifecycle.HEALTH_HEALTHY,
                                       lifecycle.HEALTH_SEALED,
                                       lifecycle.HEALTH_UNAVAILABLE}


# =============================================================================
# 4) Sobriété du corps public — la ligne de partage posée par #116
# =============================================================================

class TestCorpsPublicSobre:

    def test_aucun_detail_de_dependance_ne_fuit(self):
        """
        On INJECTE un détail sensible dans la panne et on vérifie son absence.
        Un test qui se contenterait de lire les clés attendues passerait même
        si le diagnostic était recopié dans la réponse.
        """
        lifecycle.mark_startup_ready()
        h = Harnais(SondeFactice(exception=RuntimeError(DETAIL_SENSIBLE)))
        events = h.appel("/health")

        brut = json.dumps(h.corps(events))
        assert DETAIL_SENSIBLE not in brut
        assert "openbao.interne.example" not in brut
        assert "hvs." not in brut
        assert "8200" not in brut

    def test_enumeration_fermee(self):
        """Aucun état hors des trois valeurs ne peut sortir, quelle que soit la sonde."""
        lifecycle.mark_startup_ready()
        autorises = {lifecycle.HEALTH_HEALTHY, lifecycle.HEALTH_SEALED,
                     lifecycle.HEALTH_UNAVAILABLE}
        cas = [SondeFactice(reponse=SAIN),
               SondeFactice(reponse=SCELLE),
               SondeFactice(reponse=NON_INITIALISE),
               SondeFactice(reponse={"inattendu": True}),
               SondeFactice(reponse=None),
               SondeFactice(exception=RuntimeError("boum"))]

        for sonde in cas:
            h = Harnais(sonde)
            for chemin in ("/health", "/ready"):
                statut = h.corps(h.appel(chemin))["status"]
                assert statut in autorises, f"état hors énumération : {statut!r}"

    @pytest.mark.parametrize("reponse", [None, "texte", 42, [], True])
    def test_reponse_inexploitable_n_est_jamais_saine(self, reponse):
        """
        Une réponse que l'on ne peut pas lire ne PROUVE PAS « initialisé et
        descellé ». Le code d'origine la promouvait en « accessible », donc en
        sain — la même complaisance que le littéral corrigé par cette issue.

        Le test d'énumération ci-dessus ne suffisait PAS à l'attraper : `healthy`
        appartient à l'énumération, donc il vérifiait le vocabulaire et non la
        sémantique. Relevé en revue de diff.
        """
        lifecycle.mark_startup_ready()
        h = Harnais(SondeFactice(reponse=reponse))
        events = h.appel("/health")

        assert h.corps(events)["status"] == lifecycle.HEALTH_UNAVAILABLE
        assert h.statut(events) == 503

    @pytest.mark.parametrize("reponse", [
        {},                                    # rien d'affirmé
        {"initialized": True},                 # `sealed` absent
        {"sealed": False},                     # `initialized` absent
        {"sealed": "false", "initialized": True},   # type inattendu
        {"sealed": 0, "initialized": 1},            # coercition refusée
    ])
    def test_dict_incomplet_est_indisponible_pas_scelle(self, reponse):
        """
        Une réponse incomplète ne prouve NI le scellement NI l'utilisabilité.

        `sealed` est devenu un état PUBLIC et ACTIONNABLE : le déduire d'une
        valeur par défaut ferait annoncer « descellez-moi » sur une réponse qui
        ne le dit pas. Fail-close, mais sans usurper `sealed`. Relevé en revue.
        """
        lifecycle.mark_startup_ready()
        h = Harnais(SondeFactice(reponse=reponse))
        events = h.appel("/health")

        assert h.corps(events)["status"] == lifecycle.HEALTH_UNAVAILABLE
        assert h.statut(events) == 503

    def test_scelle_reste_scelle_quand_il_est_explicitement_constate(self):
        """Le durcissement ci-dessus ne doit pas faire disparaître `sealed`."""
        lifecycle.mark_startup_ready()
        h = Harnais(SondeFactice(reponse={"sealed": True}))

        assert h.corps(h.appel("/health"))["status"] == lifecycle.HEALTH_SEALED

    def test_format_du_corps_preserve(self):
        """La CI asserte `version` dans ce corps — le format ne doit pas bouger."""
        lifecycle.mark_startup_ready()
        h = Harnais(SondeFactice(reponse=SAIN))
        corps = h.corps(h.appel("/health"))

        assert set(corps) == {"status", "service", "version", "transport"}
        assert corps["transport"] == "streamable-http"


# =============================================================================
# 5) La sonde ne gèle pas et ne se multiplie pas
# =============================================================================

class TestSondeBorneeEtSingleFlight:

    def test_rafale_ne_declenche_qu_une_seule_sonde(self):
        """
        Sans single-flight, N requêtes concurrentes lançaient N appels réels.
        `/health` est public : c'est un facteur d'amplification.
        """
        lifecycle.mark_startup_ready()
        sonde = SondeFactice(reponse=SAIN, delai=0.3)
        h = Harnais(sonde)

        async def rafale():
            return await asyncio.gather(*(h.appel_async("/health") for _ in range(8)))

        resultats = h.lance(rafale)

        assert all(h.statut(ev) == 200 for ev in resultats)
        assert sonde.constructions == 1, (
            f"{sonde.constructions} sondes réelles pour 8 requêtes concurrentes")

    def test_appels_sequentiels_ne_sont_pas_mis_en_cache(self):
        """
        Un cache permettrait de répondre « disponible » APRÈS la panne —
        régression de contrat déjà refusée en revue au lot 2 de #110.
        """
        lifecycle.mark_startup_ready()
        sonde = SondeFactice(reponse=SAIN)
        h = Harnais(sonde)

        async def deux_appels():
            await h.appel_async("/health")
            await h.appel_async("/health")

        h.lance(deux_appels)
        assert sonde.constructions == 2, "un résultat a été réutilisé"

    def test_le_timeout_reel_est_transmis_a_hvac(self):
        """
        `run_blocking` documente que son attente n'est PAS bornée : la seule
        borne du thread est le timeout passé à hvac. On capture la valeur
        réellement transmise à la fabrique, pas une chaîne dans le code.
        """
        lifecycle.mark_startup_ready()
        sonde = SondeFactice(reponse=SAIN)
        h = Harnais(sonde, timeout=7)
        h.appel("/health")

        assert sonde.timeouts_recus == [7]

    def test_echeance_de_l_appelant_degrade_sans_pendre(self):
        """
        Sonde plus lente que l'échéance : la requête DOIT rendre la main, en
        dégradé, dans le budget — pas attendre la fin du thread.
        """
        lifecycle.mark_startup_ready()
        sonde = SondeFactice(reponse=SAIN, delai=2.0)
        h = Harnais(sonde, timeout=0.2)

        # La durée se mesure DANS la boucle. Mesurée autour d'`asyncio.run`,
        # elle inclurait `shutdown_default_executor()`, qui attend la fin du
        # thread : on mesurerait la fermeture de la boucle, pas la requête.
        async def scenario():
            debut = time.monotonic()
            events = await h.appel_async("/health")
            return events, time.monotonic() - debut

        events, duree = h.lance(scenario)

        assert h.statut(events) == 503
        assert h.corps(events)["status"] == lifecycle.HEALTH_UNAVAILABLE
        assert duree < 1.0, f"la requête a attendu le thread ({duree:.2f}s)"

    def test_echeance_de_l_appelant_n_annule_pas_la_sonde_partagee(self):
        """
        `wait_for` annule le `shield`, jamais la tâche derrière. Si l'échéance
        annulait la sonde partagée, les autres appelants seraient frappés.
        """
        lifecycle.mark_startup_ready()
        sonde = SondeFactice(reponse=SAIN, delai=0.6)
        h = Harnais(sonde, timeout=0.15)

        async def scenario():
            await h.appel_async("/health")          # expire
            etat = manager._probe_state_for_loop()
            tache = etat["probe_task"]
            assert tache is not None and not tache.cancelled()
            return await tache                      # la sonde va au bout

        resultat = h.lance(scenario)
        assert resultat.ok is True

    def test_la_sonde_est_reellement_offloadee(self):
        """
        Preuve d'offload : un témoin asyncio doit PROGRESSER pendant que la
        sonde bloque. Si l'appel hvac était resté dans la boucle, le témoin
        serait figé — c'est exactement le défaut #110.
        """
        lifecycle.mark_startup_ready()
        sonde = SondeFactice(reponse=SAIN, delai=0.5)
        h = Harnais(sonde)

        async def scenario():
            tours = 0

            async def temoin():
                nonlocal tours
                while True:
                    tours += 1
                    await asyncio.sleep(0.01)

            t = asyncio.create_task(temoin())
            await h.appel_async("/health")
            t.cancel()
            return tours

        tours = h.lance(scenario)
        assert tours > 5, f"la boucle est restée figée pendant la sonde ({tours} tours)"


# =============================================================================
# 6) Surface authentifiée — même prédicat, mais elle a droit au diagnostic
# =============================================================================

class TestSurfaceAdmin:

    def _appel_admin(self, sonde, settings):
        from mcp_vault.admin import api as admin_api

        events = []

        async def send(ev):
            events.append(ev)

        async def scenario():
            with patch.object(manager.hvac, "Client", sonde), \
                 patch("mcp_vault.openbao.manager.get_settings", return_value=settings), \
                 patch("mcp_vault.admin.api.get_settings", return_value=settings):
                await admin_api._api_health(send, mcp=None)

        _run(scenario())
        for ev in events:
            if ev["type"] == "http.response.body":
                return json.loads(ev["body"])
        return None

    def test_admin_reflete_le_meme_etat_que_la_sonde_publique(self):
        lifecycle.mark_startup_ready()
        corps = self._appel_admin(SondeFactice(reponse=SCELLE), _settings())

        assert corps["status"] == "degraded"
        assert corps["availability"] == lifecycle.HEALTH_SEALED

    def test_admin_reste_ok_quand_tout_va_bien(self):
        lifecycle.mark_startup_ready()
        corps = self._appel_admin(SondeFactice(reponse=SAIN), _settings())

        assert corps["status"] == "ok"
        assert corps["availability"] == lifecycle.HEALTH_HEALTHY

    def test_admin_authentifie_porte_le_diagnostic(self):
        """
        La surface authentifiée a droit à ce que la publique n'a pas — sinon
        l'exploitation perd le moyen de diagnostiquer.
        """
        lifecycle.mark_startup_ready()
        corps = self._appel_admin(SondeFactice(reponse=SCELLE), _settings())

        assert corps["availability_detail"]
        assert "scellé" in corps["availability_detail"].lower()


# =============================================================================
# 7) Fail-fast de configuration
# =============================================================================

class TestBorneObligatoire:

    @pytest.mark.parametrize("valeur", [0, -1, -30])
    def test_timeout_non_strictement_positif_refuse_le_demarrage(self, valeur):
        from mcp_vault.config import Settings

        s = Settings(admin_bootstrap_key="x" * 40, openbao_health_timeout=valeur)
        ok, msg = s.check_openbao_health_bounds()

        assert ok is False
        assert "OPENBAO_HEALTH_TIMEOUT" in msg

    def test_timeout_positif_accepte(self):
        from mcp_vault.config import Settings

        s = Settings(admin_bootstrap_key="x" * 40, openbao_health_timeout=2)
        assert s.check_openbao_health_bounds()[0] is True

    def test_le_fail_fast_est_branche_aux_deux_points_d_entree(self):
        """
        Tester un validateur ne prouve PAS qu'il est BRANCHÉ (leçon de la PR
        #129 : débrancher l'appel laissait 47 tests verts). `create_app()` et
        `main()` sont deux points d'entrée distincts — un lancement
        `uvicorn ...:create_app --factory` ne passe pas par `main()`.
        """
        import inspect

        from mcp_vault import server

        for fabrique in (server.create_app, server.main):
            source = inspect.getsource(fabrique)
            assert "check_openbao_health_bounds" in source, (
                f"{fabrique.__name__} ne valide pas la borne de sonde")

    def test_la_generation_est_rearmee_dans_le_vrai_lifespan(self):
        """
        Même raisonnement : les tests de latch manipulent `mark_startup_*`
        directement. Ils ne prouvent donc PAS que le vrai lifespan ouvre bien
        une génération avant de tenter le démarrage — sans quoi un lifespan
        précédent léguerait son « prêt » au suivant.
        """
        import inspect

        from mcp_vault import server

        source = inspect.getsource(server._install_vault_lifespan)
        assert "mark_startup_starting()" in source
        assert "mark_startup_ready()" in source
        # L'ouverture de génération DOIT précéder la tentative de démarrage.
        assert source.index("mark_startup_starting()") < source.index("vault_startup()")


# =============================================================================
# 8) Journalisation — sur transition, pas sur requête
# =============================================================================

class TestJournalSurTransition:

    def test_une_rafale_degradee_ne_produit_qu_une_ligne(self, caplog):
        """
        `/health` est PUBLIC et non authentifié. Une ligne par réponse dégradée
        donnerait à n'importe qui un levier d'amplification de journal (famille
        #111). Relevé en revue de diff.
        """
        import logging

        from mcp_vault.auth import middleware

        middleware._reset_journal_sante()
        lifecycle.mark_startup_ready()
        h = Harnais(SondeFactice(exception=ConnectionRefusedError("refus")))

        with caplog.at_level(logging.WARNING, logger="mcp-vault.health"):
            for _ in range(6):
                h.appel("/health")

        lignes = [r for r in caplog.records if r.name == "mcp-vault.health"]
        assert len(lignes) == 1, f"{len(lignes)} lignes pour 6 requêtes dégradées"

    def test_le_retablissement_est_journalise(self, caplog):
        """Une transition dans l'autre sens doit rester visible."""
        import logging

        from mcp_vault.auth import middleware

        middleware._reset_journal_sante()
        lifecycle.mark_startup_ready()

        panne = Harnais(SondeFactice(exception=OSError("panne")))
        retabli = Harnais(SondeFactice(reponse=SAIN))

        with caplog.at_level(logging.INFO, logger="mcp-vault.health"):
            panne.appel("/health")
            retabli.appel("/health")

        messages = [r.getMessage() for r in caplog.records
                    if r.name == "mcp-vault.health"]
        assert len(messages) == 2, messages
        assert "rétabli" in messages[1]

    def test_le_journal_ne_recopie_pas_le_detail_dans_la_reponse(self, caplog):
        """
        Le diagnostic va dans le JOURNAL — c'est voulu — mais il ne doit pas
        pour autant atteindre le corps public. Les deux propriétés sont
        vérifiées ENSEMBLE, sinon on peut satisfaire l'une en cassant l'autre.
        """
        import logging

        from mcp_vault.auth import middleware

        middleware._reset_journal_sante()
        lifecycle.mark_startup_ready()
        h = Harnais(SondeFactice(exception=RuntimeError(DETAIL_SENSIBLE)))

        with caplog.at_level(logging.WARNING, logger="mcp-vault.health"):
            events = h.appel("/health")

        assert any("RuntimeError" in r.getMessage() for r in caplog.records)
        assert DETAIL_SENSIBLE not in json.dumps(h.corps(events))
