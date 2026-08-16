# -*- coding: utf-8 -*-
"""
Rafraîchissement de fond des magasins — issue #123, lot 3 de #110.

Non-complaisant : on prouve l'incident, pas la couverture.

  - **La preuve du lot** : un chargement S3 LENT ne gèle plus la boucle. C'est
    l'incident #110 lui-même (488 s mesurées, sonde de santé comprise), reproduit
    en miniature et vérifié dans les deux sens — la garde répond vite, et le banc
    échouerait si le chargement repassait dans la boucle.
  - Les deux horloges de `Freshness` : brider une re-tentative ne rajeunit pas un
    instantané. C'est la confusion que `_cache_time` portait, et elle rendait un
    magasin en panne « frais » indéfiniment.
  - La cadence de re-tentative (10 s après un échec, TTL/2 sinon) — propriété
    déplacée ici depuis les bancs des magasins, où elle prouvait l'ancien
    chargement en ligne.
  - Le drainage d'arrêt : `stop()` ne rend la main qu'une fois le thread terminé.
    Un arrêt qui laisse une écriture en vol la ferait atterrir APRÈS l'archive
    finale.
  - Le verrou du registre wrap existe réellement — sans lui, `_offload_registre`
    prend silencieusement un chemin non sérialisé.
"""

import asyncio
import os
import sys
import threading
import time

import pytest

# Convention du projet : mcp_vault vit dans src/ (pas d'install du package)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp_vault.store_refresh import (
    RETRY_AFTER_ERROR_SECONDS,
    Freshness,
    StoreRefresher,
    drain_store_lock,
)


def _run(coro):
    return asyncio.run(coro)


class _MagasinFactice:
    """Magasin minimal conforme au contrat attendu par `StoreRefresher`."""

    CACHE_TTL = 0.2

    def __init__(self, duree_load: float = 0.0, echoue: bool = False):
        self.freshness = Freshness()
        self.refresh_lock = asyncio.Lock()
        self._duree = duree_load
        self._echoue = echoue
        self.chargements = 0
        self.thread_de_chargement = []

    def load(self):
        self.chargements += 1
        self.thread_de_chargement.append(threading.current_thread().name)
        if self._duree:
            time.sleep(self._duree)
        if self._echoue:
            self.freshness.mark_failure("S3 GET: TimeoutError")
        else:
            self.freshness.mark_success()


# =============================================================================
# LA preuve du lot : un S3 lent ne gèle plus la boucle
# =============================================================================

class TestLaBoucleResteReactive:
    def test_un_chargement_LENT_ne_gele_pas_la_boucle(self):
        """Reproduction miniature de #110.

        Un `load()` de 400 ms tourne. Pendant ce temps, une autre coroutine doit
        continuer à progresser — c'est exactement ce qui manquait quand la sonde
        de santé attendait 488 s derrière un GET S3.

        SABOTAGE : remplacer `run_blocking(self.store.load)` par `self.store.load()`
        dans `StoreRefresher._refresh_once` fait tomber ce test — les tours
        tombent à ~0 et la latence explose.
        """
        magasin = _MagasinFactice(duree_load=0.4)

        async def scenario():
            refresher = StoreRefresher("lent", magasin)
            chargement = asyncio.create_task(refresher._refresh_once())
            tours = 0
            debut = time.monotonic()
            while not chargement.done() and time.monotonic() - debut < 2.0:
                await asyncio.sleep(0.005)
                tours += 1
            await chargement
            return tours

        tours = _run(scenario())
        assert magasin.chargements == 1
        # Sans offload, la boucle serait bloquée du début à la fin du load :
        # aucun tour n'aurait lieu. Avec offload, il y en a des dizaines.
        assert tours > 20, f"la boucle n'a tourné que {tours} fois — elle est gelée"

    def test_le_chargement_se_fait_HORS_du_thread_de_la_boucle(self):
        """Le test précédent mesure une conséquence ; celui-ci nomme la cause."""
        magasin = _MagasinFactice()

        async def scenario():
            thread_boucle = threading.current_thread().name
            await StoreRefresher("x", magasin)._refresh_once()
            return thread_boucle

        thread_boucle = _run(scenario())
        assert magasin.thread_de_chargement == [
            t for t in magasin.thread_de_chargement if t != thread_boucle
        ], "le chargement a eu lieu dans le thread de la boucle"

    def test_la_garde_du_PolicyStore_repond_pendant_un_chargement_lent(self):
        """Le bout en bout : le point de décision réel, pendant un S3 lent.

        C'est la propriété que #123 vend. La vérifier sur un magasin factice ne
        suffirait pas : c'est `is_tool_allowed` qui gelait le service.
        """
        from types import SimpleNamespace
        from mcp_vault.auth.policies import PolicyStore

        store = PolicyStore(SimpleNamespace(s3_bucket_name="b"))
        store._policies = {"p": {"policy_id": "p", "allowed_tools": [],
                                 "denied_tools": [], "path_rules": []}}
        store.freshness.mark_success()

        lent = {"n": 0}
        vrai_load = store.load

        def load_lent():
            lent["n"] += 1
            time.sleep(0.4)
            store.freshness.mark_success()

        store.load = load_lent

        async def scenario():
            refresher = StoreRefresher("policy", store)
            chargement = asyncio.create_task(refresher._refresh_once())
            await asyncio.sleep(0.05)  # laisser le thread démarrer
            debut = time.monotonic()
            decision = store.is_tool_allowed("p", "vault_delete")
            latence = time.monotonic() - debut
            await chargement
            return decision, latence

        decision, latence = _run(scenario())
        assert decision is True
        assert latence < 0.05, (
            f"la décision a mis {latence * 1000:.0f} ms — elle attend le réseau")
        assert lent["n"] == 1


# =============================================================================
# Les deux horloges — la confusion que `_cache_time` portait
# =============================================================================

class TestFreshness:
    def test_un_objet_neuf_est_PERIME(self):
        """Venir d'être construit n'autorise rien."""
        assert Freshness().is_stale(300) is True
        assert Freshness().never_loaded is True

    def test_un_echec_ne_rajeunit_PAS_l_instantane(self):
        """RÉGRESSION CENTRALE. SABOTAGE : faire avancer `_last_success` dans
        `mark_failure` fait passer ce test au vert à tort — et ressuscite le
        défaut d'origine, où un magasin en panne restait « frais » pour toujours
        parce que chaque échec repoussait la même horloge."""
        f = Freshness()
        f.mark_success()
        f._last_success -= 299
        for _ in range(50):
            f.mark_failure("panne")
        assert f.is_stale(300) is False   # encore frais, de justesse
        f._last_success -= 2
        assert f.is_stale(300) is True    # la fraîcheur RÉELLE a expiré

    def test_un_echec_bride_bien_la_re_tentative(self):
        """L'autre moitié : `last_attempt` doit avancer, sinon on martèle S3."""
        f = Freshness()
        assert f.may_retry(10) is True    # jamais tenté
        f.mark_failure("panne")
        assert f.may_retry(10) is False
        f._last_attempt -= 11
        assert f.may_retry(10) is True

    def test_le_temps_est_MONOTONE_pas_l_horloge_murale(self):
        """Un recul d'horloge murale (NTP, VM restaurée) ne doit pas rajeunir un
        instantané : ce serait servir des autorisations qui devaient être
        refusées. SABOTAGE : repasser `Freshness` sur `time.time()` fait tomber
        ce test."""
        from unittest.mock import patch
        f = Freshness()
        f.mark_success()
        f._last_success -= 400
        with patch("time.time", return_value=0.0):  # horloge murale reculée à zéro
            assert f.is_stale(300) is True


# =============================================================================
# Cadence — propriété déplacée depuis les bancs des magasins
# =============================================================================

class TestCadence:
    def test_apres_un_echec_la_re_tentative_est_ACCELEREE(self):
        """Déplacé depuis `test_token_store_hardening` et
        `test_policy_store_availability` : la propriété « on retente à 10 s, pas
        au TTL » n'a pas disparu, elle a changé de propriétaire."""
        magasin = _MagasinFactice(echoue=True)
        magasin.CACHE_TTL = 300
        refresher = StoreRefresher("x", magasin)
        assert refresher._next_delay() == max(1.0, 300 / 2)  # nominal avant tout échec
        magasin.freshness.mark_failure("S3 GET: TimeoutError")
        assert refresher._next_delay() == RETRY_AFTER_ERROR_SECONDS
        assert RETRY_AFTER_ERROR_SECONDS < magasin.CACHE_TTL

    def test_la_cadence_nominale_tient_dans_le_TTL(self):
        """Rafraîchir À l'échéance du TTL laisserait une fenêtre où l'instantané
        est périmé alors que rien n'est en panne — et donc un fail-close sur un
        service parfaitement sain. La moitié du TTL laisse un rafraîchissement
        raté sans conséquence."""
        magasin = _MagasinFactice()
        magasin.CACHE_TTL = 300
        assert StoreRefresher("x", magasin)._next_delay() < magasin.CACHE_TTL

    def test_une_erreur_INATTENDUE_ne_tue_pas_la_boucle(self):
        """Un rafraîchisseur mort périme son magasin en silence jusqu'au
        fail-close. `_refresh_once` doit donc absorber l'inattendu."""
        magasin = _MagasinFactice()

        def load_qui_explose():
            raise RuntimeError("exécuteur cassé")

        magasin.load = load_qui_explose

        async def scenario():
            await StoreRefresher("x", magasin)._refresh_once()  # ne doit pas lever
            return True

        assert _run(scenario()) is True


# =============================================================================
# Drainage d'arrêt
# =============================================================================

class TestDrainage:
    def test_stop_ATTEND_la_fin_du_chargement_en_vol(self):
        """Une écriture encore en vol après l'arrêt atterrirait APRÈS l'archive
        finale — c'est l'invariant du lot 2, qui doit tenir ici aussi."""
        magasin = _MagasinFactice(duree_load=0.3)

        async def scenario():
            refresher = StoreRefresher("x", magasin)
            tache = asyncio.create_task(refresher._refresh_once())
            await asyncio.sleep(0.05)
            async with magasin.refresh_lock:      # n'est pris qu'une fois libéré
                pris_pendant = magasin.chargements
            await tache
            return pris_pendant

        # Le verrou n'a pu être pris qu'APRÈS la fin du chargement : le compteur
        # est donc déjà à 1, et le thread terminé.
        assert _run(scenario()) == 1

    def test_drain_store_lock_attend_le_verrou(self):
        magasin = _MagasinFactice(duree_load=0.2)

        async def scenario():
            tache = asyncio.create_task(StoreRefresher("x", magasin)._refresh_once())
            await asyncio.sleep(0.02)
            debut = time.monotonic()
            await drain_store_lock("x", magasin)
            attendu = time.monotonic() - debut
            await tache
            return attendu

        # Le drainage a réellement attendu (il n'a pas rendu la main aussitôt).
        assert _run(scenario()) > 0.05

    def test_une_mutation_arrivant_APRES_le_drainage_est_REFUSEE(self, monkeypatch):
        """Ce que « drainé » doit vouloir dire.

        Prendre puis relâcher le verrou ne prouve rien à lui seul : une mutation
        arrivée pendant l'arrêt attendrait simplement son tour et ferait son PUT
        APRÈS. Il faut une barrière de FERMETURE, vérifiée avant le verrou.
        SABOTAGE : retirer la pose de `_ferme_pour_arret` fait passer la mutation.
        """
        from types import SimpleNamespace

        import mcp_vault.store_refresh as sr
        from mcp_vault.auth.policies import PolicyStore

        store = PolicyStore(SimpleNamespace(s3_bucket_name="b"))
        store.freshness.mark_success()
        store._save = lambda snapshot: True
        monkeypatch.setattr(sr, "_magasins", lambda: [("policy", store)])
        monkeypatch.setattr(sr, "_refreshers", [])

        async def scenario():
            avant = await store.acreate("avant-arret")
            atteste = await sr.stop_store_refreshers()
            apres = await store.acreate("apres-arret")
            return avant, atteste, apres

        avant, atteste, apres = _run(scenario())
        assert avant["status"] == "created"
        assert atteste is True, "le drainage devait être attesté"
        assert apres.get("error_type") == "policy_store_unavailable", apres
        assert "apres-arret" not in store._policies, (
            "une mutation a été publiée après le drainage — elle aurait pu écrire "
            "sur S3 après l'arrêt")

    def test_le_REGISTRE_WRAP_est_fermé_lui_aussi_apres_le_drainage(self, monkeypatch):
        """⚠️ Trou relevé en revue : la barrière couvrait TROIS magasins sur quatre.

        `_offload_registre` ne regardait que le verrou. Après la fermeture et le
        drainage, création, révocation, compensation et consommation pouvaient
        donc encore prendre le verrou, écrire le registre et appeler OpenBao —
        c'est-à-dire écrire APRÈS l'attestation « aucune écriture en vol ».
        Une demi-fermeture annoncée est pire qu'une absence de fermeture.

        La CONSULTATION reste ouverte, délibérément : elle ne mute rien, et la
        refuser dégraderait le diagnostic au pire moment.
        """
        from types import SimpleNamespace
        from unittest.mock import MagicMock, patch

        import mcp_vault.store_refresh as sr
        from mcp_vault.vault import wrapping as w
        from mcp_vault.vault.wrapping import WrapRegistry

        class RegistreEnMemoire(WrapRegistry):
            def __init__(self):
                super().__init__(SimpleNamespace(s3_bucket_name="b"))
                self.freshness.mark_success()
                self.sauvegardes = 0

            def load(self):
                pass

            def _save(self):
                self.sauvegardes += 1
                return True

        registre = RegistreEnMemoire()
        # Une entrée ACTIVE : sans elle, révocation et compensation sortiraient
        # en `not_found` même sans barrière, et le test serait creux.
        registre._wraps = [{
            "operation_id": "op-1", "mission_id": "m", "accessor": "ACC-1",
            "vault_id": "v", "secret_path": "p", "created_at": "",
            "expires_at": "2099-01-01T00:00:00+00:00", "status": "active",
        }]
        monkeypatch.setattr(sr, "_magasins", lambda: [("wrap_registry", registre)])
        monkeypatch.setattr(sr, "_refreshers", [])
        client = MagicMock()

        from tests.conftest import admin_auth_context

        async def scenario():
            await sr.stop_store_refreshers()
            # Contexte admin : sans lui le filtre de visibilité (#115) masque
            # l'entrée et la consultation rendrait `not_found` — le test ne
            # prouverait alors pas que la LECTURE a réellement abouti.
            with admin_auth_context(), \
                 patch.object(w, "get_wrap_registry", return_value=registre), \
                 patch.object(w, "_get_client", return_value=client), \
                 patch.object(w, "_get_config",
                              return_value=SimpleNamespaceConfig()):
                return {
                    "création": await w.wrap_secret(
                        vault_id="v", secret_path="p", mission_id="m",
                        operation_id="op-2"),
                    "révocation": await w.revoke_wrap("ACC-1"),
                    "compensation": await w.lookup_and_revoke_by_operation_id(
                        "op-1", "m"),
                    "consommation": await w.consume_wrap_secret(
                        wrap_token="t", operation_id="op-1", mission_id="m"),
                    "consultation": await w.status_by_operation_id("op-1", "m"),
                }

        r = _run(scenario())

        # ── Les QUATRE écritures sont refusées ───────────────────────────
        for nom in ("création", "révocation", "compensation", "consommation"):
            assert r[nom].get("error_type") == "backend_unavailable", (
                f"{nom} acceptée après le drainage : {r[nom]!r}")
        assert registre.sauvegardes == 0, (
            "le registre a été écrit après le drainage — l'attestation ment")
        assert not client.read.called, "OpenBao lu après le drainage"
        assert not client.auth.token.revoke_accessor.called, (
            "révocation OpenBao émise après le drainage")

        # ── La LECTURE reste servie ──────────────────────────────────────
        # ⚠️ Assertion POSITIVE et vérifiable. Une première version écrivait
        # `assert ... != "backend_unavailable" or True` : toujours vraie, donc
        # muette si la consultation était fermée à tort. Relevé en revue.
        consultation = r["consultation"]
        assert consultation.get("status") == "ok", (
            f"la consultation a été fermée à tort : elle ne mute rien et son "
            f"diagnostic est le plus utile pendant un arrêt — {consultation!r}")
        assert consultation.get("state") == "active", consultation

    def test_un_SECOND_lifespan_reouvre_les_magasins(self, monkeypatch):
        """Les singletons survivent à l'arrêt : la barrière doit être LEVÉE au
        démarrage suivant.

        Un même processus peut enchaîner deux lifespans (ASGI embarqué,
        redémarrage à chaud) — c'est la raison d'être de `_reset_shutdown_state`.
        Sans cette levée, le second démarrage refuserait toute mutation,
        définitivement et en silence. SABOTAGE : retirer la remise à False dans
        `start_store_refreshers` fait tomber ce test.
        """
        from types import SimpleNamespace

        import mcp_vault.store_refresh as sr
        from mcp_vault.auth.policies import PolicyStore

        store = PolicyStore(SimpleNamespace(s3_bucket_name="b"))
        store.freshness.mark_success()
        store._save = lambda snapshot: True
        monkeypatch.setattr(sr, "_magasins", lambda: [("policy", store)])
        monkeypatch.setattr(sr, "_refreshers", [])

        async def scenario():
            sr.start_store_refreshers()
            await sr.stop_store_refreshers()          # 1er lifespan
            sr.start_store_refreshers()               # 2e lifespan
            resultat = await store.acreate("apres-redemarrage")
            await sr.stop_store_refreshers()
            return resultat

        res = _run(scenario())
        assert res["status"] == "created", (
            f"le second lifespan refuse toute mutation : la barrière d'arrêt "
            f"n'a jamais été levée — {res!r}")

    def test_un_drainage_EN_ECHEC_est_rapporte_et_non_avale(self, monkeypatch):
        """`stop_store_refreshers` avalait ses erreurs pendant que le lifecycle
        annonçait « aucune écriture en vol ». Un arrêt qui ment sur son propre
        drainage est pire qu'un arrêt bruyant."""
        import mcp_vault.store_refresh as sr

        casse = SimpleNamespaceMagasinCasse()
        monkeypatch.setattr(sr, "_magasins", lambda: [("casse", casse)])
        monkeypatch.setattr(sr, "_refreshers", [])
        assert _run(sr.stop_store_refreshers()) is False

    def test_drain_sur_un_magasin_SANS_verrou_ne_leve_pas(self):
        """S3 non configuré : il n'y a pas de magasin, le drainage doit être un
        non-événement et non une exception à l'arrêt."""
        _run(drain_store_lock("absent", object()))


# =============================================================================
# Le verrou du registre wrap doit exister
# =============================================================================

class TestOrchestration:
    """Le câblage : sans lui, tout le reste est du code mort."""

    def test_demarrage_puis_arret_des_rafraichisseurs(self, monkeypatch):
        import mcp_vault.store_refresh as sr

        magasin = _MagasinFactice()
        magasin.CACHE_TTL = 0.2
        monkeypatch.setattr(sr, "_magasins", lambda: [("factice", magasin)])
        monkeypatch.setattr(sr, "_refreshers", [])

        async def scenario():
            noms = sr.start_store_refreshers()
            assert noms == ["factice"]
            # ⚠️ La cadence n'est PAS TTL/2 ici : `_next_delay` applique un
            # plancher d'une seconde, qui domine sur un TTL de test. Ce plancher
            # protège d'un martèlement si un TTL était configuré très bas ; les
            # TTL réels (300 s et 30 s) n'y touchent jamais.
            await asyncio.sleep(1.2)
            await sr.stop_store_refreshers()
            return magasin.chargements

        chargements = _run(scenario())
        assert chargements >= 1, "le rafraîchisseur n'a jamais chargé"
        assert sr._refreshers == [], "l'arrêt n'a pas vidé la liste"

    def test_l_arret_est_idempotent_et_ne_leve_pas_sans_demarrage(self, monkeypatch):
        """L'arrêt est appelé par le lifespan, qui peut s'exécuter sans que le
        démarrage ait abouti. Il ne doit jamais faire échouer la séquence."""
        import mcp_vault.store_refresh as sr
        monkeypatch.setattr(sr, "_magasins", lambda: [])
        monkeypatch.setattr(sr, "_refreshers", [])
        _run(sr.stop_store_refreshers())
        _run(sr.stop_store_refreshers())

    def test_le_rapport_de_fraicheur_SIGNALE_un_magasin_perime(self, monkeypatch):
        """Sans ce signal, un rafraîchisseur mort ne se voit qu'au premier refus :
        le service répond normalement, puis refuse tout d'un coup."""
        import mcp_vault.store_refresh as sr

        magasin = _MagasinFactice()
        magasin.CACHE_TTL = 300
        magasin.freshness.mark_success()
        monkeypatch.setattr(sr, "_magasins", lambda: [("factice", magasin)])

        assert sr.freshness_report()["factice"]["stale"] is False
        magasin.freshness._last_success -= 301
        vue = sr.freshness_report()["factice"]
        assert vue["stale"] is True
        assert vue["age_seconds"] > 300


class TestLesFacadesOffloadentVRAIMENT:
    """⚠️ Relevé en revue : les bancs admin prouvent que les handlers appellent
    un nom de méthode compatible, pas qu'un PUT lent ne les bloque pas.

    `tests/doubles_magasins.py` relaie `a<verbe>` vers le mock synchrone dans la
    boucle — c'est voulu (les bancs configurent et inspectent la méthode
    synchrone), mais cela ne prouve rien sur l'offload. Ces deux tests le
    prouvent sur les vrais objets.
    """

    def test_une_mutation_LENTE_ne_gele_pas_la_boucle(self):
        """Le PUT d'une mutation part en thread : la boucle continue de tourner.

        SABOTAGE : remplacer `await run_blocking(...)` par un appel direct dans
        `PolicyStore.acreate` fait tomber ce test.
        """
        from types import SimpleNamespace
        from mcp_vault.auth.policies import PolicyStore

        store = PolicyStore(SimpleNamespace(s3_bucket_name="b"))
        store.freshness.mark_success()

        def save_lent(snapshot):
            time.sleep(0.4)
            return True

        store._save = save_lent

        async def scenario():
            mutation = asyncio.create_task(store.acreate("p-lente"))
            tours = 0
            debut = time.monotonic()
            while not mutation.done() and time.monotonic() - debut < 2.0:
                await asyncio.sleep(0.005)
                tours += 1
            return await mutation, tours

        res, tours = _run(scenario())
        assert res["status"] == "created", res
        assert tours > 20, f"la boucle n'a tourné que {tours} fois pendant le PUT"

    def test_chaque_facade_porte_LES_TROIS_garanties(self):
        """Verrou, offload, barrière de fermeture : les trois, sur les neuf.

        Une façade ajoutée plus tard sans l'une des trois régresserait en
        silence — un verrou oublié rouvre la course avec le rafraîchisseur, un
        offload oublié ramène le gel, une barrière oubliée laisse écrire après
        l'arrêt. Aucun banc fonctionnel ne le verrait : le résultat métier
        resterait correct.
        """
        import ast
        import pathlib

        VERBES = {"create", "update", "delete", "revoke", "purge", "purge_revoked"}
        manquants = []
        vues = 0
        for chemin in ("src/mcp_vault/auth/policies.py",
                       "src/mcp_vault/auth/token_store.py",
                       "src/mcp_vault/auth/mission_bindings.py"):
            arbre = ast.parse(pathlib.Path(chemin).read_text())
            for n in ast.walk(arbre):
                if (isinstance(n, ast.AsyncFunctionDef)
                        and n.name.startswith("a") and n.name[1:] in VERBES):
                    vues += 1
                    corps = ast.dump(n)
                    for garantie in ("refresh_lock", "run_blocking", "magasin_ferme"):
                        if garantie not in corps:
                            manquants.append(f"{chemin}::{n.name} → {garantie}")
        assert vues == 9, f"{vues} façades trouvées, 9 attendues (une a disparu ?)"
        assert not manquants, "garanties absentes :\n  " + "\n  ".join(manquants)

    def test_les_appelants_applicatifs_passent_TOUS_par_les_facades(self):
        """Un seul appel synchrone régressé suffit à ramener le gel, et il ne
        ferait rougir aucun banc fonctionnel : les bancs admin passeraient encore.
        On le vérifie donc structurellement, sur le code de production."""
        import ast
        import pathlib

        VERBES = {"create", "update", "delete", "revoke", "purge", "purge_revoked"}
        fautifs = []
        for chemin in ("src/mcp_vault/server.py", "src/mcp_vault/admin/api.py"):
            arbre = ast.parse(pathlib.Path(chemin).read_text())
            for n in ast.walk(arbre):
                if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                        and n.func.attr in VERBES
                        and isinstance(n.func.value, ast.Name)
                        and n.func.value.id == "store"):
                    fautifs.append(f"{chemin}:{n.lineno} store.{n.func.attr}()")
        assert not fautifs, (
            "mutation appelée en SYNCHRONE depuis un handler async — le PUT S3 "
            "gèlera la boucle (#110) :\n  " + "\n  ".join(fautifs))


class TestFailCloseSurInstantaneAmbigu:
    """RÉGRESSION S1 — trouvée en revue adversariale, couverte par AUCUN test.

    `blocking_intent_status` ne vaut que ce que vaut l'instantané qu'il interroge.
    Sur un registre non rafraîchi, une entrée bloquante EXISTANTE est invisible :
    la clé passe pour vierge, `register_pending` écrase l'entrée distante en
    dernier-écrivain-gagne, et OpenBao crée un SECOND wrap sur la même clé — soit
    exactement l'invariant d'usage unique que v0.14.0 a fermé et que nous avons
    publié aux trois équipes.

    ⚠️ La garde manquait DÉJÀ avant #123 : `_maybe_refresh` tentait un GET, mais un
    GET en échec laissait la décision se prendre sur la mémoire périmée. #123
    élargit la fenêtre (l'instantané peut être périmé alors que S3 est joignable),
    ce qui rend la garde indispensable. `revoke_wrap`, `secret_wrap_lookup` et
    `secret_wrap_status` la portaient déjà ; création et consommation, non.
    """

    def _registre_ambigu(self, entrees=()):
        from types import SimpleNamespace
        from mcp_vault.vault.wrapping import WrapRegistry

        class RegistreAmbigu(WrapRegistry):
            def __init__(self):
                super().__init__(SimpleNamespace(s3_bucket_name="b"))
                self._wraps = list(entrees)
                self.freshness.mark_success()
                self.sauvegardes = 0

            def load(self):
                raise AssertionError("aucun chargement ne doit partir de la boucle")

            def _save(self):
                self.sauvegardes += 1
                return True

        registre = RegistreAmbigu()
        # Personne n'a rechargé depuis plus que le TTL : `_maybe_refresh` doit le
        # constater et poser `_last_load_ok = False`.
        registre.freshness._last_success -= registre.CACHE_TTL + 1
        return registre

    def test_la_CREATION_est_refusee_sur_un_registre_non_rafraichi(self):
        from unittest.mock import MagicMock, patch

        from mcp_vault.vault import wrapping as w

        registre = self._registre_ambigu()
        client = MagicMock()
        with patch.object(w, "get_wrap_registry", return_value=registre), \
             patch.object(w, "_get_client", return_value=client), \
             patch.object(w, "_get_config", return_value=SimpleNamespaceConfig()):
            res = _run(w.wrap_secret(vault_id="v", secret_path="p",
                                     mission_id="m", operation_id="op-1"))

        assert res["error_type"] == "backend_unavailable", res
        assert registre.sauvegardes == 0, (
            "une intention a été écrite sur un instantané ambigu — elle écrase une "
            "entrée distante en dernier-écrivain-gagne")
        assert not client.write.called and not client.read.called, (
            "OpenBao appelé alors que la décision reposait sur un état incertain")

    def test_la_CONSOMMATION_est_refusee_sur_un_registre_non_rafraichi(self):
        from unittest.mock import MagicMock, patch

        from mcp_vault.vault import wrapping as w

        registre = self._registre_ambigu()
        client = MagicMock()
        with patch.object(w, "get_wrap_registry", return_value=registre), \
             patch.object(w, "_get_client", return_value=client):
            res = _run(w.consume_wrap_secret(wrap_token="t", operation_id="op-1",
                                             mission_id="m"))

        assert res["error_type"] == "backend_unavailable", res
        assert registre.sauvegardes == 0
        assert not client.sys.unwrap.called, "déballage tenté sur un état incertain"


class SimpleNamespaceMagasinCasse:
    """Magasin dont le drainage échoue — `refresh_lock` n'est pas un verrou."""
    refresh_lock = object()


class SimpleNamespaceConfig:
    """Réglages minimaux pour `wrap_secret` (aucun appel réseau attendu)."""
    openbao_addr = "http://localhost:8200"
    wrap_default_ttl_seconds = 300
    wrap_max_ttl_seconds = 600


class TestVerrouDuRegistreWrap:
    def test_le_vrai_registre_porte_TOUJOURS_un_verrou(self):
        """`_offload_registre` retombe sur un chemin NON sérialisé quand le
        registre ne porte pas `refresh_lock` — prévu pour les doubles de banc.
        Si le vrai registre perdait cet attribut, les opérations wrap cesseraient
        SILENCIEUSEMENT d'être sérialisées contre le rafraîchisseur de fond.
        """
        from types import SimpleNamespace
        from mcp_vault.vault.wrapping import WrapRegistry

        registre = WrapRegistry(SimpleNamespace(s3_bucket_name="b"))
        assert isinstance(registre.refresh_lock, asyncio.Lock)
        assert isinstance(registre.freshness, Freshness)

    def test_les_quatre_magasins_exposent_le_contrat_du_rafraichisseur(self):
        """Un magasin qui n'expose pas `load`/`freshness`/`refresh_lock`/`CACHE_TTL`
        ne serait jamais rafraîchi — il se périmerait puis refuserait, sans que
        rien ne l'annonce au démarrage."""
        from types import SimpleNamespace
        from mcp_vault.auth.mission_bindings import MissionBindingStore
        from mcp_vault.auth.policies import PolicyStore
        from mcp_vault.auth.token_store import TokenStore
        from mcp_vault.vault.wrapping import WrapRegistry

        reglages = SimpleNamespace(s3_bucket_name="b", s3_endpoint_url="http://x",
                                   resolved_mission_aud="mcp-vault:test:v1")
        for classe in (TokenStore, PolicyStore, MissionBindingStore, WrapRegistry):
            magasin = classe(reglages)
            for attribut in ("load", "freshness", "refresh_lock", "CACHE_TTL"):
                assert hasattr(magasin, attribut), (
                    f"{classe.__name__} n'expose pas {attribut!r} : il ne sera "
                    "jamais rafraîchi")
