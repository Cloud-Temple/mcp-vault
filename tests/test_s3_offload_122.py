# -*- coding: utf-8 -*-
"""
Issue #122 (lot 2 de #110) — les appels S3 sortent de la boucle d'événements.

## Ce que ces tests prouvent, et comment

Le défaut mesuré en production (#110) : un appel S3 synchrone dans la boucle
asyncio gèle TOUT le service — sonde de santé comprise — pendant la durée de
l'appel. Le lot 1 a borné cette durée ; le lot 2 supprime le gel **sur les cinq
chemins qu'il traite** (les magasins d'autorisation restent synchrones dans la
boucle jusqu'au lot 3, issue #123).

La preuve centrale ne dépend d'**aucun seuil de performance** — pas de compteur
de battements, pas de « au moins N tours en M millisecondes », rien qui puisse
devenir instable selon la charge de la machine. Elle repose sur un
ORDONNANCEMENT, vérifié par des barrières. (Des délais subsistent ailleurs :
plafonds de sécurité pour qu'un test en échec se termine, et budgets de
drainage volontairement raccourcis — aucun ne conditionne le verdict.)

    1. le stub bloquant signale son ENTRÉE (`entree`), puis attend `liberation` ;
    2. une coroutine témoin, dans la même boucle, attend cette entrée puis pose
       `temoin_a_progresse = True` et libère le stub ;
    3. **le stub échantillonne le témoin JUSTE AVANT DE SORTIR**, depuis le
       thread — donc entre son entrée effective et sa sortie, exactement ce que
       demande l'issue ;
    4. le test juge cet échantillon.

Si l'appel est resté dans la boucle, le témoin ne peut pas s'exécuter tant que
le stub n'a pas rendu la main : l'échantillon vaut `False`. C'est un RED
structurel, pas une course.

## Contrôle de l'instrument

`test_le_temoin_detecte_un_appel_reste_dans_la_boucle` applique le MÊME témoin à
un appel volontairement laissé dans la boucle et exige un résultat NÉGATIF. Sans
lui, un témoin cassé rendrait tous les autres tests verts sans rien prouver —
c'est arrivé deux fois sur ce dépôt (un script de mutation produisant un fichier
invalide comptait 0 échec).
"""

import asyncio
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_vault import s3_sync
from mcp_vault.async_offload import run_blocking

# Plafond de sécurité des attentes bloquantes : garantit qu'un test qui échoue
# se termine par un ÉCHEC lisible plutôt que par un blocage de la suite.
_GARDE_SECONDES = 5.0


# =============================================================================
# Harnais
# =============================================================================

class Barriere:
    """Stub bloquant instrumenté (cf. docstring du module)."""

    def __init__(self, retour=None, exception: BaseException = None):
        self.entree = threading.Event()
        self.liberation = threading.Event()
        self.temoin_a_progresse = False
        self.temoin_avant_sortie = None  # échantillon, posé DEPUIS le thread
        self.appels = 0
        self._retour = retour
        self._exception = exception

    def __call__(self, *args, **kwargs):
        self.appels += 1
        self.entree.set()
        self.liberation.wait(timeout=_GARDE_SECONDES)
        # ÉCHANTILLON : pris entre l'entrée effective et la sortie.
        self.temoin_avant_sortie = self.temoin_a_progresse
        if self._exception is not None:
            raise self._exception
        return self._retour


async def _temoin(barriere: Barriere) -> None:
    """Coroutine témoin : ne peut progresser que si la boucle est vivante."""
    while not barriere.entree.is_set():
        await asyncio.sleep(0.001)
    barriere.temoin_a_progresse = True
    barriere.liberation.set()


async def _avec_temoin(barriere: Barriere, operation):
    """Lance l'opération et le témoin dans la même boucle."""
    resultats = await asyncio.gather(operation, _temoin(barriere),
                                     return_exceptions=True)
    return resultats[0]


def _assert_boucle_restee_vivante(barriere: Barriere, quoi: str):
    assert barriere.entree.is_set(), f"{quoi} : le stub n'a jamais été appelé"
    assert barriere.temoin_avant_sortie is True, (
        f"{quoi} : la boucle d'événements était GELÉE pendant l'appel bloquant "
        f"(le témoin n'avait pas progressé au moment de sortir du stub)"
    )


def _settings(data_dir) -> SimpleNamespace:
    return SimpleNamespace(
        openbao_data_dir=str(data_dir),
        s3_bucket_name="test-bucket",
        vault_s3_prefix="_storage",
        vault_s3_sync_interval=60,
        s3_endpoint_url="http://localhost:0",
        s3_region_name="fr1",
        s3_connect_timeout=5,
        s3_read_timeout=30,
        s3_max_attempts=2,
        admin_bootstrap_key="Test-Bootstrap-Key-2026-Pour-Tests!!",
        openbao_addr="http://127.0.0.1:8200",
        openbao_shares=1,
        openbao_threshold=1,
    )


@pytest.fixture(autouse=True)
def _etat_neutre():
    s3_sync._reset_sync_state_for_tests()
    s3_sync._sync_task = None
    s3_sync._sync_stop_event = None

    yield
    s3_sync._reset_sync_state_for_tests()
    s3_sync._sync_task = None
    s3_sync._sync_stop_event = None



@pytest.fixture
def coffre(tmp_path, monkeypatch):
    data_dir = tmp_path / "openbao"
    data_dir.mkdir()
    (data_dir / "core").write_bytes(b"donnee-de-test")
    monkeypatch.setattr(s3_sync, "get_settings", lambda: _settings(data_dir))
    return data_dir


# =============================================================================
# 0) Contrôle de l'instrument — sans lui, tout le reste ne prouve rien
# =============================================================================

def test_le_temoin_detecte_un_appel_reste_dans_la_boucle():
    """
    Le MÊME témoin, appliqué à un appel volontairement laissé dans la boucle,
    doit être NÉGATIF. C'est la validation de l'outil de mesure lui-même.
    """
    barriere = Barriere(retour="peu importe")

    async def operation_bloquante_dans_la_boucle():
        return barriere()  # appel SYNCHRONE direct : gèle la boucle

    async def scenario():
        return await _avec_temoin(barriere, operation_bloquante_dans_la_boucle())

    asyncio.run(scenario())

    assert barriere.entree.is_set()
    assert barriere.temoin_avant_sortie is False, (
        "l'instrument est cassé : il ne détecte pas un gel de la boucle, donc "
        "aucun autre test de ce fichier ne prouve quoi que ce soit"
    )


def test_le_temoin_est_positif_quand_le_travail_est_offloade():
    """Face positive du contrôle : offloadé, le témoin progresse."""
    barriere = Barriere(retour="ok")

    async def scenario():
        return await _avec_temoin(barriere, run_blocking(barriere))

    assert asyncio.run(scenario()) == "ok"
    _assert_boucle_restee_vivante(barriere, "run_blocking")


# =============================================================================
# 1) Réactivité — les 5 sites S3 du périmètre de l'issue
# =============================================================================

def test_upload_reste_reactif_pendant_le_put(coffre, monkeypatch):
    barriere = Barriere(retour=None)
    monkeypatch.setattr(s3_sync, "_put_archive_blocking", barriere)

    async def scenario():
        return await _avec_temoin(barriere, s3_sync.upload_to_s3())

    assert asyncio.run(scenario()) is True
    _assert_boucle_restee_vivante(barriere, "upload_to_s3 (PUT)")


def test_upload_reste_reactif_pendant_une_compression_lente(coffre, monkeypatch):
    """
    Le gel ne vient pas seulement du réseau : le parcours disque et la
    compression sont bloquants et NON bornés. Un coffre volumineux gèlerait la
    boucle avant même qu'un octet parte vers S3.
    """
    barriere = Barriere(retour=(b"archive", "empreinte"))
    monkeypatch.setattr(s3_sync, "_snapshot_and_archive", barriere)
    monkeypatch.setattr(s3_sync, "_put_archive_blocking", lambda *a: None)

    async def scenario():
        return await _avec_temoin(barriere, s3_sync.upload_to_s3())

    assert asyncio.run(scenario()) is True
    _assert_boucle_restee_vivante(barriere, "upload_to_s3 (archive)")


def test_download_reste_reactif(coffre, monkeypatch):
    barriere = Barriere(retour=s3_sync.RestoreResult.RESTORED)
    monkeypatch.setattr(s3_sync, "_download_from_s3_blocking", barriere)

    async def scenario():
        return await _avec_temoin(barriere, s3_sync.download_from_s3())

    assert asyncio.run(scenario()) is s3_sync.RestoreResult.RESTORED
    _assert_boucle_restee_vivante(barriere, "download_from_s3")


def test_sonde_de_sante_reste_reactive(coffre, monkeypatch):
    """C'est le site le plus visible : `system_health` appelle `head_bucket` à
    chaque invocation. Un S3 lent y gelait le service à chaque vérification."""
    barriere = Barriere(retour=(True, "S3 OK (test-bucket)"))
    monkeypatch.setattr(s3_sync, "_head_bucket_blocking", barriere)

    async def scenario():
        return await _avec_temoin(barriere, s3_sync.check_s3_connectivity())

    assert asyncio.run(scenario()) == (True, "S3 OK (test-bucket)")
    _assert_boucle_restee_vivante(barriere, "check_s3_connectivity")


def test_upload_des_cles_openbao_reste_reactif(coffre, monkeypatch):
    """PUT des clés chiffrées + PBKDF2 600 000 itérations : bloquant deux fois."""
    from mcp_vault.openbao import lifecycle as ob_lifecycle

    barriere = Barriere(retour=True)
    monkeypatch.setattr(ob_lifecycle, "get_settings", lambda: _settings(coffre))
    monkeypatch.setattr(ob_lifecycle, "_upload_encrypted_keys_to_s3", barriere)

    client = MagicMock()
    client.sys.is_initialized.return_value = False
    client.sys.initialize.return_value = {
        "root_token": "jeton-de-test", "keys": ["cle"], "keys_base64": ["Y2xl"],
    }
    monkeypatch.setattr(ob_lifecycle.hvac, "Client", lambda **kw: client)

    async def scenario():
        return await _avec_temoin(barriere, ob_lifecycle.initialize_vault())

    resultat = asyncio.run(scenario())
    assert resultat["status"] == "initialized"
    _assert_boucle_restee_vivante(barriere, "initialize_vault (PUT clés)")


def test_download_des_cles_openbao_reste_reactif(coffre, monkeypatch):
    from mcp_vault.openbao import lifecycle as ob_lifecycle

    barriere = Barriere(retour=None)  # aucune clé trouvée : chemin sans effet
    monkeypatch.setattr(ob_lifecycle, "get_settings", lambda: _settings(coffre))
    monkeypatch.setattr(ob_lifecycle, "_check_and_migrate_legacy_keys", lambda: None)
    monkeypatch.setattr(ob_lifecycle, "_download_encrypted_keys_from_s3", barriere)
    monkeypatch.setattr(ob_lifecycle, "_openbao_data_exists", lambda: False)
    monkeypatch.setattr(ob_lifecycle, "_in_memory_keys", None)

    client = MagicMock()
    client.sys.is_sealed.return_value = True
    monkeypatch.setattr(ob_lifecycle.hvac, "Client", lambda **kw: client)

    async def scenario():
        return await _avec_temoin(barriere, ob_lifecycle.unseal_vault())

    asyncio.run(scenario())
    _assert_boucle_restee_vivante(barriere, "unseal_vault (GET clés)")


# =============================================================================
# 2) La primitive d'offload — l'invariant du verrou
# =============================================================================

def test_annulation_de_l_attente_ne_rend_pas_la_main_avant_la_fin_du_thread():
    """
    L'invariant central. Si `run_blocking` rendait la main sur annulation, le
    `async with lock` de l'appelant se terminerait alors que le thread écrit
    encore sur S3 — exactement ce que le verrou existe pour empêcher.
    """
    barriere = Barriere(retour="termine")
    thread_fini_au_retour = {}

    async def scenario():
        tache = asyncio.create_task(run_blocking(barriere))
        while not barriere.entree.is_set():
            await asyncio.sleep(0.001)
        tache.cancel()                       # on annule l'ATTENTE
        await asyncio.sleep(0.01)
        assert not tache.done(), (
            "run_blocking a rendu la main alors que le thread tourne encore : "
            "le verrou de l'appelant serait relâché avec un PUT en vol"
        )
        barriere.liberation.set()            # le thread termine enfin
        try:
            await tache
        except asyncio.CancelledError:
            pass
        thread_fini_au_retour["valeur"] = barriere.temoin_avant_sortie is not None

    asyncio.run(scenario())
    assert thread_fini_au_retour["valeur"] is True


def test_exception_metier_n_est_pas_masquee_par_l_annulation():
    """
    Priorité de récolte : une erreur d'upload ne doit jamais être maquillée en
    simple annulation — sinon un échec S3 passerait pour un arrêt normal.
    """
    class ErreurUpload(RuntimeError):
        pass

    barriere = Barriere(exception=ErreurUpload("PUT refusé"))

    async def scenario():
        tache = asyncio.create_task(run_blocking(barriere))
        while not barriere.entree.is_set():
            await asyncio.sleep(0.001)
        tache.cancel()
        barriere.liberation.set()
        return await tache

    with pytest.raises(ErreurUpload):
        asyncio.run(scenario())


def test_le_travailleur_n_est_pas_une_tache_annulable_par_le_teardown():
    """
    Régression du piège mesuré : une `Task` autour de `to_thread` est annulée
    par `_cancel_all_tasks()` au teardown d'`asyncio.run`, et l'attente part
    alors en rotation à vide (1 411 649 tours en 0,5 s lors de la mesure).
    Un `Future` d'exécuteur n'apparaît pas dans `all_tasks()`.

    L'observation est faite PENDANT que le travailleur est bloqué : sinon le
    décompte dépendrait de l'ordonnancement — un travail qui rend la main
    immédiatement ferait passer le test sans rien prouver.
    """
    barriere = Barriere(retour="fini")
    vues = {}

    async def scenario():
        tache = asyncio.create_task(run_blocking(barriere))
        while not barriere.entree.is_set():
            await asyncio.sleep(0.001)
        # Le travailleur est ICI bloqué : le décompte est déterministe.
        vues["taches"] = len(asyncio.all_tasks())
        barriere.temoin_a_progresse = True
        barriere.liberation.set()
        return await tache

    assert asyncio.run(scenario()) == "fini"
    # Tâche du scénario + tâche `run_blocking` = 2. Un travailleur enregistré
    # comme `Task` en ajouterait une troisième — et serait annulable par le
    # teardown.
    assert vues["taches"] == 2, (
        f"{vues['taches']} tâches pendant le travail bloquant : un travailleur "
        f"enregistré comme Task serait annulé par le teardown de la boucle"
    )


# =============================================================================
# 3) Sérialisation des uploads
# =============================================================================

def test_deux_uploads_concurrents_ne_s_entrelacent_pas(coffre, monkeypatch):
    """
    Sans verrou, un tick périodique et un upload PKI simultanés pourraient
    publier une archive et enregistrer l'empreinte d'une AUTRE — le cycle
    suivant sauterait alors un upload sur une référence qui ne correspond à
    rien de publié.
    """
    en_cours = {"valeur": 0}
    chevauchement = {"vu": False}

    def put(*args):
        en_cours["valeur"] += 1
        if en_cours["valeur"] > 1:
            chevauchement["vu"] = True
        threading.Event().wait(0.02)
        en_cours["valeur"] -= 1

    monkeypatch.setattr(s3_sync, "_put_archive_blocking", put)

    async def scenario():
        return await asyncio.gather(*(s3_sync.upload_to_s3() for _ in range(4)))

    assert all(asyncio.run(scenario()))
    assert chevauchement["vu"] is False, (
        "deux uploads se sont chevauchés : le verrou de sérialisation ne "
        "couvre pas l'offload"
    )


# =============================================================================
# 4) Sonde single-flight
# =============================================================================

def test_rafale_de_sondes_ne_declenche_qu_un_seul_head_reel(coffre, monkeypatch):
    barriere = Barriere(retour=(True, "S3 OK (test-bucket)"))
    monkeypatch.setattr(s3_sync, "_head_bucket_blocking", barriere)

    async def scenario():
        rafale = asyncio.gather(*(s3_sync.check_s3_connectivity() for _ in range(8)))
        return (await asyncio.gather(rafale, _temoin(barriere)))[0]

    resultats = asyncio.run(scenario())
    assert all(ok for ok, _ in resultats)
    assert barriere.appels == 1, (
        f"{barriere.appels} HEAD réels pour 8 appels — le single-flight ne "
        f"tient pas, et chaque HEAD est un blocage potentiel de plus"
    )


def test_echeance_d_un_appelant_n_annule_pas_la_sonde_partagee(coffre, monkeypatch):
    """
    L'échéance est LOCALE à l'appelant. Si elle annulait la tâche partagée, le
    premier impatient priverait tous les autres de leur résultat.
    """
    barriere = Barriere(retour=(True, "S3 OK (test-bucket)"))
    monkeypatch.setattr(s3_sync, "_head_bucket_blocking", barriere)
    # Échéance quasi nulle : l'appelant abandonne, la sonde doit survivre.
    monkeypatch.setattr(s3_sync, "get_settings",
                        lambda: SimpleNamespace(**{**vars(_settings(coffre)),
                                                   "s3_connect_timeout": 0.01}))

    async def scenario():
        impatient = await s3_sync.check_s3_connectivity()
        tache_partagee = s3_sync._state_for_loop()["probe_task"]
        assert not tache_partagee.cancelled(), (
            "l'échéance d'un appelant a annulé la sonde partagée"
        )
        barriere.temoin_a_progresse = True
        barriere.liberation.set()
        return impatient, await tache_partagee

    impatient, partage = asyncio.run(scenario())
    assert impatient == (False, "S3 inaccessible: sonde en cours (délai dépassé)")
    assert partage == (True, "S3 OK (test-bucket)")
    assert barriere.appels == 1


# =============================================================================
# 5) Drainage à l'arrêt — jamais d'annulation d'un PUT mutant
# =============================================================================

def test_drainage_attend_le_tick_en_vol_puis_autorise_l_upload_final(coffre, monkeypatch):
    puts = []
    barriere = Barriere(retour=None)

    def put(*args):
        puts.append("tick")
        barriere()

    monkeypatch.setattr(s3_sync, "_put_archive_blocking", put)
    monkeypatch.setattr(s3_sync, "get_settings",
                        lambda: SimpleNamespace(**{**vars(_settings(coffre)),
                                                   "vault_s3_sync_interval": 1}))

    async def scenario():
        await s3_sync.start_periodic_sync()
        while not barriere.entree.is_set():      # attendre le tick en vol
            await asyncio.sleep(0.001)
        barriere.temoin_a_progresse = True
        arret = asyncio.create_task(s3_sync.stop_periodic_sync())
        await asyncio.sleep(0.01)
        barriere.liberation.set()
        return await arret

    assert asyncio.run(scenario()) is True
    assert puts == ["tick"], "le tick en vol doit avoir été drainé, pas annulé"


def test_drainage_expire_ne_laisse_pas_la_tache_annulee(coffre, monkeypatch):
    """
    Contrainte centrale : un PUT mutant n'est JAMAIS annulé. Sur dépassement du
    budget, la tâche continue détachée et l'appelant reçoit False (qui interdit
    l'upload final côté `_vault_shutdown_sequence`).
    """
    barriere = Barriere(retour=None)
    monkeypatch.setattr(s3_sync, "_put_archive_blocking", barriere)
    monkeypatch.setattr(s3_sync, "_DRAIN_BUDGET_SECONDS", 0.05)
    monkeypatch.setattr(s3_sync, "get_settings",
                        lambda: SimpleNamespace(**{**vars(_settings(coffre)),
                                                   "vault_s3_sync_interval": 1}))
    observe = {}

    async def scenario():
        await s3_sync.start_periodic_sync()
        tache = s3_sync._sync_task
        while not barriere.entree.is_set():
            await asyncio.sleep(0.001)
        drainee = await s3_sync.stop_periodic_sync()      # doit expirer
        observe["annulee_pendant_le_put"] = tache.cancelled()
        observe["terminee_pendant_le_put"] = tache.done()
        barriere.temoin_a_progresse = True
        barriere.liberation.set()
        await asyncio.sleep(0.05)
        return drainee

    assert asyncio.run(scenario()) is False
    assert observe["annulee_pendant_le_put"] is False, (
        "la tâche a été ANNULÉE : un PUT orphelin peut terminer après l'upload "
        "final et écraser une archive plus récente"
    )
    assert observe["terminee_pendant_le_put"] is False


def test_intervalle_long_sans_tick_actif_draine_immediatement(coffre, monkeypatch):
    """
    Le piège que ferme la boucle réveillable : avec `asyncio.sleep(interval)` et
    un intervalle supérieur au budget de drainage, un worker AU REPOS serait
    classé « non drainé » — et l'upload final abandonné alors que rien n'était
    en cours. RED si la boucle redevient un `sleep`.
    """
    monkeypatch.setattr(s3_sync, "_DRAIN_BUDGET_SECONDS", 0.5)
    monkeypatch.setattr(s3_sync, "get_settings",
                        lambda: SimpleNamespace(**{**vars(_settings(coffre)),
                                                   "vault_s3_sync_interval": 300}))

    async def scenario():
        await s3_sync.start_periodic_sync()
        await asyncio.sleep(0.01)          # worker au repos, aucun tick en vol
        return await s3_sync.stop_periodic_sync()

    assert asyncio.run(scenario()) is True, (
        "un worker au repos avec un intervalle de 300 s doit se drainer "
        "immédiatement, pas expirer au budget de drainage"
    )


def test_arret_sans_tache_de_sync_est_considere_draine(coffre):
    """Sync désactivée (interval=0) : rien à drainer, l'upload final reste permis."""
    assert asyncio.run(s3_sync.stop_periodic_sync()) is True


def test_aucun_demarrage_n_est_accepte_pendant_un_drainage(coffre, monkeypatch):
    """
    Le scénario le plus dangereux de tout le chemin d'arrêt, et il exerce le
    VRAI `start_periodic_sync()` — pas une tâche injectée à la main.

    Le drainage rend la main à la boucle. Si un démarrage s'intercale dès que la
    tâche drainée se termine, l'arrêt conclut « drainé » sur une tâche pendant
    qu'une NOUVELLE boucle, jamais drainée, reste libre d'écrire — et la
    sauvegarde finale part quand même.
    """
    monkeypatch.setattr(s3_sync, "get_settings",
                        lambda: SimpleNamespace(**{**vars(_settings(coffre)),
                                                   "vault_s3_sync_interval": 300}))
    observe = {}

    async def scenario():
        await s3_sync.start_periodic_sync()
        ancienne = s3_sync._sync_task

        arret = asyncio.create_task(s3_sync.stop_periodic_sync())
        # Borné : sans boucle réveillable, l'attente durerait l'intervalle
        # entier et ce test figerait au lieu d'échouer.
        await asyncio.wait_for(ancienne, 2)

        # FENÊTRE : la tâche drainée est terminée, l'arrêt n'a pas repris la
        # main. Un démarrage ici doit être REFUSÉ.
        await s3_sync.start_periodic_sync()
        observe["aucune_nouvelle_boucle"] = s3_sync._sync_task is ancienne

        observe["drainee"] = await arret
        observe["reference_liberee"] = s3_sync._sync_task is None

        # Le verrou est DÉFINITIF : même après le retour de l'arrêt, plus
        # aucune boucle ne démarre. C'est ce qui protège la suite de la
        # séquence (seal, puis sauvegarde finale).
        await s3_sync.start_periodic_sync()
        observe["toujours_ferme_apres"] = s3_sync._sync_task is None

    asyncio.run(scenario())

    assert observe["aucune_nouvelle_boucle"] is True, (
        "une boucle de sync a été créée PENDANT un drainage : l'arrêt va "
        "conclure « drainé » et autoriser la sauvegarde finale alors que cette "
        "boucle peut encore écrire"
    )
    assert observe["drainee"] is True
    assert observe["reference_liberee"] is True
    assert observe["toujours_ferme_apres"] is True, (
        "une boucle a démarré APRÈS le retour de l'arrêt : elle vivrait pendant "
        "le seal et la sauvegarde finale, sans avoir été drainée"
    )


def test_un_nouveau_cycle_de_vie_rouvre_la_sync(coffre, monkeypatch):
    """
    Le verrou d'arrêt ne doit pas casser un scénario supporté : un même
    processus peut enchaîner deux lifespans (embedding ASGI, redémarrage à
    chaud), et `vault_startup()` réarme déjà l'idempotence de l'arrêt pour
    cette raison. Sans réouverture, la sync du SECOND coffre ne démarrerait
    jamais — silencieusement.

    Le test prouve le CÂBLAGE, pas seulement l'existence de la fonction : il
    interrompt `vault_startup()` juste après le point de réouverture et vérifie
    que le verrou est déjà retombé.
    """
    from mcp_vault import lifecycle as vault_lifecycle

    class _Sentinelle(Exception):
        pass

    def _interrompre():
        raise _Sentinelle

    monkeypatch.setattr(vault_lifecycle, "get_settings", _interrompre)
    s3_sync._sync_task = None
    s3_sync._sync_closed = True  # état laissé par un arrêt précédent

    with pytest.raises(_Sentinelle):
        asyncio.run(vault_lifecycle.vault_startup())

    assert s3_sync._sync_closed is False, (
        "un nouveau cycle de vie n'a pas rouvert la sync : le second coffre "
        "tournerait sans aucune sauvegarde périodique, sans erreur visible"
    )


def test_un_demarrage_pendant_un_arret_en_cours_est_refuse(coffre, monkeypatch):
    """
    Le verrou d'arrêt pouvait être contourné par l'autre bout.

    L'arrêt draine la sync, libère sa référence, puis poursuit — seal, puis
    sauvegarde finale — en rendant la main. Un `vault_startup()` qui s'exécute
    dans cette fenêtre voyait `_sync_task` à `None`, rouvrait donc le verrou, et
    créait une boucle que l'arrêt en cours ne connaît pas et ne drainera jamais :
    libre de publier un instantané ANTÉRIEUR après la sauvegarde finale.

    Le test exerce les deux VRAIS points d'entrée, en concurrence réelle.
    """
    from mcp_vault import lifecycle as vault_lifecycle
    from mcp_vault.lifecycle import _reset_shutdown_state_for_tests
    from mcp_vault.openbao import lifecycle as ob_lifecycle
    from mcp_vault.openbao import manager as ob_manager

    _reset_shutdown_state_for_tests()
    monkeypatch.setattr(s3_sync, "_put_archive_blocking", lambda *a: None)
    monkeypatch.setattr(ob_lifecycle, "clear_in_memory_keys", lambda: None)
    monkeypatch.setattr(ob_manager, "stop_openbao", AsyncMock())
    observe = {}

    async def scenario():
        dans_le_seal = asyncio.Event()
        liberer = asyncio.Event()

        async def seal_bloquant():
            dans_le_seal.set()
            await liberer.wait()
            return {"status": "sealed"}

        monkeypatch.setattr(ob_lifecycle, "seal_vault", seal_bloquant)

        arret = asyncio.create_task(vault_lifecycle.vault_shutdown())
        await dans_le_seal.wait()  # arrêt EN COURS, entre drainage et sauvegarde

        observe["demarrage"] = await vault_lifecycle.vault_startup()
        observe["verrou_maintenu"] = s3_sync._sync_closed
        observe["aucune_boucle"] = s3_sync._sync_task is None

        liberer.set()
        await arret

    try:
        asyncio.run(scenario())
    finally:
        _reset_shutdown_state_for_tests()

    assert observe["demarrage"] is False, (
        "un coffre a démarré pendant un arrêt en cours"
    )
    assert observe["verrou_maintenu"] is True, (
        "le verrou de sync a été rouvert pendant un arrêt en cours"
    )
    assert observe["aucune_boucle"] is True, (
        "une boucle de sync a été créée pendant un arrêt en cours : cet arrêt "
        "ne la drainera jamais"
    )


def test_un_nouveau_cycle_est_refuse_si_une_boucle_precedente_vit_encore(coffre, monkeypatch):
    """
    Au VRAI point d'entrée, pas sur la fonction isolée.

    Si une boucle du cycle précédent n'a pas été drainée, elle peut encore
    écrire sur S3. Démarrer un nouveau coffre la laisserait publier son
    instantané ANTÉRIEUR par-dessus les écritures du nouveau cycle — lequel
    n'aurait même pas de sync périodique pour rattraper, le verrou restant posé.

    Le test prouve que le démarrage s'arrête AVANT tout le reste : rien après le
    point de refus n'est atteint.
    """
    from mcp_vault import lifecycle as vault_lifecycle

    atteint = []
    monkeypatch.setattr(vault_lifecycle, "get_settings",
                        lambda: atteint.append("suite du démarrage") or _settings(coffre))
    observe = {}

    async def scenario():
        vivante = asyncio.create_task(asyncio.sleep(0.3))
        s3_sync._sync_task = vivante
        s3_sync._sync_closed = True

        observe["demarrage"] = await vault_lifecycle.vault_startup()

        vivante.cancel()
        try:
            await vivante
        except asyncio.CancelledError:
            pass

    asyncio.run(scenario())

    assert observe["demarrage"] is False, (
        "le coffre a démarré alors qu'une boucle du cycle précédent peut "
        "encore écrire sur S3"
    )
    assert atteint == [], (
        "le démarrage a poursuivi au-delà du refus : OpenBao aurait été relancé"
    )


def test_une_boucle_non_drainee_empeche_la_reouverture(coffre):
    """
    La réouverture n'est pas inconditionnelle. Si la boucle du cycle précédent
    n'a pas été drainée, elle peut encore écrire sur S3 : lui superposer une
    nouvelle boucle la rendrait invisible de l'arrêt suivant.
    """
    observe = {}

    async def scenario():
        vivante = asyncio.create_task(asyncio.sleep(0.3))
        s3_sync._sync_task = vivante
        s3_sync._sync_closed = True

        observe["rouverte"] = s3_sync.reopen_periodic_sync()
        observe["verrou_maintenu"] = s3_sync._sync_closed

        vivante.cancel()
        try:
            await vivante
        except asyncio.CancelledError:
            pass

    asyncio.run(scenario())

    assert observe["rouverte"] is False
    assert observe["verrou_maintenu"] is True, (
        "la sync a été rouverte alors qu'une boucle non drainée vit encore"
    )


def test_deux_demarrages_sans_arret_ne_creent_qu_une_boucle(coffre, monkeypatch):
    """
    Cas distinct du verrou définitif : ici aucun arrêt n'a eu lieu, donc
    `_sync_closed` est faux et ne protège rien. C'est la garde de démarrage qui
    doit empêcher une seconde boucle de se superposer à une première encore
    vivante — sinon deux boucles ticquent en parallèle, et l'arrêt n'en drainera
    qu'une.

    (Protection découverte NON COUVERTE par la mesure de mutation : la retirer
    ne faisait tomber aucun test, le verrou définitif masquant le cas dans tous
    les autres scénarios.)
    """
    monkeypatch.setattr(s3_sync, "get_settings",
                        lambda: SimpleNamespace(**{**vars(_settings(coffre)),
                                                   "vault_s3_sync_interval": 300}))
    observe = {}

    async def scenario():
        await s3_sync.start_periodic_sync()
        premiere = s3_sync._sync_task
        await s3_sync.start_periodic_sync()          # aucun arrêt entre les deux
        observe["une_seule_boucle"] = s3_sync._sync_task is premiere
        observe["premiere_vivante"] = not premiere.done()
        await s3_sync.stop_periodic_sync()

    asyncio.run(scenario())

    assert observe["premiere_vivante"] is True
    assert observe["une_seule_boucle"] is True, (
        "un second démarrage a créé une boucle par-dessus une première encore "
        "vivante : deux boucles ticquent en parallèle et l'arrêt n'en drainera "
        "qu'une"
    )


def test_aucune_boucle_ne_demarre_pendant_la_sequence_d_arret(coffre, monkeypatch):
    """
    La fenêtre que le drainage seul ne protège pas — exercée sur la VRAIE
    séquence `vault_shutdown()`, pas sur `stop_periodic_sync()` isolé.

    L'arrêt du coffre ne s'achève pas avec le drainage : viennent ensuite le
    seal PUIS la sauvegarde finale, deux `await` qui rendent la main à la
    boucle d'événements. Une boucle de sync démarrée là serait invisible de
    l'arrêt et pourrait écrire APRÈS la sauvegarde dite finale.
    """
    from mcp_vault.lifecycle import vault_shutdown, _reset_shutdown_state_for_tests
    from mcp_vault.openbao import lifecycle as ob_lifecycle
    from mcp_vault.openbao import manager as ob_manager

    _reset_shutdown_state_for_tests()
    monkeypatch.setattr(s3_sync, "get_settings", lambda: _settings(coffre))
    monkeypatch.setattr(s3_sync, "_put_archive_blocking", lambda *a: None)
    observe = {}

    async def seal_puis_tenter_un_demarrage():
        # Exactement la fenêtre : drainage terminé, sauvegarde finale à venir.
        await s3_sync.start_periodic_sync()
        observe["boucle_creee_pendant_l_arret"] = s3_sync._sync_task is not None
        return {"status": "sealed"}

    monkeypatch.setattr(ob_lifecycle, "seal_vault", seal_puis_tenter_un_demarrage)
    monkeypatch.setattr(ob_lifecycle, "clear_in_memory_keys", lambda: None)
    monkeypatch.setattr(ob_manager, "stop_openbao", AsyncMock())

    try:
        asyncio.run(vault_shutdown())
    finally:
        _reset_shutdown_state_for_tests()

    assert observe["boucle_creee_pendant_l_arret"] is False, (
        "une boucle de sync a démarré pendant la séquence d'arrêt, entre le "
        "drainage et la sauvegarde finale : elle n'a jamais été drainée et "
        "peut écrire après cette sauvegarde"
    )


def test_un_redemarrage_pendant_le_drainage_ne_perd_pas_sa_reference(coffre, monkeypatch):
    """
    DÉFENSE INTERNE, pas un scénario atteignable. Depuis l'ajout du verrou
    `_sync_closed`, plus aucun démarrage ne peut s'intercaler pendant un
    drainage — la course d'origine est fermée en amont.

    Ce test vérifie la SECONDE barrière : le nettoyage ne libère que la tâche
    qu'il a effectivement drainée. La correction ne repose donc pas sur la seule
    justesse du verrou. On installe ici la situation à la main, précisément
    parce qu'elle n'est plus produisible autrement.
    """
    monkeypatch.setattr(s3_sync, "get_settings",
                        lambda: SimpleNamespace(**{**vars(_settings(coffre)),
                                                   "vault_s3_sync_interval": 300}))
    observe = {}

    async def scenario():
        await s3_sync.start_periodic_sync()
        ancienne = s3_sync._sync_task

        arret = asyncio.create_task(s3_sync.stop_periodic_sync())
        # Borné : si la boucle cessait d'être réveillable, l'ancienne tâche
        # attendrait l'intervalle entier (300 s) et ce test FIGERAIT au lieu
        # d'échouer — un test qui fige ne rapporte rien.
        await asyncio.wait_for(ancienne, 2)

        # FENÊTRE DE COURSE : on installe la nouvelle boucle avant que
        # `stop_periodic_sync()` ne reprenne la main pour son nettoyage.
        nouvelle = asyncio.create_task(asyncio.sleep(0.2))
        s3_sync._sync_task = nouvelle
        s3_sync._sync_stop_event = asyncio.Event()

        observe["drainee"] = await arret
        observe["reference_preservee"] = s3_sync._sync_task is nouvelle

        nouvelle.cancel()
        try:
            await nouvelle
        except asyncio.CancelledError:
            pass

    asyncio.run(scenario())

    assert observe["drainee"] is True
    assert observe["reference_preservee"] is True, (
        "le nettoyage a effacé la référence d'une boucle qu'il n'avait PAS "
        "drainée : cette boucle vit désormais sans être traçable"
    )


def test_une_boucle_non_drainee_interdit_d_en_demarrer_une_seconde(coffre, monkeypatch):
    """
    Le pire scénario du drainage. Si l'on perdait la référence à une boucle non
    drainée, un redémarrage de la sync créerait une SECONDE boucle par-dessus.
    L'arrêt suivant ne connaîtrait que la nouvelle, la drainerait avec succès —
    et autoriserait l'upload final pendant que l'ancienne écrit encore sur S3.
    """
    barriere = Barriere(retour=None)
    monkeypatch.setattr(s3_sync, "_put_archive_blocking", barriere)
    monkeypatch.setattr(s3_sync, "_DRAIN_BUDGET_SECONDS", 0.05)
    monkeypatch.setattr(s3_sync, "get_settings",
                        lambda: SimpleNamespace(**{**vars(_settings(coffre)),
                                                   "vault_s3_sync_interval": 1}))
    observe = {}

    async def scenario():
        await s3_sync.start_periodic_sync()
        ancienne = s3_sync._sync_task
        while not barriere.entree.is_set():
            await asyncio.sleep(0.001)

        observe["premier_drainage"] = await s3_sync.stop_periodic_sync()
        observe["reference_conservee"] = s3_sync._sync_task is ancienne

        # Tentative de redémarrage alors que l'ancienne boucle vit encore.
        await s3_sync.start_periodic_sync()
        observe["pas_de_seconde_boucle"] = s3_sync._sync_task is ancienne

        barriere.temoin_a_progresse = True
        barriere.liberation.set()
        await asyncio.sleep(0.05)
        # Un arrêt ultérieur ré-attend LA MÊME tâche, avec un budget neuf.
        observe["second_drainage"] = await s3_sync.stop_periodic_sync()
        observe["reference_liberee"] = s3_sync._sync_task is None

    asyncio.run(scenario())

    assert observe["premier_drainage"] is False
    assert observe["reference_conservee"] is True, (
        "la référence à une boucle non drainée a été perdue : plus rien ne "
        "sait qu'un travail peut encore écrire sur S3"
    )
    assert observe["pas_de_seconde_boucle"] is True, (
        "une SECONDE boucle de sync a été créée par-dessus une boucle non "
        "drainée — le prochain arrêt croirait tout drainé"
    )
    assert observe["second_drainage"] is True
    assert observe["reference_liberee"] is True
