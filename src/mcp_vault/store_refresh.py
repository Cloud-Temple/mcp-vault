# -*- coding: utf-8 -*-
"""
Fraîcheur et rafraîchissement de fond des magasins (issue #123, lot 3 de #110).

Le lot 1 (v0.10.1) a borné la durée des appels S3 ; le lot 2 (#122) a fourni
`async_offload.run_blocking` et l'a appliqué à cinq points d'appel. Restaient les
**magasins d'autorisation**, qui appelaient encore S3 de façon SYNCHRONE depuis
la boucle, à l'intérieur de gardes elles-mêmes synchrones : un stockage lent y
gelait le service entier (incident #110, 488 s mesurées).

Ce module porte la règle du lot 3 :

    **Le point de décision lit la mémoire, jamais le réseau.**

## Les deux horloges, et pourquoi il en fallait deux

Le code historique n'en portait qu'une, `_cache_time`, avec DEUX rôles :
dater l'instantané servi, et brider les re-tentatives après une panne
(`_mark_invalid` la repoussait). Tant que tout va bien, les deux coïncident.
Une panne les met en désaccord : repousser la date pour éviter de marteler S3
rajeunissait aussi, mécaniquement, un instantané qui n'avait pas été rechargé.

`Freshness` les sépare :

- `last_success` — dernier chargement **réussi**. Seul juge de la fraîcheur,
  donc du droit de servir une décision d'autorisation ;
- `last_attempt` — dernière tentative, réussie **ou non**. Seul juge du droit
  de retenter, donc de la charge imposée à S3.

⚠️ **Temps MONOTONE**, jamais l'horloge murale. Un recul d'horloge (NTP, VM
restaurée depuis un instantané) rendrait « frais » un état périmé — c'est-à-dire
ferait servir des autorisations qui auraient dû être refusées. Les expirations
**métier** (`expires_at` d'un bearer ou d'un binding, rétention de purge)
restent en UTC mural : ce sont des dates absolues, pas des durées écoulées.

## Ce que ce module ne fait pas

Il ne remplace pas le fail-close de #86 : un magasin dont l'instantané est
périmé au-delà de son TTL doit refuser, exactement comme le faisait le
chargement en ligne quand S3 était mort. `Freshness` fournit le constat
(`is_stale`), pas la décision — chaque magasin garde la sienne.

Il n'apporte **aucune** garantie multi-instance : le dernier écrivain gagne
toujours (#13/#51), et un rafraîchissement de fond ne fait qu'élargir la fenêtre
pendant laquelle deux instances peuvent diverger sans le savoir.
"""

import asyncio
import logging
import time
from typing import Callable, Optional

from .async_offload import run_blocking

logger = logging.getLogger("mcp-vault.store-refresh")

# Délai de re-tentative après un échec de chargement. Volontairement bien plus
# court que le TTL : entre un échec et la péremption de l'instantané, il faut
# assez de tentatives pour qu'un incident S3 bref reste invisible.
RETRY_AFTER_ERROR_SECONDS = 10.0


class Freshness:
    """
    Les deux horloges d'un magasin, en temps monotone (voir docstring module).

    Un objet neuf est **périmé** : `last_success` vaut `None`, donc `is_stale()`
    rend True quel que soit le TTL. C'est voulu — un magasin qui n'a jamais
    chargé ne doit pas servir de décision d'autorisation au prétexte qu'il vient
    d'être construit.
    """

    __slots__ = ("_last_success", "_last_attempt", "_last_error")

    def __init__(self) -> None:
        self._last_success: Optional[float] = None
        self._last_attempt: Optional[float] = None
        self._last_error: str = ""

    # ── Constats ──────────────────────────────────────────────────────

    def is_stale(self, ttl: float) -> bool:
        """L'instantané publié a-t-il dépassé son TTL ? Jamais chargé = périmé."""
        if self._last_success is None:
            return True
        return (time.monotonic() - self._last_success) > ttl

    def may_retry(self, delay: float) -> bool:
        """A-t-on le droit de retenter un chargement ? Jamais tenté = oui."""
        if self._last_attempt is None:
            return True
        return (time.monotonic() - self._last_attempt) >= delay

    def age(self) -> Optional[float]:
        """Âge de l'instantané publié en secondes, ou None s'il n'y en a pas."""
        if self._last_success is None:
            return None
        return time.monotonic() - self._last_success

    @property
    def last_error(self) -> str:
        return self._last_error

    @property
    def never_loaded(self) -> bool:
        return self._last_success is None

    # ── Transitions ───────────────────────────────────────────────────

    def mark_success(self) -> None:
        """Chargement réussi : les deux horloges avancent, l'erreur est levée."""
        now = time.monotonic()
        self._last_success = now
        self._last_attempt = now
        self._last_error = ""

    def mark_failure(self, error: str) -> None:
        """
        Tentative échouée : SEULE `last_attempt` avance.

        ⚠️ Ne jamais toucher `last_success` ici. C'est précisément la confusion
        que ce module corrige : brider les re-tentatives ne doit pas rajeunir un
        instantané qui n'a pas été rechargé.
        """
        self._last_attempt = time.monotonic()
        self._last_error = error

    def observability(self) -> dict:
        """Vue lisible de l'état, pour la sonde de santé et l'API admin."""
        age = self.age()
        return {
            "age_seconds": None if age is None else round(age, 1),
            "never_loaded": self.never_loaded,
            "last_error": self._last_error,
        }


class StoreRefresher:
    """
    Tâche de fond qui recharge UN magasin hors de la boucle.

    Le magasin doit exposer :
      - `load()`            — chargement synchrone et bloquant (S3) ;
      - `refresh_lock`      — `asyncio.Lock` partagé avec ses mutations ;
      - `freshness`         — l'objet `Freshness` ci-dessus ;
      - `CACHE_TTL`         — durée de validité de l'instantané.

    ⚠️ Le verrou est pris pendant TOUT le chargement, `run_blocking` compris.
    Sans cela, un `load()` tardif peut publier un instantané antérieur à une
    mutation déjà confirmée — la révocation d'un jeton, par exemple, ressuscitée
    par une lecture partie avant elle. `run_blocking` ne rend la main qu'à la fin
    réelle du thread (lot 2), le verrou n'est donc jamais relâché sur un appel
    S3 en vol.

    La cadence nominale est **la moitié du TTL** : un rafraîchissement raté ne
    doit pas suffire à périmer l'instantané. Après un échec, on repasse à
    `RETRY_AFTER_ERROR_SECONDS` pour récupérer vite.
    """

    def __init__(self, name: str, store) -> None:
        self.name = name
        self.store = store
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()

    def _next_delay(self) -> float:
        """Cadence courante : nominale si le dernier chargement a réussi, sinon rapide."""
        if self.store.freshness.last_error:
            return RETRY_AFTER_ERROR_SECONDS
        return max(1.0, self.store.CACHE_TTL / 2)

    async def _refresh_once(self) -> None:
        """Un chargement, sous verrou, hors de la boucle. N'échoue jamais bruyamment."""
        try:
            async with self.store.refresh_lock:
                await run_blocking(self.store.load)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001 — une tâche de fond ne meurt pas sur une erreur
            # `load()` avale déjà ses propres pannes et marque le magasin
            # indisponible. Arriver ici signale autre chose (bug, exécuteur
            # arrêté) : on le journalise sans tuer la boucle de rafraîchissement,
            # sinon le magasin se périmerait en silence jusqu'au fail-close.
            logger.error("Rafraîchissement %s : erreur inattendue %s", self.name, type(e).__name__)

    async def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._next_delay())
                return  # arrêt demandé
            except asyncio.TimeoutError:
                pass
            await self._refresh_once()

    def start(self) -> None:
        """Démarre la tâche. Idempotent."""
        if self._task is not None and not self._task.done():
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._loop(), name=f"refresh-{self.name}")

    async def stop(self) -> None:
        """
        Arrête la tâche et attend sa fin.

        ⚠️ On demande l'arrêt par un `Event` plutôt que par `cancel()`, puis on
        attend : annuler pendant `_refresh_once` sortirait de l'`async with`
        alors que `run_blocking` n'a pas encore rendu la main du thread. Le
        drainage exige que plus aucune écriture ne soit en vol à la sortie.
        """
        if self._task is None:
            return
        self._stop.set()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        finally:
            self._task = None


# =============================================================================
# Orchestration : un rafraîchisseur par magasin, piloté par le lifecycle
# =============================================================================

_refreshers: list[StoreRefresher] = []


def _magasins() -> list[tuple[str, object]]:
    """Les magasins configurés, dans l'ordre où ils sont initialisés au démarrage.

    Imports locaux : `store_refresh` est importé PAR les magasins, un import de
    module créerait un cycle.
    """
    from .auth.mission_bindings import get_mission_binding_store
    from .auth.policies import get_policy_store
    from .auth.token_store import get_token_store
    from .vault.wrapping import get_wrap_registry

    couples = [
        ("token", get_token_store()),
        ("policy", get_policy_store()),
        ("mission_binding", get_mission_binding_store()),
        ("wrap_registry", get_wrap_registry()),
    ]
    # Un magasin absent = S3 non configuré pour lui : rien à rafraîchir.
    return [(n, s) for n, s in couples if s is not None]


def start_store_refreshers() -> list[str]:
    """
    Démarre un rafraîchisseur de fond par magasin configuré.

    À appeler au démarrage, APRÈS l'initialisation des magasins : c'est elle qui
    fait le premier chargement, synchrone et hors trafic. À partir d'ici, plus
    aucun chargement ne doit partir de la boucle.

    Retourne les noms démarrés, pour la trace de démarrage.
    """
    global _refreshers
    if _refreshers:
        return [r.name for r in _refreshers]
    magasins = _magasins()
    # ⚠️ RÉ-OUVRIR les magasins. Un même processus peut enchaîner deux lifespans
    # (ASGI embarqué, redémarrage à chaud) — c'est la raison d'être de
    # `_reset_shutdown_state`. Les singletons de magasin survivent au premier
    # arrêt : sans cette levée, le second démarrage repartirait avec la barrière
    # posée et refuserait TOUTE mutation, définitivement et en silence.
    for _, magasin in magasins:
        setattr(magasin, "_ferme_pour_arret", False)
    _refreshers = [StoreRefresher(nom, magasin) for nom, magasin in magasins]
    for r in _refreshers:
        r.start()
    return [r.name for r in _refreshers]


async def stop_store_refreshers() -> bool:
    """
    Ferme les magasins, arrête les rafraîchisseurs, draine les verrous.

    **Rend True seulement si le drainage est ATTESTÉ.** Un False signifie qu'une
    écriture de MAGASIN peut encore aboutir après cet appel — tokens, policies,
    bindings, registre wrap. L'appelant doit le signaler bruyamment.

    ⚠️ Il ne doit PAS en déduire d'annuler l'archive finale du coffre, à la
    différence du drainage de la sync périodique (#122). Les deux ne protègent
    pas le même objet : l'archive compresse le file backend d'OpenBao
    (`openbao_data_dir`), tandis que les magasins écrivent des objets S3
    DISTINCTS (`_system/tokens.json`, `_system/policies.json`,
    `_system/wrap_registry.json`, `_system/mission_bindings/*`). Une écriture de
    magasin tardive ne peut donc pas figer un état antérieur dans l'archive, et
    y renoncer coûterait une sauvegarde réelle du coffre pour couvrir un risque
    inexistant. Voir la note correspondante dans `lifecycle.py`.

    Trois étapes, dans cet ordre, et l'ordre est le fond du sujet :

    1. **Fermer** — au-delà de ce point, toute mutation est REFUSÉE. Sans cette
       barrière, prendre puis relâcher le verrou ne prouve rien : une mutation
       arrivée pendant le drainage attend simplement son tour et fait son PUT
       *après* l'attestation.
    2. **Arrêter** les rafraîchisseurs — l'inverse laisserait un rafraîchissement
       démarrer pendant le drainage.
    3. **Drainer** les verrous — ne restent alors que les détenteurs entrés avant
       la fermeture, et `run_blocking` garantit que leur thread est terminé.
    """
    global _refreshers
    atteste = True

    magasins = _magasins()
    for _, magasin in magasins:
        setattr(magasin, "_ferme_pour_arret", True)

    encours, _refreshers = _refreshers, []
    for r in encours:
        try:
            await r.stop()
        except Exception as e:  # noqa: BLE001 — on récolte, on n'interrompt pas la séquence
            logger.warning("Arrêt du rafraîchissement %s : %s", r.name, type(e).__name__)
            atteste = False
    for nom, magasin in magasins:
        try:
            await drain_store_lock(nom, magasin)
        except Exception as e:  # noqa: BLE001
            logger.warning("Drainage du magasin %s : %s", nom, type(e).__name__)
            atteste = False
    return atteste


def magasin_ferme(magasin) -> bool:
    """Le magasin refuse-t-il les mutations (arrêt en cours) ?

    Consulté par les façades async AVANT de prendre le verrou : attendre le
    verrou puis écrire ferait atterrir l'écriture après le drainage.
    """
    return getattr(magasin, "_ferme_pour_arret", False)


class MagasinFerme(RuntimeError):
    """Levée par une façade async quand l'arrêt a déjà fermé le magasin."""


def freshness_report() -> dict:
    """Fraîcheur de chaque magasin configuré, pour la sonde et l'API admin.

    Rend visible un rafraîchisseur mort : sans cela, un magasin se périmerait en
    silence et le fail-close ne serait diagnostiqué qu'au premier refus.
    """
    rapport = {}
    for nom, magasin in _magasins():
        fraicheur = getattr(magasin, "freshness", None)
        if fraicheur is None:
            continue
        vue = fraicheur.observability()
        ttl = getattr(magasin, "CACHE_TTL", None)
        vue["stale"] = fraicheur.is_stale(ttl) if ttl else None
        # Métriques propres au magasin, s'il en expose (#146 : volumétrie du
        # registre wrap). Optionnel par construction : un magasin qui n'a rien à
        # dire n'a rien à implémenter.
        metriques = getattr(magasin, "volumetrie", None)
        if callable(metriques):
            vue.update(metriques())
        rapport[nom] = vue
    return rapport


async def drain_store_lock(name: str, store) -> None:
    """
    Attend qu'aucune opération ne soit en vol sur ce magasin.

    Prendre puis relâcher le verrou suffit : il n'est relâché que lorsque le
    thread S3 de son détenteur est réellement terminé (`run_blocking`, lot 2).
    Appelé au drainage d'arrêt, après l'arrêt des rafraîchisseurs.
    """
    lock = getattr(store, "refresh_lock", None)
    if lock is None:
        return
    async with lock:
        pass
    logger.debug("Magasin %s drainé", name)
