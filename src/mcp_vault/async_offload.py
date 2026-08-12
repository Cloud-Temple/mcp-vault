# -*- coding: utf-8 -*-
"""
Offload d'appels bloquants hors de la boucle d'événements (issue #122, lot 2 de #110).

Les appels S3 (boto3) sont SYNCHRONES. Exécutés directement dans la boucle
asyncio, ils monopolisent l'unique thread qui sert TOUTES les requêtes : un S3
lent gèle le service entier, sonde de santé comprise (incident #110, 488 s
mesurées). Le lot 1 (v0.10.1) a borné la durée de ces appels ; ce module fournit
la primitive qui les sort de la boucle.

⚠️ PORTÉE. Le lot 2 n'applique cette primitive qu'à CINQ points d'appel :
sauvegarde (archive + envoi), restauration au démarrage, sonde de connectivité,
PUT et GET des clés chiffrées d'OpenBao. Les magasins d'autorisation
(`TokenStore`, `PolicyStore`, `MissionBindingStore`, `WrapRegistry`) appellent
TOUJOURS S3 de façon synchrone dans la boucle : **un stockage lent sur ces
chemins peut encore geler le service**, jusqu'au lot 3 (issue #123). Ce module
ne garantit rien pour ce qui ne l'appelle pas.

## Pourquoi pas simplement `await asyncio.to_thread(...)`

Parce que l'offload doit cohabiter avec un VERROU de sérialisation : la section
critique lit un état module, travaille, puis récrit cet état. Le verrou ne doit
JAMAIS être relâché tant que le thread écrit encore sur S3 — sinon deux PUT
concurrents se marchent dessus et l'archive publiée n'est plus celle dont on a
enregistré l'empreinte.

Or, une attente asyncio peut être ANNULÉE. Trois pièges, tous vérifiés
expérimentalement plutôt que déduits :

1. **`await asyncio.shield(task)` rend la main à l'annulation.** L'annulation de
   l'attente ne touche pas le travailleur, mais l'appelant sort — donc le
   `async with lock` se termine — alors que le thread continue. Le verrou est
   perdu au pire moment.

2. **`task.done()` / `task.cancelled()` ne prouvent PAS la fin du thread.**
   Annuler la tâche asyncio qui enveloppe un travail en thread n'interrompt pas
   le thread : `to_thread` ne peut pas préempter du code Python bloquant. La
   tâche est « annulée », le PUT continue.

3. **Une `Task` autour de `to_thread` est annulée par le teardown d'`asyncio.run`.**
   `_cancel_all_tasks()` annule TOUTE tâche pendante — `shield` ne protège que
   de l'annulation propagée par l'awaiter, pas d'un `cancel()` direct sur la
   tâche interne. La tâche passe alors « cancelled » pendant que le thread
   tourne, `await shield(task)` relève `CancelledError` IMMÉDIATEMENT à chaque
   tour, et la boucle d'attente part en rotation à vide. Mesuré sur ce piège
   précis : **1 411 649 tours en 0,5 s**.

D'où la forme retenue :

- le travailleur est un **`Future` de `loop.run_in_executor`**, pas une `Task` —
  un `Future` n'apparaît pas dans `asyncio.all_tasks()` et échappe donc au
  teardown (vérifié : `all_tasks()` ne le contient pas, 0 tour de boucle) ;
- la preuve de fin est un **`threading.Event` posé dans le `finally` du wrapper
  SYNCHRONE**, c'est-à-dire depuis le thread lui-même — la seule primitive qui
  observe la fin réelle du travail ;
- l'annulation est **mémorisée puis re-levée APRÈS** la fin du thread, jamais
  avant : l'appelant ne reprend pas la main tant que le travail n'est pas fini,
  et il apprend quand même qu'il a été annulé.

## Ce que ce module ne garantit pas

L'attente n'est PAS bornée par un compteur. Une borne qui rend la main
relâcherait le verrou avec un thread encore actif — c'est-à-dire violerait
exactement l'invariant qu'elle prétendrait protéger. Ce qui termine l'attente,
c'est la fin du thread.

Cette fin n'est donc garantie que si `fn` se termine. Les appels RÉSEAU sont
bornés par le lot 1 (`total_max_attempts`, `connect_timeout`, `read_timeout` —
fabrique unique dans `s3_client._build_config`), mais **ce n'est pas vrai de
tout ce qui est offloadé ici** : la construction de l'archive (parcours disque
et compression) et la dérivation PBKDF2 n'ont aucune borne propre, pas plus que
l'attente d'un worker libre dans l'exécuteur. Un `fn` qui ne rendrait jamais la
main bloquerait cette attente indéfiniment — par construction, et c'est le
choix assumé face à l'alternative (relâcher le verrou sur une écriture en vol).
"""

import asyncio
import contextvars
import logging
import threading
from typing import Any, Callable

logger = logging.getLogger("mcp-vault.offload")


async def run_blocking(fn: Callable[..., Any], *args: Any) -> Any:
    """
    Exécute `fn(*args)` dans un thread et n'en revient QUE lorsque le thread est
    réellement terminé — y compris si l'attente est annulée entre-temps.

    Récolte explicite, dans cet ordre de priorité :
        1. exception métier levée par `fn` (ne doit jamais être masquée) ;
        2. annulation mémorisée pendant l'attente (re-levée telle quelle) ;
        3. valeur de retour.

    L'ordre compte : une annulation qui masquerait une erreur d'upload ferait
    passer un échec S3 pour un simple arrêt.
    """
    done = threading.Event()
    box: dict[str, Any] = {}

    def _wrapper() -> None:
        try:
            box["result"] = fn(*args)
        except BaseException as exc:  # noqa: BLE001 — récolté et re-levé à l'identique
            box["error"] = exc
        finally:
            # Posé DEPUIS LE THREAD, dans un `finally` : c'est la seule
            # observation fiable de la fin réelle du travail. Ni `task.done()`
            # ni `future.done()` ne prouvent que le thread est sorti.
            done.set()

    loop = asyncio.get_running_loop()
    # `copy_context()` reproduit ce que fait `asyncio.to_thread` : sans lui, le
    # code appelé perdrait les contextvars du contexte appelant — un changement
    # de comportement silencieux par rapport à l'existant.
    ctx = contextvars.copy_context()
    future = loop.run_in_executor(None, lambda: ctx.run(_wrapper))

    cancelled: BaseException | None = None
    while not done.is_set():
        try:
            # `shield` : l'annulation de CETTE attente ne doit pas se propager
            # au travailleur. Et comme `future` n'est pas une `Task`, le
            # teardown de la boucle ne l'annule pas non plus — sans quoi chaque
            # tour relèverait immédiatement et la boucle tournerait à vide.
            await asyncio.shield(future)
        except asyncio.CancelledError as exc:
            if cancelled is None:
                cancelled = exc
        except BaseException:  # noqa: BLE001
            # Le wrapper capture TOUT ce que lève `fn` : si le futur porte
            # malgré tout une exception, c'est que le wrapper n'a jamais
            # tourné (exécuteur arrêté, par exemple). `done` ne sera alors
            # JAMAIS posé — il faut sortir, sinon la boucle tourne à vide.
            if not done.is_set():
                logger.error("Le travail offloadé n'a pas démarré")
                raise

    if "error" in box:
        raise box["error"]
    if cancelled is not None:
        raise cancelled
    return box.get("result")
