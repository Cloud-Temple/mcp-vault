# -*- coding: utf-8 -*-
"""
OpenBao Process Manager — Gestion du processus OpenBao embedded.

Responsabilités :
    - Démarrer le serveur OpenBao (`bao server -config=...`)
    - Arrêter proprement (SIGTERM)
    - Vérifier l'état de santé (health check localhost:8200)
    - Fournir le client hvac pré-configuré
"""

import asyncio
import logging
import subprocess
import sys
import weakref
from pathlib import Path
from typing import Any, NamedTuple, Optional

import hvac

from ..async_offload import run_blocking
from ..config import get_settings

logger = logging.getLogger("mcp-vault.openbao")


def _openbao_log_paths() -> tuple[Path, Path]:
    settings = get_settings()
    log_dir = Path(settings.openbao_data_dir).parent / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir / "openbao-stdout.log", log_dir / "openbao-stderr.log"


def _read_process_tail(path: Path, lines: int = 20) -> str:
    try:
        if not path.exists():
            return ""
        content = path.read_text(errors="replace").splitlines()
        return "\n".join(content[-lines:])
    except Exception:
        return ""

# =============================================================================
# Singleton — processus OpenBao et client hvac
# =============================================================================

_process: Optional[subprocess.Popen] = None
_client: Optional[hvac.Client] = None


def get_hvac_client() -> Optional[hvac.Client]:
    """Retourne le client hvac connecté à OpenBao (None si pas démarré)."""
    return _client


def set_hvac_client(client: hvac.Client):
    """
    Remplace le client hvac singleton.

    Utilisé par lifecycle.unseal_vault() après avoir configuré le root token.
    """
    global _client
    _client = client


async def _is_openbao_reachable() -> bool:
    settings = get_settings()
    import httpx
    try:
        async with httpx.AsyncClient(timeout=2) as http:
            resp = await http.get(f"{settings.openbao_addr}/v1/sys/health")
            return resp.status_code in (200, 501, 503)
    except Exception:
        return False


async def start_openbao() -> bool:
    """
    Démarre le serveur OpenBao en arrière-plan.

    1. Génère la config HCL si absente
    2. Lance `bao server -config=/openbao/config/server.hcl`
    3. Attend que le serveur soit prêt (health check)

    Returns:
        True si démarré avec succès
    """
    global _process, _client
    settings = get_settings()

    if await _is_openbao_reachable():
        logger.info("♻️ OpenBao déjà joignable — réutilisation de l'instance existante")
        _client = hvac.Client(url=settings.openbao_addr)
        return True

    from .config import generate_hcl_config
    config_path = generate_hcl_config()

    logger.info("🚀 Démarrage d'OpenBao...")
    try:
        stdout_log, stderr_log = _openbao_log_paths()
        stdout_fh = open(stdout_log, "ab", buffering=0)
        stderr_fh = open(stderr_log, "ab", buffering=0)
        _process = subprocess.Popen(
            ["bao", "server", f"-config={config_path}"],
            stdout=stdout_fh,
            stderr=stderr_fh,
        )
    except FileNotFoundError:
        logger.error("❌ Binaire 'bao' non trouvé. OpenBao n'est pas installé.")
        return False

    # Attendre que le serveur soit accessible (même sealed/uninitialized)
    # OpenBao retourne 200 (ready), 501 (not initialized) ou 503 (sealed)
    # On veut juste qu'il écoute — l'init et l'unseal viennent après.
    import httpx

    for attempt in range(30):  # 30 secondes max
        await asyncio.sleep(1)

        if _process.poll() is not None:
            _, stderr_log = _openbao_log_paths()
            tail = _read_process_tail(stderr_log, lines=40)
            logger.error("❌ OpenBao s'est arrêté prématurément")
            if tail:
                logger.error(f"Dernières lignes stderr bao:\n{tail}")
            return False

        try:
            async with httpx.AsyncClient(timeout=2) as http:
                resp = await http.get(f"{settings.openbao_addr}/v1/sys/health")
                logger.info(
                    f"✅ OpenBao écoute (HTTP {resp.status_code}, tentative {attempt + 1})"
                )
                _client = hvac.Client(url=settings.openbao_addr)
                return True
        except Exception:
            pass

    _, stderr_log = _openbao_log_paths()
    tail = _read_process_tail(stderr_log, lines=40)
    logger.error("❌ OpenBao n'a pas démarré dans les 30 secondes")
    if tail:
        logger.error(f"Dernières lignes stderr bao:\n{tail}")
    return False


async def stop_openbao():
    """Arrête proprement le processus OpenBao."""
    global _process, _client

    if _process and _process.poll() is None:
        logger.info("🛑 Arrêt d'OpenBao...")
        _process.terminate()
        try:
            _process.wait(timeout=10)
            logger.info("✅ OpenBao arrêté proprement")
        except subprocess.TimeoutExpired:
            logger.warning("⚠️ OpenBao ne répond pas, kill forcé")
            _process.kill()
            _process.wait()

    _process = None
    _client = None


def is_running() -> bool:
    """Vérifie si le processus OpenBao tourne."""
    return _process is not None and _process.poll() is None


class OpenBaoProbe(NamedTuple):
    """
    Résultat d'une sonde OpenBao (issue #103).

    `sealed` est un état À PART ENTIÈRE, pas un cas particulier de `not ok` :
    « joignable mais scellé » est l'information que l'exploitation doit pouvoir
    lire de l'extérieur, alors que `not ok` seul ne dit pas quoi faire.

    ⚠️ `detail` est un texte de DIAGNOSTIC. Il alimente les surfaces
    AUTHENTIFIÉES (`system_health`, `/admin/api/health`) et les journaux ; il ne
    doit jamais atteindre une réponse publique non authentifiée — c'est
    précisément la famille de divulgation fermée par #116.
    """
    ok: bool       # joignable, initialisé ET descellé
    sealed: bool   # joignable MAIS scellé
    detail: str


# État de sonde attaché à la boucle d'événements courante. Un `asyncio.Lock` de
# module se lie à la première boucle qui le met en contention et lève ensuite
# « bound to a different event loop » (piège mesuré au lot 2 de #110).
_probe_loop_state: "weakref.WeakKeyDictionary[Any, dict]" = weakref.WeakKeyDictionary()


def _probe_state_for_loop() -> dict:
    """Verrou et tâche de sonde partagée, attachés à la boucle courante."""
    loop = asyncio.get_running_loop()
    state = _probe_loop_state.get(loop)
    if state is None:
        state = {"probe_lock": asyncio.Lock(), "probe_task": None}
        _probe_loop_state[loop] = state
    return state


def _probe_openbao_blocking(settings) -> OpenBaoProbe:
    """
    Interroge `/sys/health`. BLOQUANT (hvac est synchrone) — destiné à
    `run_blocking`. Ne lève JAMAIS.

    Le `timeout` est OBLIGATOIRE et non négociable : `run_blocking` documente
    explicitement que son attente n'est PAS bornée et ne se termine qu'avec le
    thread. Sans borne côté hvac, un OpenBao qui accepte la connexion sans
    répondre immobiliserait un thread de l'exécuteur — depuis un endpoint
    public et non authentifié.
    """
    try:
        client = hvac.Client(url=settings.openbao_addr,
                             timeout=settings.openbao_health_timeout)
        status = client.sys.read_health_status(method="GET")
        if not isinstance(status, dict):
            # Une réponse inexploitable ne PROUVE PAS « initialisé et descellé ».
            # Le code d'origine la promouvait en « accessible », donc en sain :
            # c'est la même complaisance que le littéral `healthy` corrigé ici,
            # et elle contredit le prédicat. Fail-close.
            return OpenBaoProbe(False, False,
                                "OpenBao : réponse de santé inexploitable")
        sealed = status.get("sealed")
        initialized = status.get("initialized")
        if sealed is True:
            # `sealed` est un état PUBLIC et ACTIONNABLE depuis #103 : il ne
            # s'affirme que s'il a été explicitement CONSTATÉ. Le déduire d'une
            # valeur par défaut ferait annoncer « descellez-moi » sur une
            # réponse qui ne le dit pas.
            return OpenBaoProbe(False, True, "OpenBao est scellé (sealed)")
        if sealed is not False or initialized is not True:
            # Réponse incomplète : elle ne prouve NI le scellement NI
            # l'utilisabilité. Fail-close, sans usurper l'état `sealed`.
            return OpenBaoProbe(False, False, "OpenBao : état de santé incomplet")
        return OpenBaoProbe(True, False, "OpenBao OK (unsealed, initialized)")
    except Exception as e:  # noqa: BLE001 — une sonde ne propage pas ses pannes
        return OpenBaoProbe(False, False, f"OpenBao inaccessible: {type(e).__name__}")


async def _probe_openbao(settings) -> OpenBaoProbe:
    """
    Sonde partagée. Ne lève JAMAIS : elle est attendue par N appelants, et une
    exception qui remonterait les frapperait tous — en plus de produire un
    « Task exception never retrieved » si plus personne n'attend.
    """
    try:
        return await run_blocking(_probe_openbao_blocking, settings)
    except Exception as e:  # noqa: BLE001
        return OpenBaoProbe(False, False, f"OpenBao inaccessible: {type(e).__name__}")


async def probe_openbao() -> OpenBaoProbe:
    """
    Sonde OpenBao — SINGLE-FLIGHT et BORNÉE (issue #103).

    `/health` est public et non authentifié : chaque requête déclenchait
    auparavant son propre appel hvac SYNCHRONE dans la boucle d'événements. Une
    rafale — ou un simple OpenBao lent — gelait le service par l'endpoint censé
    signaler qu'il va mal.

    Une seule sonde réelle est en vol à la fois ; les appelants suivants s'y
    raccrochent. Chacun attend avec sa PROPRE échéance, et cette échéance
    n'annule PAS la sonde partagée : `wait_for` annule le `shield`, jamais la
    tâche derrière.

    PAS de cache de résultat. Un cache permettrait de répondre « disponible »
    APRÈS la panne — une régression de contrat déguisée en optimisation, déjà
    refusée en revue au lot 2 de #110. Le prix est un appel par requête
    séquentielle ; il est borné par `openbao_health_timeout`.

    ⚠️ RISQUE RÉSIDUEL, à ne pas surévaluer. L'échéance rend la main à l'APPELANT,
    elle n'interrompt pas le thread : `run_blocking` ne se termine qu'avec lui.
    Une sonde en vol peut donc retarder la fermeture de la boucle d'événements à
    l'arrêt (`shutdown_default_executor` attend l'exécuteur). Avec le défaut de
    2 s c'est négligeable devant le délai de grâce, mais ce n'est PAS une borne
    stricte : le `timeout` hvac couvre la connexion et la lecture, pas une
    résolution DNS pathologique ni l'attente d'un worker libre. Le single-flight
    borne l'exposition à UNE sonde en vol, quelle que soit la charge.
    """
    settings = get_settings()
    state = _probe_state_for_loop()
    async with state["probe_lock"]:
        task = state["probe_task"]
        if task is None or task.done():
            task = asyncio.create_task(_probe_openbao(settings))
            state["probe_task"] = task

    try:
        return await asyncio.wait_for(asyncio.shield(task),
                                      settings.openbao_health_timeout)
    except asyncio.TimeoutError:
        # Seule `TimeoutError` est capturée : une annulation de L'APPELANT doit
        # se propager normalement (ce n'est pas un résultat de sonde).
        return OpenBaoProbe(False, False,
                            "OpenBao inaccessible: sonde en cours (délai dépassé)")


async def health_check() -> tuple[bool, str]:
    """
    Vérifie l'état de santé d'OpenBao.

    Conservé pour les appelants existants (`get_vault_status`, `system_health`),
    qui attendent `(ok, detail)`. Les appelants ayant besoin de distinguer
    « scellé » d'« injoignable » utilisent `probe_openbao()`.

    Returns:
        (ok, detail) — True si accessible, avec un message de détail
    """
    result = await probe_openbao()
    return result.ok, result.detail
