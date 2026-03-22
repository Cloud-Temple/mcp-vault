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
from pathlib import Path
from typing import Optional

import hvac

from ..config import get_settings

logger = logging.getLogger("mcp-vault.openbao")

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

    # Générer la config HCL
    from .config import generate_hcl_config
    config_path = generate_hcl_config()

    # Lancer le processus
    logger.info("🚀 Démarrage d'OpenBao...")
    try:
        _process = subprocess.Popen(
            ["bao", "server", f"-config={config_path}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
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
        try:
            async with httpx.AsyncClient(timeout=2) as http:
                resp = await http.get(f"{settings.openbao_addr}/v1/sys/health")
                # Toute réponse HTTP (200, 501, 503) = OpenBao écoute
                logger.info(
                    f"✅ OpenBao écoute (HTTP {resp.status_code}, tentative {attempt + 1})"
                )
                _client = hvac.Client(url=settings.openbao_addr)
                return True
        except Exception:
            pass

    logger.error("❌ OpenBao n'a pas démarré dans les 30 secondes")
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


async def health_check() -> tuple[bool, str]:
    """
    Vérifie l'état de santé d'OpenBao.

    Returns:
        (ok, detail) — True si accessible, avec un message de détail
    """
    settings = get_settings()
    try:
        client = hvac.Client(url=settings.openbao_addr)
        status = client.sys.read_health_status(method="GET")
        if isinstance(status, dict):
            sealed = status.get("sealed", True)
            initialized = status.get("initialized", False)
            if sealed:
                return False, "OpenBao est scellé (sealed)"
            if not initialized:
                return False, "OpenBao non initialisé"
            return True, "OpenBao OK (unsealed, initialized)"
        return True, "OpenBao accessible"
    except Exception as e:
        return False, f"OpenBao inaccessible: {e}"
