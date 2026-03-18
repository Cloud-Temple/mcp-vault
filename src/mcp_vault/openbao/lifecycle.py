# -*- coding: utf-8 -*-
"""
OpenBao Lifecycle — Init, Unseal, Seal.

Gère le cycle de vie complet d'OpenBao :
    1. Init (première fois) — crée les clés et le root token
    2. Unseal — déverrouille avec les clés Shamir
    3. Seal — reverrouille avant arrêt
    4. Status — état courant
"""

import json
import logging
from pathlib import Path
from typing import Optional

import hvac

from ..config import get_settings
from .manager import get_hvac_client

logger = logging.getLogger("mcp-vault.openbao")

# Fichier local stockant les clés d'init (dans le data dir)
_INIT_FILE = "init_keys.json"


def _get_init_path() -> Path:
    """Chemin du fichier de clés d'initialisation."""
    settings = get_settings()
    return Path(settings.openbao_data_dir) / _INIT_FILE


def _load_init_keys() -> Optional[dict]:
    """Charge les clés d'init depuis le fichier local."""
    path = _get_init_path()
    if path.exists():
        return json.loads(path.read_text())
    return None


def _save_init_keys(keys: dict):
    """Sauvegarde les clés d'init dans le fichier local."""
    path = _get_init_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(keys, indent=2))
    path.chmod(0o600)  # Lecture seule owner
    logger.info(f"🔑 Clés d'init sauvegardées : {path}")


async def initialize_vault() -> dict:
    """
    Initialise OpenBao (première fois uniquement).

    - shares=1, threshold=1 (single operator pour embedded)
    - Sauvegarde le root token et les clés localement

    Returns:
        {"status": "initialized", "root_token": "...", ...} ou {"status": "already_initialized"}
    """
    settings = get_settings()
    client = hvac.Client(url=settings.openbao_addr)

    if client.sys.is_initialized():
        logger.info("✅ OpenBao déjà initialisé")
        return {"status": "already_initialized"}

    logger.info(f"🔧 Initialisation OpenBao (shares={settings.openbao_shares}, threshold={settings.openbao_threshold})...")
    result = client.sys.initialize(
        secret_shares=settings.openbao_shares,
        secret_threshold=settings.openbao_threshold,
    )

    init_data = {
        "root_token": result["root_token"],
        "keys": result["keys"],
        "keys_base64": result.get("keys_base64", []),
    }

    _save_init_keys(init_data)

    logger.info("✅ OpenBao initialisé avec succès")
    return {"status": "initialized", **init_data}


async def unseal_vault() -> dict:
    """
    Déverrouille OpenBao avec les clés Shamir.

    Charge les clés depuis le fichier local et soumet chaque clé.

    Returns:
        {"status": "unsealed"} ou {"status": "error", "message": "..."}
    """
    settings = get_settings()
    client = hvac.Client(url=settings.openbao_addr)

    if not client.sys.is_sealed():
        logger.info("✅ OpenBao déjà déverrouillé")
        return {"status": "already_unsealed"}

    init_keys = _load_init_keys()
    if not init_keys:
        return {"status": "error", "message": "Clés d'init non trouvées — initialiser d'abord"}

    logger.info("🔓 Déverrouillage d'OpenBao...")
    keys = init_keys["keys"]
    for i, key in enumerate(keys[:settings.openbao_threshold]):
        response = client.sys.submit_unseal_key(key)
        if not response["sealed"]:
            break

    if client.sys.is_sealed():
        return {"status": "error", "message": "Échec du déverrouillage"}

    # Configurer le client hvac avec le root token
    from .manager import set_hvac_client
    client.token = init_keys["root_token"]
    set_hvac_client(client)

    logger.info("✅ OpenBao déverrouillé")
    return {"status": "unsealed"}


async def seal_vault() -> dict:
    """
    Scelle (verrouille) OpenBao.

    Doit être appelé avant l'arrêt propre pour protéger les données.

    Returns:
        {"status": "sealed"}
    """
    client = get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    logger.info("🔒 Scellement d'OpenBao...")
    try:
        client.sys.seal()
        logger.info("✅ OpenBao scellé")
        return {"status": "sealed"}
    except Exception as e:
        logger.error(f"❌ Erreur au scellement: {e}")
        return {"status": "error", "message": str(e)}


async def get_vault_status() -> tuple[bool, str]:
    """
    Retourne l'état d'OpenBao pour le health check.

    Returns:
        (ok, detail)
    """
    from .manager import health_check
    return await health_check()


def get_root_token() -> Optional[str]:
    """Retourne le root token depuis les clés d'init."""
    init_keys = _load_init_keys()
    if init_keys:
        return init_keys.get("root_token")
    return None
