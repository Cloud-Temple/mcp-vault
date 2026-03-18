# -*- coding: utf-8 -*-
"""
Lifecycle Orchestrator — Séquence complète de démarrage et d'arrêt.

STARTUP :
    1. Token Store S3 (charge les tokens)
    2. Check données locales (Docker volume = crash recovery)
    3. Si pas de local → download depuis S3
    4. Démarrer OpenBao (bao server)
    5. Init si première fois (Shamir shares=1, threshold=1)
    6. Unseal (déverrouiller)
    7. Démarrer le sync S3 périodique

SHUTDOWN (SIGTERM) :
    1. Arrêter le sync périodique
    2. Sceller OpenBao (seal)
    3. Upload final S3
    4. Arrêter le processus OpenBao
"""

import logging
from pathlib import Path

from .config import get_settings

logger = logging.getLogger("mcp-vault.lifecycle")


async def vault_startup() -> bool:
    """
    Séquence complète de démarrage du vault.

    Tolérante aux pannes : si OpenBao ne démarre pas, le serveur MCP
    reste accessible en mode dégradé (health check indique l'erreur).

    Returns:
        True si tout est OK, False si mode dégradé
    """
    settings = get_settings()

    # ── 1. Token Store S3 ──────────────────────────────────────────
    logger.info("🔑 Initialisation du Token Store...")
    try:
        from .auth.token_store import init_token_store
        init_token_store()
    except Exception as e:
        logger.error(f"❌ Token Store : {e}")

    # ── 2. Vérifier les données locales (Docker volume) ───────────
    data_dir = Path(settings.openbao_data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    has_local_data = data_dir.exists() and any(
        f for f in data_dir.iterdir() if f.name != ".gitkeep"
    )

    if has_local_data:
        logger.info(f"📁 Données locales trouvées dans {data_dir} (crash recovery)")
    else:
        # ── 3. Download depuis S3 si pas de données locales ───────
        logger.info("📥 Pas de données locales — tentative de restauration depuis S3...")
        try:
            from .s3_sync import download_from_s3
            downloaded = await download_from_s3()
            if downloaded:
                logger.info("✅ Données restaurées depuis S3")
                has_local_data = True
            else:
                logger.info("📦 Pas de données sur S3 non plus — première exécution")
        except Exception as e:
            logger.warning(f"⚠️ Download S3 échoué : {e}")

    # ── 4. Démarrer OpenBao ───────────────────────────────────────
    logger.info("🚀 Démarrage d'OpenBao...")
    try:
        from .openbao.manager import start_openbao
        ok = await start_openbao()
        if not ok:
            logger.error("❌ OpenBao n'a pas démarré — mode dégradé")
            return False
    except Exception as e:
        logger.error(f"❌ Erreur démarrage OpenBao : {e}")
        return False

    # ── 5. Init si première fois ──────────────────────────────────
    try:
        from .openbao.lifecycle import initialize_vault
        init_result = await initialize_vault()
        if init_result.get("status") == "initialized":
            logger.info("🔧 OpenBao initialisé pour la première fois")
        elif init_result.get("status") == "already_initialized":
            logger.info("✅ OpenBao déjà initialisé")
    except Exception as e:
        logger.error(f"❌ Erreur initialisation OpenBao : {e}")
        return False

    # ── 6. Unseal (déverrouiller) ─────────────────────────────────
    try:
        from .openbao.lifecycle import unseal_vault
        unseal_result = await unseal_vault()
        status = unseal_result.get("status")
        if status in ("unsealed", "already_unsealed"):
            logger.info("🔓 OpenBao déverrouillé et prêt")
        else:
            logger.error(f"❌ Échec du déverrouillage : {unseal_result}")
            return False
    except Exception as e:
        logger.error(f"❌ Erreur unseal OpenBao : {e}")
        return False

    # ── 7. Démarrer le sync S3 périodique ─────────────────────────
    try:
        from .s3_sync import start_periodic_sync
        await start_periodic_sync()
    except Exception as e:
        logger.warning(f"⚠️ Sync S3 périodique non démarré : {e}")

    logger.info("=" * 50)
    logger.info("  ✅ MCP Vault opérationnel")
    logger.info("=" * 50)
    return True


async def vault_shutdown():
    """
    Séquence complète d'arrêt du vault.

    Ordre important :
    1. Arrêter le sync (plus d'uploads en parallèle)
    2. Seal OpenBao (protéger les données en mémoire)
    3. Upload final S3 (sauvegarder l'état le plus récent)
    4. Arrêter le processus (cleanup)
    """
    logger.info("🛑 Arrêt de MCP Vault...")

    # ── 1. Arrêter le sync périodique ─────────────────────────────
    try:
        from .s3_sync import stop_periodic_sync
        await stop_periodic_sync()
    except Exception as e:
        logger.warning(f"⚠️ Erreur arrêt sync : {e}")

    # ── 2. Sceller OpenBao ────────────────────────────────────────
    try:
        from .openbao.lifecycle import seal_vault
        seal_result = await seal_vault()
        if seal_result.get("status") == "sealed":
            logger.info("🔒 OpenBao scellé")
    except Exception as e:
        logger.warning(f"⚠️ Erreur scellement : {e}")

    # ── 3. Upload final S3 ────────────────────────────────────────
    try:
        from .s3_sync import upload_to_s3
        uploaded = await upload_to_s3()
        if uploaded:
            logger.info("📤 Upload S3 final réussi")
    except Exception as e:
        logger.warning(f"⚠️ Erreur upload S3 final : {e}")

    # ── 4. Arrêter le processus OpenBao ───────────────────────────
    try:
        from .openbao.manager import stop_openbao
        await stop_openbao()
    except Exception as e:
        logger.warning(f"⚠️ Erreur arrêt OpenBao : {e}")

    logger.info("👋 MCP Vault arrêté proprement")
