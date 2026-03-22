# -*- coding: utf-8 -*-
"""
S3 Sync Manager — Synchronisation du file backend OpenBao avec S3.

Pattern :
    1. STARTUP  : download depuis S3 → décompresse dans data_dir
    2. RUNTIME  : periodic upload (toutes les 60s si changements)
    3. SHUTDOWN : upload final → seal

Le file backend OpenBao est compressé en tar.gz pour le transport S3.
"""

import asyncio
import io
import logging
import os
import tarfile
import time
from pathlib import Path
from typing import Optional

from .config import get_settings
from .s3_client import get_s3_data_client, get_s3_meta_client

logger = logging.getLogger("mcp-vault.s3-sync")

# Nom de l'archive sur S3
ARCHIVE_NAME = "openbao-data.tar.gz"

_sync_task: Optional[asyncio.Task] = None
_last_sync_time: float = 0


def _s3_key() -> str:
    """Clé S3 de l'archive OpenBao."""
    settings = get_settings()
    return f"{settings.vault_s3_prefix}/{ARCHIVE_NAME}"


# =============================================================================
# Download (startup)
# =============================================================================

async def download_from_s3() -> bool:
    """
    Télécharge le file backend depuis S3 et le décompresse.

    Returns:
        True si téléchargé avec succès, False si pas de données sur S3
    """
    settings = get_settings()
    data_dir = Path(settings.openbao_data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)

    try:
        s3 = get_s3_data_client()  # GET = SigV2
        key = _s3_key()

        logger.info(f"📥 Téléchargement depuis S3: {key}")
        response = s3.get_object(Bucket=settings.s3_bucket_name, Key=key)
        archive_bytes = response["Body"].read()

        # Décompresser dans le data_dir
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
            tar.extractall(path=str(data_dir))

        size_mb = len(archive_bytes) / (1024 * 1024)
        logger.info(f"✅ Données OpenBao restaurées depuis S3 ({size_mb:.1f} MB)")
        return True

    except Exception as e:
        if "NoSuchKey" in str(e) or "404" in str(e):
            logger.info("📦 Pas de données sur S3 (première exécution)")
            return False
        logger.error(f"❌ Erreur download S3: {e}")
        return False


# =============================================================================
# Upload (runtime + shutdown)
# =============================================================================

async def upload_to_s3() -> bool:
    """
    Compresse le file backend et l'upload sur S3.

    Returns:
        True si uploadé avec succès
    """
    global _last_sync_time
    settings = get_settings()
    data_dir = Path(settings.openbao_data_dir)

    if not data_dir.exists():
        logger.warning("⚠️ Data dir n'existe pas, rien à uploader")
        return False

    try:
        s3 = get_s3_data_client()  # PUT = SigV2
        key = _s3_key()

        # Créer l'archive tar.gz en mémoire
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for item in data_dir.iterdir():
                tar.add(str(item), arcname=item.name)
        buf.seek(0)

        size_mb = buf.getbuffer().nbytes / (1024 * 1024)
        logger.info(f"📤 Upload vers S3: {key} ({size_mb:.1f} MB)")

        s3.put_object(
            Bucket=settings.s3_bucket_name,
            Key=key,
            Body=buf.read(),
            ContentType="application/gzip",
        )

        _last_sync_time = time.time()
        logger.info("✅ Données OpenBao sauvegardées sur S3")
        return True

    except Exception as e:
        logger.error(f"❌ Erreur upload S3: {e}")
        return False


# =============================================================================
# Periodic sync (background task)
# =============================================================================

async def start_periodic_sync():
    """Démarre la tâche de sync périodique en arrière-plan."""
    global _sync_task
    settings = get_settings()
    interval = settings.vault_s3_sync_interval

    if interval <= 0:
        logger.info("⏸️ Sync périodique désactivée (interval=0)")
        return

    async def _sync_loop():
        while True:
            await asyncio.sleep(interval)
            try:
                await upload_to_s3()
            except Exception as e:
                logger.error(f"❌ Erreur sync périodique: {e}")

    _sync_task = asyncio.create_task(_sync_loop())
    logger.info(f"🔄 Sync périodique activée (toutes les {interval}s)")


async def stop_periodic_sync():
    """Arrête la tâche de sync périodique."""
    global _sync_task
    if _sync_task:
        _sync_task.cancel()
        try:
            await _sync_task
        except asyncio.CancelledError:
            pass
        _sync_task = None
        logger.info("⏹️ Sync périodique arrêtée")


# =============================================================================
# Health check
# =============================================================================

async def check_s3_connectivity() -> tuple[bool, str]:
    """
    Vérifie la connectivité S3.

    Returns:
        (ok, detail)
    """
    settings = get_settings()
    if not settings.s3_endpoint_url:
        return False, "S3 non configuré"

    try:
        s3 = get_s3_meta_client()  # HEAD = SigV4
        s3.head_bucket(Bucket=settings.s3_bucket_name)
        return True, f"S3 OK ({settings.s3_bucket_name})"
    except Exception as e:
        return False, f"S3 inaccessible: {e}"
