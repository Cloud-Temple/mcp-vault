# -*- coding: utf-8 -*-
"""
OpenBao Lifecycle — Init, Unseal, Seal (Option C — Sécurité renforcée).

Gère le cycle de vie complet d'OpenBao avec séparation physique données/clés :

    1. Init (première fois) — crée les clés, les chiffre, les uploade sur S3
    2. Unseal — télécharge les clés chiffrées depuis S3, déchiffre en mémoire
    3. Seal — scelle OpenBao et efface les clés de la mémoire
    4. Status — état courant

INVARIANTS DE SÉCURITÉ (Option C) :
    - Les clés unseal ne sont JAMAIS écrites en clair sur le filesystem local
    - Elles sont stockées chiffrées (AES-256-GCM) sur S3 uniquement
    - Pendant le runtime, elles ne vivent qu'en mémoire Python (_in_memory_keys)
    - Un crash du processus efface automatiquement les clés (garbage collection)
    - 3 facteurs nécessaires : données (barrier) + clés enc (S3) + bootstrap key (env)

MIGRATION :
    Si un ancien fichier init_keys.json (en clair) est détecté au startup,
    il est automatiquement migré vers S3 chiffré puis supprimé localement.
"""

import json
import logging
from pathlib import Path
from typing import Optional

import hvac

from ..config import get_settings
from .crypto import encrypt_with_bootstrap_key, decrypt_with_bootstrap_key
from .manager import get_hvac_client

logger = logging.getLogger("mcp-vault.openbao")

# ─────────────────────────────────────────────────────────────────────────────
# Clés en mémoire uniquement — jamais sur le filesystem
# ─────────────────────────────────────────────────────────────────────────────

_in_memory_keys: Optional[dict] = None
"""
Stockage en mémoire des clés unseal + root token.
Structure : {"keys": [...], "keys_base64": [...], "root_token": "..."}
Effacé au seal/shutdown. Garbage collected au crash.
"""

# Chemin S3 des clés chiffrées (aligné sur DESIGN §5)
_S3_INIT_KEY = "_init/init_keys.json.enc"

# Ancien fichier local (v0.1.x) — pour migration uniquement
_LEGACY_INIT_FILE = "init_keys.json"


# ─────────────────────────────────────────────────────────────────────────────
# Opérations S3 pour les clés chiffrées
# ─────────────────────────────────────────────────────────────────────────────

def _upload_encrypted_keys_to_s3(init_data: dict) -> bool:
    """
    Chiffre les clés unseal avec ADMIN_BOOTSTRAP_KEY et les uploade sur S3.

    Args:
        init_data: Dictionnaire contenant keys, keys_base64, root_token

    Returns:
        True si l'upload a réussi
    """
    settings = get_settings()

    # Chiffrer avec AES-256-GCM (clé dérivée de ADMIN_BOOTSTRAP_KEY via PBKDF2)
    plaintext = json.dumps(init_data)
    encrypted_b64 = encrypt_with_bootstrap_key(plaintext, settings.admin_bootstrap_key)

    # Upload sur S3
    from ..s3_client import get_s3_data_client
    s3 = get_s3_data_client()
    s3.put_object(
        Bucket=settings.s3_bucket_name,
        Key=_S3_INIT_KEY,
        Body=encrypted_b64.encode("ascii"),
        ContentType="application/octet-stream",
    )

    logger.info(f"🔐 Clés unseal chiffrées uploadées sur S3 ({_S3_INIT_KEY})")
    return True


def _download_encrypted_keys_from_s3() -> Optional[dict]:
    """
    Télécharge et déchiffre les clés unseal depuis S3.

    Returns:
        Dictionnaire des clés ou None si non trouvé
    """
    settings = get_settings()

    try:
        from ..s3_client import get_s3_data_client
        s3 = get_s3_data_client()
        response = s3.get_object(
            Bucket=settings.s3_bucket_name,
            Key=_S3_INIT_KEY,
        )
        encrypted_b64 = response["Body"].read().decode("ascii")
    except Exception as e:
        if "NoSuchKey" in str(e) or "404" in str(e):
            logger.debug(f"Pas de clés chiffrées sur S3 ({_S3_INIT_KEY})")
            return None
        raise

    # Déchiffrer avec ADMIN_BOOTSTRAP_KEY
    plaintext = decrypt_with_bootstrap_key(encrypted_b64, settings.admin_bootstrap_key)
    init_data = json.loads(plaintext)

    logger.info(f"🔓 Clés unseal déchiffrées depuis S3 ({_S3_INIT_KEY})")
    return init_data


# ─────────────────────────────────────────────────────────────────────────────
# Migration ancien format (v0.1.x → Option C)
# ─────────────────────────────────────────────────────────────────────────────

def _check_and_migrate_legacy_keys() -> Optional[dict]:
    """
    Vérifie si un ancien fichier init_keys.json (en clair) existe.

    Si oui :
    1. Le charge en mémoire
    2. Le chiffre et l'uploade sur S3
    3. Supprime le fichier local (plus jamais de clé en clair sur disque)

    Returns:
        Les clés migrées ou None si pas de fichier legacy
    """
    settings = get_settings()
    legacy_path = Path(settings.openbao_data_dir) / _LEGACY_INIT_FILE

    if not legacy_path.exists():
        return None

    logger.warning(
        f"⚠️ Ancien fichier de clés en clair détecté : {legacy_path}\n"
        f"   Migration automatique vers S3 chiffré (Option C)..."
    )

    # 1. Charger les clés en clair
    init_data = json.loads(legacy_path.read_text())

    # 2. Chiffrer et uploader sur S3
    try:
        _upload_encrypted_keys_to_s3(init_data)
    except Exception as e:
        logger.error(f"❌ Échec migration vers S3 : {e}")
        logger.error("   Les clés en clair sont conservées localement (fallback)")
        return init_data  # On retourne quand même les clés pour ne pas bloquer

    # 3. Supprimer le fichier local en clair
    legacy_path.unlink()
    logger.info(
        f"✅ Migration terminée — fichier local supprimé ({legacy_path})\n"
        f"   Les clés sont désormais chiffrées sur S3 uniquement"
    )

    return init_data


# ─────────────────────────────────────────────────────────────────────────────
# Cycle de vie : Init, Unseal, Seal
# ─────────────────────────────────────────────────────────────────────────────

async def initialize_vault() -> dict:
    """
    Initialise OpenBao (première fois uniquement).

    - shares=1, threshold=1 (single operator pour embedded)
    - Chiffre les clés avec ADMIN_BOOTSTRAP_KEY (AES-256-GCM)
    - Upload sur S3 uniquement — JAMAIS de fichier local en clair
    - Stocke en mémoire pour l'unseal immédiat

    Returns:
        {"status": "initialized", ...} ou {"status": "already_initialized"}
    """
    global _in_memory_keys
    settings = get_settings()
    client = hvac.Client(url=settings.openbao_addr)

    if client.sys.is_initialized():
        logger.info("✅ OpenBao déjà initialisé")
        return {"status": "already_initialized"}

    logger.info(
        f"🔧 Initialisation OpenBao "
        f"(shares={settings.openbao_shares}, threshold={settings.openbao_threshold})..."
    )
    result = client.sys.initialize(
        secret_shares=settings.openbao_shares,
        secret_threshold=settings.openbao_threshold,
    )

    init_data = {
        "root_token": result["root_token"],
        "keys": result["keys"],
        "keys_base64": result.get("keys_base64", []),
    }

    # ── Chiffrer et uploader sur S3 (Option C) ──
    try:
        _upload_encrypted_keys_to_s3(init_data)
    except Exception as e:
        # CRITIQUE : si l'upload S3 échoue, on ne peut pas continuer
        # car on ne sauvegarde PAS en local (invariant Option C)
        logger.error(f"❌ CRITIQUE — Upload S3 des clés échoué : {e}")
        logger.error(
            "   Les clés ne seront PAS persistées ! "
            "Vérifiez la connectivité S3 et relancez."
        )
        # On garde quand même en mémoire pour que cette session fonctionne
        _in_memory_keys = init_data
        return {
            "status": "initialized",
            "warning": "Clés non persistées sur S3 — session unique",
            **init_data,
        }

    # ── Stocker en mémoire uniquement (pas sur disque) ──
    _in_memory_keys = init_data

    logger.info("✅ OpenBao initialisé — clés chiffrées sur S3, mémoire seule au runtime")
    # SÉCURITÉ V3-07 : ne pas retourner root_token/keys dans la réponse
    return {"status": "initialized", "s3_persisted": True}


async def unseal_vault() -> dict:
    """
    Déverrouille OpenBao avec les clés Shamir.

    Ordre de résolution des clés :
    1. Mémoire (_in_memory_keys) — si déjà chargées (post-init)
    2. Migration legacy — ancien fichier local en clair → S3 chiffré
    3. S3 chiffré — télécharge et déchiffre avec ADMIN_BOOTSTRAP_KEY

    Les clés ne touchent JAMAIS le filesystem en clair.

    Returns:
        {"status": "unsealed"} ou {"status": "error", "message": "..."}
    """
    global _in_memory_keys
    settings = get_settings()
    client = hvac.Client(url=settings.openbao_addr)

    # Déjà déverrouillé ?
    if not client.sys.is_sealed():
        logger.info("✅ OpenBao déjà déverrouillé")
        return {"status": "already_unsealed"}

    # ── Résolution des clés (3 sources, par priorité) ──

    init_keys = None

    # Source 1 : déjà en mémoire (post-init dans la même session)
    if _in_memory_keys:
        init_keys = _in_memory_keys
        logger.info("🔑 Clés trouvées en mémoire (session courante)")

    # Source 2 : migration ancien fichier local → S3 chiffré
    if not init_keys:
        init_keys = _check_and_migrate_legacy_keys()
        if init_keys:
            logger.info("🔑 Clés récupérées par migration legacy → S3")

    # Source 3 : téléchargement depuis S3 (cas nominal)
    if not init_keys:
        try:
            init_keys = _download_encrypted_keys_from_s3()
            if init_keys:
                logger.info("🔑 Clés déchiffrées depuis S3")
        except ValueError as e:
            return {
                "status": "error",
                "message": f"Déchiffrement des clés S3 impossible : {e}",
            }
        except Exception as e:
            return {
                "status": "error",
                "message": f"Erreur téléchargement clés S3 : {e}",
            }

    if not init_keys:
        return {
            "status": "error",
            "message": (
                "Clés unseal introuvables — ni en mémoire, ni en local (legacy), "
                "ni sur S3. Initialiser d'abord avec initialize_vault()."
            ),
        }

    # ── Unseal OpenBao ──
    logger.info("🔓 Déverrouillage d'OpenBao...")
    keys = init_keys["keys"]
    for key in keys[:settings.openbao_threshold]:
        response = client.sys.submit_unseal_key(key)
        if not response["sealed"]:
            break

    if client.sys.is_sealed():
        return {"status": "error", "message": "Échec du déverrouillage"}

    # ── Configurer le client hvac avec le root token ──
    from .manager import set_hvac_client
    client.token = init_keys["root_token"]
    set_hvac_client(client)

    # ── Stocker en mémoire (pas sur disque) ──
    _in_memory_keys = init_keys

    logger.info("✅ OpenBao déverrouillé — clés en mémoire uniquement")
    return {"status": "unsealed"}


async def seal_vault() -> dict:
    """
    Scelle (verrouille) OpenBao et efface les clés de la mémoire.

    Après le seal :
    - Les données du file backend sont illisibles sans les clés
    - Les clés n'existent plus qu'en version chiffrée sur S3
    - Prochain unseal = re-téléchargement depuis S3

    Returns:
        {"status": "sealed"}
    """
    global _in_memory_keys
    client = get_hvac_client()

    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    logger.info("🔒 Scellement d'OpenBao...")
    try:
        client.sys.seal()

        # ── Effacer les clés de la mémoire ──
        _in_memory_keys = None
        logger.info("🗑️ Clés unseal effacées de la mémoire")

        logger.info("✅ OpenBao scellé — clés uniquement sur S3 (chiffrées)")
        return {"status": "sealed"}

    except Exception as e:
        logger.error(f"❌ Erreur au scellement: {e}")
        return {"status": "error", "message": str(e)}


def clear_in_memory_keys():
    """
    Efface explicitement les clés unseal de la mémoire.

    Appelé par le lifecycle orchestrateur au shutdown pour garantir
    que les clés ne restent pas en mémoire même en cas d'erreur.
    """
    global _in_memory_keys
    if _in_memory_keys:
        _in_memory_keys = None
        logger.info("🗑️ Clés unseal effacées de la mémoire (shutdown)")


# ─────────────────────────────────────────────────────────────────────────────
# Accesseurs
# ─────────────────────────────────────────────────────────────────────────────

async def get_vault_status() -> tuple[bool, str]:
    """
    Retourne l'état d'OpenBao pour le health check.

    Returns:
        (ok, detail)
    """
    from .manager import health_check
    return await health_check()


def get_root_token() -> Optional[str]:
    """
    Retourne le root token depuis la mémoire.

    En Option C, les clés ne sont JAMAIS lues depuis le filesystem.
    Elles ne vivent qu'en mémoire pendant le runtime.

    Returns:
        Le root token ou None si pas déverrouillé
    """
    if _in_memory_keys:
        return _in_memory_keys.get("root_token")
    return None
