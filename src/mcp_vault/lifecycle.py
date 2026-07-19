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

    # ── 0. Bootstrap key (défense en profondeur) ────────────────────
    # La validation autoritaire (fail-fast) est dans server.main() avant tout
    # démarrage : si on arrive ici, la clé est déjà validée. On revérifie quand
    # même au cas où vault_startup() serait appelé hors du point d'entrée main().
    try:
        from .openbao.crypto import validate_bootstrap_key
        is_valid, msg = validate_bootstrap_key(settings.admin_bootstrap_key)
        if not is_valid:
            logger.warning(f"⚠️  Bootstrap key : {msg} (le chiffrement des clés unseal échouera)")
    except Exception as e:
        logger.warning(f"⚠️ Validation bootstrap key : {e}")

    # ── 1. Token Store S3 ──────────────────────────────────────────
    logger.info("🔑 Initialisation du Token Store...")
    try:
        from .auth.token_store import init_token_store
        init_token_store()
    except Exception as e:
        logger.error(f"❌ Token Store : {e}")

    # ── 1b. Policy Store S3 ────────────────────────────────────────
    logger.info("📋 Initialisation du Policy Store...")
    try:
        from .auth.policies import init_policy_store
        init_policy_store()
    except Exception as e:
        logger.error(f"❌ Policy Store : {e}")

    # ── 1b-bis. Mission Binding Store S3 (octroi périmètre vault mission JWT, #69) ──
    logger.info("🎟️  Initialisation du Mission Binding Store...")
    try:
        from .auth.mission_bindings import (
            init_mission_binding_store,
            get_mission_binding_store,
        )
        init_mission_binding_store()
        # Mode dégradé OBSERVABLE : le PEP mission JWT est actif mais aucun octroi
        # n'est possible → toutes les identités mission seront refusées (deny-all).
        if settings.mcp_auth_mode != "bearer" and get_mission_binding_store() is None:
            logger.warning(
                "⚠️  MCP_AUTH_MODE=%s mais Mission Binding Store non configuré : "
                "toutes les identités mission JWT seront refusées (deny-all, aucun périmètre "
                "vault ne peut être octroyé).",
                settings.mcp_auth_mode,
            )
    except Exception as e:
        logger.error(f"❌ Mission Binding Store : {e}")

    # ── 1c. Audit Store ────────────────────────────────────────────
    logger.info("📋 Initialisation de l'Audit Store...")
    try:
        from .audit import init_audit_store
        init_audit_store()
    except Exception as e:
        logger.error(f"❌ Audit Store : {e}")

    # ── 1d. Wrap Registry (JIT broker mcp-mission) ─────────────────
    logger.info("🔐 Initialisation du Wrap Registry...")
    try:
        from .vault.wrapping import init_wrap_registry
        init_wrap_registry()
    except Exception as e:
        logger.error(f"❌ Wrap Registry : {e}")

    # ── 1e. Mission Token Validator (C18, singleton process-wide) ──────────────
    logger.info("🔐 Initialisation du Mission Token Validator...")
    try:
        from .auth.jwt_validator import init_mission_token_validator
        _v = init_mission_token_validator(
            jwks_url=settings.mission_jwks_url,
            expected_aud=settings.resolved_mission_aud,  # source unique (#47)
            cache_ttl=settings.mission_jwks_cache_ttl,
            max_refresh_per_min=settings.mission_jwks_max_refresh_per_min,
            leeway_seconds=settings.mission_token_leeway_seconds,
            component_kind=settings.mcp_component_kind,  # aligné PEP, issue #86
        )
        if _v:
            logger.info("✅ Mission Token Validator prêt (JWKS configuré)")
        else:
            logger.info("ℹ️  Mission Token Validator non configuré (MISSION_JWKS_URL vide — mode standalone)")
    except Exception as e:
        logger.error(f"❌ Mission Token Validator : {e}")

    # ── 1f. PKI CA (vérification état au démarrage) ───────────────
    logger.info("🔐 Vérification PKI CA...")
    try:
        from .vault.pki_ca import is_pki_initialized
        if is_pki_initialized():
            logger.info("✅ PKI CA déjà initialisée.")
        else:
            logger.info("ℹ️  PKI CA non initialisée — utilisez pki_ca_setup pour démarrer.")
    except Exception as e:
        logger.error(f"❌ PKI CA check échoué : {e} — la PKI sera indisponible jusqu'à correction")

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

    # ── 2. Sceller OpenBao + effacer les clés mémoire ────────────
    try:
        from .openbao.lifecycle import seal_vault, clear_in_memory_keys
        seal_result = await seal_vault()
        if seal_result.get("status") == "sealed":
            logger.info("🔒 OpenBao scellé")
        # Garantir l'effacement des clés même si le seal a échoué
        clear_in_memory_keys()
    except Exception as e:
        logger.warning(f"⚠️ Erreur scellement : {e}")
        # Tentative d'effacement des clés malgré l'erreur
        try:
            from .openbao.lifecycle import clear_in_memory_keys
            clear_in_memory_keys()
        except Exception:
            pass

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
