# -*- coding: utf-8 -*-
"""
Lifecycle Orchestrator — Séquence complète de démarrage et d'arrêt.

STARTUP :
    1. Token Store S3 (charge les tokens)
    2. Check données locales (Docker volume = crash recovery)
    3. Si pas de local → download depuis S3 (résultat à 3 états : restauré /
       absence confirmée / échec ambigu — un échec ambigu refuse le démarrage
       plutôt que d'initialiser un coffre vide, cf. `s3_sync.RestoreResult`)
    4. Démarrer OpenBao (bao server)
    5. Init si première fois (Shamir shares=1, threshold=1)
    6. Unseal (déverrouiller)
    7. Démarrer le sync S3 périodique (conditionnel — n'uploade que si l'état a
       changé, cf. `s3_sync.py`)

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

# Idempotence de l'arrêt (issue #110) : l'arrêt est déclenché par le lifespan
# ASGI, avec un appel de secours dans server.main(). Deux états DISTINCTS —
# `running` (séquence en cours) et `done` (séquence ACHEVÉE) : si l'arrêt est
# interrompu (annulation, exception) alors que rien n'a été scellé, il doit
# rester REJOUABLE. Un drapeau unique posé avant le premier `await` gèlerait
# définitivement l'arrêt sur une annulation précoce (revue pré-commit).
_shutdown_running: bool = False
_shutdown_done: bool = False


def _reset_shutdown_state() -> None:
    """Réarme l'idempotence pour un NOUVEAU cycle de vie.

    Appelé par `vault_startup()` : un même processus peut enchaîner deux
    lifespans (embedding ASGI, redémarrage à chaud) — sans réarmement, le
    second coffre ne serait jamais arrêté proprement.
    """
    global _shutdown_running, _shutdown_done
    _shutdown_running = False
    _shutdown_done = False


# Alias historique conservé pour les tests.
_reset_shutdown_state_for_tests = _reset_shutdown_state


# ─────────────────────────────────────────────────────────────────────────────
# État de démarrage — second terme du prédicat de disponibilité (issue #103)
# ─────────────────────────────────────────────────────────────────────────────
#
# Une sonde OpenBao verte NE PROUVE PAS que le service peut servir : le
# démarrage comprend aussi la restauration S3 et l'initialisation des magasins.
# `/health` doit donc conjuguer DEUX termes, et ce drapeau porte le second.
#
# L'état est LATCHÉ : il n'est jamais promu par une sonde verte, seulement par
# un `vault_startup()` qui a abouti. Après un démarrage manqué, le signal ne
# repasse donc pas au vert tout seul — un redémarrage est requis, et c'est une
# information d'exploitation, pas un défaut.
#
# ⚠️ Ne PAS généraliser la justification : dans le cas d'une restauration S3
# ambiguë, `vault_startup()` renvoie False AVANT de démarrer OpenBao, qui n'est
# donc jamais lancé. Mais d'autres échecs (init, unseal) surviennent APRÈS son
# démarrage — le latch y reste sûr sans être « exact ».
_startup_ready: bool = False


def mark_startup_starting() -> None:
    """Ouvre une génération de démarrage. Appelé au DÉBUT de chaque lifespan."""
    global _startup_ready
    _startup_ready = False


def mark_startup_ready() -> None:
    """Marque le démarrage abouti. Appelé UNIQUEMENT après `vault_startup() is True`."""
    global _startup_ready
    _startup_ready = True


def startup_is_ready() -> bool:
    """True si la génération de démarrage courante a abouti."""
    return _startup_ready


# ─────────────────────────────────────────────────────────────────────────────
# Prédicat de disponibilité (issue #103)
# ─────────────────────────────────────────────────────────────────────────────
#
# Énumération FERMÉE. Ces trois valeurs — et aucune autre — peuvent atteindre
# une surface PUBLIQUE non authentifiée. Le projet a déjà tranché cette forme
# d'arbitrage en #78 (allow-list de raisons internes, message externe
# générique) : ce qui est interdit, c'est le texte libre reflété, pas le fait
# de nommer un état dans un vocabulaire fermé.
HEALTH_HEALTHY = "healthy"
HEALTH_SEALED = "sealed"
HEALTH_UNAVAILABLE = "unavailable"

# Vocabulaire DISTINCT de la liveness : `/healthz` répond à une autre question
# (« le processus répond-il ? »), il ne doit donc jamais emprunter le
# vocabulaire de disponibilité — dire `healthy` pendant que `/health` dit
# `sealed` serait une contradiction entre deux surfaces du même service.
HEALTH_ALIVE = "alive"


async def availability_status() -> tuple[str, str]:
    """
    Calcule l'état de disponibilité — source UNIQUE pour toutes les surfaces.

        sealed       ⇔ sonde : OpenBao joignable ET scellé
        healthy      ⇔ démarrage abouti ET sonde : initialisé ET descellé
        unavailable  ⇔ tous les autres cas

    `sealed` est prioritaire : « joignable mais scellé » est l'information
    actionnable, et elle reste vraie que le démarrage ait abouti ou non.

    Returns:
        (status, detail) — `status` appartient à l'énumération fermée
        ci-dessus et peut être exposé publiquement ; `detail` est un
        DIAGNOSTIC réservé aux surfaces authentifiées et aux journaux.
    """
    from .openbao.manager import probe_openbao

    probe = await probe_openbao()
    if probe.sealed:
        return HEALTH_SEALED, probe.detail
    if probe.ok:
        if startup_is_ready():
            return HEALTH_HEALTHY, probe.detail
        # OpenBao répond, mais la séquence de démarrage n'a pas abouti (par
        # exemple restauration S3 ambiguë, magasins non chargés). Fail-close :
        # le service ne peut pas garantir qu'il sert un état correct.
        return HEALTH_UNAVAILABLE, "démarrage non abouti — redémarrage requis"
    return HEALTH_UNAVAILABLE, probe.detail


def _check_local_data_status(data_dir: Path) -> bool:
    """
    Détermine si `data_dir` contient une donnée locale FIABLE (crash recovery),
    par opposition à une absence ou à un résultat de restauration S3 incomplet.

    Effectue aussi le nettoyage défensif d'un résidu de staging de restauration
    (cf. `s3_sync.py::download_from_s3`).

    Extrait de `vault_startup()` en fonction pure et directement testable
    (durcissement 2026-07, revue de diff round 2) : la logique elle-même ne
    change pas, seul le fait qu'elle soit isolable sans mocker toute la
    séquence de démarrage (Token Store, OpenBao, PKI...) change.

    Le marqueur `_RESTORE_MARKER_FILENAME` (posé par `download_from_s3` AVANT
    tout nettoyage/extraction, retiré SEULEMENT après une promotion
    intégralement réussie ou une absence confirmée) invalide `data_dir` comme
    source de vérité locale, quel que soit son contenu physique, tant qu'il est
    présent : la promotion par renommages individuels n'est pas
    transactionnelle — un crash ou une erreur I/O au milieu peut laisser
    data_dir dans un état MIXTE (certaines entrées promues, d'autres non), et
    rien d'autre ne distingue cet état d'une "vraie" donnée locale légitime.

    Le répertoire de staging (`_RESTORE_STAGING_DIRNAME`) est TOUJOURS exclu
    du test de "contenu réel" ci-dessous, indépendamment du succès du
    nettoyage défensif — bloquant round 4 : un staging durablement non
    supprimable (permission, erreur I/O persistante) pouvait sinon survivre au
    retrait du marqueur et être ensuite compté comme donnée locale "valide",
    alors qu'il ne s'agit que d'un artefact de bookkeeping interne. Cette
    exclusion est la protection PRINCIPALE (elle tient même si le nettoyage
    échoue) ; le nettoyage lui-même reste un best-effort de hygiène.
    """
    from .s3_sync import _RESTORE_STAGING_DIRNAME, _RESTORE_MARKER_FILENAME

    stray_staging = data_dir / _RESTORE_STAGING_DIRNAME
    if stray_staging.exists():
        import shutil
        logger.warning("⚠️ Résidu de staging de restauration détecté — nettoyage")
        shutil.rmtree(stray_staging, ignore_errors=True)

    restore_incomplete = (data_dir / _RESTORE_MARKER_FILENAME).exists()
    if restore_incomplete:
        logger.warning(
            "⚠️ Marqueur de restauration incomplète détecté — contenu local NON "
            "fiable, nouvelle tentative de restauration S3 forcée"
        )

    return (
        not restore_incomplete
        and data_dir.exists()
        and any(
            f for f in data_dir.iterdir()
            if f.name not in (".gitkeep", _RESTORE_MARKER_FILENAME, _RESTORE_STAGING_DIRNAME)
        )
    )


async def vault_startup() -> bool:
    """
    Séquence complète de démarrage du vault.

    Tolérante aux pannes : si OpenBao ne démarre pas, le serveur MCP
    reste accessible en mode dégradé (health check indique l'erreur).

    Returns:
        True si tout est OK, False si mode dégradé
    """
    # Un arrêt est EN COURS (issue #122). Sa séquence se poursuit bien après le
    # drainage — seal, puis sauvegarde finale — avec des points où le service
    # rend la main. Démarrer ici réarmerait l'idempotence d'arrêt sous les pieds
    # de cette séquence, et rouvrirait la sync : le nouveau cycle créerait une
    # boucle que l'arrêt en cours ne connaît pas et ne drainera pas, libre de
    # publier un instantané ANTÉRIEUR après la sauvegarde finale.
    if _shutdown_running:
        logger.critical(
            "🚨 DÉMARRAGE REFUSÉ — un arrêt du coffre est en cours. Démarrer "
            "maintenant créerait une sauvegarde périodique invisible de cet "
            "arrêt."
        )
        return False

    # Nouveau cycle de vie → l'arrêt redevient exécutable (issue #110) : un même
    # processus peut enchaîner deux lifespans, le second doit pouvoir s'arrêter.
    _reset_shutdown_state()

    # Même raison pour la sync périodique (issue #122) : son arrêt la verrouille
    # jusqu'à la fin COMPLÈTE de la séquence d'arrêt (seal + sauvegarde finale).
    # C'est ici, et nulle part ailleurs, qu'un nouveau cycle la rouvre — la
    # rouvrir depuis `start_periodic_sync()` rendrait le verrou inopérant.
    # Une boucle du cycle précédent encore vivante fait échouer la réouverture :
    # elle peut écrire, et lui en superposer une seconde la rendrait invisible.
    from .s3_sync import reopen_periodic_sync
    if not reopen_periodic_sync():
        # Refus AVANT tout démarrage d'OpenBao : une boucle du cycle précédent
        # peut encore écrire sur S3. Démarrer ici la laisserait publier son
        # instantané ANTÉRIEUR par-dessus les écritures du nouveau cycle — et
        # ce nouveau cycle n'aurait même pas de sync périodique pour rattraper,
        # puisque le verrou reste posé.
        #
        # Le retour `False` emprunte le signal EXISTANT de démarrage non abouti
        # (il fait notamment sauter la sauvegarde finale à l'arrêt, ce qui est
        # exactement ce qu'on veut ici). La politique de « mode dégradé » qui
        # découle de ce booléen n'est PAS modifiée : c'est un comportement
        # préexistant, hors périmètre de #122.
        logger.critical(
            "🚨 DÉMARRAGE REFUSÉ — une boucle de sauvegarde du cycle précédent "
            "n'a pas été drainée et peut encore écrire sur S3."
        )
        return False

    from .openbao.lifecycle import UnsealKeysUnrecoverable

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
        if settings.mission_pep_active and get_mission_binding_store() is None:
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
    has_local_data = _check_local_data_status(data_dir)

    if has_local_data:
        logger.info("📁 Données locales trouvées (crash recovery)")
    else:
        # ── 3. Download depuis S3 si pas de données locales ───────
        logger.info("📥 Pas de données locales — tentative de restauration depuis S3...")
        from .s3_sync import download_from_s3, RestoreResult
        try:
            restore_result = await download_from_s3()
        except Exception as e:
            # Défensif : download_from_s3() catche déjà ses propres erreurs et
            # renvoie FAILED — un raise ici serait un bug interne, traité de la
            # même façon (fail-closed) plutôt que de tomber en "première exécution".
            logger.error(f"❌ Restauration S3 : échec inattendu ({type(e).__name__})")
            restore_result = RestoreResult.FAILED

        if restore_result is RestoreResult.RESTORED:
            logger.info("✅ Données restaurées depuis S3")
            has_local_data = True
        elif restore_result is RestoreResult.CONFIRMED_ABSENT:
            logger.info("📦 Pas de données sur S3 non plus — première exécution")
        else:
            # FAILED = erreur AMBIGUË (réseau, permission, archive corrompue...).
            # On refuse de démarrer plutôt que d'initialiser un coffre vide qui
            # écraserait ensuite une sauvegarde distante potentiellement valide
            # (cf. incident versions S3 — durcissement restauration, 2026-07).
            logger.error(
                "❌ Restauration S3 ambiguë — démarrage refusé pour ne pas risquer "
                "d'initialiser un coffre vide par-dessus une sauvegarde distante "
                "potentiellement valide. Réessayez une fois S3 de nouveau joignable."
            )
            return False

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
    except UnsealKeysUnrecoverable:
        # #121 : ÉCHEC BRUYANT, PAS de mode dégradé. Les clés d'unseal sont
        # inexploitables (ADMIN_BOOTSTRAP_KEY probablement changée, ou objet
        # chiffré manquant alors que des données existent). Un coffre qui ne
        # peut pas s'ouvrir n'a aucune raison d'accepter du trafic, et le mode
        # dégradé retarderait le diagnostic. L'exception traverse le lifespan
        # (qui la relaie) → le service refuse de démarrer.
        logger.critical("🚨 DÉMARRAGE REFUSÉ — clés d'unseal inexploitables")
        raise
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


async def vault_shutdown(skip_upload: bool = False):
    """
    Séquence complète d'arrêt du vault.

    Ordre important :
    1. Arrêter le sync (plus d'uploads en parallèle)
    2. Seal OpenBao (protéger les données en mémoire)
    3. Upload final S3 (sauvegarder l'état le plus récent) — SAUF si
       `skip_upload=True`
    4. Arrêter le processus (cleanup)

    Args:
        skip_upload: à passer à `True` quand `vault_startup()` n'a PAS
            complété avec succès (durcissement 2026-07, revue de diff). Sans
            cette garde, un démarrage en échec (ex. restauration S3 ambiguë,
            OpenBao qui ne démarre pas) laisse le serveur tourner en "mode
            dégradé" (comportement existant de `server.py`, inchangé ici) puis,
            à l'arrêt, cet upload FINAL était jusqu'ici TOUJOURS inconditionnel
            — il pouvait donc écraser une sauvegarde S3 valide avec l'état
            local incomplet/non initialisé issu d'un démarrage qui n'a jamais
            correctement abouti. `skip_upload=True` retire spécifiquement CET
            upload, sans changer la politique de "mode dégradé" elle-même
            (hors périmètre de ce fix).

    IDEMPOTENT (issue #110, lot 1) : l'arrêt est porté par le lifespan ASGI, et
    `server.main()` conserve un appel de secours au cas où le lifespan n'aurait
    pas pu s'exécuter. Un second appel ne refait donc NI seal, NI upload final
    (un upload rejoué après le seal réécrirait l'archive sans raison, et un
    second seal masquerait le résultat du premier dans les logs).

    L'idempotence n'est PAS un verrou définitif : si la séquence est interrompue
    (annulation, exception) avant d'aboutir, l'état est restauré et un appel
    ultérieur la rejoue — sinon une annulation précoce laisserait le coffre non
    scellé sans plus aucune chance d'arrêt propre.
    """
    global _shutdown_running, _shutdown_done
    if _shutdown_done or _shutdown_running:
        logger.debug("Arrêt déjà effectué ou en cours — appel ignoré (idempotence)")
        return
    _shutdown_running = True
    try:
        await _vault_shutdown_sequence(skip_upload=skip_upload)
    finally:
        # Rejouable si la séquence n'a pas abouti (annulation/exception).
        _shutdown_running = False
    _shutdown_done = True


async def _vault_shutdown_sequence(skip_upload: bool = False):
    """Séquence d'arrêt proprement dite (voir `vault_shutdown`)."""
    logger.info("🛑 Arrêt de MCP Vault...")

    # ── 1. Arrêter le sync périodique (par DRAINAGE) ──────────────
    # `stop_periodic_sync()` ne fait plus d'annulation (issue #122) : annuler une
    # tâche qui porte un PUT S3 en vol ne l'interrompt pas, et ce PUT pourrait
    # terminer APRÈS l'upload final — écrasant une archive récente par une
    # ancienne. On draine, et le résultat décide de l'upload final.
    try:
        from .s3_sync import stop_periodic_sync
        drained = await stop_periodic_sync()
    except Exception as e:
        logger.warning(f"⚠️ Erreur arrêt sync : {e}")
        # Fail-close : sans preuve de drainage, on ne prend pas le risque
        # d'écraser une sauvegarde distante potentiellement plus récente.
        drained = False

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
    if skip_upload:
        logger.warning(
            "⚠️ Upload S3 final SAUTÉ (le démarrage n'a pas abouti — éviter "
            "d'écraser une sauvegarde distante potentiellement valide avec un "
            "état local incomplet ou non initialisé)"
        )
    elif not drained:
        # PERTE DE DURABILITÉ S3 ASSUMÉE (issue #122). Le coffre n'est pas perdu
        # — le volume local reste l'autorité de reprise — mais la copie distante
        # peut rester périmée. C'est le prix de l'invariant « ne jamais écraser
        # une archive plus récente par une plus ancienne ».
        logger.critical(
            "🚨 Upload S3 final SAUTÉ — la sync périodique n'a pas pu être "
            "drainée. Une sauvegarde peut être encore en vol ; l'écraser "
            "risquerait de publier un état plus ancien. La copie S3 peut donc "
            "rester périmée : la reprise s'appuiera sur le volume local."
        )
    else:
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
