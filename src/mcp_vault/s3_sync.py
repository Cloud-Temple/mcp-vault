# -*- coding: utf-8 -*-
"""
S3 Sync Manager — Synchronisation du file backend OpenBao avec S3.

Pattern :
    1. STARTUP  : download depuis S3 → décompresse dans data_dir
    2. RUNTIME  : periodic upload (toutes les <interval>s, SEULEMENT si l'état a changé)
    3. SHUTDOWN : upload final (toujours inconditionnel) → seal

Le file backend OpenBao est compressé en tar.gz pour le transport S3.

## Détection de changement (fix incident versions S3, 2026-07)

Contexte : le bucket de production a le versioning S3 activé sans lifecycle. Un
PUT inconditionnel toutes les 60s produisait une version par cycle (6000+ versions,
600+ Mo en quelques jours) même quand rien n'avait changé.

Le sync PÉRIODIQUE n'effectue désormais un PUT que si l'état source a changé
depuis le dernier upload réussi. Points clés de sûreté :

- L'empreinte de l'état est calculée **dans la même passe** que la construction de
  l'archive (`_snapshot_and_archive`) : pour un fichier régulier, contenu ET
  métadonnées archivés viennent du MÊME descripteur ouvert (`open()` + `fstat(fd)`
  + `read()`), jamais d'un second stat par CHEMIN séparé. Ferme la divergence
  trouvée en revue de diff (round 1) : la version précédente combinait un `lstat()`,
  un `tar.gettarinfo(chemin)` et un `read_bytes()` — trois observations séparées du
  même chemin — si l'entité changeait de type entre elles (ex. remplacée par un
  symlink), l'archive et l'empreinte pouvaient diverger. Résidu assumé, non
  exploitable avec l'usage réel du file backend OpenBao (qui ne remplace jamais un
  fichier par un symlink en cours de fonctionnement) : la décision de branchement
  (fichier/répertoire/symlink) repose sur UN SEUL `lstat()` initial ; un changement
  de type dans l'intervalle minuscule entre ce `lstat()` et l'`open()` qui suit
  peut affecter l'étiquette de type archivée, mais jamais faire diverger le
  contenu réellement archivé de celui réellement empreint (les deux viennent
  toujours du même `open()`+`read()`).
- L'empreinte NE porte JAMAIS sur le tar.gz généré (ses métadonnées gzip/mtime
  varient sans changement métier) — elle porte sur le contenu logique : chemins
  relatifs triés, contenu des fichiers, type (fichier/répertoire/symlink), détection
  implicite des créations/modifications/suppressions.
- La référence ("dernière empreinte uploadée") n'avance QU'APRÈS un PUT confirmé
  réussi. Un échec — y compris AMBIGU, comme un timeout après l'envoi où l'objet a
  pu être écrit côté S3 malgré l'exception côté client — place l'état "incertain" :
  aucun skip n'est autorisé tant qu'un PUT n'a pas explicitement réussi ensuite. Le
  cycle suivant retente donc un vrai PUT (rejouable), jamais un skip erroné.
- Les uploads FORCÉS (arrêt, opérations PKI qui appellent `upload_to_s3()` sans
  argument) ne sautent JAMAIS : seule la boucle périodique (`_periodic_sync_tick`)
  active `skip_if_unchanged=True`.
- La restauration au démarrage distingue "absence confirmée par S3" (première
  exécution légitime) d'un "échec ambigu" (réseau, archive corrompue...) : seul le
  premier cas autorise une initialisation à vide. Un échec ambigu fait échouer le
  démarrage plutôt que de risquer d'écraser une sauvegarde distante valide avec un
  coffre neuf (cf. `RestoreResult`).
- La restauration extrait dans un répertoire de STAGING (à l'intérieur de
  data_dir, même filesystem) avant toute promotion : une extraction qui échoue
  APRÈS avoir déjà écrit certains membres (archive corrompue, ou membre rejeté
  par `filter='data'` après des membres valides) ne laisse alors RIEN dans
  data_dir lui-même — seul le staging jetable contient le résultat partiel.
- Un démarrage qui n'aboutit pas (dont une restauration S3 ambiguë) doit
  empêcher l'upload final inconditionnel de l'arrêt (`vault_shutdown(skip_upload=...)`,
  câblé depuis `server.py` à partir du même booléen que `vault_startup()` retourne)
  — sans quoi ce dernier upload pourrait écraser une sauvegarde distante valide
  avec un état local incomplet ou jamais initialisé.

Aucun secret, contenu OpenBao, clé d'accès S3, clé objet S3 ou chemin interne n'est
journalisé par ce module (seuls des tailles, types d'erreur fermés et statuts).
"""

import asyncio
import hashlib
import io
import logging
import os
import shutil
import stat
import tarfile
import time
from enum import Enum
from pathlib import Path
from typing import Optional

from .config import get_settings
from .s3_client import get_s3_data_client, get_s3_meta_client

logger = logging.getLogger("mcp-vault.s3-sync")

# Nom de l'archive sur S3
ARCHIVE_NAME = "openbao-data.tar.gz"

# Répertoire de staging pour la restauration atomique (cf. download_from_s3) —
# préfixé par un point pour ne jamais apparaître comme une "vraie" donnée dans
# un listing superficiel, mais explicitement exclu par nom partout où c'est
# pertinent (jamais traité comme une entrée OpenBao par has_local_data, la
# construction de l'archive, etc.).
_RESTORE_STAGING_DIRNAME = ".s3_sync_restore_staging"

# Marqueur durable "restauration en cours" (cf. download_from_s3) — sa PRÉSENCE
# signale que data_dir ne doit PAS être considéré fiable, quel que soit son
# contenu physique (la boucle de promotion par renommages individuels n'est pas
# transactionnelle : un crash ou une erreur I/O au milieu peut laisser un état
# mixte). Exclu par nom des mêmes endroits que le staging.
_RESTORE_MARKER_FILENAME = ".s3_sync_restore_in_progress"

_sync_task: Optional[asyncio.Task] = None
_last_sync_time: float = 0

# --- État de détection de changement (cf. docstring module) ---
# Empreinte de l'état source au moment du dernier PUT CONFIRMÉ réussi. `None` tant
# qu'aucun upload n'a encore réussi (démarrage, ou après un reset de test) — un
# `skip_if_unchanged` ne peut alors jamais s'appliquer (pas de référence).
_last_uploaded_fingerprint: Optional[str] = None
# `True` dès qu'un PUT a échoué de façon AMBIGUË (l'objet a pu être écrit côté S3
# malgré l'exception locale). Interdit tout skip jusqu'au prochain PUT confirmé.
_s3_state_uncertain: bool = False


class RestoreResult(str, Enum):
    """Résultat à 3 états de `download_from_s3` — jamais confondre échec et absence."""

    RESTORED = "restored"
    CONFIRMED_ABSENT = "confirmed_absent"
    FAILED = "failed"


def _s3_key() -> str:
    """Clé S3 de l'archive OpenBao."""
    settings = get_settings()
    return f"{settings.vault_s3_prefix}/{ARCHIVE_NAME}"


def _reset_sync_state_for_tests() -> None:
    """
    Réinitialise l'état module (empreinte, incertitude, horodatage).

    Réservé aux tests : permet à chaque test de partir d'un état neutre sans
    dépendre de l'ordre d'exécution de la suite (l'état de détection de
    changement est un singleton module, comme les clients S3 — cf. `reset_clients`
    dans `s3_client.py`).
    """
    global _last_uploaded_fingerprint, _s3_state_uncertain, _last_sync_time
    _last_uploaded_fingerprint = None
    _s3_state_uncertain = False
    _last_sync_time = 0


def _is_confirmed_absent(exc: Exception) -> bool:
    """
    Vérifie que S3 a EXPLICITEMENT répondu "objet absent" (404/NoSuchKey), par
    opposition à une erreur ambiguë (réseau, timeout, permission, backend). Seule
    une absence CONFIRMÉE autorise à traiter un échec de download comme une
    première exécution légitime — cf. `RestoreResult.CONFIRMED_ABSENT`.
    """
    response = getattr(exc, "response", None)
    error_code = None
    if isinstance(response, dict):
        error = response.get("Error")
        if isinstance(error, dict):
            error_code = error.get("Code")
    if error_code is not None:
        return error_code in ("NoSuchKey", "404", "NotFound")
    # Fallback pour les exceptions sans `.response` structuré (ex. exceptions
    # spécifiques boto3 comme `s3.exceptions.NoSuchKey`, ou stubs de test) :
    # correspondance EXACTE sur le nom de la classe, jamais sur le message complet
    # (qui peut contenir bucket/clé — pas de dépendance à du texte non structuré).
    return type(exc).__name__ == "NoSuchKey"


# =============================================================================
# Download (startup)
# =============================================================================

def _clear_data_dir_leftovers(data_dir: Path, *, include_staging: bool = False) -> None:
    """
    Retire tout contenu de `data_dir` autre que le marqueur de restauration
    (et, par défaut, le staging).

    Utilisé À LA FOIS avant une promotion (le staging va remplacer ce qui s'y
    trouve — NE JAMAIS passer `include_staging=True` ici, ce serait détruire
    la source active dont on s'apprête à lire le contenu) ET sur une absence
    CONFIRMÉE par S3 consécutive à une tentative précédente ratée (bloquant
    round 3 : une absence confirmée ne rend PAS fiable un résidu de promotion
    partielle préexistant — sans cette purge, lever le marqueur aurait fait
    réapparaître ce résidu comme donnée locale valide au prochain démarrage).

    Args:
        include_staging: si True, purge aussi le répertoire de staging s'il
            existe. Réservé aux appelants où AUCUNE session de staging n'est
            active dans CET appel (le chemin CONFIRMED_ABSENT) — tout staging
            y est nécessairement le résidu d'une tentative PRÉCÉDENTE et
            différente (bloquant round 4 : sans ce paramètre, un staging
            durablement non supprimable — permission, erreur I/O persistante
            — pouvait survivre au retrait du marqueur et être ensuite compté
            comme donnée locale "valide" par `_check_local_data_status`,
            alors qu'il ne s'agit que d'un artefact de bookkeeping interne).

    Toute exception se propage : l'appelant doit alors traiter l'opération
    comme un échec (marqueur laissé en place, fail-closed).
    """
    skip_names = {_RESTORE_MARKER_FILENAME}
    if not include_staging:
        skip_names.add(_RESTORE_STAGING_DIRNAME)
    for leftover in data_dir.iterdir():
        if leftover.name in skip_names:
            continue
        if leftover.is_dir() and not leftover.is_symlink():
            shutil.rmtree(leftover)
        else:
            leftover.unlink()


async def download_from_s3() -> RestoreResult:
    """
    Télécharge le file backend depuis S3 et le décompresse.

    ⚠️ Contrat d'appel : cette fonction ne doit être invoquée QUE lorsque
    l'appelant a déjà déterminé l'absence de donnée locale fiable (cf.
    `lifecycle.py::_check_local_data_status`). Elle nettoie et remplace
    inconditionnellement le contenu de `data_dir` sur ses chemins de succès —
    un appel direct hors de ce contrat écraserait destructivement une donnée
    locale valide.

    Returns:
        RESTORED         : données téléchargées et extraites avec succès.
        CONFIRMED_ABSENT : S3 confirme qu'aucune archive n'existe (première
                           exécution légitime — l'appelant peut initialiser à vide).
        FAILED           : erreur AMBIGUË (réseau, permission, archive corrompue,
                           timeout...). NE DOIT PAS être traité comme une absence :
                           l'appelant doit refuser de démarrer plutôt que
                           d'initialiser un coffre vide par-dessus une sauvegarde
                           distante potentiellement valide.
    """
    settings = get_settings()
    data_dir = Path(settings.openbao_data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)

    # Marqueur DURABLE "restauration en cours", écrit AVANT tout nettoyage ou
    # extraction (bloquant trouvé en revue de diff round 2 : la promotion par
    # renommages individuels n'est PAS transactionnelle — un rename() est
    # atomique unitairement, mais la BOUCLE ne l'est pas. Une erreur I/O ou un
    # crash/SIGKILL au milieu laissait data_dir dans un état MIXTE (certaines
    # entrées promues, d'autres non), sans qu'aucun signal ne distingue cet
    # état d'une "vraie" donnée locale légitime — has_local_data l'acceptait
    # silencieusement au redémarrage suivant, court-circuitant toute nouvelle
    # tentative de restauration S3).
    #
    # Tant que ce marqueur existe, `lifecycle.py::has_local_data` traite
    # data_dir comme NON fiable, quel que soit son contenu physique — il est
    # retiré UNIQUEMENT après une promotion INTÉGRALEMENT réussie (dernière
    # ligne de cette fonction, chemin RESTORED) ou une absence CONFIRMÉE
    # (chemin CONFIRMED_ABSENT — un état terminal légitime, rien à protéger).
    # Sur FAILED (quelle qu'en soit la cause), le marqueur reste : le prochain
    # démarrage retente une restauration complète, jamais un skip.
    marker = data_dir / _RESTORE_MARKER_FILENAME
    try:
        marker.touch()
    except Exception as e:
        logger.error(f"❌ Impossible de marquer la restauration en cours ({type(e).__name__})")
        return RestoreResult.FAILED

    try:
        s3 = get_s3_data_client()  # GET = SigV2
        key = _s3_key()
        response = s3.get_object(Bucket=settings.s3_bucket_name, Key=key)
        archive_bytes = response["Body"].read()
    except Exception as e:
        if _is_confirmed_absent(e):
            logger.info("📦 Pas de données sur S3 (première exécution)")
            # Bloquant trouvé en revue de diff round 3 : une absence CONFIRMÉE
            # par S3 ne rend PAS fiable un résidu PRÉEXISTANT de promotion
            # partielle (une tentative précédente a pu échouer en laissant le
            # marqueur ET une entrée déjà promue — ex. objet S3 supprimé entre
            # deux tentatives). Sans cette purge, retirer le marqueur ici
            # aurait fait réapparaître ce résidu comme donnée locale valide au
            # prochain calcul de `_check_local_data_status` — rouvrant
            # exactement l'invariant du bloquant round 2. Si CETTE purge
            # échoue à son tour, le marqueur reste (fail-closed, pas d'état
            # terminal atteint). include_staging=True (bloquant round 4) :
            # aucune session de staging n'est active dans CET appel — tout
            # staging présent est nécessairement le résidu d'une tentative
            # PRÉCÉDENTE différente, jamais celui en cours de constitution.
            try:
                _clear_data_dir_leftovers(data_dir, include_staging=True)
            except Exception as cleanup_error:
                logger.error(
                    f"❌ Nettoyage avant absence confirmée échoué "
                    f"({type(cleanup_error).__name__})"
                )
                return RestoreResult.FAILED
            marker.unlink(missing_ok=True)  # SEULEMENT ICI : data_dir purgé et fiable
            return RestoreResult.CONFIRMED_ABSENT
        logger.error(f"❌ Erreur download S3 ({type(e).__name__})")
        return RestoreResult.FAILED

    # Extraction dans un répertoire de STAGING, à l'intérieur de data_dir (donc
    # garanti sur le MÊME filesystem — le volume Docker est monté exactement sur
    # data_dir, pas sur son parent : un rename atomique parent<->data_dir
    # échouerait avec EXDEV). Une extraction qui échoue APRÈS avoir déjà écrit
    # certains membres (ex. archive corrompue ou membre rejeté par filter='data'
    # après des membres valides) ne laisse alors RIEN dans data_dir lui-même —
    # seul le staging, jeté en bloc, contient le résultat partiel.
    staging_dir = data_dir / _RESTORE_STAGING_DIRNAME
    if staging_dir.exists():
        shutil.rmtree(staging_dir, ignore_errors=True)  # résidu d'une tentative précédente
    staging_dir.mkdir()

    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
            # SÉCURITÉ : filter='data' bloque les path traversal (../../),
            # symlinks dangereux et fichiers device (CVE-2007-4559)
            tar.extractall(path=str(staging_dir), filter='data')
    except Exception as e:
        logger.error(f"❌ Archive S3 illisible ou corrompue ({type(e).__name__})")
        shutil.rmtree(staging_dir, ignore_errors=True)
        return RestoreResult.FAILED  # marqueur laissé en place

    # Extraction INTÉGRALE réussie : nettoyer tout résidu de data_dir (y compris
    # une éventuelle promotion PARTIELLE d'une tentative précédente interrompue
    # — le marqueur garantit que rien de ce qui s'y trouve n'a jamais été validé
    # comme fiable) puis promouvoir par renommages individuels (même filesystem
    # que le staging). Si CETTE étape échoue à son tour (I/O, crash), le
    # marqueur reste en place — le prochain démarrage ne verra JAMAIS ce
    # résultat partiel comme une donnée locale valide, et redémarrera une
    # restauration complète depuis ce même nettoyage.
    try:
        _clear_data_dir_leftovers(data_dir)
        for entry in staging_dir.iterdir():
            entry.rename(data_dir / entry.name)
        staging_dir.rmdir()
    except Exception as e:
        logger.error(f"❌ Promotion de la restauration échouée ({type(e).__name__})")
        return RestoreResult.FAILED  # marqueur laissé en place

    marker.unlink(missing_ok=True)  # SEULEMENT ICI : promotion intégralement réussie
    size_mb = len(archive_bytes) / (1024 * 1024)
    logger.info(f"✅ Données OpenBao restaurées depuis S3 ({size_mb:.1f} MB)")
    return RestoreResult.RESTORED


# =============================================================================
# Empreinte + archive (calcul unifié — cf. docstring module)
# =============================================================================

def _snapshot_and_archive(data_dir: Path) -> tuple[bytes, str]:
    """
    Parcourt `data_dir` de façon déterministe et construit, EN UNE SEULE PASSE,
    l'archive tar.gz ET l'empreinte de l'état RÉELLEMENT archivé.

    Pour chaque fichier régulier, contenu ET métadonnées archivés viennent du
    MÊME descripteur ouvert (`open()` + `fstat(fd)` + `read()`), jamais d'un
    second stat par CHEMIN séparé après lecture — élimine la divergence trouvée
    en revue de diff (round 1) entre archive et empreinte quand l'entité change
    de type entre deux observations distinctes du même chemin. Résidu assumé :
    la décision de branchement (fichier/répertoire/symlink) repose sur un seul
    `lstat()` initial ; un changement de type dans l'intervalle minuscule entre
    ce `lstat()` et l'`open()` qui suit peut affecter l'étiquette de type
    archivée, mais ne fait jamais diverger le contenu réellement archivé de
    celui réellement empreint (les deux viennent toujours du même `open()`+
    `read()`). Non exploitable avec l'usage réel du file backend OpenBao.

    Couverture de l'empreinte : fichiers réguliers (contenu haché), répertoires et
    symlinks (type + cible), énumérés dans l'ordre trié des chemins relatifs
    (déterministe, indépendant de l'ordre retourné par le filesystem). mtime et
    permissions sont exclus du HASH (bruit sans signification métier — c'est
    précisément la source du problème à éliminer) mais restent préservés dans
    l'archive elle-même via `tarfile` (fidélité de restauration inchangée).

    Toute erreur pendant le parcours (ex. fichier supprimé entre le listing et la
    lecture — même fenêtre de course que l'implémentation historique, qui itérait
    puis lisait chaque fichier séparément) se propage : l'appelant doit alors
    traiter CE cycle comme un échec plutôt que d'utiliser un résultat partiel —
    aucun skip ne doit jamais être décidé sur une empreinte incomplète.

    Returns:
        (archive_bytes, fingerprint_hex)
    """
    entries = sorted(
        (
            p for p in data_dir.rglob("*")
            # Exclusion défensive du staging ET du marqueur de restauration : ne
            # devraient jamais coexister avec un appel normal (download_from_s3
            # les nettoie/retire dans tous ses chemins de sortie), mais un crash
            # EXACTEMENT pendant la promotion pourrait en laisser un résidu — ni
            # l'un ni l'autre ne doit jamais être traité comme une donnée
            # OpenBao réelle.
            if _RESTORE_STAGING_DIRNAME not in p.relative_to(data_dir).parts
            and p.name != _RESTORE_MARKER_FILENAME
        ),
        key=lambda p: p.relative_to(data_dir).as_posix(),
    )

    buf = io.BytesIO()
    hasher = hashlib.sha256()

    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path in entries:
            rel = path.relative_to(data_dir).as_posix()
            st = path.lstat()
            mode = st.st_mode

            if stat.S_ISLNK(mode):
                target = os.readlink(path)
                info = _make_tarinfo(rel, st, tarfile.SYMTYPE)
                info.linkname = target
                tar.addfile(info)
                kind = b"L"
                digest = hashlib.sha256(target.encode("utf-8", "surrogateescape")).digest()
            elif stat.S_ISDIR(mode):
                info = _make_tarinfo(rel, st, tarfile.DIRTYPE)
                tar.addfile(info)
                kind = b"D"
                digest = b"\x00" * 32
            elif stat.S_ISREG(mode):
                # Ouvre le fichier UNE SEULE fois : le contenu ARCHIVÉ et les
                # métadonnées du TarInfo viennent du MÊME descripteur ouvert
                # (fstat sur le fd, jamais un re-stat par CHEMIN). Ferme la
                # divergence trouvée en revue de diff : l'ancienne version
                # appelait `tar.gettarinfo(str(path), ...)` — qui refait son
                # propre stat du CHEMIN — PUIS `path.read_bytes()` — une
                # TROISIÈME observation par chemin. Si l'entité changeait de
                # type entre ces observations séparées (ex. remplacée par un
                # symlink), l'archive et l'empreinte pouvaient être construites
                # à partir d'états DIFFÉRENTS de la même entrée.
                with path.open("rb") as fh:
                    content = fh.read()
                    fstat_result = os.fstat(fh.fileno())
                info = _make_tarinfo(rel, fstat_result, tarfile.REGTYPE)
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
                kind = b"F"
                digest = hashlib.sha256(content).digest()
            else:
                # device/fifo/socket : hors périmètre du file backend OpenBao.
                # Ignoré de l'archive ET de l'empreinte — comportement identique
                # des deux côtés, ne peut pas causer de divergence.
                continue

            rel_bytes = rel.encode("utf-8", "surrogateescape")
            # Longueur préfixée : anti-collision de concaténation (ex. "ab"+"c"
            # vs "a"+"bc" ne doivent jamais produire la même empreinte).
            hasher.update(len(rel_bytes).to_bytes(8, "big"))
            hasher.update(rel_bytes)
            hasher.update(kind)
            hasher.update(digest)

    buf.seek(0)
    return buf.read(), hasher.hexdigest()


def _make_tarinfo(rel: str, st: os.stat_result, tar_type: bytes) -> tarfile.TarInfo:
    """
    Construit un `TarInfo` directement depuis un `stat_result` DÉJÀ obtenu —
    jamais via `tarfile.gettarinfo(chemin, ...)`, qui refait son propre
    stat/lstat DU CHEMIN (une source de divergence si l'entité change entre
    temps — cf. `_snapshot_and_archive`). Pour un fichier régulier, `st` doit
    venir d'un `os.fstat()` sur le DESCRIPTEUR déjà ouvert pour la lecture du
    contenu (pas un stat par chemin séparé) : garantit que métadonnées
    archivées et contenu haché proviennent de la même observation.
    """
    info = tarfile.TarInfo(name=rel)
    info.mode = stat.S_IMODE(st.st_mode)
    info.uid = st.st_uid
    info.gid = st.st_gid
    info.mtime = int(st.st_mtime)
    info.type = tar_type
    if tar_type == tarfile.DIRTYPE and not info.name.endswith("/"):
        info.name += "/"
    return info


# =============================================================================
# Upload (runtime + shutdown)
# =============================================================================

async def upload_to_s3(skip_if_unchanged: bool = False) -> bool:
    """
    Compresse le file backend et l'upload sur S3.

    Args:
        skip_if_unchanged: si True ET que l'état source n'a pas changé depuis le
            dernier PUT confirmé réussi ET qu'aucun échec ambigu n'est en attente,
            le PUT est sauté. Réservé à la boucle périodique (`_periodic_sync_tick`)
            — tous les autres appelants (arrêt, opérations PKI) laissent le défaut
            `False` : ils uploadent TOUJOURS, sans condition, comme avant ce fix.

    Returns:
        True si uploadé avec succès OU sauté car inchangé (cas nominal du point de
        vue de l'appelant — rien à signaler). False UNIQUEMENT si le PUT a
        réellement échoué.
    """
    global _last_sync_time, _last_uploaded_fingerprint, _s3_state_uncertain
    settings = get_settings()
    data_dir = Path(settings.openbao_data_dir)

    if not data_dir.exists():
        logger.warning("⚠️ Data dir n'existe pas, rien à uploader")
        return False

    try:
        archive_bytes, fingerprint = _snapshot_and_archive(data_dir)
    except Exception as e:
        # Échec de construction (ex. fichier disparu pendant le parcours) : même
        # profil de risque que l'implémentation historique (qui pouvait lever de
        # la même façon pendant tar.add()). Ce cycle échoue, le suivant retente.
        logger.error(f"❌ Erreur construction archive ({type(e).__name__})")
        return False

    can_skip = (
        skip_if_unchanged
        and not _s3_state_uncertain
        and fingerprint == _last_uploaded_fingerprint
    )
    if can_skip:
        logger.debug("⏭️ État inchangé depuis le dernier upload — sync ignorée")
        return True

    size_mb = len(archive_bytes) / (1024 * 1024)

    try:
        s3 = get_s3_data_client()  # PUT = SigV2
        s3.put_object(
            Bucket=settings.s3_bucket_name,
            Key=_s3_key(),
            Body=archive_bytes,
            ContentType="application/gzip",
        )
    except Exception as e:
        # Échec possiblement AMBIGU : par exemple un timeout après l'envoi, où
        # l'objet peut avoir été écrit côté S3 malgré l'exception côté client. On
        # ne peut PAS prouver l'absence d'écriture distante — on marque l'état
        # incertain, ce qui interdit tout skip tant qu'un PUT n'aura pas
        # explicitement réussi. La référence n'avance PAS : la prochaine tentative
        # est un vrai PUT, rejouable (contrainte de rejeu sur échec).
        _s3_state_uncertain = True
        logger.error(f"❌ Erreur upload S3 ({type(e).__name__})")
        return False

    # PUT confirmé réussi : la référence devient l'empreinte du snapshot
    # RÉELLEMENT envoyé (construit dans la même passe que l'archive — jamais une
    # empreinte lue séparément, cf. `_snapshot_and_archive`).
    _last_uploaded_fingerprint = fingerprint
    _s3_state_uncertain = False
    _last_sync_time = time.time()
    logger.info(f"✅ Données OpenBao sauvegardées sur S3 ({size_mb:.1f} MB)")
    return True


# =============================================================================
# Periodic sync (background task)
# =============================================================================

async def _periodic_sync_tick() -> bool:
    """
    Un cycle de la boucle périodique — extrait en fonction testable séparément
    (sans dépendre de `asyncio.sleep`), et pour garantir que SEUL ce point d'entrée
    active `skip_if_unchanged=True`. Tous les autres appelants d'`upload_to_s3`
    (arrêt, opérations PKI) doivent conserver le défaut `False`.
    """
    return await upload_to_s3(skip_if_unchanged=True)


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
                await _periodic_sync_tick()
            except Exception as e:
                logger.error(f"❌ Erreur sync périodique ({type(e).__name__})")

    _sync_task = asyncio.create_task(_sync_loop())
    logger.info(f"🔄 Sync périodique activée (toutes les {interval}s, conditionnelle)")


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
        return False, f"S3 inaccessible: {type(e).__name__}"
