# -*- coding: utf-8 -*-
"""
Vault Secrets — CRUD des secrets KV v2.

Chaque secret est stocké dans un vault (= mount point KV v2).
Supporte le versioning natif de KV v2.
"""

import logging
import re
from typing import Optional

import hvac

from ..openbao.manager import get_hvac_client
from .spaces import VAULT_META_PATH
from .types import validate_secret, enrich_secret_data, list_types, generate_password, SECRET_TYPES

logger = logging.getLogger("mcp-vault.secrets")

# Chemins réservés — protégés contre l'écriture/lecture/suppression directe
RESERVED_PATHS = {VAULT_META_PATH}

# SÉCURITÉ V3-23 / #81 : validation canonique des chemins de secrets.
# Un chemin est une suite de segments séparés par '/'. Chaque segment doit
# commencer par un caractère alphanumérique puis n'utiliser que [a-zA-Z0-9_.-].
# Rejette donc : segment vide (⇒ '//' et slash terminal), '.' et '..'
# (anti-traversal), '\', caractères de contrôle et séparateurs exotiques.
_MAX_PATH_LEN = 256
_SEGMENT_PATTERN = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.\-]*')
_CAS_CONFLICT_FRAGMENT = "check-and-set parameter did not match"


def _is_cas_conflict(error: hvac.exceptions.InvalidRequest) -> bool:
    """Reconnaît uniquement le conflit CAS KV v2, jamais un 400 générique."""
    raw_errors = error.errors or []
    candidates = list(raw_errors) if isinstance(raw_errors, (list, tuple)) else [raw_errors]
    candidates.extend(item for item in error.args if isinstance(item, str))
    return any(
        _CAS_CONFLICT_FRAGMENT in candidate.lower()
        for candidate in candidates
        if isinstance(candidate, str)
    )


def _validate_secret_path(path: str) -> Optional[dict]:
    """
    Valide le format d'un chemin de secret (canonique, anti-traversal).

    SÉCURITÉ V3-23 : empêche les traversals vers les endpoints OpenBao internes.
    SÉCURITÉ #81 (cohérent #78) : validation par segments (rejette '//', slash
    terminal, '.', '..'), contrôle de type, et message **constant** — la valeur
    rejetée n'est jamais réinjectée dans la réponse ni dans l'audit MCP
    (`server._r`), ce qui ferme un vecteur d'injection de journal.
    """
    if path == "":
        return None  # Chemin vide = listing racine, OK
    if not isinstance(path, str) or len(path) > _MAX_PATH_LEN or "\\" in path:
        return {"status": "error", "message": "Chemin de secret invalide"}
    for segment in path.split("/"):
        if segment in ("", ".", "..") or not _SEGMENT_PATTERN.fullmatch(segment):
            return {"status": "error", "message": "Chemin de secret invalide"}
    return None


def normalize_list_path(raw) -> Optional[str]:
    """
    Canonicalise ET valide un chemin de LISTING (préfixe de dossier).

    Retourne le chemin canonique (`str`) si valide, ou `None` si invalide.

    SÉCURITÉ #81 (« validate vs use ») : la MÊME valeur canonique doit servir au
    contrôle de policy (`check_path_policy`) ET à l'appel OpenBao. Normaliser
    APRÈS le contrôle ouvrait un contournement : `?prefix=%2F` (→ `"/"`) était
    autorisé par une policy sur `"/"` puis listait la racine (`""`). D'où :

    - `""` = racine (autorisé) ;
    - un slash terminal unique est retiré ;
    - un préfixe non vide qui se réduit à vide (cas `"/"`) est **rejeté** ;
    - le reste doit passer `_validate_secret_path` (rejette `//`, `.`, `..`, etc.).
    """
    if not isinstance(raw, str):
        return None
    if raw == "":
        return ""  # racine
    canonical = raw[:-1] if raw.endswith("/") else raw
    if canonical == "":  # ex. "/" seul → ambigu (alias de la racine) → rejet
        return None
    if _validate_secret_path(canonical) is not None:
        return None
    return canonical


def _is_reserved_path(path: str) -> bool:
    """
    Vérifie si un chemin est réservé (match exact OU sous-chemin).

    SÉCURITÉ V3-24 : match préfixe pour empêcher le bypass via _vault_meta/injected.
    """
    return any(
        path == rp or path.rstrip("/") == rp or path.startswith(rp + "/")
        for rp in RESERVED_PATHS
    )


async def write_secret(vault_id: str, path: str, data: dict,
                       secret_type: str = "custom", tags: str = "",
                       favorite: bool = False,
                       create_only: bool = False) -> dict:
    """
    Écrit ou met à jour un secret typé.

    Args:
        vault_id: Vault cible
        path: Chemin du secret
        data: Données du secret (champs selon le type)
        secret_type: Type de secret (login, password, api_key, etc.)
        tags: Tags séparés par des virgules
        favorite: Marquer comme favori
        create_only: Créer uniquement si le chemin n'existe pas (CAS 0)
    """
    # SÉCURITÉ V3-23 : validation du chemin
    path_err = _validate_secret_path(path)
    if path_err:
        return path_err

    # SÉCURITÉ V3-24 : protection des chemins réservés (match préfixe)
    if _is_reserved_path(path):
        return {"status": "error", "message": f"Le chemin '{path}' est réservé au système"}

    # Validation du type
    error = validate_secret(secret_type, data)
    if error:
        return {"status": "error", "message": error}

    client = get_hvac_client()
    if not client:
        return {
            "status": "error",
            "error_type": "backend",
            "message": "OpenBao non connecté",
        }

    # Enrichir les données avec type + métadonnées
    enriched = enrich_secret_data(secret_type, data)
    if tags:
        enriched["_tags"] = tags
    if favorite:
        enriched["_favorite"] = "true"

    try:
        write_options = {
            "path": path,
            "secret": enriched,
            "mount_point": vault_id,
        }
        if create_only:
            # OpenBao KV v2 garantit atomiquement que la version courante est
            # absente. Un contrôle GET puis POST ne fournirait pas cette
            # garantie (fenêtre TOCTOU entre les deux appels).
            write_options["cas"] = 0
        response = client.secrets.kv.v2.create_or_update_secret(
            **write_options,
        )
        version = response.get("data", {}).get("version", 0) if isinstance(response, dict) else 0
        icon = SECRET_TYPES.get(secret_type, {}).get("icon", "⚙️")
        logger.info(f"{icon} Secret {secret_type} écrit: {vault_id}/{path} (v{version})")
        return {
            "status": "ok", "vault_id": vault_id, "path": path,
            "type": secret_type, "version": version,
        }
    except hvac.exceptions.InvalidRequest as exc:
        if create_only and _is_cas_conflict(exc):
            logger.info("Conflit create-only sur %s/%s", vault_id, path)
            return {"status": "conflict", "message": "Secret déjà présent"}
        logger.error("Erreur de requête OpenBao pendant l'écriture de %s/%s", vault_id, path)
        return {
            "status": "error",
            "error_type": "backend",
            "message": "Écriture OpenBao refusée",
        }
    except Exception as exc:
        logger.error(
            "Erreur backend pendant l'écriture de %s/%s; type=%s",
            vault_id,
            path,
            type(exc).__name__,
        )
        return {
            "status": "error",
            "error_type": "backend",
            "message": "Écriture OpenBao impossible",
        }


async def read_secret(vault_id: str, path: str, version: int = 0) -> dict:
    """Lit un secret (dernière version ou version spécifique)."""
    # SÉCURITÉ V3-23 : validation du chemin
    path_err = _validate_secret_path(path)
    if path_err:
        return path_err

    # SÉCURITÉ V3-25 : protection des chemins réservés en lecture
    if _is_reserved_path(path):
        return {"status": "error", "message": f"Le chemin '{path}' est réservé au système"}

    client = get_hvac_client()
    if not client:
        return {
            "status": "error",
            "error_type": "backend",
            "message": "OpenBao non connecté",
        }

    try:
        kwargs: dict = {"path": path, "mount_point": vault_id}
        if version > 0:
            kwargs["version"] = version

        response = client.secrets.kv.v2.read_secret_version(**kwargs)
        secret_data = response.get("data", {}).get("data", {})
        metadata = response.get("data", {}).get("metadata", {})

        return {
            "status": "ok",
            "vault_id": vault_id,
            "path": path,
            "data": secret_data,
            "version": metadata.get("version", 0),
            "created_time": metadata.get("created_time", ""),
        }
    except hvac.exceptions.InvalidPath:
        # InvalidPath signifie aussi « mount absent ». On ne publie 404 que si
        # l'autorité OpenBao atteste que le mount KV v2 demandé existe encore.
        # Toute erreur de cette contre-preuve reste ambiguë et fail-close.
        try:
            mounts_response = client.sys.list_mounted_secrets_engines()
            mounts = mounts_response.get("data", mounts_response)
            mount = mounts.get(f"{vault_id}/") if isinstance(mounts, dict) else None
            mount_is_kv_v2 = (
                isinstance(mount, dict)
                and mount.get("type") == "kv"
                and isinstance(mount.get("options"), dict)
                and str(mount["options"].get("version")) == "2"
            )
        except Exception as exc:
            logger.error(
                "Contre-preuve du mount impossible pour %s; type=%s",
                vault_id,
                type(exc).__name__,
            )
            mount_is_kv_v2 = False
        if not mount_is_kv_v2:
            return {
                "status": "error",
                "error_type": "backend",
                "message": "Lecture OpenBao impossible",
            }
        # Compatibilité du contrat MCP historique : une absence reste une
        # erreur applicative, enrichie d'un type stable pour que REST puisse
        # lui attribuer 404 sans confondre les autres erreurs.
        return {"status": "error", "error_type": "not_found", "message": "Secret absent"}
    except Exception as exc:
        # Une panne ou un refus OpenBao n'est jamais une preuve d'absence. Le
        # message reste constant afin de ne pas relayer un détail sensible de
        # la réponse backend dans l'API ou les journaux opérateur.
        logger.error(
            "Erreur backend pendant la lecture de %s/%s; type=%s",
            vault_id,
            path,
            type(exc).__name__,
        )
        return {
            "status": "error",
            "error_type": "backend",
            "message": "Lecture OpenBao impossible",
        }


async def list_secrets(vault_id: str, path: str = "") -> dict:
    """
    Liste les entrées d'un niveau du vault (clés uniquement, pas les valeurs).

    En KV v2, `list` renvoie les entrées du niveau `path` : les feuilles
    (secrets) apparaissent telles quelles, les sous-dossiers avec un '/' final.
    Les clés retournées sont **relatives** à `path` (OpenBao 2.x / hvac 2.x) —
    l'appelant reconstruit le chemin complet en préfixant par `path`.

    `path` peut désigner un sous-dossier ("bootstrap" ou "bootstrap/") ; le
    slash terminal éventuel est normalisé.
    """
    # SÉCURITÉ #81 : canonicaliser + valider via la source unique normalize_list_path
    # (la MÊME valeur canonique doit servir au contrôle de policy amont). Validation
    # ABSENTE avant #81 — protège aussi l'outil MCP secret_list (anti-traversal).
    norm_path = normalize_list_path(path)
    if norm_path is None:
        return {"status": "error", "message": "Chemin de secret invalide"}

    client = get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    try:
        response = client.secrets.kv.v2.list_secrets(path=norm_path, mount_point=vault_id)
        all_keys = response.get("data", {}).get("keys", [])
        # Filtrer les chemins réservés (ex: _vault_meta)
        keys = [k for k in all_keys if k not in RESERVED_PATHS]
        return {"status": "ok", "vault_id": vault_id, "path": norm_path, "keys": keys, "count": len(keys)}
    except Exception as e:
        if "InvalidPath" in str(type(e).__name__) or "404" in str(e):
            return {"status": "ok", "vault_id": vault_id, "path": norm_path, "keys": [], "count": 0}
        logger.error("❌ Erreur listing secrets %s/%r: %s", vault_id, norm_path, e)
        return {"status": "error", "message": str(e)}


async def delete_secret(vault_id: str, path: str) -> dict:
    """Supprime un secret et toutes ses versions."""
    # SÉCURITÉ V3-23 : validation du chemin
    path_err = _validate_secret_path(path)
    if path_err:
        return path_err

    # SÉCURITÉ V3-24 : protection des chemins réservés (match préfixe)
    if _is_reserved_path(path):
        return {"status": "error", "message": f"Le chemin '{path}' est réservé au système"}

    client = get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    try:
        client.secrets.kv.v2.delete_metadata_and_all_versions(path=path, mount_point=vault_id)
        logger.info(f"🗑️ Secret supprimé: {vault_id}/{path}")
        return {"status": "deleted", "vault_id": vault_id, "path": path}
    except Exception as e:
        logger.error(f"❌ Erreur suppression secret {vault_id}/{path}: {e}")
        return {"status": "error", "message": str(e)}
