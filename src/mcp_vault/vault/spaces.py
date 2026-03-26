# -*- coding: utf-8 -*-
"""
Vault Spaces — CRUD des espaces vault (mount points KV v2).

Chaque vault = un mount point KV v2 dans OpenBao.
L'utilisateur organise ses secrets librement (par serveur, app, env, etc.)

Métadonnées vault :
    Chaque vault contient un secret réservé `_vault_meta` qui stocke
    les informations de création, modification et propriété.
    Ce chemin est protégé contre l'écriture directe par les utilisateurs.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from ..auth.context import get_current_client_name
from ..openbao.manager import get_hvac_client

logger = logging.getLogger("mcp-vault.spaces")

# ─── Constantes ─────────────────────────────────────────────────────────────
VAULT_META_PATH = "_vault_meta"


def _now_iso() -> str:
    """Retourne la date/heure courante en ISO 8601 UTC."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read_vault_meta(client, vault_id: str) -> dict:
    """
    Lit les métadonnées d'un vault depuis le secret réservé _vault_meta.

    Returns:
        dict des métadonnées, ou {} si absent
    """
    try:
        response = client.secrets.kv.v2.read_secret_version(
            path=VAULT_META_PATH,
            mount_point=vault_id,
        )
        return response.get("data", {}).get("data", {})
    except Exception:
        return {}


def _write_vault_meta(client, vault_id: str, meta: dict):
    """Écrit les métadonnées dans le secret réservé _vault_meta."""
    try:
        client.secrets.kv.v2.create_or_update_secret(
            path=VAULT_META_PATH,
            secret=meta,
            mount_point=vault_id,
        )
    except Exception as e:
        logger.warning(f"⚠️ Impossible d'écrire les métadonnées de {vault_id}: {e}")


# ═══════════════════════════════════════════════════════════════════════
# Owner check (utilisé par check_access pour l'isolation)
# ═══════════════════════════════════════════════════════════════════════

def check_vault_owner(vault_id: str, client_name: str) -> bool:
    """
    Vérifie si un client est le propriétaire d'un vault.

    Lit _vault_meta.created_by et compare avec client_name.
    Retourne True si :
    - Le client est le propriétaire (created_by == client_name)
    - Le vault n'existe pas encore (permet la création)

    Note: synchrone car appelé depuis check_access() (contextvar).
    """
    client = get_hvac_client()
    if not client:
        return False

    # Vérifier si le vault (mount) existe
    try:
        mounts = client.sys.list_mounted_secrets_engines()
        mount_key = f"{vault_id}/"
        if mount_key not in mounts.get("data", mounts):
            return True  # Vault n'existe pas encore → autoriser (création)
    except Exception:
        return False

    meta = _read_vault_meta(client, vault_id)
    if not meta:
        # SÉCURITÉ V3-09 : fail-close — vault sans métadonnées = accès refusé
        logger.warning(f"SECURITY: vault {vault_id} has no _vault_meta — access denied")
        return False

    return meta.get("created_by", "") == client_name


# ═══════════════════════════════════════════════════════════════════════
# CRUD — Create
# ═══════════════════════════════════════════════════════════════════════

import re

# Regex de validation vault_id : alphanumérique + tirets, 1-64 caractères
_VAULT_ID_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$')


def _validate_vault_id(vault_id: str) -> Optional[str]:
    """
    Valide le format du vault_id.

    SÉCURITÉ : empêche les injections de mount path dans OpenBao.
    Accepte : alphanumérique + tirets + underscores, 1-64 chars, commence par alphanum.
    Rejette : chemins relatifs, caractères spéciaux, espaces, vide.

    Returns:
        None si OK, message d'erreur sinon
    """
    if not vault_id:
        return "vault_id est requis"
    if not _VAULT_ID_PATTERN.match(vault_id):
        return (
            f"vault_id '{vault_id}' invalide — "
            "seuls les caractères alphanumériques, tirets et underscores sont autorisés "
            "(1-64 chars, doit commencer par une lettre ou un chiffre)"
        )
    return None


async def create_space(vault_id: str, description: str = "") -> dict:
    """
    Crée un espace vault (mount KV v2 dans OpenBao).

    Écrit automatiquement les métadonnées (created_at, created_by)
    dans le secret réservé _vault_meta.

    Args:
        vault_id: Identifiant unique (utilisé comme mount path)
        description: Description optionnelle
    """
    # Validation du format vault_id (sécurité : empêche injections mount path)
    err = _validate_vault_id(vault_id)
    if err:
        return {"status": "error", "message": err}

    client = get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    try:
        client.sys.enable_secrets_engine(
            backend_type="kv",
            path=vault_id,
            description=description or f"Vault: {vault_id}",
            options={"version": "2"},
        )

        # ── Écrire les métadonnées ──────────────────────────────
        now = _now_iso()
        owner = get_current_client_name()
        meta = {
            "created_at": now,
            "created_by": owner,
            "updated_at": now,
            "updated_by": owner,
            "description": description or f"Vault: {vault_id}",
        }
        _write_vault_meta(client, vault_id, meta)

        logger.info(f"✅ Vault créé: {vault_id} (owner={owner})")
        return {
            "status": "created",
            "vault_id": vault_id,
            "description": description,
            "created_at": now,
            "created_by": owner,
        }
    except Exception as e:
        if "existing mount" in str(e).lower() or "path is already in use" in str(e).lower():
            return {"status": "error", "message": f"Le vault '{vault_id}' existe déjà"}
        logger.error(f"❌ Erreur création vault {vault_id}: {e}")
        return {"status": "error", "message": str(e)}


# ═══════════════════════════════════════════════════════════════════════
# CRUD — List
# ═══════════════════════════════════════════════════════════════════════

async def list_spaces(
    allowed_vault_ids: Optional[list] = None,
    owner_filter: Optional[str] = None,
) -> dict:
    """
    Liste les espaces vault (mount points KV v2).

    Args:
        allowed_vault_ids: Si fourni, ne retourne que les vaults de cette liste.
                           None = pas de filtre par liste (admin ou owner-based).
        owner_filter: Si fourni, ne retourne que les vaults dont created_by == owner_filter.
                      Utilisé pour l'isolation owner-based (allowed_resources vide).
    """
    client = get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    try:
        mounts = client.sys.list_mounted_secrets_engines()
        vaults = []
        for path, info in mounts.get("data", mounts).items():
            # Filtrer les mount points système (cubbyhole, identity, sys, secret)
            clean_path = path.rstrip("/")
            if info.get("type") == "kv" and clean_path not in ("cubbyhole", "identity", "sys", "secret"):
                # ── Filtrage par liste explicite ──────────────────
                if allowed_vault_ids and clean_path not in allowed_vault_ids:
                    continue

                # ── Filtrage par propriétaire (owner-based) ──────
                if owner_filter:
                    meta = _read_vault_meta(client, clean_path)
                    if meta.get("created_by", "") != owner_filter:
                        continue

                vault_entry = {
                    "vault_id": clean_path,
                    "description": info.get("description", ""),
                    "type": info.get("type"),
                    "options": info.get("options", {}),
                }
                vaults.append(vault_entry)

        return {"status": "ok", "vaults": vaults, "count": len(vaults)}
    except Exception as e:
        logger.error(f"❌ Erreur listing vaults: {e}")
        return {"status": "error", "message": str(e)}


# ═══════════════════════════════════════════════════════════════════════
# CRUD — Info (détaillé, avec métadonnées)
# ═══════════════════════════════════════════════════════════════════════

async def get_space_info(vault_id: str) -> dict:
    """
    Informations détaillées sur un espace vault, incluant les métadonnées.

    Retourne : description, nombre de secrets, created_at, created_by, etc.
    """
    client = get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    try:
        mounts = client.sys.list_mounted_secrets_engines()
        mount_key = f"{vault_id}/"
        mount_info = mounts.get("data", mounts).get(mount_key)

        if not mount_info:
            return {"status": "error", "message": f"Vault '{vault_id}' non trouvé"}

        # ── Compter les secrets (en excluant _vault_meta) ─────
        secret_count = 0
        try:
            secrets = client.secrets.kv.v2.list_secrets(path="", mount_point=vault_id)
            keys = secrets.get("data", {}).get("keys", [])
            secret_count = len([k for k in keys if k != VAULT_META_PATH])
        except Exception:
            pass  # Pas de secrets ou erreur de listing

        # ── Lire les métadonnées ──────────────────────────────
        meta = _read_vault_meta(client, vault_id)

        result = {
            "status": "ok",
            "vault_id": vault_id,
            "description": meta.get("description", mount_info.get("description", "")),
            "type": mount_info.get("type"),
            "options": mount_info.get("options", {}),
            "secrets_count": secret_count,
        }

        # Ajouter les métadonnées si elles existent
        if meta:
            result["created_at"] = meta.get("created_at", "")
            result["created_by"] = meta.get("created_by", "")
            result["updated_at"] = meta.get("updated_at", "")
            result["updated_by"] = meta.get("updated_by", "")

        return result
    except Exception as e:
        logger.error(f"❌ Erreur info vault {vault_id}: {e}")
        return {"status": "error", "message": str(e)}


# ═══════════════════════════════════════════════════════════════════════
# CRUD — Update
# ═══════════════════════════════════════════════════════════════════════

async def update_space(vault_id: str, description: str = "") -> dict:
    """
    Met à jour les métadonnées d'un vault (description).

    Args:
        vault_id: Identifiant du vault
        description: Nouvelle description
    """
    client = get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    try:
        # ── Vérifier que le vault existe ──────────────────────
        mounts = client.sys.list_mounted_secrets_engines()
        mount_key = f"{vault_id}/"
        if mount_key not in mounts.get("data", mounts):
            return {"status": "error", "message": f"Vault '{vault_id}' non trouvé"}

        # ── Mettre à jour la description du mount OpenBao ─────
        if description:
            client.sys.tune_mount_configuration(
                path=vault_id,
                description=description,
            )

        # ── Mettre à jour les métadonnées ─────────────────────
        now = _now_iso()
        updater = get_current_client_name()
        meta = _read_vault_meta(client, vault_id)

        if description:
            meta["description"] = description
        meta["updated_at"] = now
        meta["updated_by"] = updater

        # Garantir que les champs de création existent
        if not meta.get("created_at"):
            meta["created_at"] = now
        if not meta.get("created_by"):
            meta["created_by"] = updater

        _write_vault_meta(client, vault_id, meta)

        logger.info(f"✅ Vault mis à jour: {vault_id} (by={updater})")
        return {
            "status": "updated",
            "vault_id": vault_id,
            "description": meta.get("description", ""),
            "updated_at": now,
            "updated_by": updater,
        }
    except Exception as e:
        logger.error(f"❌ Erreur mise à jour vault {vault_id}: {e}")
        return {"status": "error", "message": str(e)}


# ═══════════════════════════════════════════════════════════════════════
# CRUD — Delete
# ═══════════════════════════════════════════════════════════════════════

async def delete_space(vault_id: str) -> dict:
    """
    Supprime un espace vault (unmount KV v2) et sa CA SSH associée.

    Supprime automatiquement :
    - Tous les secrets et métadonnées (KV v2 mount)
    - Le mount SSH CA si configuré (ssh-ca-{vault_id})
    """
    client = get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    try:
        # 1. Supprimer le mount SSH CA associé (si existant)
        from .ssh_ca import cleanup_ssh_ca
        ssh_cleaned = await cleanup_ssh_ca(vault_id)
        if not ssh_cleaned:
            logger.warning(f"⚠️ Impossible de nettoyer la SSH CA de {vault_id} (non bloquant)")

        # 2. Supprimer le mount KV v2 (secrets + métadonnées)
        client.sys.disable_secrets_engine(path=vault_id)
        logger.info(f"🗑️ Vault supprimé: {vault_id}")
        return {"status": "deleted", "vault_id": vault_id}
    except Exception as e:
        logger.error(f"❌ Erreur suppression vault {vault_id}: {e}")
        return {"status": "error", "message": str(e)}
