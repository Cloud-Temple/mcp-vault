# -*- coding: utf-8 -*-
"""
Vault Spaces — CRUD des espaces vault (mount points KV v2).

Chaque space = un mount point KV v2 dans OpenBao.
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
# CRUD — Create
# ═══════════════════════════════════════════════════════════════════════

async def create_space(vault_id: str, description: str = "") -> dict:
    """
    Crée un espace vault (mount KV v2 dans OpenBao).

    Écrit automatiquement les métadonnées (created_at, created_by)
    dans le secret réservé _vault_meta.

    Args:
        vault_id: Identifiant unique (utilisé comme mount path)
        description: Description optionnelle
    """
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

async def list_spaces(allowed_vault_ids: Optional[list] = None) -> dict:
    """
    Liste les espaces vault (mount points KV v2).

    Args:
        allowed_vault_ids: Si fourni, ne retourne que les vaults de cette liste.
                           None ou [] = pas de filtre (admin).
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
                # ── Filtrage par token ────────────────────────────
                if allowed_vault_ids and clean_path not in allowed_vault_ids:
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
        logger.error(f"❌ Erreur listing spaces: {e}")
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
    Supprime un espace vault (unmount KV v2).

    Supprime automatiquement tous les secrets ET les métadonnées.
    """
    client = get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    try:
        client.sys.disable_secrets_engine(path=vault_id)
        logger.info(f"🗑️ Vault supprimé: {vault_id}")
        return {"status": "deleted", "vault_id": vault_id}
    except Exception as e:
        logger.error(f"❌ Erreur suppression vault {vault_id}: {e}")
        return {"status": "error", "message": str(e)}
