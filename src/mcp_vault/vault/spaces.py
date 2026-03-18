# -*- coding: utf-8 -*-
"""
Vault Spaces — CRUD des espaces vault (mount points KV v2).

Chaque space = un mount point KV v2 dans OpenBao.
L'utilisateur organise ses secrets librement (par serveur, app, env, etc.)
"""

import logging
from typing import Optional

from ..openbao.manager import get_hvac_client

logger = logging.getLogger("mcp-vault.spaces")


async def create_space(vault_id: str, description: str = "") -> dict:
    """
    Crée un espace vault (mount KV v2 dans OpenBao).

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
        logger.info(f"✅ Vault créé: {vault_id}")
        return {"status": "created", "vault_id": vault_id, "description": description}
    except Exception as e:
        if "existing mount" in str(e).lower() or "path is already in use" in str(e).lower():
            return {"status": "error", "message": f"Le vault '{vault_id}' existe déjà"}
        logger.error(f"❌ Erreur création vault {vault_id}: {e}")
        return {"status": "error", "message": str(e)}


async def list_spaces() -> dict:
    """Liste tous les espaces vault (mount points KV v2)."""
    client = get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    try:
        mounts = client.sys.list_mounted_secrets_engines()
        vaults = []
        for path, info in mounts.get("data", mounts).items():
            # Filtrer les mount points système (cubbyhole, identity, sys)
            clean_path = path.rstrip("/")
            if info.get("type") == "kv" and clean_path not in ("cubbyhole", "identity", "sys", "secret"):
                vaults.append({
                    "vault_id": clean_path,
                    "description": info.get("description", ""),
                    "type": info.get("type"),
                    "options": info.get("options", {}),
                })
        return {"status": "ok", "vaults": vaults, "count": len(vaults)}
    except Exception as e:
        logger.error(f"❌ Erreur listing spaces: {e}")
        return {"status": "error", "message": str(e)}


async def get_space_info(vault_id: str) -> dict:
    """Informations détaillées sur un espace vault."""
    client = get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    try:
        mounts = client.sys.list_mounted_secrets_engines()
        mount_key = f"{vault_id}/"
        mount_info = mounts.get("data", mounts).get(mount_key)

        if not mount_info:
            return {"status": "error", "message": f"Vault '{vault_id}' non trouvé"}

        # Compter les secrets
        secret_count = 0
        try:
            secrets = client.secrets.kv.v2.list_secrets(path="", mount_point=vault_id)
            secret_count = len(secrets.get("data", {}).get("keys", []))
        except Exception:
            pass  # Pas de secrets ou erreur de listing

        return {
            "status": "ok",
            "vault_id": vault_id,
            "description": mount_info.get("description", ""),
            "type": mount_info.get("type"),
            "options": mount_info.get("options", {}),
            "secrets_count": secret_count,
        }
    except Exception as e:
        logger.error(f"❌ Erreur info vault {vault_id}: {e}")
        return {"status": "error", "message": str(e)}


async def delete_space(vault_id: str) -> dict:
    """Supprime un espace vault (unmount KV v2)."""
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
