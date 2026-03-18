# -*- coding: utf-8 -*-
"""
Vault Secrets — CRUD des secrets KV v2.

Chaque secret est stocké dans un space (= mount point KV v2).
Supporte le versioning natif de KV v2.
"""

import logging

from ..openbao.manager import get_hvac_client
from .types import validate_secret, enrich_secret_data, list_types, generate_password, SECRET_TYPES

logger = logging.getLogger("mcp-vault.secrets")


async def write_secret(vault_id: str, path: str, data: dict,
                       secret_type: str = "custom", tags: str = "",
                       favorite: bool = False) -> dict:
    """
    Écrit ou met à jour un secret typé.

    Args:
        vault_id: Vault cible
        path: Chemin du secret
        data: Données du secret (champs selon le type)
        secret_type: Type de secret (login, password, api_key, etc.)
        tags: Tags séparés par des virgules
        favorite: Marquer comme favori
    """
    # Validation du type
    error = validate_secret(secret_type, data)
    if error:
        return {"status": "error", "message": error}

    client = get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    # Enrichir les données avec type + métadonnées
    enriched = enrich_secret_data(secret_type, data)
    if tags:
        enriched["_tags"] = tags
    if favorite:
        enriched["_favorite"] = "true"

    try:
        response = client.secrets.kv.v2.create_or_update_secret(
            path=path,
            secret=enriched,
            mount_point=vault_id,
        )
        version = response.get("data", {}).get("version", 0) if isinstance(response, dict) else 0
        icon = SECRET_TYPES.get(secret_type, {}).get("icon", "⚙️")
        logger.info(f"{icon} Secret {secret_type} écrit: {vault_id}/{path} (v{version})")
        return {
            "status": "ok", "vault_id": vault_id, "path": path,
            "type": secret_type, "version": version,
        }
    except Exception as e:
        logger.error(f"❌ Erreur écriture secret {vault_id}/{path}: {e}")
        return {"status": "error", "message": str(e)}


async def read_secret(vault_id: str, path: str, version: int = 0) -> dict:
    """Lit un secret (dernière version ou version spécifique)."""
    client = get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    try:
        kwargs = {"path": path, "mount_point": vault_id}
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
    except Exception as e:
        if "InvalidPath" in str(type(e).__name__) or "404" in str(e):
            return {"status": "error", "message": f"Secret '{vault_id}/{path}' non trouvé"}
        logger.error(f"❌ Erreur lecture secret {vault_id}/{path}: {e}")
        return {"status": "error", "message": str(e)}


async def list_secrets(vault_id: str, path: str = "") -> dict:
    """Liste les secrets d'un space (clés uniquement, pas les valeurs)."""
    client = get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    try:
        response = client.secrets.kv.v2.list_secrets(path=path, mount_point=vault_id)
        keys = response.get("data", {}).get("keys", [])
        return {"status": "ok", "vault_id": vault_id, "path": path, "keys": keys, "count": len(keys)}
    except Exception as e:
        if "InvalidPath" in str(type(e).__name__) or "404" in str(e):
            return {"status": "ok", "vault_id": vault_id, "path": path, "keys": [], "count": 0}
        logger.error(f"❌ Erreur listing secrets {vault_id}/{path}: {e}")
        return {"status": "error", "message": str(e)}


async def delete_secret(vault_id: str, path: str) -> dict:
    """Supprime un secret et toutes ses versions."""
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
