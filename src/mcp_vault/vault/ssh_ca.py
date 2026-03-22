# -*- coding: utf-8 -*-
"""
SSH Certificate Authority — Signature de clés publiques SSH.

Chaque vault peut avoir sa propre CA SSH (mount ssh engine par vault).
Les agents demandent la signature de leur clé publique et reçoivent
un certificat éphémère pour se connecter aux serveurs cibles.
"""

import logging

from ..openbao.manager import get_hvac_client

logger = logging.getLogger("mcp-vault.ssh-ca")

# Préfixe pour le mount path SSH dans OpenBao
SSH_MOUNT_PREFIX = "ssh-ca-"


def _ssh_mount_point(vault_id: str) -> str:
    """Mount point SSH pour un vault donné."""
    return f"{SSH_MOUNT_PREFIX}{vault_id}"


async def setup_ssh_ca(vault_id: str, role_name: str, allowed_users: str = "*",
                       default_user: str = "ubuntu", ttl: str = "30m") -> dict:
    """
    Configure un rôle SSH CA dans un espace vault.

    1. Monte le SSH secrets engine (si pas déjà monté)
    2. Génère la paire de clés CA (si pas déjà générée)
    3. Crée le rôle SSH
    """
    client = get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    mount_point = _ssh_mount_point(vault_id)

    try:
        # 1. Monter le SSH engine (ignore si déjà monté)
        try:
            client.sys.enable_secrets_engine(
                backend_type="ssh",
                path=mount_point,
                description=f"SSH CA for vault {vault_id}",
            )
            logger.info(f"✅ SSH engine monté: {mount_point}")
        except Exception as e:
            if "existing mount" not in str(e).lower() and "path is already in use" not in str(e).lower():
                raise

        # 2. Générer la CA (ignore si déjà générée)
        try:
            client.write(
                f"{mount_point}/config/ca",
                generate_signing_key=True,
            )
            logger.info(f"✅ CA SSH générée pour {vault_id}")
        except Exception:
            pass  # Déjà générée

        # 3. Créer le rôle
        client.write(
            f"{mount_point}/roles/{role_name}",
            key_type="ca",
            ttl=ttl,
            allowed_users=allowed_users,
            default_user=default_user,
            allow_user_certificates=True,
        )
        logger.info(f"✅ Rôle SSH créé: {role_name} dans {vault_id}")

        return {
            "status": "ok",
            "vault_id": vault_id,
            "role_name": role_name,
            "mount_point": mount_point,
            "allowed_users": allowed_users,
            "default_user": default_user,
            "ttl": ttl,
        }
    except Exception as e:
        logger.error(f"❌ Erreur setup SSH CA {vault_id}: {e}")
        return {"status": "error", "message": str(e)}


async def sign_ssh_key(vault_id: str, role_name: str, public_key: str,
                       ttl: str = "30m") -> dict:
    """Signe une clé publique SSH avec la CA du vault."""
    client = get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    mount_point = _ssh_mount_point(vault_id)

    try:
        response = client.write(
            f"{mount_point}/sign/{role_name}",
            public_key=public_key,
            ttl=ttl,
        )
        signed_key = response.get("data", {}).get("signed_key", "")
        serial = response.get("data", {}).get("serial_number", "")

        logger.info(f"✅ Clé SSH signée: rôle={role_name}, serial={serial}")
        return {
            "status": "ok",
            "signed_key": signed_key,
            "serial_number": serial,
            "ttl": ttl,
        }
    except Exception as e:
        logger.error(f"❌ Erreur signature SSH {vault_id}/{role_name}: {e}")
        return {"status": "error", "message": str(e)}


async def get_ca_public_key(vault_id: str) -> dict:
    """Récupère la clé publique de la CA SSH."""
    client = get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    mount_point = _ssh_mount_point(vault_id)

    try:
        response = client.read(f"{mount_point}/config/ca")
        public_key = response.get("data", {}).get("public_key", "")

        return {
            "status": "ok",
            "vault_id": vault_id,
            "public_key": public_key,
            "usage": "Ajouter dans /etc/ssh/trusted-user-ca-keys.pem sur les serveurs cibles",
        }
    except Exception as e:
        logger.error(f"❌ Erreur lecture CA publique {vault_id}: {e}")
        return {"status": "error", "message": str(e)}


async def list_ssh_roles(vault_id: str) -> dict:
    """
    Liste les rôles SSH CA configurés dans un vault.

    Retourne la liste des noms de rôles disponibles pour la signature.
    """
    client = get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    mount_point = _ssh_mount_point(vault_id)

    try:
        response = client.list(f"{mount_point}/roles")
        roles = response.get("data", {}).get("keys", [])

        logger.info(f"📋 Rôles SSH listés pour {vault_id}: {roles}")
        return {
            "status": "ok",
            "vault_id": vault_id,
            "roles": roles,
            "count": len(roles),
        }
    except Exception as e:
        error_msg = str(e).lower()
        # Si aucun rôle n'existe, OpenBao retourne une 404
        if "404" in error_msg or "no entries" in error_msg:
            return {
                "status": "ok",
                "vault_id": vault_id,
                "roles": [],
                "count": 0,
            }
        logger.error(f"❌ Erreur listing rôles SSH {vault_id}: {e}")
        return {"status": "error", "message": str(e)}


async def get_ssh_role_info(vault_id: str, role_name: str) -> dict:
    """
    Récupère les détails d'un rôle SSH CA.

    Retourne : key_type, ttl, max_ttl, allowed_users, default_user,
    allowed_extensions, allow_user_certificates, etc.
    """
    client = get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    mount_point = _ssh_mount_point(vault_id)

    try:
        response = client.read(f"{mount_point}/roles/{role_name}")
        if not response or not response.get("data"):
            return {"status": "error", "message": f"Rôle SSH '{role_name}' non trouvé dans vault '{vault_id}'"}

        data = response["data"]

        return {
            "status": "ok",
            "vault_id": vault_id,
            "role_name": role_name,
            "key_type": data.get("key_type", ""),
            "ttl": data.get("ttl", ""),
            "max_ttl": data.get("max_ttl", ""),
            "default_user": data.get("default_user", ""),
            "allowed_users": data.get("allowed_users", ""),
            "allowed_extensions": data.get("allowed_extensions", ""),
            "allow_user_certificates": data.get("allow_user_certificates", False),
            "allow_host_certificates": data.get("allow_host_certificates", False),
        }
    except Exception as e:
        logger.error(f"❌ Erreur info rôle SSH {vault_id}/{role_name}: {e}")
        return {"status": "error", "message": str(e)}


async def cleanup_ssh_ca(vault_id: str) -> bool:
    """
    Supprime le mount SSH CA d'un vault (appelé lors de vault_delete).

    Retourne True si le mount a été supprimé ou n'existait pas, False en cas d'erreur.
    """
    client = get_hvac_client()
    if not client:
        return False

    mount_point = _ssh_mount_point(vault_id)

    try:
        # Vérifier si le mount SSH existe avant de le supprimer
        mounts = client.sys.list_mounted_secrets_engines()
        mount_key = f"{mount_point}/"
        if mount_key in mounts.get("data", mounts):
            client.sys.disable_secrets_engine(path=mount_point)
            logger.info(f"🗑️ SSH CA supprimée pour vault {vault_id} (mount: {mount_point})")
        else:
            logger.debug(f"ℹ️ Pas de SSH CA à supprimer pour vault {vault_id}")
        return True
    except Exception as e:
        logger.warning(f"⚠️ Erreur suppression SSH CA {vault_id}: {e}")
        return False
