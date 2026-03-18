# -*- coding: utf-8 -*-
"""
Helpers d'authentification basés sur contextvars.

Le middleware ASGI injecte les infos du token dans les contextvars.
Les outils MCP appellent check_access() et check_write_permission()
pour vérifier les permissions sans dépendre du framework HTTP.
"""

from contextvars import ContextVar
from typing import Optional

# --- Context variables injectées par le middleware ---
current_token_info: ContextVar[Optional[dict]] = ContextVar("current_token_info", default=None)


def check_access(resource_id: str) -> Optional[dict]:
    """
    Vérifie que le token courant a accès à la ressource.

    Args:
        resource_id: ID de la ressource à vérifier

    Returns:
        None si OK, dict {"status": "error", ...} si refusé
    """
    token_info = current_token_info.get()

    # Pas de token → accès refusé
    if token_info is None:
        return {"status": "error", "message": "Authentification requise"}

    # Admin → accès total
    if "admin" in token_info.get("permissions", []):
        return None

    # Vérifier que la ressource est dans les space_ids autorisés
    allowed = token_info.get("space_ids", [])
    if allowed and resource_id not in allowed:
        return {
            "status": "error",
            "message": f"Accès refusé à '{resource_id}'",
            "allowed_spaces": allowed,
        }

    return None


def check_write_permission() -> Optional[dict]:
    """
    Vérifie que le token courant a la permission d'écriture.

    Returns:
        None si OK, dict {"status": "error", ...} si refusé
    """
    token_info = current_token_info.get()

    if token_info is None:
        return {"status": "error", "message": "Authentification requise"}

    permissions = token_info.get("permissions", [])
    if "write" not in permissions and "admin" not in permissions:
        return {"status": "error", "message": "Permission d'écriture requise"}

    return None


def check_admin_permission() -> Optional[dict]:
    """
    Vérifie que le token courant a la permission admin.

    Returns:
        None si OK, dict {"status": "error", ...} si refusé
    """
    token_info = current_token_info.get()

    if token_info is None:
        return {"status": "error", "message": "Authentification requise"}

    if "admin" not in token_info.get("permissions", []):
        return {"status": "error", "message": "Permission admin requise"}

    return None


def get_current_client_name() -> str:
    """Retourne le nom du client courant (depuis le token)."""
    token_info = current_token_info.get()
    if token_info is None:
        return "anonymous"
    return token_info.get("client_name", "unknown")
