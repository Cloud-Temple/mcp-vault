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
    Vérifie que le token courant a accès à la ressource (vault).

    Logique d'autorisation :
    1. Pas de token → refusé
    2. Admin → accès total
    3. allowed_resources non vide → la ressource doit être dans la liste
    4. allowed_resources vide → owner-based isolation :
       seul le créateur du vault y a accès (via _vault_meta.created_by)

    Args:
        resource_id: ID du vault à vérifier

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

    # Liste explicite de vaults autorisés → vérifier l'appartenance.
    # Typage défensif : un allowed_resources non-liste (token mal formé) est
    # traité comme vide (fail-close), jamais comme un motif (ex. sous-chaîne).
    allowed = token_info.get("allowed_resources", [])
    if not isinstance(allowed, list):
        allowed = []
    if allowed:
        if resource_id not in allowed:
            return {
                "status": "error",
                "message": f"Accès refusé à '{resource_id}'",
                "allowed_vaults": allowed,
            }
        return None

    # Identité mission JWT sans périmètre explicite → REFUS (issues #47/#69).
    # Le mission_token ne porte aucune autorisation vault ; le périmètre est
    # provisionné localement (MissionBindingStore, #69) et injecté dans
    # allowed_resources ci-dessus. Quand il est vide (binding absent/désactivé/
    # expiré, ou store indisponible → 503 en amont), cette garde reste le filet
    # fail-close : PAS de fallback owner-based (anti fail-open).
    if token_info.get("auth_type") == "mission_jwt":
        return {
            "status": "error",
            "message": f"Accès refusé à '{resource_id}' "
                       "(aucun périmètre vault provisionné pour cette identité mission)",
        }

    # Liste vide → owner-based isolation
    # Le token n'a accès qu'aux vaults qu'il a créés
    client_name = token_info.get("client_name", "")
    if not client_name:
        # Identité incomplète (ni périmètre explicite, ni propriétaire) → REFUS
        # (fail-close : ne jamais autoriser sur une identité inexploitable).
        return {
            "status": "error",
            "message": f"Accès refusé à '{resource_id}' (identité incomplète)",
        }
    from ..vault.spaces import check_vault_owner
    if not check_vault_owner(resource_id, client_name):
        return {
            "status": "error",
            "message": f"Accès refusé à '{resource_id}' (vous n'en êtes pas le propriétaire)",
        }

    return None


def get_listing_filter() -> dict:
    """
    Projection d'accès pour le LISTING de vaults (vault_list) — source unique.

    Centralise la logique owner-based/allow-list que vault_list réimplémentait en
    ligne, et applique le deny-by-default mission_jwt (issue #47).

    ATTENTION : `list_spaces(allowed_vault_ids=[])` ignore le filtre (liste vide
    falsy) — c'est pourquoi le refus est exprimé par visible=False (court-circuit
    AVANT l'appel à list_spaces), jamais par une liste vide.

    Returns:
        {"visible": bool, "allowed_vault_ids": list|None, "owner_filter": str|None}
    """
    token_info = current_token_info.get()

    if token_info is None:
        # Pas de token : comportement historique (pas de filtre — les déploiements
        # sans auth voient tout, cohérent avec vault_list avant #47).
        return {"visible": True, "allowed_vault_ids": None, "owner_filter": None}

    if "admin" in token_info.get("permissions", []):
        return {"visible": True, "allowed_vault_ids": None, "owner_filter": None}

    allowed = token_info.get("allowed_resources", [])
    if not isinstance(allowed, list):
        allowed = []
    if allowed:
        return {"visible": True, "allowed_vault_ids": allowed, "owner_filter": None}

    if token_info.get("auth_type") == "mission_jwt":
        # Identité mission sans périmètre provisionné → AUCUN vault visible
        # (jamais owner-based — cohérent avec check_access).
        return {"visible": False, "allowed_vault_ids": None, "owner_filter": None}

    # Bearer/bootstrap sans liste explicite → owner-based (inchangé), SAUF si
    # client_name est vide : owner_filter="" serait ignoré par list_spaces (falsy)
    # et listerait TOUT → fail-close (rien de visible) sur identité incomplète.
    client_name = token_info.get("client_name", "")
    if not client_name:
        return {"visible": False, "allowed_vault_ids": None, "owner_filter": None}
    return {"visible": True, "allowed_vault_ids": None, "owner_filter": client_name}


# ── Périmètre outils des identités mission JWT (issues #47 / #69) ───────────────
# Deny-by-default : un mission_jwt ne peut appeler que les outils listés ici.
# DATA-PLANE STRICT (arbitrage produit #69, revue Codex BLOQUANT-3) : une mission
# lit/écrit des SECRETS dans ses coffres autorisés — rien de plus. L'admin-plane
# (vault_create/update/delete, ssh_* : créer/détruire des coffres, gérer des autorités
# SSH) reste RÉSERVÉ aux bearers admin : une mission ne se voit JAMAIS déléguer de
# surface d'administration, même avec le droit d'écriture.
# - Cette allow-list est un PLAFOND DUR : un binding ne peut PAS l'élargir. Les gardes
#   fins (check_access sur le périmètre provisionné, check_write_permission, policies)
#   s'appliquent PAR-DESSUS. secret_write/secret_delete exigent le droit "write".
# - PUBLIC : utilitaires sans donnée ni métadonnée d'infra (enum statique, RNG).
# NON listés (donc refusés aux mission_jwt) : vault_create/update/delete + ssh_*
# (admin-plane), system_health/system_about (exposent openbao_addr/S3/platform — la
# liveness reste publique via HTTP /health), pki_*, policy_*, token_update, audit_log,
# secret_wrap/revoke/lookup (admin-gated). secret_consume n'appelle pas check_policy :
# il s'auto-garde par la validation C18 de son paramètre mission_token.
MISSION_JWT_ALLOWED_TOOLS = frozenset({
    "vault_list", "vault_info",
    "secret_read", "secret_list", "secret_write", "secret_delete",
})

MISSION_JWT_PUBLIC_TOOLS = frozenset({
    "secret_types", "secret_generate_password",
})


def enforce_mission_jwt_tool(tool_name: str) -> Optional[dict]:
    """
    Refuse un outil non autorisé aux identités mission JWT (deny-by-default).

    Appelé par check_policy() (couvre tous les outils qui l'utilisent) ET en
    première ligne des outils sans check (system_health, system_about).
    Sans effet pour les identités bearer/bootstrap.

    Returns:
        None si OK, dict {"status": "error", ...} si refusé.
    """
    token_info = current_token_info.get()
    if token_info is None or token_info.get("auth_type") != "mission_jwt":
        return None

    if tool_name in MISSION_JWT_ALLOWED_TOOLS or tool_name in MISSION_JWT_PUBLIC_TOOLS:
        return None

    # Audit : refus d'outil à une identité mission (événement de sécurité).
    client = token_info.get("client_name", "?")
    try:
        from ..audit import log_audit
        log_audit(
            tool_name, "denied",
            detail=f"Outil non autorisé pour une identité mission "
                   f"(mission={token_info.get('mission_id', '?')})",
            client_name=client,
        )
    except Exception:
        pass

    return {
        "status": "error",
        "message": f"Outil '{tool_name}' non autorisé pour une identité mission",
    }


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


def check_policy(tool_name: str) -> Optional[dict]:
    """
    Vérifie que le token courant a le droit d'utiliser cet outil MCP.

    Logique :
    1. Pas de token → pas de restriction (géré par check_access)
    2. Admin → toujours autorisé
    3. Pas de policy_id → tout autorisé
    4. PolicyStore absent + policy_id présent → fail-close (la policy ne peut être vérifiée)
    5. Policy existe → vérifier via is_tool_allowed()
    6. Policy introuvable dans le store → fail-close (cohérent avec policies.py)

    Args:
        tool_name: Nom de l'outil MCP (ex: "vault_delete", "ssh_sign_key")

    Returns:
        None si OK, dict {"status": "error", ...} si refusé par la policy
    """
    token_info = current_token_info.get()

    # Pas de token → pas de policy à vérifier
    if token_info is None:
        return None

    # Admin → toujours autorisé
    if "admin" in token_info.get("permissions", []):
        return None

    # Identité mission JWT → deny-by-default par allowlist d'outils (issue #47).
    # PLACÉ AVANT le retour permissif "pas de policy_id" : un mission_jwt a
    # policy_id vide et serait sinon autorisé sur tout outil passant par check_policy.
    mission_err = enforce_mission_jwt_tool(tool_name)
    if mission_err:
        return mission_err

    # Pas de policy_id assignée → tout autorisé
    policy_id = token_info.get("policy_id", "")
    if not policy_id:
        return None

    # Vérifier via PolicyStore
    from .policies import get_policy_store

    store = get_policy_store()
    if not store:
        # PolicyStore absent mais token porte un policy_id : on ne peut pas vérifier
        # → fail-close pour éviter qu'une policy soit contournée par indisponibilité S3.
        # Si S3 n'est pas configuré du tout, les tokens n'ont jamais de policy_id.
        client = token_info.get("client_name", "?")
        try:
            from ..audit import log_audit
            log_audit(tool_name, "denied",
                      detail=f"PolicyStore indisponible — policy '{policy_id}' non vérifiable",
                      client_name=client)
        except Exception:
            pass
        return {"status": "error",
                "message": f"PolicyStore indisponible — policy '{policy_id}' ne peut être vérifiée",
                "policy_id": policy_id}

    if store.is_tool_allowed(policy_id, tool_name):
        return None

    # Audit : enregistrer le refus de policy (événement de sécurité)
    client = token_info.get("client_name", "?")
    try:
        from ..audit import log_audit
        log_audit(
            tool_name, "denied",
            detail=f"Bloque par policy '{policy_id}'",
            client_name=client,
        )
    except Exception:
        pass

    return {
        "status": "error",
        "message": f"Outil '{tool_name}' refusé par la policy '{policy_id}'",
        "policy_id": policy_id,
    }


def check_path_policy(vault_id: str, path: str,
                       required_permission: str = "read") -> Optional[dict]:
    """
    Vérifie que le token courant a le droit d'accéder à ce chemin de secret.

    Utilise les path_rules de la policy assignée au token. Vérifie à la fois :
    - que l'opération est permise par la règle (required_permission)
    - que le chemin est dans les allowed_paths de la règle

    Args:
        vault_id: ID du vault
        path: Chemin du secret (ex: "web/github")
        required_permission: "read", "write" (couvre delete), "admin"

    Returns:
        None si OK, dict {"status": "error", ...} si refusé
    """
    token_info = current_token_info.get()

    if token_info is None:
        return None  # Pas de token → pas de restriction path

    if "admin" in token_info.get("permissions", []):
        return None  # Admin → tout autorisé

    policy_id = token_info.get("policy_id", "")
    if not policy_id:
        return None  # Pas de policy → pas de restriction

    from .policies import get_policy_store

    store = get_policy_store()
    if not store:
        # Fail-close cohérent avec check_policy() : policy_id présent sans PolicyStore → refus
        client = token_info.get("client_name", "?")
        try:
            from ..audit import log_audit
            log_audit(f"secret_{required_permission}", "denied",
                      detail=f"PolicyStore indisponible — path policy '{policy_id}' non vérifiable",
                      client_name=client, vault_id=vault_id)
        except Exception:
            pass
        return {"status": "error",
                "message": f"PolicyStore indisponible — path policy '{policy_id}' ne peut être vérifiée",
                "policy_id": policy_id}

    if store.is_path_allowed(policy_id, vault_id, path, required_permission):
        return None

    # Refusé — log audit
    client = token_info.get("client_name", "?")
    try:
        from ..audit import log_audit
        log_audit(
            f"secret_{required_permission}", "denied",
            detail=f"Chemin '{path}' dans '{vault_id}' bloque par policy '{policy_id}'",
            client_name=client,
            vault_id=vault_id,
        )
    except Exception:
        pass

    return {
        "status": "error",
        "message": (
            f"Accès refusé au chemin '{path}' dans '{vault_id}' (policy '{policy_id}')"
            if path else
            f"Accès refusé au vault '{vault_id}' (policy '{policy_id}')"
        ),
        "policy_id": policy_id,
    }


def get_current_client_name() -> str:
    """Retourne le nom du client courant (depuis le token)."""
    token_info = current_token_info.get()
    if token_info is None:
        return "anonymous"
    return token_info.get("client_name", "unknown")
