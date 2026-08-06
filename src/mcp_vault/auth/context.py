# -*- coding: utf-8 -*-
"""
Helpers d'authentification basés sur contextvars.

Le middleware ASGI injecte les infos du token dans les contextvars.
Les outils MCP appellent check_access() et check_write_permission()
pour vérifier les permissions sans dépendre du framework HTTP.
"""

from contextvars import ContextVar
from typing import Optional

from ..vault_ids import is_valid_vault_id

# --- Context variables injectées par le middleware ---
current_token_info: ContextVar[Optional[dict]] = ContextVar("current_token_info", default=None)


def check_access(resource_id: str) -> Optional[dict]:
    """
    Vérifie que le token courant a accès à la ressource (vault).

    Logique d'autorisation :
    1. Pas de token → refusé
    2. Admin → accès total
    3. resource_id non canonique → refusé (cf. sécurité ci-dessous)
    4. allowed_resources non vide → la ressource doit être dans la liste
    5. allowed_resources vide → owner-based isolation :
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

    # SÉCURITÉ (découverte en revue adversariale round 3, PR #97/issue #96,
    # 2026-07-22) : valider resource_id AVANT toute décision d'autorisation.
    # check_vault_owner() (vault/spaces.py) teste l'existence du mount via
    # `f"{vault_id}/" not in mounts` puis AUTORISE si absent (cas "vault pas
    # encore créé"). Un resource_id non canonique (ex. slash final,
    # "agentic-platform/") fait chercher un mount qui ne matchera jamais un
    # mount réel ("agentic-platform//" au lieu de "agentic-platform/") : le
    # vault EXISTANT est alors traité comme absent, et l'appelant — même non
    # propriétaire, même sans allowed_resources — se voit autorisé. Bloquer
    # ici, avant le branchement liste/owner-based, ferme les deux chemins
    # d'un coup, y compris pour un futur appelant qui oublierait de valider.
    if not is_valid_vault_id(resource_id):
        return {
            "status": "error",
            "message": f"Identifiant de coffre invalide : '{resource_id}'",
        }

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
# secret_wrap/revoke/lookup/status (permission wrap ou admin requise depuis #115 ;
# leurs check_policy matérialisent désormais ce deny-by-default pour les missions).
# secret_consume n'appelle pas check_policy : il s'auto-garde par la validation C18
# de son paramètre mission_token (+ refus des bearers wrap-only, #115).
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


# ── Permission `wrap` — broker JIT non-admin (issue #115) ────────────────────
# Un token `wrap` est destiné au broker de credentials mcp-mission : il ne doit
# pouvoir QUE créer/révoquer/consulter des wraps, dans un périmètre vault+chemins
# provisionné explicitement. Trois gardes coopèrent :
#   - check_wrap_permission() : flag wrap (ou admin) + allow-list + policy
#     explicite OBLIGATOIRES (pas de fallback owner-based, pas de « policy
#     absente = tout permis ») ;
#   - enforce_wrap_only_token() : un token wrap SANS read/write/admin est
#     confiné aux 4 outils wrap (deny-by-default, comme les identités mission) ;
#   - check_wrap_path_policy() : évaluation STRICTE des chemins (pas de règle =
#     refus, allowed_paths vide = refus) via PolicyStore.

WRAP_ONLY_ALLOWED_TOOLS = frozenset({
    "secret_wrap", "secret_revoke_wrap", "secret_wrap_lookup", "secret_wrap_status",
})


def is_wrap_only_token(token_info) -> bool:
    """Token portant `wrap` SANS aucun de read/write/admin.

    Un composite (ex. ["read","wrap"]) n'est PAS wrap-only : il conserve ses
    droits read — choix explicite, signalé par la SPA à la création. Le
    déploiement broker nominal utilise ["wrap"] seul.
    """
    if not isinstance(token_info, dict):
        return False
    perms = token_info.get("permissions", [])
    if not isinstance(perms, list):
        return False
    return "wrap" in perms and not ({"read", "write", "admin"} & set(
        p for p in perms if isinstance(p, str)))


def enforce_wrap_only_token(tool_name: str) -> Optional[dict]:
    """
    Refuse un outil hors WRAP_ONLY_ALLOWED_TOOLS à un token wrap-only.

    Appelé par check_policy() (couvre tous les outils qui l'utilisent) ET en
    première ligne des outils sans check_policy accessibles sans admin
    (system_health, system_about, secret_types, secret_generate_password,
    secret_consume). Sans effet pour les autres identités ; token absent →
    None (déploiements sans auth inchangés — jamais traité comme wrap-only
    NI comme admin).

    Returns:
        None si OK, dict {"status": "error", ...} si refusé.
    """
    token_info = current_token_info.get()
    if not is_wrap_only_token(token_info):
        return None

    if tool_name in WRAP_ONLY_ALLOWED_TOOLS:
        return None

    # Audit : refus d'outil à un token wrap-only (événement de sécurité).
    client = token_info.get("client_name", "?")
    try:
        from ..audit import log_audit
        log_audit(
            tool_name, "denied",
            detail="Outil non autorisé pour un token wrap-only",
            client_name=client,
        )
    except Exception:
        pass

    return {
        "status": "error",
        "message": f"Outil '{tool_name}' non autorisé pour un token wrap "
                   "(périmètre limité au broker JIT)",
    }


def check_wrap_permission() -> Optional[dict]:
    """
    Vérifie que le token courant peut utiliser les outils du broker JIT.

    Accepte `admin` (rétrocompat #115) ou `wrap`. Pour un usage NON-admin de
    `wrap`, l'invariant de moindre privilège est EXÉCUTABLE, pas documentaire :
    - allowed_resources non vide OBLIGATOIRE (pas de fallback owner-based) ;
    - policy_id non vide OBLIGATOIRE ;
    - la policy doit porter des allowed_tools EXPLICITES (une policy « vide »
      serait permissive via is_tool_allowed — refusée ici) ;
    - PolicyStore absent/indisponible → refus fail-close observable.

    L'autorisation de l'outil lui-même (allowed_tools/denied_tools) est
    vérifiée par check_policy(), appelé AVANT cette garde par les 4 outils.

    Returns:
        None si OK, dict {"status": "error", ...} si refusé
    """
    token_info = current_token_info.get()

    if token_info is None:
        return {"status": "error", "message": "Authentification requise"}

    permissions = token_info.get("permissions", [])
    if "admin" in permissions:
        return None

    if "wrap" not in permissions:
        return {"status": "error", "message": "Permission wrap (ou admin) requise"}

    client = token_info.get("client_name", "?")

    allowed = token_info.get("allowed_resources", [])
    if not isinstance(allowed, list) or not allowed:
        return {
            "status": "error",
            "message": "Un token wrap exige une allow-list de vaults non vide "
                       "(allowed_resources) — pas de fallback owner-based",
        }

    policy_id = token_info.get("policy_id", "")
    if not isinstance(policy_id, str) or not policy_id:
        return {
            "status": "error",
            "message": "Un token wrap exige une policy applicative explicite "
                       "(policy_id)",
        }

    from .policies import get_policy_store, PolicyStoreUnavailable

    store = get_policy_store()
    if not store:
        _audit_denied("secret_wrap", f"PolicyStore indisponible — policy "
                      f"'{policy_id}' non vérifiable (token wrap)", client)
        return {"status": "error", "error_type": "policy_store_unavailable",
                "message": f"PolicyStore indisponible — policy '{policy_id}' "
                           "ne peut être vérifiée"}

    try:
        explicit_tools = store.has_explicit_allowed_tools(policy_id)
    except PolicyStoreUnavailable as e:
        _audit_denied("secret_wrap", f"PolicyStore indisponible — policy "
                      f"'{policy_id}' non vérifiable ({e})", client)
        return {"status": "error", "error_type": "policy_store_unavailable",
                "message": f"PolicyStore indisponible — policy '{policy_id}' "
                           "ne peut être vérifiée"}

    if not explicit_tools:
        _audit_denied("secret_wrap", f"Policy '{policy_id}' sans allowed_tools "
                      "explicites — requis pour un token wrap", client)
        return {
            "status": "error",
            "message": f"La policy '{policy_id}' doit déclarer des allowed_tools "
                       "explicites pour un token wrap (une policy sans allow-list "
                       "d'outils serait permissive)",
            "policy_id": policy_id,
        }

    return None


def check_wrap_path_policy(vault_id: str, secret_path: str,
                           audit: bool = True) -> Optional[dict]:
    """
    Évaluation STRICTE du chemin pour une identité wrap non-admin (issue #115).

    Contrairement à check_path_policy (pas de règle matchante ou allowed_paths
    vide = autorisé), la variante stricte exige une path_rule matchante avec
    allowed_paths non vide (PolicyStore.is_wrap_path_strictly_allowed — même
    first-match, même fnmatch : aucune divergence PDP/PEP). Admin → bypass
    (comportement actuel). Utilisée par secret_wrap ET par le filtre de
    visibilité du registre de wraps (symétrie création/visibilité).

    Args:
        audit: False pour une évaluation SILENCIEUSE (filtre de visibilité du
            registre : une entrée hors scope est un cas nominal, pas un refus
            d'opération — même précédent que can_read_vault_content).

    Returns:
        None si OK, dict {"status": "error", ...} si refusé
    """
    token_info = current_token_info.get()

    if token_info is None:
        return {"status": "error", "message": "Authentification requise"}

    if "admin" in token_info.get("permissions", []):
        return None

    client = token_info.get("client_name", "?")
    policy_id = token_info.get("policy_id", "")
    if not isinstance(policy_id, str) or not policy_id:
        # check_wrap_permission (appelée avant) refuse déjà ce cas ; garde
        # conservée pour les appels directs (filtre registre) — fail-close.
        return {"status": "error",
                "message": "Un token wrap exige une policy applicative explicite"}

    from .policies import get_policy_store, PolicyStoreUnavailable

    store = get_policy_store()
    if not store:
        if audit:
            _audit_denied("secret_wrap", f"PolicyStore indisponible — path policy "
                          f"'{policy_id}' non vérifiable (strict)", client,
                          vault_id=vault_id)
        return {"status": "error", "error_type": "policy_store_unavailable",
                "message": f"PolicyStore indisponible — policy '{policy_id}' "
                           "ne peut être vérifiée"}

    try:
        allowed = store.is_wrap_path_strictly_allowed(policy_id, vault_id, secret_path)
    except PolicyStoreUnavailable as e:
        if audit:
            _audit_denied("secret_wrap", f"PolicyStore indisponible — path policy "
                          f"'{policy_id}' non vérifiable ({e})", client,
                          vault_id=vault_id)
        return {"status": "error", "error_type": "policy_store_unavailable",
                "message": f"PolicyStore indisponible — policy '{policy_id}' "
                           "ne peut être vérifiée"}

    if allowed:
        return None

    if audit:
        _audit_denied("secret_wrap",
                      f"Chemin '{secret_path}' dans '{vault_id}' refusé par la "
                      f"policy '{policy_id}' (évaluation stricte wrap)", client,
                      vault_id=vault_id)
    return {
        "status": "error",
        "message": f"Accès refusé au chemin '{secret_path}' dans '{vault_id}' "
                   f"(policy '{policy_id}', évaluation stricte : une path_rule "
                   "matchante avec allowed_paths explicites est requise)",
        "policy_id": policy_id,
    }


def _audit_denied(tool_name: str, detail: str, client: str,
                  vault_id: str = None) -> None:
    """Journalise un refus d'autorisation sans jamais faire échouer la garde."""
    try:
        from ..audit import log_audit
        if vault_id is not None:
            log_audit(tool_name, "denied", detail=detail, client_name=client,
                      vault_id=vault_id)
        else:
            log_audit(tool_name, "denied", detail=detail, client_name=client)
    except Exception:
        pass


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

    # Token wrap-only → confiné aux 4 outils du broker JIT (issue #115).
    # PLACÉ AVANT l'évaluation de policy : une policy mal configurée qui
    # autoriserait secret_read ne doit pas élargir le périmètre d'un wrap-only.
    wrap_err = enforce_wrap_only_token(tool_name)
    if wrap_err:
        return wrap_err

    policy_id = token_info.get("policy_id", "")
    # issue #86 Lot 3 (round 3 diff review) : un policy_id de type invalide dans
    # le TOKEN LUI-MÊME (donnée corrompue — au chargement TokenStore, pas
    # seulement à la création) est falsy comme une chaîne vide et serait sinon
    # traité comme "pas de policy" (tout autorisé) au lieu d'un refus fail-close.
    # Défense en profondeur au dernier point de décision, indépendamment de la
    # façon dont la donnée corrompue serait arrivée jusqu'ici.
    if not isinstance(policy_id, str):
        return {"status": "error",
                "message": "Token corrompu (policy_id invalide) — accès refusé"}
    # Pas de policy_id assignée → tout autorisé
    if not policy_id:
        return None

    # Vérifier via PolicyStore
    from .policies import get_policy_store, PolicyStoreUnavailable

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
        return {"status": "error", "error_type": "policy_store_unavailable",
                "message": f"PolicyStore indisponible — policy '{policy_id}' ne peut être vérifiée",
                "policy_id": policy_id}

    # issue #86 Lot 3 : panne/corruption S3 détectée après TTL → refus OBSERVABLE,
    # jamais une décision silencieuse basée sur la dernière policy connue en cache.
    try:
        allowed = store.is_tool_allowed(policy_id, tool_name)
    except PolicyStoreUnavailable as e:
        client = token_info.get("client_name", "?")
        try:
            from ..audit import log_audit
            log_audit(tool_name, "denied",
                      detail=f"PolicyStore indisponible — policy '{policy_id}' non vérifiable ({e})",
                      client_name=client)
        except Exception:
            pass
        return {"status": "error", "error_type": "policy_store_unavailable",
                "message": f"PolicyStore indisponible — policy '{policy_id}' ne peut être vérifiée",
                "policy_id": policy_id}

    if allowed:
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
    # issue #86 Lot 3 (round 3 diff review) : voir check_policy() — même défense
    # en profondeur contre un policy_id de type invalide dans le token.
    if not isinstance(policy_id, str):
        return {"status": "error",
                "message": "Token corrompu (policy_id invalide) — accès refusé"}
    if not policy_id:
        return None  # Pas de policy → pas de restriction

    from .policies import get_policy_store, PolicyStoreUnavailable

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
        return {"status": "error", "error_type": "policy_store_unavailable",
                "message": f"PolicyStore indisponible — path policy '{policy_id}' ne peut être vérifiée",
                "policy_id": policy_id}

    # issue #86 Lot 3 : panne/corruption S3 détectée après TTL → refus OBSERVABLE.
    try:
        path_allowed = store.is_path_allowed(policy_id, vault_id, path, required_permission)
    except PolicyStoreUnavailable as e:
        client = token_info.get("client_name", "?")
        try:
            from ..audit import log_audit
            log_audit(f"secret_{required_permission}", "denied",
                      detail=f"PolicyStore indisponible — path policy '{policy_id}' non vérifiable ({e})",
                      client_name=client, vault_id=vault_id)
        except Exception:
            pass
        return {"status": "error", "error_type": "policy_store_unavailable",
                "message": f"PolicyStore indisponible — path policy '{policy_id}' ne peut être vérifiée",
                "policy_id": policy_id}

    if path_allowed:
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


def can_read_vault_content(vault_id: str) -> bool:
    """
    Indique si l'identité courante a le droit de LISTER le contenu d'un vault
    (capability `secret_list` + path policy racine), calculé **sans effet de bord
    d'audit**.

    SÉCURITÉ #81 : sert à décider d'exposer une **cardinalité** (nombre d'entrées
    d'un vault) sans divulguer le contenu à une identité qui n'a pas le droit de
    lister — et sans générer de faux événement `denied` (ce que feraient
    `check_policy`/`check_path_policy`/`enforce_mission_jwt_tool`, qui journalisent
    les refus). Reprend leur logique de décision en version silencieuse ; ces
    fonctions restent la référence pour les vraies opérations. L'accès au vault
    lui-même est supposé déjà validé par `check_access()` chez l'appelant.
    """
    token_info = current_token_info.get()
    if token_info is None:
        return True
    if "admin" in token_info.get("permissions", []):
        return True
    if token_info.get("auth_type") == "mission_jwt":
        # Capability outil (deny-by-default) évaluée sans auditer. On NE retourne
        # PAS True ici : une mission peut être restreinte par un policy_id
        # (path_rules) — on poursuit l'évaluation policy commune ci-dessous, pour
        # s'aligner exactement sur check_policy + check_path_policy (#81 R3, sinon
        # sur-autorisation : compteur exposé malgré une policy qui refuse).
        if not ("secret_list" in MISSION_JWT_ALLOWED_TOOLS
                or "secret_list" in MISSION_JWT_PUBLIC_TOOLS):
            return False
    policy_id = token_info.get("policy_id", "")
    # issue #86 Lot 3 (round 3 diff review) : même défense en profondeur que
    # check_policy()/check_path_policy() contre un policy_id de type invalide.
    if not isinstance(policy_id, str):
        return False
    if not policy_id:
        return True
    from .policies import get_policy_store, PolicyStoreUnavailable
    store = get_policy_store()
    if not store:
        return False  # fail-close, cohérent avec check_policy/check_path_policy
    # issue #86 Lot 3 : store indisponible (panne/corruption détectée) → False,
    # cohérent avec le fail-close de check_policy/check_path_policy. Pas d'audit
    # ici (fonction volontairement silencieuse, cf. docstring).
    try:
        return bool(store.is_tool_allowed(policy_id, "secret_list")
                    and store.is_path_allowed(policy_id, vault_id, "", "read"))
    except PolicyStoreUnavailable:
        return False


def get_current_client_name() -> str:
    """Retourne le nom du client courant (depuis le token)."""
    token_info = current_token_info.get()
    if token_info is None:
        return "anonymous"
    return token_info.get("client_name", "unknown")
