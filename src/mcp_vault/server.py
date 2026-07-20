# -*- coding: utf-8 -*-
"""
MCP Vault — Serveur principal.

Stack ASGI :
    AdminMiddleware → HealthCheckMiddleware → AuthMiddleware → LoggingMiddleware → FastMCP

Lifecycle :
    startup  → S3 download → OpenBao start → unseal
    shutdown → seal → S3 upload
"""

import logging
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .config import get_settings

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("mcp-vault")

# --- Settings ---
settings = get_settings()


import time as _time

_TOOL_LABELS = {
    "vault_create": "Création vault", "vault_list": "Liste vaults",
    "vault_info": "Détails vault", "vault_update": "Modification vault",
    "vault_delete": "Suppression vault",
    "secret_write": "Écriture secret", "secret_read": "Lecture secret",
    "secret_list": "Liste secrets", "secret_delete": "Suppression secret",
    "ssh_ca_setup": "Setup SSH CA", "ssh_sign_key": "Signature clé SSH",
    "ssh_ca_public_key": "Clé publique CA", "ssh_ca_list_roles": "Liste rôles SSH",
    "ssh_ca_role_info": "Détails rôle SSH",
    "policy_create": "Création policy", "policy_list": "Liste policies",
    "policy_get": "Détails policy", "policy_delete": "Suppression policy",
    "token_update": "Modification token", "audit_log": "Consultation audit",
    "pki_ca_setup": "Setup PKI CA", "pki_ca_public_key": "Clé publique CA PKI",
    "pki_ca_list_roles": "Liste rôles PKI", "pki_ca_role_info": "Détails rôle PKI",
    "pki_list_certs": "Inventaire certs PKI", "pki_revoke_cert": "Révocation cert PKI",
    "pki_issue_cert": "Émission cert PKI",
    "pki_ca_rotate_intermediate": "Rotation intermédiaire PKI",
    "secret_consume": "Consommation médiée (C18)",
}

def _r(tool: str, result: dict, vault_id: str = "", detail: str = "") -> dict:
    """Log audit event with human-readable detail, and return result."""
    from .audit import log_audit
    status = result.get("status", "?") if isinstance(result, dict) else "?"
    # Build a readable detail message (no emojis — breaks CLI table alignment)
    label = _TOOL_LABELS.get(tool, tool)
    parts = [label]
    if vault_id:
        parts.append(f"[{vault_id}]")
    if detail:
        parts.append(detail)
    if status in ("error",):
        msg = result.get("message", "") if isinstance(result, dict) else ""
        if msg:
            parts.append(f"- {msg[:60]}")
    readable = " ".join(parts)
    log_audit(tool, status, vault_id, readable)
    return result

# --- FastMCP instance ---
def _build_transport_security(cfg=None):
    """
    Construit les réglages anti-DNS-rebinding du SDK MCP pour le transport
    streamable-http.

    Sans ce réglage explicite, FastMCP auto-active la protection avec pour seul
    `host` le loopback (défaut interne 127.0.0.1), ce qui rejette toute requête
    portant le FQDN public en HTTP 421 « Invalid Host header » (cf. issue #3).

    Le loopback reste TOUJOURS autorisé (health checks internes, tests e2e via le
    WAF localhost). Les FQDN publics proviennent de la config (MCP_ALLOWED_HOSTS) ;
    pour chacun on autorise aussi la variante avec port (`fqdn:*`) et on dérive
    systématiquement l'origin `https://fqdn`. MCP_ALLOWED_ORIGINS ajoute d'éventuelles
    origins supplémentaires (sans remplacer les origins dérivées).

    NB : le matcher du SDK ne gère le wildcard que sur le port (`base:*`), pas sur
    les sous-domaines — chaque FQDN doit donc être listé explicitement. Les FQDN sont
    normalisés en minuscules (DNS insensible à la casse, matcher SDK sensible) ; les
    doublons sont éliminés en conservant l'ordre.

    Args:
        cfg: Settings à utiliser (défaut : la config globale du module). Paramétrable
             pour faciliter les tests unitaires.
    """
    from mcp.server.transport_security import TransportSecuritySettings

    cfg = cfg or settings

    hosts = ["localhost", "127.0.0.1", "localhost:*", "127.0.0.1:*", "[::1]", "[::1]:*"]
    origins = ["http://localhost:*", "http://127.0.0.1:*", "http://[::1]:*"]

    for fqdn in cfg.allowed_hosts_list:
        hosts.extend([fqdn, f"{fqdn}:*"])
        origins.append(f"https://{fqdn}")

    origins.extend(cfg.allowed_origins_list)

    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=list(dict.fromkeys(hosts)),
        allowed_origins=list(dict.fromkeys(origins)),
    )


mcp = FastMCP(
    settings.mcp_server_name,
    instructions="MCP Vault — Gestion sécurisée des secrets pour agents IA (OpenBao embedded)",
    transport_security=_build_transport_security(),
)


# ═══════════════════════════════════════════════════════════════════════
# OUTILS MCP — System
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def system_health() -> dict:
    """
    Vérifie l'état de santé du service MCP Vault.

    Teste la connectivité OpenBao et S3, retourne le statut de chaque service.
    """
    from .auth.context import enforce_mission_jwt_tool

    # Refusé aux identités mission JWT : expose des métadonnées d'infrastructure
    # (détails OpenBao/S3, bucket, exceptions). La liveness reste disponible sans
    # auth via l'endpoint HTTP /health (HealthCheckMiddleware).
    # Garde placée AVANT les imports backend (refuser sans rien charger).
    mission_err = enforce_mission_jwt_tool("system_health")
    if mission_err:
        return mission_err

    from .openbao.lifecycle import get_vault_status
    from .s3_sync import check_s3_connectivity

    openbao_ok, openbao_detail = await get_vault_status()
    s3_ok, s3_detail = await check_s3_connectivity()

    all_ok = openbao_ok and s3_ok
    return {
        "status": "ok" if all_ok else "degraded",
        "services": {
            "openbao": {"status": "ok" if openbao_ok else "error", "detail": openbao_detail},
            "s3": {"status": "ok" if s3_ok else "error", "detail": s3_detail},
        },
    }


@mcp.tool()
async def system_about() -> dict:
    """
    Informations sur le service MCP Vault.

    Retourne la version, les outils disponibles, et les infos système.
    """
    import platform
    from .auth.context import enforce_mission_jwt_tool

    # Refusé aux identités mission JWT : expose openbao_addr, platform, python,
    # tools_count (reconnaissance d'infrastructure).
    mission_err = enforce_mission_jwt_tool("system_about")
    if mission_err:
        return mission_err

    return {
        "service": settings.mcp_server_name,
        "description": "MCP Vault — Gestion sécurisée des secrets pour agents IA",
        "version": Path("VERSION").read_text().strip() if Path("VERSION").exists() else "0.1.0",
        "openbao_addr": settings.openbao_addr,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "tools_count": len(mcp._tool_manager._tools) if hasattr(mcp, "_tool_manager") else "unknown",
    }


# ═══════════════════════════════════════════════════════════════════════
# OUTILS MCP — Vaults (coffres de secrets, mount KV v2)
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def vault_create(vault_id: str, description: str = "") -> dict:
    """
    Crée un nouveau vault (coffre de secrets, mount KV v2 dans OpenBao).

    Args:
        vault_id: Identifiant unique du vault (alphanum + tirets)
        description: Description optionnelle du vault
    """
    from .auth.context import check_access, check_write_permission, check_policy
    from .vault.spaces import create_space

    policy_err = check_policy("vault_create")
    if policy_err:
        return policy_err
    access_err = check_access(vault_id)
    if access_err:
        return access_err
    write_err = check_write_permission()
    if write_err:
        return write_err

    return _r("vault_create", await create_space(vault_id, description), vault_id)


@mcp.tool()
async def vault_list() -> dict:
    """Liste tous les vaults (coffres de secrets) accessibles par le token courant."""
    from .auth.context import check_policy, get_listing_filter
    from .vault.spaces import list_spaces

    policy_err = check_policy("vault_list")
    if policy_err:
        return policy_err

    # ── Filtrage par token : projection centralisée (issue #47) ─────
    # get_listing_filter applique admin/allow-list/owner-based ET le
    # deny-by-default mission_jwt. Court-circuit si rien n'est visible :
    # list_spaces([]) ignorerait le filtre (liste vide falsy).
    listing = get_listing_filter()
    if not listing["visible"]:
        return _r("vault_list", {"status": "ok", "vaults": [], "count": 0})

    return _r("vault_list", await list_spaces(
        allowed_vault_ids=listing["allowed_vault_ids"],
        owner_filter=listing["owner_filter"],
    ))


@mcp.tool()
async def vault_info(vault_id: str) -> dict:
    """
    Informations détaillées sur un vault.

    Args:
        vault_id: Identifiant du vault
    """
    from .auth.context import check_access, check_policy, can_read_vault_content
    from .vault.spaces import get_space_info

    policy_err = check_policy("vault_info")
    if policy_err:
        return policy_err
    access_err = check_access(vault_id)
    if access_err:
        return access_err

    # #81 : n'exposer la cardinalité (secrets_count/root_entries_count) que si
    # l'identité peut LISTER le contenu (moindre privilège). Test silencieux, sans
    # faux 'denied'. Une identité autorisée conserve le compteur (contrat inchangé).
    return _r("vault_info",
              await get_space_info(vault_id, count=can_read_vault_content(vault_id)),
              vault_id)


@mcp.tool()
async def vault_update(vault_id: str, description: str = "") -> dict:
    """
    Met à jour les métadonnées d'un vault (description).

    Args:
        vault_id: Identifiant du vault à modifier
        description: Nouvelle description du vault
    """
    from .auth.context import check_access, check_write_permission, check_policy
    from .vault.spaces import update_space

    policy_err = check_policy("vault_update")
    if policy_err:
        return policy_err
    access_err = check_access(vault_id)
    if access_err:
        return access_err
    write_err = check_write_permission()
    if write_err:
        return write_err

    if not description:
        return {"status": "error", "message": "Au moins un champ à modifier est requis (description)"}

    return _r("vault_update", await update_space(vault_id, description), vault_id)


@mcp.tool()
async def vault_delete(vault_id: str, confirm: bool = False) -> dict:
    """
    Supprime un vault et TOUS ses secrets (irréversible).

    Args:
        vault_id: Identifiant du vault à supprimer
        confirm: Doit être True pour confirmer la suppression
    """
    from .auth.context import check_access, check_admin_permission, check_policy
    from .vault.spaces import delete_space

    policy_err = check_policy("vault_delete")
    if policy_err:
        return policy_err
    access_err = check_access(vault_id)
    if access_err:
        return access_err
    admin_err = check_admin_permission()
    if admin_err:
        return admin_err

    if not confirm:
        return {"status": "error", "message": "confirm=True requis pour supprimer un vault"}

    # SÉCURITÉ PKI : double guard défense en profondeur (spaces.py aussi vérifie)
    from .vault.pki_ca import is_reserved_mount
    if is_reserved_mount(vault_id):
        logger.warning(f"⚠️ Tentative de suppression du mount PKI protégé '{vault_id}' bloquée (vault_delete MCP tool)")
        return {"status": "error", "error": "reserved_mount",
                "message": f"'{vault_id}' est un mount système PKI protégé et ne peut pas être supprimé."}

    return _r("vault_delete", await delete_space(vault_id), vault_id)


# ═══════════════════════════════════════════════════════════════════════
# OUTILS MCP — Secrets (KV v2)
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def secret_write(vault_id: str, path: str, data: dict,
                       secret_type: str = "custom", tags: str = "",
                       favorite: bool = False) -> dict:
    """
    Écrit un secret typé dans un vault.

    Types disponibles : login, password, secure_note, api_key, ssh_key,
    database, server, certificate, env_file, credit_card, identity,
    wifi, crypto_wallet, custom.

    Args:
        vault_id: Vault cible (coffre de secrets)
        path: Chemin du secret (ex: "web/github", "db/production")
        data: Données du secret (champs selon le type)
        secret_type: Type de secret (défaut: custom)
        tags: Tags séparés par des virgules (ex: "prod,critical")
        favorite: Marquer comme favori
    """
    from .auth.context import check_access, check_write_permission, check_policy, check_path_policy
    from .vault.secrets import write_secret

    policy_err = check_policy("secret_write")
    if policy_err:
        return policy_err
    access_err = check_access(vault_id)
    if access_err:
        return access_err
    path_err = check_path_policy(vault_id, path, "write")
    if path_err:
        return path_err
    write_err = check_write_permission()
    if write_err:
        return write_err

    return _r("secret_write", await write_secret(vault_id, path, data, secret_type, tags, favorite), vault_id, path)


@mcp.tool()
async def secret_read(vault_id: str, path: str, version: int = 0) -> dict:
    """
    Lit un secret depuis un vault.

    Args:
        vault_id: Vault cible
        path: Chemin du secret
        version: Version spécifique (0 = dernière)
    """
    from .auth.context import check_access, check_policy, check_path_policy
    from .vault.secrets import read_secret

    policy_err = check_policy("secret_read")
    if policy_err:
        return policy_err
    access_err = check_access(vault_id)
    if access_err:
        return access_err
    path_err = check_path_policy(vault_id, path, "read")
    if path_err:
        return path_err

    return _r("secret_read", await read_secret(vault_id, path, version), vault_id, path)


@mcp.tool()
async def secret_list(vault_id: str, path: str = "") -> dict:
    """
    Liste les secrets d'un vault.

    Args:
        vault_id: Vault cible
        path: Préfixe pour filtrer (optionnel)
    """
    from .auth.context import check_access, check_policy, check_path_policy
    from .vault.secrets import list_secrets, normalize_list_path

    policy_err = check_policy("secret_list")
    if policy_err:
        return policy_err
    access_err = check_access(vault_id)
    if access_err:
        return access_err
    # SÉCURITÉ #81 : canonicaliser AVANT check_path_policy — le PDP et l'appel
    # OpenBao doivent porter sur la MÊME valeur (sinon `?prefix=%2F` contourne la
    # policy en listant la racine). Message constant (anti-injection d'audit).
    canonical = normalize_list_path(path)
    if canonical is None:
        return {"status": "error", "message": "Chemin de secret invalide"}
    # SÉCURITÉ V2-05b : check_path_policy sur secret_list (consistance avec read/write/delete)
    path_err = check_path_policy(vault_id, canonical, "read")
    if path_err:
        return path_err

    return _r("secret_list", await list_secrets(vault_id, canonical), vault_id)


@mcp.tool()
async def secret_delete(vault_id: str, path: str) -> dict:
    """
    Supprime un secret et toutes ses versions.

    Args:
        vault_id: Vault cible
        path: Chemin du secret à supprimer
    """
    from .auth.context import check_access, check_write_permission, check_policy, check_path_policy
    from .vault.secrets import delete_secret

    policy_err = check_policy("secret_delete")
    if policy_err:
        return policy_err
    access_err = check_access(vault_id)
    if access_err:
        return access_err
    path_err = check_path_policy(vault_id, path, "write")
    if path_err:
        return path_err
    write_err = check_write_permission()
    if write_err:
        return write_err

    return _r("secret_delete", await delete_secret(vault_id, path), vault_id, path)


# ═══════════════════════════════════════════════════════════════════════
# OUTILS MCP — JIT Wrap Broker (mcp-mission)
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def secret_wrap(
    vault_id: str,
    secret_path: str,
    mission_id: str,
    operation_id: str,
    ttl_seconds: int = 300,
    tenant_id: str = "",
    expected_aud: str = "",
) -> dict:
    """
    Crée un wrap token single-use pour (vault_id, secret_path) scopé à une mission JIT.

    Contrat VaultClient pour mcp-mission CredentialBrokerService.
    Le secret en clair ne transite jamais — OpenBao cubbyhole garantit le single-use.
    Le wrap_token retourné ne doit jamais être loggué côté broker.

    Args:
        vault_id: Vault source du secret
        secret_path: Chemin du secret dans le vault
        mission_id: Identifiant de la mission (scope)
        operation_id: Corrélation write-ahead pour compensation des orphelins (#74)
        ttl_seconds: TTL du wrap token en secondes (défaut: 300s = 5 min)

    Returns:
        {status, wrap_token (SENSIBLE), secret_id, accessor, vault_url, expires_at, intended_use}
    """
    from .auth.context import check_admin_permission, check_access, check_path_policy
    from .vault.wrapping import wrap_secret, is_safe_id

    # check_admin assure que seul mcp-mission (token admin) peut créer des wraps
    admin_err = check_admin_permission()
    if admin_err:
        return admin_err

    if ttl_seconds < 60 or ttl_seconds > 3600:
        return {"status": "error", "message": "ttl_seconds doit être entre 60 et 3600"}

    # #78/D6 : valider les identifiants AVANT l'appel core ET l'audit (_r logge op_id[:32]).
    if not is_safe_id(operation_id):
        return {"status": "error", "error_type": "invalid_input",
                "message": "operation_id invalide (alphanum + _-:., 1-256 chars)"}
    if not is_safe_id(mission_id):
        return {"status": "error", "error_type": "invalid_input",
                "message": "mission_id invalide (alphanum + _-:., 1-256 chars)"}

    # En mode ENFORCE=true + JWKS configuré : enrichir expected_aud automatiquement
    # pour garantir le binding complet côté secret_consume (ÉLEVÉ — issue #29).
    # Les wraps créés sans expected_aud auraient un binding mission_id-only.
    if settings.enforce_mission_token_validation and settings.mission_jwks_url:
        if not expected_aud:
            # Source unique d'audience (#47) : mcp_instance_id (canonique) ou
            # mission_token_aud (alias legacy). Cohérence garantie par
            # check_mission_pep_config au boot.
            resolved_aud = settings.resolved_mission_aud
            if resolved_aud:
                expected_aud = resolved_aud
            else:
                return {"status": "error", "error_type": "misconfigured",
                        "message": "expected_aud requis en mode ENFORCE=true "
                                   "(configurer MCP_INSTANCE_ID ou MISSION_TOKEN_AUD)"}

    # Vérification d'accès au vault (owner/allowed_resources) + policy path
    access_err = check_access(vault_id)
    if access_err:
        return access_err
    path_err = check_path_policy(vault_id, secret_path, "read")
    if path_err:
        return path_err

    result = await wrap_secret(vault_id, secret_path, mission_id, operation_id, ttl_seconds,
                               tenant_id=tenant_id, expected_aud=expected_aud)
    # Ne pas logguer le wrap_token dans l'audit — seuls les champs non-sensibles
    audit_result = {k: v for k, v in result.items() if k != "wrap_token"}
    _r("secret_wrap", audit_result, vault_id, f"op={operation_id[:32]}")
    return result


@mcp.tool()
async def secret_revoke_wrap(lease_id: str) -> dict:
    """
    Révoque un wrap token de façon IDEMPOTENTE.

    Contrat VaultClient pour mcp-mission : revoke(lease_id) → idempotent.
    lease_id introuvable ou déjà révoqué = SUCCÈS (jamais une erreur dure).
    Erreur réseau ou 5xx = erreur réelle (le broker doit retenter).

    Args:
        lease_id: Accessor du wrap token (retourné par secret_wrap)

    Returns:
        {status: "ok", state: "revoked" | "already_revoked" | "not_found"}
    """
    from .auth.context import check_admin_permission
    from .vault.wrapping import revoke_wrap, is_safe_id

    admin_err = check_admin_permission()
    if admin_err:
        return admin_err

    # #78/D5 (annexe) : lease_id validé avant d'être reflété (réponse + audit).
    if not is_safe_id(lease_id):
        return {"status": "error", "error_type": "invalid_input",
                "message": "lease_id invalide (alphanum + _-:., 1-256 chars)"}

    result = await revoke_wrap(lease_id)
    _r("secret_revoke_wrap", result, detail=f"prefix={lease_id[:8]}...")
    return result


@mcp.tool()
async def secret_wrap_lookup(operation_id: str) -> dict:
    """
    ⚠️ RÉVOQUE les wraps créés avec un operation_id donné (effet de bord destructif).

    Utilisé par mcp-mission pour compenser les provisions orphelines (#74) :
    si le broker crashe entre un wrap réussi côté Vault et sa confirmation,
    ce tool retrouve **et révoque** les wraps non rattachés.

    ⚠️ Ce n'est PAS une consultation : appeler cet outil sur un wrap actif le
    RÉVOQUE. Pour consulter l'état SANS effet de bord, utiliser
    `secret_wrap_status` (issue #77).

    États retournés (idempotent) :
        not_found        — aucune provision pour cet operation_id
        found_unattached — provision orpheline (pending sans accessor) ; **NON**
                           révoquée (le TTL OpenBao l'expirera)
        already_revoked  — déjà révoqué lors d'un appel précédent
        revoked          — révocation effectuée maintenant
        ambiguous        — plusieurs provisions (toutes révoquées)

    Args:
        operation_id: Identifiant de corrélation write-ahead

    Returns:
        {status, state, operation_id, count_revoked, entries_found}
    """
    from .auth.context import check_admin_permission
    from .vault.wrapping import lookup_and_revoke_by_operation_id, is_safe_id

    admin_err = check_admin_permission()
    if admin_err:
        return admin_err

    # #78/D6 : validation stricte (fullmatch, via is_safe_id) AVANT tout audit.
    if not is_safe_id(operation_id):
        return {"status": "error", "error_type": "invalid_input",
                "message": "operation_id invalide (alphanum + _-:., 1-256 chars)"}

    result = await lookup_and_revoke_by_operation_id(operation_id)
    _r("secret_wrap_lookup", result, detail=f"op={operation_id[:32]}")
    return result


@mcp.tool()
async def secret_wrap_status(operation_id: str) -> dict:
    """
    Consulte l'état d'un secret partagé (wrap) par operation_id — LECTURE SEULE.

    Contrairement à `secret_wrap_lookup` (qui RÉVOQUE — compensation orpheline #74),
    cet outil ne modifie rien : il retourne un **instantané best-effort** du
    registre (cache court, S3 *last-write-wins*). `active` signifie « actif dans
    l'instantané », PAS une garantie de consommabilité (un wrap expiré côté OpenBao
    peut encore apparaître actif ; une consommation concurrente peut l'invalider).
    Aucune révocation, aucune écriture durable (issue #77).

    États : not_found | pending | active | consuming | consumed | revoked |
            failed | ambiguous | registry_inconsistent (status=ok) ;
            backend_unavailable (status=error).

    Args:
        operation_id: Identifiant de corrélation write-ahead.

    Returns:
        {status, state, expires_at?} — jamais d'accessor ni de wrap_token.
    """
    from .auth.context import check_admin_permission
    from .vault.wrapping import status_by_operation_id, is_safe_id

    admin_err = check_admin_permission()
    if admin_err:
        return admin_err

    # #78/D6 : validation stricte (fullmatch, via is_safe_id) AVANT tout audit.
    if not is_safe_id(operation_id):
        return {"status": "error", "error_type": "invalid_input",
                "message": "operation_id invalide (alphanum + _-:., 1-256 chars)"}

    result = await status_by_operation_id(operation_id)
    _r("secret_wrap_status", result, detail=f"op={operation_id[:32]}")
    return result


# ═══════════════════════════════════════════════════════════════════════
# OUTILS MCP — Consommation médiée (issue #26, anti-confused-deputy C18)
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def secret_consume(
    wrap_token: str,
    operation_id: str,
    mission_token: str,
) -> dict:
    """
    Libère un secret en validant l'identité de mission (anti-confused-deputy C18).

    Chemin C18 : valide le JWT mission_token (ES256/JWKS), vérifie les bindings
    registry (mission_id, tenant_id, aud), puis unwrap OpenBao cubbyhole.

    Modes :
    - ENFORCE_MISSION_TOKEN_VALIDATION=false (défaut, standalone) :
        JWT validé si MISSION_JWKS_URL configuré, sinon log warning + continue.
        Zéro impact sur les déploiements sans mcp-mission.
    - ENFORCE_MISSION_TOKEN_VALIDATION=true (E2E) :
        Hard-reject sur toute violation JWT ou binding.

    Sécurité :
    - wrap_token et mission_token ne sont JAMAIS loggués ni retournés
    - Erreurs sanitisées (reason code seulement, pas de données sensibles)
    - Anti-replay : entrée registry marquée "consumed" après succès

    Args:
        wrap_token: Token de déballage OpenBao (SENSIBLE — ne jamais loguer).
        operation_id: Identifiant de l'opération (corrélation registry).
        mission_token: JWT mission compact ES256 (SENSIBLE — ne jamais loguer).
    """
    from .vault.wrapping import consume_wrap_secret, is_safe_id

    # #78/D6 : valider operation_id AVANT toute logique/audit (anti-injection log).
    if not is_safe_id(operation_id):
        return {"status": "error", "error_type": "invalid_input",
                "message": "operation_id invalide (alphanum + _-:., 1-256 chars)"}

    enforce = settings.enforce_mission_token_validation
    jwks_url = settings.mission_jwks_url

    mission_id = ""
    jwt_claims: dict = {}

    # ── Validation JWT (si JWKS configuré) ──────────────────────────
    if jwks_url:
        from .auth.jwt_validator import get_mission_token_validator, MissionTokenError
        validator = get_mission_token_validator()
        if validator is None:
            # Singleton absent = lifecycle échoué ou JWKS_URL ajouté à chaud.
            # Fail-close en mode enforced ; sinon log warning et continue.
            if enforce:
                return {"status": "error", "error_type": "misconfigured",
                        "message": "Mission Token Validator non initialisé — redémarrer le service"}
            logger.warning("secret_consume : singleton JWT absent (ENFORCE=false) — JWT non validé")
        else:
            try:
                jwt_claims = validator.validate(mission_token)
                mission_id = jwt_claims.get("mission_id", "")
            except Exception as e:
                reason = getattr(e, "reason", "jwt_validation_failed")
                logger.warning("secret_consume JWT rejected: %s", reason)
                if enforce:
                    if reason == "misconfigured_expected_aud":
                        # Misconfiguration serveur (MISSION_TOKEN_AUD/MCP_INSTANCE_ID
                        # non résolu), pas un JWT invalide — cohérent avec les autres
                        # retours "misconfigured" de ce bloc et de secret_wrap (#86).
                        return {"status": "error", "error_type": "misconfigured",
                                "message": "Configuration mission_token incomplète "
                                           "(audience non résolue) — redémarrer le "
                                           "service après correction"}
                    # #78/D5 : message client GÉNÉRIQUE — le reason (potentiellement porteur
                    # d'une valeur non vérifiée) reste dans le log serveur ci-dessus, jamais
                    # renvoyé au client ni versé à l'audit humain.
                    return {"status": "error", "error_type": "jwt_invalid",
                            "message": "Mission token invalide"}
                logger.warning(
                    "secret_consume : JWT invalide ignoré (ENFORCE=false) — reason=%s", reason
                )

    elif enforce:
        # ENFORCE=true mais pas de JWKS configuré → incohérence config
        return {"status": "error", "error_type": "misconfigured",
                "message": "ENFORCE_MISSION_TOKEN_VALIDATION=true mais MISSION_JWKS_URL vide"}

    # ── Vérification mission active (optionnel) ──────────────────────
    if mission_id and settings.mission_status_url:
        status_ok, status_reason = await _check_mission_active(
            mission_id=mission_id,
            status_url_template=settings.mission_status_url,
            cache_ttl=settings.mission_status_cache_ttl,
        )
        if not status_ok:
            logger.warning("secret_consume : mission inactive — %s", status_reason)
            if enforce:
                # #78/D5 : message client générique — status_reason loggué serveur, non reflété.
                return {"status": "error", "error_type": "mission_inactive",
                        "message": "Mission non active"}

    # ── Consommation médiée ─────────────────────────────────────────
    # Extraire tenant_id depuis les claims JWT.
    # expected_aud utilise settings.mission_token_aud (validé par PyJWT decode) — pas
    # jwt_claims["aud"] qui peut être une liste non-ordonnée (MOYEN — issue #29).
    tenant_id_from_jwt = jwt_claims.get("tenant_id", "") if jwt_claims else ""
    expected_aud_from_jwt = settings.resolved_mission_aud  # source unique (#47)

    result = await consume_wrap_secret(
        wrap_token=wrap_token,
        operation_id=operation_id,
        mission_id=mission_id or "",
        tenant_id=tenant_id_from_jwt,
        expected_aud=expected_aud_from_jwt,
        enforce=enforce,
    )

    # Audit : jamais wrap_token, jamais mission_token, jamais le secret data
    audit_result = {
        k: v for k, v in result.items()
        if k not in ("data", "wrap_token")
    }
    _r("secret_consume", audit_result, detail=f"op={operation_id[:32]}")
    return result


# Vérification mission active : déplacée dans auth/mission_jwt.py (issue #47) —
# partagée entre le PEP /mcp (AuthMiddleware) et secret_consume, avec un cache
# commun et une allow-list d'états actifs {RUNNING, WAITING_HUMAN, PAUSED}
# (fail-close : état inconnu = inactif). Alias conservé pour secret_consume.
from .auth.mission_jwt import check_mission_active as _check_mission_active


# ═══════════════════════════════════════════════════════════════════════
# OUTILS MCP — Types & Utilitaires
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def secret_types() -> dict:
    """
    Liste tous les types de secrets disponibles (style 1Password).

    Retourne les 14 types avec leurs champs requis et optionnels :
    login, password, secure_note, api_key, ssh_key, database, server,
    certificate, env_file, credit_card, identity, wifi, crypto_wallet, custom.
    """
    from .vault.types import list_types

    types = list_types()
    return {"status": "ok", "types": types, "count": len(types)}


@mcp.tool()
async def secret_generate_password(length: int = 24, uppercase: bool = True,
                                    lowercase: bool = True, digits: bool = True,
                                    symbols: bool = True, exclude: str = "") -> dict:
    """
    Génère un mot de passe cryptographiquement sûr (CSPRNG).

    Args:
        length: Longueur du mot de passe (8-128, défaut: 24)
        uppercase: Inclure des majuscules A-Z
        lowercase: Inclure des minuscules a-z
        digits: Inclure des chiffres 0-9
        symbols: Inclure des symboles !@#$%...
        exclude: Caractères à exclure (ex: "lI10O")
    """
    from .vault.types import generate_password

    password = generate_password(length, uppercase, lowercase, digits, symbols, exclude)
    return {
        "status": "ok",
        "password": password,
        "length": len(password),
        "charset": {
            "uppercase": uppercase,
            "lowercase": lowercase,
            "digits": digits,
            "symbols": symbols,
            "excluded": exclude,
        },
    }


# ═══════════════════════════════════════════════════════════════════════
# OUTILS MCP — Policies (Phase 8a — CRUD)
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def policy_create(policy_id: str, description: str = "",
                        allowed_tools: list = None, denied_tools: list = None,
                        path_rules: list = None) -> dict:
    """
    Crée une nouvelle policy MCP (contrôle d'accès granulaire).

    Une policy définit quels outils MCP sont accessibles et quelles
    permissions s'appliquent par vault. Assignable à un token via policy_id.

    Logique d'évaluation :
    - denied_tools a PRIORITÉ sur allowed_tools
    - allowed_tools vide = tous les outils autorisés (sauf denied)
    - Les patterns supportent les wildcards (ex: "ssh_*", "secret_*")

    Args:
        policy_id: Identifiant unique (alphanum + tirets, max 64 chars)
        description: Description lisible de la policy
        allowed_tools: Patterns d'outils autorisés (ex: ["system_*", "vault_list", "secret_read"])
        denied_tools: Patterns d'outils refusés (ex: ["vault_delete", "ssh_*"])
        path_rules: Règles par vault (ex: [{"vault_pattern": "prod-*", "permissions": ["read"]}])
    """
    from .auth.context import check_admin_permission, get_current_client_name
    from .auth.policies import get_policy_store

    admin_err = check_admin_permission()
    if admin_err:
        return admin_err

    store = get_policy_store()
    if not store:
        return {"status": "error", "message": "Policy Store non configuré (S3 requis)"}

    result = store.create(
        policy_id=policy_id,
        description=description,
        allowed_tools=allowed_tools or [],
        denied_tools=denied_tools or [],
        path_rules=path_rules or [],
        created_by=get_current_client_name(),
    )
    return _r("policy_create", result, detail=f"policy={policy_id}")


@mcp.tool()
async def policy_list() -> dict:
    """
    Liste toutes les policies MCP.

    Retourne un résumé de chaque policy (ID, description, compteurs).
    Requiert la permission admin.
    """
    from .auth.context import check_admin_permission
    from .auth.policies import get_policy_store, PolicyStoreUnavailable

    admin_err = check_admin_permission()
    if admin_err:
        return admin_err

    store = get_policy_store()
    if not store:
        return {"status": "error", "message": "Policy Store non configuré (S3 requis)"}

    try:
        policies = store.list_all()
    except PolicyStoreUnavailable as e:
        return {"status": "error", "error_type": "policy_store_unavailable",
                "message": f"Policy Store indisponible ({e})"}
    return {"status": "ok", "policies": policies, "count": len(policies)}


@mcp.tool()
async def policy_get(policy_id: str) -> dict:
    """
    Détails complets d'une policy MCP.

    Retourne toutes les règles (allowed_tools, denied_tools, path_rules).
    Requiert la permission admin.

    Args:
        policy_id: Identifiant de la policy
    """
    from .auth.context import check_admin_permission
    from .auth.policies import get_policy_store, PolicyStoreUnavailable

    admin_err = check_admin_permission()
    if admin_err:
        return admin_err

    store = get_policy_store()
    if not store:
        return {"status": "error", "message": "Policy Store non configuré (S3 requis)"}

    try:
        policy = store.get(policy_id)
    except PolicyStoreUnavailable as e:
        return {"status": "error", "error_type": "policy_store_unavailable",
                "message": f"Policy Store indisponible ({e})"}
    if not policy:
        return {"status": "error", "message": f"Policy '{policy_id}' non trouvée"}

    return {"status": "ok", **policy}


@mcp.tool()
async def policy_delete(policy_id: str, confirm: bool = False) -> dict:
    """
    Supprime une policy MCP (irréversible).

    ⚠️ Les tokens qui référencent cette policy seront BLOQUÉS sur tout outil
    soumis à policy (fail-close, cf. is_tool_allowed()) — ils ne deviennent
    PAS non-restreints. Réassigner une autre policy si un accès doit persister.
    Le paramètre confirm doit être True pour confirmer.

    Args:
        policy_id: Identifiant de la policy à supprimer
        confirm: Doit être True pour confirmer la suppression
    """
    from .auth.context import check_admin_permission
    from .auth.policies import get_policy_store

    admin_err = check_admin_permission()
    if admin_err:
        return admin_err

    if not confirm:
        return {"status": "error", "message": "confirm=True requis pour supprimer une policy"}

    store = get_policy_store()
    if not store:
        return {"status": "error", "message": "Policy Store non configuré (S3 requis)"}

    result = store.delete(policy_id)
    if result is True:
        return _r("policy_delete", {"status": "deleted", "policy_id": policy_id},
                  detail=f"policy={policy_id}")
    elif result in ("storage_error", "policy_store_unavailable"):
        # Suppression non persistée = la policy reste active → événement critique à tracer.
        # issue #86 Lot 3 : les deux sentinelles (échec PUT pendant l'écriture, ou store
        # déjà connu indisponible) sont unifiées côté client sous le même contrat d'erreur.
        return _r("policy_delete",
                  {"status": "error", "error_type": "policy_store_unavailable",
                   "message": "Suppression non persistée (Policy Store indisponible)"},
                  detail=f"policy={policy_id} NON PERSISTÉE (Policy Store indisponible)")
    else:
        return {"status": "error", "message": f"Policy '{policy_id}' non trouvée"}


# ═══════════════════════════════════════════════════════════════════════
# OUTILS MCP — SSH CA
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def ssh_ca_setup(vault_id: str, role_name: str, allowed_users: str = "*",
                       default_user: str = "ubuntu", ttl: str = "30m") -> dict:
    """
    Configure un rôle SSH CA dans un vault.

    Args:
        vault_id: Vault cible
        role_name: Nom du rôle SSH (ex: "prod-servers")
        allowed_users: Utilisateurs autorisés (virgules, * = tous)
        default_user: Utilisateur par défaut
        ttl: Durée de validité des certificats (ex: "30m", "1h")
    """
    from .auth.context import check_access, check_write_permission, check_policy
    from .vault.ssh_ca import setup_ssh_ca

    policy_err = check_policy("ssh_ca_setup")
    if policy_err:
        return policy_err
    access_err = check_access(vault_id)
    if access_err:
        return access_err
    write_err = check_write_permission()
    if write_err:
        return write_err

    return _r("ssh_ca_setup", await setup_ssh_ca(vault_id, role_name, allowed_users, default_user, ttl), vault_id, role_name)


@mcp.tool()
async def ssh_sign_key(vault_id: str, role_name: str, public_key: str,
                       ttl: str = "30m") -> dict:
    """
    Signe une clé publique SSH avec la CA du vault.

    Args:
        vault_id: Vault cible
        role_name: Rôle SSH à utiliser
        public_key: Contenu de la clé publique SSH
        ttl: Durée de validité du certificat
    """
    from .auth.context import check_access, check_write_permission, check_policy
    from .vault.ssh_ca import sign_ssh_key

    policy_err = check_policy("ssh_sign_key")
    if policy_err:
        return policy_err
    access_err = check_access(vault_id)
    if access_err:
        return access_err
    write_err = check_write_permission()
    if write_err:
        return write_err

    return _r("ssh_sign_key", await sign_ssh_key(vault_id, role_name, public_key, ttl), vault_id, role_name)


@mcp.tool()
async def ssh_ca_public_key(vault_id: str) -> dict:
    """
    Récupère la clé publique de la CA SSH (pour configurer les serveurs cibles).

    Args:
        vault_id: Vault cible
    """
    from .auth.context import check_access, check_policy
    from .vault.ssh_ca import get_ca_public_key

    policy_err = check_policy("ssh_ca_public_key")
    if policy_err:
        return policy_err
    access_err = check_access(vault_id)
    if access_err:
        return access_err

    return _r("ssh_ca_public_key", await get_ca_public_key(vault_id), vault_id)


@mcp.tool()
async def ssh_ca_list_roles(vault_id: str) -> dict:
    """
    Liste les rôles SSH CA configurés dans un vault.

    Chaque rôle définit qui peut signer quoi (utilisateurs autorisés, TTL, extensions).

    Args:
        vault_id: Vault cible
    """
    from .auth.context import check_access, check_policy
    from .vault.ssh_ca import list_ssh_roles

    policy_err = check_policy("ssh_ca_list_roles")
    if policy_err:
        return policy_err
    access_err = check_access(vault_id)
    if access_err:
        return access_err

    return _r("ssh_ca_list_roles", await list_ssh_roles(vault_id), vault_id)


@mcp.tool()
async def ssh_ca_role_info(vault_id: str, role_name: str) -> dict:
    """
    Détails d'un rôle SSH CA (TTL, allowed_users, extensions, etc.).

    Args:
        vault_id: Vault cible
        role_name: Nom du rôle SSH à inspecter
    """
    from .auth.context import check_access, check_policy
    from .vault.ssh_ca import get_ssh_role_info

    policy_err = check_policy("ssh_ca_role_info")
    if policy_err:
        return policy_err
    access_err = check_access(vault_id)
    if access_err:
        return access_err

    return _r("ssh_ca_role_info", await get_ssh_role_info(vault_id, role_name), vault_id, role_name)


# ═══════════════════════════════════════════════════════════════════════
# OUTILS MCP — PKI Certificate Authority (Phase 5 — issue #15)
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def pki_ca_setup(lab_mode: bool = True,
                       allowed_domains: str = "*.lesur.lan,lesur.lan",
                       leaf_ttl: str = "720h") -> dict:
    """
    Configure la PKI interne complète (CA racine + intermédiaire + ACME).

    Idempotent. Le serveur ACME est activé sur la CA intermédiaire.
    En lab, la racine est self-signed (opération entièrement locale).
    En prod, générer le CSR avec lab_mode=False et importer le cert signé.

    Args:
        lab_mode: True = CA racine self-signed (lab/dev). False = CSR pour CA externe (prod).
        allowed_domains: Domaines autorisés par le rôle ACME, séparés par des virgules.
        leaf_ttl: TTL max des certificats feuilles (ex: 720h = 30 jours).
    """
    from .auth.context import check_admin_permission, check_policy
    from .vault.pki_ca import setup_pki_ca

    policy_err = check_policy("pki_ca_setup")
    if policy_err:
        return policy_err
    admin_err = check_admin_permission()
    if admin_err:
        return admin_err

    domains_list = [d.strip() for d in allowed_domains.split(",") if d.strip()]
    return _r("pki_ca_setup", await setup_pki_ca(lab_mode, domains_list, leaf_ttl))


@mcp.tool()
async def pki_ca_public_key() -> dict:
    """
    Retourne la CA racine PEM avec son empreinte SHA-256 et l'URL stable.

    Utiliser l'URL stable pour les clients httpx (bundle CA) et le Caddyfile.
    """
    from .auth.context import check_policy
    from .vault.pki_ca import get_ca_root_pem

    policy_err = check_policy("pki_ca_public_key")
    if policy_err:
        return policy_err

    return _r("pki_ca_public_key", await get_ca_root_pem())


@mcp.tool()
async def pki_ca_list_roles() -> dict:
    """Liste les rôles d'émission PKI configurés sur la CA intermédiaire."""
    from .auth.context import check_policy
    from .vault.pki_ca import list_pki_roles

    policy_err = check_policy("pki_ca_list_roles")
    if policy_err:
        return policy_err

    return _r("pki_ca_list_roles", await list_pki_roles())


@mcp.tool()
async def pki_ca_role_info(role_name: str) -> dict:
    """
    Détails d'un rôle d'émission PKI (domaines autorisés, TTL, flags TLS).

    Args:
        role_name: Nom du rôle (ex: acme-servers)
    """
    from .auth.context import check_policy
    from .vault.pki_ca import get_pki_role_info

    policy_err = check_policy("pki_ca_role_info")
    if policy_err:
        return policy_err

    return _r("pki_ca_role_info", await get_pki_role_info(role_name))


@mcp.tool()
async def pki_list_certs(limit: int = 100, offset: int = 0) -> dict:
    """
    Inventaire paginé des certificats émis (serials, SANs, expiration, révocation).

    Args:
        limit: Nombre max de certificats retournés (défaut 100).
        offset: Offset de pagination.
    """
    from .auth.context import check_policy
    from .vault.pki_ca import list_issued_certs

    policy_err = check_policy("pki_list_certs")
    if policy_err:
        return policy_err

    return _r("pki_list_certs", await list_issued_certs(limit, offset))


@mcp.tool()
async def pki_revoke_cert(serial_number: str) -> dict:
    """
    Révoque un certificat et force la mise à jour de la CRL.

    Args:
        serial_number: Numéro de série du certificat à révoquer (format hex, ex: 12:34:ab:cd:...).
    """
    from .auth.context import check_admin_permission, check_policy
    from .vault.pki_ca import revoke_cert

    policy_err = check_policy("pki_revoke_cert")
    if policy_err:
        return policy_err
    admin_err = check_admin_permission()
    if admin_err:
        return admin_err

    return _r("pki_revoke_cert", await revoke_cert(serial_number))


@mcp.tool()
async def pki_issue_cert(common_name: str, ttl: str = "720h",
                         alt_names: str = "", ip_sans: str = "") -> dict:
    """
    Émet un certificat serveur signé par la CA intermédiaire (émission manuelle, hors ACME).

    Réservé admin. La clé privée est retournée UNE FOIS et n'est jamais stockée
    côté Vault ni journalisée — à sauvegarder immédiatement côté appelant.

    Args:
        common_name: FQDN principal du certificat (doit appartenir aux domaines autorisés).
        ttl: Durée de validité (ex: 720h, 30m, 90d), bornée par le max_ttl du rôle.
        alt_names: SANs DNS supplémentaires, séparés par des virgules (optionnel).
        ip_sans: SANs IP, séparés par des virgules (optionnel).
    """
    from .auth.context import check_admin_permission, check_policy
    from .vault.pki_ca import issue_certificate

    policy_err = check_policy("pki_issue_cert")
    if policy_err:
        return policy_err
    admin_err = check_admin_permission()
    if admin_err:
        return admin_err

    result = await issue_certificate(common_name, ttl, alt_names, ip_sans)
    # Audit : jamais la clé privée ni le certificat complet — seulement CN + serial.
    audit_result = {k: v for k, v in result.items() if k not in ("private_key", "certificate", "ca_chain")}
    _r("pki_issue_cert", audit_result, detail=f"cn={common_name[:48]}")
    return result


@mcp.tool()
async def pki_ca_rotate_intermediate(keep_old_issuer: bool = True,
                                      overlap_ttl: str = "48h") -> dict:
    """
    Rotation sans coupure de la CA intermédiaire.

    Génère un nouveau CSR, signe avec la CA racine, importe comme nouvel issuer.
    L'ancien issuer reste valide si keep_old_issuer=True (certs existants honorés).

    Args:
        keep_old_issuer: Conserver l'ancien issuer pour valider les certs existants.
        overlap_ttl: Durée de chevauchement documentée (non appliquée automatiquement).
    """
    from .auth.context import check_admin_permission, check_policy
    from .vault.pki_ca import rotate_intermediate

    policy_err = check_policy("pki_ca_rotate_intermediate")
    if policy_err:
        return policy_err
    admin_err = check_admin_permission()
    if admin_err:
        return admin_err

    return _r("pki_ca_rotate_intermediate", await rotate_intermediate(keep_old_issuer, overlap_ttl))


# ═══════════════════════════════════════════════════════════════════════
# OUTILS MCP — Token Management (Phase 8b)
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def token_update(hash_prefix: str, policy_id: str = "",
                       permissions: str = "", vaults: str = "") -> dict:
    """
    Met à jour un token existant (policy, permissions, vaults autorisés).

    Seuls les champs fournis (non vides) sont modifiés.
    Requiert la permission admin.

    Args:
        hash_prefix: Préfixe du hash du token à modifier (depuis token list)
        policy_id: Policy à assigner (vide = retirer la policy, "_remove" = retirer)
        permissions: Nouvelles permissions séparées par virgule (ex: "read,write")
        vaults: Vaults autorisés séparés par virgule (vide = pas de changement, "_all" = tous)
    """
    from .auth.context import check_admin_permission
    from .auth.token_store import get_token_store

    admin_err = check_admin_permission()
    if admin_err:
        return admin_err

    store = get_token_store()
    if not store:
        return {"status": "error", "message": "Token Store non configuré (S3 requis)"}

    # Préparer les champs à modifier (None = pas de changement)
    new_policy = None
    new_perms = None
    new_resources = None

    if policy_id:
        if policy_id == "_remove":
            new_policy = ""  # Retirer la policy
        else:
            # Vérifier que la policy existe.
            # issue #86 Lot 3 : référence non vérifiable (store absent OU indisponible)
            # → refus explicite (bug historique corrigé : `if pstore and ...` acceptait
            # silencieusement tout policy_id quand pstore était None).
            from .auth.policies import get_policy_store, PolicyStoreUnavailable
            pstore = get_policy_store()
            if not pstore:
                return {"status": "error",
                        "message": "Policy Store non configuré — policy_id ne peut être vérifié"}
            try:
                policy_found = pstore.get(policy_id)
            except PolicyStoreUnavailable as e:
                return {"status": "error", "error_type": "policy_store_unavailable",
                        "message": f"Policy Store indisponible — policy_id ne peut être vérifié ({e})"}
            if not policy_found:
                return {"status": "error", "message": f"Policy '{policy_id}' non trouvée"}
            new_policy = policy_id

    if permissions:
        new_perms = [p.strip() for p in permissions.split(",") if p.strip()]

    if vaults:
        if vaults == "_all":
            new_resources = []  # Vide = accès à tous
        else:
            new_resources = [v.strip() for v in vaults.split(",") if v.strip()]

    result = store.update(
        hash_prefix=hash_prefix,
        policy_id=new_policy,
        permissions=new_perms,
        allowed_resources=new_resources,
    )
    return _r("token_update", result, detail=f"hash={hash_prefix[:12]}")


# ═══════════════════════════════════════════════════════════════════════
# OUTILS MCP — Audit Log (Phase 8c)
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
async def audit_log(limit: int = 50, client: str = "", vault_id: str = "",
                    tool: str = "", category: str = "", status: str = "",
                    since: str = "") -> dict:
    """
    Journal d'audit — toutes les opérations MCP avec filtres.

    Requiert la permission admin.

    Retourne les événements les plus récents en premier. Chaque entrée
    contient : timestamp, client, outil, vault, statut, détail, durée.

    Filtres disponibles (combinables) :
    - client : nom du client (ex: "agent-sre")
    - vault_id : vault concerné (ex: "prod-servers")
    - tool : nom de l'outil (supporte préfixes, ex: "secret_*")
    - category : system, vault, secret, ssh, policy, token
    - status : ok, error, created, deleted, updated, denied
    - since : date ISO 8601 (ex: "2026-03-18T10:00:00")

    Args:
        limit: Nombre max d'entrées (défaut 50, max 1000)
        client: Filtrer par client
        vault_id: Filtrer par vault
        tool: Filtrer par outil (wildcards)
        category: Filtrer par catégorie
        status: Filtrer par statut
        since: Entrées après cette date
    """
    # SÉCURITÉ V2-03 : audit_log requiert admin (conformément à ARCHITECTURE.md §6.7)
    from .auth.context import check_admin_permission
    admin_err = check_admin_permission()
    if admin_err:
        return admin_err

    from .audit import get_audit_store

    store = get_audit_store()
    if not store:
        return {"status": "error", "message": "Audit Store non initialisé"}

    entries = store.get_entries(
        limit=limit, client=client, vault_id=vault_id,
        tool=tool, category=category, status=status, since=since,
    )
    stats = store.get_stats()

    return {
        "status": "ok",
        "entries": entries,
        "count": len(entries),
        "total_in_buffer": stats["total"],
        "stats": stats,
    }


# ═══════════════════════════════════════════════════════════════════════
# ASGI MIDDLEWARE STACK + MAIN
# ═══════════════════════════════════════════════════════════════════════

def create_app():
    """
    Construit la stack ASGI complète.

    Inclut le fail-fast bootstrap key : si ADMIN_BOOTSTRAP_KEY est vide/par défaut/faible,
    lève RuntimeError avant de construire la stack — protège les déploiements ASGI directs
    (ex: `uvicorn mcp_vault.server:create_app --factory`) en dehors du chemin server.main().
    """
    from .openbao.crypto import validate_bootstrap_key
    is_valid, msg = validate_bootstrap_key(settings.admin_bootstrap_key)
    if not is_valid:
        raise RuntimeError(
            f"ADMIN_BOOTSTRAP_KEY invalide — démarrage refusé : {msg}\n"
            "Définissez une clé forte via ADMIN_BOOTSTRAP_KEY "
            "(ex: python -c \"import secrets; print(secrets.token_urlsafe(48))\")."
        )

    # ── Fail-fast validation mission JWT (issues #47, #86) ─────────────────
    # Refuse de démarrer avec une config incohérente : jwks_url/audience absents,
    # drift instance_id/mission_token_aud, PEP actif sans enforcement C18, statut
    # mission absent/mal formé/hors bornes — dès que le PEP transport (jwt/dual-stack)
    # OU l'enforcement C18 seul (bearer + ENFORCE_MISSION_TOKEN_VALIDATION=true) est
    # actif. Voir Settings.check_mission_pep_config() pour le détail des règles.
    # NB : un lancement `uvicorn ...:create_app --factory` passe par ce fail-fast
    # mais n'exécute pas vault_startup() (lifespan) — le validateur C18/JWKS ne sera
    # donc pas opérationnel malgré une config validée ici ; ce chemin reste fail-close
    # (503) mais n'est pas un mode de démarrage pleinement supporté en prod.
    pep_ok, pep_msg = settings.check_mission_pep_config()
    if not pep_ok:
        raise RuntimeError(f"Config mission JWT invalide — démarrage refusé : {pep_msg}")

    from .auth.middleware import AuthMiddleware, LoggingMiddleware, HealthCheckMiddleware
    from .admin.middleware import AdminMiddleware
    from .pki_middleware import PkiMiddleware

    # Stack ASGI (ordre d'application : Pki → Admin → Health → Auth → Logging → MCP)
    app = mcp.streamable_http_app()
    app = LoggingMiddleware(app)
    app = AuthMiddleware(app, mcp)
    app = HealthCheckMiddleware(app)
    app = AdminMiddleware(app, mcp)
    app = PkiMiddleware(app)  # couche la plus externe — /acme/* et /pki/ca/* sans auth

    return app


def main():
    """
    Point d'entrée principal avec lifecycle complet.

    Séquence :
    1. Afficher la bannière
    2. Construire la stack ASGI
    3. Lancer le startup (S3 download → OpenBao start → init → unseal → sync)
    4. Démarrer uvicorn (bloquant jusqu'à SIGTERM/SIGINT)
    5. Lancer le shutdown (sync stop → seal → S3 upload → stop OpenBao)
    """
    import asyncio
    import uvicorn

    version = Path("VERSION").read_text().strip() if Path("VERSION").exists() else "0.1.0"

    logger.info("=" * 60)
    logger.info(f"  🔐 MCP Vault v{version}")
    logger.info(f"  📡 Port: {settings.mcp_server_port}")
    logger.info(f"  🏛️  OpenBao: {settings.openbao_addr}")
    logger.info(f"  ☁️  S3: {settings.s3_bucket_name or '(non configuré)'}")
    logger.info("=" * 60)

    # ── Fail-fast sécurité : refuser de démarrer avec une bootstrap key invalide ──
    # ADMIN_BOOTSTRAP_KEY chiffre les clés unseal (AES-256-GCM) et sert de credential
    # admin de secours. Une clé vide/par défaut/faible compromet tout le service — on
    # refuse donc de démarrer plutôt que de tourner avec un chiffrement cassé.
    from .openbao.crypto import validate_bootstrap_key
    is_valid, msg = validate_bootstrap_key(settings.admin_bootstrap_key)
    if not is_valid:
        logger.error(f"❌ ADMIN_BOOTSTRAP_KEY invalide : {msg}")
        logger.error(
            "   Démarrage refusé (fail-fast sécurité). Définissez une clé forte via la "
            "variable d'environnement ADMIN_BOOTSTRAP_KEY "
            "(ex: python -c \"import secrets; print(secrets.token_urlsafe(48))\")."
        )
        sys.exit(1)
    logger.info("✅ ADMIN_BOOTSTRAP_KEY validée (entropie suffisante)")

    # ── Fail-fast validation mission JWT (issues #47, #86) ─────────────────
    pep_ok, pep_msg = settings.check_mission_pep_config()
    if not pep_ok:
        logger.error(f"❌ Config mission JWT invalide : {pep_msg}")
        logger.error("   Démarrage refusé (fail-fast sécurité).")
        sys.exit(1)
    if settings.mcp_auth_mode != "bearer":
        logger.info(f"🛡️  PEP mission JWT actif (mode={settings.mcp_auth_mode}, "
                    f"aud={settings.resolved_mission_aud})")
    if settings.enforce_mission_token_validation:
        logger.info("🎫  Enforcement C18 actif (secret_consume) — "
                     f"statut mission vérifié via {settings.mission_status_url}")

    app = create_app()

    config = uvicorn.Config(
        app,
        host=settings.mcp_server_host,
        port=settings.mcp_server_port,
        log_level="info" if not settings.mcp_server_debug else "debug",
    )
    server = uvicorn.Server(config)

    async def serve_with_lifecycle():
        """Lance le lifecycle startup → serveur → shutdown."""
        from .lifecycle import vault_startup, vault_shutdown

        # ── STARTUP ──────────────────────────────────────────
        try:
            ok = await vault_startup()
            if not ok:
                logger.warning("⚠️ Démarrage en mode dégradé (OpenBao indisponible)")
        except Exception as e:
            logger.error(f"❌ Erreur critique au démarrage : {e}")
            logger.warning("⚠️ Démarrage en mode dégradé")

        # ── SERVEUR (bloquant jusqu'à SIGTERM/SIGINT) ────────
        try:
            await server.serve()
        except Exception as e:
            logger.error(f"❌ Erreur serveur : {e}")

        # ── SHUTDOWN ─────────────────────────────────────────
        try:
            await vault_shutdown()
        except Exception as e:
            logger.error(f"❌ Erreur au shutdown : {e}")

    asyncio.run(serve_with_lifecycle())
