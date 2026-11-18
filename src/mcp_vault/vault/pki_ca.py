# -*- coding: utf-8 -*-
"""
PKI Certificate Authority — CA interne pour l'écosystème mcp-vault.

CA globale (deux mounts système réservés) :
  _sys_pki_root/  — CA racine (lab: self-signed ; prod: CSR importé)
  _sys_pki_int/   — CA intermédiaire d'émission + serveur ACME

Les mounts _sys_pki_* sont protégés contre vault_delete
(guard dans spaces.py:delete_space et server.py:vault_delete).

Sync S3 forcée après toute mutation critique (setup, rotate, revoke)
pour éviter la perte d'inventaire/révocation lors d'un crash.
"""

from ..storage.audit_bao import bao_step, bao_step_sync
from ..async_offload import run_blocking

import asyncio
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ..config import get_settings
from ._hvac_utils import safe_list_keys

logger = logging.getLogger("mcp-vault.pki-ca")

_ROOT_MOUNT = "_sys_pki_root"
_INT_MOUNT = "_sys_pki_int"
_ACME_ROLE_NAME = "acme-servers"
# Rôle dédié à l'émission manuelle de certificats (issue #41). Distinct du rôle
# ACME : autorise les IP SANs, refuse les wildcards manuels, no_store=False pour
# apparaître dans l'inventaire. allowed_domains alignés sur le rôle ACME.
_MANUAL_ROLE_NAME = "manual-servers"
# Rôle de signature de CSR (issue #206) : un seul nom DNS, sous-domaine strict de
# PKI_CSR_DOMAIN, ni joker ni IP, clés EC. Nom FIXE : l'outil pki_sign_csr ne
# prend pas de nom de rôle, un jeton autorisé à signer ne signe que sous celui-ci.
_CSR_ROLE_NAME = "csr-servers"
_CSR_MAX_PEM_BYTES = 16 * 1024
# Durées historiques des autorités, appliquées à la CRÉATION quand l'appelant
# n'en donne pas. Une PKI existante conserve ses plafonds (issue #206).
_DEFAULT_ROOT_TTL = "87600h"
_DEFAULT_INT_TTL = "43800h"
# X.509 encode les dates à la seconde : seule tolérance admise au contrôle de durée.
_VALIDITY_SLACK = timedelta(seconds=1)
# Format TTL OpenBao (ex : 720h, 30m, 90d) — validation locale.
_TTL_PATTERN = re.compile(r'^\d{1,6}[smhd]$')
_TTL_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _ttl_to_seconds(ttl) -> Optional[int]:
    """Convertit un TTL ('720h', '90d', ou un int de secondes) en secondes. None si invalide."""
    if isinstance(ttl, int):
        return ttl if ttl >= 0 else None
    if not isinstance(ttl, str):
        return None
    ttl = ttl.strip()
    if not _TTL_PATTERN.fullmatch(ttl):
        return None
    return int(ttl[:-1]) * _TTL_UNITS[ttl[-1]]


def _normalize_domain_list(value) -> list:
    """Normalise allowed_domains (liste OU chaîne CSV renvoyée par OpenBao) en liste."""
    if isinstance(value, str):
        return [d.strip() for d in value.split(",") if d.strip()]
    if isinstance(value, list):
        return [str(d).strip() for d in value if str(d).strip()]
    return []

# Politiques EAB valides côté OpenBao (config/acme). "required" N'EXISTE PAS —
# valeurs acceptées : not-required, new-account-required, always-required.
# Lab : pas d'EAB (enrôlement libre). Prod : EAB exigé à la création de compte
# (bloque l'enrôlement public non authentifié sans casser les comptes existants).
_EAB_POLICY_LAB = "not-required"
_EAB_POLICY_PROD = "new-account-required"
# Headers de réponse ACME (RFC 8555) qu'OpenBao doit être autorisé à renvoyer ;
# sinon ils sont strippés et l'enrôlement ACME réel échoue.
_ACME_RESPONSE_HEADERS = ["Replay-Nonce", "Link", "Location"]


class PkiTtlError(Exception):
    """Refus explicite lié à une durée (issue #206) : jamais de troncature silencieuse."""

    def __init__(self, error_type: str, message: str):
        super().__init__(message)
        self.error_type = error_type


def _validity_shortfall(cert, t0: datetime, ttl_seconds: int) -> Optional[str]:
    """Message si `cert` expire avant `t0 + ttl` (à la seconde près), sinon None.

    `t0` est pris AVANT l'appel OpenBao, qui calcule `not_after = maintenant + ttl`
    sur la même horloge. Un certificat plus court a été tronqué, quelle qu'en soit
    la cause : plafond du mount ou du rôle, fin de l'autorité émettrice, émetteur
    configuré `leaf_not_after_behavior=truncate`.
    """
    expected = t0 + timedelta(seconds=ttl_seconds)
    if cert.not_valid_after_utc + _VALIDITY_SLACK < expected:
        return (f"certificat tronqué : expire le {cert.not_valid_after_utc.isoformat()}, "
                f"durée demandée jusqu'au {expected.isoformat()}")
    return None


def _read_mount_max_ttl(client, mount: str) -> Optional[int]:
    """`max_lease_ttl` (secondes) d'un mount existant ; None s'il n'existe pas ou n'en fixe pas."""
    mounts = bao_step_sync(lambda: client.sys.list_mounted_secrets_engines())
    if f"{mount}/" not in mounts.get("data", mounts):
        return None
    tune = bao_step_sync(lambda: client.sys.read_mount_configuration(path=mount))
    value = tune.get("data", tune).get("max_lease_ttl") if isinstance(tune, dict) else None
    return int(value) if isinstance(value, int) and value > 0 else None


def _resolve_ttl(explicit: Optional[str], current_seconds: Optional[int],
                 default: str, label: str) -> tuple[int, str]:
    """Durée effective : valeur explicite, sinon plafond actuel du mount, sinon défaut historique.

    Une omission CONSERVE l'existant : un second setup sans durée ne ramène pas
    une PKI 25 ans / 1 an aux défauts 10 ans / 5 ans (revue de plan #206).
    """
    if explicit is not None:
        seconds = _ttl_to_seconds(explicit)
        if not isinstance(explicit, str) or not seconds:
            raise PkiTtlError("invalid_input", f"{label} invalide (ex : 219000h, 8760h, 365d)")
        return seconds, explicit.strip()
    if current_seconds:
        return current_seconds, f"{current_seconds}s"
    return _ttl_to_seconds(default), default


def _tune_max_ttl(client, mount: str, ttl: str) -> None:
    bao_step_sync(lambda: client.sys.tune_mount_configuration(path=mount, max_lease_ttl=ttl))


async def _sign_and_import_intermediate(client, common_name: str,
                                        int_ttl: str, int_ttl_seconds: int) -> str:
    """CSR intermédiaire → signature par la racine → contrôle de durée → import → défaut.

    Partagé par le setup et la rotation. Si la racine rend un intermédiaire plus
    court que demandé (plafond du mount racine, fin de la racine), RIEN n'est
    importé : aucun émetteur ajouté, l'émetteur par défaut reste inchangé.
    Retourne l'identifiant du nouvel émetteur par défaut.
    """
    csr_resp = await bao_step(lambda: client.write(
        f"{_INT_MOUNT}/intermediate/generate/internal",
        common_name=common_name,
        ttl=int_ttl,
        key_type="rsa",
        key_bits=4096,
        add_basic_constraints=True,
    ))
    csr = csr_resp["data"]["csr"]

    t0 = datetime.now(timezone.utc)
    # issuer_ref est un paramètre de PATH (pas de body) dans l'API OpenBao :
    # /issuer/:issuer_ref/sign-intermediate.
    sign_resp = await bao_step(lambda: client.write(
        f"{_ROOT_MOUNT}/issuer/mcp-vault-root/sign-intermediate",
        csr=csr,
        format="pem_bundle",
        ttl=int_ttl,
    ))
    signed_bundle = sign_resp["data"]["certificate"]
    bundle = x509.load_pem_x509_certificates(signed_bundle.encode())
    signed = [c for c in bundle if c.subject != c.issuer]
    if len(signed) != 1:
        raise PkiTtlError("backend_error", "Réponse de signature d'intermédiaire inattendue")
    shortfall = _validity_shortfall(signed[0], t0, int_ttl_seconds)
    if shortfall:
        raise PkiTtlError("ttl_truncated",
                          f"Intermédiaire non importé, {shortfall}. Vérifier la durée "
                          "restante de la racine et le plafond du mount racine.")
    # Mesuré sur 2.5.1 : la racine signe un intermédiaire qui lui SURVIT. La chaîne
    # deviendrait invalide à la fin de la racine, avant celle des certificats émis :
    # une troncature silencieuse vue du client. Refus explicite.
    roots = [c for c in bundle if c.subject == c.issuer]
    if roots and signed[0].not_valid_after_utc > roots[0].not_valid_after_utc:
        raise PkiTtlError("issuer_expires_too_soon",
                          "Intermédiaire non importé : il expirerait après la racine "
                          f"({roots[0].not_valid_after_utc.isoformat()}). Réduire int_ttl.")

    import_resp = await bao_step(lambda: client.write(
        f"{_INT_MOUNT}/intermediate/set-signed",
        certificate=signed_bundle,
    ))
    imported_issuers = import_resp.get("data", {}).get("imported_issuers", []) if import_resp else []
    new_issuer_id = imported_issuers[0] if imported_issuers else ""
    if new_issuer_id:
        await bao_step(lambda: client.write(f"{_INT_MOUNT}/config/issuers", default=new_issuer_id))
    return new_issuer_id


def _eab_required(eab_policy: Optional[str]) -> bool:
    """True si la politique EAB impose un External Account Binding."""
    return eab_policy in ("new-account-required", "always-required")


def _domain_allowed(name: str, allowed_domains: list) -> bool:
    """
    True si `name` (FQDN) appartient à l'un des domaines autorisés du rôle :
    correspondance exacte ou sous-domaine. Validation locale (issue #41) en
    complément du contrôle OpenBao — on ne délègue pas uniquement au backend.
    """
    name = (name or "").lower().strip().rstrip(".")
    if not name:
        return False
    for d in (allowed_domains or []):
        d = (d or "").lower().strip().rstrip(".")
        if not d:
            continue
        if d.startswith("*."):
            d = d[2:]
        if name == d or name.endswith("." + d):
            return True
    return False

# Préfixe protégé — utilisé dans spaces.py et server.py pour refuser vault_delete
RESERVED_MOUNT_PREFIX = "_sys_pki_"

# SÉCURITÉ : regex de validation du serial_number (hex séparé par colons)
_SERIAL_NUMBER_PATTERN = re.compile(r'^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2})+$')

# SÉCURITÉ : regex de validation des domaines ACME (FQDN ou wildcard *.domain.tld)
_DOMAIN_PATTERN = re.compile(
    r'^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
)

# Lock global pour serialiser les appels à setup_pki_ca (idempotence + race condition)
_PKI_SETUP_LOCK: Optional[asyncio.Lock] = None


def _get_setup_lock() -> asyncio.Lock:
    # ⚠️ Lock per-process (asyncio) : NE FONCTIONNE QU'EN SINGLE-WORKER.
    # Pour multi-worker (uvicorn workers > 1), utiliser un verrou distribué.
    global _PKI_SETUP_LOCK
    if _PKI_SETUP_LOCK is None:
        _PKI_SETUP_LOCK = asyncio.Lock()
    return _PKI_SETUP_LOCK


def _get_hvac_client():
    """Lazy import de get_hvac_client (évite l'import hvac au niveau module)."""
    from ..openbao.manager import get_hvac_client
    return get_hvac_client()  # noqa: F821 — hvac importé dans get_hvac_client


def is_reserved_mount(vault_id: str) -> bool:
    """Retourne True si vault_id est un mount système PKI protégé."""
    return vault_id.startswith(RESERVED_MOUNT_PREFIX)


def _sha256_fingerprint(pem_text: str) -> str:
    """Empreinte SHA-256 d'un certificat PEM (format XX:XX:...)."""
    cert = x509.load_pem_x509_certificate(pem_text.encode())
    fp_bytes = cert.fingerprint(hashes.SHA256())
    return ":".join(f"{b:02X}" for b in fp_bytes)


def _cert_expiry_iso(pem_text: str) -> str:
    """Date d'expiration ISO 8601 d'un certificat PEM."""
    cert = x509.load_pem_x509_certificate(pem_text.encode())
    return cert.not_valid_after_utc.isoformat()


async def _read_pem_url(path: str) -> str:
    """
    Lit un endpoint PKI OpenBao retournant du texte PEM brut (non-JSON).

    Les endpoints /ca/pem, /ca_chain, /crl sont unauthenticated dans PKI engine.
    Valide que la réponse est du PEM avant de la retourner (sauf CRL — format DER/PEM distinct).
    """
    settings = get_settings()
    url = f"{settings.openbao_addr}/v1/{path}"
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(url, follow_redirects=False)
        resp.raise_for_status()

    # Validation minimale : le contenu doit commencer par un header PEM
    text = resp.text
    if not text.strip().startswith("-----BEGIN "):
        raise ValueError(f"Réponse OpenBao non-PEM pour {path} : {text[:80]!r}")
    return text


def is_pki_initialized() -> bool:
    """Retourne True si les deux mounts PKI système sont montés."""
    client = _get_hvac_client()
    if not client:
        return False
    try:
        mounts = bao_step_sync(lambda: client.sys.list_mounted_secrets_engines())
        data = mounts.get("data", mounts)
        return f"{_ROOT_MOUNT}/" in data and f"{_INT_MOUNT}/" in data
    except Exception:
        return False


def _base_url() -> str:
    """URL publique de la façade mcp-vault (issuing_certificates, ACME directory).

    Priorité : PKI_BASE_URL (override explicite, ex: http://mcp-vault:8030 en test Docker)
    > premier FQDN non-loopback de MCP_ALLOWED_HOSTS (https://{fqdn})
    > fallback localhost (invalide en prod — warning émis).
    """
    settings = get_settings()
    if settings.pki_base_url:
        return settings.pki_base_url_validated
    hosts = settings.allowed_hosts_list
    loopback = {"127.0.0.1", "localhost", "::1"}
    fqdn = next((h for h in hosts if h not in loopback), None)
    if not fqdn:
        logger.warning(
            "⚠️ PKI : aucun FQDN public dans MCP_ALLOWED_HOSTS — "
            "les CDPs et URLs ACME utiliseront localhost (invalides en prod). "
            "Configurer MCP_ALLOWED_HOSTS ou PKI_BASE_URL."
        )
        return "http://localhost:8080"
    return f"https://{fqdn}"


def _mount_pki_engine(client, mount: str, max_ttl: str) -> None:
    """Monte un engine PKI (idempotent — ignore si déjà monté)."""
    try:
        bao_step_sync(lambda: client.sys.enable_secrets_engine(
            backend_type="pki",
            path=mount,
            config={"max_lease_ttl": max_ttl},
        ))
        logger.info(f"✅ PKI engine monté : {mount}")
    except Exception as e:
        msg = str(e).lower()
        if "existing mount" not in msg and "path is already in use" not in msg:
            raise


def _acme_closed(data) -> bool:
    # Un mount vierge est aussi disabled, mais sa politique vaut sign-verbatim.
    return (isinstance(data, dict) and data.get("enabled") is False
            and data.get("default_directory_policy") == "forbid")


def _read_acme_setup(client) -> tuple[bool, list[str]]:
    """Conserve les rôles nommés dans config/acme, pas tous les rôles du mount."""
    response = bao_step_sync(lambda: client.read(f"{_INT_MOUNT}/config/acme"))
    # hvac.read rend None pour un 404 (notamment avant le premier montage).
    if response is None:
        return False, [_ACME_ROLE_NAME]
    data = response.get("data") if isinstance(response, dict) else None
    roles = data.get("allowed_roles") if isinstance(data, dict) else None
    if (not isinstance(roles, list) or not roles
            or any(not isinstance(role, str) or not role.strip() for role in roles)):
        raise ValueError("Configuration ACME existante invalide : allowed_roles")
    if not isinstance(data.get("enabled"), bool):
        raise ValueError("Configuration ACME existante invalide : enabled")
    if not data["enabled"] and not data.get("default_directory_policy"):
        raise ValueError("Configuration ACME existante invalide : default_directory_policy")
    closed = _acme_closed(data)
    # Le défaut OpenBao d'un mount neuf est ["*"]. Le setup le restreint
    # toujours au rôle maison, comme auparavant ; aucun wildcard n'est promu.
    if roles == ["*"]:
        return closed, [_ACME_ROLE_NAME]
    if "*" in roles:
        raise ValueError("Configuration ACME ambiguë : wildcard et rôles nommés")
    preserved = list(dict.fromkeys([_ACME_ROLE_NAME, *roles]))
    # OpenBao refuse config/acme si un rôle autorisé a depuis été supprimé.
    # Le détecter avant toute écriture, sans supprimer silencieusement ce rôle
    # de la configuration ni énumérer les autres rôles du mount.
    for role in preserved:
        if role == _ACME_ROLE_NAME:  # Le setup crée/reconfigure ce rôle maison.
            continue
        response = bao_step_sync(lambda: client.read(f"{_INT_MOUNT}/roles/{role}"))
        if not isinstance(response, dict) or not isinstance(response.get("data"), dict):
            raise ValueError(f"Rôle ACME configuré absent ou illisible : {role}")
    return closed, preserved


async def setup_pki_ca(lab_mode: bool = True,
                       allowed_domains: Optional[list] = None,
                       leaf_ttl: str = "720h",
                       root_ttl: Optional[str] = None,
                       int_ttl: Optional[str] = None,
                       acme: Optional[bool] = None) -> dict:
    """
    Configure la hiérarchie PKI complète (racine + intermédiaire + ACME).

    Idempotent : reconfigure sans détruire les mounts existants.
    Lab : CA racine self-signed. Prod : générer un CSR, signer extern, importer.

    Durées (issue #206) : `root_ttl` / `int_ttl` explicites règlent aussi le
    `max_lease_ttl` des mounts. Omises, elles CONSERVENT les plafonds d'une PKI
    existante (défauts historiques 87600h / 43800h à la création). La racine
    n'est générée qu'une fois : sur une racine existante, `root_ttl` ne change
    que le plafond du mount (`root_created: false` dans la réponse).

    Sync S3 forcée après setup (durabilité CA critique).
    """
    if acme is not None and not isinstance(acme, bool):
        return {"status": "error", "message": "acme doit être un booléen"}
    if allowed_domains is None:
        allowed_domains = ["*.lesur.lan", "lesur.lan"] if lab_mode and acme is not False else []

    if not allowed_domains and acme is not False:
        return {"status": "error", "message": "allowed_domains requis"}

    # MOYEN : validation du format des domaines autorisés (FQDN ou wildcard *.domain.tld)
    for domain in allowed_domains:
        if not _DOMAIN_PATTERN.fullmatch(domain.strip()):
            return {"status": "error", "message": f"Domaine invalide : '{domain}' (format FQDN requis)"}

    client = _get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    base = _base_url()

    # ÉLEVÉ : lock global pour éviter les race conditions si setup_pki_ca est appelé en parallèle
    async with _get_setup_lock():
        try:
            # Lecture avant toute mutation : un accès refusé ou un état illisible
            # ne doit jamais être pris pour une liste vide à écraser.
            closed, acme_roles = await run_blocking(_read_acme_setup, client)
            enable_acme = not closed if acme is None else acme
            if enable_acme and _CSR_ROLE_NAME in acme_roles:
                raise ValueError("Le rôle de signature de CSR ne peut pas être exposé par ACME")

            # Durées effectives (issue #206) : explicite > plafond existant > défaut.
            root_sec, root_ttl_eff = _resolve_ttl(
                root_ttl, await run_blocking(_read_mount_max_ttl, client, _ROOT_MOUNT),
                _DEFAULT_ROOT_TTL, "root_ttl")
            int_sec, int_ttl_eff = _resolve_ttl(
                int_ttl, await run_blocking(_read_mount_max_ttl, client, _INT_MOUNT),
                _DEFAULT_INT_TTL, "int_ttl")
            leaf_sec = _ttl_to_seconds(leaf_ttl)
            if not int_sec < root_sec or (leaf_sec is not None and not leaf_sec < int_sec):
                raise PkiTtlError("invalid_input",
                                  "Durées incohérentes : leaf_ttl < int_ttl < root_ttl requis")

            if not enable_acme:
                # Fermer avant toute mutation d'autorité. Une panne ultérieure
                # laisse le marqueur persistant en place, y compris au rejeu.
                await run_blocking(_mount_pki_engine, client, _INT_MOUNT, int_ttl_eff)
                other_roles = [role for role in acme_roles if role != _ACME_ROLE_NAME]
                await bao_step(lambda: client.write(
                    f"{_INT_MOUNT}/config/acme", enabled=False,
                    default_directory_policy="forbid", allowed_roles=other_roles or ["*"],
                ))
                role_path = f"{_INT_MOUNT}/roles/{_ACME_ROLE_NAME}"
                existing = await bao_step(lambda: client.read(role_path))
                if existing is not None:
                    if not isinstance(existing, dict) or not isinstance(existing.get("data"), dict):
                        raise ValueError("Rôle ACME illisible après fermeture du service")
                    await bao_step(lambda: client.delete(role_path))

            # ── 1. CA Racine ────────────────────────────────────────────────
            await run_blocking(_mount_pki_engine, client, _ROOT_MOUNT, root_ttl_eff)
            if root_ttl is not None:
                # Avant la génération : le plafond du mount tronque SILENCIEUSEMENT
                # la racine et les intermédiaires qu'elle signe (mesuré sur 2.5.1).
                await run_blocking(_tune_max_ttl, client, _ROOT_MOUNT, root_ttl_eff)

            root_cert_pem = ""
            root_created = False
            try:
                t0 = datetime.now(timezone.utc)
                root_resp = await bao_step(lambda: client.write(
                    f"{_ROOT_MOUNT}/root/generate/internal",
                    common_name="MCP Vault Root CA",
                    ttl=root_ttl_eff,
                    key_type="rsa",
                    key_bits=4096,
                    issuer_name="mcp-vault-root",
                ))
                root_cert_pem = root_resp.get("data", {}).get("certificate", "") if root_resp else ""
                root_created = bool(root_cert_pem)
                if root_created:
                    shortfall = _validity_shortfall(
                        x509.load_pem_x509_certificate(root_cert_pem.encode()), t0, root_sec)
                    if shortfall:
                        # Défense en profondeur : le tune ci-dessus l'empêche.
                        raise PkiTtlError("ttl_truncated", f"Racine {shortfall}")
            except PkiTtlError:
                raise
            except Exception as e:
                if "issuer name already in use" in str(e).lower():
                    logger.info("ℹ️  CA racine déjà générée — skip génération (idempotent)")
                else:
                    raise
            if not root_cert_pem:
                # Racine existante : rendre son expiration RÉELLE plutôt que « inconnu ».
                try:
                    root_cert_pem = await _read_pem_url(f"{_ROOT_MOUNT}/ca/pem")
                except Exception as e:
                    logger.warning("Lecture de la racine existante impossible : %s", type(e).__name__)

            await bao_step(lambda: client.write(
                f"{_ROOT_MOUNT}/config/urls",
                issuing_certificates=[f"{base}/pki/ca/root.pem"],
                crl_distribution_points=[f"{base}/pki/ca/crl.pem"],
            ))
            logger.info("✅ CA racine PKI configurée")

            # ── 2. CA Intermédiaire ─────────────────────────────────────────
            if enable_acme:
                await run_blocking(_mount_pki_engine, client, _INT_MOUNT, int_ttl_eff)

                # Autoriser OpenBao à renvoyer les headers de réponse ACME (RFC 8555).
                # Sans ce tuning, OpenBao strippe Replay-Nonce/Link/Location et
                # l'enrôlement ACME (newNonce, newOrder) échoue côté client — y compris
                # en lab. C'est un prérequis dur : on fait échouer le setup si le tuning
                # échoue, plutôt que d'annoncer une PKI opérationnelle qui ne l'est pas.
                try:
                    await bao_step(lambda: client.sys.tune_mount_configuration(
                        path=_INT_MOUNT,
                        allowed_response_headers=_ACME_RESPONSE_HEADERS,
                    ))
                    logger.info("✅ Tuning ACME headers : %s", ", ".join(_ACME_RESPONSE_HEADERS))
                except Exception as e:
                    logger.error("❌ Tuning allowed_response_headers échoué : %s", type(e).__name__)
                    raise RuntimeError(
                        "Tuning ACME headers (Replay-Nonce/Link/Location) échoué — "
                        "l'enrôlement ACME serait cassé ; setup PKI interrompu"
                    ) from e

            try:
                await _sign_and_import_intermediate(
                    client, "MCP Vault Intermediate CA", int_ttl_eff, int_sec)
            except PkiTtlError:
                raise
            except Exception as e:
                if "issuer name already in use" in str(e).lower():
                    logger.info("ℹ️  CA intermédiaire déjà générée — skip génération (idempotent)")
                else:
                    raise
            if int_ttl is not None:
                # Après l'import réussi : le plafond du mount intermédiaire borne
                # les feuilles, il ne doit pas changer si l'intermédiaire est refusé.
                await run_blocking(_tune_max_ttl, client, _INT_MOUNT, int_ttl_eff)

            await bao_step(lambda: client.write(
                f"{_INT_MOUNT}/config/urls",
                issuing_certificates=[f"{base}/pki/ca/chain.pem"],
                crl_distribution_points=[f"{base}/pki/ca/crl.pem"],
            ))
            logger.info("✅ CA intermédiaire PKI configurée")

            eab_policy = None
            if enable_acme:
                # ── 3. Rôle d'émission ACME ─────────────────────────────────────
                await bao_step(lambda: client.write(
                    f"{_INT_MOUNT}/roles/{_ACME_ROLE_NAME}",
                    server_flag=True,
                    client_flag=False,
                    allow_any_name=False,
                    allow_localhost=False,
                    allow_ip_sans=False,
                    allowed_domains=allowed_domains,
                    allow_bare_domains=True,   # émettre pour les domaines exactement listés
                    allow_subdomains=True,
                    allow_glob_domains=True,   # supporter les patterns *.domain dans allowed_domains
                    allow_wildcard_certificates=True,
                    enforce_hostnames=True,
                    max_ttl=leaf_ttl,
                    no_store=False,
                    key_type="any",   # clients ACME (Caddy) génèrent souvent des clés EC — ne pas imposer RSA
                    require_cn=False,
                ))
                logger.info(f"✅ Rôle ACME '{_ACME_ROLE_NAME}' configuré pour {allowed_domains}")

                # ── 3b. Cluster path (requis par OpenBao pour ACME) ─────────────
                # OpenBao génère des URLs absolues dans le directory ACME basées
                # sur ce chemin. PkiMiddleware gère les deux patterns :
                #   /acme/*               (URL courte, user-facing)
                #   /v1/_sys_pki_int/acme/* (URL longue, générée par OpenBao)
                # Note : hvac.write(path, **kwargs) a path en 1er arg → collision
                # avec le champ body OpenBao "path". On passe par l'adaptateur.
                _cluster_path = f"{base}/v1/{_INT_MOUNT}"
                await bao_step(lambda: client._adapter.post(
                    f"/v1/{_INT_MOUNT}/config/cluster",
                    json={"path": _cluster_path},
                ))
                logger.info(f"✅ Cluster path PKI configuré : {_cluster_path}")

                # ── 4. Serveur ACME ─────────────────────────────────────────────
                eab_policy = _EAB_POLICY_LAB if lab_mode else _EAB_POLICY_PROD
                await bao_step(lambda: client.write(
                    f"{_INT_MOUNT}/config/acme",
                    enabled=True,
                    default_directory_policy=f"role:{_ACME_ROLE_NAME}",
                    allowed_roles=acme_roles,
                    allowed_issuers=["*"],
                    eab_policy=eab_policy,
                ))
                logger.info("✅ Serveur ACME activé (eab_policy=%s)", eab_policy)

            # ── 5. Sync S3 forcée ───────────────────────────────────────────
            from ..s3_sync import upload_to_s3
            sync_ok = await upload_to_s3()
            if not sync_ok:
                logger.error("❌ Sync S3 échouée après setup PKI — durabilité CA compromise")
            else:
                logger.info("✅ Sync S3 OK après setup PKI")

            try:
                root_expiry = _cert_expiry_iso(root_cert_pem) if root_cert_pem else "inconnu"
                root_fp = _sha256_fingerprint(root_cert_pem) if root_cert_pem else ""
            except ValueError:  # racine existante relue illisible : ne pas inventer
                root_expiry, root_fp = "inconnu", ""

            return {
                "status": "ok",
                "lab_mode": lab_mode,
                "root_mount": _ROOT_MOUNT,
                "int_mount": _INT_MOUNT,
                "acme_enabled": enable_acme,
                "acme_directory": f"{base}/acme/directory" if enable_acme else None,
                "root_pem_url": f"{base}/pki/ca/root.pem",
                "chain_pem_url": f"{base}/pki/ca/chain.pem",
                "crl_url": f"{base}/pki/ca/crl.pem",
                "root_expires": root_expiry,
                "root_fingerprint_sha256": root_fp,
                "allowed_domains": allowed_domains if enable_acme else [],
                "leaf_ttl": leaf_ttl,
                "root_ttl": root_ttl_eff,
                "int_ttl": int_ttl_eff,
                "root_created": root_created,
                "eab_policy": eab_policy,
                "eab_required": _eab_required(eab_policy),
                "s3_sync_ok": sync_ok,
            }
        except PkiTtlError as e:
            logger.error("❌ Setup PKI CA refusé (%s) : %s", e.error_type, e)
            return {"status": "error", "error_type": e.error_type, "message": str(e)}
        except Exception as e:
            logger.error(f"❌ Erreur setup PKI CA : {e}")
            return {"status": "error", "message": str(e)}


async def get_ca_root_pem() -> dict:
    """Retourne la CA racine PEM avec empreinte SHA-256 et URL stable."""
    if not await run_blocking(is_pki_initialized):
        return {"status": "error", "message": "PKI non initialisée — appelez pki_ca_setup"}
    try:
        pem = await _read_pem_url(f"{_ROOT_MOUNT}/ca/pem")
        return {
            "status": "ok",
            "pem": pem,
            "sha256_fingerprint": _sha256_fingerprint(pem),
            "expires": _cert_expiry_iso(pem),
            "url": f"{_base_url()}/pki/ca/root.pem",
            "usage": "Ajouter dans le trust store des clients httpx et Caddyfile (trusted_ca_file / acme_ca_root)",
        }
    except Exception as e:
        logger.error(f"❌ Erreur lecture CA racine : {e}")
        return {"status": "error", "message": str(e)}


async def get_pki_status() -> dict:
    """État complet de la PKI (issuers, expiration, ACME, compteur certs)."""
    if not await run_blocking(is_pki_initialized):
        return {"status": "not_initialized", "message": "PKI non initialisée"}

    client = _get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    try:
        try:
            certs_resp = await bao_step(lambda: client.list(f"{_INT_MOUNT}/certs"))
            cert_count = len(certs_resp.get("data", {}).get("keys", []))
        except Exception:
            cert_count = 0

        try:
            root_pem = await _read_pem_url(f"{_ROOT_MOUNT}/ca/pem")
            root_expires = _cert_expiry_iso(root_pem)
            root_fp = _sha256_fingerprint(root_pem)
        except Exception:
            root_expires, root_fp = "inconnu", ""

        try:
            int_pem = await _read_pem_url(f"{_INT_MOUNT}/ca/pem")
            int_expires = _cert_expiry_iso(int_pem)
        except Exception:
            int_expires = "inconnu"

        acme_cfg = await bao_step(lambda: client.read(f"{_INT_MOUNT}/config/acme"))
        acme_data = acme_cfg.get("data") if isinstance(acme_cfg, dict) else None
        if not isinstance(acme_data, dict) or not isinstance(acme_data.get("enabled"), bool):
            return {"status": "error", "message": "État ACME illisible dans OpenBao"}
        acme_enabled = acme_data["enabled"]
        eab_policy = acme_data.get("eab_policy", "unknown") if acme_enabled else None

        base = _base_url()
        return {
            "status": "ok",
            "initialized": True,
            "root_expires": root_expires,
            "root_fingerprint_sha256": root_fp,
            "int_expires": int_expires,
            "cert_count": cert_count,
            "acme_enabled": acme_enabled,
            "eab_policy": eab_policy,
            "eab_required": _eab_required(eab_policy),
            "acme_directory": f"{base}/acme/directory" if acme_enabled else None,
            "root_pem_url": f"{base}/pki/ca/root.pem",
            "chain_pem_url": f"{base}/pki/ca/chain.pem",
            "crl_url": f"{base}/pki/ca/crl.pem",
        }
    except Exception as e:
        logger.error(f"❌ Erreur status PKI : {e}")
        return {"status": "error", "message": str(e)}


async def list_pki_roles() -> dict:
    """Liste les rôles d'émission PKI configurés sur la CA intermédiaire."""
    if not await run_blocking(is_pki_initialized):
        return {"status": "error", "message": "PKI non initialisée"}

    client = _get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    try:
        response = await bao_step(lambda: client.list(f"{_INT_MOUNT}/roles"))
        roles = safe_list_keys(response)  # None si aucun rôle (issue #38)
        return {"status": "ok", "roles": roles, "count": len(roles)}
    except Exception as e:
        msg = str(e).lower()
        if "404" in msg or "no entries" in msg:
            return {"status": "ok", "roles": [], "count": 0}
        logger.error(f"❌ Erreur liste rôles PKI : {e}")
        return {"status": "error", "message": str(e)}


async def get_pki_role_info(role_name: str) -> dict:
    """Détails d'un rôle d'émission PKI (domaines, TTL, flags TLS)."""
    if not role_name:
        return {"status": "error", "message": "role_name requis"}
    if not await run_blocking(is_pki_initialized):
        return {"status": "error", "message": "PKI non initialisée"}

    client = _get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    try:
        response = await bao_step(lambda: client.read(f"{_INT_MOUNT}/roles/{role_name}"))
        if not response or not response.get("data"):
            return {"status": "error", "message": f"Rôle PKI '{role_name}' non trouvé"}
        data = response["data"]
        return {
            "status": "ok",
            "role_name": role_name,
            "allowed_domains": data.get("allowed_domains", []),
            "allow_any_name": data.get("allow_any_name", False),
            "allow_subdomains": data.get("allow_subdomains", False),
            "allow_wildcard_certificates": data.get("allow_wildcard_certificates", False),
            "server_flag": data.get("server_flag", False),
            "client_flag": data.get("client_flag", False),
            "allow_ip_sans": data.get("allow_ip_sans", False),
            "allow_localhost": data.get("allow_localhost", False),
            "max_ttl": data.get("max_ttl", ""),
            "key_type": data.get("key_type", ""),
            "key_bits": data.get("key_bits", 0),
        }
    except Exception as e:
        logger.error(f"❌ Erreur info rôle PKI '{role_name}' : {e}")
        return {"status": "error", "message": str(e)}


async def list_issued_certs(limit: int = 100, offset: int = 0) -> dict:
    """Inventaire paginé des certificats émis (serials, SANs, expiration, révocation)."""
    if not await run_blocking(is_pki_initialized):
        return {"status": "error", "message": "PKI non initialisée"}

    client = _get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    try:
        certs_resp = await bao_step(lambda: client.list(f"{_INT_MOUNT}/certs"))
        all_serials = safe_list_keys(certs_resp)  # None si aucun cert émis (issue #38)
        total = len(all_serials)
        page_serials = all_serials[offset:offset + limit]

        certs = []
        for serial in page_serials:
            try:
                cert_resp = await bao_step(lambda: client.read(f"{_INT_MOUNT}/cert/{serial}"))
                cert_data = cert_resp.get("data", {}) if cert_resp else {}
                cert_pem = cert_data.get("certificate", "")
                revocation_time = cert_data.get("revocation_time", 0)

                entry: dict = {"serial": serial, "revoked": revocation_time > 0}

                if cert_pem:
                    try:
                        cert = x509.load_pem_x509_certificate(cert_pem.encode())
                        entry["not_after"] = cert.not_valid_after_utc.isoformat()
                        try:
                            san_ext = cert.extensions.get_extension_for_oid(
                                x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                            )
                            entry["sans"] = [str(n.value) for n in san_ext.value]
                        except x509.ExtensionNotFound:
                            entry["sans"] = []
                    except Exception:
                        pass

                certs.append(entry)
            except Exception:
                certs.append({"serial": serial, "error": "unreadable"})

        return {
            "status": "ok",
            "total": total,
            "offset": offset,
            "limit": limit,
            "certs": certs,
        }
    except Exception as e:
        msg = str(e).lower()
        if "404" in msg or "no entries" in msg:
            return {"status": "ok", "total": 0, "offset": offset, "limit": limit, "certs": []}
        logger.error(f"❌ Erreur inventaire certs PKI : {e}")
        return {"status": "error", "message": str(e)}


def _ensure_manual_role(client, allowed_domains: list, max_ttl: str) -> None:
    """
    Crée/met à jour (idempotent) le rôle d'émission manuelle `manual-servers`.

    Distinct du rôle ACME : autorise les IP SANs, refuse les wildcards (émission
    manuelle nominative), no_store=False (inventaire). Domaines alignés sur la PKI.
    """
    bao_step_sync(lambda: client.write(
        f"{_INT_MOUNT}/roles/{_MANUAL_ROLE_NAME}",
        server_flag=True,
        client_flag=False,
        allow_any_name=False,
        allow_localhost=False,
        allow_ip_sans=True,
        allowed_domains=allowed_domains,
        allow_bare_domains=True,   # émettre pour les domaines exactement listés
        allow_subdomains=True,
        allow_glob_domains=True,
        allow_wildcard_certificates=False,
        enforce_hostnames=True,
        max_ttl=max_ttl,
        no_store=False,
        key_type="rsa",
        key_bits=2048,
        require_cn=True,
    ))


async def issue_certificate(common_name: str, ttl: str = "720h",
                            alt_names: str = "", ip_sans: str = "") -> dict:
    """
    Émet un certificat serveur signé par la CA intermédiaire (émission manuelle,
    hors ACME — issue #41).

    Sécurité :
    - common_name et alt_names DNS validés localement contre les allowed_domains
      du rôle ACME (en plus du contrôle OpenBao via le rôle manual-servers).
    - ip_sans validés via ipaddress.
    - ttl borné par le max_ttl du rôle (OpenBao) + format validé localement.
    - private_key retournée UNE FOIS (jamais stockée côté Vault, jamais loggée).

    Returns: {status, serial_number, certificate, private_key (SENSIBLE),
              ca_chain, expiration, common_name}
    """
    if not await run_blocking(is_pki_initialized):
        return {"status": "error", "message": "PKI non initialisée"}

    client = _get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    common_name = (common_name or "").strip().lower()
    if not common_name:
        return {"status": "error", "error_type": "invalid_input", "message": "common_name requis"}
    if not _TTL_PATTERN.fullmatch(ttl or ""):
        return {"status": "error", "error_type": "invalid_input",
                "message": "ttl invalide (ex: 720h, 30m, 90d)"}

    # Domaines autorisés de la PKI (lus sur le rôle ACME) — référence de validation.
    try:
        role_resp = await bao_step(lambda: client.read(f"{_INT_MOUNT}/roles/{_ACME_ROLE_NAME}"))
        role_data = (role_resp or {}).get("data") or {}
        # OpenBao peut renvoyer allowed_domains en liste OU chaîne CSV → normaliser.
        allowed_domains = _normalize_domain_list(role_data.get("allowed_domains"))
        role_max_ttl_sec = _ttl_to_seconds(role_data.get("max_ttl")) or _ttl_to_seconds("8760h")
        role_max_ttl = role_data.get("max_ttl") or "8760h"
        if isinstance(role_max_ttl, int):
            role_max_ttl = f"{role_max_ttl}s"
    except Exception as e:
        logger.error("issue_certificate : lecture rôle ACME échouée : %s", type(e).__name__)
        return {"status": "error", "message": "Impossible de lire la configuration PKI"}

    if not allowed_domains:
        return {"status": "error", "message": "Aucun domaine autorisé configuré sur la PKI"}

    # Validation locale de la borne TTL (pas seulement le format) — défense en profondeur.
    req_ttl_sec = _ttl_to_seconds(ttl)
    if req_ttl_sec is None:
        return {"status": "error", "error_type": "invalid_input",
                "message": "ttl invalide (ex: 720h, 30m, 90d)"}
    if role_max_ttl_sec and req_ttl_sec > role_max_ttl_sec:
        return {"status": "error", "error_type": "invalid_input",
                "message": f"ttl {ttl} dépasse le max autorisé ({role_max_ttl})"}

    # Validation locale des noms DNS (CN + alt_names) contre allowed_domains.
    extra_dns = [a.strip().lower() for a in (alt_names or "").split(",") if a.strip()]
    for name in [common_name] + extra_dns:
        if "*" in name:
            return {"status": "error", "error_type": "invalid_input",
                    "message": f"Wildcard interdit en émission manuelle : {name}"}
        if not _domain_allowed(name, allowed_domains):
            return {"status": "error", "error_type": "domain_not_allowed",
                    "message": f"Nom hors domaines autorisés : {name}"}

    # Validation locale des IP SANs.
    ip_list = [x.strip() for x in (ip_sans or "").split(",") if x.strip()]
    if ip_list:
        import ipaddress
        for ip in ip_list:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                return {"status": "error", "error_type": "invalid_input",
                        "message": f"IP SAN invalide : {ip}"}

    # Rôle d'émission manuelle (idempotent, sous lock pour éviter les races).
    async with _get_setup_lock():
        try:
            await run_blocking(_ensure_manual_role, client, allowed_domains, role_max_ttl)
        except Exception as e:
            logger.error("issue_certificate : création rôle manual échouée : %s", type(e).__name__)
            return {"status": "error", "message": "Impossible de configurer le rôle d'émission"}

    # Émission.
    try:
        issue_args = {"common_name": common_name, "ttl": ttl}
        if extra_dns:
            issue_args["alt_names"] = ",".join(extra_dns)
        if ip_list:
            issue_args["ip_sans"] = ",".join(ip_list)
        t0 = datetime.now(timezone.utc)
        resp = await bao_step(lambda: client.write(f"{_INT_MOUNT}/issue/{_MANUAL_ROLE_NAME}", **issue_args))
        data = (resp or {}).get("data") or {}
    except Exception as e:
        err = str(e).lower()
        logger.error("issue_certificate OpenBao error: %s", type(e).__name__)
        if any(k in err for k in ("not allowed", "not match", "domain")):
            return {"status": "error", "error_type": "domain_not_allowed",
                    "message": "Nom refusé par la politique du rôle"}
        return {"status": "error", "error_type": "backend_error",
                "message": "Émission du certificat échouée (voir logs serveur)"}

    if not data.get("certificate") or not data.get("private_key"):
        return {"status": "error", "error_type": "backend_error",
                "message": "Réponse d'émission incomplète"}

    # Jamais de troncature silencieuse (issue #206) : un certificat plus court
    # que demandé n'est pas rendu, et sa clé non plus.
    try:
        shortfall = _validity_shortfall(
            x509.load_pem_x509_certificate(data["certificate"].encode()), t0, req_ttl_sec)
    except ValueError:
        return {"status": "error", "error_type": "backend_error",
                "message": "Certificat émis illisible"}
    if shortfall:
        logger.error("issue_certificate : %s (serial=%s)", shortfall, data.get("serial_number", "?"))
        return {"status": "error", "error_type": "ttl_truncated",
                "serial_number": data.get("serial_number", ""),
                "message": f"Émission refusée, {shortfall}. Faire tourner l'intermédiaire."}
    # Une feuille qui survivrait à sa chaîne (PKI héritée dont l'intermédiaire
    # dépasse la racine) cesserait d'être vérifiable avant sa fin : refus.
    try:
        leaf = x509.load_pem_x509_certificate(data["certificate"].encode())
        raw_chain = data.get("ca_chain") or []
        chain = [x509.load_pem_x509_certificate(p.encode())
                 for p in (raw_chain if isinstance(raw_chain, list) else [raw_chain])]
    except ValueError:
        return {"status": "error", "error_type": "backend_error",
                "message": "Chaîne d'émission illisible"}
    if any(leaf.not_valid_after_utc > c.not_valid_after_utc for c in chain):
        logger.error("issue_certificate : certificat au-delà de sa chaîne (serial=%s)",
                     data.get("serial_number", "?"))
        return {"status": "error", "error_type": "issuer_expires_too_soon",
                "serial_number": data.get("serial_number", ""),
                "message": "Émission refusée : le certificat expirerait après son autorité. "
                           "Faire tourner l'intermédiaire."}

    # Sync S3 (le nouveau cert est stocké dans l'inventaire).
    from ..s3_sync import upload_to_s3
    sync_ok = await upload_to_s3()
    if not sync_ok:
        logger.error("❌ Sync S3 échouée après émission cert — durabilité inventaire compromise")

    ca_chain = data.get("ca_chain")
    if isinstance(ca_chain, list):
        ca_chain = "\n".join(ca_chain)

    logger.info("✅ Certificat émis : cn=%s serial=%s", common_name, data.get("serial_number", "?"))
    return {
        "status": "ok",
        "common_name": common_name,
        "serial_number": data.get("serial_number", ""),
        "certificate": data.get("certificate", ""),
        "private_key": data.get("private_key", ""),  # SENSIBLE — one-shot
        "ca_chain": ca_chain or data.get("issuing_ca", ""),
        "expiration": data.get("expiration", ""),
        "s3_sync_ok": sync_ok,
    }


def _csr_rejected(reason: str) -> dict:
    return {"status": "error", "error_type": "csr_rejected", "message": f"CSR refusée : {reason}"}


def _validate_csr(csr_pem, domain: str):
    """Valide une CSR pour le rôle `csr-servers`. Retourne (csr, nom_dns) ou (None, erreur).

    Contrôle LOCAL, avant tout appel OpenBao : mesuré sur 2.5.1, `/sign/<rôle>`
    ACCEPTE une CSR à deux SAN (ou CN ≠ SAN) et IGNORE silencieusement une
    demande d'usage CA. Le rôle seul ne garantit donc pas « un seul nom, jamais CA ».
    """
    if not isinstance(csr_pem, str) or not csr_pem.strip():
        return None, _csr_rejected("CSR PEM requise")
    raw = csr_pem.strip().encode()
    if len(raw) > _CSR_MAX_PEM_BYTES:
        return None, _csr_rejected("taille supérieure à 16 Kio")
    if (raw.count(b"-----BEGIN ") != 1
            or not raw.startswith(b"-----BEGIN CERTIFICATE REQUEST-----")
            or not raw.endswith(b"-----END CERTIFICATE REQUEST-----")):
        return None, _csr_rejected("un seul bloc PEM « CERTIFICATE REQUEST » attendu")
    try:
        csr = x509.load_pem_x509_csr(raw)
        valid_signature = csr.is_signature_valid
        extensions = list(csr.extensions)  # lève sur une extension dupliquée ou invalide
        common_names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        public_key = csr.public_key()
    except Exception:
        return None, _csr_rejected("CSR illisible")
    if not valid_signature:
        return None, _csr_rejected("signature de la CSR invalide")
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or public_key.curve.key_size < 256:
        return None, _csr_rejected("clé EC (P-256 ou plus) requise")

    by_type = {type(ext.value): ext.value for ext in extensions}
    san = by_type.get(x509.SubjectAlternativeName)
    if san is None or len(san) != 1 or not isinstance(list(san)[0], x509.DNSName):
        return None, _csr_rejected("exactement un SAN, de type DNS, est requis (ni IP, ni URI, ni e-mail)")
    name = list(san)[0].value
    if len(common_names) > 1 or (common_names and common_names[0].value != name):
        return None, _csr_rejected("le CN, s'il est présent, doit être égal au SAN")
    if ("*" in name or name != name.lower() or len(name) > 253
            or not _DOMAIN_PATTERN.fullmatch(name)):
        return None, _csr_rejected(f"nom DNS invalide : {name[:80]!r} (ni joker, minuscules)")
    if not name.endswith("." + domain):
        return None, _csr_rejected(f"{name} n'est pas un sous-domaine de {domain}")

    constraints = by_type.get(x509.BasicConstraints)
    usage = by_type.get(x509.KeyUsage)
    if (constraints is not None and constraints.ca) or (
            usage is not None and (usage.key_cert_sign or usage.crl_sign)):
        return None, _csr_rejected("usage d'autorité de certification interdit")
    return csr, name


def _ensure_csr_role(client, domain: str, ttl: str) -> None:
    """Crée/met à jour (idempotent) le rôle `csr-servers` — restrictif sur tous les axes."""
    bao_step_sync(lambda: client.write(
        f"{_INT_MOUNT}/roles/{_CSR_ROLE_NAME}",
        server_flag=True,
        client_flag=False,
        allow_any_name=False,
        allow_localhost=False,
        allow_ip_sans=False,
        allowed_uri_sans="",
        allowed_other_sans="",
        allowed_domains=[domain],
        allow_bare_domains=False,
        allow_subdomains=True,
        allow_glob_domains=False,
        allow_wildcard_certificates=False,
        enforce_hostnames=True,
        key_type="ec",
        key_bits=256,
        ttl=ttl,
        max_ttl=ttl,
        no_store=False,      # inventaire pki_list_certs
        require_cn=False,
    ))


def _spki(key) -> bytes:
    return key.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


async def sign_csr(csr_pem: str) -> dict:
    """
    Signe une CSR sous le rôle restreint `csr-servers` (issue #206).

    La clé privée reste chez l'appelant : rien n'est généré, reçu ni rendu.
    Domaine et durée viennent de PKI_CSR_DOMAIN / PKI_CSR_TTL ; domaine vide =
    fonction désactivée. Le certificat rendu est contrôlé (un seul SAN, non-CA,
    même clé publique que la CSR, durée complète) avant d'être remis.

    Returns: {status, dns_name, serial_number, certificate, ca_chain
              (intermédiaire(s) sans la racine), not_after, root_fingerprint_sha256}
    """
    settings = get_settings()
    domain = (settings.pki_csr_domain or "").strip()
    if not domain:
        return {"status": "error", "error_type": "feature_disabled",
                "message": "Signature de CSR désactivée sur cette instance (PKI_CSR_DOMAIN vide)"}
    ttl = settings.pki_csr_ttl.strip()
    ttl_seconds = _ttl_to_seconds(ttl)

    csr, name_or_error = _validate_csr(csr_pem, domain)
    if csr is None:
        return name_or_error
    name = name_or_error

    if not await run_blocking(is_pki_initialized):
        return {"status": "error", "message": "PKI non initialisée"}
    client = _get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    async with _get_setup_lock():
        # La façade ACME (/acme/*, non authentifiée) sert les rôles que
        # config/acme autorise. Si `csr-servers` en fait partie (nommément ou
        # par `*`), on pourrait émettre sous ce rôle sans la garde MCP ni le
        # contrôle d'unicité du SAN : refuser de créer ou réécrire le rôle.
        try:
            acme = await bao_step(lambda: client.read(f"{_INT_MOUNT}/config/acme"))
        except Exception as e:
            logger.error("sign_csr : lecture config/acme échouée : %s", type(e).__name__)
            return {"status": "error", "error_type": "backend_error",
                    "message": "Configuration ACME illisible : signature refusée par précaution"}
        # Fermé par défaut : seule l'absence franche (404 → None) n'expose rien.
        # Toute autre forme doit porter une liste de noms de rôles non vides.
        data = acme.get("data") if isinstance(acme, dict) else None
        if acme is None:
            acme_roles = []
        else:
            acme_roles = data.get("allowed_roles") if isinstance(data, dict) else None
        if (not isinstance(acme_roles, list)
                or any(not isinstance(r, str) or not r.strip() for r in acme_roles)
                or _CSR_ROLE_NAME in acme_roles
                or ("*" in acme_roles and not (acme_roles == ["*"] and _acme_closed(data)))):
            return {"status": "error", "error_type": "unsafe_configuration",
                    "message": f"La configuration ACME autorise le rôle {_CSR_ROLE_NAME} "
                               "(nommément ou par '*') : signature refusée. Relancer "
                               "pki_ca_setup, qui restreint ACME au rôle acme-servers."}
        try:
            await run_blocking(_ensure_csr_role, client, domain, ttl)
        except Exception as e:
            logger.error("sign_csr : configuration du rôle échouée : %s", type(e).__name__)
            return {"status": "error", "error_type": "backend_error",
                    "message": "Impossible de configurer le rôle de signature"}

    t0 = datetime.now(timezone.utc)
    try:
        resp = await bao_step(lambda: client.write(
            f"{_INT_MOUNT}/sign/{_CSR_ROLE_NAME}", csr=csr_pem.strip(), ttl=ttl))
        data = (resp or {}).get("data") or {}
    except Exception as e:
        err = str(e).lower()
        logger.error("sign_csr OpenBao error: %s", type(e).__name__)
        if "beyond the expiration of the ca certificate" in err:
            return {"status": "error", "error_type": "issuer_expires_too_soon",
                    "message": f"L'intermédiaire expire avant {ttl} : faire tourner "
                               "l'intermédiaire (pki_ca_rotate_intermediate). Aucun "
                               "certificat raccourci n'est émis."}
        if "not allowed" in err:
            return _csr_rejected("nom refusé par la politique du rôle")
        return {"status": "error", "error_type": "backend_error",
                "message": "Signature échouée (voir logs serveur)"}

    serial = data.get("serial_number", "")
    try:
        cert = x509.load_pem_x509_certificate((data.get("certificate") or "").encode())
        chain = [x509.load_pem_x509_certificate(p.encode()) for p in (data.get("ca_chain") or [])]
        sans = list(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
        try:
            is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        except x509.ExtensionNotFound:
            is_ca = False
    except Exception:
        logger.error("sign_csr : réponse illisible (serial=%s)", serial or "?")
        return {"status": "error", "error_type": "backend_error",
                "serial_number": serial, "message": "Certificat signé illisible"}
    if (is_ca or len(sans) != 1 or not isinstance(sans[0], x509.DNSName)
            or sans[0].value != name or _spki(cert.public_key()) != _spki(csr.public_key())):
        logger.error("sign_csr : certificat non conforme à la CSR validée (serial=%s)", serial)
        return {"status": "error", "error_type": "backend_error", "serial_number": serial,
                "message": "Certificat signé non conforme à la CSR validée : non remis"}
    shortfall = _validity_shortfall(cert, t0, ttl_seconds)
    if shortfall:
        logger.error("sign_csr : %s (serial=%s)", shortfall, serial)
        return {"status": "error", "error_type": "ttl_truncated", "serial_number": serial,
                "message": f"Certificat non remis, {shortfall}. Faire tourner l'intermédiaire."}
    # Un certificat qui survivrait à sa chaîne cesserait d'être vérifiable avant
    # sa propre fin : même effet qu'une troncature, refus explicite.
    if not chain or any(cert.not_valid_after_utc > c.not_valid_after_utc for c in chain):
        logger.error("sign_csr : certificat au-delà de sa chaîne (serial=%s)", serial)
        return {"status": "error", "error_type": "issuer_expires_too_soon", "serial_number": serial,
                "message": "Certificat non remis : il expirerait après son autorité. "
                           "Faire tourner l'intermédiaire."}

    # Le serveur présente feuille + intermédiaire ; le client ne garde que la racine.
    intermediates = [c for c in chain if c.subject != c.issuer]
    roots = [c for c in chain if c.subject == c.issuer]

    from ..s3_sync import upload_to_s3
    sync_ok = await upload_to_s3()
    if not sync_ok:
        logger.error("❌ Sync S3 échouée après signature de CSR — durabilité inventaire compromise")

    logger.info("✅ CSR signée : dns=%s serial=%s", name, serial)
    return {
        "status": "ok",
        "dns_name": name,
        "serial_number": serial,
        "certificate": data["certificate"].strip() + "\n",
        "ca_chain": "".join(c.public_bytes(serialization.Encoding.PEM).decode()
                            for c in intermediates),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "root_fingerprint_sha256": (
            ":".join(f"{b:02X}" for b in roots[0].fingerprint(hashes.SHA256())) if roots else ""),
        "s3_sync_ok": sync_ok,
    }


async def revoke_cert(serial_number: str) -> dict:
    """
    Révoque un certificat et force la rotation de la CRL.

    Sync S3 forcée : la révocation est une mutation critique (ne pas perdre).
    """
    if not serial_number:
        return {"status": "error", "message": "serial_number requis"}
    # CRITIQUE : validation stricte du serial_number (format hex:xx:xx)
    if not _SERIAL_NUMBER_PATTERN.fullmatch(serial_number.strip()):
        return {"status": "error", "message": "serial_number invalide (format attendu : aa:bb:cc:...)"}
    if not await run_blocking(is_pki_initialized):
        return {"status": "error", "message": "PKI non initialisée"}

    client = _get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    try:
        revoke_resp = await bao_step(lambda: client.write(
            f"{_INT_MOUNT}/revoke",
            serial_number=serial_number.strip(),
        ))
        rev_time = revoke_resp.get("data", {}).get("revocation_time", 0) if revoke_resp else 0

        await bao_step(lambda: client.write(f"{_INT_MOUNT}/crl/rotate"))

        from ..s3_sync import upload_to_s3
        sync_ok = await upload_to_s3()
        if not sync_ok:
            logger.error(f"❌ Sync S3 échouée après révocation {serial_number} — CRL peut être obsolète en S3")

        logger.info(f"✅ Cert révoqué et CRL mise à jour : {serial_number}")
        return {
            "status": "ok",
            "serial_number": serial_number,
            "revocation_time": rev_time,
            "crl_updated": True,
            "s3_sync_ok": sync_ok,
        }
    except Exception as e:
        logger.error(f"❌ Erreur révocation cert {serial_number} : {e}")
        return {"status": "error", "message": str(e)}


async def rotate_intermediate(keep_old_issuer: bool = True,
                               overlap_ttl: str = "48h",
                               int_ttl: Optional[str] = None) -> dict:
    """
    Rotation sans coupure de la CA intermédiaire.

    Nouveau CSR → signature racine → contrôle de durée → import → set default issuer.
    L'ancien issuer reste actif si keep_old_issuer=True (certs existants valides).
    `int_ttl` explicite (issue #206) : durée du nouvel intermédiaire, et plafond
    du mount intermédiaire réglé APRÈS l'import réussi. Omis : durée = plafond
    actuel du mount intermédiaire (comportement inchangé). Le plafond racine
    n'est jamais modifié ici. Un intermédiaire plus court que demandé n'est pas
    importé (`ttl_truncated`).
    Sync S3 forcée après rotation.
    """
    if not await run_blocking(is_pki_initialized):
        return {"status": "error", "message": "PKI non initialisée"}

    client = _get_hvac_client()
    if not client:
        return {"status": "error", "message": "OpenBao non connecté"}

    try:
        int_sec, int_ttl_eff = _resolve_ttl(
            int_ttl, await run_blocking(_read_mount_max_ttl, client, _INT_MOUNT),
            _DEFAULT_INT_TTL, "int_ttl")

        old_config = await bao_step(lambda: client.read(f"{_INT_MOUNT}/config/issuers"))
        old_default_id = old_config.get("data", {}).get("default", "") if old_config else ""

        new_issuer_id = await _sign_and_import_intermediate(
            client, "MCP Vault Intermediate CA (rotated)", int_ttl_eff, int_sec)
        if new_issuer_id:
            logger.info(f"✅ Nouvel issuer intermédiaire défini comme default : {new_issuer_id}")
        if int_ttl is not None:
            await run_blocking(_tune_max_ttl, client, _INT_MOUNT, int_ttl_eff)

        if not keep_old_issuer and old_default_id:
            try:
                await bao_step(lambda: client.delete(f"{_INT_MOUNT}/issuer/{old_default_id}"))
                logger.info(f"🗑️ Ancien issuer supprimé : {old_default_id}")
            except Exception as e:
                logger.warning(f"⚠️ Impossible de supprimer l'ancien issuer {old_default_id} : {e}")

        from ..s3_sync import upload_to_s3
        sync_ok = await upload_to_s3()
        if not sync_ok:
            logger.error("❌ Sync S3 échouée après rotation intermédiaire — durabilité compromise")

        try:
            new_pem = await _read_pem_url(f"{_INT_MOUNT}/ca/pem")
            new_expires = _cert_expiry_iso(new_pem)
        except Exception:
            new_expires = "inconnu"

        return {
            "status": "ok",
            "old_issuer_id": old_default_id,
            "new_issuer_id": new_issuer_id,
            "new_expires": new_expires,
            "keep_old_issuer": keep_old_issuer,
            "overlap_ttl": overlap_ttl,
            "int_ttl": int_ttl_eff,
            "s3_sync_ok": sync_ok,
        }
    except PkiTtlError as e:
        logger.error("❌ Rotation intermédiaire refusée (%s) : %s", e.error_type, e)
        return {"status": "error", "error_type": e.error_type, "message": str(e)}
    except Exception as e:
        logger.error(f"❌ Erreur rotation intermédiaire PKI : {e}")
        return {"status": "error", "message": str(e)}
