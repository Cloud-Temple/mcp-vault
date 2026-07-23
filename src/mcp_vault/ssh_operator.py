# -*- coding: utf-8 -*-
"""Parcours SSH JIT opérateur pour un bearer nominatif à clé pré-enrôlée.

Le demandeur ne choisit jamais les attributs de sécurité du certificat. Un
``profile_id`` résout côté serveur l'identité bearer, l'empreinte de clé
autorisée, la CA, le rôle, le principal, la cible et le TTL.

Décision produit (2026-07-22) : ce parcours n'exige PAS de dispositif
matériel (FIDO2/clé de sécurité physique) — MCP Vault est avant tout un
serveur MCP, et l'identité de l'opérateur repose sur le même mécanisme que
tout le reste du système : un bearer token nominatif, scopé par une policy
dédiée. Un HSM (Thales Luna, à venir) répond à un problème différent — la
protection de la clé privée de la CA elle-même, pas la preuve de présence
physique d'un opérateur — les deux ne sont pas substituables. Voir
CHANGELOG.md pour le contexte complet de cette décision.

Le bearer étant désormais la SEULE autorité d'émission (2026-07-23, suite
revue adversariale) : son expiration doit être bornée
(``SSH_OPERATOR_JIT_MAX_BEARER_EXPIRES_DAYS``, défaut 1 jour) — un bearer
sans expiration ou trop long-vivant est refusé sur ce parcours, quelles que
soient ses autres permissions. La révocation multi-instance (cache
TokenStore 300s) reste une limitation connue et assumée pour une première
mise en production mono-instance, dans le même esprit que les limites déjà
documentées sur PolicyStore/TokenStore (#51/#13) — voir CHANGELOG.md.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .audit import log_audit
from .auth.context import (
    check_access,
    check_policy,
    check_write_permission,
    current_token_info,
)
from .auth.policies import PolicyStoreUnavailable, get_policy_store
from .auth.token_store import get_token_store
from .config import get_settings
from .vault.ssh_ca import sign_ssh_key
from .vault_ids import is_valid_vault_id


TOOL_LIST = "ssh_operator_access_profiles"
TOOL_REQUEST = "ssh_request_operator_access"
_DEDICATED_OPERATOR_TOOLS = frozenset({TOOL_LIST, TOOL_REQUEST})
_GENERIC_SSH_MUTATION_TOOLS = ("ssh_sign_key", "ssh_ca_setup")

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_SAFE_CLIENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$")
_SAFE_PRINCIPAL = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_SAFE_TARGET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
# Types de clé acceptés pour ce parcours : algorithmes modernes uniquement
# (pas de RSA pour l'instant — aucun besoin réel identifié, ré-évaluer si
# nécessaire). Ce sont des clés SSH STANDARD, pas des clés de sécurité
# matérielle (FIDO2) : voir la docstring de ce module pour le contexte.
_OPERATOR_KEY_TYPES = frozenset({
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
})


class OperatorSSHConfigurationError(ValueError):
    """Configuration de profils opérateur invalide."""


class OperatorSSHRequestError(ValueError):
    """Clé ou demande opérateur invalide."""


@dataclass(frozen=True)
class OperatorSSHProfile:
    profile_id: str
    client_name: str
    policy_id: str
    key_fingerprints: tuple[str, ...]
    vault_id: str
    role_name: str
    principal: str
    target: str
    ttl_seconds: int


@dataclass(frozen=True)
class InspectedOperatorPublicKey:
    key_type: str
    fingerprint: str
    canonical_public_key: str


def _decode_sha256_fingerprint(value: str) -> bytes:
    if not isinstance(value, str) or not value.startswith("SHA256:"):
        raise OperatorSSHConfigurationError("empreinte de clé invalide")
    encoded = value[7:]
    try:
        raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise OperatorSSHConfigurationError("empreinte de clé invalide") from exc
    canonical = base64.b64encode(raw).decode("ascii").rstrip("=")
    if len(raw) != hashlib.sha256().digest_size or canonical != encoded:
        raise OperatorSSHConfigurationError("empreinte de clé invalide")
    return raw


def _required_string(raw: dict, field: str, pattern: re.Pattern[str]) -> str:
    value = raw.get(field)
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise OperatorSSHConfigurationError(f"{field} invalide")
    return value


def parse_operator_profiles(settings=None) -> dict[str, OperatorSSHProfile]:
    """Parse et valide la configuration JSON des profils JIT.

    Le JSON peut être fourni directement ou en Base64 URL-safe pour traverser
    un renderer ``.env`` à alphabet restreint. Les deux sources sont
    mutuellement exclusives. Une configuration vide désactive volontairement
    la fonctionnalité ; toute autre forme invalide est refusée sans profil
    partiellement utilisable.
    """
    settings = settings or get_settings()
    json_source = settings.ssh_operator_profiles_json.strip()
    b64_source = settings.ssh_operator_profiles_b64.strip()
    max_config_chars = settings.ssh_operator_jit_max_config_chars
    if type(max_config_chars) is not int or max_config_chars < 1:
        raise OperatorSSHConfigurationError(
            "SSH_OPERATOR_JIT_MAX_CONFIG_CHARS invalide"
        )
    if json_source and b64_source:
        raise OperatorSSHConfigurationError(
            "SSH_OPERATOR_PROFILES_JSON et SSH_OPERATOR_PROFILES_B64 "
            "sont mutuellement exclusives"
        )
    if len(json_source) > max_config_chars or len(b64_source) > max_config_chars:
        raise OperatorSSHConfigurationError("configuration SSH opérateur surdimensionnée")

    source = json_source
    if b64_source:
        try:
            decoded = base64.b64decode(
                b64_source + "=" * (-len(b64_source) % 4),
                altchars=b"-_",
                validate=True,
            )
            canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
            if canonical != b64_source.rstrip("="):
                raise ValueError("encodage non canonique")
            source = decoded.decode("utf-8")
        except (binascii.Error, UnicodeError, ValueError) as exc:
            raise OperatorSSHConfigurationError(
                "SSH_OPERATOR_PROFILES_B64 invalide"
            ) from exc
        if len(source) > max_config_chars:
            raise OperatorSSHConfigurationError(
                "configuration SSH opérateur surdimensionnée"
            )
    if not source:
        return {}
    try:
        raw_profiles = json.loads(source)
    except (json.JSONDecodeError, TypeError) as exc:
        raise OperatorSSHConfigurationError("SSH_OPERATOR_PROFILES_JSON invalide") from exc
    if not isinstance(raw_profiles, dict):
        raise OperatorSSHConfigurationError("SSH_OPERATOR_PROFILES_JSON doit être un objet")
    max_profiles = settings.ssh_operator_jit_max_profiles
    if type(max_profiles) is not int or max_profiles < 1:
        raise OperatorSSHConfigurationError("SSH_OPERATOR_JIT_MAX_PROFILES invalide")
    if len(raw_profiles) > max_profiles:
        raise OperatorSSHConfigurationError("trop de profils SSH opérateur")

    max_reason = settings.ssh_operator_jit_max_reason_chars
    max_public_key = settings.ssh_operator_jit_max_public_key_chars
    if type(max_reason) is not int or max_reason < 1:
        raise OperatorSSHConfigurationError(
            "SSH_OPERATOR_JIT_MAX_REASON_CHARS invalide"
        )
    if type(max_public_key) is not int or max_public_key < 1:
        raise OperatorSSHConfigurationError(
            "SSH_OPERATOR_JIT_MAX_PUBLIC_KEY_CHARS invalide"
        )

    min_ttl = settings.ssh_operator_jit_min_ttl_seconds
    max_ttl = settings.ssh_operator_jit_max_ttl_seconds
    if type(min_ttl) is not int or type(max_ttl) is not int or min_ttl < 1 or max_ttl < min_ttl:
        raise OperatorSSHConfigurationError("bornes TTL SSH opérateur invalides")

    max_bearer_expires_days = settings.ssh_operator_jit_max_bearer_expires_days
    if type(max_bearer_expires_days) is not int or max_bearer_expires_days < 1:
        raise OperatorSSHConfigurationError(
            "SSH_OPERATOR_JIT_MAX_BEARER_EXPIRES_DAYS invalide"
        )

    required_fields = {
        "client_name", "policy_id", "key_fingerprints", "vault_id",
        "role_name", "principal", "target", "ttl_seconds",
    }
    profiles: dict[str, OperatorSSHProfile] = {}
    for profile_id, raw in raw_profiles.items():
        if not isinstance(profile_id, str) or not _SAFE_ID.fullmatch(profile_id):
            raise OperatorSSHConfigurationError("profile_id invalide")
        if not isinstance(raw, dict) or set(raw) != required_fields:
            raise OperatorSSHConfigurationError(
                f"profil '{profile_id}' incomplet ou avec champs inconnus"
            )
        fingerprints = raw.get("key_fingerprints")
        if not isinstance(fingerprints, list) or not fingerprints:
            raise OperatorSSHConfigurationError("key_fingerprints doit être une liste non vide")
        if not all(isinstance(item, str) for item in fingerprints):
            raise OperatorSSHConfigurationError("key_fingerprints invalide")
        for fingerprint in fingerprints:
            _decode_sha256_fingerprint(fingerprint)
        if len(set(fingerprints)) != len(fingerprints):
            raise OperatorSSHConfigurationError("empreinte de clé dupliquée")

        ttl_seconds = raw.get("ttl_seconds")
        if type(ttl_seconds) is not int or not min_ttl <= ttl_seconds <= max_ttl:
            raise OperatorSSHConfigurationError("ttl_seconds hors bornes")

        profiles[profile_id] = OperatorSSHProfile(
            profile_id=profile_id,
            client_name=_required_string(raw, "client_name", _SAFE_CLIENT),
            policy_id=_required_string(raw, "policy_id", _SAFE_ID),
            key_fingerprints=tuple(fingerprints),
            vault_id=_required_string(raw, "vault_id", _SAFE_ID),
            role_name=_required_string(raw, "role_name", _SAFE_ID),
            principal=_required_string(raw, "principal", _SAFE_PRINCIPAL),
            target=_required_string(raw, "target", _SAFE_TARGET),
            ttl_seconds=ttl_seconds,
        )
    return profiles


def reserved_operator_vaults(settings=None) -> frozenset[str]:
    """Coffres (vault_id) réservés par au moins un profil opérateur JIT.

    Bloquer uniquement le couple exact ``(vault_id, role_name)`` d'un profil
    NE SUFFIT PAS : la CA SSH OpenBao est partagée par ``mount`` (un seul
    mount par ``vault_id``), donc un bearer avec un droit d'écriture générique
    sur ce vault peut créer un rôle ALTERNATIF (``ssh_ca_setup``) dans le même
    mount puis signer une clé logicielle avec ce nouveau rôle — contournement
    démontré empiriquement en revue (rôle ``shadow-operator`` créé avec
    ``allowed_users="*"``, signature réussie sans ``verify-required``).
    Réserver un seul nom de rôle n'est donc pas une frontière de sécurité :
    c'est le ``vault_id`` entier qui doit être fermé aux outils SSH génériques
    dès qu'il héberge un profil opérateur. Propage
    ``OperatorSSHConfigurationError`` si la configuration ne peut pas être
    déterminée — l'appelant doit alors refuser par précaution (fail-closed).
    """
    profiles = parse_operator_profiles(settings)
    return frozenset(profile.vault_id for profile in profiles.values())


def check_not_reserved_for_operator(vault_id: str) -> dict | None:
    """Garde à appeler par les points d'entrée SSH génériques (signer, setup).

    Refuse TOUT appel générique — quel que soit le rôle, existant ou à créer
    — sur un coffre qui héberge un profil opérateur JIT. Voir
    ``reserved_operator_vaults()`` pour la justification (CA partagée par
    mount : réserver un rôle ne suffit pas, il faut réserver le coffre).

    Retourne ``None`` si l'appel générique peut continuer, un dict d'erreur
    sinon — y compris si l'état de la configuration opérateur ne peut pas
    être déterminé (fail-closed).

    SÉCURITÉ (round 5, revue Codex, BLOQUANT) : valide ``vault_id`` lui-même
    plutôt que de compter sur ``check_access()`` pour l'avoir déjà fait.
    ``check_access()`` autorise un bearer ADMIN avant toute validation de
    format (court-circuit légitime pour ses autres usages) — un admin
    fournissant ``"agentic-platform/"`` (slash final) atteignait donc ce
    garde avec un ``vault_id`` non canonique, que la comparaison stricte
    ``vault_id in reserved_vaults`` ne reconnaissait pas comme réservé
    (``hvac``/OpenBao normalisent pourtant le même mount côté backend) —
    contournement complet du parcours dédié avec un bearer admin légitime,
    sans exécution de code. Contraire au contrat non négociable de
    l'issue #96 : « un token admin sert à administrer/enrôler, jamais à
    contourner le contrôle d'identité opérateur ».
    """
    if not is_valid_vault_id(vault_id):
        return {
            "status": "error",
            "error_type": "invalid_request",
            "message": "Identifiant de coffre invalide — signature générique refusée par précaution",
        }
    try:
        reserved_vaults = reserved_operator_vaults()
    except OperatorSSHConfigurationError:
        return {
            "status": "error",
            "error_type": "configuration_error",
            "message": "Configuration SSH opérateur invalide — signature générique refusée par précaution",
        }
    if vault_id in reserved_vaults:
        return {
            "status": "error",
            "error_type": "reserved_for_operator_jit",
            "message": (
                "Coffre réservé au parcours opérateur JIT — aucune signature "
                "ni configuration SSH générique n'est autorisée sur ce "
                "coffre ; utilisez ssh_request_operator_access"
            ),
        }
    return None


def _read_ssh_field(blob: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(blob):
        raise OperatorSSHRequestError("clé publique tronquée")
    size = struct.unpack(">I", blob[offset:offset + 4])[0]
    start = offset + 4
    end = start + size
    if end > len(blob):
        raise OperatorSSHRequestError("clé publique tronquée")
    return blob[start:end], end


def inspect_operator_public_key(public_key: str) -> InspectedOperatorPublicKey:
    """Valide le wire format OpenSSH d'une clé standard et calcule son empreinte.

    Types acceptés : ``ssh-ed25519``, ``ecdsa-sha2-nistp256`` (cf.
    ``_OPERATOR_KEY_TYPES``) — des clés SSH standard, pas des clés de
    sécurité matérielle (FIDO2/``*-sk``, cf. docstring du module pour le
    contexte de cette décision).
    """
    if not isinstance(public_key, str):
        raise OperatorSSHRequestError("clé publique requise")
    parts = public_key.strip().split(None, 2)
    if len(parts) < 2 or parts[0] not in _OPERATOR_KEY_TYPES:
        raise OperatorSSHRequestError(
            "une clé publique OpenSSH ssh-ed25519 ou ecdsa-sha2-nistp256 est requise"
        )
    declared_type = parts[0]
    try:
        blob = base64.b64decode(parts[1] + "=" * (-len(parts[1]) % 4), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise OperatorSSHRequestError("clé publique encodée en Base64 invalide") from exc

    embedded_type, offset = _read_ssh_field(blob, 0)
    try:
        embedded_type_text = embedded_type.decode("ascii")
    except UnicodeDecodeError as exc:
        raise OperatorSSHRequestError("type de clé invalide") from exc
    if embedded_type_text != declared_type:
        raise OperatorSSHRequestError("type de clé déclaré différent du blob")

    if declared_type == "ssh-ed25519":
        key_bytes, offset = _read_ssh_field(blob, offset)
        if len(key_bytes) != 32:
            raise OperatorSSHRequestError("clé ed25519 de longueur invalide")
    else:
        curve, offset = _read_ssh_field(blob, offset)
        point, offset = _read_ssh_field(blob, offset)
        if curve != b"nistp256" or len(point) != 65 or not point.startswith(b"\x04"):
            raise OperatorSSHRequestError("clé ecdsa nistp256 invalide")
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
        except ValueError as exc:
            raise OperatorSSHRequestError("point public ecdsa invalide") from exc

    if offset != len(blob):
        raise OperatorSSHRequestError("données superflues dans la clé publique")

    fingerprint = "SHA256:" + base64.b64encode(
        hashlib.sha256(blob).digest()
    ).decode("ascii").rstrip("=")
    canonical_public_key = (
        f"{declared_type} {base64.b64encode(blob).decode('ascii')}"
    )
    return InspectedOperatorPublicKey(declared_type, fingerprint, canonical_public_key)


def _audit_denial(client_name: str, profile_id: str, message: str,
                  error_type: str = "forbidden") -> dict:
    log_audit(
        TOOL_REQUEST,
        "denied",
        detail=f"profile={profile_id or '(absent)'} - {message}",
        client_name=client_name or "unknown",
    )
    return {"status": "error", "error_type": error_type, "message": message}


def _current_operator_identity(profile_id: str) -> tuple[dict | None, dict | None]:
    token_info = current_token_info.get()
    if not isinstance(token_info, dict):
        return None, _audit_denial("unknown", profile_id, "Authentification opérateur requise")
    client_name = token_info.get("client_name", "")
    if token_info.get("auth_type") != "token" or "admin" in token_info.get("permissions", []):
        return None, _audit_denial(client_name, profile_id, "Bearer opérateur nominatif requis")
    # Fail-closed spécifique à ce parcours : un Token Store connu dégradé
    # (panne/corruption S3 détectée après TTL) ne doit jamais autoriser un
    # accès SSH privilégié depuis un cache potentiellement périmé, même si
    # `token_info` semble nominal. Ne modifie PAS le comportement global de
    # TokenStore.get_by_hash() (limite documentée, hors scope ici) : seul ce
    # parcours opérateur devient plus strict.
    store = get_token_store()
    if store is not None and not store.available:
        return None, _audit_denial(
            client_name, profile_id,
            "Store d'identité indisponible — accès opérateur refusé par précaution",
            "identity_store_unavailable",
        )
    if not isinstance(client_name, str) or not _SAFE_CLIENT.fullmatch(client_name):
        return None, _audit_denial("unknown", profile_id, "Identité opérateur invalide")
    # Durée bornée du bearer (décision produit, cf. docstring du module) : le
    # bearer est désormais la SEULE autorité d'émission de ce parcours (plus
    # de clé matérielle FIDO2), donc un bearer sans expiration ou trop
    # long-vivant lui donnerait une portée d'attaque illimitée en cas de vol.
    # TokenStore.get_by_hash() a déjà fail-close sur un bearer EXPIRÉ (et sur
    # une valeur non timezone-aware, au chargement) ; ce garde ne se fie
    # cependant pas qu'à cette garantie amont (défense en profondeur, revue
    # round 9) — il revalide lui-même le format ET re-rejette une expiration
    # naïve ou déjà passée, au cas où `current_token_info` serait un jour
    # construit autrement qu'en passant par TokenStore.
    expires_at = token_info.get("expires_at")
    if not expires_at:
        return None, _audit_denial(
            client_name, profile_id, "Bearer opérateur doit avoir une expiration bornée"
        )
    try:
        expiry = datetime.fromisoformat(expires_at)
    except (TypeError, ValueError):
        return None, _audit_denial(client_name, profile_id, "Bearer opérateur : expiration invalide")
    now = datetime.now(timezone.utc)
    if expiry.tzinfo is None or expiry <= now:
        return None, _audit_denial(client_name, profile_id, "Bearer opérateur : expiration invalide")
    max_window = timedelta(days=get_settings().ssh_operator_jit_max_bearer_expires_days)
    if expiry - now > max_window:
        return None, _audit_denial(
            client_name, profile_id, "Bearer opérateur trop long-vivant pour ce parcours"
        )
    return token_info, None


def _check_dedicated_policy(token_info: dict, profile: OperatorSSHProfile,
                            tool_name: str) -> dict | None:
    permissions = token_info.get("permissions")
    resources = token_info.get("allowed_resources")
    if (
        not isinstance(permissions, list)
        or len(permissions) != 2
        or set(permissions) != {"read", "write"}
        or resources != [profile.vault_id]
    ):
        return _audit_denial(
            token_info.get("client_name", ""), profile.profile_id,
            "Bearer opérateur hors périmètre minimal attendu",
        )
    policy_id = token_info.get("policy_id", "")
    if policy_id != profile.policy_id:
        return _audit_denial(
            token_info.get("client_name", ""), profile.profile_id,
            "Policy opérateur attendue absente",
        )
    policy_err = check_policy(tool_name)
    if policy_err:
        return policy_err
    store = get_policy_store()
    if store is None:
        return {
            "status": "error",
            "error_type": "policy_store_unavailable",
            "message": "Policy opérateur non vérifiable",
        }
    try:
        policy = store.get(policy_id)
        allowed_tools = policy.get("allowed_tools") if isinstance(policy, dict) else None
        if (
            not isinstance(allowed_tools, list)
            or len(allowed_tools) != len(_DEDICATED_OPERATOR_TOOLS)
            or set(allowed_tools) != _DEDICATED_OPERATOR_TOOLS
        ):
            return _audit_denial(
                token_info.get("client_name", ""), profile.profile_id,
                "Policy opérateur non dédiée aux seuls outils SSH JIT",
            )
        overly_broad = any(
            store.is_tool_allowed(policy_id, generic_tool)
            for generic_tool in _GENERIC_SSH_MUTATION_TOOLS
        )
    except PolicyStoreUnavailable:
        return {
            "status": "error",
            "error_type": "policy_store_unavailable",
            "message": "Policy opérateur non vérifiable",
        }
    if overly_broad:
        return _audit_denial(
            token_info.get("client_name", ""), profile.profile_id,
            "Policy opérateur trop large : outil SSH générique autorisé",
        )
    return None


def list_operator_access_profiles() -> dict:
    """Liste uniquement les profils utilisables par le bearer courant."""
    token_info, identity_err = _current_operator_identity("")
    if identity_err:
        return identity_err
    try:
        profiles = parse_operator_profiles()
    except OperatorSSHConfigurationError:
        return {"status": "error", "error_type": "configuration_error",
                "message": "Configuration SSH opérateur invalide"}

    visible = []
    for profile in profiles.values():
        if profile.client_name != token_info["client_name"]:
            continue
        policy_err = _check_dedicated_policy(token_info, profile, TOOL_LIST)
        if policy_err:
            return policy_err
        visible.append({
            "profile_id": profile.profile_id,
            "vault_id": profile.vault_id,
            "target": profile.target,
            "principal": profile.principal,
            "ttl_seconds": profile.ttl_seconds,
        })
    return {"status": "ok", "profiles": visible, "count": len(visible)}


async def request_operator_ssh_access(profile_id: str, public_key: str,
                                      reason: str) -> dict:
    """Émet un certificat SSH opérateur avec des attributs imposés côté serveur."""
    token_info, identity_err = _current_operator_identity(
        profile_id if isinstance(profile_id, str) else ""
    )
    if identity_err:
        return identity_err
    client_name = token_info["client_name"]
    if not isinstance(profile_id, str) or not _SAFE_ID.fullmatch(profile_id):
        return _audit_denial(client_name, "", "profile_id invalide", "invalid_request")
    try:
        profiles = parse_operator_profiles()
    except OperatorSSHConfigurationError:
        return {"status": "error", "error_type": "configuration_error",
                "message": "Configuration SSH opérateur invalide"}
    profile = profiles.get(profile_id)
    if profile is None or profile.client_name != client_name:
        return _audit_denial(client_name, profile_id, "Profil SSH opérateur non autorisé")

    policy_err = _check_dedicated_policy(token_info, profile, TOOL_REQUEST)
    if policy_err:
        return policy_err
    write_err = check_write_permission()
    if write_err:
        return write_err
    access_err = check_access(profile.vault_id)
    if access_err:
        return access_err

    settings = get_settings()
    if not isinstance(reason, str):
        return _audit_denial(client_name, profile_id, "Motif d'accès requis", "invalid_request")
    reason = reason.strip()
    max_reason = settings.ssh_operator_jit_max_reason_chars
    max_public_key = settings.ssh_operator_jit_max_public_key_chars
    if not reason or len(reason) > max_reason or any(
        ord(char) < 0x20 or ord(char) == 0x7F for char in reason
    ):
        return _audit_denial(client_name, profile_id, "Motif d'accès invalide", "invalid_request")
    if not isinstance(public_key, str) or len(public_key) > max_public_key:
        return _audit_denial(client_name, profile_id, "Clé publique invalide", "invalid_request")

    try:
        inspected = inspect_operator_public_key(public_key)
    except OperatorSSHRequestError as exc:
        return _audit_denial(client_name, profile_id, str(exc), "invalid_request")
    if inspected.fingerprint not in profile.key_fingerprints:
        return _audit_denial(client_name, profile_id, "Clé non enrôlée")

    # Pas de `critical_options` : `verify-required` n'a de sens que pour une
    # clé de sécurité matérielle FIDO2 (cf. docstring du module) — l'imposer
    # sur une clé standard casserait la connexion SSH côté client, qui ne
    # peut pas la satisfaire.
    key_id = f"operator:{client_name}:{profile.profile_id}:{secrets.token_hex(8)}"
    result = await sign_ssh_key(
        vault_id=profile.vault_id,
        role_name=profile.role_name,
        public_key=inspected.canonical_public_key,
        ttl=f"{profile.ttl_seconds}s",
        key_id=key_id,
        valid_principals=profile.principal,
    )
    status = result.get("status", "error") if isinstance(result, dict) else "error"
    serial = result.get("serial_number", "") if isinstance(result, dict) else ""
    log_audit(
        TOOL_REQUEST,
        status,
        vault_id=profile.vault_id,
        detail=(
            f"profile={profile.profile_id} target={profile.target} "
            f"principal={profile.principal} fingerprint={inspected.fingerprint} "
            f"key_id={key_id} serial={serial or '(absent)'} reason={reason}"
        ),
        client_name=client_name,
    )
    if status != "ok":
        return result
    return {
        **result,
        "profile_id": profile.profile_id,
        "target": profile.target,
        "principal": profile.principal,
        "fingerprint": inspected.fingerprint,
        "key_id": key_id,
    }
