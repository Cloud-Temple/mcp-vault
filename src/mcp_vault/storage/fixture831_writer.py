"""Writer A2 de la préparation831 (plan831 R1 A2, R2 §2.2).

Module privé : seul `storage.fixture831_job` l'importe. Le serveur ASGI, qui
importe `fixture831_preparation` pour le périmètre de lecture, ne charge jamais
ce writer.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import re
import time
import uuid
from dataclasses import dataclass

from .audit_contract import IDENT
from .fixture831_preparation import PREPARATION_TOOL
from .postgres import MetadataUnavailable

# -- Writer A2 : trace réelle de préparation (plan831 R1 A2) ---------------------------
#
# Une lecture Bao réelle du canary du tenant, autorisée par un jeton opérateur
# Vault local et par le binding Mission du tenant, revalidés sous verrou dans la
# transaction d'admission. Trois événements : admission, bao_step_outcome,
# public_terminal, écrits par `_write`/`record_step`. Jamais de secret_read C18,
# jamais d'événement ajouté pour atteindre trois, jamais de valeur de secret en
# sortie.

NONCE = re.compile(r"[0-9a-f]{12}\Z")
MISSION_ID = re.compile(r"mis_(?:[0-9a-f]{8}|[0-9a-f]{24})\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
FACT_FIELDS = frozenset({"mission_id", "tenant_id", "operation_id", "vault_id", "path", "expected_sha256"})
FACT_TTL_SECONDS = 60.0
_SEAL = object()


class PreparationRefused(PermissionError):
    """Refus avant tout effet Bao ; code fermé, aucune donnée recopiée."""


class PreparationUncertain(RuntimeError):
    """Effet Bao ou audit non confirmé : rien n'est rejoué, la recette observe."""

    def __init__(self, code, call_id=None):
        self.code, self.call_id = code, call_id
        super().__init__(code)


@dataclass(frozen=True)
class PreparationFact:
    """Corrélateurs d'une préparation831. N'accorde aucun droit : l'autorisation
    vient du jeton opérateur et du binding, relus à chaque écriture."""

    nonce: str
    mission_id: str
    tenant_id: str
    operation_id: str
    vault_id: str
    path: str
    expected_sha256: str
    not_after: float
    seal: object


def preparation_fact(arguments, *, nonce, clock=time.monotonic):
    """Seul constructeur : champs fermés, domaine831 exact, validité courte."""
    if (type(arguments) is not dict or set(arguments) != FACT_FIELDS
            or not all(type(arguments[k]) is str for k in FACT_FIELDS)
            or not isinstance(nonce, str) or not NONCE.fullmatch(nonce)):
        raise PreparationRefused("fact_invalid")
    mission, tenant = arguments["mission_id"], arguments["tenant_id"]
    if (not MISSION_ID.fullmatch(mission) or not IDENT.fullmatch(tenant)
            or not tenant.startswith(f"q831-{nonce}-")
            or arguments["operation_id"] != f"q831-prepare-{mission}"
            or not re.fullmatch(f"q831-{nonce}-t[0-9]{{2}}", arguments["vault_id"])
            or arguments["path"] != f"q831/{nonce}/canary"
            or not SHA256.fullmatch(arguments["expected_sha256"])):
        raise PreparationRefused("fact_invalid")
    return PreparationFact(nonce, mission, tenant, arguments["operation_id"], arguments["vault_id"],
                           arguments["path"], arguments["expected_sha256"], clock() + FACT_TTL_SECONDS, _SEAL)


def _operator_identity(raw_token, fact):
    """Le vrai validateur du middleware, sur les faits PG frais de cette requête."""
    from ..auth.middleware import AuthMiddleware

    identity = AuthMiddleware(None)._validate_token(raw_token)
    permissions = identity.get("permissions") if isinstance(identity, dict) else None
    resources = identity.get("allowed_resources") if isinstance(identity, dict) else None
    # Jeton opérateur scopé : pas d'admin, lecture explicite du seul coffre visé.
    if (not isinstance(permissions, list) or identity.get("auth_type") != "token"
            or "admin" in permissions or "read" not in permissions
            or not isinstance(resources, list) or fact.vault_id not in resources):
        raise PreparationRefused("operator_denied")
    return identity


def operator_actor(actor_hash, fact):
    return "operator_" + hashlib.sha256(json.dumps(
        [actor_hash, fact.tenant_id, fact.mission_id, fact.nonce]).encode()).hexdigest()[:16]


def _admit_preparation(call, facts, deadline):
    """Admission dans une seule transaction : jeton, policies (validate=True) puis binding."""
    from .audit_pg import _write, record_step
    from .postgres import _revalidate_binding
    from .stores import view

    def insert(conn):
        _revalidate_binding(conn, call.instance, facts, {"tenant_id": call.tenant_id})
        row = conn.execute("SELECT payload,revision FROM vault_metadata.mission_bindings "
                           "WHERE instance_id=%s AND tenant_id=%s FOR SHARE",
                           (call.instance, call.tenant_id)).fetchone()
        binding = view("binding", [row] if row else []).resolve(call.tenant_id)
        if not binding or call.vault_id not in binding.get("allowed_resources", []):
            raise MetadataUnavailable("binding_changed")
        conn.execute("""INSERT INTO vault_metadata.audit_calls
            (instance_id,call_id,actor_ref,tool,vault_id,tenant_id,mission_id,operation_id)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s)""",
            (call.instance, call.call_id, call.actor_ref, call.tool, call.vault_id,
             call.tenant_id, call.mission_id, call.operation_id))
        record_step(conn, call, "admission", "admitted")
    return _write(call, deadline, insert, validate=True)


async def prepare_read(fact, raw_token, *, clock=time.monotonic):
    """Une trace `operator_*`/`fixture831_prepare_read` après une vraie lecture Bao.

    Rend seulement des métadonnées : identifiant d'appel, coffre, chemin,
    empreinte attendue et compte d'événements. Toute incertitude lève
    PreparationUncertain, qui bloque l'admission du jeu nominal.
    """
    from ..auth.context import (
        check_access,
        check_path_policy,
        check_policy,
        current_token_info,
    )
    from ..config import get_settings
    from ..vault.secrets import read_secret
    from .admission import load_facts
    from .audit_pg import Call, append, current_audit_call, current_audit_effects
    from .postgres import MutationUnknown, offload, request_facts

    if type(fact) is not PreparationFact or fact.seal is not _SEAL:
        raise PreparationRefused("fact_invalid")
    if clock() >= fact.not_after:
        raise PreparationRefused("fact_expired")
    settings = get_settings()
    if settings.metadata_backend != "postgres":
        raise PreparationRefused("postgres_required")
    if (not isinstance(raw_token, str) or not raw_token or len(raw_token) > 8192
            or hmac.compare_digest(raw_token, settings.admin_bootstrap_key)):
        raise PreparationRefused("operator_denied")
    try:
        facts = await offload(load_facts, raw_token, fact.tenant_id)
    except MetadataUnavailable:
        raise PreparationRefused("facts_unavailable") from None
    if not facts.get("actor_hash") or facts.get("actor_binding") != fact.tenant_id:
        raise PreparationRefused("operator_or_binding_absent")
    try:
        binding = facts["binding"].resolve(fact.tenant_id)
    except Exception:
        raise PreparationRefused("binding_scope") from None
    if not binding or binding.get("enabled") is not True or fact.vault_id not in binding.get("allowed_resources", []):
        raise PreparationRefused("binding_scope")
    facts_marker = request_facts.set(facts)
    try:
        identity = _operator_identity(raw_token, fact)
        token_marker = current_token_info.set(identity)
        try:
            if (check_policy("secret_read") or check_access(fact.vault_id)
                    or check_path_policy(fact.vault_id, fact.path, "read")):
                raise PreparationRefused("operator_denied")
            call = Call(str(uuid.uuid4()), settings.metadata_instance_id, operator_actor(facts["actor_hash"], fact),
                        PREPARATION_TOOL, fact.vault_id, fact.tenant_id, fact.mission_id, fact.operation_id,
                        time.monotonic())
            end = time.monotonic() + settings.audit_stage_seconds
            try:
                await offload(_admit_preparation, call, facts, end)
            except MutationUnknown:
                raise PreparationUncertain("admission_unknown", call.call_id) from None
            except MetadataUnavailable:
                # Rien d'écrit : jeton, policy ou binding changé à R, ou base indisponible.
                raise PreparationRefused("admission_refused") from None
            effects = {"dispatched": False, "steps": 0, "confirmed": 0, "audit_unknown": False}
            call_marker = current_audit_call.set(call)
            effects_marker = current_audit_effects.set(effects)
            try:
                try:
                    result = await read_secret(fact.vault_id, fact.path)
                except BaseException as error:
                    try:
                        await append(call, "public_terminal", "unknown")
                    except BaseException:
                        pass
                    if isinstance(error, asyncio.CancelledError):
                        raise  # terminal unknown écrit ; l'annulation n'est pas avalée
                    raise PreparationUncertain("bao_unknown", call.call_id) from None
                read_ok = isinstance(result, dict) and result.get("status") == "ok"
                outcome = "completed" if read_ok and not effects["audit_unknown"] else "unknown"
                try:
                    await append(call, "public_terminal", outcome)
                except (MetadataUnavailable, MutationUnknown):
                    raise PreparationUncertain("terminal_unknown", call.call_id) from None
            finally:
                current_audit_effects.reset(effects_marker)
                current_audit_call.reset(call_marker)
            if outcome != "completed" or effects["steps"] != 1 or effects["confirmed"] != 1:
                raise PreparationUncertain("read_not_confirmed", call.call_id)
            data = result.get("data")
            value = data.get("fixture831") if isinstance(data, dict) else None
            if not isinstance(value, str) or hashlib.sha256(value.encode()).hexdigest() != fact.expected_sha256:
                # Lecture réelle confirmée mais canary différent : jeu nominal non admis.
                raise PreparationUncertain("canary_mismatch", call.call_id)
            del result, data, value
            return {"call_id": call.call_id, "vault_id": fact.vault_id, "path": fact.path,
                    "fixture_sha256": fact.expected_sha256, "events": 3, "outcome": "completed"}
        finally:
            current_token_info.reset(token_marker)
    finally:
        request_facts.reset(facts_marker)
