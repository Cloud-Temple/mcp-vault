"""Écritures d'audit PG corrélées ; aucune boucle de replay ni payload libre."""

import hashlib
import json
import re
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass

from ..auth.context import current_token_info
from ..config import get_settings
from .audit_contract import ACTOR, IDENT, OUTCOMES, PHASES, TOOLS
from .postgres import (
    MetadataUnavailable, MutationUnknown, connection, offload, request_facts,
    revalidate_actor, validate_durability,
)

ZERO = "00000000-0000-0000-0000-000000000000"
current_audit_call = ContextVar("vault_audit_call", default=None)
current_audit_effects = ContextVar("vault_audit_effects", default=None)


@dataclass(frozen=True)
class Call:
    call_id: str
    instance: str
    actor_ref: str
    tool: str
    vault_id: str
    tenant_id: str | None
    mission_id: str | None
    operation_id: str | None
    started: float


def make_call(tool, vault_id="", *, operation_id=None):
    """Identité issue des seuls faits du middleware PG, jamais d'arguments MCP."""
    from ..vault_ids import is_valid_vault_id
    if tool not in TOOLS or not isinstance(vault_id, str) or (vault_id and not is_valid_vault_id(vault_id)):
        raise MetadataUnavailable("audit_target_invalid")
    facts = request_facts.get() or {}
    identity = current_token_info.get() or {}
    tenant = mission = None
    raw_hash = facts.get("actor_hash")
    if identity.get("auth_type") == "token" and isinstance(raw_hash, str) and re.fullmatch("[0-9a-f]{64}", raw_hash):
        actor = "tok_" + raw_hash[:16]
    elif identity.get("auth_type") == "mission_jwt" and facts.get("actor_binding"):
        tenant, mission = identity.get("tenant_id"), identity.get("mission_id")
        if any(not isinstance(v, str) or not IDENT.fullmatch(v) for v in (tenant, mission)):
            raise MetadataUnavailable("audit_identity_invalid")
        actor = "mission_" + hashlib.sha256(json.dumps([tenant, mission, identity.get("jti")]).encode()).hexdigest()[:16]
    else:
        actor = "anonymous"
    if operation_id is not None and (not isinstance(operation_id, str) or not IDENT.fullmatch(operation_id)):
        raise MetadataUnavailable("audit_correlation_invalid")
    return Call(str(uuid.uuid4()), get_settings().metadata_instance_id, actor, tool, vault_id,
                tenant, mission, operation_id, time.monotonic())


def _before(conn, deadline):
    remaining = deadline-time.monotonic()
    margin = get_settings().metadata_sql_cancel_seconds
    if remaining <= margin:
        raise MetadataUnavailable("audit_deadline")
    # Deadline SQL connecté hérité raccourci ; pas de borne de drainage inventée.
    conn.end = min(conn.end, deadline-margin)


def _write(call, deadline, operation, *, validate=False):
    committing = False
    try:
        if time.monotonic() >= deadline:
            raise MetadataUnavailable("audit_dispatch_expired")
        with connection() as conn:
            _before(conn, deadline)
            notices = []
            conn.add_notice_handler(lambda diagnostic: notices.append(diagnostic.sqlstate))
            try:
                conn.execute("BEGIN")
                validate_durability(conn)
                if validate:
                    revalidate_actor(conn)
                value = operation(conn)
                if notices:
                    raise MetadataUnavailable("audit_transaction_notice")
                _before(conn, deadline)
                committing = True
                conn.execute("COMMIT")
                if notices:
                    raise MutationUnknown(call.call_id)
                return value
            except BaseException:
                if not committing:
                    try:
                        conn.execute("ROLLBACK")
                    except Exception:
                        pass
                raise
    except BaseException as error:
        if committing:
            raise MutationUnknown(call.call_id) from error
        raise


def record_step(conn, call, phase, outcome, *, step_id=ZERO, mutation_id=None):
    """Dans la transaction du résultat métier ; n'écrit aucun terminal implicite."""
    if (phase not in PHASES or outcome not in OUTCOMES or not ACTOR.fullmatch(call.actor_ref)
            or call.instance != get_settings().metadata_instance_id):
        raise MetadataUnavailable("audit_event_invalid")
    try:
        step_id = str(uuid.UUID(str(step_id)))
        mutation_id = str(uuid.UUID(str(mutation_id))) if mutation_id is not None else None
    except (ValueError, TypeError, AttributeError):
        raise MetadataUnavailable("audit_event_invalid") from None
    existing = conn.execute("""SELECT outcome,mutation_id FROM vault_metadata.audit_events
        WHERE instance_id=%s AND call_id=%s AND phase=%s AND step_id=%s""",
        (call.instance, call.call_id, phase, step_id)).fetchone()
    if existing:
        if existing["outcome"] != outcome or (str(existing["mutation_id"]) if existing["mutation_id"] else None) != mutation_id:
            raise MetadataUnavailable("audit_event_conflict")
        return False  # Observation seulement, ne pas répéter l'effet associé.
    conn.execute("""INSERT INTO vault_metadata.audit_events
        (instance_id,call_id,phase,step_id,mutation_id,outcome,duration_ms)
        VALUES(%s,%s,%s,%s,%s,%s,%s)""",
        (call.instance, call.call_id, phase, step_id, mutation_id, outcome,
         max(0, (time.monotonic()-call.started)*1000)))
    return True


def _admit(call, outcome, deadline):
    if outcome not in {"admitted", "denied"} or (outcome == "admitted" and call.actor_ref == "anonymous"):
        raise MetadataUnavailable("audit_actor_missing")
    def insert(conn):
        conn.execute("""INSERT INTO vault_metadata.audit_calls
            (instance_id,call_id,actor_ref,tool,vault_id,tenant_id,mission_id,operation_id)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s)""",
            (call.instance, call.call_id, call.actor_ref, call.tool, call.vault_id,
             call.tenant_id, call.mission_id, call.operation_id))
        record_step(conn, call, "admission", outcome)
    return _write(call, deadline, insert, validate=outcome == "admitted")


async def admit(call, *, denied=False, request_deadline=None):
    end = time.monotonic()+get_settings().audit_stage_seconds
    if request_deadline is not None:
        end = min(end, request_deadline)
    await offload(_admit, call, "denied" if denied else "admitted", end)


async def append(call, phase, outcome, *, step_id=ZERO, mutation_id=None, request_deadline=None):
    end = time.monotonic()+get_settings().audit_stage_seconds
    if request_deadline is not None:
        end = min(end, request_deadline)
    if time.monotonic() >= end:
        raise MetadataUnavailable("audit_dispatch_expired")
    # L'acteur historique n'est pas revalidé après effet ; aucun droit nouveau.
    await offload(_write, call, end,
        lambda conn: record_step(conn, call, phase, outcome, step_id=step_id, mutation_id=mutation_id))
