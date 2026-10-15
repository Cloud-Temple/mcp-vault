"""Frontière async d'un appel audité ; aucun effet dispatché avant admission PG."""

from functools import wraps
import inspect

from ..config import get_settings
from .audit_pg import admit, append, current_audit_call, current_audit_effects, make_call
from .postgres import MetadataUnavailable, MutationUnknown


def audited_call(function):
    signature = inspect.signature(function)

    @wraps(function)
    async def invoke(*args, **kwargs):
        if get_settings().metadata_backend != "postgres":
            return await function(*args, **kwargs)
        bound = signature.bind(*args, **kwargs)
        vault_id = bound.arguments.get("vault_id", "")
        try:
            call = make_call(function.__name__, vault_id)
            await admit(call)
        except (MetadataUnavailable, MutationUnknown):
            return {"status": "error", "error_type": "audit_unavailable", "audit_status": "unknown"}
        marker = current_audit_call.set(call)
        effects = {"dispatched": False, "steps": 0, "confirmed": 0, "audit_unknown": False}
        effects_marker = current_audit_effects.set(effects)
        try:
            try:
                result = await function(*args, **kwargs)
            except BaseException:
                # L'exception peut survenir après effet. Aucun terminal failed certain.
                try:
                    await append(call, "public_terminal", "unknown")
                except BaseException:
                    # append/offload a déjà drainé son worker avant de lever.
                    # Même une annulation secondaire ne masque pas la cause initiale.
                    pass
                raise
            outcome = "completed" if isinstance(result, dict) and result.get("status") in {"ok", "created", "updated", "deleted"} else "unknown"
            if (not effects["dispatched"] and isinstance(result, dict)
                    and result.get("error_type") in {"access_denied", "permission_denied", "unauthenticated"}):
                outcome = "denied"
            if effects["audit_unknown"]:
                outcome = "unknown"
            try:
                await append(call, "public_terminal", outcome)
            except (MetadataUnavailable, MutationUnknown):
                # Ne restitue ni secret ni résultat d'effet dont l'audit est incertain.
                return {"status": "error", "error_type": "audit_closure_unconfirmed",
                        "audit_status": "unknown", "audit_call_id": call.call_id,
                        "business_outcome": "confirmed" if outcome == "completed" or effects["steps"] == effects["confirmed"] == 1 else "unknown", "replay_allowed": False}
            if effects["audit_unknown"]:
                return {"status": "error", "error_type": "audit_step_unconfirmed",
                        "audit_status": "unknown", "audit_call_id": call.call_id,
                        "business_outcome": "confirmed" if effects["steps"] == effects["confirmed"] == 1 else "unknown",
                        "replay_allowed": False}
            return result
        finally:
            current_audit_effects.reset(effects_marker)
            current_audit_call.reset(marker)
    return invoke
