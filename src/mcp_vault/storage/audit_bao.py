"""Étape OpenBao explicite : résultat rendu uniquement après observation PG."""

import uuid

from .audit_pg import append, current_audit_call, current_audit_effects


async def bao_step(operation, *, compensation=False):
    call = current_audit_call.get()
    if call is None:
        return operation()  # Backend historique ou contrôle opérateur hors requête.
    step_id = str(uuid.uuid4())
    phase = "compensation_outcome" if compensation else "bao_step_outcome"
    effects = current_audit_effects.get()
    if effects is not None:
        effects["dispatched"] = True
        effects["steps"] += 1
    try:
        result = operation()
    except BaseException:
        # Le transport peut avoir perdu l'ACK après l'effet ; pas de failed certain.
        try:
            await append(call, phase, "unknown", step_id=step_id)
        except BaseException:
            if effects is not None:
                effects["audit_unknown"] = True
            pass  # append attend le drainage ; priorité à l'exception initiale.
        raise
    if effects is not None:
        effects["confirmed"] += 1
    try:
        await append(call, phase, "confirmed", step_id=step_id)
    except BaseException:
        if effects is not None:
            effects["audit_unknown"] = True
        raise
    return result
