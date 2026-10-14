"""Réservation pure du coffre SQL : aucune lecture backend pour décider."""

from functools import wraps
from inspect import signature

from .config import get_settings
from .vault_ids import is_valid_vault_id


class ReservedMetadataAccess(Exception):
    """Refus structurel, à ne jamais traiter comme cleanup non bloquant."""


def target_error(vault_id, *, ssh=False):
    settings = get_settings()
    if getattr(settings, "metadata_backend", "s3") != "postgres":
        return None
    if not is_valid_vault_id(vault_id):
        return {"status": "error", "error_type": "invalid_request",
                "message": "Identifiant de coffre invalide"}
    targets = (vault_id, "ssh-ca-" + vault_id) if ssh else (vault_id,)
    if settings.metadata_pg_vault_id in targets:
        return {"status": "error", "error_type": "access_denied",
                "message": "Accès au coffre refusé"}
    return None


def business_target(*, ssh=False, raises=False):
    """Garde aussi les appels directs de primitives, avant leur première instruction."""
    def decorate(fn):
        sig = signature(fn)

        @wraps(fn)
        async def guarded(*args, **kwargs):
            vault_id = sig.bind(*args, **kwargs).arguments["vault_id"]
            error = target_error(vault_id, ssh=ssh)
            if error:
                if raises:
                    raise ReservedMetadataAccess(error["message"])
                return error
            return await fn(*args, **kwargs)
        return guarded
    return decorate


def entries_error(entries):
    """Admettre toute une sélection avant le premier effet mutatif."""
    for entry in entries:
        if not isinstance(entry, dict) or not is_valid_vault_id(entry.get("vault_id")):
            return {"status": "error", "error_type": "backend_unavailable",
                    "message": "Cible de registre indéterminable"}
        error = target_error(entry["vault_id"])
        if error:
            return error
    return None


def pg_offload(fn):
    """Primitives async historiques contenant des I/O sync, hors ASGI en PG."""
    @wraps(fn)
    async def call(*args,**kwargs):
        if getattr(get_settings(),"metadata_backend","s3") == "postgres":
            import asyncio
            from .storage.postgres import offload
            return await offload(lambda:asyncio.run(fn(*args,**kwargs)))
        return await fn(*args,**kwargs)
    return call
