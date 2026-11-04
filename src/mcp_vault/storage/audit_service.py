"""Seam publique unique de consultation PG ; aucun fallback local ni auto-audit."""

from ..auth.context import current_token_info
from ..auth.policies import PolicyStoreUnavailable, get_policy_store
from ..config import get_settings
from .audit_contract import audit_scope
from .audit_cursor import context_fingerprint, cursors
from .audit_read import ExportIncomplete, normalize_filters, read_page
from .postgres import MetadataUnavailable, offload, request_facts


async def query(*, limit=100, cursor="", filters=None):
    try:
        settings = get_settings()
        if settings.metadata_backend != "postgres":
            raise MetadataUnavailable("audit_pg_profile_required")
        identity = current_token_info.get()
        facts = request_facts.get()
        if not isinstance(identity, dict) or not isinstance(facts, dict):
            raise PermissionError("audit access denied")
        policy_id = identity.get("policy_id", "")
        if not isinstance(policy_id, str):
            raise PermissionError("audit access denied")
        store = get_policy_store()
        policy = store.get(policy_id) if policy_id and store else None
        scope = audit_scope(settings.metadata_instance_id, identity, policy)
        selected = normalize_filters(filters)
        bound = {key: facts.get(key) for key in ("actor_hash", "actor_revision", "policy_revisions",
                                                "actor_binding", "binding_revision")}
        context = context_fingerprint(scope, bound, selected)
        internal = cursors.take(cursor, context) if cursor else None
        result = await offload(read_page, scope, limit=limit, cursor=internal, filters=selected)
        next_cursor = cursors.put(context, result["cursor"]) if result["cursor"] else ""
        return {"status": "ok", "source": "postgres", "entries": result["entries"],
                "count": len(result["entries"]), "total": result["total"], "stats": result["stats"],
                "complete": result["complete"], "cursor": next_cursor}
    except PermissionError:
        return {"status": "error", "error_type": "access_denied", "message": "Consultation d'audit refusée"}
    except ExportIncomplete:
        return {"status": "error", "error_type": "export_incomplete", "complete": False,
                "message": "Export incomplet ; commencer une nouvelle lecture"}
    except (ValueError, TypeError):
        return {"status": "error", "error_type": "invalid_request", "message": "Filtres ou page invalides"}
    except (MetadataUnavailable, PolicyStoreUnavailable):
        return {"status": "error", "error_type": "audit_unavailable", "complete": False,
                "message": "Audit PostgreSQL indisponible"}
