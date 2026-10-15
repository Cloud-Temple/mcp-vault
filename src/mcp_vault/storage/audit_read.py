"""Consultation PG filtrée ; le curseur est interne, jamais une entrée HTTP brute."""

from dataclasses import dataclass

from .audit_contract import ACTOR, IDENT, OUTCOMES, AuditScope, _utc, project_entry
from ..vault_ids import is_valid_vault_id
from .postgres import MetadataUnavailable, connection, revalidate_actor


class ExportIncomplete(MetadataUnavailable):
    pass


@dataclass(frozen=True)
class Cursor:
    revision: int
    upper: int
    position: int
    total: int
    delivered: int


def where_scope(scope: AuditScope):
    clauses, values = ["c.instance_id=%s"], [scope.instance]
    if scope.coffers is not None:
        if not scope.coffers:
            raise PermissionError("audit scope denied")
        clauses += ["c.vault_id=ANY(%s)", "c.actor_ref<>'anonymous'", "c.tenant_id IS NULL", "c.mission_id IS NULL"]
        values.append(sorted(scope.coffers))
    from .hub_vault_activity import MissionAuditScope
    if isinstance(scope, MissionAuditScope):
        # Replace the opaque auditor's NULL-only clauses, never broaden its branch.
        clauses = ["c.instance_id=%s", "c.vault_id=ANY(%s)", "left(c.actor_ref,8)='mission_'",
                   "c.tenant_id=%s", "c.mission_id=%s"]
        values = [scope.instance, sorted(scope.coffers), scope.tenant_id, scope.mission_id]
    return clauses, values


def _revision(conn, instance):
    row = conn.execute("SELECT revision FROM vault_metadata.audit_revision WHERE instance_id=%s", (instance,)).fetchone()
    return row["revision"] if row else 0


def normalize_filters(filters):
    if filters is None:
        return {}
    allowed = {"client", "vault_id", "tool", "category", "status", "since"}
    if not isinstance(filters, dict) or set(filters)-allowed:
        raise ValueError("audit filter invalid")
    result = {}
    for key, value in filters.items():
        if not isinstance(value, str) or len(value) > 128:
            raise ValueError("audit filter invalid")
        if not value:
            continue
        if key == "client" and not ACTOR.fullmatch(value):
            raise ValueError("audit filter invalid")
        if key == "vault_id" and not is_valid_vault_id(value):
            raise ValueError("audit filter invalid")
        if key == "tool" and not IDENT.fullmatch(value[:-1] if value.endswith("*") else value):
            raise ValueError("audit filter invalid")
        if key == "category" and not IDENT.fullmatch(value):
            raise ValueError("audit filter invalid")
        if key == "status" and value not in OUTCOMES:
            raise ValueError("audit filter invalid")
        result[key] = _utc(value) if key == "since" else value
    return result


def where_filters(filters):
    clauses, values = [], []
    for key, value in filters.items():
        if key in {"client", "vault_id", "status"}:
            column = {"client": "c.actor_ref", "vault_id": "c.vault_id", "status": "e.outcome"}[key]
            clauses.append(column+"=%s")
            values.append(value)
        elif key == "tool":
            if value.endswith("*"):
                clauses.append("left(c.tool,%s)=%s")
                values.extend([len(value)-1, value[:-1]])
            else:
                clauses.append("c.tool=%s")
                values.append(value)
        elif key == "category":
            clauses.append("split_part(c.tool,'_',1)=%s")
            values.append(value)
        else:
            clauses.append("e.created_at>=%s")
            values.append(value)
    return clauses, values


def read_page(scope, *, limit=100, cursor=None, filters=None):
    """Une page expurgée, total correspondant et invalidation si le journal change.

    Le futur raccord public doit décoder/authentifier son curseur et lier scope,
    identité et filtres avant cet appel ; aucun dictionnaire client accepté ici.
    """
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("audit page invalid")
    if cursor is not None and (not isinstance(cursor, Cursor)
            or any(type(v) is not int or v < 0 for v in vars(cursor).values())
            or cursor.position > cursor.upper or cursor.delivered > cursor.total):
        raise ValueError("audit cursor invalid")
    filters = normalize_filters(filters)
    clauses, values = where_scope(scope)
    more_clauses, more_values = where_filters(filters)
    clauses.extend(more_clauses)
    values.extend(more_values)
    with connection() as conn:
        # Les verrous d'identité existants ne sont pas permis en TX READ ONLY.
        # Chaque vérification fraîche reste donc hors de la transaction snapshot.
        revalidate_actor(conn)
        begun = False
        try:
            conn.execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
            begun = True
            revision = _revision(conn, scope.instance)
            if cursor is not None and revision != cursor.revision:
                raise ExportIncomplete("audit_export_changed")
            upper = cursor.upper if cursor else conn.execute(
                "SELECT COALESCE(max(seq),0) AS upper FROM vault_metadata.audit_events WHERE instance_id=%s",
                (scope.instance,)).fetchone()["upper"]
            clauses.append("e.seq<=%s")
            values.append(upper)
            joined = " FROM vault_metadata.audit_calls c JOIN vault_metadata.audit_events e USING(instance_id,call_id) WHERE "
            condition = " AND ".join(clauses)
            total = conn.execute("SELECT count(*) AS total"+joined+condition, values).fetchone()["total"]
            if cursor is not None and total != cursor.total:
                raise ExportIncomplete("audit_export_changed")
            position = cursor.position if cursor else upper+1
            rows = conn.execute("""SELECT c.instance_id,c.call_id,c.actor_ref,c.tool,c.vault_id,c.tenant_id,
                c.mission_id,c.operation_id,e.seq,e.phase,e.outcome,e.duration_ms,e.created_at,e.expires_at,
                e.step_id,e.mutation_id"""+joined+condition+" AND e.seq<%s ORDER BY e.seq DESC LIMIT %s",
                [*values, position, limit]).fetchall()
            entries = [project_entry(row, scope) for row in rows]
            if any(entry is None for entry in entries):
                raise MetadataUnavailable("audit_projection_inconsistent")
            delivered = (cursor.delivered if cursor else 0)+len(entries)
            if delivered > total:
                raise ExportIncomplete("audit_export_count_invalid")
            if not rows and delivered != total:
                raise ExportIncomplete("audit_export_count_invalid")
            stats = {"total": total, "truncated": False}
            for key, expression in (("by_category", "split_part(c.tool,'_',1)"),
                                    ("by_status", "e.outcome"), ("by_client", "c.actor_ref")):
                grouped = conn.execute("SELECT "+expression+" AS value,count(*) AS count"+joined+condition+
                    " GROUP BY "+expression+" ORDER BY count(*) DESC,"+expression+" LIMIT 101", values).fetchall()
                stats[key] = {row["value"]: row["count"] for row in grouped[:100]}
                stats["truncated"] |= len(grouped) > 100
            conn.execute("COMMIT")
            begun = False
        except BaseException:
            if begun:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
            raise
        # Un commit tardif/purge ou une révocation interdit la restitution finale.
        if _revision(conn, scope.instance) != revision:
            raise ExportIncomplete("audit_export_changed")
        revalidate_actor(conn)
        complete = delivered == total
        return {"entries": entries, "total": total, "stats": stats, "complete": complete,
                "cursor": None if complete else Cursor(revision, upper, rows[-1]["seq"], total, delivered)}
