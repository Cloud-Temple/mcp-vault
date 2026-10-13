"""Adaptateurs PG par lignes, utilisant les validations et contrats existants.

Les vues de guards vivent dans le contexte de requête. Les mutations ne
réécrivent jamais un snapshot : seuls les objets modifiés sont persistés CAS.
"""

import asyncio
import copy
from contextvars import ContextVar
import hashlib
import json

from ..config import get_settings
from .postgres import (MetadataUnavailable, MetadataRejected, MutationUnknown, connection, mutation,
                       offload, request_facts)

TABLES = {"token": ("tokens", "token_hash", "_tokens"),
          "policy": ("policies", "policy_id", "_policies"),
          "binding": ("mission_bindings", "tenant_id", "_bindings"),
          "wrap": ("wrap_registry", "operation_id", "_wraps")}
_wrap_scope = ContextVar("vault_pg_wrap_scope", default=None)


def base(kind):
    from ..auth.token_store import TokenStore
    from ..auth.policies import PolicyStore
    from ..auth.mission_bindings import MissionBindingStore
    from ..vault.wrapping import WrapRegistry
    obj = {"token":TokenStore, "policy":PolicyStore,
           "binding":MissionBindingStore, "wrap":WrapRegistry}[kind](get_settings())
    obj._maybe_refresh = lambda: None
    if kind == "binding":
        obj.instance_id = get_settings().metadata_instance_id
    return obj


def select(conn, kind, method, args, *, lock=False, scope=None):
    from psycopg import sql
    table, key, _ = TABLES[kind]
    where = sql.SQL("instance_id=%s")
    params = [get_settings().metadata_instance_id]
    if kind == "wrap":
        if scope is None:
            raise MetadataUnavailable("wrap_scope_missing")
        if scope[0] == "accessor":
            where += sql.SQL(" AND accessor=%s")
            params += [scope[1]]
        else:
            where += sql.SQL(" AND operation_id=%s AND mission_id=%s")
            params += list(scope[1:])
    elif method not in {"create", "list_all", "purge_revoked", "purge", "count"}:
        if not args or not isinstance(args[0], str):
            raise MetadataUnavailable("invalid_target")
        if kind == "token" and method in {"update", "revoke"}:
            from ..auth.token_store import TokenStore
            if TokenStore._validate_hash_prefix(args[0]):
                raise MetadataUnavailable("invalid_target")
            where += sql.SQL(" AND token_hash LIKE %s")
            params += [args[0].lower() + "%"]
        else:
            where += sql.SQL(" AND {}=%s").format(sql.Identifier(key))
            params += [args[0]]
    elif method == "create":
        if kind != "token":
            where += sql.SQL(" AND {}=%s").format(sql.Identifier(key))
            params += [args[0]]
        else:
            where += sql.SQL(" AND false")
    query = sql.SQL("SELECT * FROM vault_metadata.{} WHERE {} ORDER BY {} LIMIT 1001{}").format(
        sql.Identifier(table),where,sql.Identifier(key),sql.SQL(" FOR UPDATE" if lock else ""))
    rows = conn.execute(query,params).fetchall()
    if len(rows) > 1000:
        raise MetadataUnavailable("collection_limit")
    return rows


def key_of(kind, value):
    if kind == "wrap":
        return (value["operation_id"], value["mission_id"])
    return value[{"token":"hash","policy":"policy_id","binding":"tenant_id"}[kind]]


def validate(kind, value):
    from ..auth.token_store import _validate_and_normalize_token
    from ..auth.policies import _validate_and_normalize_policy
    from ..auth.mission_bindings import validate_binding
    if kind == "token":
        return _validate_and_normalize_token(value)
    if kind == "policy":
        return _validate_and_normalize_policy(value)
    if kind == "binding":
        ok, _ = validate_binding(value)
        if not ok:
            raise MetadataUnavailable("binding_corrupt")
    if kind == "wrap":
        from ..vault.wrapping import _entry_well_formed,_validate_inputs,_KNOWN_WRAP_STATUSES
        if (not _entry_well_formed(value)
                or _validate_inputs(value.get("vault_id"),value.get("secret_path"),value.get("mission_id"),value.get("operation_id"))
                or value.get("status") not in _KNOWN_WRAP_STATUSES):
            raise MetadataUnavailable("registry_corrupt")
    return copy.deepcopy(value)


def view(kind, rows):
    obj = base(kind)
    try:
        values = [validate(kind, r["payload"]) for r in rows if not r["payload"].get("_deleted")]
    except (ValueError,TypeError,KeyError) as exc:
        raise MetadataUnavailable("metadata_corrupt") from exc
    setattr(obj,TABLES[kind][2],values if kind == "wrap" else {key_of(kind,v):v for v in values})
    return obj


def persist(conn, kind, rows, candidate):
    from psycopg import sql
    from psycopg.types.json import Jsonb
    table, key, _ = TABLES[kind]
    previous = {key_of(kind,r["payload"]):r for r in rows}
    values = candidate if kind == "wrap" else candidate.values()
    new = {key_of(kind,v):v for v in values}
    if len(new) != len(candidate):
        raise MetadataUnavailable("duplicate_intent")
    for k in previous.keys() | new.keys():
        old = previous.get(k)
        value = new.get(k)
        if old and value == old["payload"]:
            continue
        keyvalues = list(k) if kind == "wrap" else [k]
        keycols = ["operation_id", "mission_id"] if kind == "wrap" else [key]
        condition = sql.SQL("instance_id=%s AND ") + sql.SQL(" AND ").join(
            sql.SQL("{}=%s").format(sql.Identifier(c)) for c in keycols)
        params = [get_settings().metadata_instance_id, *keyvalues]
        if value is None:
            if kind == "wrap":
                raise MetadataUnavailable("wrap_delete_forbidden")
            if kind == "binding":
                value = {**old["payload"], "enabled":False, "_deleted":True}
            else:
                conn.execute(sql.SQL("DELETE FROM vault_metadata.{} WHERE {} AND revision=%s").format(
                    sql.Identifier(table),condition),[*params,old["revision"]])
                continue
        value = validate(kind,value)
        extra = {}
        if kind in {"token","binding"}:
            extra["policy_id"] = value.get("policy_id") or None
        if kind == "wrap":
            from ..reserved_metadata import entries_error
            if entries_error([value]):
                raise MetadataUnavailable("reserved_target")
            extra = {name:value.get(name) for name in ("accessor","vault_id","secret_path","status")}
            if old and value["status"] == "pending":
                raise MetadataUnavailable("intent_already_engaged")
        if old:
            cols = {"payload":Jsonb(value), **extra}
            query = sql.SQL("UPDATE vault_metadata.{} SET {}, revision=revision+1 WHERE {} AND revision=%s").format(
                sql.Identifier(table),sql.SQL(",").join(sql.SQL("{}=%s").format(sql.Identifier(c)) for c in cols),condition)
            if conn.execute(query,[*cols.values(),*params,old["revision"]]).rowcount != 1:
                raise MetadataUnavailable("revision_conflict")
        else:
            cols = {"instance_id":params[0], **dict(zip(keycols,keyvalues)),
                    "payload":Jsonb(value), "revision":1, **extra}
            conn.execute(sql.SQL("INSERT INTO vault_metadata.{} ({}) VALUES ({})").format(
                sql.Identifier(table),sql.SQL(",").join(map(sql.Identifier,cols)),
                sql.SQL(",").join(sql.Placeholder() for _ in cols)),list(cols.values()))
        if kind in {"token","binding"}:
            child = "token_vaults" if kind == "token" else "binding_vaults"
            conn.execute(sql.SQL("DELETE FROM vault_metadata.{} WHERE instance_id=%s AND {}=%s").format(
                sql.Identifier(child),sql.Identifier(key)),params)
            for vid in value.get("allowed_resources",[]):
                conn.execute(sql.SQL("INSERT INTO vault_metadata.{} VALUES(%s,%s,%s)").format(sql.Identifier(child)),[*params,vid])
    return True


def execute(kind, method, args=(), kwargs=None, *, mutating=False, scope=None, expected=None, publish=None):
    kwargs = kwargs or {}
    target = {"scope":list(scope or args[:1]), "intent_hash":hashlib.sha256(json.dumps([args,kwargs],sort_keys=True,default=str).encode()).hexdigest()}
    publication = {}
    if kind=="wrap" and scope and scope[0]=="operation":
        target.update(business_operation_id=scope[1],mission_id=scope[2])
    def operation(conn):
        if mutating and kind != "wrap":
            from ..auth.context import current_token_info
            if "admin" not in (current_token_info.get() or {}).get("permissions",[]):
                raise MetadataUnavailable("admin_required")
        selected_args = args or ((kwargs.get({"token":"hash_prefix", "policy":"policy_id", "binding":"tenant_id"}.get(kind,"operation_id")),) if kind != "token" or method != "create" else ())
        rows = select(conn,kind,method,selected_args,lock=mutating,scope=scope)
        obj = view(kind,rows)
        if kind=="policy" and mutating and method=="delete" and rows:
            referenced = conn.execute("""SELECT EXISTS(SELECT 1 FROM vault_metadata.tokens
                WHERE instance_id=%s AND policy_id=%s) OR EXISTS(SELECT 1 FROM vault_metadata.mission_bindings
                WHERE instance_id=%s AND policy_id=%s) AS found""",
                (get_settings().metadata_instance_id,selected_args[0],get_settings().metadata_instance_id,selected_args[0])).fetchone()
            if referenced["found"]:
                raise MetadataRejected({"status":"error","error_type":"policy_in_use","message":"Policy référencée ; réassigner les octrois avant suppression"})
        revisions = {key_of(kind,r["payload"]):r["revision"] for r in rows}
        if mutating and expected is not None and revisions != expected:
            raise MetadataUnavailable("revision_conflict")
        target["expected_revisions"] = [[k,v] for k,v in revisions.items()]
        target["result_revisions"] = target["expected_revisions"]
        target["effect_changed"] = False
        if mutating:
            def save(candidate=None):
                value = candidate if candidate is not None else obj._wraps
                if kind=="wrap" and method=="register_pending":
                    for entry in value:
                        tenant = entry.get("tenant_id")
                        if tenant:
                            row = conn.execute("SELECT payload,revision FROM vault_metadata.mission_bindings WHERE instance_id=%s AND tenant_id=%s FOR SHARE",(get_settings().metadata_instance_id,tenant)).fetchone()
                            binding = view("binding",[row] if row else []).resolve(tenant)
                            if not binding or entry["vault_id"] not in binding["allowed_resources"]:
                                raise MetadataUnavailable("binding_unavailable")
                            entry["binding_revision"] = row["revision"]
                            target["binding_revision"] = row["revision"]
                result = persist(conn,kind,rows,value)
                if kind=="wrap":
                    publication["rows"] = [{"payload":copy.deepcopy(v), "revision":revisions.get(key_of(kind,v),0)+1} for v in value]
                target["effect_changed"] = True
                target["result_revisions"] = [[key_of(kind,v),revisions.get(key_of(kind,v),0)+1] for v in (value if kind=="wrap" else value.values())]
                return result
            obj._save = save
        if kind=="wrap" and mutating and method=="try_mark_consuming":
            for entry in obj._wraps:
                tenant = entry.get("tenant_id")
                if tenant:
                    row = conn.execute("SELECT payload,revision FROM vault_metadata.mission_bindings WHERE instance_id=%s AND tenant_id=%s FOR SHARE",(get_settings().metadata_instance_id,tenant)).fetchone()
                    binding = view("binding",[row] if row else []).resolve(tenant)
                    if (not binding or row["revision"]!=entry.get("binding_revision")
                            or entry["vault_id"] not in binding["allowed_resources"]):
                        raise MetadataUnavailable("binding_changed")
                    target["binding_revision"] = row["revision"]
        facts = request_facts.get()
        ctx = None
        if facts is not None and kind == "binding" and kwargs.get("policy_id"):
            extra = conn.execute("SELECT payload,revision FROM vault_metadata.policies WHERE instance_id=%s AND policy_id=%s FOR SHARE",
                                (get_settings().metadata_instance_id,kwargs["policy_id"])).fetchall()
            existing = list(facts["policy"]._policies.values())
            policy_view = view("policy",[{"payload":v} for v in existing]+extra)
            ctx = request_facts.set({**facts,"policy":policy_view})
        try:
            if kind == "wrap" and method == "mark_entries_revoked":
                keys = {key_of("wrap",v) for v in args[0]}
                args_for_call = ([v for v in obj._wraps if key_of("wrap",v) in keys],)
            else:
                args_for_call = args
            result = getattr(obj,method)(*args_for_call,**kwargs)
            if mutating and isinstance(result,dict) and result.get("status")=="error":
                raise MetadataRejected(result)
            return result
        finally:
            if ctx is not None:
                request_facts.reset(ctx)
    if mutating:
        result = mutation(kind+":"+method,target,operation)
        if publish is not None and "rows" in publication:
            publish(publication["rows"])
        return result
    with connection() as conn:
        return operation(conn)


class PGStore:
    """Lectures sync de guards = vue de requête ; I/O = méthodes async explicites."""
    def __init__(self, kind):
        self.kind = kind
        self.refresh_lock = asyncio.Lock()
        self.available = True
        self.last_error = ""
        self._ferme_pour_arret = False
        from ..store_refresh import Freshness
        self.freshness = Freshness()
        self.CACHE_TTL = 0

    def volumetrie(self):
        return {"entries":None,"source":"postgres","cache":False}

    def __getattr__(self, name):
        if name.startswith("a"):
            method = name[1:]
            async def call(*args, **kwargs):
                try:
                    if self._ferme_pour_arret:
                        raise MetadataUnavailable("shutdown")
                    async with self.refresh_lock:
                        if self._ferme_pour_arret:
                            raise MetadataUnavailable("shutdown")
                        return await offload(execute,self.kind,method,args,kwargs,
                            mutating=method in {"create","update","revoke","delete","purge","purge_revoked"})
                except MetadataRejected as exc:
                    return exc.response
                except MutationUnknown as exc:
                    return {"status":"error","error_type":"outcome_unknown", "mutation_id":exc.mutation_id,
                            "message":"Résultat indéterminé ; ne pas rejouer"}
                except MetadataUnavailable:
                    if method in {"get","list_all"}:
                        raise
                    return {"status":"error","error_type":"storage_unavailable", "message":"Métadonnées indisponibles"}
            return call
        guards = {"token":{"get_by_hash","_is_expired","validate_expires_in_days"},
                  "policy":{"get","is_tool_allowed","get_vault_permissions","is_path_allowed","has_explicit_allowed_tools","is_wrap_path_strictly_allowed"},
                  "binding":{"get","resolve"}}
        if name=="count":
            return lambda:None
        if name not in guards[self.kind]:
            raise AttributeError(name)  # Aucun load/_save/S3 hérité en profil PG.
        facts = request_facts.get()
        if facts is None or self.kind not in facts:
            if name == "count":
                return lambda: None
            raise MetadataUnavailable("request_facts_missing")
        return getattr(facts[self.kind],name)


class PGWrap:
    def __init__(self, scope=None):
        self.scope = scope
        self._ferme_pour_arret = False
        from ..store_refresh import Freshness
        self.freshness = Freshness()
        self.CACHE_TTL = 0
        self.refresh_lock = asyncio.Lock()
        self._last_load_ok = True
        self._wraps = []
        self.revisions = {}
        if scope:
            with connection() as conn:
                self.load_snapshot(select(conn,"wrap","",(),scope=scope))

    def load_snapshot(self, rows):
        obj = view("wrap",rows)
        self._wraps = obj._wraps
        self.revisions = {key_of("wrap",r["payload"]):r["revision"] for r in rows}

    def _maybe_refresh(self):
        return None

    def volumetrie(self):
        return {"entries":None,"last_write_bytes":None}

    def __getattr__(self, name):
        mutating = name in {"register_pending","mark_active","mark_failed","mark_revoked",
            "mark_entries_revoked","try_mark_consuming","mark_consumed","mark_unusable","mark_outcome_unknown"}
        def call(*args, **kwargs):
            if not mutating:
                obj = base("wrap")
                obj._wraps = self._wraps
                return getattr(obj,name)(*args,**kwargs)
            return execute("wrap",name,args,kwargs,mutating=True,scope=self.scope,expected=self.revisions,publish=self.load_snapshot)
        return call


def wrap_for_worker(fn, args, kwargs=None):
    if fn.__name__ == "_wrap_secret_blocking":
        from ..reserved_metadata import target_error
        error = target_error(args[0])
        if error:
            return error
        scope = ("operation",args[3],args[2])
    elif fn.__name__ == "_consume_wrap_secret_blocking":
        scope = ("operation",args[1],args[2])
    elif fn.__name__ == "_revoke_wrap_blocking":
        scope = ("accessor",args[0])
    else:
        scope = ("operation",args[0],args[1])
    from ..vault.wrapping import is_safe_id
    if not all(is_safe_id(v) for v in scope[1:]):
        return {"status":"error","error_type":"invalid_request", "message":"Identifiants de registre invalides"}
    registry = PGWrap(scope)
    from ..reserved_metadata import entries_error
    if entries_error(registry._wraps):
        return entries_error(registry._wraps)
    from ..auth.context import current_token_info
    from .reader import owner_metadata
    identity = current_token_info.get() or {}
    facts = request_facts.get()
    if facts is None:
        raise MetadataUnavailable("request_facts_missing")
    if not identity.get("allowed_resources") and "admin" not in identity.get("permissions",[]):
        ids = {v["vault_id"] for v in registry._wraps}
        if len(ids)>get_settings().metadata_batch_max_ids:
            raise MetadataUnavailable("collection_limit")
        import time
        end = time.monotonic()+5
        for vid in ids:
            facts["owners"][vid] = owner_metadata(vid,deadline=end)
    token = _wrap_scope.set(registry)
    try:
        return fn(*args, **(kwargs or {}))
    finally:
        _wrap_scope.reset(token)
