"""Faits frais par requête, partagés entre les deux résolutions bearer."""

import hashlib
import hmac
import time

from ..config import get_settings
from .postgres import connection, MetadataUnavailable, offload, request_facts
from .stores import view


def load_facts(raw_token, tenant_id=None):
    s = get_settings()
    with connection() as conn:
        conn.execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        tokens = conn.execute("SELECT payload,revision FROM vault_metadata.tokens WHERE instance_id=%s AND token_hash=%s",
                              (s.metadata_instance_id,token_hash)).fetchall()
        bindings = []
        if tenant_id:
            bindings = conn.execute("SELECT payload,revision FROM vault_metadata.mission_bindings WHERE instance_id=%s AND tenant_id=%s",
                                   (s.metadata_instance_id,tenant_id)).fetchall()
        ids = {r["payload"].get("policy_id") for r in tokens+bindings} - {None,""}
        policies = conn.execute("SELECT payload,revision FROM vault_metadata.policies WHERE instance_id=%s AND policy_id=ANY(%s)",
                               (s.metadata_instance_id,list(ids))).fetchall()
        conn.execute("COMMIT")
        facts = {"token":view("token",tokens),"policy":view("policy",policies),
                 "binding":view("binding",bindings),"owners":{},
                 "actor_hash":token_hash if tokens else None,
                 "actor_revision":tokens[0]["revision"] if tokens else None,
                 "policy_revisions":{r["payload"]["policy_id"]:r["revision"] for r in policies}}
        if bindings:
            facts["actor_binding"] = tenant_id
            facts["binding_revision"] = bindings[0]["revision"]
        return facts


async def admit(raw_token):
    s = get_settings()
    if not raw_token or len(raw_token)>8192 or hmac.compare_digest(raw_token,s.admin_bootstrap_key):
        raise PermissionError("Métier fermé à la clé bootstrap")
    tenant = None
    if raw_token.count(".") == 2 and s.mcp_auth_mode in {"jwt","dual-stack"}:
        # Une sélection SQL n'est pas une décision d'auth : la signature et le
        # binding sont ensuite vérifiés par le PEP JWT existant.
        import jwt
        try:
            claims = jwt.decode(raw_token,options={"verify_signature":False})
            tenant = claims.get("tenant_id")
            if not isinstance(tenant,str) or len(tenant)>128:
                tenant = None
        except jwt.PyJWTError:
            pass
    return await offload(load_facts,raw_token,tenant)


async def preload_owners(ids, *, batch=False):
    import asyncio
    from .reader import owner_metadata, MetadataAbsent
    from ..reserved_metadata import target_error
    from ..auth.context import current_token_info
    facts = request_facts.get()
    identity = current_token_info.get()
    if facts is None or identity is None:
        raise MetadataUnavailable("request_facts_missing")
    ids = list(dict.fromkeys(ids))
    if len(ids)>get_settings().metadata_batch_max_ids:
        raise ValueError("Lot hors borne")
    if any(target_error(v) for v in ids):
        raise PermissionError("Accès au coffre refusé")
    allow = identity.get("allowed_resources",[])
    admin = "admin" in identity.get("permissions",[])
    if identity.get("auth_type")=="mission_jwt" and not allow:
        raise PermissionError("Périmètre requis")
    if allow and not admin and any(v not in allow for v in ids):
        raise PermissionError("Accès au coffre refusé")
    end = time.monotonic()+5
    async def read(vid):
        try:
            value = await offload(owner_metadata,vid,deadline=end)
        except MetadataAbsent:
            if not admin and not allow:
                raise PermissionError("Accès au coffre refusé")
            raise MetadataUnavailable("metadata_incomplete")
        if not admin and not allow and value["created_by"] != identity.get("client_name"):
            raise PermissionError("Accès au coffre refusé")
        return vid,value
    values = await asyncio.gather(*(read(vid) for vid in ids),return_exceptions=True)
    # Drain de tous les workers avant publication/erreur, aucune vue partielle.
    for value in values:
        if isinstance(value,BaseException):
            raise value
    facts["owners"].update(dict(values))


async def batch_metadata(vault_ids, limit=50, cursor=None):
    import base64
    import json
    from ..vault_ids import is_valid_vault_id
    from ..auth.context import check_policy, enforce_wrap_only_token, current_token_info
    error = enforce_wrap_only_token("vault_metadata_batch") or check_policy("vault_metadata_batch")
    if error:
        return error
    if (not isinstance(vault_ids,list) or not vault_ids or len(vault_ids)>get_settings().metadata_batch_max_ids
            or not all(is_valid_vault_id(v) for v in vault_ids)
            or isinstance(limit,bool) or not isinstance(limit,int) or limit<1
            or limit>get_settings().metadata_batch_max_ids):
        return {"status":"error","error_type":"invalid_request","message":"Lot invalide"}
    ids = sorted(set(vault_ids))
    actor = current_token_info.get() or {}
    fingerprint = hashlib.sha256(json.dumps([ids,actor],sort_keys=True).encode()).hexdigest()
    offset = 0
    try:
        if cursor:
            if not isinstance(cursor,str) or len(cursor)>1024:
                raise ValueError()
            decoded = json.loads(base64.urlsafe_b64decode(cursor))
            if not isinstance(decoded,dict):
                raise ValueError()
            if decoded.get("fingerprint") != fingerprint or type(decoded.get("offset")) is not int:
                raise ValueError()
            offset = decoded["offset"]
            if offset<0 or offset>len(ids):
                raise ValueError()
        await preload_owners(ids,batch=True)
        owners = request_facts.get()["owners"]
        page = [{"vault_id":v,**{k:owners[v][k] for k in
                ("description","created_by","created_at","updated_by","updated_at") if k in owners[v]},
                 "source":"openbao", "complete":True} for v in ids[offset:offset+limit]]
        next_cursor = None
        if offset+limit<len(ids):
            next_cursor = base64.urlsafe_b64encode(json.dumps(
                {"fingerprint":fingerprint,"offset":offset+limit}).encode()).decode()
        return {"status":"ok","vaults":page,"count":len(page),"total":len(ids),"cursor":next_cursor}
    except PermissionError:
        return {"status":"error","error_type":"access_denied","message":"Accès au coffre refusé"}
    except MetadataUnavailable as exc:
        classification = {"metadata_absent_confirmed":"absence_confirmed", "backend_denied":"backend_denied", "metadata_corrupt":"corrupt"}.get(exc.reason,"unavailable")
        return {"status":"error","error_type":"metadata_incomplete","classification":classification,"message":"Métadonnées indisponibles"}
    except (ValueError,TypeError):
        return {"status":"error","error_type":"invalid_request","message":"Curseur ou lot invalide"}


def request_target(*, ssh=False, creating=False):
    from functools import wraps
    from inspect import signature
    def decorate(fn):
        sig = signature(fn)
        @wraps(fn)
        async def call(*args,**kwargs):
            if get_settings().metadata_backend == "postgres":
                from ..reserved_metadata import target_error
                from ..auth.context import current_token_info
                vid = sig.bind(*args,**kwargs).arguments["vault_id"]
                error = target_error(vid,ssh=ssh)
                if error:
                    return error
                identity = current_token_info.get() or {}
                if request_facts.get() is None:
                    return {"status":"error","error_type":"storage_unavailable", "message":"Admission requise"}
                if creating:
                    request_facts.get()["creating"] = vid
                elif not identity.get("allowed_resources") and "admin" not in identity.get("permissions",[]):
                    try:
                        await preload_owners([vid])
                    except PermissionError:
                        return {"status":"error","error_type":"access_denied","message":"Accès au coffre refusé"}
                    except MetadataUnavailable:
                        return {"status":"error","error_type":"backend_unavailable","message":"Métadonnées indisponibles"}
            return await fn(*args,**kwargs)
        return call
    return decorate


async def admitted_call(scope, receive, send, fn):
    import json
    raw = dict(scope.get("headers",[])).get(b"authorization",b"").decode("latin-1")
    raw = raw[7:] if raw.startswith("Bearer ") else ""
    try:
        facts = await admit(raw)
    except (PermissionError,MetadataUnavailable) as exc:
        status = 403 if isinstance(exc,PermissionError) else 503
        body = json.dumps({"status":"error","message":"Accès aux métadonnées indisponible"}).encode()
        await send({"type":"http.response.start","status":status,"headers":[(b"content-type",b"application/json")]})
        return await send({"type":"http.response.body","body":body})
    ctx = request_facts.set(facts)
    started = False
    async def monitored_send(message):
        nonlocal started
        if message["type"]=="http.response.start":
            started = True
        await send(message)
    try:
        try:
            return await fn(scope,receive,monitored_send)
        except MetadataUnavailable:
            if started:
                raise
            body = b'{"status":"error","message":"Metadonnees indisponibles"}'
            await send({"type":"http.response.start","status":503,"headers":[(b"content-type",b"application/json")]})
            return await send({"type":"http.response.body","body":body})
    finally:
        request_facts.reset(ctx)
