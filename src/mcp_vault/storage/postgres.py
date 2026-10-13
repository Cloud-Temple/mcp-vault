"""Connexions Vault-first et confirmation honnête, sans retry mutatif."""

import asyncio
import hashlib
import json
import threading
import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar

from ..async_offload import run_blocking
from ..config import get_settings

request_facts = ContextVar("vault_pg_request_facts", default=None)
_slots = None
_slot_lock = threading.Lock()


def slots():
    global _slots
    with _slot_lock:
        if _slots is None:
            _slots = threading.BoundedSemaphore(get_settings().metadata_sql_concurrency)
        return _slots


class BoundedConnection:
    """Budget SQL partagé ; chaque statement est borné par le temps restant."""
    def __init__(self, conn):
        self.conn = conn
        self.end = time.monotonic()+10

    def __getattr__(self,name):
        return getattr(self.conn,name)

    def execute(self,query,params=None,**kwargs):
        remaining = self.end-time.monotonic()
        rollback = isinstance(query,str) and query.strip().upper()=="ROLLBACK"
        if rollback:
            return self.conn.execute(query,params,**kwargs)
        if remaining<=0 and not rollback:
            raise MetadataUnavailable("sql_deadline")
        milliseconds = max(1,min(get_settings().metadata_sql_statement_seconds*1000,int(max(0,remaining)*1000)))
        self.conn.execute("SELECT set_config('statement_timeout',%s,false)",(str(milliseconds),))
        return self.conn.execute(query,params,**kwargs)



class MetadataUnavailable(Exception):
    """Diagnostic fermé, jamais message/DSN du backend sur les interfaces."""
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class MetadataRejected(MetadataUnavailable):
    def __init__(self,response):
        super().__init__("business_rejected")
        self.response = response


class MutationUnknown(MetadataUnavailable):
    def __init__(self, mutation_id):
        super().__init__("outcome_unknown")
        self.mutation_id = mutation_id


def credentials(*, provisioner=False):
    """Seule couture interne de lecture de connexion ; jamais une API métier."""
    from ..openbao.manager import get_hvac_client
    settings = get_settings()
    client = get_hvac_client()
    if client is None:
        raise MetadataUnavailable("vault_unavailable")
    path = (settings.metadata_pg_provisioner_secret_path if provisioner
            else settings.metadata_pg_secret_path)
    # Client HTTP dédié borné : pas de mutation du singleton hvac partagé.
    from .reader import exact_kv
    value = exact_kv(settings.metadata_pg_vault_id, path)
    role = settings.metadata_pg_provisioner_role if provisioner else settings.metadata_pg_app_role
    required = {"host", "port", "dbname", "user", "password"}
    if (not isinstance(value, dict) or set(value) != required
            or not all(isinstance(value[k], str) and value[k] for k in required)
            or value["dbname"] != settings.metadata_pg_database or value["user"] != role
            or not value["port"].isdigit()):
        raise MetadataUnavailable("connection_invalid")
    return value


@contextmanager
def connection(*, provisioner=False, schema=True):
    import psycopg
    from psycopg.rows import dict_row
    s = get_settings()
    admission_slots = slots()
    if not admission_slots.acquire(timeout=1):
        raise MetadataUnavailable("admission_timeout")
    conn = None
    try:
        value = credentials(provisioner=provisioner)
        conn = psycopg.connect(**value, options="-c statement_timeout="+str(s.metadata_sql_statement_seconds*1000),
            keepalives=1, keepalives_idle=2, keepalives_interval=1, keepalives_count=2, tcp_user_timeout=5000, sslmode="verify-full", sslrootcert=s.metadata_pg_ca_file,
            target_session_attrs="read-write", connect_timeout=s.metadata_sql_connect_seconds,
            autocommit=True, row_factory=dict_row)
        conn = BoundedConnection(conn)
        identity = conn.execute("SELECT current_database() AS db, current_user AS role").fetchone()
        if identity != {"db": s.metadata_pg_database, "role": value["user"]}:
            raise MetadataUnavailable("identity_invalid")
        conn.execute("SELECT set_config('statement_timeout', %s, false)",
                     (str(s.metadata_sql_statement_seconds * 1000),))
        conn.execute("SELECT set_config('lock_timeout', %s, false)",
                     (str(s.metadata_sql_lock_seconds * 1000),))
        if not provisioner:
            rights = conn.execute("""SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication,
                 rolbypassrls FROM pg_roles WHERE rolname=current_user""").fetchone()
            if not rights or any(rights.values()):
                raise MetadataUnavailable("rights_invalid")
            ddl = conn.execute("""SELECT has_database_privilege(current_user,current_database(),'CREATE') AS db,
                 has_schema_privilege(current_user,'public','CREATE') AS public, has_database_privilege(current_user,current_database(),'TEMP') AS temp""").fetchone()
            if any(ddl.values()):
                raise MetadataUnavailable("rights_invalid")
            memberships = conn.execute("SELECT pg_has_role(current_user,%s,'MEMBER') AS owner, pg_has_role(current_user,%s,'MEMBER') AS provisioner",
                       (s.metadata_pg_owner_role,s.metadata_pg_provisioner_role)).fetchone()
            inherited = conn.execute("SELECT EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON m.member=r.oid WHERE r.rolname=current_user) AS member").fetchone()
            if any(memberships.values()) or inherited["member"]:
                raise MetadataUnavailable("rights_invalid")
        if schema:
            row = conn.execute("SELECT version FROM vault_metadata.schema_version").fetchall()
            if row != [{"version": 1}]:
                raise MetadataUnavailable("schema_invalid")
            if not provisioner:
                if conn.execute("SELECT has_schema_privilege(current_user,'vault_metadata','CREATE') AS ddl").fetchone()["ddl"]:
                    raise MetadataUnavailable("rights_invalid")
                tables = ["vault_metadata."+t for t in ("tokens","token_vaults","policies","mission_bindings","binding_vaults","wrap_registry")]
                grants = conn.execute("""SELECT bool_and(has_table_privilege(current_user,t,p)) AS allowed
                     FROM unnest(%s::text[]) t CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE']) p""", (tables,)).fetchone()
                immutable = conn.execute("""SELECT bool_and(has_table_privilege(current_user,t,'SELECT')
                    AND has_table_privilege(current_user,t,'INSERT')
                    AND NOT has_table_privilege(current_user,t,'UPDATE')
                    AND NOT has_table_privilege(current_user,t,'DELETE')) AS allowed
                    FROM unnest(ARRAY['vault_metadata.operation_receipts','vault_metadata.installation']) t""").fetchone()
                ownership = conn.execute("SELECT pg_get_userbyid(nspowner) AS owner FROM pg_namespace WHERE nspname='vault_metadata'").fetchone()
                default_public = conn.execute("""SELECT EXISTS(SELECT 1 FROM pg_default_acl d
                    JOIN pg_roles r ON r.oid=d.defaclrole,
                    LATERAL aclexplode(d.defaclacl) a WHERE r.rolname=%s AND d.defaclobjtype='r'
                    AND a.grantee=0) AS allowed""",(s.metadata_pg_owner_role,)).fetchone()
                schema_public = conn.execute("""SELECT EXISTS(SELECT 1 FROM pg_namespace n,
                    LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a
                    WHERE n.nspname='vault_metadata' AND a.grantee=0) AS allowed""").fetchone()
                public = conn.execute("""SELECT EXISTS(SELECT 1 FROM pg_database d,
                    LATERAL aclexplode(COALESCE(d.datacl,acldefault('d',d.datdba))) a
                    WHERE d.datname=current_database() AND a.grantee=0
                    AND a.privilege_type IN ('CONNECT','TEMPORARY','CREATE')) AS allowed""").fetchone()
                if (not grants["allowed"] or not immutable["allowed"] or public["allowed"]
                        or not ownership or ownership["owner"]!=s.metadata_pg_owner_role
                        or default_public["allowed"] or schema_public["allowed"]):
                    raise MetadataUnavailable("rights_invalid")
        yield conn
    except (MetadataUnavailable, MutationUnknown):
        raise
    except Exception as exc:
        raise MetadataUnavailable("storage_unavailable") from exc
    finally:
        try:
            if conn is not None:
                conn.close()
        except Exception as exc:
            raise MetadataUnavailable("close_unconfirmed") from exc
        finally:
            admission_slots.release()


def revalidate_actor(conn):
    from ..auth.context import current_token_info
    from ..auth.token_store import TokenStore
    facts = request_facts.get()
    identity = current_token_info.get() or {}
    if facts is None:
        raise MetadataUnavailable("actor_missing")
    instance = get_settings().metadata_instance_id
    if facts.get("actor_hash"):
        row = conn.execute("SELECT payload,revision FROM vault_metadata.tokens WHERE instance_id=%s AND token_hash=%s FOR SHARE",
                           (instance,facts["actor_hash"])).fetchone()
        if (not row or row["revision"]!=facts["actor_revision"]
                or row["payload"].get("revoked") or TokenStore._is_expired(row["payload"])):
            raise MetadataUnavailable("actor_changed")
    elif identity.get("auth_type")=="mission_jwt" and facts.get("actor_binding"):
        row = conn.execute("SELECT payload,revision FROM vault_metadata.mission_bindings WHERE instance_id=%s AND tenant_id=%s FOR SHARE",
                           (instance,facts["actor_binding"])).fetchone()
        if (not row or row["revision"]!=facts["binding_revision"] or not row["payload"].get("enabled")
                or row["payload"].get("_deleted") or identity.get("tenant_id")!=facts["actor_binding"]):
            raise MetadataUnavailable("binding_changed")
        from datetime import datetime,timezone
        expires = row["payload"].get("expires_at")
        if expires and datetime.fromisoformat(expires)<=datetime.now(timezone.utc):
            raise MetadataUnavailable("binding_expired")
    else:
        raise MetadataUnavailable("actor_missing")
    for policy_id,revision in facts.get("policy_revisions",{}).items():
        row = conn.execute("SELECT revision FROM vault_metadata.policies WHERE instance_id=%s AND policy_id=%s FOR SHARE",
                           (instance,policy_id)).fetchone()
        if not row or row["revision"]!=revision:
            raise MetadataUnavailable("policy_changed")


def validate_durability(conn):
    s = get_settings()
    conn.execute("SET LOCAL synchronous_commit = 'remote_apply'")
    policy = conn.execute("SHOW synchronous_commit").fetchone()
    if policy.get("synchronous_commit") != "remote_apply":
        raise MetadataUnavailable("durability_invalid")
    if s.metadata_pg_durability == "ha":
        names = conn.execute("SHOW synchronous_standby_names").fetchone()
        replicas = conn.execute("SELECT state,sync_state FROM pg_stat_replication").fetchall()
        if not names.get("synchronous_standby_names") or not any(
            r["state"]=="streaming" and r["sync_state"] in {"sync","quorum"} for r in replicas):
            raise MetadataUnavailable("synchronous_replica_unavailable")
    if conn.execute("SHOW fsync").fetchone().get("fsync") != "on":
        raise MetadataUnavailable("durability_invalid")

def _mutation(kind, target, operation, *, operator=False, mutation_id=None):
    from psycopg.types.json import Jsonb
    s = get_settings()
    mid = str(uuid.UUID(mutation_id)) if mutation_id else str(uuid.uuid4())
    committing = False
    notices = []
    with connection() as conn:
        conn.add_notice_handler(lambda diagnostic: notices.append(diagnostic.sqlstate))
        try:
            conn.execute("BEGIN")
            validate_durability(conn)
            if not operator:
                revalidate_actor(conn)
            # Un UUID déjà présent ne constitue jamais une demande de replay.
            if conn.execute("SELECT 1 FROM vault_metadata.operation_receipts WHERE instance_id=%s AND mutation_id=%s",
                            (s.metadata_instance_id, mid)).fetchone():
                raise MetadataUnavailable("mutation_already_recorded")
            result = operation(conn)
            if notices:
                raise MetadataUnavailable("transaction_notice")
            intent = hashlib.sha256(json.dumps([kind,target], sort_keys=True).encode()).hexdigest()
            actor = (request_facts.get() or {}).get("actor_hash")
            if actor is None and not operator:
                from ..auth.context import current_token_info
                identity = current_token_info.get() or {}
                actor = hashlib.sha256(json.dumps({k:identity.get(k) for k in ("auth_type","tenant_id","mission_id","jti")},sort_keys=True).encode()).hexdigest()
            conn.execute("""INSERT INTO vault_metadata.operation_receipts
                (instance_id,mutation_id,kind,actor_hash,intent_hash,target,phase,database_result)
                VALUES(%s,%s,%s,%s,%s,%s,%s,'committed')""",
                (s.metadata_instance_id,mid,kind,actor,intent,Jsonb(target),kind))
            committing = True
            conn.execute("COMMIT")
            if notices:
                raise MutationUnknown(mid)
            return result
        except MutationUnknown:
            raise
        except Exception as exc:
            if committing:
                raise MutationUnknown(mid) from exc
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            if isinstance(exc, MetadataUnavailable):
                raise
            raise MetadataUnavailable("mutation_rejected") from exc


def mutation(kind,target,operation,*,operator=False,mutation_id=None):
    mid = str(uuid.UUID(mutation_id)) if mutation_id else str(uuid.uuid4())
    try:
        return _mutation(kind,target,operation,operator=operator,mutation_id=mid)
    except MetadataUnavailable as exc:
        if exc.reason=="close_unconfirmed":
            raise MutationUnknown(mid) from exc
        raise


async def offload(fn, *args, **kwargs):
    from functools import partial
    return await run_blocking(partial(fn, *args, **kwargs))


def resolve_receipt(mutation_id,kind,target,*,initial_confirmation="unknown"):
    """Résolution INTERNE autorisée sur tuple entier ; aucune API témoin ajoutée.

    Une présence SQL constate l'effet. Elle ne change jamais la classification
    initiale d'ACK du caller et ne permet aucune remise en file/replay.
    """
    from ..auth.context import current_token_info
    identity = current_token_info.get() or {}
    facts = request_facts.get() or {}
    mid = str(uuid.UUID(mutation_id))
    if initial_confirmation not in {"unknown","confirmed"} or not isinstance(target,dict):
        raise MetadataUnavailable("receipt_target_invalid")
    actor = facts.get("actor_hash")
    if actor is None:
        actor = hashlib.sha256(json.dumps({k:identity.get(k) for k in
            ("auth_type","tenant_id","mission_id","jti")},sort_keys=True).encode()).hexdigest()
    with connection() as conn:
        conn.execute("BEGIN")
        try:
            revalidate_actor(conn)
            row = conn.execute("SELECT kind,actor_hash,target,phase FROM vault_metadata.operation_receipts WHERE instance_id=%s AND mutation_id=%s",
                (get_settings().metadata_instance_id,mid)).fetchone()
            if not row or row["kind"]!=kind or row["phase"]!=kind or row["actor_hash"]!=actor or row["target"]!=target:
                return {"status":"inaccessible","initial_confirmation":initial_confirmation}
            if kind.startswith("wrap:"):
                operation_id = target.get("business_operation_id")
                mission_id = target.get("mission_id")
                if not operation_id or not mission_id:
                    return {"status":"inaccessible","initial_confirmation":initial_confirmation}
                entries = conn.execute("SELECT payload FROM vault_metadata.wrap_registry WHERE instance_id=%s AND operation_id=%s AND mission_id=%s",
                    (get_settings().metadata_instance_id,operation_id,mission_id)).fetchall()
                from ..reserved_metadata import entries_error
                values = [r["payload"] for r in entries]
                if not values or entries_error(values):
                    return {"status":"inaccessible","initial_confirmation":initial_confirmation}
                if not identity.get("allowed_resources") and "admin" not in identity.get("permissions",[]):
                    from .reader import owner_metadata
                    for vid in {v["vault_id"] for v in values}:
                        facts["owners"][vid] = owner_metadata(vid)
                from ..vault.wrapping import _visible_entries
                if len(_visible_entries(values))!=len(values):
                    return {"status":"inaccessible","initial_confirmation":initial_confirmation}
            elif "admin" not in identity.get("permissions",[]):
                return {"status":"inaccessible","initial_confirmation":initial_confirmation}
            return {"status":"ok","effect_observed":bool(target.get("effect_changed")),"mutation_id":mid,
                    "initial_confirmation":initial_confirmation,"replay_allowed":False}
        finally:
            conn.execute("ROLLBACK")
