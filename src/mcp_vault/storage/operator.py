"""Voie opérateur finie, indépendante du magasin bearer PG."""

import hashlib
import hmac
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..config import get_settings
from .postgres import (MetadataUnavailable, MutationUnknown, connection, credentials,
                       mutation, offload)


def bao_request(method, suffix, data=None):
    import httpx
    from ..openbao.manager import get_hvac_client
    s = get_settings()
    client = get_hvac_client()
    if client is None or not client.token:
        raise MetadataUnavailable("vault_unavailable")
    try:
        with httpx.Client(timeout=httpx.Timeout(connect=1,read=2,write=1,pool=1),follow_redirects=False) as http:
            with http.stream(method,s.openbao_addr.rstrip("/")+"/v1/"+suffix,
                    headers={"X-Vault-Token":client.token},json=data) as response:
                chunks = bytearray()
                import time
                end = time.monotonic()+5
                for chunk in response.iter_bytes():
                    if len(chunks)+len(chunk)>65536 or time.monotonic()>=end:
                        raise MetadataUnavailable("operator_response_unknown")
                    chunks.extend(chunk)
                if response.status_code not in {200,204}:
                    raise MetadataUnavailable("operator_backend_rejected")
                return None if response.status_code==204 else json.loads(chunks)
    except MetadataUnavailable:
        raise
    except Exception as exc:
        raise MetadataUnavailable("operator_outcome_unconfirmed") from exc


def validate_connection(value, provisioner=False):
    s = get_settings()
    required = {"host","port","dbname","user","password"}
    role = s.metadata_pg_provisioner_role if provisioner else s.metadata_pg_app_role
    if (not isinstance(value,dict) or set(value)!=required
            or not all(isinstance(value[k],str) and value[k] for k in required)
            or value["dbname"]!=s.metadata_pg_database or value["user"]!=role
            or not value["port"].isdigit()):
        raise ValueError("Credential de connexion invalide")
    return value


def action(name, body):
    s = get_settings()
    mount = s.metadata_pg_vault_id
    if name == "vault":
        bao_request("POST","sys/mounts/"+mount,{"type":"kv","options":{"version":"2"}})
        return {"status":"ok","created":True}
    if name == "connections":
        if set(body)!={"app","provisioner"}:
            raise ValueError("Deux credentials requis")
        app = validate_connection(body["app"])
        provisioner = validate_connection(body["provisioner"],True)
        tune = bao_request("GET","sys/mounts/"+mount+"/tune")
        if not isinstance(tune,dict) or tune.get("data",{}).get("options",{}).get("version")!="2":
            raise MetadataUnavailable("technical_mount_invalid")
        from .reader import exact_kv, MetadataAbsent
        proposed = (("app",s.metadata_pg_secret_path,app),
                    ("provisioner",s.metadata_pg_provisioner_secret_path,provisioner))
        absent = set()
        # Prévalider les DEUX intentions, sans secret reflété et sans écrasement.
        for kind,path,value in proposed:
            try:
                present = exact_kv(mount,path)
            except MetadataAbsent:
                absent.add(kind)
                continue
            if present != value:
                raise MetadataUnavailable("installation_intent_mismatch")
        results = {}
        for kind,path,value in proposed:
            if kind not in absent:
                results[kind] = "already_verified"
                continue
            try:
                bao_request("POST",mount+"/data/"+path,{"options":{"cas":0},"data":value})
                results[kind] = "confirmed"
            except MetadataUnavailable:
                return {"status":"error","error_type":"operator_outcome_unconfirmed",
                        "steps":{**results,kind:"unconfirmed"},"message":"Arrêter et vérifier sans rejouer"}
        return {"status":"ok","steps":results}
    if name == "verify-connections":
        credentials()
        credentials(provisioner=True)
        return {"status":"ok","app_valid":True,"provisioner_valid":True}
    if name == "schema-init":
        from psycopg import sql
        credentials()  # Valider aussi le chemin app avant le premier effet DDL.
        mid = str(uuid.uuid4())
        committing = False
        notices = []
        with connection(provisioner=True,schema=False) as conn:
            conn.add_notice_handler(lambda diagnostic:notices.append(diagnostic.sqlstate))
            try:
                conn.execute("BEGIN")
                from .postgres import validate_durability
                validate_durability(conn)
                conn.execute(sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(s.metadata_pg_owner_role)))
                owner = conn.execute("SELECT rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=current_user").fetchone()
                if not owner or any(owner.values()):
                    raise MetadataUnavailable("owner_invalid")
                conn.execute(Path(__file__).with_name("schema").joinpath("001.sql").read_text(),prepare=False)
                conn.execute(sql.SQL("GRANT USAGE ON SCHEMA vault_metadata TO {}").format(sql.Identifier(s.metadata_pg_app_role)))
                conn.execute(sql.SQL("GRANT SELECT ON vault_metadata.schema_version TO {}").format(sql.Identifier(s.metadata_pg_app_role)))
                for table in ("tokens","token_vaults","policies","mission_bindings","binding_vaults",
                              "wrap_registry","operation_receipts","installation"):
                    conn.execute(sql.SQL("GRANT SELECT,INSERT,UPDATE,DELETE ON vault_metadata.{} TO {}").format(
                        sql.Identifier(table),sql.Identifier(s.metadata_pg_app_role)))
                conn.execute(sql.SQL("REVOKE UPDATE,DELETE ON vault_metadata.operation_receipts,vault_metadata.installation FROM {}").format(sql.Identifier(s.metadata_pg_app_role)))
                conn.execute("ALTER DEFAULT PRIVILEGES IN SCHEMA vault_metadata REVOKE ALL ON TABLES FROM PUBLIC")
                conn.execute(sql.SQL("ALTER DEFAULT PRIVILEGES IN SCHEMA vault_metadata GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO {}").format(sql.Identifier(s.metadata_pg_app_role)))
                from psycopg.types.json import Jsonb
                target = {"schema_version":1,"expected_revision":0,"result_revision":1}
                intent = hashlib.sha256(json.dumps(target,sort_keys=True).encode()).hexdigest()
                conn.execute("INSERT INTO vault_metadata.operation_receipts(instance_id,mutation_id,kind,intent_hash,target,phase,database_result) VALUES(%s,%s,'schema-init',%s,%s,'schema-init','committed')",
                             (s.metadata_instance_id,mid,intent,Jsonb(target)))
                if notices:
                    raise MetadataUnavailable("schema_notice")
                committing = True
                conn.execute("COMMIT")
                if notices:
                    raise MutationUnknown(mid)
            except Exception as exc:
                if committing:
                    raise MutationUnknown(mid) from exc
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise MetadataUnavailable("schema_init_rejected") from exc
        # Aucun DDL app : cette connexion ne fait que qualifier les droits.
        with connection():
            pass
        return {"status":"ok","schema_version":1,"mutation_id":mid}
    if name == "initial-admin":
        from psycopg.types.json import Jsonb
        if set(body)!={"token_hash","client_name","mutation_id"}:
            raise ValueError("Seed invalide")
        token_hash = body["token_hash"]
        if not isinstance(token_hash,str) or not re.fullmatch(r"[0-9a-f]{64}",token_hash):
            raise ValueError("Hash invalide")
        client_name = body["client_name"]
        if not isinstance(client_name,str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}",client_name):
            raise ValueError("Identité invalide")
        mid = str(uuid.UUID(body["mutation_id"]))
        now = datetime.now(timezone.utc)
        value = {"hash":token_hash,"client_name":client_name,"permissions":["admin"],
            "policy_id":"","allowed_resources":[],"email":"","revoked":False,
            "created_at":now.isoformat(),"expires_at":(now+timedelta(hours=s.metadata_initial_admin_hours)).isoformat()}
        def seed(conn):
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",(s.metadata_instance_id,))
            if conn.execute("SELECT 1 FROM vault_metadata.installation WHERE instance_id=%s",(s.metadata_instance_id,)).fetchone():
                raise MetadataUnavailable("already_installed")
            if conn.execute("SELECT 1 FROM vault_metadata.tokens WHERE instance_id=%s LIMIT 1",(s.metadata_instance_id,)).fetchone():
                raise MetadataUnavailable("installation_ambiguous")
            conn.execute("INSERT INTO vault_metadata.tokens VALUES(%s,%s,NULL,%s,1)",
                (s.metadata_instance_id,token_hash,Jsonb(value)))
            conn.execute("INSERT INTO vault_metadata.installation VALUES(%s,%s,%s)",(s.metadata_instance_id,mid,token_hash))
            return {"status":"ok","mutation_id":mid}
        return mutation("initial-admin",{"client_name":client_name,"token_hash":token_hash},seed,
                        operator=True,mutation_id=mid)
    if name.startswith("installation-result/"):
        mid = str(uuid.UUID(name.split("/",1)[1]))
        if set(body)!={"token_hash","client_name"}:
            raise ValueError("Intention attendue requise")
        target = {"client_name":body["client_name"],"token_hash":body["token_hash"]}
        intent = hashlib.sha256(json.dumps(["initial-admin",target],sort_keys=True).encode()).hexdigest()
        with connection() as conn:
            row = conn.execute("""SELECT r.kind FROM vault_metadata.operation_receipts r
                JOIN vault_metadata.installation i USING(instance_id,mutation_id)
                WHERE r.instance_id=%s AND r.mutation_id=%s AND r.kind='initial-admin' AND r.intent_hash=%s AND i.actor_hash=%s""",
                (s.metadata_instance_id,mid,intent,body["token_hash"])).fetchone()
        return {"status":"ok","effect_observed":bool(row),"mutation_id":mid,
                "initial_confirmation":"not_asserted"}
    raise ValueError("Action inconnue")


async def handle_operator(scope, receive, send):
    from ..admin.api import _json_response
    s = get_settings()
    raw = dict(scope.get("headers",[])).get(b"authorization",b"").decode("latin-1")
    key = raw[7:] if raw.startswith("Bearer ") else ""
    if not key or not hmac.compare_digest(key,s.admin_bootstrap_key):
        return await _json_response(send,401,{"status":"error","message":"Authentification requise"})
    name = scope.get("path","").removeprefix("/admin/api/metadata-operator/")
    expected = "GET" if name=="status" or name.startswith("installation-result/") else "POST"
    permitted = {"status","verify-connections"}
    if s.metadata_operator_mode == "install":
        permitted |= {"vault","connections","schema-init","initial-admin"}
    if (s.metadata_operator_mode=="disabled" or scope.get("method")!=expected
            or name not in permitted and not name.startswith("installation-result/")):
        return await _json_response(send,403,{"status":"error","message":"Action opérateur refusée"})
    if name=="status":
        from ..openbao.manager import probe_openbao
        result = await probe_openbao()
        return await _json_response(send,200,{"status":"ok","mode":s.metadata_operator_mode,
            "openbao_ready":result.ok,"metadata_readiness":"not_probed"})
    body = bytearray()
    try:
        while True:
            part = await receive()
            if part["type"]=="http.disconnect":
                raise ValueError("Requête interrompue")
            body.extend(part.get("body",b""))
            if len(body)>65536:
                raise ValueError("Corps hors borne")
            if not part.get("more_body"):
                break
        if name.startswith("installation-result/"):
            from urllib.parse import parse_qs
            parameters = parse_qs(scope.get("query_string",b"").decode("ascii"),strict_parsing=True)
            if any(len(v)!=1 for v in parameters.values()):
                raise ValueError()
            data = {k:v[0] for k,v in parameters.items()}
        else:
            data = json.loads(body) if body else {}
        if not isinstance(data,dict):
            raise ValueError("Objet requis")
        result = await offload(action,name,data)
        return await _json_response(send,200 if result.get("status")=="ok" else 503,result)
    except MutationUnknown as exc:
        return await _json_response(send,503,{"status":"error","error_type":"outcome_unknown",
            "mutation_id":exc.mutation_id,"message":"Résultat indéterminé ; ne pas rejouer"})
    except (ValueError,TypeError):
        return await _json_response(send,400,{"status":"error","message":"Requête opérateur invalide"})
    except MetadataUnavailable:
        return await _json_response(send,503,{"status":"error","message":"Action non confirmée ; vérifier sans rejouer"})
