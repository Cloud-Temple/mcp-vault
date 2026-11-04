"""Expiration dédiée : Vault-first, LOGIN maintenance, aucun DML applicatif."""
import uuid
from contextlib import contextmanager

from ..config import get_settings
from .postgres import BoundedConnection, MetadataUnavailable, MutationUnknown, connection, slots, validate_durability
from .reader import MetadataAbsent, exact_kv


def validate_credential(value):
    s = get_settings()
    required = {'host', 'port', 'dbname', 'user', 'password'}
    if (not isinstance(value, dict) or set(value) != required
            or not all(isinstance(value[k], str) and value[k] for k in required)
            or value['dbname'] != s.metadata_pg_database or value['user'] != s.audit_maintenance_role
            or not value['port'].isdigit() or not 1 <= int(value['port']) <= 65535):
        raise ValueError('Credential maintenance invalide')
    return value


def install_credential(body):
    from .operator import bao_request
    s = get_settings()
    value = validate_credential(body)
    try:
        present = exact_kv(s.metadata_pg_vault_id, s.audit_maintenance_secret_path)
    except MetadataAbsent:
        # CAS0 protège aussi contre une écriture concurrente après cette lecture.
        bao_request('POST', s.metadata_pg_vault_id+'/data/'+s.audit_maintenance_secret_path,
                    {'options': {'cas': 0}, 'data': value})
        return {'status': 'ok', 'credential': 'confirmed'}
    if present != value:
        raise MetadataUnavailable('audit_credential_intent_mismatch')
    return {'status': 'ok', 'credential': 'already_verified'}


@contextmanager
def maintenance_connection():
    import psycopg
    from psycopg.rows import dict_row
    s = get_settings()
    limiter = slots()
    if not limiter.acquire(timeout=1):
        raise MetadataUnavailable('admission_timeout')
    conn = None
    try:
        value = validate_credential(exact_kv(s.metadata_pg_vault_id, s.audit_maintenance_secret_path))
        conn = BoundedConnection(psycopg.connect(**value, autocommit=True, row_factory=dict_row,
            sslmode='verify-full', sslrootcert=s.metadata_pg_ca_file, target_session_attrs='read-write',
            connect_timeout=s.metadata_sql_connect_seconds,
            options='-c statement_timeout='+str(s.metadata_sql_statement_seconds*1000),
            keepalives=1, keepalives_idle=2, keepalives_interval=1, keepalives_count=2, tcp_user_timeout=5000))
        identity = conn.execute('SELECT current_database() AS db,current_user AS role').fetchone()
        if identity != {'db': s.metadata_pg_database, 'role': s.audit_maintenance_role}:
            raise MetadataUnavailable('audit_maintenance_identity')
        role = conn.execute("""SELECT rolcanlogin AND NOT(rolsuper OR rolcreatedb OR rolcreaterole
            OR rolreplication OR rolbypassrls) AND NOT EXISTS(
            SELECT 1 FROM pg_auth_members WHERE member=r.oid) AS allowed
            FROM pg_roles r WHERE rolname=current_user""").fetchone()
        if not role or not role['allowed']:
            raise MetadataUnavailable('audit_maintenance_rights')
        conn.execute("SELECT set_config('lock_timeout',%s,false)", (str(s.metadata_sql_lock_seconds*1000),))
        yield conn
    except MetadataUnavailable:
        raise
    except Exception as exc:
        raise MetadataUnavailable('audit_maintenance_unavailable') from exc
    finally:
        try:
            if conn is not None:
                conn.close()
        except Exception as exc:
            raise MetadataUnavailable('close_unconfirmed') from exc
        finally:
            limiter.release()


def expire(body):
    if not isinstance(body, dict) or set(body) - {'batch', 'dry_run', 'confirm'}:
        raise ValueError('Requête expiration invalide')
    batch, dry_run = body.get('batch', 100), body.get('dry_run', True)
    if (isinstance(batch, bool) or not isinstance(batch, int) or not 1 <= batch <= 500
            or not isinstance(dry_run, bool) or not dry_run and body.get('confirm') != 'audit-expire'):
        raise ValueError('Expiration hors borne ou non confirmée')
    if get_settings().metadata_backend != 'postgres':
        raise MetadataUnavailable('audit_pg_profile_required')
    # La connexion applicative vérifie le schéma v2 et les ACL app/maintenance
    # avant l'effet ; maintenance ne reçoit pas SELECT sur les tables métier.
    with connection():
        pass
    operation_id = str(uuid.uuid4())
    committing = False
    try:
        with maintenance_connection() as conn:
            notices = []
            conn.add_notice_handler(lambda diagnostic: notices.append(diagnostic.sqlstate))
            try:
                conn.execute('BEGIN')
                validate_durability(conn)
                row = conn.execute('SELECT vault_metadata.audit_expire(%s,%s,%s) AS result',
                    (get_settings().metadata_instance_id, batch, dry_run)).fetchone()
                if not row or not isinstance(row['result'], dict) or notices:
                    raise MetadataUnavailable('audit_expiration_not_confirmed')
                result = row['result']
                if (set(result) != {'calls', 'events', 'dry_run', 'has_more', 'receipt'}
                        or any(isinstance(result[k], bool) or not isinstance(result[k], int)
                               or result[k] < 0 for k in ('calls', 'events'))
                        or result['calls'] > batch or result['dry_run'] is not dry_run
                        or not isinstance(result['has_more'], bool)):
                    raise MetadataUnavailable('audit_expiration_result_invalid')
                if not dry_run and result['calls']:
                    try:
                        uuid.UUID(result['receipt'])
                    except (ValueError, TypeError, AttributeError):
                        raise MetadataUnavailable('audit_expiration_receipt_invalid') from None
                elif result['receipt'] is not None:
                    raise MetadataUnavailable('audit_expiration_receipt_invalid')
                committing = True
                conn.execute('COMMIT')
                if notices:
                    raise MetadataUnavailable('audit_expiration_notice')
            except BaseException as exc:
                if committing:
                    raise MutationUnknown(operation_id) from exc
                try:
                    conn.execute('ROLLBACK')
                except Exception:
                    pass
                raise
    except MutationUnknown:
        raise
    except MetadataUnavailable as exc:
        if exc.reason == 'close_unconfirmed':
            raise MutationUnknown(operation_id) from exc
        raise
    return {'status': 'ok', 'confirmed': True, **result}
