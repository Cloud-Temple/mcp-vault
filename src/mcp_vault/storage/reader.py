"""Lectures KV v2 ciblées et bornées ; aucune découverte globale de mounts."""

import json
import threading
import time
from urllib.parse import quote

from ..config import get_settings
from .postgres import MetadataUnavailable

_reads = threading.BoundedSemaphore(4)
# Place réservée à la relecture de fond du login PG des métadonnées
# (storage/pg_login.py), qui ne lance jamais deux lectures à la fois. Sans
# elle, des lectures propriétaire qui saturent `_reads` pourraient priver cette
# relecture de place jusqu'à l'expiration du login : toutes les requêtes
# seraient alors refusées, au lieu de quelques-unes.
_login_reads = threading.BoundedSemaphore(1)


class MetadataAbsent(MetadataUnavailable):
    pass


def _request(vault_id, path, *, deadline=None, listing=False, sem=None):
    import httpx
    from ..openbao.manager import get_hvac_client
    client = get_hvac_client()
    if client is None or not client.token:
        raise MetadataUnavailable("vault_unavailable")
    end = deadline if deadline is not None else time.monotonic() + 5
    reads = _reads if sem is None else sem
    if not reads.acquire(timeout=max(0, min(1, end - time.monotonic()))):
        raise MetadataUnavailable("reader_admission_timeout")
    try:
        if time.monotonic() >= end:
            raise MetadataUnavailable("reader_deadline")
        url = (get_settings().openbao_addr.rstrip("/") + "/v1/"
               + quote(vault_id, safe="") + ("/metadata/" if listing else "/data/") + quote(path, safe="/"))
        with httpx.Client(timeout=httpx.Timeout(connect=1, read=2, write=1, pool=1),
                          follow_redirects=False) as http:
            with http.stream("LIST" if listing else "GET", url, headers={"X-Vault-Token": client.token}) as response:
                # Un refus d'OpenBao se décide sur le statut, avant le corps :
                # un 401/403 au corps illisible reste un refus, pas une corruption.
                if response.status_code in {401, 403}:
                    raise MetadataUnavailable("backend_denied")
                body = bytearray()
                for chunk in response.iter_bytes():
                    if time.monotonic() >= end or len(body) + len(chunk) > 65536:
                        raise MetadataUnavailable("reader_limit")
                    body.extend(chunk)
                try:
                    value = json.loads(body)
                except (ValueError, UnicodeError) as exc:
                    raise MetadataUnavailable("metadata_corrupt") from exc
                if (response.status_code == 404 and isinstance(value, dict)
                        and value == {"errors": []}):
                    raise MetadataAbsent("metadata_absent_confirmed")
                if response.status_code in {401, 403}:
                    raise MetadataUnavailable("backend_denied")
                if response.status_code != 200:
                    raise MetadataUnavailable("backend_unavailable")
                if not isinstance(value,dict) or not isinstance(value.get("data"),dict):
                    raise MetadataUnavailable("metadata_corrupt")
                if listing:
                    keys = value["data"].get("keys")
                    if not isinstance(keys,list) or not all(isinstance(k,str) for k in keys):
                        raise MetadataUnavailable("metadata_corrupt")
                    return [k for k in keys if k!="_vault_meta"]
                if not isinstance(value["data"].get("data"),dict):
                    raise MetadataUnavailable("metadata_corrupt")
                return value["data"]["data"]
    except MetadataUnavailable:
        raise
    except Exception as exc:
        raise MetadataUnavailable("backend_unavailable") from exc
    finally:
        reads.release()


def exact_kv(vault_id, path, *, deadline=None, login_refresh=False):
    """`login_refresh` : lecture du login par pg_login, sur sa place dédiée."""
    return _request(vault_id,path,deadline=deadline,sem=_login_reads if login_refresh else None)


def root_keys(vault_id):
    try:
        return _request(vault_id,"",listing=True)
    except MetadataAbsent:
        # Cette absence concerne un LIST, jamais la présence du coffre/owner.
        return []


def owner_metadata(vault_id, *, deadline=None):
    value = exact_kv(vault_id, "_vault_meta", deadline=deadline)
    if not isinstance(value.get("created_by"), str) or not value["created_by"]:
        raise MetadataUnavailable("metadata_corrupt")
    if any(k in value and not isinstance(value[k], str) for k in
           ("description", "created_at", "updated_by", "updated_at")):
        raise MetadataUnavailable("metadata_corrupt")
    return value
