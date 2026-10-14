"""Lectures KV v2 ciblées et bornées ; aucune découverte globale de mounts."""

import json
import threading
import time
from urllib.parse import quote

from ..config import get_settings
from .postgres import MetadataUnavailable

_reads = threading.BoundedSemaphore(4)


class MetadataAbsent(MetadataUnavailable):
    pass


def _request(vault_id, path, *, deadline=None, listing=False):
    import httpx
    from ..openbao.manager import get_hvac_client
    client = get_hvac_client()
    if client is None or not client.token:
        raise MetadataUnavailable("vault_unavailable")
    end = deadline if deadline is not None else time.monotonic() + 5
    if not _reads.acquire(timeout=max(0, min(1, end - time.monotonic()))):
        raise MetadataUnavailable("reader_admission_timeout")
    try:
        if time.monotonic() >= end:
            raise MetadataUnavailable("reader_deadline")
        url = (get_settings().openbao_addr.rstrip("/") + "/v1/"
               + quote(vault_id, safe="") + ("/metadata/" if listing else "/data/") + quote(path, safe="/"))
        with httpx.Client(timeout=httpx.Timeout(connect=1, read=2, write=1, pool=1),
                          follow_redirects=False) as http:
            with http.stream("LIST" if listing else "GET", url, headers={"X-Vault-Token": client.token}) as response:
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
        _reads.release()


def exact_kv(vault_id, path, *, deadline=None):
    return _request(vault_id,path,deadline=deadline)


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
