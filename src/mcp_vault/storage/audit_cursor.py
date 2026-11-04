"""Curseurs179 éphémères : métadonnées seulement, aucune autorité ni cache d'audits."""

import hashlib
import hmac
import json
import re
import secrets
import threading
import time

from .audit_read import Cursor, ExportIncomplete


class Cursors:
    CAPACITY = 128
    TTL_SECONDS = 120

    def __init__(self):
        self._lock = threading.Lock()
        self._entries = {}

    def _expire(self, now):
        for key, (_, expires, _) in list(self._entries.items()):
            if expires <= now:
                del self._entries[key]

    def put(self, context, cursor):
        if not re.fullmatch(r"[0-9a-f]{64}", context) or not isinstance(cursor, Cursor):
            raise ValueError("audit cursor context invalid")
        with self._lock:
            now = time.monotonic()
            self._expire(now)
            if len(self._entries) >= self.CAPACITY:
                raise ExportIncomplete("audit_export_capacity")
            key = secrets.token_urlsafe(32)
            if key in self._entries:
                raise ExportIncomplete("audit_export_capacity")
            self._entries[key] = (context, now+self.TTL_SECONDS, cursor)
            return key

    def take(self, key, context):
        if (not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", key)
                or not isinstance(context, str) or not re.fullmatch(r"[0-9a-f]{64}", context)):
            raise ExportIncomplete("audit_export_cursor_invalid")
        with self._lock:
            self._expire(time.monotonic())
            entry = self._entries.pop(key, None)
            if entry is None or not hmac.compare_digest(entry[0], context):
                raise ExportIncomplete("audit_export_cursor_invalid")
            return entry[2]


def context_fingerprint(scope, authenticated_facts, filters):
    """Les faits proviennent du service authentifié, jamais de paramètres client."""
    data = [scope.instance, None if scope.coffers is None else sorted(scope.coffers), authenticated_facts, filters]
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


cursors = Cursors()
