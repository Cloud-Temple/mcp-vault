# -*- coding: utf-8 -*-
"""
Audit Store — Journal d'audit MCP Vault.

Enregistre toutes les opérations MCP dans :
- Ring buffer mémoire (5000 entrées, accès rapide)
- Fichier JSONL persistant (/openbao/logs/audit-mcp.jsonl, synced S3)

Chaque entrée contient :
- timestamp, client_name, tool_name, vault_id, status, detail, duration_ms

Usage :
    init_audit_store()      → Au démarrage (charge les dernières entrées)
    log_audit(...)          → Après chaque opération MCP
    get_audit_entries(...)  → Lecture avec filtres
"""

import collections
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import get_settings

# =============================================================================
# Audit Store singleton
# =============================================================================

_audit_store = None


def get_audit_store() -> Optional["AuditStore"]:
    """Retourne l'Audit Store (None si non initialisé)."""
    return _audit_store


def init_audit_store():
    """Initialise l'Audit Store au démarrage."""
    global _audit_store
    settings = get_settings()
    log_dir = Path(settings.openbao_data_dir).parent / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    _audit_store = AuditStore(log_dir / "audit-mcp.jsonl")
    _audit_store.load_recent()
    print(f"📋 Audit Store initialisé ({_audit_store.count()} entrées chargées)", file=sys.stderr)


def log_audit(tool_name: str, status: str, vault_id: str = "",
              detail: str = "", duration_ms: float = 0, client_name: str = ""):
    """
    Enregistre un événement d'audit.

    Args:
        tool_name: Nom de l'outil MCP (ex: "vault_create", "secret_read")
        status: Résultat ("ok", "created", "deleted", "error", "updated")
        vault_id: Vault concerné (vide si pas applicable)
        detail: Détail additionnel (ex: path du secret, message d'erreur)
        duration_ms: Durée de l'opération en ms
        client_name: Nom du client (auto-détecté si vide)
    """
    store = get_audit_store()
    if not store:
        return

    if not client_name:
        try:
            from .auth.context import get_current_client_name
            client_name = get_current_client_name()
        except Exception:
            client_name = "unknown"

    store.log(tool_name, status, vault_id, detail, duration_ms, client_name)


# =============================================================================
# AuditStore — Ring buffer + fichier JSONL
# =============================================================================

class AuditStore:
    """
    Journal d'audit MCP avec ring buffer mémoire + fichier JSONL persistant.

    - Ring buffer : 5000 entrées en mémoire (accès rapide, filtrage)
    - Fichier JSONL : persistant sur disque (synced S3 avec le volume OpenBao)
    - Chargement au startup : lit les dernières entrées du fichier
    """

    BUFFER_SIZE = 5000
    MAX_DETAIL_LEN = 500  # Tronquer les détails trop longs

    def __init__(self, jsonl_path: Path):
        self._buffer = collections.deque(maxlen=self.BUFFER_SIZE)
        self._jsonl_path = jsonl_path
        self._file = None

    def load_recent(self):
        """Charge les dernières entrées depuis le fichier JSONL."""
        if not self._jsonl_path.exists():
            return

        try:
            with open(self._jsonl_path, "r") as f:
                lines = f.readlines()
                # Charger les dernières BUFFER_SIZE lignes
                for line in lines[-self.BUFFER_SIZE:]:
                    line = line.strip()
                    if line:
                        try:
                            entry = json.loads(line)
                            self._buffer.append(entry)
                        except json.JSONDecodeError:
                            pass
        except Exception as e:
            print(f"⚠️  Audit load: {e}", file=sys.stderr)

    def log(self, tool_name: str, status: str, vault_id: str = "",
            detail: str = "", duration_ms: float = 0, client_name: str = ""):
        """Enregistre un événement d'audit."""
        now = datetime.now(timezone.utc)

        # Tronquer le détail si trop long
        if len(detail) > self.MAX_DETAIL_LEN:
            detail = detail[:self.MAX_DETAIL_LEN] + "…"

        # Catégoriser l'opération
        category = _categorize_tool(tool_name)

        entry = {
            "ts": now.isoformat(),
            "client": client_name,
            "tool": tool_name,
            "category": category,
            "vault_id": vault_id,
            "status": status,
            "detail": detail,
            "duration_ms": round(duration_ms, 1),
        }

        # Ring buffer
        self._buffer.append(entry)

        # Fichier JSONL (append)
        try:
            with open(self._jsonl_path, "a") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass  # Ne pas bloquer l'opération si l'écriture audit échoue

    def count(self) -> int:
        """Nombre d'entrées dans le ring buffer."""
        return len(self._buffer)

    def get_entries(self, limit: int = 100, client: str = "",
                    vault_id: str = "", tool: str = "",
                    category: str = "", status: str = "",
                    since: str = "") -> list:
        """
        Retourne les entrées d'audit filtrées (plus récentes en premier).

        Args:
            limit: Nombre max d'entrées (défaut 100, max 1000)
            client: Filtrer par client_name
            vault_id: Filtrer par vault_id
            tool: Filtrer par tool_name (supporte wildcards via startswith)
            category: Filtrer par catégorie (system, vault, secret, ssh, policy, token)
            status: Filtrer par status (ok, error, created, deleted, updated)
            since: Entrées après cette date ISO 8601
        """
        limit = min(limit, 1000)
        results = []

        for entry in reversed(self._buffer):
            if len(results) >= limit:
                break

            # Filtres
            if client and entry.get("client") != client:
                continue
            if vault_id and entry.get("vault_id") != vault_id:
                continue
            if tool:
                if "*" in tool:
                    prefix = tool.replace("*", "")
                    if not entry.get("tool", "").startswith(prefix):
                        continue
                elif entry.get("tool") != tool:
                    continue
            if category and entry.get("category") != category:
                continue
            if status and entry.get("status") != status:
                continue
            if since:
                if entry.get("ts", "") < since:
                    continue

            results.append(entry)

        return results

    def get_stats(self) -> dict:
        """Statistiques d'audit (pour le dashboard)."""
        total = len(self._buffer)
        if total == 0:
            return {"total": 0, "by_category": {}, "by_status": {}, "by_client": {}}

        by_category = {}
        by_status = {}
        by_client = {}

        for entry in self._buffer:
            cat = entry.get("category", "other")
            by_category[cat] = by_category.get(cat, 0) + 1

            st = entry.get("status", "?")
            by_status[st] = by_status.get(st, 0) + 1

            cl = entry.get("client", "?")
            by_client[cl] = by_client.get(cl, 0) + 1

        return {
            "total": total,
            "by_category": dict(sorted(by_category.items(), key=lambda x: -x[1])),
            "by_status": dict(sorted(by_status.items(), key=lambda x: -x[1])),
            "by_client": dict(sorted(by_client.items(), key=lambda x: -x[1])),
        }


# =============================================================================
# Helpers
# =============================================================================

def _categorize_tool(tool_name: str) -> str:
    """Catégorise un outil MCP pour le filtrage et l'affichage."""
    if tool_name.startswith("system_"):
        return "system"
    if tool_name.startswith("vault_"):
        return "vault"
    if tool_name.startswith("secret_"):
        return "secret"
    if tool_name.startswith("ssh_"):
        return "ssh"
    if tool_name.startswith("policy_"):
        return "policy"
    if tool_name.startswith("token_"):
        return "token"
    if tool_name.startswith("audit_"):
        return "audit"
    return "other"
