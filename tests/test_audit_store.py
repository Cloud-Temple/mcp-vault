#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests unitaires — AuditStore (audit.py).

Couvre :
- écriture réussie : write_errors == 0, entrée dans le ring buffer
- écriture échouée : write_errors incrémenté, stderr renseigné, ring buffer intact
- get_stats() zero-case : write_errors présent même buffer vide
- compteur cumulatif : N échecs → write_errors == N
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from mcp_vault.audit import AuditStore


def _make_entry_kwargs():
    return dict(
        tool_name="secret_read",
        status="ok",
        vault_id="v1",
        detail="test",
        duration_ms=1.0,
        client_name="test-client",
    )


# ── Chemin valide : écriture réussie ─────────────────────────────────────────

def test_log_valid_path_no_write_errors(tmp_path):
    """Écriture réussie → write_errors == 0, entrée dans le ring buffer."""
    store = AuditStore(tmp_path / "audit.jsonl")
    store.log(**_make_entry_kwargs())

    assert store.get_stats()["write_errors"] == 0
    assert store.count() == 1


# ── Chemin invalide : écriture échouée ───────────────────────────────────────

def test_log_unwritable_path_increments_write_errors(tmp_path, capsys):
    """
    Écriture impossible → write_errors == 1, stderr renseigné, ring buffer intact.

    Ce test est RED sur le code original (KeyError : la clé 'write_errors' n'existe pas)
    et GREEN après le fix.
    """
    store = AuditStore(tmp_path / "missing_dir" / "audit.jsonl")
    store.log(**_make_entry_kwargs())

    stats = store.get_stats()
    assert stats["write_errors"] == 1
    assert store.count() == 1, "le ring buffer doit rester intact même si l'écriture disque échoue"

    captured = capsys.readouterr()
    assert "AuditStore write error" in captured.err
    assert str(tmp_path / "missing_dir" / "audit.jsonl") in captured.err


def test_log_unwritable_path_stderr_contains_exception_type(tmp_path, capsys):
    """Le message stderr inclut le type d'exception pour le diagnostic."""
    store = AuditStore(tmp_path / "missing_dir" / "audit.jsonl")
    store.log(**_make_entry_kwargs())

    captured = capsys.readouterr()
    assert "FileNotFoundError" in captured.err or "NotADirectoryError" in captured.err or "OSError" in captured.err


# ── Compteur cumulatif ────────────────────────────────────────────────────────

def test_log_write_errors_cumulative(tmp_path):
    """N appels échoués → write_errors == N."""
    store = AuditStore(tmp_path / "missing_dir" / "audit.jsonl")
    for _ in range(3):
        store.log(**_make_entry_kwargs())

    assert store.get_stats()["write_errors"] == 3
    assert store.count() == 3


# ── get_stats() zero-case ─────────────────────────────────────────────────────

def test_get_stats_zero_buffer_has_write_errors_key(tmp_path):
    """get_stats() avec buffer vide doit tout de même exposer write_errors."""
    store = AuditStore(tmp_path / "audit.jsonl")
    stats = store.get_stats()

    assert "write_errors" in stats
    assert stats["write_errors"] == 0


# ── Pas de faux positif sur chemin valide ─────────────────────────────────────

def test_log_valid_path_write_errors_absent_from_error_count(tmp_path):
    """Plusieurs écritures réussies : write_errors reste à zéro."""
    store = AuditStore(tmp_path / "audit.jsonl")
    for _ in range(5):
        store.log(**_make_entry_kwargs())

    assert store.get_stats()["write_errors"] == 0
    assert store.count() == 5
