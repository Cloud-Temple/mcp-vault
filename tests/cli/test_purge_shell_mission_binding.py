#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests CLI shell — mission-binding purge (issue #69).

Opération destructrice : on verrouille le comportement FAIL-CLOSE du shell (finding revue
Codex round 3, aligné sur token purge-revoked / #50) :
- --older-than invalide ou incomplet → AUCUN appel réseau (pas de purge) ;
- un dry-run en échec → la purge effective n'est JAMAIS déclenchée ;
- --yes n'exécute la purge qu'APRÈS un dry-run réussi ;
- sans --yes → dry-run seulement, jamais de suppression.

On intercepte httpx.AsyncClient et on inspecte les POST réellement émis.
"""

import os
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

_scripts = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
if _scripts not in sys.path:
    sys.path.insert(0, _scripts)

from cli.shell import cmd_mission_binding


class _Resp:
    def __init__(self, data):
        self._d = data

    def json(self):
        return self._d


class _FakeHttp:
    """Faux httpx.AsyncClient : enregistre chaque POST et débite une file de réponses."""
    def __init__(self, queue):
        self._queue = list(queue)
        self.posts = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, headers=None, json=None):
        self.posts.append(json)
        return _Resp(self._queue.pop(0) if self._queue else {"status": "error", "message": "no response"})


def _client():
    return SimpleNamespace(base_url="http://vault.test", token="tok")


def _run(args, queue):
    fake = _FakeHttp(queue)
    with patch("httpx.AsyncClient", return_value=fake):
        import asyncio
        asyncio.run(cmd_mission_binding(_client(), args, json_output=True))
    return fake


def test_shell_purge_older_than_non_entier_ne_poste_rien():
    fake = _run("purge --older-than abc --yes", queue=[])
    assert fake.posts == []  # fail-close : aucune requête (ni dry-run ni purge)


def test_shell_purge_older_than_eof_ne_poste_rien():
    fake = _run("purge --older-than", queue=[])  # --older-than en fin de ligne (EOF)
    assert fake.posts == []


def test_shell_purge_dry_run_en_echec_pas_de_purge_effective():
    fake = _run("purge --yes", queue=[{"status": "error", "message": "boom"}])
    assert len(fake.posts) == 1  # seul le dry-run a été tenté
    assert fake.posts[0]["dry_run"] is True  # jamais de POST dry_run=False


def test_shell_purge_yes_execute_apres_dry_run_ok():
    fake = _run("purge --yes", queue=[
        {"status": "ok", "count": 2, "older_than_days": 30, "candidates": []},
        {"status": "ok", "count": 2, "older_than_days": 30, "purged": []},
    ])
    assert len(fake.posts) == 2
    assert fake.posts[0]["dry_run"] is True
    assert fake.posts[1]["dry_run"] is False  # purge effective APRÈS dry-run réussi


def test_shell_purge_sans_yes_dry_run_seulement():
    fake = _run("purge", queue=[
        {"status": "ok", "count": 2, "older_than_days": 30, "candidates": []},
    ])
    assert len(fake.posts) == 1
    assert fake.posts[0]["dry_run"] is True  # aucune purge sans --yes


def test_shell_purge_older_than_valide_propage_la_retention():
    fake = _run("purge --older-than 7 --yes", queue=[
        {"status": "ok", "count": 1, "older_than_days": 7, "candidates": []},
        {"status": "ok", "count": 1, "older_than_days": 7, "purged": []},
    ])
    assert fake.posts[0]["older_than_days"] == 7
    assert fake.posts[1]["older_than_days"] == 7 and fake.posts[1]["dry_run"] is False
