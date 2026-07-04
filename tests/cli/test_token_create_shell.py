#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests CLI shell — token create --expires (issue #65).

On verrouille le comportement FAIL-CLOSE du shell face à un --expires invalide :
- non-entier / négatif / hors borne / valeur manquante → AUCUN POST (pas de création) ;
- 0 (illimité explicite) et valeur bornée valide → POST avec expires_in_days correct.

On intercepte httpx.AsyncClient et on inspecte les POST réellement émis (approche identique
à test_purge_shell_mission_binding.py).
"""

import os
import sys
from types import SimpleNamespace
from unittest.mock import patch

_scripts = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
if _scripts not in sys.path:
    sys.path.insert(0, _scripts)

from cli.shell import cmd_token


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
        return _Resp(self._queue.pop(0) if self._queue else {"status": "ok"})


def _client():
    return SimpleNamespace(base_url="http://vault.test", token="tok")


def _run(args, queue):
    fake = _FakeHttp(queue)
    with patch("httpx.AsyncClient", return_value=fake):
        import asyncio
        asyncio.run(cmd_token(_client(), args, json_output=True))
    return fake


_CREATED = {"status": "created", "hash": "abc123def456", "expires_at": None, "client_name": "c"}


def test_shell_create_expires_non_entier_ne_poste_rien():
    fake = _run("create c --expires abc", queue=[])
    assert fake.posts == []  # fail-close : aucune création


def test_shell_create_expires_negatif_ne_poste_rien():
    fake = _run("create c --expires -1", queue=[])
    assert fake.posts == []


def test_shell_create_expires_hors_borne_ne_poste_rien():
    fake = _run("create c --expires 36501", queue=[])
    assert fake.posts == []


def test_shell_create_expires_valeur_manquante_ne_poste_rien():
    fake = _run("create c --expires", queue=[])  # --expires en fin de ligne (EOF)
    assert fake.posts == []


def test_shell_create_expires_zero_illimite_poste():
    fake = _run("create c --expires 0", queue=[_CREATED])
    assert len(fake.posts) == 1
    assert fake.posts[0]["expires_in_days"] == 0  # 0 = jamais, transmis tel quel


def test_shell_create_expires_borne_valide_poste():
    fake = _run("create c --expires 30", queue=[_CREATED])
    assert len(fake.posts) == 1
    assert fake.posts[0]["expires_in_days"] == 30


def test_shell_create_sans_expires_defaut_90():
    fake = _run("create c", queue=[_CREATED])
    assert len(fake.posts) == 1
    assert fake.posts[0]["expires_in_days"] == 90  # défaut sûr
