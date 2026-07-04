#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Wrapper pytest du test de contrat frontend (issue #65).

Le bug initial de #65 était FRONTEND (`parseInt(v) || 90` écrasait "0" en 90). Une simple
« revue manuelle » serait trop faible. On exécute donc pour de vrai le contrat de
static/js/expires.js sous Node (tests/js/expires_contract.test.js).

Skip propre si `node` est absent de l'environnement — l'assertion réelle tourne partout où
node existe (poste dev + CI disposant de node). Ce n'est PAS un test de complaisance : quand
il tourne, il échoue si le contrat de parsing (coercition float/texte, "0" = jamais) régresse.
"""
import os
import shutil
import subprocess

import pytest

_NODE = shutil.which("node")
_TEST_JS = os.path.join(os.path.dirname(__file__), "js", "expires_contract.test.js")


@pytest.mark.skipif(_NODE is None, reason="node absent : contrat frontend non exécutable ici")
def test_frontend_expires_contract():
    result = subprocess.run([_NODE, _TEST_JS], capture_output=True, text=True)
    assert result.returncode == 0, (
        "Contrat frontend parseExpiresInDays violé :\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
