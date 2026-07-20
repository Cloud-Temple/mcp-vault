#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Wrapper pytest du test de contrat frontend de masquage des secrets (issue
agentic-platform, console Admin, 2026-07-20).

Le bug initial était FRONTEND (toggleSecret() dans vaults.js injectait la valeur
brute des champs sensibles en clair dans le DOM, `isHidden` ne changeant qu'une
couleur). Une simple « revue manuelle » serait trop faible : on exécute donc pour
de vrai le contrat de static/js/vaults.js sous Node
(tests/js/secret_visibility_contract.test.js), y compris la fonction toggleSecret()
elle-même (via un faux DOM + un faux api() injectés), pas seulement les helpers purs.

Skip propre si `node` est absent de l'environnement — l'assertion réelle tourne
partout où node existe (poste dev + CI disposant de node). Ce n'est PAS un test de
complaisance : quand il tourne, il échoue si un champ sensible réapparaît en clair
dans le DOM, si la purge au repli régresse, ou si une réponse réseau tardive
repeuple une fiche déjà repliée (course confirmée en revue de plan Codex).
"""
import os
import shutil
import subprocess

import pytest

_NODE = shutil.which("node")
_TEST_JS = os.path.join(os.path.dirname(__file__), "js", "secret_visibility_contract.test.js")


@pytest.mark.skipif(_NODE is None, reason="node absent : contrat frontend non exécutable ici")
def test_frontend_secret_masking_contract():
    result = subprocess.run([_NODE, _TEST_JS], capture_output=True, text=True)
    assert result.returncode == 0, (
        "Contrat frontend de masquage des secrets violé :\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
