# -*- coding: utf-8 -*-
"""
Wrapper pytest du contrat frontend de login face à un coffre dégradé (#103).

Exécute `static/js/api.js` sous Node (tests/js/health_login_contract.test.js).

Ce n'est PAS un test de complaisance : depuis #103, `/admin/api/health` répond
`degraded` quand la disponibilité ne l'est pas. La garde d'origine
(`health.status !== 'ok'`) aurait enfermé l'exploitant DEHORS pendant
l'incident — au moment précis où la console sert à diagnostiquer et à desceller.
Le contrat vérifie aussi que les valeurs de refus le restent, sans coercition.
"""

import os
import shutil
import subprocess

import pytest

_NODE = shutil.which("node")
_TEST_JS = os.path.join(os.path.dirname(__file__), "js",
                        "health_login_contract.test.js")


@pytest.mark.skipif(_NODE is None,
                    reason="node absent : contrat frontend non exécutable ici")
def test_frontend_health_login_contract():
    result = subprocess.run([_NODE, _TEST_JS], capture_output=True, text=True)
    assert result.returncode == 0, (
        "Contrat frontend healthAllowsLogin violé :\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
