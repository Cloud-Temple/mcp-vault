"""Wrapper pytest du contrat de la page PKI de la console (#217).

Le contrat (tests/js/pki_console_contract.test.js) exécute les VRAIS gestionnaires
de static/js/pki.js sous Node. Il saute ici si `node` est absent (image de test) ;
en CI, le job `image-and-tests` l'exécute sur le runner, où Node est présent, et
l'échec y est bloquant : un vert ne vient pas d'un test sauté.
"""
import os
import shutil
import subprocess

import pytest

_NODE = shutil.which("node")
_TEST_JS = os.path.join(os.path.dirname(__file__), "js", "pki_console_contract.test.js")


@pytest.mark.skipif(_NODE is None, reason="node absent : contrat console non exécutable ici")
def test_contrat_console_pki():
    result = subprocess.run([_NODE, _TEST_JS], capture_output=True, text=True)
    assert result.returncode == 0, f"stdout: {result.stdout}\nstderr: {result.stderr}"
    assert "pki_console_contract : OK" in result.stdout
