#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Wrapper pytest du contrat frontend SSH JIT opérateur."""

import os
import shutil
import subprocess

import pytest


_NODE = shutil.which("node")
_TEST_JS = os.path.join(
    os.path.dirname(__file__), "js", "operator_ssh_jit_contract.test.js"
)


@pytest.mark.skipif(_NODE is None, reason="node absent : contrat frontend non exécutable ici")
def test_operator_ssh_jit_frontend_contract():
    result = subprocess.run(
        [_NODE, _TEST_JS], capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, (
        "Le contrat frontend SSH JIT a échoué\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "operator SSH JIT UI contract: OK" in result.stdout
