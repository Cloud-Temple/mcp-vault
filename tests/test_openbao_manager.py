#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests comportementaux pour openbao/manager.py.

Réécriture de la version initiale (pure recherche de chaînes dans le source)
vers des tests qui exercent réellement le comportement du code :
- start_openbao() ne lance pas Popen si OpenBao est déjà reachable
- start_openbao() redirige stdout/stderr vers des fichiers log (pas PIPE)

Ces tests échoueraient si le comportement était modifié, pas juste si les
chaînes littérales étaient retirées du code.
"""

import asyncio
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock

os.environ.setdefault("MCP_SERVER_NAME", "mcp-vault-test")
os.environ.setdefault("ADMIN_BOOTSTRAP_KEY", "Test-Bootstrap-Key-2026-Pour-Tests!!")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# hvac (dep Docker-only) est stubbé de façon DÉTERMINISTE et FAIL-CLOSE dans tests/conftest.py
# (issue #64). L'ancienne injection sys.modules au niveau module ici était le même anti-pattern
# que test_pki (fuite globale, ordre-dépendante) et est désormais inerte. Les tests ci-dessous
# qui exercent le manager patchent donc `hvac.Client` EXPLICITEMENT (le stub fail-close lève sinon).


def run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def test_manager_reuses_existing_openbao_instance():
    """
    start_openbao() ne doit pas lancer subprocess.Popen si _is_openbao_reachable()
    retourne True. Vérifie le comportement, pas la présence de chaînes dans le source.
    """
    from mcp_vault.openbao import manager as mgr

    mock_popen = MagicMock()

    with patch.object(mgr, "_is_openbao_reachable", new=AsyncMock(return_value=True)), \
         patch("hvac.Client", return_value=MagicMock()), \
         patch("subprocess.Popen", mock_popen):
        result = run(mgr.start_openbao())

    mock_popen.assert_not_called(), "Popen ne doit pas être appelé si OpenBao est déjà reachable"
    assert result is True, f"start_openbao doit retourner True si déjà reachable, obtenu {result}"
    print("  ✅ start_openbao réutilise l'instance existante (Popen non appelé)")


def test_manager_redirects_bao_logs_to_files():
    """
    Quand start_openbao() lance le processus, il doit rediriger stdout/stderr
    vers des fichiers (pas subprocess.PIPE), avec les noms *-stdout.log / *-stderr.log.
    Vérifie le comportement réel, pas la présence de chaînes dans le code.
    """
    from mcp_vault.openbao import manager as mgr

    captured_popen_kwargs = {}

    def fake_popen(cmd, stdout, stderr, **kwargs):
        captured_popen_kwargs["stdout"] = stdout
        captured_popen_kwargs["stderr"] = stderr
        proc = MagicMock()
        proc.poll.return_value = None  # process alive
        return proc

    call_count = 0

    async def reachable_after_start():
        nonlocal call_count
        call_count += 1
        return call_count > 1  # False la première fois, True ensuite

    # Fournir de vrais fichiers temporaires nommés pour les redirections
    import tempfile
    tmp_dir = tempfile.mkdtemp()
    stdout_path = Path(tmp_dir) / "openbao-stdout.log"
    stderr_path = Path(tmp_dir) / "openbao-stderr.log"

    def fake_log_paths():
        return stdout_path, stderr_path

    with patch.object(mgr, "_is_openbao_reachable", new=reachable_after_start), \
         patch("hvac.Client", return_value=MagicMock()), \
         patch("subprocess.Popen", side_effect=fake_popen), \
         patch("mcp_vault.openbao.config.generate_hcl_config", return_value="/tmp/fake.hcl"), \
         patch.object(mgr, "_openbao_log_paths", side_effect=fake_log_paths), \
         patch("asyncio.sleep", new=AsyncMock()):
        result = run(mgr.start_openbao())

    # Vérifier que stdout/stderr étaient des handles fichier (pas None ni PIPE)
    stdout = captured_popen_kwargs.get("stdout")
    stderr = captured_popen_kwargs.get("stderr")

    assert stdout is not None, "stdout doit être redirigé (pas None)"
    assert stderr is not None, "stderr doit être redirigé (pas None)"
    assert stdout != subprocess.PIPE, "stdout ne doit pas être PIPE (évite les deadlocks)"
    assert stderr != subprocess.PIPE, "stderr ne doit pas être PIPE"

    # Les handles doivent référencer des fichiers avec "stdout" / "stderr" dans le nom
    stdout_name = getattr(stdout, "name", str(stdout))
    stderr_name = getattr(stderr, "name", str(stderr))
    assert "stdout" in str(stdout_name).lower(), \
        f"Le handle stdout ne pointe pas vers un fichier *stdout*: {stdout_name}"
    assert "stderr" in str(stderr_name).lower(), \
        f"Le handle stderr ne pointe pas vers un fichier *stderr*: {stderr_name}"

    print("  ✅ start_openbao redirige stdout/stderr vers des fichiers log (pas PIPE)")


if __name__ == "__main__":
    tests = [test_manager_reuses_existing_openbao_instance,
             test_manager_redirects_bao_logs_to_files]
    passed = failed = 0
    print(f"\n🧪 Tests openbao/manager.py ({len(tests)} tests)\n")
    for t in tests:
        try:
            t(); passed += 1
        except Exception as e:
            import traceback
            print(f"  ❌ {t.__name__}: {e}")
            traceback.print_exc()
            failed += 1
    print(f"\n{'=' * 50}")
    print(f"  {'✅' if not failed else '❌'} {passed}/{passed+failed} tests passent")
    print(f"{'=' * 50}")
    sys.exit(0 if not failed else 1)
