#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, sys
from pathlib import Path
os.environ.setdefault("MCP_SERVER_NAME", "mcp-vault-test")
os.environ.setdefault("ADMIN_BOOTSTRAP_KEY", "test-bootstrap-key-for-unit-tests")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
def test_manager_redirects_bao_logs_to_files():
    source = Path("src/mcp_vault/openbao/manager.py").read_text()
    assert 'openbao-stdout.log' in source
    assert 'openbao-stderr.log' in source
def test_manager_reuses_existing_openbao_instance():
    source = Path("src/mcp_vault/openbao/manager.py").read_text()
    assert 'if await _is_openbao_reachable():' in source
