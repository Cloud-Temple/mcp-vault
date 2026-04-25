#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, sys
from pathlib import Path
os.environ.setdefault("MCP_SERVER_NAME", "mcp-vault-test")
os.environ.setdefault("ADMIN_BOOTSTRAP_KEY", "test-bootstrap-key-for-unit-tests")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
def test_admin_api_imports_check_path_policy():
    source = Path("src/mcp_vault/admin/api.py").read_text()
    assert "check_path_policy" in source
def test_admin_api_read_secret_checks_path_policy():
    source = Path("src/mcp_vault/admin/api.py").read_text()
    assert 'path_err = check_path_policy(vault_id, secret_path)' in source
def test_admin_api_write_secret_checks_path_from_body():
    source = Path("src/mcp_vault/admin/api.py").read_text()
    assert 'path_err = check_path_policy(vault_id, data.get("path", "").strip())' in source
