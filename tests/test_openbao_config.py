#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, sys
os.environ.setdefault("MCP_SERVER_NAME", "mcp-vault-test")
os.environ.setdefault("ADMIN_BOOTSTRAP_KEY", "test-bootstrap-key-for-unit-tests")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from mcp_vault.openbao.config import _compute_openbao_listen_addr
def test_compute_openbao_listen_addr_default_port():
    assert _compute_openbao_listen_addr("http://127.0.0.1:8200") == "127.0.0.1:8200"
def test_compute_openbao_listen_addr_custom_port():
    assert _compute_openbao_listen_addr("http://127.0.0.1:18200") == "127.0.0.1:18200"
