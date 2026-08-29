# -*- coding: utf-8 -*-
"""Contrats mécaniques de la migration vers le SDK MCP Python v2."""

import ast
import importlib.metadata
import inspect
from pathlib import Path

from packaging.version import Version


ROOT = Path(__file__).resolve().parent.parent
EXCLUDED_SCAN_ROOTS = {".git", ".venv", "venv", "node_modules"}
FORBIDDEN_V1_NAMES = {
    "fastmcp",
    "FastMCP",
    "streamablehttp_client",
    "create_connected_server_and_client_session",
}
FORBIDDEN_V1_ATTRS = {
    "_tool_manager",
    "inputSchema",
    "isError",
    "_received_notification",
}


def _v1_sdk_violations(label: str, source: str) -> list[str]:
    tree = ast.parse(source, filename=label)
    violations = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("mcp.server.fastmcp"):
                    violations.append(f"{label}:{node.lineno}: {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                target = f"{module}.{alias.name}" if module else alias.name
                if (target.startswith("mcp.server.fastmcp")
                        or alias.name in FORBIDDEN_V1_NAMES):
                    violations.append(f"{label}:{node.lineno}: {target}")
        elif isinstance(node, ast.Name) and node.id in FORBIDDEN_V1_NAMES:
            violations.append(f"{label}:{node.lineno}: {node.id}")
        elif isinstance(node, ast.Attribute) and node.attr in (
            FORBIDDEN_V1_ATTRS | FORBIDDEN_V1_NAMES
        ):
            violations.append(f"{label}:{node.lineno}: .{node.attr}")
    return violations


def test_installed_sdk_exposes_the_v2_public_api():
    from mcp import Client
    from mcp.server import MCPServer

    installed = Version(importlib.metadata.version("mcp"))
    assert installed.major == 2, installed
    assert Client is not None
    assert MCPServer is not None


def test_server_attaches_security_and_stateless_mode_at_the_http_boundary():
    from mcp_vault import server

    constructor = inspect.signature(server.MCPServer)
    app_factory = inspect.signature(server.MCPServer.streamable_http_app)
    assert "transport_security" not in constructor.parameters
    assert "transport_security" in app_factory.parameters
    assert "stateless_http" in app_factory.parameters

    source = inspect.getsource(server.create_app)
    assert "stateless_http=True" in source
    assert "transport_security=_build_transport_security()" in source


def test_no_executable_code_uses_removed_or_private_v1_sdk_apis():
    """Balayage de classe, pas liste de fichiers vouée à devenir incomplète."""
    legacy_probe = ROOT / "scripts/verify_mcp_legacy_v1.py"
    assert legacy_probe.is_file()
    violations = []
    for path in ROOT.rglob("*.py"):
        relative = path.relative_to(ROOT)
        if relative.parts[0] in EXCLUDED_SCAN_ROOTS or path == legacy_probe:
            continue
        violations.extend(_v1_sdk_violations(
            str(relative), path.read_text(encoding="utf-8"),
        ))
    assert violations == [], violations


def test_v1_sdk_guard_catches_submodule_import_aliases():
    evasions = (
        "from mcp.server import fastmcp as fm\nfm.FastMCP('vault')\n",
        "from mcp.server.fastmcp import FastMCP as Legacy\nLegacy('vault')\n",
        "from mcp import server as sdk_server\nsdk_server.fastmcp.FastMCP('vault')\n",
    )
    for source in evasions:
        assert _v1_sdk_violations("reviewer_escape.py", source), source


def test_vault_does_not_feed_or_persist_the_sdk_subscription_bus():
    """Le capability SDK reste inerte sans ressource, publication ni replay."""
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (ROOT / "src").rglob("*.py")
    )
    assert "event_store=" not in source
    assert "@mcp.subscribe" not in source
    assert "SubscriptionBus" not in source
    assert ".publish(" not in source
