#!/bin/sh
set -eu

# Par défaut MCP_URL vise le WAF local (:8085), jamais le port interne :8030.
probe_dir=$(mktemp -d /tmp/mcp-vault-legacy-v1.XXXXXX)
trap 'rm -rf -- "$probe_dir"' EXIT HUP INT TERM

python3 -m venv "$probe_dir/venv"
"$probe_dir/venv/bin/pip" install --disable-pip-version-check -q "mcp==1.26.0"
"$probe_dir/venv/bin/python" "$(dirname "$0")/verify_mcp_legacy_v1.py"
