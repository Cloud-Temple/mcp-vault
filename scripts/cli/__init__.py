# -*- coding: utf-8 -*-
"""
Configuration globale du CLI — MCP Vault.

Variables d'environnement :
    MCP_URL   — URL du serveur MCP (défaut: http://localhost:8082)
    MCP_TOKEN — Token d'authentification
    ADMIN_BOOTSTRAP_KEY — Clé admin (fallback si MCP_TOKEN non défini)

Charge automatiquement le fichier .env du projet (python-dotenv).
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Charger le .env du projet (remonte depuis scripts/cli/ vers la racine)
_project_root = Path(__file__).resolve().parent.parent.parent
_env_file = _project_root / ".env"
if _env_file.exists():
    load_dotenv(_env_file)

BASE_URL = os.environ.get("MCP_URL", "http://localhost:8082")
TOKEN = os.environ.get("MCP_TOKEN", os.environ.get("ADMIN_BOOTSTRAP_KEY", ""))
