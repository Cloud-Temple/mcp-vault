# -*- coding: utf-8 -*-
"""Configuration du service MCP Vault via pydantic-settings."""

from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Configuration chargée depuis les variables d'env / .env."""

    # --- Serveur MCP ---
    mcp_server_name: str = "mcp-vault"
    mcp_server_host: str = "0.0.0.0"
    mcp_server_port: int = 8030
    mcp_server_debug: bool = False

    # --- Auth ---
    admin_bootstrap_key: str = "change_me_in_production"

    # --- S3 Token Store (optionnel — si vide, tokens en mémoire uniquement) ---
    s3_endpoint_url: str = ""
    s3_access_key_id: str = ""
    s3_secret_access_key: str = ""
    s3_bucket_name: str = ""
    s3_region_name: str = "fr1"

    # --- OpenBao ---
    openbao_addr: str = "http://127.0.0.1:8200"
    openbao_shares: int = 1
    openbao_threshold: int = 1
    openbao_data_dir: str = "/openbao/file"
    openbao_config_dir: str = "/openbao/config"

    # --- S3 Vault Storage Sync ---
    vault_s3_prefix: str = "_storage"
    vault_s3_sync_interval: int = 60

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


@lru_cache
def get_settings() -> Settings:
    """Singleton pour la config (cachée en mémoire)."""
    return Settings()
