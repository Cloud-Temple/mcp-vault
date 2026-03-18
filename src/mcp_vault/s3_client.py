# -*- coding: utf-8 -*-
"""
Client S3 Dell ECS — Configuration HYBRIDE SigV2/SigV4.

Dell ECS (ViPR/1.0) Cloud Temple nécessite :
    - SigV2 pour les opérations de données (PUT/GET/DELETE)
    - SigV4 pour les opérations métadonnées (HEAD/LIST)

Ce module fournit les deux clients pré-configurés.
"""

import logging
from typing import Optional

import boto3
from botocore.config import Config

from .config import get_settings

logger = logging.getLogger("mcp-vault.s3")

# =============================================================================
# Singleton clients
# =============================================================================

_client_v2: Optional[object] = None  # PUT/GET/DELETE (données)
_client_v4: Optional[object] = None  # HEAD/LIST (métadonnées)


def get_s3_data_client():
    """
    Client S3 SigV2 pour opérations sur les données.

    Utilisé pour : PUT, GET, DELETE objects.
    """
    global _client_v2
    if _client_v2 is None:
        settings = get_settings()
        config_v2 = Config(
            region_name=settings.s3_region_name,
            signature_version="s3",  # SigV2 legacy — requis par Dell ECS
            s3={"addressing_style": "path"},
            retries={"max_attempts": 3, "mode": "adaptive"},
        )
        _client_v2 = boto3.client(
            "s3",
            endpoint_url=settings.s3_endpoint_url,
            aws_access_key_id=settings.s3_access_key_id,
            aws_secret_access_key=settings.s3_secret_access_key,
            config=config_v2,
        )
        logger.debug("S3 data client (SigV2) initialisé")
    return _client_v2


def get_s3_meta_client():
    """
    Client S3 SigV4 pour opérations métadonnées.

    Utilisé pour : HEAD bucket, LIST objects.
    """
    global _client_v4
    if _client_v4 is None:
        settings = get_settings()
        config_v4 = Config(
            region_name=settings.s3_region_name,
            signature_version="s3v4",
            s3={"addressing_style": "path", "payload_signing_enabled": False},
            retries={"max_attempts": 3, "mode": "adaptive"},
        )
        _client_v4 = boto3.client(
            "s3",
            endpoint_url=settings.s3_endpoint_url,
            aws_access_key_id=settings.s3_access_key_id,
            aws_secret_access_key=settings.s3_secret_access_key,
            config=config_v4,
        )
        logger.debug("S3 meta client (SigV4) initialisé")
    return _client_v4


def reset_clients():
    """Reset les clients (utile pour les tests)."""
    global _client_v2, _client_v4
    _client_v2 = None
    _client_v4 = None


def create_s3_clients(endpoint_url: str, access_key: str, secret_key: str,
                      region: str = "fr1") -> tuple:
    """
    Crée une paire de clients S3 (data SigV2 + meta SigV4).

    Utile pour les tests ou quand on veut des clients non-singleton.

    Returns:
        (data_client, meta_client)
    """
    config_v2 = Config(
        region_name=region,
        signature_version="s3",
        s3={"addressing_style": "path"},
        retries={"max_attempts": 3, "mode": "adaptive"},
    )
    config_v4 = Config(
        region_name=region,
        signature_version="s3v4",
        s3={"addressing_style": "path", "payload_signing_enabled": False},
        retries={"max_attempts": 3, "mode": "adaptive"},
    )

    data_client = boto3.client(
        "s3", endpoint_url=endpoint_url,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        config=config_v2,
    )
    meta_client = boto3.client(
        "s3", endpoint_url=endpoint_url,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        config=config_v4,
    )

    return data_client, meta_client
