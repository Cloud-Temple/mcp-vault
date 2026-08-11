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


def _build_config(region: str, signature_version: str, *,
                  connect_timeout: int, read_timeout: int, max_attempts: int,
                  payload_signing: bool = None) -> Config:
    """
    Fabrique UNIQUE de configuration botocore (issue #110, lot 1).

    Source unique des bornes réseau : tout client S3 du projet passe par ici,
    y compris `create_s3_clients()` — pas de profil divergent qui repartirait
    sans timeout.

    `total_max_attempts` (et NON `max_attempts`) : botocore interprète
    `max_attempts=N` comme N retries APRÈS la tentative initiale (soit N+1
    appels réseau). `total_max_attempts=N` borne le nombre TOTAL de tentatives,
    ce qui est la sémantique attendue d'un plafond de disponibilité.

    Mode "standard" (et non "adaptive") : déterministe pendant une panne —
    l'adaptatif ajoute une temporisation côté client, imprévisible pour un
    calcul de borne.
    """
    s3_opts = {"addressing_style": "path"}
    if payload_signing is not None:
        s3_opts["payload_signing_enabled"] = payload_signing
    return Config(
        region_name=region,
        signature_version=signature_version,
        s3=s3_opts,
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
        retries={"total_max_attempts": max_attempts, "mode": "standard"},
    )


def _config_from_settings(signature_version: str, *,
                          payload_signing: bool = None) -> Config:
    """Configuration bornée depuis les settings (jamais de valeur en dur)."""
    settings = get_settings()
    return _build_config(
        settings.s3_region_name, signature_version,
        connect_timeout=settings.s3_connect_timeout,
        read_timeout=settings.s3_read_timeout,
        max_attempts=settings.s3_max_attempts,
        payload_signing=payload_signing,
    )


def get_s3_data_client():
    """
    Client S3 SigV2 pour opérations sur les données.

    Utilisé pour : PUT, GET, DELETE objects.
    """
    global _client_v2
    if _client_v2 is None:
        settings = get_settings()
        config_v2 = _config_from_settings("s3")  # SigV2 legacy — requis par Dell ECS
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
        config_v4 = _config_from_settings("s3v4", payload_signing=False)
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
    Passe par la MÊME fabrique de configuration que les singletons (bornes
    réseau depuis les settings — issue #110) : aucun client du projet ne peut
    repartir avec les défauts botocore.

    Returns:
        (data_client, meta_client)
    """
    settings = get_settings()
    config_v2 = _build_config(
        region, "s3",
        connect_timeout=settings.s3_connect_timeout,
        read_timeout=settings.s3_read_timeout,
        max_attempts=settings.s3_max_attempts,
    )
    config_v4 = _build_config(
        region, "s3v4",
        connect_timeout=settings.s3_connect_timeout,
        read_timeout=settings.s3_read_timeout,
        max_attempts=settings.s3_max_attempts,
        payload_signing=False,
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
