# -*- coding: utf-8 -*-
"""
Chiffrement des clés unseal — Option C.

Chiffre/déchiffre les clés unseal OpenBao avec ADMIN_BOOTSTRAP_KEY.

Algorithme :
    - Dérivation : PBKDF2-HMAC-SHA256 (600 000 itérations)
    - Chiffrement : AES-256-GCM (authentifié)
    - Format binaire : salt(16B) || nonce(12B) || ciphertext || tag(16B)
    - Transport : base64 (pour stockage S3 en texte)

Invariant de sécurité :
    Les clés unseal ne sont JAMAIS écrites en clair sur le filesystem.
    Elles ne vivent qu'en mémoire pendant le runtime.
"""

import base64
import logging
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger("mcp-vault.crypto")

# Paramètres cryptographiques (alignés sur le DESIGN §8.0)
_PBKDF2_ITERATIONS = 600_000
_SALT_LENGTH = 16   # bytes
_NONCE_LENGTH = 12  # bytes (requis par AES-GCM)
_KEY_LENGTH = 32    # bytes (AES-256)


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """
    Dérive une clé AES-256 depuis une passphrase via PBKDF2-HMAC-SHA256.

    Args:
        passphrase: La clé source (ADMIN_BOOTSTRAP_KEY)
        salt: Sel aléatoire (16 bytes)

    Returns:
        Clé AES-256 de 32 bytes
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_LENGTH,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_with_bootstrap_key(plaintext: str, bootstrap_key: str) -> str:
    """
    Chiffre un texte avec ADMIN_BOOTSTRAP_KEY (AES-256-GCM + PBKDF2).

    Le format binaire résultant est :
        salt(16B) || nonce(12B) || ciphertext+tag

    Le tout est encodé en base64 pour le transport/stockage S3.

    Args:
        plaintext: Texte en clair à chiffrer (JSON des clés unseal)
        bootstrap_key: ADMIN_BOOTSTRAP_KEY (variable d'environnement)

    Returns:
        Chaîne base64 contenant salt + nonce + ciphertext + tag

    Raises:
        ValueError: Si la bootstrap_key est vide ou trop courte
    """
    if not bootstrap_key or len(bootstrap_key) < 16:
        raise ValueError(
            "ADMIN_BOOTSTRAP_KEY doit faire au moins 16 caractères "
            "(64+ recommandé en production)"
        )

    # Générer sel et nonce aléatoires (CSPRNG)
    salt = os.urandom(_SALT_LENGTH)
    nonce = os.urandom(_NONCE_LENGTH)

    # Dériver la clé AES-256
    key = _derive_key(bootstrap_key, salt)

    # Chiffrer (AES-256-GCM — le tag est automatiquement ajouté au ciphertext)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    # Assembler : salt || nonce || ciphertext+tag
    result = salt + nonce + ciphertext_with_tag

    logger.debug(
        f"Chiffrement OK — salt={len(salt)}B, nonce={len(nonce)}B, "
        f"ciphertext+tag={len(ciphertext_with_tag)}B"
    )
    return base64.b64encode(result).decode("ascii")


def decrypt_with_bootstrap_key(encrypted_b64: str, bootstrap_key: str) -> str:
    """
    Déchiffre un texte chiffré avec ADMIN_BOOTSTRAP_KEY (AES-256-GCM + PBKDF2).

    Attend le format : base64(salt(16B) || nonce(12B) || ciphertext+tag)

    Args:
        encrypted_b64: Chaîne base64 produite par encrypt_with_bootstrap_key()
        bootstrap_key: ADMIN_BOOTSTRAP_KEY (même clé que pour le chiffrement)

    Returns:
        Texte en clair (JSON des clés unseal)

    Raises:
        ValueError: Si la bootstrap_key est incorrecte ou les données corrompues
    """
    if not bootstrap_key:
        raise ValueError("ADMIN_BOOTSTRAP_KEY est requise pour le déchiffrement")

    try:
        raw = base64.b64decode(encrypted_b64)
    except Exception as e:
        raise ValueError(f"Données base64 invalides : {e}")

    # Vérifier la taille minimale : salt(16) + nonce(12) + tag(16) = 44 bytes minimum
    min_size = _SALT_LENGTH + _NONCE_LENGTH + 16  # 16 = tag GCM minimum
    if len(raw) < min_size:
        raise ValueError(
            f"Données chiffrées trop courtes ({len(raw)}B, minimum {min_size}B)"
        )

    # Extraire les composants
    salt = raw[:_SALT_LENGTH]
    nonce = raw[_SALT_LENGTH:_SALT_LENGTH + _NONCE_LENGTH]
    ciphertext_with_tag = raw[_SALT_LENGTH + _NONCE_LENGTH:]

    # Dériver la même clé
    key = _derive_key(bootstrap_key, salt)

    # Déchiffrer (lève InvalidTag si la clé est mauvaise ou données corrompues)
    try:
        aesgcm = AESGCM(key)
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    except Exception:
        raise ValueError(
            "Déchiffrement impossible — ADMIN_BOOTSTRAP_KEY incorrecte "
            "ou données corrompues"
        )

    logger.debug("Déchiffrement OK")
    return plaintext_bytes.decode("utf-8")
