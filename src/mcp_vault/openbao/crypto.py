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

Durcissement mémoire :
    Les clés dérivées sont stockées en bytearray (mutable) et effacées
    (zero-fill) explicitement après usage pour limiter la fenêtre
    d'exposition en RAM.
"""

import base64
import logging
import os
import string

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger("mcp-vault.crypto")

# Paramètres cryptographiques (alignés sur le DESIGN §8.0)
_PBKDF2_ITERATIONS = 600_000
_SALT_LENGTH = 16   # bytes
_NONCE_LENGTH = 12  # bytes (requis par AES-GCM)
_KEY_LENGTH = 32    # bytes (AES-256)

# Exigences minimales pour la bootstrap key
_MIN_KEY_LENGTH = 32
_MIN_CHAR_CLASSES = 3  # sur 4 classes possibles (maj, min, chiffres, symboles)


def _zero_fill(buf: bytearray) -> None:
    """
    Efface le contenu d'un bytearray en le remplissant de zéros.

    C'est la meilleure approche possible en Python pur pour limiter
    la fenêtre d'exposition des clés en mémoire. En CPython, le buffer
    sous-jacent est directement modifié en place (pas de copie).
    """
    for i in range(len(buf)):
        buf[i] = 0


def validate_bootstrap_key(key: str) -> tuple[bool, str]:
    """
    Valide la complexité et l'entropie de la bootstrap key.

    Exigences :
        - Longueur minimale : 32 caractères (256+ bits effectifs via PBKDF2)
        - Au moins 3 classes de caractères sur 4 :
          majuscules, minuscules, chiffres, symboles
        - Pas un pattern faible connu (répétition, séquence)

    Args:
        key: La clé à valider

    Returns:
        Tuple (is_valid, message) — True si OK, sinon message d'erreur
    """
    if not key:
        return False, "ADMIN_BOOTSTRAP_KEY est vide"

    if key == "change_me_in_production":
        return False, (
            "ADMIN_BOOTSTRAP_KEY est la valeur par défaut "
            "'change_me_in_production' — elle DOIT être changée"
        )

    if len(key) < _MIN_KEY_LENGTH:
        return False, (
            f"ADMIN_BOOTSTRAP_KEY trop courte ({len(key)} chars, "
            f"minimum {_MIN_KEY_LENGTH}). "
            f"Générez une clé avec : python -c \"import secrets; print(secrets.token_urlsafe(48))\""
        )

    # Compter les classes de caractères présentes
    has_upper = any(c in string.ascii_uppercase for c in key)
    has_lower = any(c in string.ascii_lowercase for c in key)
    has_digit = any(c in string.digits for c in key)
    has_symbol = any(c not in string.ascii_letters + string.digits for c in key)
    char_classes = sum([has_upper, has_lower, has_digit, has_symbol])

    if char_classes < _MIN_CHAR_CLASSES:
        return False, (
            f"ADMIN_BOOTSTRAP_KEY manque de diversité ({char_classes}/4 classes). "
            f"Utilisez un mix de majuscules, minuscules, chiffres et symboles. "
            f"Générez une clé avec : python -c \"import secrets; print(secrets.token_urlsafe(48))\""
        )

    # Détecter les patterns faibles (répétition d'un seul caractère)
    if len(set(key)) < len(key) // 4:
        return False, (
            "ADMIN_BOOTSTRAP_KEY contient trop de répétitions — "
            "utilisez une clé aléatoire (CSPRNG)"
        )

    return True, "OK"


def _derive_key(passphrase: str, salt: bytes) -> bytearray:
    """
    Dérive une clé AES-256 depuis une passphrase via PBKDF2-HMAC-SHA256.

    Retourne un bytearray (mutable) pour permettre le zeroing après usage.

    Args:
        passphrase: La clé source (ADMIN_BOOTSTRAP_KEY)
        salt: Sel aléatoire (16 bytes)

    Returns:
        Clé AES-256 de 32 bytes (bytearray, mutable pour zeroing)
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_LENGTH,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    # PBKDF2 retourne bytes (immuable), on copie dans un bytearray (mutable)
    derived = kdf.derive(passphrase.encode("utf-8"))
    return bytearray(derived)


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
        ValueError: Si la bootstrap_key est invalide
    """
    # Validation stricte de la bootstrap key
    is_valid, msg = validate_bootstrap_key(bootstrap_key)
    if not is_valid:
        raise ValueError(msg)

    # Générer sel et nonce aléatoires (CSPRNG)
    salt = os.urandom(_SALT_LENGTH)
    nonce = os.urandom(_NONCE_LENGTH)

    # Dériver la clé AES-256 (bytearray mutable pour zeroing)
    key = _derive_key(bootstrap_key, salt)

    try:
        # Chiffrer (AES-256-GCM — le tag est automatiquement ajouté)
        aesgcm = AESGCM(bytes(key))
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    finally:
        # Effacer la clé dérivée de la mémoire
        _zero_fill(key)

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

    # Dériver la même clé (bytearray mutable pour zeroing)
    key = _derive_key(bootstrap_key, salt)

    # Déchiffrer (lève InvalidTag si la clé est mauvaise ou données corrompues)
    try:
        aesgcm = AESGCM(bytes(key))
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    except Exception:
        raise ValueError(
            "Déchiffrement impossible — ADMIN_BOOTSTRAP_KEY incorrecte "
            "ou données corrompues"
        )
    finally:
        # Effacer la clé dérivée de la mémoire
        _zero_fill(key)

    logger.debug("Déchiffrement OK")
    return plaintext_bytes.decode("utf-8")
