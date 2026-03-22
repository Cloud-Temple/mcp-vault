# -*- coding: utf-8 -*-
"""
Types de secrets — Schémas style 1Password.

Chaque type définit :
    - required_fields : champs obligatoires
    - optional_fields : champs facultatifs
    - description : description humaine du type

Les secrets sont stockés dans OpenBao KV v2 avec les données typées.
Le champ `_type` est ajouté automatiquement aux métadonnées.
"""

import secrets
import string
from typing import Optional

# =============================================================================
# Définition des types
# =============================================================================

SECRET_TYPES = {
    "login": {
        "description": "Identifiants web/application (login + mot de passe + URL)",
        "required_fields": ["username", "password"],
        "optional_fields": ["url", "totp_secret", "notes"],
        "icon": "🔑",
    },
    "password": {
        "description": "Mot de passe simple",
        "required_fields": ["password"],
        "optional_fields": ["notes"],
        "icon": "🔒",
    },
    "secure_note": {
        "description": "Note sécurisée (texte libre chiffré)",
        "required_fields": ["content"],
        "optional_fields": ["title", "notes"],
        "icon": "📝",
    },
    "api_key": {
        "description": "Clé API (REST, GraphQL, services cloud)",
        "required_fields": ["key"],
        "optional_fields": ["secret", "endpoint", "notes"],
        "icon": "🔌",
    },
    "ssh_key": {
        "description": "Paire de clés SSH",
        "required_fields": ["private_key"],
        "optional_fields": ["public_key", "passphrase", "notes"],
        "icon": "🗝️",
    },
    "database": {
        "description": "Connexion base de données",
        "required_fields": ["host", "username", "password"],
        "optional_fields": ["port", "database", "connection_string", "notes"],
        "icon": "🗄️",
    },
    "server": {
        "description": "Accès serveur (SSH, RDP, etc.)",
        "required_fields": ["host", "username"],
        "optional_fields": ["port", "password", "private_key", "notes"],
        "icon": "🖥️",
    },
    "certificate": {
        "description": "Certificat TLS/SSL",
        "required_fields": ["certificate", "private_key"],
        "optional_fields": ["chain", "expiry", "notes"],
        "icon": "📜",
    },
    "env_file": {
        "description": "Fichier .env (variables d'environnement)",
        "required_fields": ["content"],
        "optional_fields": ["notes"],
        "icon": "📄",
    },
    "credit_card": {
        "description": "Carte bancaire",
        "required_fields": ["number", "expiry", "cvv"],
        "optional_fields": ["cardholder", "notes"],
        "icon": "💳",
    },
    "identity": {
        "description": "Identité (nom, email, téléphone, adresse)",
        "required_fields": ["name"],
        "optional_fields": ["email", "phone", "address", "company", "notes"],
        "icon": "👤",
    },
    "wifi": {
        "description": "Réseau Wi-Fi",
        "required_fields": ["ssid", "password"],
        "optional_fields": ["security_type", "notes"],
        "icon": "📶",
    },
    "crypto_wallet": {
        "description": "Wallet crypto (seed phrase, clé privée)",
        "required_fields": [],
        "optional_fields": ["seed_phrase", "private_key", "address", "notes"],
        "icon": "₿",
    },
    "custom": {
        "description": "Secret personnalisé (champs libres)",
        "required_fields": [],
        "optional_fields": [],  # Accepte tout
        "icon": "⚙️",
    },
}


# =============================================================================
# Validation
# =============================================================================

def validate_secret(secret_type: str, data: dict) -> Optional[str]:
    """
    Valide les données d'un secret selon son type.

    Args:
        secret_type: Type du secret (login, password, etc.)
        data: Données du secret

    Returns:
        None si valide, message d'erreur sinon
    """
    if secret_type not in SECRET_TYPES:
        return f"Type inconnu '{secret_type}'. Types valides : {', '.join(SECRET_TYPES.keys())}"

    schema = SECRET_TYPES[secret_type]

    # Vérifier les champs requis
    for field in schema["required_fields"]:
        if field not in data or not data[field]:
            return f"Champ requis manquant pour type '{secret_type}' : {field}"

    return None


def enrich_secret_data(secret_type: str, data: dict) -> dict:
    """
    Enrichit les données du secret avec le type et les métadonnées.

    Ajoute `_type`, `_tags`, `_favorite` si absents.
    """
    enriched = dict(data)
    enriched["_type"] = secret_type

    # Tags (liste de strings)
    if "_tags" not in enriched:
        enriched["_tags"] = ""

    # Favori
    if "_favorite" not in enriched:
        enriched["_favorite"] = "false"

    return enriched


def list_types() -> list[dict]:
    """Retourne la liste des types disponibles avec leur description."""
    return [
        {
            "type": name,
            "description": schema["description"],
            "icon": schema["icon"],
            "required_fields": schema["required_fields"],
            "optional_fields": schema["optional_fields"],
        }
        for name, schema in SECRET_TYPES.items()
    ]


# =============================================================================
# Générateur de mots de passe
# =============================================================================

def generate_password(length: int = 24, uppercase: bool = True,
                      lowercase: bool = True, digits: bool = True,
                      symbols: bool = True, exclude: str = "") -> str:
    """
    Génère un mot de passe cryptographiquement sûr.

    Args:
        length: Longueur (min 8, max 128)
        uppercase: Inclure A-Z
        lowercase: Inclure a-z
        digits: Inclure 0-9
        symbols: Inclure !@#$%^&*...
        exclude: Caractères à exclure

    Returns:
        Mot de passe généré
    """
    length = max(8, min(128, length))

    chars = ""
    if uppercase:
        chars += string.ascii_uppercase
    if lowercase:
        chars += string.ascii_lowercase
    if digits:
        chars += string.digits
    if symbols:
        chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"

    if not chars:
        chars = string.ascii_letters + string.digits

    # Exclure les caractères indésirables
    if exclude:
        chars = "".join(c for c in chars if c not in exclude)

    if not chars:
        chars = string.ascii_letters

    # Générer avec secrets (CSPRNG)
    password = "".join(secrets.choice(chars) for _ in range(length))

    return password
