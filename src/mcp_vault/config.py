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

    # --- WAF ---
    # Port externe du WAF Caddy (variable partagée avec docker-compose). Déclaré ici
    # pour que le .env mutualisé ne soit pas rejeté tout en gardant extra="forbid"
    # (toute autre variable inconnue = typo → erreur explicite au démarrage).
    waf_port: int = 8085

    # --- Transport security (protection anti-DNS-rebinding du SDK MCP) ---
    # FQDN publics autorisés pour le header Host sur /mcp, séparés par des virgules.
    # Le loopback (localhost/127.0.0.1) est TOUJOURS autorisé en plus (health checks
    # internes, tests e2e via WAF localhost). Surchargeable via MCP_ALLOWED_HOSTS.
    mcp_allowed_hosts: str = "vault.mcp.cloud-temple.app,my.vault.mcp.cloud-temple.app"
    # Origins HTTP supplémentaires, séparés par des virgules. "https://<fqdn>" est de
    # toute façon dérivé pour chaque FQDN ci-dessus ; cette variable AJOUTE d'autres
    # origins (ne les remplace pas). Surchargeable via MCP_ALLOWED_ORIGINS.
    mcp_allowed_origins: str = ""

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

    # --- PKI ---
    # URL publique de base pour les CDP ACME, CRL et cluster path OpenBao PKI.
    # Si vide (défaut) : déduite automatiquement du premier FQDN non-loopback
    # de mcp_allowed_hosts. Override utile en test Docker (ex: http://mcp-vault:8030).
    # Doit commencer par http:// ou https:// — validé au démarrage.
    pki_base_url: str = ""

    # --- Mission token enforcement (issue #26, anti-confused-deputy C18) ---
    # Désactivé par défaut : zéro impact sur les déploiements standalone (sans mcp-mission).
    # Activer sur l'environnement E2E pour prouver C18.
    enforce_mission_token_validation: bool = False

    # URL du JWKS public de mcp-mission. Vide = validation JWT désactivée.
    # Ex: https://mcp-mission.cloud-temple.app/.well-known/jwks.json
    mission_jwks_url: str = ""

    # Audience attendue dans le mission_token (anti-confused-deputy).
    # Doit correspondre à l'aud JWT : ex "mcp-vault:prod:v1" ou l'instance_id Vault.
    # Vide = vérification aud désactivée (non recommandé en production).
    mission_token_aud: str = ""

    # TTL du cache JWKS en secondes (défaut 60s — compromis révocation/performance).
    mission_jwks_cache_ttl: int = 60

    # Nombre max de refreshes JWKS par minute (rate-limit anti-DoS).
    mission_jwks_max_refresh_per_min: int = 3

    # Leeway JWT en secondes (tolérance clock skew inter-services).
    mission_token_leeway_seconds: int = 10

    # URL de vérification du statut de mission (mcp-mission status endpoint).
    # Vide = vérification mission active désactivée.
    # Ex: https://mcp-mission.cloud-temple.app/api/v1/missions/{mission_id}/status
    mission_status_url: str = ""

    # TTL du cache de statut de mission en secondes (court : fail-close rapide).
    mission_status_cache_ttl: int = 5

    # --- PEP mission JWT (issue #47) — validation du bearer entrant sur /mcp ---
    # Mode d'authentification de l'endpoint MCP :
    #   "bearer"     : bearer opaque uniquement (défaut — comportement historique, zéro impact).
    #   "jwt"        : mission_token JWT ES256 obligatoire sur /mcp (bearer opaque refusé).
    #   "dual-stack" : accepte un JWT valide OU un bearer opaque (mode de migration).
    mcp_auth_mode: str = "bearer"

    # Identifiant d'instance de CE Vault, attendu dans l'aud du mission_token ET dans
    # component_id[mcp_component_kind]. Ex: "mcp-vault:prod:v1". Source unique de
    # l'audience PEP (cf. resolved_mission_aud) — mission_token_aud est un alias legacy.
    mcp_instance_id: str = ""

    # Type de composant pour la validation component_id[kind] == instance_id (contrat mcp-mission).
    mcp_component_kind: str = "vault"

    @property
    def resolved_mission_aud(self) -> str:
        """Audience attendue du mission_token — source unique de vérité.

        mcp_instance_id (issue #47) est la valeur canonique ; mission_token_aud
        (issue #26) est conservé comme alias legacy. La cohérence entre les deux est
        garantie par un fail-fast au démarrage (cf. check_mission_pep_config) : si
        les deux sont renseignés et divergent, le service refuse de démarrer.
        """
        return self.mcp_instance_id or self.mission_token_aud

    def check_mission_pep_config(self) -> tuple[bool, str]:
        """Valide la cohérence de la config PEP mission JWT (fail-fast au boot).

        Règles :
          1. mcp_auth_mode ∈ {bearer, jwt, dual-stack}.
          2. mcp_instance_id et mission_token_aud, si tous deux renseignés, doivent
             être identiques (une seule vérité d'audience — anti config-drift).
          3. En mode != bearer : mission_jwks_url ET resolved_mission_aud requis
             (sinon le PEP ne peut ni récupérer les clés ni vérifier l'audience).

        Returns:
            (True, "") si OK, (False, message) sinon.
        """
        valid_modes = {"bearer", "jwt", "dual-stack"}
        if self.mcp_auth_mode not in valid_modes:
            return False, (
                f"MCP_AUTH_MODE invalide : '{self.mcp_auth_mode}' — "
                f"valeurs autorisées : {', '.join(sorted(valid_modes))}"
            )

        if self.mcp_instance_id and self.mission_token_aud \
                and self.mcp_instance_id != self.mission_token_aud:
            return False, (
                "MCP_INSTANCE_ID et MISSION_TOKEN_AUD divergent "
                f"('{self.mcp_instance_id}' != '{self.mission_token_aud}') — "
                "une seule audience mission doit être configurée (config drift)."
            )

        if self.mcp_auth_mode != "bearer":
            if not self.mission_jwks_url:
                return False, (
                    f"MCP_AUTH_MODE='{self.mcp_auth_mode}' requiert MISSION_JWKS_URL "
                    "(URL du JWKS public de mcp-mission)."
                )
            if not self.resolved_mission_aud:
                return False, (
                    f"MCP_AUTH_MODE='{self.mcp_auth_mode}' requiert MCP_INSTANCE_ID "
                    "(ou MISSION_TOKEN_AUD) pour vérifier l'audience du mission_token."
                )

        return True, ""

    @property
    def pki_base_url_validated(self) -> str:
        """Retourne pki_base_url validé ou lève ValueError si malformé."""
        url = self.pki_base_url.strip()
        if url and not url.startswith(("http://", "https://")):
            raise ValueError(
                f"PKI_BASE_URL invalide : '{url}' — doit commencer par http:// ou https://"
            )
        return url.rstrip("/")

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

    @property
    def allowed_hosts_list(self) -> list[str]:
        """FQDN publics autorisés (CSV), normalisés en minuscules (DNS insensible à la casse)."""
        return [h.strip().lower() for h in self.mcp_allowed_hosts.split(",") if h.strip()]

    @property
    def allowed_origins_list(self) -> list[str]:
        """Origins HTTP supplémentaires (CSV), normalisées en minuscules."""
        return [o.strip().lower() for o in self.mcp_allowed_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    """Singleton pour la config (cachée en mémoire)."""
    return Settings()
