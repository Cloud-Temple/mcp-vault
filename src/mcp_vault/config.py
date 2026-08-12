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

    # --- Accès SSH JIT opérateur ---
    # Objet JSON profile_id -> profil nominatif. Vide = fonctionnalité désactivée.
    # Les profils contiennent uniquement des données publiques/de policy : identité
    # bearer, policy_id, empreinte(s) de clé pré-enrôlée, vault/role/principal/cible et TTL.
    ssh_operator_profiles_json: str = ""
    # Variante Base64 URL-safe du même JSON pour les renderers .env qui refusent
    # volontairement les accolades et guillemets. Mutuellement exclusive du JSON.
    ssh_operator_profiles_b64: str = ""
    ssh_operator_jit_max_config_chars: int = 65536
    ssh_operator_jit_min_ttl_seconds: int = 60
    ssh_operator_jit_max_ttl_seconds: int = 900
    ssh_operator_jit_max_reason_chars: int = 512
    ssh_operator_jit_max_public_key_chars: int = 16384
    ssh_operator_jit_max_profiles: int = 32
    # Plafond de durée de vie RESTANTE d'un bearer pour être utilisable sur ce
    # parcours (jours, granularité de TokenStore.create()). Un bearer sans
    # expiration (expires_in_days=0) ou dont l'expiration dépasse ce plafond
    # est refusé — cf. décision produit dans la docstring de ssh_operator.py.
    ssh_operator_jit_max_bearer_expires_days: int = 1

    # --- S3 Token Store (optionnel — si vide, tokens en mémoire uniquement) ---
    s3_endpoint_url: str = ""
    s3_access_key_id: str = ""
    s3_secret_access_key: str = ""
    s3_bucket_name: str = ""
    s3_region_name: str = "fr1"
    # Bornes réseau des appels S3 (issue #110, lot 1). Les défauts botocore
    # (60 s connexion + 60 s lecture, retries "adaptive") laissent un appel
    # lent monopoliser la boucle asyncio pendant plusieurs minutes — 488 s
    # mesurées en production. Ces bornes plafonnent l'attente ; le retrait des
    # appels S3 de la boucle est traité séparément (lots 2 et 3).
    # `s3_max_attempts` = nombre TOTAL de tentatives (botocore
    # `total_max_attempts`), pas un nombre de retries additionnels.
    s3_connect_timeout: int = 5
    s3_read_timeout: int = 30
    s3_max_attempts: int = 2

    # Plafond du pré-drain des connexions ASGI par uvicorn à l'arrêt (issue
    # #110) : au-delà, uvicorn passe à la phase de shutdown du lifespan, où le
    # coffre exécute seal + effacement des clés + sauvegarde finale. Sans
    # plafond, des connexions clientes qui traînent consomment tout le délai de
    # grâce du conteneur.
    uvicorn_graceful_timeout: int = 10

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
    # Alias legacy de mcp_instance_id (cf. resolved_mission_aud). Vide = secret_consume
    # (C18) rejette explicitement toute validation JWT (misconfigured_expected_aud,
    # issue #86) — plus un mode permissif où la vérification aud serait désactivée.
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
    #   "bearer"     : bearer opaque VALIDE EXIGÉ (défaut) — sans jeton, ou jeton
    #                  invalide, refus 401 au middleware (issue #116).
    #   "bearer-anonymous" : ⚠️ MODE D'EXCEPTION — ancien comportement de "bearer" :
    #                  un appelant sans identité atteint les outils. CRITICAL au
    #                  démarrage. Repli temporaire uniquement.
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
    def mission_pep_active(self) -> bool:
        """Le PEP mission JWT est-il actif ? (modes `jwt` et `dual-stack` SEULS)

        Cette propriété existe parce que la formulation historique
        `mcp_auth_mode != "bearer"` était un PIÈGE LATENT (issue #116) : elle
        range du côté « PEP actif » TOUT mode qui n'est pas exactement
        `bearer`. L'ajout de `bearer-anonymous` aurait donc exigé de lui un
        JWKS, une audience et `ENFORCE_MISSION_TOKEN_VALIDATION=true` — rendant
        inutilisable le seul geste de repli offert à un exploitant dont un
        client anonyme se casse.

        Nommer l'intention ferme le piège pour tout mode futur : c'est une
        appartenance à un ensemble explicite, jamais une négation.
        """
        return self.mcp_auth_mode in {"jwt", "dual-stack"}

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
        """Valide la cohérence de la config mission JWT (fail-fast au boot).

        La validation du mission_token peut être active par DEUX portes indépendantes
        (issue #86, finding 1 — trouvé par revue de plan Codex) :
          - le PEP transport /mcp (mcp_auth_mode ∈ {jwt, dual-stack}) ;
          - l'enforcement C18 de secret_consume seul (enforce_mission_token_validation=
            true en mode bearer — mécanisme historique #26, indépendant de #47).
        Les DEUX portes exigent les mêmes garanties (clés JWKS, audience, statut
        mission) : sans cela, activer le PEP transport n'empêche pas secret_consume
        de rester permissif (c'était exactement le scénario du finding CRITIQUE).

        Règles :
          1. mcp_auth_mode ∈ {bearer, jwt, dual-stack}.
          2. mcp_instance_id et mission_token_aud, si tous deux renseignés, doivent
             être identiques (une seule vérité d'audience — anti config-drift).
          3. Si une des deux portes est active : mission_jwks_url ET
             resolved_mission_aud requis (sinon aucun mission_token n'est vérifiable).
          4. Si le PEP transport est actif (mode != bearer) : l'enforcement C18 doit
             l'être aussi (sinon secret_consume reste permissif malgré le PEP).
          5. Si une des deux portes est active : mission_status_url requis (sinon une
             mission abortée garde l'accès jusqu'à expiration du token, jusqu'à 1h),
             doit contenir le placeholder littéral '{mission_id}' (sinon une URL
             statique validerait silencieusement n'importe quelle mission comme
             active), et mission_status_cache_ttl doit être dans [0,30]s (0 = pas de
             cache ; recommandation mcp-mission ≤30s).

        Returns:
            (True, "") si OK, (False, message) sinon.
        """
        valid_modes = {"bearer", "bearer-anonymous", "jwt", "dual-stack"}
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

        pep_active = self.mission_pep_active
        mission_validation_active = pep_active or self.enforce_mission_token_validation

        if mission_validation_active:
            if not self.mission_jwks_url:
                return False, (
                    "MISSION_JWKS_URL requis dès que la validation mission_token est "
                    "active (MCP_AUTH_MODE ∈ {jwt, dual-stack}, ou "
                    "ENFORCE_MISSION_TOKEN_VALIDATION=true) — URL du JWKS public de "
                    "mcp-mission."
                )
            if not self.resolved_mission_aud:
                return False, (
                    "MCP_INSTANCE_ID (ou MISSION_TOKEN_AUD) requis dès que la "
                    "validation mission_token est active, pour vérifier l'audience "
                    "du mission_token."
                )

        if pep_active and not self.enforce_mission_token_validation:
            return False, (
                f"MCP_AUTH_MODE='{self.mcp_auth_mode}' requiert "
                "ENFORCE_MISSION_TOKEN_VALIDATION=true — sans cela, secret_consume "
                "reste en mode permissif (mission_token invalide ou mission inactive "
                "ignorés) même si le PEP /mcp est actif."
            )

        if mission_validation_active:
            if not self.mission_status_url:
                return False, (
                    "MISSION_STATUS_URL requis dès que la validation mission_token "
                    "est active (MCP_AUTH_MODE != bearer, ou "
                    "ENFORCE_MISSION_TOKEN_VALIDATION=true) — sans cela, une mission "
                    "abortée garde l'accès jusqu'à expiration du mission_token "
                    "(jusqu'à 1h). Doit contenir le placeholder '{mission_id}', ex : "
                    "https://mcp-mission.example/api/v1/missions/{mission_id}/status"
                )
            if "{mission_id}" not in self.mission_status_url:
                return False, (
                    f"MISSION_STATUS_URL='{self.mission_status_url}' ne contient pas "
                    "le placeholder littéral '{mission_id}' — une URL statique "
                    "validerait silencieusement n'importe quelle mission comme "
                    "active."
                )
            if not (0 <= self.mission_status_cache_ttl <= 30):
                return False, (
                    f"MISSION_STATUS_CACHE_TTL={self.mission_status_cache_ttl} hors "
                    "bornes [0,30] secondes (0 = pas de cache) — une valeur négative "
                    "est invalide, une valeur trop grande retarde la détection d'une "
                    "mission abortée."
                )

        return True, ""

    def check_s3_timeouts(self) -> tuple[bool, str]:
        """Valide les bornes réseau S3 au démarrage (fail-fast, issue #110).

        Une valeur nulle ou négative signifierait « pas de borne » côté
        botocore (ou lèverait à l'usage) : c'est exactement le défaut que ce
        lot corrige. On refuse donc de démarrer plutôt que de servir avec des
        appels S3 non bornés.
        """
        if self.s3_connect_timeout <= 0:
            return False, (f"S3_CONNECT_TIMEOUT={self.s3_connect_timeout} invalide "
                           "— doit être > 0 (secondes)")
        if self.s3_read_timeout <= 0:
            return False, (f"S3_READ_TIMEOUT={self.s3_read_timeout} invalide "
                           "— doit être > 0 (secondes)")
        if self.s3_max_attempts < 1:
            return False, (f"S3_MAX_ATTEMPTS={self.s3_max_attempts} invalide — doit "
                           "être >= 1 (nombre TOTAL de tentatives, 1 = aucun retry)")
        return True, ""

    def check_operator_ssh_jit_config(self) -> tuple[bool, str]:
        """Valide les profils SSH opérateur au démarrage (fail-fast)."""
        try:
            from .ssh_operator import parse_operator_profiles
            parse_operator_profiles(self)
        except (ValueError, TypeError) as exc:
            return False, str(exc)
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
