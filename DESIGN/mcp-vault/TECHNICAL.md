# Documentation Technique — MCP Vault

> **Version** : 0.1.0 | **Date** : 2026-03-17 | **Auteur** : Cloud Temple
> **Licence** : Apache 2.0 | **Statut** : 🚧 Implémentation en cours

---

## 1. Vue d'ensemble

MCP Vault est un serveur MCP (Model Context Protocol) qui fournit une gestion sécurisée des secrets pour les agents IA. Il embarque **OpenBao 2.5.1** (fork open-source de HashiCorp Vault, Linux Foundation) comme moteur de chiffrement et de stockage de secrets.

### Principes fondamentaux

1. **OpenBao embedded** — Le binaire OpenBao tourne comme processus intégré dans le conteneur Docker, pas comme un service séparé
2. **File backend + S3 sync** — Les données sont stockées localement (file backend) et synchronisées périodiquement avec S3 (source de vérité froide)
3. **Types de secrets style 1Password** — 14 types prédéfinis avec validation des champs
4. **Même pattern que Live Memory** — Bearer tokens, `vault_ids`, `check_access()`, starter-kit Cloud Temple
5. **Zéro mocking** — Tous les tests sont réels (S3 Dell ECS, Docker, OpenBao)

---

## 2. Architecture

### 2.1 Diagramme système

```
┌─────────────────────────────────────────────────────────────────┐
│  Internet / Agents IA / MCP Clients                             │
└──────────────────────┬──────────────────────────────────────────┘
                       │ HTTPS
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│  WAF — Caddy (:8082)                                            │
│  • Reverse proxy → mcp-vault:8030                               │
│  • Headers de sécurité (X-Content-Type-Options, X-Frame-Options)│
│  • Coraza OWASP CRS (production)                                │
│  • Timeouts adaptés MCP (120s)                                  │
└──────────────────────┬──────────────────────────────────────────┘
                       │ HTTP interne (réseau Docker)
                       ▼
┌────────────────────────────────────────────────────────────────┐
│  MCP Vault — Python 3.12 (:8030)                               │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Stack ASGI (5 couches)                                   │  │
│  │                                                          │  │
│  │  AdminMiddleware    → /admin, /admin/api/*               │  │
│  │  HealthCheckMiddleware → /health, /healthz, /ready       │  │
│  │  AuthMiddleware     → Bearer token → contextvars         │  │
│  │  LoggingMiddleware  → stderr + ring buffer (200 entrées) │  │
│  │  FastMCP            → /mcp (Streamable HTTP, 17 outils)  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ vault/       │  │ openbao/     │  │ S3 Sync              │  │
│  │ • spaces.py  │  │ • manager.py │  │ • s3_client.py       │  │
│  │ • secrets.py │  │ • config.py  │  │   (SigV2/SigV4)      │  │
│  │ • ssh_ca.py  │  │ • lifecycle  │  │ • s3_sync.py         │  │
│  │ • types.py   │  │   .py        │  │   (tar.gz periodic)  │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │
│         │ hvac            │ subprocess          │ boto3        │
│         ▼                 ▼                     ▼              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ OpenBao      │  │ /openbao/    │  │ S3 Dell ECS          │  │
│  │ :8200        │  │  file/       │  │ Cloud Temple         │  │
│  │ (localhost)  │  │  config/     │  │ (s3-endpoint)         │  │
│  │              │  │  logs/       │  │                      │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

### 2.2 Stack ASGI

Les requêtes traversent 5 couches middleware dans cet ordre :

| #   | Middleware              | Rôle                                  | Routes interceptées             |
| --- | ----------------------- | ------------------------------------- | ------------------------------- |
| 1   | `AdminMiddleware`       | Console admin web + API REST          | `/admin`, `/admin/api/*`        |
| 2   | `HealthCheckMiddleware` | Health checks (200 OK direct)         | `/health`, `/healthz`, `/ready` |
| 3   | `AuthMiddleware`        | Extraction et validation Bearer token | Toutes sauf publiques           |
| 4   | `LoggingMiddleware`     | Log stderr + ring buffer mémoire      | Toutes les requêtes HTTP        |
| 5   | `FastMCP`               | Outils MCP via Streamable HTTP        | `/mcp`                          |

---

## 3. Modules source

### 3.1 `config.py` — Configuration

Utilise `pydantic-settings` pour charger la configuration depuis les variables d'environnement ou le fichier `.env`.

| Variable                 | Défaut                    | Description                 |
| ------------------------ | ------------------------- | --------------------------- |
| `MCP_SERVER_NAME`        | `mcp-vault`               | Nom du service              |
| `MCP_SERVER_PORT`        | `8030`                    | Port d'écoute               |
| `ADMIN_BOOTSTRAP_KEY`    | `change_me_in_production` | Clé admin initiale          |
| `S3_ENDPOINT_URL`        | *(vide)*                  | Endpoint S3 Dell ECS        |
| `S3_ACCESS_KEY_ID`       | *(vide)*                  | Access key S3               |
| `S3_SECRET_ACCESS_KEY`   | *(vide)*                  | Secret key S3               |
| `S3_BUCKET_NAME`         | *(vide)*                  | Nom du bucket S3            |
| `S3_REGION_NAME`         | `fr1`                     | Région S3                   |
| `OPENBAO_ADDR`           | `http://127.0.0.1:8200`   | Adresse OpenBao             |
| `OPENBAO_SHARES`         | `1`                       | Nombre de parts Shamir      |
| `OPENBAO_THRESHOLD`      | `1`                       | Seuil de déverrouillage     |
| `OPENBAO_DATA_DIR`       | `/openbao/file`           | Répertoire file backend     |
| `OPENBAO_CONFIG_DIR`     | `/openbao/config`         | Répertoire config HCL       |
| `VAULT_S3_PREFIX`        | `_storage`                | Préfixe S3 pour le sync     |
| `VAULT_S3_SYNC_INTERVAL` | `60`                      | Intervalle sync en secondes |

### 3.2 `s3_client.py` — Client S3 hybride

Dell ECS (ViPR/1.0) Cloud Temple nécessite une configuration **hybride** :

```python
# SigV2 pour opérations de données (PUT/GET/DELETE)
Config(signature_version="s3", s3={"addressing_style": "path"})

# SigV4 pour opérations métadonnées (HEAD/LIST)
Config(signature_version="s3v4", s3={"addressing_style": "path", "payload_signing_enabled": False})
```

**Fonctions exposées** :
- `get_s3_data_client()` → Client SigV2 (singleton)
- `get_s3_meta_client()` → Client SigV4 (singleton)
- `create_s3_clients(endpoint, key, secret)` → Paire non-singleton
- `reset_clients()` → Reset des singletons

### 3.3 `s3_sync.py` — Synchronisation file backend ↔ S3

**Lifecycle** :

```
STARTUP:  download_from_s3() → décompresse tar.gz → /openbao/file/
RUNTIME:  start_periodic_sync() → upload tar.gz toutes les 60s
SHUTDOWN: upload_to_s3() → tar.gz final
CRASH:    Docker volume local conservé → fallback
```

**Format de transport** : `_storage/openbao-data.tar.gz` sur S3.

### 3.4 `auth/context.py` — Gestion des droits

Utilise les `contextvars` Python pour injecter les infos du token sans dépendre du framework HTTP.

**Fonctions** :

| Fonction                    | Retour si OK      | Retour si refusé                        |
| --------------------------- | ----------------- | --------------------------------------- |
| `check_access(resource_id)` | `None`            | `{"status": "error", "message": "..."}` |
| `check_write_permission()`  | `None`            | `{"status": "error", "message": "..."}` |
| `check_admin_permission()`  | `None`            | `{"status": "error", "message": "..."}` |
| `get_current_client_name()` | `"nom-du-client"` | `"anonymous"`                           |

**Matrice de permissions** :

| Token                      | `check_access(own_space)` | `check_access(other)` | `check_write`  | `check_admin` |
| -------------------------- | ------------------------- | --------------------- | -------------- | ------------- |
| Aucun                      | ❌                        | ❌                    | ❌             | ❌            |
| `read` + spaces restreints | ✅                        | ❌                    | ❌             | ❌            |
| `read` + spaces vides      | ✅                        | ✅                    | ❌             | ❌            |
| `read,write` + spaces      | ✅                        | ❌                    | ✅             | ❌            |
| `admin`                    | ✅                        | ✅                    | ✅ (implicite) | ✅            |

**Règles** :
- `vault_ids: []` (vide) → accès à **tous** les vaults
- `vault_ids: ["a", "b"]` → accès **uniquement** à "a" et "b"
- La comparaison est **case-sensitive** et **exacte** (pas de wildcard)
- `admin` implique `read` et `write`

### 3.5 `auth/middleware.py` — Authentification HTTP

**Ordre de validation du token** :
1. Bootstrap key (`ADMIN_BOOTSTRAP_KEY`) → admin total
2. Token Store S3 (lookup par hash SHA-256) → permissions du token

**Extraction du token** :
1. Header `Authorization: Bearer <token>`
2. Query string `?token=<token>` (fallback)

### 3.6 `auth/token_store.py` — Token Store S3

**Stockage** : `_system/tokens.json` sur S3.

**Cache** : Mémoire avec TTL de 5 minutes. Rafraîchissement automatique.

**Opérations** :
- `create(client_name, permissions, allowed_resources, expires_in_days, email)` → Crée un token, sauvegarde sur S3
- `get_by_hash(token_hash)` → Lookup + vérification expiration
- `list_all()` → Liste sans les hash complets
- `revoke(hash_prefix)` → Marque comme révoqué, sauvegarde sur S3
- `count()` → Nombre de tokens actifs

### 3.7 `vault/types.py` — Types de secrets

**14 types** avec validation des champs requis :

```python
SECRET_TYPES = {
    "login":         {"required": ["username", "password"], "optional": ["url", "totp_secret", "notes"]},
    "password":      {"required": ["password"], "optional": ["notes"]},
    "secure_note":   {"required": ["content"], "optional": ["title", "notes"]},
    "api_key":       {"required": ["key"], "optional": ["secret", "endpoint", "notes"]},
    "ssh_key":       {"required": ["private_key"], "optional": ["public_key", "passphrase", "notes"]},
    "database":      {"required": ["host", "username", "password"], "optional": ["port", "database", "connection_string", "notes"]},
    "server":        {"required": ["host", "username"], "optional": ["port", "password", "private_key", "notes"]},
    "certificate":   {"required": ["certificate", "private_key"], "optional": ["chain", "expiry", "notes"]},
    "env_file":      {"required": ["content"], "optional": ["notes"]},
    "credit_card":   {"required": ["number", "expiry", "cvv"], "optional": ["cardholder", "notes"]},
    "identity":      {"required": ["name"], "optional": ["email", "phone", "address", "company", "notes"]},
    "wifi":          {"required": ["ssid", "password"], "optional": ["security_type", "notes"]},
    "crypto_wallet": {"required": [], "optional": ["seed_phrase", "private_key", "address", "notes"]},
    "custom":        {"required": [], "optional": []},  # Accepte tout
}
```

**Enrichissement automatique** : chaque secret stocké reçoit les métadonnées `_type`, `_tags`, `_favorite`.

**Générateur de mots de passe** : CSPRNG (`secrets.choice`), 8-128 caractères, contrôle fin (uppercase, lowercase, digits, symbols, exclusions).

### 3.8 `vault/spaces.py` — Vault Spaces

Chaque space = un **mount point KV v2** dans OpenBao.

**Métadonnées vault** : chaque vault contient un secret réservé `_vault_meta` qui stocke
`created_at`, `created_by`, `updated_at`, `updated_by`, `description`. Ce chemin est protégé
contre l'écriture directe par les utilisateurs (via `RESERVED_PATHS` dans secrets.py).

| Opération                    | OpenBao API                                                          | Notes                                   |
| ---------------------------- | -------------------------------------------------------------------- | --------------------------------------- |
| `create_space(id, desc)`     | `sys.enable_secrets_engine("kv", path=id, options={"version": "2"})` | + écriture `_vault_meta` avec owner/date |
| `list_spaces(allowed_ids?)`  | `sys.list_mounted_secrets_engines()` → filtre type "kv"              | Filtrage par vault_ids du token          |
| `get_space_info(id)`         | Mounts info + `kv.v2.list_secrets()` pour le count                   | + lecture `_vault_meta` pour métadonnées |
| `update_space(id, desc)`     | `sys.tune_mount_configuration()` + `_vault_meta`                     | Mise à jour description + updated_at/by  |
| `delete_space(id)`           | `sys.disable_secrets_engine(path=id)`                                | Supprime tout (secrets + métadonnées)    |

### 3.9 `vault/secrets.py` — Secrets CRUD

**Protection des chemins réservés** : le set `RESERVED_PATHS` (contenant `_vault_meta`)
empêche l'écriture directe, la suppression et masque ces chemins dans les listings.

| Opération                               | OpenBao API                                | Notes                                     |
| --------------------------------------- | ------------------------------------------ | ----------------------------------------- |
| `write_secret(space, path, data, type)` | `kv.v2.create_or_update_secret()`          | Validation type + enrichissement + protection RESERVED_PATHS |
| `read_secret(space, path, version)`     | `kv.v2.read_secret_version()`              | Version 0 = dernière                      |
| `list_secrets(space, path)`             | `kv.v2.list_secrets()`                     | Clés uniquement, filtre `_vault_meta`     |
| `delete_secret(space, path)`            | `kv.v2.delete_metadata_and_all_versions()` | Irréversible, protection RESERVED_PATHS   |

### 3.10 `vault/ssh_ca.py` — SSH Certificate Authority

Chaque vault peut avoir sa propre CA SSH (mount `ssh-ca-{vault_id}`).

| Opération                                    | Description                                          |
| -------------------------------------------- | ---------------------------------------------------- |
| `setup_ssh_ca(space, role, users, ttl)`      | Monte le SSH engine + génère la CA + crée le rôle    |
| `sign_ssh_key(space, role, public_key, ttl)` | Signe une clé publique → certificat éphémère         |
| `get_ca_public_key(space)`                   | Retourne la clé publique CA pour `TrustedUserCAKeys` |

### 3.11 `openbao/` — OpenBao Process Manager

| Module         | Rôle                                                                         |
| -------------- | ---------------------------------------------------------------------------- |
| `manager.py`   | Démarrage/arrêt du process `bao server`, health check, client hvac singleton |
| `config.py`    | Génération du fichier HCL (file backend, listener localhost, disable_mlock)  |
| `lifecycle.py` | Init (Shamir shares=1), unseal, seal, status, chiffrement clés unseal        |

**Gestion sécurisée des clés unseal (Option C)** :

Les clés unseal (Shamir key + root token) sont gérées selon le principe de
**séparation physique données/clés** :

| Étape | Action | Stockage des clés |
|-------|--------|-------------------|
| Init (1ère fois) | `initialize()` → chiffrement AES-256-GCM → upload S3 | S3 uniquement (chiffré) |
| Unseal (suivants) | Download S3 → déchiffrement → `submit_unseal_key()` | Mémoire uniquement |
| Runtime | Clés en mémoire Python (variable de module) | Mémoire uniquement |
| Shutdown/Crash | `seal()` → mémoire libérée | Nulle part (garbage collected) |

**Chiffrement** : AES-256-GCM, clé dérivée de `ADMIN_BOOTSTRAP_KEY` via
PBKDF2-HMAC-SHA256 (600 000 itérations). Format : `salt(16B) || nonce(12B) || ciphertext || tag(16B)` encodé base64.

**⚠️ Invariant** : les clés unseal ne sont **jamais** écrites en clair sur le
filesystem local. Elles transitent uniquement en mémoire pendant le runtime.

**Configuration HCL générée** :

```hcl
storage "file" {
  path = "/openbao/file"
}
listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = true
}
disable_mlock = true
api_addr = "http://127.0.0.1:8200"
ui = false
```

---

## 4. Docker

### 4.1 Dockerfile (multi-stage)

```
Stage 1: alpine:3.20 → télécharge OpenBao 2.5.1 (ARM64/x86_64 auto-détecté)
Stage 2: python:3.12-slim → installe deps + copie source + OpenBao binary
```

**Particularités** :
- `setcap cap_ipc_lock=+ep` sur le binaire `bao` (verrouillage mémoire)
- User non-root `mcp` pour l'exécution
- Health check via `curl` sur `/admin/api/health`

### 4.2 Docker Compose

```yaml
services:
  waf:        # Caddy reverse proxy (:8082 → :8030)
  mcp-vault:  # Python + OpenBao embedded
  test:       # Service ponctuel (profil "test")

volumes:
  openbao-data:  # Persistance locale (crash recovery)
  openbao-logs:  # Logs OpenBao (optionnel)
```

**IPC_LOCK** : `cap_add: IPC_LOCK` dans docker-compose pour le mlock OpenBao.

---

## 5. Tests

### 5.1 Script de recette (`scripts/test_service.py`)

**78 tests** répartis en 8 catégories :

| #   | Catégorie    | Tests | Description                                      |
| --- | ------------ | ----- | ------------------------------------------------ |
| 1   | Connectivité | 1     | REST /health                                     |
| 2   | Auth HTTP    | 4     | Sans token, mauvais token, admin API             |
| 3   | S3 Dell ECS  | 8     | HEAD, LIST, PUT, GET, DELETE, JSON, 1MB, préfixe |
| 4   | Token Store  | 4     | Create, reload, list, revoke (persisté S3)       |
| 5   | Tar.gz Sync  | 3     | Upload, download, extract                        |
| 6   | Permissions  | 37    | 8 scénarios × edge cases                         |
| 7   | Types        | 14    | 14 types + password generator                    |
| 8   | Admin        | 7     | HTML, sécurité, API                              |

### 5.2 Scénarios de permissions testés

| Scénario                       | Tests                                      |
| ------------------------------ | ------------------------------------------ |
| Aucun token                    | 4 (access, write, admin, client_name)      |
| Admin (accès total)            | 9 (5 spaces + write + admin + client_name) |
| Read-only + spaces restreints  | 6 (2 OK + 2 refusés + write + admin)       |
| Read+Write + spaces restreints | 4 (1 OK + 1 refusé + write + admin)        |
| Spaces vides (= tous)          | 5 (5 spaces différents)                    |
| Admin-only (sans r/w)          | 3 (access + write implicite + admin)       |
| Permissions vides              | 3 (access OK + write + admin)              |
| Edge cases                     | 4 (case sensitive, wildcard, empty)        |

### 5.3 Exécution

```bash
# Test complet (build + start + test + stop)
WAF_PORT=8092 python3 scripts/test_service.py

# Test spécifique
python3 scripts/test_service.py --no-docker --test permissions

# Verbose
python3 scripts/test_service.py --verbose

# Docker container (sans serveur)
docker compose run --rm --entrypoint python test scripts/test_service.py --no-docker --test s3
```

---

## 6. Sécurité

### 6.1 Chiffrement

- **OpenBao barrier** : Chiffrement at-rest de toutes les données du file backend (XChaCha20-Poly1305)
- **Shamir's Secret Sharing** : Clé racine divisée en parts (shares=1, threshold=1 pour embedded)
- **Clés unseal** : Chiffrées AES-256-GCM (clé dérivée PBKDF2 de `ADMIN_BOOTSTRAP_KEY`)

### 6.2 Gestion des clés unseal (Option C)

Principe : **séparation physique** données / clés / bootstrap key.

```
Données chiffrées (barrier)  → Volume Docker + S3 (_storage/)
Clés unseal (chiffrées)      → S3 uniquement (_init/init_keys.json.enc)
ADMIN_BOOTSTRAP_KEY          → Variable d'environnement uniquement
```

**Invariants** :
- Les clés unseal ne sont **jamais** en clair sur le filesystem local
- Elles ne vivent qu'en **mémoire** pendant le runtime
- Un crash efface automatiquement les clés (garbage collection)
- 3 facteurs nécessaires pour accéder aux secrets : données + clés enc + bootstrap key

**Chiffrement** : `AES-256-GCM` via `cryptography` Python, dérivation `PBKDF2-HMAC-SHA256` (600k itérations).

**Roadmap** : Transit Auto-Unseal via OpenBao dédié (v0.3.0), HSM/Cloud KMS (v1.0).

### 6.3 Réseau

- OpenBao écoute **uniquement sur localhost:8200** (TLS désactivé car localhost)
- Le service MCP n'est **pas exposé directement** (WAF en frontal)
- Docker network isolé (`mcp-net`)

### 6.4 Tokens

- Hash SHA-256 stocké (jamais le token en clair)
- Expiration configurable
- Révocation immédiate
- Cache TTL 5 minutes

### 6.5 S3

- Config hybride SigV2/SigV4 (Dell ECS)
- Path-style addressing
- Retries adaptatifs (3 tentatives)

---

## 7. Dépendances

| Package             | Version | Rôle                                     |
| ------------------- | ------- | ---------------------------------------- |
| `mcp[cli]`          | ≥1.9.0  | Framework MCP (FastMCP, Streamable HTTP) |
| `pydantic-settings` | ≥2.0    | Configuration env vars                   |
| `boto3`             | ≥1.35.0 | Client S3 Dell ECS                       |
| `hvac`              | ≥2.3.0  | Client Python pour OpenBao/Vault         |
| `cryptography`      | ≥42.0   | Chiffrement clés unseal (AES-256-GCM, PBKDF2) |
| `uvicorn[standard]` | ≥0.32.0 | Serveur ASGI                             |
| `pytest`            | ≥8.0    | Tests                                    |
| `pytest-asyncio`    | ≥0.24.0 | Tests async                              |

**Runtime** :
- Python 3.12+
- OpenBao 2.5.1 (binaire embarqué)
- Docker + Docker Compose
- S3 Dell ECS Cloud Temple

---

## 8. Roadmap

| Phase                       | Statut | Description                                         |
| --------------------------- | ------ | --------------------------------------------------- |
| Phase 0 — Bootstrap         | ✅     | Starter-kit, structure, config, Docker              |
| Phase 1 — S3 + Auth         | ✅     | Client S3 hybride, Token Store, middleware          |
| Phase 2 — Types             | ✅     | 14 types de secrets, validation, password generator |
| Phase 3 — Tests             | ✅     | 78 tests e2e (permissions, S3, admin)               |
| Phase 4 — OpenBao lifecycle | ✅     | Init/unseal/seal intégré, clés chiffrées AES-256-GCM sur S3, 104 tests |
| Phase 5 — Vault Spaces CRUD | ✅     | Métadonnées (owner, dates), vault_update, filtrage token, protection _vault_meta, 118 tests |
| Phase 6 — SSH CA            | 🔜    | Tests e2e signature de clés                         |
| Phase 7 — Interface web     | 🔜    | Console admin enrichie (/vault)                     |
| Phase 8 — WAF Coraza        | 🔜    | OWASP CRS en production                             |
