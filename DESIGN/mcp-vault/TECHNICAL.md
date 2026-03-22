# Documentation Technique — MCP Vault

> **Version** : 0.2.0 | **Date** : 2026-03-18 | **Auteur** : Cloud Temple
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
│  WAF — Caddy (:8085)                                            │
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
│  │  FastMCP            → /mcp (Streamable HTTP, 24 outils)  │  │
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

| Token                      | `check_access(own_vault)` | `check_access(other)` | `check_write`  | `check_admin` |
| -------------------------- | ------------------------- | --------------------- | -------------- | ------------- |
| Aucun                      | ❌                        | ❌                    | ❌             | ❌            |
| `read` + vaults restreints | ✅                        | ❌                    | ❌             | ❌            |
| `read` + vaults vides      | ✅                        | ✅                    | ❌             | ❌            |
| `read,write` + vaults      | ✅                        | ❌                    | ✅             | ❌            |
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

### 3.8 `vault/spaces.py` — Vaults (coffres de secrets)

Chaque vault = un **mount point KV v2** dans OpenBao.

**Métadonnées vault** : chaque vault contient un secret réservé `_vault_meta` qui stocke
`created_at`, `created_by`, `updated_at`, `updated_by`, `description`. Ce chemin est protégé
contre l'écriture directe par les utilisateurs (via `RESERVED_PATHS` dans secrets.py).

| Opération                   | OpenBao API                                                          | Notes                                    |
| --------------------------- | -------------------------------------------------------------------- | ---------------------------------------- |
| `create_space(id, desc)`    | `sys.enable_secrets_engine("kv", path=id, options={"version": "2"})` | + écriture `_vault_meta` avec owner/date |
| `list_spaces(allowed_ids?)` | `sys.list_mounted_secrets_engines()` → filtre type "kv"              | Filtrage par vault_ids du token          |
| `get_space_info(id)`        | Mounts info + `kv.v2.list_secrets()` pour le count                   | + lecture `_vault_meta` pour métadonnées |
| `update_space(id, desc)`    | `sys.tune_mount_configuration()` + `_vault_meta`                     | Mise à jour description + updated_at/by  |
| `delete_space(id)`          | `sys.disable_secrets_engine(path=id)`                                | Supprime tout (secrets + métadonnées)    |

### 3.9 `vault/secrets.py` — Secrets CRUD

**Protection des chemins réservés** : le set `RESERVED_PATHS` (contenant `_vault_meta`)
empêche l'écriture directe, la suppression et masque ces chemins dans les listings.

| Opération                                  | OpenBao API                                | Notes                                                        |
| ------------------------------------------ | ------------------------------------------ | ------------------------------------------------------------ |
| `write_secret(vault_id, path, data, type)` | `kv.v2.create_or_update_secret()`          | Validation type + enrichissement + protection RESERVED_PATHS |
| `read_secret(vault_id, path, version)`     | `kv.v2.read_secret_version()`              | Version 0 = dernière                                         |
| `list_secrets(vault_id, path)`             | `kv.v2.list_secrets()`                     | Clés uniquement, filtre `_vault_meta`                        |
| `delete_secret(vault_id, path)`            | `kv.v2.delete_metadata_and_all_versions()` | Irréversible, protection RESERVED_PATHS                      |

### 3.10 `vault/ssh_ca.py` — SSH Certificate Authority

Chaque vault possède sa **propre CA SSH isolée** (mount `ssh-ca-{vault_id}`).
L'isolation est cryptographique : les CA sont des paires de clés différentes.
Un certificat signé par la CA d'un vault ne fonctionne PAS sur les serveurs
configurés pour un autre vault.

**Mount point** : `SSH_MOUNT_PREFIX = "ssh-ca-"` → `ssh-ca-{vault_id}`

| Opération                                        | Description                                                        |
| ------------------------------------------------ | ------------------------------------------------------------------ |
| `setup_ssh_ca(vault_id, role, users, user, ttl)` | Monte le SSH engine + génère la CA + crée le rôle                  |
| `sign_ssh_key(vault_id, role, public_key, ttl)`  | Signe une clé publique → certificat éphémère avec serial number    |
| `get_ca_public_key(vault_id)`                    | Retourne la clé publique CA + snippet sshd_config pour déploiement |
| `list_ssh_roles(vault_id)`                       | Liste les rôles SSH CA configurés dans le vault                    |
| `get_ssh_role_info(vault_id, role)`              | Détails d'un rôle : TTL, allowed_users, extensions, max_ttl        |

**Modèle de sécurité** :

| Niveau    | Mécanisme                           | Protection                                       |
| --------- | ----------------------------------- | ------------------------------------------------ |
| **Vault** | Mount SSH CA dédié par vault        | CA cryptographiquement isolées                   |
| **Token** | `vault_ids` dans le token MCP       | Accès aux outils SSH restreint au vault autorisé |
| **Rôle**  | `allowed_users` + `ttl` + `max_ttl` | Contrôle fin de qui peut signer quel cert        |

**Workflow typique** :
1. `ssh_ca_setup("llmaas-infra", "adminct", allowed_users="adminct", ttl="1h")`
2. `ssh_ca_public_key("llmaas-infra")` → déployer sur les serveurs
3. `ssh_sign_key("llmaas-infra", "adminct", public_key="...", ttl="1h")` → certificat éphémère

**Suppression** : quand un vault est supprimé (`vault_delete`), le mount SSH CA
est également supprimé. Les certificats déjà émis restent valides jusqu'à expiration.

### 3.12 `auth/policies.py` — Policy Store S3

Même pattern que `token_store.py` : singleton + cache mémoire TTL 5 min + stockage S3.

**Stockage** : `_system/policies.json` sur S3 (même bucket que tokens.json).

**Singleton** :
- `init_policy_store()` → Appelé au startup (dans `lifecycle.py`, après `init_token_store()`)
- `get_policy_store()` → Getter singleton

**Modèle de données** :

```python
{
    "policy_id": str,          # alphanum + tirets, max 64 chars
    "description": str,        # texte libre
    "allowed_tools": list,     # patterns fnmatch (ex: ["system_*", "vault_list"])
    "denied_tools": list,      # patterns fnmatch (priorité sur allowed_tools)
    "path_rules": list,        # [{"vault_pattern": "prod-*", "permissions": ["read"]}]
    "created_at": str,         # ISO 8601
    "created_by": str,         # nom du créateur
}
```

**CRUD** :
- `create(policy_id, description, allowed_tools, denied_tools, path_rules, created_by)` → validation + sauvegarde S3
- `get(policy_id)` → lookup avec refresh cache TTL
- `list_all()` → résumé avec compteurs (allowed_tools_count, denied_tools_count, path_rules_count)
- `delete(policy_id)` → supprime + sauvegarde S3
- `count()` → nombre total

**Matching (enforcement actif — Phase 8b)** :
- `is_tool_allowed(policy_id, tool_name)` → évalue denied > allowed > refusé (wildcards fnmatch)
- `get_vault_permissions(policy_id, vault_id)` → première path_rule qui matche → permissions

**Validation** :
- `policy_id` : alphanum + tirets + underscores, max 64 chars
- `path_rules` : chaque règle doit avoir `vault_pattern`, permissions ∈ {read, write, admin}
- Doublon interdit (policy_id unique)

### 3.13 `openbao/` — OpenBao Process Manager

| Module         | Rôle                                                                         |
| -------------- | ---------------------------------------------------------------------------- |
| `manager.py`   | Démarrage/arrêt du process `bao server`, health check, client hvac singleton |
| `config.py`    | Génération du fichier HCL (file backend, listener localhost, disable_mlock)  |
| `lifecycle.py` | Init (Shamir shares=1), unseal, seal, status, chiffrement clés unseal        |
| `crypto.py`    | Chiffrement AES-256-GCM + PBKDF2 pour les clés unseal                        |

**Gestion sécurisée des clés unseal (Option C)** :

Les clés unseal (Shamir key + root token) sont gérées selon le principe de
**séparation physique données/clés** :

| Étape             | Action                                               | Stockage des clés              |
| ----------------- | ---------------------------------------------------- | ------------------------------ |
| Init (1ère fois)  | `initialize()` → chiffrement AES-256-GCM → upload S3 | S3 uniquement (chiffré)        |
| Unseal (suivants) | Download S3 → déchiffrement → `submit_unseal_key()`  | Mémoire uniquement             |
| Runtime           | Clés en mémoire Python (variable de module)          | Mémoire uniquement             |
| Shutdown/Crash    | `seal()` → mémoire libérée                           | Nulle part (garbage collected) |

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

### 3.14 `audit.py` — Audit Store MCP

Journal d'audit de toutes les opérations MCP, avec double persistance :

**Architecture** :

```
┌────────────────────────────────────────────────────────────────┐
│  AuditStore (singleton)                                        │
│                                                                │
│  ┌──────────────────────────────┐  ┌────────────────────────┐  │
│  │ Ring buffer mémoire          │  │ Fichier JSONL          │  │
│  │ • 5000 entrées (deque)       │  │ • /openbao/logs/       │  │
│  │ • Accès rapide + filtrage    │  │   audit-mcp.jsonl      │  │
│  │ • Perdu au restart           │  │ • Persistant (volume)  │  │
│  │ • Chargé depuis JSONL        │  │ • Append-only          │  │
│  │   au startup                 │  │ • Synced S3 via volume │  │
│  └──────────────────────────────┘  └────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

**Singleton** :
- `init_audit_store()` → Appelé au startup (dans `lifecycle.py`, après PolicyStore)
- `get_audit_store()` → Getter singleton
- `log_audit(tool, status, vault_id, detail, duration_ms, client_name)` → Helper global

**Chaque entrée d'audit contient** :

| Champ         | Type   | Description                                                    |
| ------------- | ------ | -------------------------------------------------------------- |
| `ts`          | string | Timestamp ISO 8601 UTC                                         |
| `client`      | string | Nom du client (auto-détecté via `get_current_client_name()`)   |
| `tool`        | string | Nom de l'outil MCP (ex: `vault_create`, `secret_read`)        |
| `category`    | string | Catégorisation automatique (system, vault, secret, ssh, policy, token, audit) |
| `vault_id`    | string | Vault concerné (vide si non applicable)                        |
| `status`      | string | Résultat (ok, created, deleted, error, updated, denied)        |
| `detail`      | string | Détail additionnel (path du secret, message d'erreur…)         |
| `duration_ms` | float  | Durée de l'opération en millisecondes                          |

**Catégorisation automatique** : basée sur le préfixe du nom d'outil (`_categorize_tool()`).

| Préfixe    | Catégorie |
| ---------- | --------- |
| `system_`  | system    |
| `vault_`   | vault     |
| `secret_`  | secret    |
| `ssh_`     | ssh       |
| `policy_`  | policy    |
| `token_`   | token     |
| `audit_`   | audit     |
| *(autre)*  | other     |

**Filtrage** (`get_entries()`) : tous les filtres sont combinables.

| Filtre     | Description                                              |
| ---------- | -------------------------------------------------------- |
| `limit`    | Nombre max d'entrées (défaut 100, max 1000)              |
| `client`   | Filtrer par client_name exact                            |
| `vault_id` | Filtrer par vault_id exact                               |
| `tool`     | Filtrer par outil (supporte `*` via startswith)           |
| `category` | Filtrer par catégorie                                    |
| `status`   | Filtrer par statut                                       |
| `since`    | Entrées après cette date ISO 8601                        |

**Statistiques** (`get_stats()`) : agrégations pour le dashboard.

```python
{
    "total": 1234,
    "by_category": {"secret": 500, "vault": 300, "ssh": 200, ...},
    "by_status": {"ok": 1000, "created": 150, "error": 84},
    "by_client": {"admin": 800, "agent-sre": 400, ...}
}
```

**Intégration dans server.py** : le helper `_r(tool, result, vault_id, detail)` appelle
`log_audit()` après chaque opération MCP et retourne le résultat inchangé. Cela permet
un audit systématique sans modifier la logique métier de chaque outil.

Les refus de policy (`check_policy()` dans `context.py`) génèrent aussi un événement
d'audit avec status `"denied"`.

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
  waf:        # Caddy reverse proxy (:8085 → :8030)
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

### 5.2 Tests e2e (`tests/test_e2e.py`)

**276 tests** e2e via protocole MCP Streamable HTTP, 14 catégories :

| #   | Catégorie                     | Tests  | Description                                                     |
| --- | ----------------------------- | ------ | --------------------------------------------------------------- |
| 1   | Système                       | 7      | health, about, services, version, tools_count (24)              |
| 2   | Vault Spaces CRUD             | ~28    | create, list, info, update, delete, metadata, erreurs           |
| 3   | Secrets CRUD                  | ~24    | 14 types, write/read/list/delete, validation                    |
| 4   | Versioning & Rotation         | 8      | v1/v2/v3, lecture version spécifique                            |
| 5   | Password Generator            | 14     | longueurs, options, exclusions, unicité CSPRNG                  |
| 6   | Isolation inter-vaults        | 7      | cloisonnement strict entre vaults                               |
| 7   | Gestion d'erreurs             | ~10    | edge cases, _vault_meta protection                              |
| 8   | S3 Sync                       | 3      | HEAD bucket, list archives, archive existe                      |
| 9   | SSH CA                        | ~33    | setup, roles multiples, signing ed25519, isolation              |
| 10  | Secret Types                  | 14     | validation des 14 types                                         |
| 11  | Admin API                     | 15     | health, whoami, generate-password, logs, CSPRNG                 |
| 12  | Policies MCP                  | 43     | CRUD, validation, wildcards, path_rules, Admin API              |
| 13  | **Policy Enforcement**        | **37** | check_policy, token_update, denied/allowed, changement policy   |

### 5.3 Scénarios SSH CA testés (Phase 6)

| Scénario         | Description                                                          |
| ---------------- | -------------------------------------------------------------------- |
| Setup CA + rôle  | Crée le mount SSH + génère CA + rôle avec allowed_users et TTL       |
| Rôles multiples  | Crée 2 rôles différents (adminct 1h, agentic 30m) dans le même vault |
| Signature de clé | Signe une clé publique ed25519, vérifie signed_key et serial_number  |
| CA publique      | Récupère la clé publique CA, vérifie le format ssh-ed25519           |
| Liste des rôles  | Liste les rôles configurés, vérifie la présence des 2 rôles          |
| Info rôle        | Récupère les détails d'un rôle (TTL, allowed_users, key_type)        |
| Vault inexistant | Tente un setup sur vault inexistant → erreur                         |
| Rôle inexistant  | Tente signature avec rôle inexistant → erreur                        |
| Clé invalide     | Tente signature avec clé publique invalide → erreur                  |
| Isolation CA     | Vérifie que la CA d'un vault est différente de celle d'un autre      |

### 5.4 Exécution

```bash
# Test complet (build + start + test + stop)
WAF_PORT=8092 python3 scripts/test_service.py

# Tests e2e (serveur déjà running)
docker compose exec mcp-vault python tests/test_e2e.py

# Un seul groupe
docker compose exec mcp-vault python tests/test_e2e.py --test ssh_ca

# Verbose
docker compose exec mcp-vault python tests/test_e2e.py --verbose
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

**Roadmap** : Transit Auto-Unseal via OpenBao dédié (v0.3.0), connexion HSM Cloud Temple (v2.0).

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

### 6.6 SSH CA — Isolation par vault

- Chaque vault possède sa **propre CA SSH** (mount `ssh-ca-{vault_id}`)
- Les CA sont des paires de clés **cryptographiquement différentes**
- Un certificat signé par la CA d'un vault ne fonctionne pas sur les serveurs d'un autre vault
- Les tokens MCP contrôlent l'accès aux outils SSH via `vault_ids`
- Les rôles SSH contrôlent quels utilisateurs peuvent être certifiés et avec quel TTL
- Suppression d'un vault = suppression de sa CA (aucune CA orpheline)

### 6.7 SSH CA — Checklist de mise en production

Résumé opérationnel des règles de sécurité pour le déploiement de la SSH CA.
Voir `ARCHITECTURE.md §7.8` pour les détails complets.

**Configuration des rôles** :
- 🔴 TTL ≤ 1h (humains), ≤ 30m (agents IA)
- 🔴 Toujours définir `max_ttl` (ex: 24h)
- 🔴 `allowed_users` explicites — jamais `"*"` en production
- 🟠 Un rôle = un profil (admin, agent, CI/CD)
- 🟠 Extensions SSH minimales (`permit-pty` uniquement sauf besoin)

**Serveurs cibles** :
- 🔴 `TrustedUserCAKeys` dans `sshd_config` sur chaque serveur
- 🟠 `AuthorizedPrincipalsFile` pour restreindre les principals par utilisateur
- 🟠 Migration progressive (conserver `authorized_keys` pendant la transition)
- 🟡 Déploiement automatisé (Ansible/Salt) de la clé CA et config sshd

**Cycle de vie** :
- 🔴 1 CA par domaine de confiance (prod ≠ staging ≠ client)
- 🟠 Rotation CA tous les 12-24 mois (chevauchement 2-4 semaines)
- 🟡 Backup vault avant rotation

**Audit** :
- 🔴 Audit device OpenBao actif
- 🟠 Alertes sur signatures hors horaires ou TTL anormaux
- 🟡 Revue des rôles SSH tous les 3 mois

**Réponse aux incidents** :
- Clé privée agent compromise → révoquer le token MCP, attendre expiration du cert
- Token admin compromis → révoquer, auditer, recréer
- CA compromise (worst case) → supprimer le vault, retirer la CA des serveurs, recréer

### 6.8 Roadmap sécurité — Trajectoire des clés unseal

| Version             | Mécanisme                                    | Où vivent les clés         | Niveau         |
| ------------------- | -------------------------------------------- | -------------------------- | -------------- |
| **v0.2.x** (actuel) | AES-256-GCM + PBKDF2 + bootstrap key env var | Mémoire Python au runtime  | 🟡 Bonne      |
| **v0.3.0**          | Transit Auto-Unseal via OpenBao KMS dédié    | KMS dédié (Shamir 5/3)     | 🟢 Excellente |
| **v2.0**            | HSM matériel (PKCS#11 / KMIP)                | HSM certifié FIPS 140-2 L3 | 🟢 Maximale   |

Voir `ARCHITECTURE.md §11.3` pour les diagrammes d'architecture et les étapes de migration détaillées.

---

## 7. Dépendances

| Package             | Version | Rôle                                          |
| ------------------- | ------- | --------------------------------------------- |
| `mcp[cli]`          | ≥1.9.0  | Framework MCP (FastMCP, Streamable HTTP)      |
| `pydantic-settings` | ≥2.0    | Configuration env vars                        |
| `boto3`             | ≥1.35.0 | Client S3 Dell ECS                            |
| `hvac`              | ≥2.3.0  | Client Python pour OpenBao/Vault              |
| `cryptography`      | ≥42.0   | Chiffrement clés unseal (AES-256-GCM, PBKDF2) |
| `uvicorn[standard]` | ≥0.32.0 | Serveur ASGI                                  |
| `pytest`            | ≥8.0    | Tests                                         |
| `pytest-asyncio`    | ≥0.24.0 | Tests async                                   |

**Runtime** :
- Python 3.12+
- OpenBao 2.5.1 (binaire embarqué)
- Docker + Docker Compose
- S3 Dell ECS Cloud Temple

---

## 8. Roadmap

| Phase                       | Statut | Description                                                                                                                              |
| --------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------- |
| Phase 0 — Bootstrap         | ✅     | Starter-kit, structure, config, Docker                                                                                                   |
| Phase 1 — S3 + Auth         | ✅     | Client S3 hybride, Token Store, middleware                                                                                               |
| Phase 2 — Types             | ✅     | 14 types de secrets, validation, password generator                                                                                      |
| Phase 3 — Tests             | ✅     | 78 tests e2e (permissions, S3, admin)                                                                                                    |
| Phase 4 — OpenBao lifecycle | ✅     | Init/unseal/seal intégré, clés chiffrées AES-256-GCM sur S3, 104 tests                                                                   |
| Phase 5 — Vault Spaces CRUD | ✅     | Métadonnées (owner, dates), vault_update, filtrage token, protection _vault_meta                                                         |
| Phase 6 — SSH CA            | ✅     | CA isolée par vault, 5 outils MCP (setup, sign, public_key, list_roles, role_info), 148 tests e2e, CLI ssh complet, cleanup CA auto      |
| Phase 7 — Interface web     | ✅     | Console admin SPA modulaire (sidebar, CRUD vaults/secrets, permissions granulaires, 15 endpoints API, 10 fichiers frontend < 200 lignes) |
| Phase 8a — Policies CRUD      | ✅     | PolicyStore S3-backed, 4 outils MCP (create, list, get, delete), wildcards fnmatch, path_rules, Admin API, 206 tests e2e |
| Phase 8b — Policy Enforcement | ✅     | `check_policy()` dans 15 outils MCP, champ `policy_id` dans tokens, outil `token_update`, 276 tests e2e / 14 catégories |
| Phase 8c — Audit Log          | ✅     | AuditStore (ring buffer 5000 + JSONL), outil `audit_log` filtrable, timeline SPA, CLI audit, catégorisation auto, stats dashboard |
| Phase 9 — HSM Integration     | ⏳     | **En attente HSM** — Design et prérequis documentés (ARCHITECTURE.md §11.3). Bloqué par la disponibilité du Thales Luna chez Cloud Temple. Config HCL cible, migration 11 étapes, commandes Luna préparées. Reprise dès que le matériel HSM sera opérationnel. |
