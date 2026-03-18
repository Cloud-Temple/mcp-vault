# Architecture — MCP Vault

> **Version** : 0.2.1-draft | **Date** : 2026-03-08 | **Auteur** : Cloud Temple  
> **Projet** : mcp-vault | **Licence** : Apache 2.0  
> **Statut** : 📐 Design — non implémenté

---

## 1. Vision

**MCP Vault** est un serveur MCP qui fournit une **gestion sécurisée de secrets** pour les agents IA et les missions. Il embarque **OpenBao** (fork open-source de HashiCorp Vault, Linux Foundation) comme moteur de chiffrement et de gestion des secrets.

### Principes

1. **OpenBao embedded** — Le binaire OpenBao tourne en process intégré, pas comme service séparé
2. **Espaces libres** — L'utilisateur organise ses secrets par serveur, application, groupe... comme il veut
3. **Même pattern que Live Memory** — Tokens Bearer, `space_ids`, `check_access()`, starter-kit
4. **S3 comme source de vérité** — Le storage OpenBao est synchronisé avec S3 (download au start, upload au stop)
5. **Missions découplées** — Les espaces vault sont indépendants des missions. On donne à la mission l'espace vault à utiliser.
6. **SSH Certificate Authority** — Signer des clés publiques à la volée (certificats éphémères)

### Pourquoi OpenBao ?

| Custom crypto (design v0.1) | OpenBao embedded (design v0.2)                |
| --------------------------- | --------------------------------------------- |
| AES-256-GCM en Python       | XChaCha20-Poly1305 (natif OpenBao)            |
| Policy engine custom        | Policies HCL battle-tested                    |
| Audit custom (JSONL)        | Audit device natif                            |
| KV basique seulement        | KV v2, SSH CA, Transit, Database...           |
| Pas de dynamic secrets      | ✅ SSH certificates, DB credentials éphémères |
| Code crypto maison (risqué) | Battle-tested, communauté Linux Foundation    |
| Beaucoup de code            | Façade MCP mince + hvac                       |

---

## 2. Architecture

### 2.1 Vue d'ensemble

```
    Humain (CLI/shell)       Mission Controller       MCP Agent (instances)
         │                        │                        │
         │  MCP Protocol (Streamable HTTP)                 │
         ▼                        ▼                        ▼
┌──────────────────────────────────────────────────────────────────┐
│       WAF Caddy + Coraza (:8082, configurable WAF_PORT)         │
│       TLS termination, rate limiting, OWASP CRS                  │
└──────────────────────────┬───────────────────────────────────────┘
                           │ reverse proxy
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│               MCP Vault Server (:8030, réseau interne)           │
│               Python / FastMCP (starter-kit)                     │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  Pile Middleware ASGI (5 couches, voir §2.3)               │  │
│  │                                                            │  │
│  │  AdminMiddleware        → /admin, /admin/static/*, API     │  │
│  │  HealthCheckMiddleware  → /health, /healthz, /ready        │  │
│  │  AuthMiddleware         → Bearer Token + space_ids         │  │
│  │  LoggingMiddleware      → Ring buffer 200 entrées          │  │
│  │  FastMCP app            → MCP Protocol (Streamable HTTP)   │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  Console Admin Web (/admin) — voir §2.4                    │  │
│  │  • SPA HTML (login + 4 vues)                               │  │
│  │  • API REST admin (8 endpoints, auth admin)                │  │
│  │  • Design Cloud Temple (dark theme #0f0f23, accent #41a890)│  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  20 Outils MCP (façade)                                    │  │
│  │                                                            │  │
│  │  Spaces :  vault_space_create, _list, _info, _delete       │  │
│  │  Secrets : secret_store, _get, _list, _delete, _rotate     │  │
│  │  SSH CA :  ssh_sign_key                                    │  │
│  │  Policies: policy_create, _list, _delete                   │  │
│  │  Tokens :  admin_create_token, _list_tokens,               │  │
│  │            _revoke_token, _update_token                    │  │
│  │  Audit :   audit_log                                       │  │
│  │  System :  system_health, system_about                     │  │
│  └─────────────────────────┬──────────────────────────────────┘  │
│                            │                                     │
│  ┌─────────────────────────▼──────────────────────────────────┐  │
│  │  hvac Python client                                        │  │
│  │  → Connecté à OpenBao sur localhost:8200                   │  │
│  │  → Traduit les appels MCP en opérations OpenBao            │  │
│  └──────────────────────────┬─────────────────────────────────┘  │
│                             │                                    │
│  ┌──────────────────────────▼─────────────────────────────────┐  │
│  │  OpenBao Process (embedded, localhost:8200)                │  │
│  │  Binaire : /usr/local/bin/bao                              │  │
│  │                                                            │  │
│  │  Storage : File backend → /tmp/openbao-data/               │  │
│  │  Encryption : XChaCha20-Poly1305 (barrier)                 │  │
│  │  Auth : Token (root) pour le MCP Vault                     │  │
│  │  Audit : File audit device                                 │  │
│  │                                                            │  │
│  │  Mount points :                                            │  │
│  │    /spaces/{space_id}/kv/  ← KV v2 par espace              │  │
│  │    /ssh/                   ← SSH CA (global)               │  │
│  │                                                            │  │
│  │  NON exposé sur le réseau — localhost uniquement           │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  S3 Sync Manager                                           │  │
│  │  • Startup  : S3 → local (télécharge openbao-data.tar.gz)  │  │
│  │  • Periodic : local → S3 (toutes les N minutes)            │  │
│  │  • Shutdown : local → S3 (upload final) + seal + cleanup   │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  Token Manager (standard starter-kit, S3)                  │  │
│  │  • _system/tokens.json sur S3                              │  │
│  │  • Même TokenService que Live Memory                       │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────┬───────────────────────────────────┘
                               │
                               ▼
                        S3 Dell ECS
                        Bucket : vault
```

### 2.2 Composants

| Composant                | Rôle                                             | Technologie                    |
| ------------------------ | ------------------------------------------------ | ------------------------------ |
| **WAF Caddy+Coraza**    | TLS, rate limiting, OWASP CRS, reverse proxy    | Caddy + plugin Coraza          |
| **AdminMiddleware**      | Console admin web + API REST admin               | ASGI middleware (starter-kit)  |
| **HealthCheckMiddleware**| Health check HTTP (/health, /healthz, /ready)    | ASGI middleware                |
| **AuthMiddleware**       | Auth Bearer Token + space access + ContextVar    | ASGI middleware (starter-kit)  |
| **LoggingMiddleware**    | Logging requêtes + ring buffer mémoire           | ASGI middleware (starter-kit)  |
| **Outils MCP**           | Façade MCP (20 outils)                           | FastMCP (starter-kit)          |
| **hvac client**          | Client Python vers OpenBao                       | `hvac` library                 |
| **OpenBao process**      | Moteur de secrets (chiffrement, policies, audit) | Binaire `bao` (Go, embedded)   |
| **S3 Sync Manager**      | Synchronisation storage local ↔ S3               | boto3 + tar/gzip               |
| **Token Manager**        | Gestion des tokens MCP, cache mémoire TTL 5min  | JSON sur S3 (starter-kit)      |

### 2.3 Pile middleware ASGI

L'application MCP Vault est assemblée en 5 couches ASGI, empilées de l'extérieur
vers l'intérieur. Chaque couche intercepte les requêtes avant de les passer à la suivante :

```
AdminMiddleware → HealthCheckMiddleware → AuthMiddleware → LoggingMiddleware → FastMCP
```

| Couche (ext → int)         | Intercepte                          | Passe au suivant si        |
| -------------------------- | ----------------------------------- | -------------------------- |
| **AdminMiddleware**        | `/admin`, `/admin/static/*`, `/admin/api/*` | Pas un chemin admin  |
| **HealthCheckMiddleware**  | `/health`, `/healthz`, `/ready`     | Pas un chemin health       |
| **AuthMiddleware**         | Toutes les requêtes MCP             | Token valide → ContextVar  |
| **LoggingMiddleware**      | Toutes les requêtes                 | Log + ring buffer 200 ent. |
| **FastMCP app**            | MCP Protocol (Streamable HTTP)      | —                          |

**Assemblage dans `create_app()`** (identique au pattern MCP Tools) :

```python
def create_app():
    from .auth.middleware import AuthMiddleware, LoggingMiddleware
    from .admin.middleware import AdminMiddleware

    app = mcp.streamable_http_app()       # FastMCP (innermost)
    app = LoggingMiddleware(app)           # Logging + ring buffer
    app = AuthMiddleware(app)              # Auth Bearer + ContextVar
    app = HealthCheckMiddleware(app)       # /health, /healthz, /ready
    app = AdminMiddleware(app, mcp)        # /admin (outermost)

    return app
```

**HealthCheckMiddleware** — Middleware ASGI dédié qui intercepte les endpoints
de health check et retourne un JSON directement, **sans passer par MCP** ni par
l'auth. Ceci permet au WAF/load balancer de vérifier l'état du service :

```json
{"status": "healthy", "service": "mcp-vault", "version": "0.2.1", "transport": "streamable-http"}
```

**AuthMiddleware + ContextVar** — Le middleware stocke les infos du token
authentifié dans un `contextvars.ContextVar` Python, accessible ensuite par
chaque outil MCP via `check_access()`, `check_write()`, `check_admin()`.
Ce mécanisme est **request-scoped** (isolé par requête, thread-safe en asyncio).

**LoggingMiddleware + Ring Buffer** — Chaque requête HTTP est loguée dans un
**ring buffer mémoire** (200 entrées par défaut) contenant : méthode, path,
status code, durée. Ce buffer alimente la vue "Activité" de la console admin
(auto-refresh 5s).

### 2.4 Console d'administration Web (`/admin`)

MCP Vault inclut une **interface web d'administration** accessible sur `/admin`,
reprenant les codes graphiques de **Cloud Temple** (dark theme #0f0f23, accent teal #41a890).
Pattern identique à MCP Tools, adapté au contexte Vault.

#### Architecture

```
AdminMiddleware (ASGI, outermost)
    │
    ├── GET /admin           → SPA HTML (admin.html)
    ├── GET /admin/static/*  → fichiers statiques (CSS, JS, images)
    └── */admin/api/*        → API REST admin (auth Bearer admin requise)
            │
            ├── GET  /admin/api/health          → état du serveur + OpenBao status
            ├── GET  /admin/api/spaces          → lister les espaces vault
            ├── POST /admin/api/spaces          → créer un espace
            ├── GET  /admin/api/tokens          → lister les tokens S3
            ├── POST /admin/api/tokens          → créer un token
            ├── GET  /admin/api/tokens/{name}   → info d'un token
            ├── DELETE /admin/api/tokens/{name}  → révoquer un token
            └── GET  /admin/api/logs            → activité récente (ring buffer 200)
```

#### 4 vues

| Vue           | Description                                                                                                      |
| ------------- | ---------------------------------------------------------------------------------------------------------------- |
| **Dashboard** | État du serveur (version, OpenBao sealed/unsealed, S3 sync status, last sync, spaces count), stats tokens        |
| **Spaces**    | Grille des espaces vault avec nombre de secrets, tags, date de création. Clic = détail des clés (pas les valeurs)|
| **Tokens**    | Table CRUD : créer (checkboxes space_ids, permissions), info, révoquer. Token brut affiché une seule fois        |
| **Activité**  | Logs temps réel (ring buffer mémoire 200 entrées, auto-refresh 5s). Méthode, path, status, durée                |

#### Sécurité de la console admin

- **Authentification admin** : seul le `ADMIN_BOOTSTRAP_KEY` ou un token S3 avec permission `admin` donne accès à l'API
- **HTML/CSS/JS publics** : la page de login est servie sans auth (l'auth se fait côté API)
- **CORS preflight** : OPTIONS géré pour les appels AJAX cross-origin
- **Path traversal** : protection contre les `../` dans les chemins statiques

---

## 3. Espaces Vault

### 3.1 Concept

Les espaces vault sont **organisés librement par l'utilisateur**, indépendamment des missions. Un espace regroupe des secrets liés à un même contexte (serveur, application, environnement...).

```
Espace "serveurs-prod"           → Clés SSH, passwords des serveurs de production
Espace "bdd-prod"                → Credentials des bases de données de production
Espace "monitoring"              → Tokens API des outils de monitoring
Espace "certificats"             → Certificats TLS, CA
Espace "ci-cd"                   → Tokens de déploiement, registries
Espace "client-alpha-staging"    → Secrets d'un client en staging
```

### 3.2 Liaison Mission ↔ Espaces Vault

Les missions **consomment** les espaces vault, elles ne les créent pas :

```
Mission "MAJ serveur web-prod-01"
  vault_spaces: ["serveurs-prod"]
  → L'agent SRE accède à serveurs-prod/ssh-key-web-prod-01

Mission "Audit sécurité application"
  vault_spaces: ["serveurs-prod", "monitoring"]
  → L'agent Security accède aux deux espaces

Mission "Migration BDD"
  vault_spaces: ["bdd-prod", "bdd-staging"]
  → L'agent DBA accède aux deux espaces
```

Le token MCP de l'agent est configuré avec les `space_ids` autorisés.

### 3.3 Implémentation OpenBao

Chaque espace = un **mount point KV v2** dans OpenBao :

```
vault_space_create("serveurs-prod")
  → hvac.sys.enable_secrets_engine("kv", path="spaces/serveurs-prod/kv", options={"version": "2"})

vault_space_delete("serveurs-prod")
  → hvac.sys.disable_secrets_engine("spaces/serveurs-prod/kv")

secret_store("serveurs-prod", "ssh-key-web-prod-01", value="...")
  → hvac.secrets.kv.v2.create_or_update_secret(
      mount_point="spaces/serveurs-prod/kv",
      path="ssh-key-web-prod-01",
      secret={"value": "...", "type": "ssh_private_key"}
    )

secret_get("serveurs-prod", "ssh-key-web-prod-01")
  → hvac.secrets.kv.v2.read_secret_version(
      mount_point="spaces/serveurs-prod/kv",
      path="ssh-key-web-prod-01"
    )
```

---

## 4. Persistance et Synchronisation S3

### 4.1 Problème : le crash brutal

Si le MCP Vault meurt brutalement (kill -9, OOM, panne machine), il n'y a
pas d'arret propre : pas de seal, pas de push S3. Le storage local contient
la donnee la plus recente et elle serait perdue si on n'utilisait que /tmp.

### 4.2 Solution : double persistance (volume Docker + S3)

```
+-------------------------------------------------------------------+
|                    DOUBLE PERSISTANCE                             |
|                                                                   |
|  Volume Docker (/data/openbao/)                                   |
|  = Persistance LOCALE                                             |
|  = Survit aux crash de container (kill -9, OOM, restart)          |
|  = NE survit PAS a la perte de la machine                         |
|                                                                   |
|  S3 (vault-bucket/_storage/)                                      |
|  = Persistance DISTANTE (3AZ)                                     |
|  = Survit a tout (perte machine, perte disque, panne DC)          |
|  = Sync periodique (toutes les N secondes apres chaque ecriture)  |
+-------------------------------------------------------------------+
```

Le File storage OpenBao pointe sur un **volume Docker persistant** (pas /tmp).
Le S3 sert de **backup distant** synchronise regulierement.

### 4.3 Strategies de sync S3

Trois niveaux de protection, configurables :

| Strategie | Quand | Perte max en cas de crash | Cout |
|-----------|-------|---------------------------|------|
| **write-through** | Apres chaque secret_store/rotate/delete | 0 | Eleve (1 upload S3 par ecriture) |
| **periodic** (defaut) | Toutes les N secondes (defaut 60s) | N secondes | Modere |
| **lazy** | Toutes les N minutes (defaut 5min) | N minutes | Faible |

Recommandation : **periodic** a 60 secondes pour un bon compromis.

### 4.4 Cycle de vie complet

```
DEMARRAGE (startup)
  |
  +-- 1. Verifier si le volume Docker /data/openbao/ contient des donnees
  |     -> Si oui : le volume local EST la source de verite (crash precedent)
  |        Comparer le timestamp local vs S3 (sync_meta.json)
  |        Si local plus recent -> utiliser le local (le S3 est en retard)
  |        Si S3 plus recent   -> telecharger S3 (cas rare : restore manuel)
  |     -> Si non (volume vide) : telecharger depuis S3 si disponible
  |     -> Si rien nulle part  : premiere fois, repertoire vide
  |
  +-- 2. Ecrire la config OpenBao (openbao.hcl)
  |     -> File storage pointant sur /data/openbao/
  |     -> Listener TCP localhost:8200 (pas de TLS interne)
  |     -> Audit file device
  |
  +-- 3. Demarrer le process OpenBao (subprocess)
  |     -> bao server -config=/data/openbao.hcl
  |
  +-- 4. Attendre que OpenBao soit pret (health check)
  |
  +-- 5. Unseal
  |     -> Si premiere fois : bao operator init + bao operator unseal
  |     -> Si existant : bao operator unseal (avec les shares stockees en env)
  |
  +-- 6. MCP Vault est pret a servir

OPERATIONS NORMALES
  |
  +-- Les outils MCP appellent OpenBao via hvac
  |
  +-- Apres chaque ecriture (secret_store, rotate, delete, space_create/delete) :
  |   -> Mettre a jour le timestamp local dans /data/openbao/sync_marker
  |
  +-- Sync S3 periodique (boucle asyncio, toutes les S3_SYNC_INTERVAL secondes) :
      -> Si sync_marker change depuis le dernier sync :
         tar + gzip /data/openbao/ -> upload S3
         Mettre a jour sync_meta.json sur S3
         Log : "S3 sync completed (delta: Xs)"
      -> Si pas de changement : skip (pas d'upload inutile)

ARRET PROPRE (SIGTERM)
  |
  +-- 1. Arreter d'accepter les requetes MCP
  +-- 2. Sync S3 final (upload)
  +-- 3. Seal OpenBao : bao operator seal
  +-- 4. Arreter le process OpenBao
  +-- 5. Le volume Docker reste intact (pour le prochain demarrage)
  +-- 6. Shutdown MCP Vault

CRASH BRUTAL (kill -9, OOM, panne)
  |
  +-- Le volume Docker /data/openbao/ survit
  +-- Au redemarrage :
      -> Le volume contient le storage le plus recent
      -> OpenBao redemarre et unseal depuis ce volume
      -> Sync S3 reprend normalement
      -> Perte = 0 (tout est sur le volume)
  |
  +-- Si perte de la MACHINE (pas juste du container) :
      -> Le volume Docker est perdu
      -> Au redemarrage sur une autre machine :
         -> Telecharge depuis S3
         -> Perte max = S3_SYNC_INTERVAL secondes

RESTAURATION MANUELLE (optionnel)
  |
  +-- Un admin peut forcer un restore depuis S3 :
      admin_vault_restore_from_s3()
      -> Telecharge S3 -> ecrase le volume local -> restart OpenBao
```

### 4.5 Config OpenBao generee

```hcl
# /data/openbao.hcl (genere par le MCP Vault au startup)
storage "file" {
  path = "/data/openbao/storage"
}

listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = 1
}

disable_mlock = true
api_addr      = "http://127.0.0.1:8200"
ui            = false
```

### 4.6 Docker Compose (avec WAF)

```yaml
# docker-compose.yml
services:
  # --- WAF (point d'entrée externe) ---
  waf:
    build: ./waf
    ports:
      - "${WAF_PORT:-8082}:8082"
    depends_on:
      - mcp-vault
    networks:
      - mcp-net
    restart: unless-stopped

  # --- MCP Vault (réseau interne uniquement) ---
  mcp-vault:
    build: .
    expose:
      - "8030"                        # PAS de ports: → pas accessible directement
    env_file: .env
    volumes:
      - vault-data:/data/openbao      # Volume persistant OpenBao
    networks:
      - mcp-net
    restart: unless-stopped

networks:
  mcp-net:
    driver: bridge

volumes:
  vault-data:                          # Survit aux crash de container
```

**Important** : Le service `mcp-vault` utilise `expose` (pas `ports`) — il n'est
**pas** accessible directement depuis l'extérieur. Tout le trafic passe par le WAF
sur le port configurable `WAF_PORT` (défaut 8082).

Le WAF (Caddy + Coraza) gère :
- **TLS termination** (HTTPS)
- **Rate limiting** (protection DDoS)
- **OWASP CRS** (règles anti-injection, XSS, etc.)
- **Reverse proxy** vers `mcp-vault:8030`

---

## 5. Modèle de données S3

```
vault-bucket/
├── _system/
│   └── tokens.json              # Tokens d'auth MCP Vault (starter-kit standard)
│
├── _storage/
│   ├── openbao-data.tar.gz      # Storage OpenBao compressé (tout le File backend)
│   └── sync_meta.json           # {last_sync: "2026-03-04T09:30:00Z", size_bytes: 12345}
│
├── _init/
│   └── init_output.json.enc     # Sortie de `bao operator init` (chiffrée)
│                                 # Contient unseal keys + root token
│                                 # Chiffré avec ADMIN_BOOTSTRAP_KEY
│
└── _meta.json                   # {version: "0.2.0", created_at: "...", spaces_count: 5}
```

**Note** : Les secrets eux-mêmes ne sont PAS directement sur S3 en clair. Ils sont dans `openbao-data.tar.gz` qui contient le File storage OpenBao, chiffré par la barrier encryption d'OpenBao (XChaCha20-Poly1305). Sans les unseal keys, les données sont illisibles.

---

## 6. Outils MCP

### 6.1 Espaces

| Outil                                               | Perm  | Description                                            |
| --------------------------------------------------- | ----- | ------------------------------------------------------ |
| `vault_space_create(space_id, description?, tags?)` | admin | Crée un espace (mount point KV v2 dans OpenBao)        |
| `vault_space_list()`                                | read  | Liste les espaces accessibles (filtrés par token)      |
| `vault_space_info(space_id)`                        | read  | Détails d'un espace (nombre de secrets, date création) |
| `vault_space_delete(space_id)`                      | admin | Supprime un espace et tous ses secrets                 |

### 6.2 Secrets

| Outil                                                            | Perm  | Description                                         |
| ---------------------------------------------------------------- | ----- | --------------------------------------------------- |
| `secret_store(space_id, key, value, type?, description?, tags?)` | write | Stocker un secret (nouvelle version si existe déjà) |
| `secret_get(space_id, key, version?)`                            | read  | Récupérer un secret (dernière version par défaut)   |
| `secret_list(space_id, prefix?)`                                 | read  | Lister les clés d'un espace (pas les valeurs !)     |
| `secret_delete(space_id, key)`                                   | admin | Supprimer un secret (toutes les versions)           |
| `secret_rotate(space_id, key, new_value)`                        | write | Rotation : crée une nouvelle version                |

### 6.3 SSH Certificate Authority

| Outil                                              | Perm  | Description                                                  |
| -------------------------------------------------- | ----- | ------------------------------------------------------------ |
| `ssh_sign_key(public_key, valid_principals, ttl?)` | write | Signe une clé publique SSH → retourne un certificat éphémère |

### 6.4 Policies OpenBao

| Outil                                   | Perm  | Description                                     |
| --------------------------------------- | ----- | ----------------------------------------------- |
| `policy_create(policy_id, hcl_content)` | admin | Créer/mettre à jour une policy HCL dans OpenBao |
| `policy_list()`                         | admin | Lister les policies                             |
| `policy_delete(policy_id)`              | admin | Supprimer une policy                            |

### 6.5 Tokens MCP

| Outil                                                                        | Perm  | Description                |
| ---------------------------------------------------------------------------- | ----- | -------------------------- |
| `admin_create_token(client_name, permissions, space_ids?, expires_in_days?)` | admin | Créer un token d'accès MCP |
| `admin_list_tokens()`                                                        | admin | Lister les tokens          |
| `admin_revoke_token(token_prefix)`                                           | admin | Révoquer un token          |
| `admin_update_token(token_prefix, space_ids?, permissions?)`                 | admin | Modifier un token          |

### 6.6 Audit & Système

| Outil                                       | Perm   | Description                                                       |
| ------------------------------------------- | ------ | ----------------------------------------------------------------- |
| `audit_log(last_n?, space_id?, operation?)` | admin  | Journal d'audit (depuis l'audit device OpenBao)                   |
| `system_health`                             | public | État de santé (OpenBao sealed/unsealed, S3 accessible, last sync) |
| `system_about`                              | public | Version, nombre d'espaces, nombre de secrets, uptime              |

**Total : 20 outils MCP**

---

## 7. SSH Certificate Authority

### 7.1 Concept

Au lieu de stocker des clés SSH privées et les distribuer aux agents (risqué), le vault **signe des clés publiques** avec un certificat SSH éphémère :

```
L'agent MCP veut accéder à un serveur :

1. L'agent génère une paire de clés éphémère (en mémoire)
2. L'agent envoie la clé publique au MCP Vault :
   → ssh_sign_key(public_key="ssh-ed25519 AAAA...", 
                   valid_principals="deploy", 
                   ttl="5m")
3. Le MCP Vault signe via OpenBao SSH CA :
   → Retourne un certificat SSH valide 5 minutes
4. L'agent utilise la clé privée + certificat pour SSH
5. Après 5 minutes, le certificat est invalide → rien à nettoyer

Prérequis : le serveur cible doit faire confiance à la CA du vault
  → TrustedUserCAKeys /etc/ssh/trusted-ca.pub
```

### 7.2 Setup initial

```python
# Activer le SSH secret engine
hvac.sys.enable_secrets_engine("ssh", path="ssh")

# Configurer la CA
hvac.secrets.ssh.create_ca(generate_signing_key=True)

# Récupérer la clé publique de la CA (à déployer sur les serveurs)
ca_public_key = hvac.secrets.ssh.read_ca()
# → À mettre dans /etc/ssh/trusted-ca.pub sur chaque serveur

# Créer un rôle pour les agents SRE
hvac.secrets.ssh.create_role(
    name="sre-role",
    key_type="ca",
    allowed_users="deploy,admin",
    default_user="deploy",
    ttl="5m",
    max_ttl="30m",
    allow_user_certificates=True
)
```

---

## 8. Démarrage et Unseal

### 8.1 Première exécution (init)

```python
async def first_time_init(self):
    """Première exécution : init OpenBao et sauvegarder les clés."""
    # 1. Init OpenBao
    init_result = self.hvac.sys.initialize(
        secret_shares=1,      # Simplifié : 1 share = 1 unseal key
        secret_threshold=1
    )
    
    # 2. Sauvegarder les clés (chiffrées avec ADMIN_BOOTSTRAP_KEY)
    init_data = {
        "unseal_key": init_result["keys"][0],
        "root_token": init_result["root_token"]
    }
    encrypted = encrypt_with_bootstrap_key(json.dumps(init_data))
    await s3.put("_init/init_output.json.enc", encrypted)
    
    # 3. Unseal
    self.hvac.sys.submit_unseal_key(init_result["keys"][0])
    
    # 4. Configurer l'audit device
    self.hvac.sys.enable_audit_device(
        device_type="file",
        options={"file_path": "/tmp/openbao-audit.log"}
    )
    
    # 5. Activer SSH CA
    self.hvac.sys.enable_secrets_engine("ssh", path="ssh")
    self.hvac.secrets.ssh.create_ca(generate_signing_key=True)
```

### 8.2 Exécutions suivantes (unseal)

```python
async def unseal_from_s3(self):
    """Charge les clés depuis S3 et unseal."""
    encrypted = await s3.get("_init/init_output.json.enc")
    init_data = json.loads(decrypt_with_bootstrap_key(encrypted))
    
    self.hvac.sys.submit_unseal_key(init_data["unseal_key"])
    self.hvac.token = init_data["root_token"]
```

**Note** : L'unseal key est chiffrée avec la `ADMIN_BOOTSTRAP_KEY` (variable d'env) avant stockage sur S3. Sans cette clé, impossible d'unseal.

---

## 9. Configuration (.env)

```env
# --- MCP Vault ---
MCP_SERVER_NAME=mcp-vault
MCP_SERVER_PORT=8030

# --- WAF ---
WAF_PORT=8082                    # Port d'écoute externe du WAF Caddy+Coraza

# --- Auth MCP ---
ADMIN_BOOTSTRAP_KEY=change_me_to_a_strong_random_key_64chars

# --- OpenBao ---
OPENBAO_BINARY=/usr/local/bin/bao
OPENBAO_DATA_DIR=/data/openbao        # Volume Docker persistant
OPENBAO_LISTEN_ADDRESS=127.0.0.1:8200
OPENBAO_LOG_LEVEL=warn

# --- S3 (stockage du File backend + tokens MCP) ---
S3_ENDPOINT_URL=https://your-endpoint.s3.fr1.cloud-temple.com
S3_ACCESS_KEY_ID=AKIA_YOUR_KEY
S3_SECRET_ACCESS_KEY=your_secret
S3_BUCKET_NAME=vault
S3_REGION_NAME=fr1

# --- S3 Sync ---
S3_SYNC_INTERVAL=60              # Sync toutes les 60 secondes (periodic)
S3_SYNC_STRATEGY=periodic        # periodic | write-through | lazy
S3_SYNC_ON_SHUTDOWN=true         # Upload au shutdown (arret propre)

# --- SSH CA ---
SSH_CA_ENABLED=true
SSH_CA_DEFAULT_TTL=5m
SSH_CA_MAX_TTL=30m
```

---

## 10. Structure fichiers (starter-kit)

```
mcp-vault/
├── src/mcp_vault/
│   ├── __init__.py
│   ├── __main__.py            # python -m mcp_vault
│   ├── server.py              # 20 outils MCP + create_app() + HealthCheckMiddleware + bannière
│   ├── config.py              # Config Pydantic-settings (S3, OpenBao, sync, WAF)
│   ├── admin/                 # Console d'administration web (/admin)
│   │   ├── __init__.py
│   │   ├── middleware.py      # AdminMiddleware ASGI (static + API routing + CORS)
│   │   └── api.py             # REST API admin (8 endpoints)
│   ├── auth/                  # Auth standard (starter-kit)
│   │   ├── __init__.py
│   │   ├── middleware.py      # AuthMiddleware (Bearer + ContextVar) + LoggingMiddleware (ring buffer)
│   │   ├── context.py         # check_access, check_write, check_admin via ContextVar
│   │   └── token_store.py     # Token Store S3 + cache mémoire TTL 5min
│   ├── static/                # Fichiers statiques admin (SPA)
│   │   ├── admin.html         # SPA HTML (login + 4 vues : Dashboard, Spaces, Tokens, Activité)
│   │   ├── css/
│   │   │   └── admin.css      # Design Cloud Temple (dark theme #0f0f23, accent #41a890)
│   │   ├── js/                # Modules JS (config, api, app, dashboard, spaces, tokens, logs)
│   │   └── img/
│   │       └── logo-cloudtemple.svg
│   └── core/
│       ├── __init__.py
│       ├── openbao.py         # OpenBaoManager : start, stop, unseal, init
│       ├── vault_service.py   # VaultService : CRUD secrets via hvac
│       ├── space_service.py   # SpaceService : CRUD espaces (mount points)
│       ├── ssh_service.py     # SSHService : CA, sign_key
│       ├── policy_service.py  # PolicyService : CRUD policies HCL
│       ├── s3_sync.py         # S3SyncManager : download, upload, periodic
│       ├── audit_service.py   # AuditService : parse audit log
│       ├── storage.py         # Service S3 (tokens MCP + sync storage)
│       └── models.py          # Pydantic: Space, Secret, Policy, SyncMeta
├── waf/                       # WAF Caddy + Coraza
│   ├── Caddyfile              # Config reverse proxy + OWASP CRS
│   └── Dockerfile             # Image Caddy avec plugin Coraza
├── scripts/
│   ├── mcp_cli.py             # Point d'entrée CLI
│   └── cli/
│       ├── __init__.py
│       ├── client.py          # Client MCP Streamable HTTP
│       ├── commands.py        # CLI Click (vault-space, secret, ssh, admin, audit)
│       ├── shell.py           # Shell interactif
│       └── display.py         # Affichage Rich
├── Dockerfile                 # Python 3.11 + binaire OpenBao
├── docker-compose.yml         # WAF + mcp-vault + volume + réseau
├── requirements.txt
├── .env.example
└── VERSION
```

### 10.1 Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Installer OpenBao
ARG OPENBAO_VERSION=2.1.0
RUN apt-get update && apt-get install -y wget unzip && \
    wget -q https://github.com/openbao/openbao/releases/download/v${OPENBAO_VERSION}/bao_${OPENBAO_VERSION}_linux_amd64.zip && \
    unzip bao_${OPENBAO_VERSION}_linux_amd64.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/bao && \
    rm bao_${OPENBAO_VERSION}_linux_amd64.zip && \
    apt-get remove -y wget unzip && apt-get autoremove -y

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application
COPY src/ src/
COPY scripts/ scripts/
COPY VERSION .

# Sécurité : utilisateur non-root
# Le volume /data/openbao est monté via docker-compose (persistance)
RUN useradd -r -u 10001 -s /bin/false mcp && \
    mkdir -p /data/openbao && \
    chown -R mcp:mcp /data/openbao
USER mcp

EXPOSE 8030

CMD ["python", "-m", "mcp_vault"]
```

### 10.2 requirements.txt

```
mcp[cli]>=1.8.0
uvicorn>=0.32.0
pydantic>=2.0
pydantic-settings>=2.0
boto3>=1.34
hvac>=2.0
click>=8.1
prompt-toolkit>=3.0
rich>=13.0
httpx>=0.27
python-dotenv>=1.0
```

---

## 11. Sécurité

### 11.1 Couches de protection

```
Couche 1 : WAF (Caddy + Coraza)       — TLS termination, rate limiting, OWASP CRS
Couche 2 : AdminMiddleware             — Console admin isolée, CORS preflight, path traversal
Couche 3 : HealthCheckMiddleware       — /health sans auth (pour WAF/load balancer)
Couche 4 : AuthMiddleware + ContextVar — Bearer Token + permissions + space_ids, request-scoped
Couche 5 : LoggingMiddleware           — Audit trail HTTP (ring buffer 200 entrées)
Couche 6 : OpenBao policies            — HCL fine-grained access control
Couche 7 : OpenBao barrier             — XChaCha20-Poly1305 encryption at rest
Couche 8 : Seal/Unseal                 — Sans les unseal keys, les données sont illisibles
Couche 9 : S3                          — Données chiffrées par OpenBao avant écriture (3AZ)
```

### 11.2 Détails des mécanismes de sécurité applicatifs

**ContextVar (request-scoped auth)** — Le middleware `AuthMiddleware` valide le
Bearer token et stocke les informations d'identité (client_name, permissions,
space_ids) dans un `contextvars.ContextVar`. Chaque outil MCP appelle ensuite
`check_access(space_id)` qui lit cette variable. Le mécanisme est :
- **Thread-safe** en asyncio (isolé par tâche)
- **Request-scoped** (pas de fuite entre requêtes)
- **Zéro couplage** entre le middleware et les outils (pas de passage de paramètre)

**Token Store S3 + cache TTL 5min** — Les tokens MCP sont stockés sur S3
(`_system/tokens.json`). Au démarrage, `init_token_store()` charge tous les tokens.
Un cache mémoire avec TTL de 5 minutes évite de relire S3 à chaque requête.
Les opérations admin (create/revoke) invalident le cache immédiatement.

**CORS preflight** — L'AdminMiddleware gère les requêtes OPTIONS pour permettre
les appels AJAX cross-origin depuis la console admin SPA. Les headers
`Access-Control-Allow-*` sont injectés.

**Path traversal** — L'AdminMiddleware protège le service de fichiers statiques
contre les attaques `../` dans les chemins. Les chemins sont normalisés et
validés avant lecture sur le filesystem.

**Service non exposé** — Le MCP Vault utilise `expose` (pas `ports`) dans le
docker-compose. Il n'est pas directement accessible depuis l'extérieur.
Tout le trafic passe par le WAF Caddy+Coraza.

### 11.3 Menaces et mitigations

| Menace                           | Mitigation                                                                      |
| -------------------------------- | ------------------------------------------------------------------------------- |
| Vol du bucket S3                 | Les données sont chiffrées par la barrier OpenBao. Sans unseal keys → illisible |
| Compromission du container       | OpenBao sealed au shutdown. Unseal keys chiffrées avec ADMIN_BOOTSTRAP_KEY      |
| Accès non autorisé à un espace   | Tokens MCP avec space_ids + OpenBao policies HCL                                |
| Fuite de la bootstrap key        | Uniquement en variable d'env, jamais sur S3 en clair                            |
| Perte du storage                 | S3 3AZ (répliqué sur 3 zones) + sync toutes les 60s (configurable)             |
| Agent lit un secret non autorisé | Token MCP scopé (ContextVar) + OpenBao policy par rôle                         |
| Audit trail altéré               | File audit device OpenBao (non modifiable par les outils MCP)                   |
| XSS/injection sur la console     | WAF OWASP CRS + console admin SPA (pas de SSR) + CORS strict                  |
| Path traversal via /admin/static | AdminMiddleware normalise les chemins, bloque `../`                             |
| DDoS sur le service              | WAF Caddy rate limiting + service non exposé directement                        |

### 11.4 Recommandations production

| Recommandation                                                | Priorité     |
| ------------------------------------------------------------- | ------------ |
| ADMIN_BOOTSTRAP_KEY ≥ 64 caractères aléatoires                | 🔴 Critique |
| TLS via WAF (HTTPS)                                           | 🔴 Critique |
| WAF_PORT non accessible publiquement (réseau privé)           | 🔴 Critique |
| Rotation périodique des secrets                               | 🟠 Élevée   |
| Monitoring des seal/unseal events                             | 🟡 Moyenne  |
| Backup S3 séparé du bucket vault                              | 🟡 Moyenne  |
| Shamir secret sharing (5 shares, threshold 3) pour production | 🟡 Moyenne  |
| Monitoring de la console admin (logs d'accès)                 | 🟡 Moyenne  |

---

## 12. Exemple d'utilisation

### 12.1 Setup initial (admin)

```bash
# CLI : créer le premier token admin
python scripts/mcp_cli.py --token $ADMIN_BOOTSTRAP_KEY admin create-token \
  --name "vault-admin" --permissions admin

# CLI : créer un espace pour les serveurs de prod
python scripts/mcp_cli.py vault-space create serveurs-prod \
  --description "Clés SSH et passwords des serveurs de production"

# CLI : stocker une clé SSH
python scripts/mcp_cli.py secret store serveurs-prod ssh-key-web-prod-01 \
  --value "$(cat ~/.ssh/id_ed25519)" --type ssh_private_key

# CLI : créer un token pour le MCP Agent (lecture seule, espace serveurs-prod)
python scripts/mcp_cli.py admin create-token \
  --name "mcp-agent-sre" --permissions read --space-ids serveurs-prod
```

### 12.2 Utilisation par un agent (via MCP)

```python
# L'agent (via MCP Agent → MCP Vault) récupère un secret :
result = await vault_client.call("secret_get", {
    "space_id": "serveurs-prod",
    "key": "ssh-key-web-prod-01"
})
# → {"status": "ok", "key": "ssh-key-web-prod-01", 
#    "value": "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
#    "version": 3, "type": "ssh_private_key"}

# Ou mieux — signer une clé SSH éphémère :
result = await vault_client.call("ssh_sign_key", {
    "public_key": agent_public_key,
    "valid_principals": "deploy",
    "ttl": "5m"
})
# → {"status": "ok", "signed_key": "ssh-ed25519-cert-v01@openssh.com AAAA...",
#    "ttl": "5m", "serial_number": "abc123"}
```

---

*Document réécrit le 8 mars 2026 — MCP Vault v0.2.1-draft (aligné innovations MCP Tools : middleware ASGI 5 couches, console admin web, WAF docker-compose, ContextVar, token cache TTL, ring buffer)*
