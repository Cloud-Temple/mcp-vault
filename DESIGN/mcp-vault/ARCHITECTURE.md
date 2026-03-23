# Architecture — MCP Vault

> **Version** : 0.2.0 | **Date** : 2026-03-22 | **Auteur** : Cloud Temple  
> **Projet** : mcp-vault | **Licence** : Apache 2.0  
> **Statut** : 📐 Design — non implémenté

---

## 1. Vision

**MCP Vault** est un serveur MCP qui fournit une **gestion sécurisée de secrets** pour les agents IA et les missions. Il embarque **OpenBao** (fork open-source de HashiCorp Vault, Linux Foundation) comme moteur de chiffrement et de gestion des secrets.

### Principes

1. **OpenBao embedded** — Le binaire OpenBao tourne en process intégré, pas comme service séparé
2. **Vaults libres** — L'utilisateur organise ses secrets par serveur, application, groupe... comme il veut
3. **Même pattern que Live Memory** — Tokens Bearer, `allowed_resources`, `check_access()`, starter-kit
4. **S3 comme source de vérité** — Le storage OpenBao est synchronisé avec S3 (download au start, upload au stop)
5. **Missions découplées** — Les vaults sont indépendants des missions. On donne à la mission le vault à utiliser.
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
│       WAF Caddy + Coraza (:8085, configurable WAF_PORT)         │
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
│  │  AuthMiddleware         → Bearer Token + vault_ids         │  │
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
│  │  24 Outils MCP (façade)                                    │  │
│  │                                                            │  │
│  │  Vaults :  vault_create, _list, _info, _update, _delete    │  │
│  │  Secrets : secret_write, _read, _list, _delete             │  │
│  │  Types :   secret_types, secret_generate_password          │  │
│  │  SSH CA :  ssh_ca_setup, _sign_key, _public_key,           │  │
│  │            _list_roles, _role_info                         │  │
│  │  Policies: policy_create, _list, _get, _delete             │  │
│  │  Token :   token_update                                    │  │
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
│  │    /vaults/{vault_id}/kv/      ← KV v2 par vault           │  │
│  │    /ssh-ca-{vault_id}/         ← SSH CA par vault (isolée) │  │
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

| Composant                 | Rôle                                             | Technologie                   |
| ------------------------- | ------------------------------------------------ | ----------------------------- |
| **WAF Caddy+Coraza**      | TLS, rate limiting, OWASP CRS, reverse proxy     | Caddy + plugin Coraza         |
| **AdminMiddleware**       | Console admin web + API REST admin               | ASGI middleware (starter-kit) |
| **HealthCheckMiddleware** | Health check HTTP (/health, /healthz, /ready)    | ASGI middleware               |
| **AuthMiddleware**        | Auth Bearer Token + vault access + ContextVar    | ASGI middleware (starter-kit) |
| **LoggingMiddleware**     | Logging requêtes + ring buffer mémoire           | ASGI middleware (starter-kit) |
| **Outils MCP**            | Façade MCP (24 outils)                           | FastMCP (starter-kit)         |
| **hvac client**           | Client Python vers OpenBao                       | `hvac` library                |
| **OpenBao process**       | Moteur de secrets (chiffrement, policies, audit) | Binaire `bao` (Go, embedded)  |
| **S3 Sync Manager**       | Synchronisation storage local ↔ S3               | boto3 + tar/gzip              |
| **Token Manager**         | Gestion des tokens MCP, cache mémoire TTL 5min   | JSON sur S3 (starter-kit)     |

### 2.3 Pile middleware ASGI

L'application MCP Vault est assemblée en 5 couches ASGI, empilées de l'extérieur
vers l'intérieur. Chaque couche intercepte les requêtes avant de les passer à la suivante :

```
AdminMiddleware → HealthCheckMiddleware → AuthMiddleware → LoggingMiddleware → FastMCP
```

| Couche (ext → int)        | Intercepte                                  | Passe au suivant si        |
| ------------------------- | ------------------------------------------- | -------------------------- |
| **AdminMiddleware**       | `/admin`, `/admin/static/*`, `/admin/api/*` | Pas un chemin admin        |
| **HealthCheckMiddleware** | `/health`, `/healthz`, `/ready`             | Pas un chemin health       |
| **AuthMiddleware**        | Toutes les requêtes MCP                     | Token valide → ContextVar  |
| **LoggingMiddleware**     | Toutes les requêtes                         | Log + ring buffer 200 ent. |
| **FastMCP app**           | MCP Protocol (Streamable HTTP)              | —                          |

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
            ├── GET  /admin/api/vaults          → lister les vaults
            ├── POST /admin/api/vaults          → créer un vault
            ├── GET  /admin/api/tokens          → lister les tokens S3
            ├── POST /admin/api/tokens          → créer un token
            ├── GET  /admin/api/tokens/{name}   → info d'un token
            ├── DELETE /admin/api/tokens/{name}  → révoquer un token
            └── GET  /admin/api/logs            → activité récente (ring buffer 200)
```

#### 4 vues

| Vue           | Description                                                                                                |
| ------------- | ---------------------------------------------------------------------------------------------------------- |
| **Dashboard** | État du serveur (version, OpenBao sealed/unsealed, S3 sync status, last sync, vaults count), stats tokens  |
| **Vaults**    | Grille des vaults avec nombre de secrets, tags, date de création. Clic = détail des clés (pas les valeurs) |
| **Tokens**    | Table CRUD : créer (checkboxes vault_ids, permissions), info, révoquer. Token brut affiché une seule fois  |
| **Activité**  | Logs temps réel (ring buffer mémoire 200 entrées, auto-refresh 5s). Méthode, path, status, durée           |

#### Sécurité de la console admin

- **Authentification admin** : seul le `ADMIN_BOOTSTRAP_KEY` ou un token S3 avec permission `admin` donne accès à l'API
- **HTML/CSS/JS publics** : la page de login est servie sans auth (l'auth se fait côté API)
- **CORS preflight** : OPTIONS géré pour les appels AJAX cross-origin
- **Path traversal** : protection contre les `../` dans les chemins statiques

---

## 3. Vaults (coffres de secrets)

### 3.1 Concept

Les vaults sont **organisés librement par l'utilisateur**, indépendamment des missions. Un vault regroupe des secrets liés à un même contexte (serveur, application, environnement...).

```
Vault "serveurs-prod"           → Clés SSH, passwords des serveurs de production
Vault "bdd-prod"                → Credentials des bases de données de production
Vault "monitoring"              → Tokens API des outils de monitoring
Vault "certificats"             → Certificats TLS, CA
Vault "ci-cd"                   → Tokens de déploiement, registries
Vault "client-alpha-staging"    → Secrets d'un client en staging
```

### 3.2 Liaison Mission ↔ Vaults

Les missions **consomment** les vaults, elles ne les créent pas :

```
Mission "MAJ serveur web-prod-01"
  vault_ids: ["serveurs-prod"]
  → L'agent SRE accède à serveurs-prod/ssh-key-web-prod-01

Mission "Audit sécurité application"
  vault_ids: ["serveurs-prod", "monitoring"]
  → L'agent Security accède aux deux espaces

Mission "Migration BDD"
  vault_ids: ["bdd-prod", "bdd-staging"]
  → L'agent DBA accède aux deux espaces
```

Le token MCP de l'agent est configuré avec les `vault_ids` autorisés.

### 3.3 Implémentation OpenBao

Chaque vault = un **mount point KV v2** dans OpenBao :

```
vault_create("serveurs-prod")
  → hvac.sys.enable_secrets_engine("kv", path="vaults/serveurs-prod/kv", options={"version": "2"})

vault_delete("serveurs-prod")
  → hvac.sys.disable_secrets_engine("vaults/serveurs-prod/kv")

secret_store("serveurs-prod", "ssh-key-web-prod-01", value="...")
  → hvac.secrets.kv.v2.create_or_update_secret(
      mount_point="vaults/serveurs-prod/kv",
      path="ssh-key-web-prod-01",
      secret={"value": "...", "type": "ssh_private_key"}
    )

secret_get("serveurs-prod", "ssh-key-web-prod-01")
  → hvac.secrets.kv.v2.read_secret_version(
      mount_point="vaults/serveurs-prod/kv",
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

| Strategie             | Quand                                   | Perte max en cas de crash | Cout                             |
| --------------------- | --------------------------------------- | ------------------------- | -------------------------------- |
| **write-through**     | Apres chaque secret_store/rotate/delete | 0                         | Eleve (1 upload S3 par ecriture) |
| **periodic** (defaut) | Toutes les N secondes (defaut 60s)      | N secondes                | Modere                           |
| **lazy**              | Toutes les N minutes (defaut 5min)      | N minutes                 | Faible                           |

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
  +-- Apres chaque ecriture (secret_store, rotate, delete, vault_create/delete) :
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
      - "${WAF_PORT:-8085}:8085"
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
sur le port configurable `WAF_PORT` (défaut 8085).

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
│   └── init_keys.json.enc       # Clés unseal + root token (chiffrées)
│                                 # Chiffrement : AES-256-GCM
│                                 # Clé dérivée de ADMIN_BOOTSTRAP_KEY via PBKDF2
│                                 # ⚠️ JAMAIS stocké en clair — ni sur S3, ni localement
│                                 # Le fichier local est supprimé après unseal
│
└── _meta.json                   # {version: "0.2.0", created_at: "...", vaults_count: 5}
```

**Séparation données/clés** : Les secrets sont dans `openbao-data.tar.gz` (File storage chiffré par la barrier OpenBao, XChaCha20-Poly1305). Les clés unseal sont dans `_init/init_keys.json.enc` (chiffrées avec ADMIN_BOOTSTRAP_KEY). Sans les **deux** (données + clé de déchiffrement des unseal keys), les secrets sont illisibles. Cette séparation physique garantit qu'un vol du bucket S3 seul est insuffisant sans la `ADMIN_BOOTSTRAP_KEY` (variable d'environnement, jamais sur S3).

---

## 6. Outils MCP

### 6.1 Vaults

| Outil                                         | Perm  | Description                                                   |
| --------------------------------------------- | ----- | ------------------------------------------------------------- |
| `vault_create(vault_id, description?, tags?)` | write | Crée un vault (mount point KV v2) + métadonnées (owner, date) |
| `vault_list()`                                | read  | Liste les vaults accessibles (filtrés par token)              |
| `vault_info(vault_id)`                        | read  | Détails d'un vault (métadonnées, nombre de secrets, owner)    |
| `vault_update(vault_id, description)`         | write | Met à jour la description d'un vault                          |
| `vault_delete(vault_id)`                      | admin | Supprime un vault et tous ses secrets                         |

### 6.2 Secrets

| Outil                                                            | Perm  | Description                                         |
| ---------------------------------------------------------------- | ----- | --------------------------------------------------- |
| `secret_store(vault_id, key, value, type?, description?, tags?)` | write | Stocker un secret (nouvelle version si existe déjà) |
| `secret_get(vault_id, key, version?)`                            | read  | Récupérer un secret (dernière version par défaut)   |
| `secret_list(vault_id, prefix?)`                                 | read  | Lister les clés d'un vault (pas les valeurs !)      |
| `secret_delete(vault_id, key)`                                   | admin | Supprimer un secret (toutes les versions)           |
| `secret_rotate(vault_id, key, new_value)`                        | write | Rotation : crée une nouvelle version                |

### 6.3 SSH Certificate Authority

| Outil                                                                    | Perm  | Description                                                                 |
| ------------------------------------------------------------------------ | ----- | --------------------------------------------------------------------------- |
| `ssh_ca_setup(vault_id, role_name, allowed_users?, default_user?, ttl?)` | write | Configure une CA SSH + rôle dans un vault (crée le mount SSH si inexistant) |
| `ssh_sign_key(vault_id, role_name, public_key, valid_principals?, ttl?)` | read  | Signe une clé publique SSH → retourne un certificat éphémère                |
| `ssh_ca_public_key(vault_id)`                                            | read  | Récupère la clé publique CA (pour `TrustedUserCAKeys` sur les serveurs)     |
| `ssh_ca_list_roles(vault_id)`                                            | read  | Liste les rôles SSH CA configurés dans un vault                             |
| `ssh_ca_role_info(vault_id, role_name)`                                  | read  | Détails d'un rôle (TTL, allowed_users, extensions, etc.)                    |

### 6.4 Policies MCP (contrôle d'accès granulaire)

Les policies MCP permettent de restreindre les outils accessibles et les
permissions par vault, au-delà du système de permissions basique (read/write/admin).
Elles sont stockées sur S3 (`_system/policies.json`) et assignables aux tokens
via un champ `policy_id` (Phase 8b).

| Outil                                                                                | Perm  | Description                                                  |
| ------------------------------------------------------------------------------------ | ----- | ------------------------------------------------------------ |
| `policy_create(policy_id, description?, allowed_tools?, denied_tools?, path_rules?)` | admin | Crée une policy avec règles d'accès aux outils et aux vaults |
| `policy_list()`                                                                      | admin | Liste les policies avec compteurs résumés                    |
| `policy_get(policy_id)`                                                              | admin | Détails complets d'une policy (rules, allowed/denied tools)  |
| `policy_delete(policy_id, confirm)`                                                  | admin | Supprime une policy (irréversible, confirm=True requis)      |

**Modèle de données policy** :

```json
{
  "policy_id": "readonly-ssh",
  "description": "Lecture seule + SSH CA uniquement",
  "allowed_tools": ["system_*", "vault_list", "vault_info", "secret_read", "secret_list", "ssh_*"],
  "denied_tools": ["vault_delete", "secret_write", "secret_delete"],
  "path_rules": [
    {"vault_pattern": "prod-*", "permissions": ["read"]},
    {"vault_pattern": "dev-*", "permissions": ["read", "write"]}
  ],
  "created_at": "2026-03-18T22:00:00+00:00",
  "created_by": "admin"
}
```

**Logique d'évaluation** :

```
1. denied_tools match    → REFUSÉ (toujours prioritaire)
2. allowed_tools vide    → tout autorisé (sauf denied)
3. allowed_tools match   → autorisé
4. Sinon                 → refusé
```

**Wildcards** : les patterns supportent `*` via `fnmatch` Python :
- `"system_*"` → matche `system_health`, `system_about`
- `"ssh_*"` → matche `ssh_ca_setup`, `ssh_sign_key`, `ssh_ca_public_key`, etc.
- `"secret_*"` → matche `secret_write`, `secret_read`, `secret_list`, `secret_delete`

**path_rules** : permissions granulaires par vault pattern :
- `{"vault_pattern": "prod-*", "permissions": ["read"]}` → lecture seule sur les vaults prod
- `{"vault_pattern": "*", "permissions": ["read", "write"]}` → lecture/écriture sur tous les vaults

#### 6.4.1 Catalogue de policies prêtes à l'emploi

Voici des exemples de policies directement utilisables, couvrant les cas d'usage
les plus courants. Chacune peut être créée via `policy_create`.

##### 🔒 `readonly` — Lecture seule complète

Pour les agents ou utilisateurs qui doivent consulter les secrets sans pouvoir
les modifier. Idéal pour les agents d'audit, de monitoring ou de documentation.

```json
{
  "policy_id": "readonly",
  "description": "Lecture seule — aucune modification possible",
  "allowed_tools": [
    "system_*",
    "vault_list", "vault_info",
    "secret_read", "secret_list", "secret_types"
  ],
  "denied_tools": [
    "vault_create", "vault_update", "vault_delete",
    "secret_write", "secret_delete",
    "ssh_ca_setup",
    "policy_*"
  ],
  "path_rules": []
}
```

##### 🔑 `ssh-operator` — Opérateur SSH CA uniquement

Pour les agents SRE/DevOps qui doivent signer des clés SSH mais n'ont pas besoin
d'accéder aux secrets KV. Combine l'accès SSH avec la lecture des secrets de base.

```json
{
  "policy_id": "ssh-operator",
  "description": "Signature SSH CA + lecture secrets — pas de modification",
  "allowed_tools": [
    "system_*",
    "vault_list", "vault_info",
    "secret_read", "secret_list",
    "ssh_ca_setup", "ssh_sign_key", "ssh_ca_public_key",
    "ssh_ca_list_roles", "ssh_ca_role_info"
  ],
  "denied_tools": [
    "vault_delete",
    "secret_delete",
    "policy_*"
  ],
  "path_rules": []
}
```

##### 🏗️ `developer` — Développeur avec écriture

Pour les développeurs qui gèrent leurs propres secrets (API keys, credentials)
mais ne doivent pas pouvoir supprimer des vaults ou modifier les policies.

```json
{
  "policy_id": "developer",
  "description": "Lecture/écriture des secrets — pas de suppression vault ni policy",
  "allowed_tools": [
    "system_*",
    "vault_list", "vault_info", "vault_create",
    "secret_write", "secret_read", "secret_list", "secret_delete",
    "secret_types", "secret_generate_password"
  ],
  "denied_tools": [
    "vault_delete",
    "ssh_ca_setup",
    "policy_*"
  ],
  "path_rules": []
}
```

##### 🏭 `prod-reader-dev-writer` — Lecture prod, écriture dev

Pattern classique séparation prod/dev : les agents peuvent lire les secrets
de production mais ne peuvent écrire que dans les vaults de développement.

```json
{
  "policy_id": "prod-reader-dev-writer",
  "description": "Lecture seule sur prod-*, lecture/écriture sur dev-*",
  "allowed_tools": [
    "system_*",
    "vault_list", "vault_info",
    "secret_write", "secret_read", "secret_list",
    "secret_types", "secret_generate_password"
  ],
  "denied_tools": [
    "vault_delete", "vault_create",
    "policy_*"
  ],
  "path_rules": [
    {"vault_pattern": "prod-*", "permissions": ["read"]},
    {"vault_pattern": "dev-*", "permissions": ["read", "write"]},
    {"vault_pattern": "staging-*", "permissions": ["read", "write"]}
  ]
}
```

##### 🤖 `ci-cd-agent` — Pipeline CI/CD

Pour les pipelines de déploiement automatisé qui doivent lire des secrets
(credentials, certificates) et signer des clés SSH pour le déploiement.

```json
{
  "policy_id": "ci-cd-agent",
  "description": "CI/CD — lecture secrets + signature SSH, pas de modification vault",
  "allowed_tools": [
    "system_health",
    "vault_list", "vault_info",
    "secret_read", "secret_list",
    "ssh_sign_key", "ssh_ca_public_key", "ssh_ca_list_roles"
  ],
  "denied_tools": [
    "vault_create", "vault_update", "vault_delete",
    "secret_write", "secret_delete",
    "ssh_ca_setup",
    "policy_*"
  ],
  "path_rules": [
    {"vault_pattern": "deploy-*", "permissions": ["read"]},
    {"vault_pattern": "ci-*", "permissions": ["read"]}
  ]
}
```

##### 🛡️ `security-auditor` — Auditeur sécurité

Pour les auditeurs qui doivent pouvoir tout lire (y compris les policies et
les rôles SSH) sans pouvoir modifier quoi que ce soit.

```json
{
  "policy_id": "security-auditor",
  "description": "Audit — lecture totale incluant policies et SSH, aucune écriture",
  "allowed_tools": [
    "system_*",
    "vault_list", "vault_info",
    "secret_read", "secret_list", "secret_types",
    "ssh_ca_public_key", "ssh_ca_list_roles", "ssh_ca_role_info",
    "policy_list", "policy_get"
  ],
  "denied_tools": [
    "vault_create", "vault_update", "vault_delete",
    "secret_write", "secret_delete",
    "ssh_ca_setup", "ssh_sign_key",
    "policy_create", "policy_delete"
  ],
  "path_rules": []
}
```

#### 6.4.2 Architecture du PolicyStore

```
┌──────────────────────────────────────────────────────────────┐
│  Policy Store (même pattern que Token Store)                 │
│                                                              │
│  Stockage  : S3 (_system/policies.json)                      │
│  Cache     : mémoire TTL 5 minutes                           │
│  Singleton : init_policy_store() au startup                  │
│  Getter    : get_policy_store()                              │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ Matching (wildcards via fnmatch)                       │  │
│  │                                                        │  │
│  │ is_tool_allowed(policy_id, tool_name) → bool           │  │
│  │  • denied_tools match → False (prioritaire)            │  │
│  │  • allowed_tools vide → True (tout permis)             │  │
│  │  • allowed_tools match → True                          │  │
│  │  • Sinon → False                                       │  │
│  │                                                        │  │
│  │ get_vault_permissions(policy_id, vault_id) → list      │  │
│  │  • Cherche la première path_rule qui matche             │  │
│  │  • Retourne les permissions (ex: ["read", "write"])    │  │
│  │  • Aucune règle → [] (permissions par défaut du token) │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  Enforcement actif (Phase 8b ✅) :                           │
│  • check_policy() dans 15 outils MCP                         │
│  • Champ policy_id dans les tokens MCP                       │
│  • Outil token_update pour assigner/modifier les policies    │
└──────────────────────────────────────────────────────────────┘
```

### 6.5 Tokens MCP

| Outil                                                                        | Perm  | Description                |
| ---------------------------------------------------------------------------- | ----- | -------------------------- |
| `admin_create_token(client_name, permissions, vault_ids?, expires_in_days?)` | admin | Créer un token d'accès MCP |
| `admin_list_tokens()`                                                        | admin | Lister les tokens          |
| `admin_revoke_token(token_prefix)`                                           | admin | Révoquer un token          |
| `admin_update_token(token_prefix, vault_ids?, permissions?)`                 | admin | Modifier un token          |

### 6.6 Token Management

| Outil                                                                  | Perm  | Description                                            |
| ---------------------------------------------------------------------- | ----- | ------------------------------------------------------ |
| `token_update(hash_prefix, policy_id?, permissions?, vaults?)`         | admin | Modifier un token existant (policy, permissions, vaults) |

### 6.7 Audit & Système

| Outil                                                                       | Perm   | Description                                                                    |
| --------------------------------------------------------------------------- | ------ | ------------------------------------------------------------------------------ |
| `audit_log(limit?, client?, vault_id?, tool?, category?, status?, since?)`  | admin  | Journal d'audit MCP avec filtres combinables (ring buffer 5000 + JSONL persistant) |
| `system_health`                                                             | public | État de santé (OpenBao sealed/unsealed, S3 accessible, last sync)              |
| `system_about`                                                              | public | Version, nombre de vaults, nombre de secrets, uptime                           |

> 💡 **Introspection** : l'endpoint `/admin/api/whoami` et la commande CLI `whoami` permettent de vérifier l'identité et les permissions du token courant (client_name, auth_type, permissions, vaults autorisés).

**Total : 24 outils MCP** (5 vaults + 6 secrets + 5 SSH CA + 4 policies + 1 token + 1 audit + 2 system)

#### 6.7.1 Architecture du journal d'audit

Le système d'audit trace **toutes** les opérations MCP, avec double persistance :

```
┌─────────────────────────────────────────────────────────────────┐
│  AUDIT FLOW                                                     │
│                                                                 │
│  Outil MCP                                                      │
│    │                                                            │
│    ├── check_policy() ──× DENIED ──→ log_audit(status="denied") │
│    │                                                            │
│    ├── [logique métier] ──→ résultat                            │
│    │                                                            │
│    └── _r(tool, result) ──→ log_audit(status=result["status"])  │
│              │                                                  │
│              ▼                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  AuditStore (singleton)                                 │    │
│  │                                                         │    │
│  │  ┌──────────────────┐  ┌──────────────────────────┐     │    │
│  │  │ Ring buffer       │  │ Fichier JSONL            │     │    │
│  │  │ 5000 entrées max  │  │ /openbao/logs/           │     │    │
│  │  │ (deque, mémoire)  │  │ audit-mcp.jsonl          │     │    │
│  │  │                   │  │ (append-only, persistant) │     │    │
│  │  │ → Filtrage rapide │  │ → Rechargé au startup    │     │    │
│  │  │ → Stats dashboard │  │ → Survit aux restarts    │     │    │
│  │  └──────────────────┘  └──────────────────────────┘     │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                 │
│  Chaque entrée :                                                │
│  {ts, client, tool, category, vault_id, status, detail, ms}     │
└─────────────────────────────────────────────────────────────────┘
```

**Catégorisation automatique** : basée sur le préfixe du nom d'outil.

| Préfixe    | Catégorie | Icône |
| ---------- | --------- | ----- |
| `system_`  | system    | ⚙️  |
| `vault_`   | vault     | 🏛️  |
| `secret_`  | secret    | 🔑   |
| `ssh_`     | ssh       | 🔏   |
| `policy_`  | policy    | 📋   |
| `token_`   | token     | 🎫   |
| `audit_`   | audit     | 📊   |

**Statuts possibles** : `ok`, `created`, `deleted`, `updated`, `error`, `denied`.

**Filtres combinables** dans `audit_log` : limit, client, vault_id, tool (wildcards), category, status, since (ISO 8601).

**Intégration** :
- Le helper `_r(tool, result)` dans `server.py` appelle `log_audit()` après chaque opération MCP et retourne le résultat inchangé — audit systématique sans modifier la logique métier.
- Les refus de policy (`check_policy()`) génèrent un événement `status="denied"` avant même l'exécution de l'outil.
- La SPA admin affiche les événements en timeline avec stats par catégorie, filtres, séparateurs de date et auto-refresh.
- Le CLI `audit` offre un affichage Rich coloré (table avec icônes par catégorie et statut).

---

## 7. SSH Certificate Authority

### 7.1 Concept — Pourquoi une SSH CA ?

**Le problème** : aujourd'hui, les clés SSH statiques sont déployées sur chaque
serveur (`authorized_keys`). Une seule clé compromis = accès à tous les serveurs,
sans limite de durée, sans audit.

**La solution** : au lieu de distribuer des clés SSH, on déploie une **CA de
confiance** une seule fois sur les serveurs. Ensuite, chaque connexion utilise
un **certificat SSH éphémère** (30 min, 1h...) signé par cette CA.

```
┌──────────────────────────────────────────────────────────────┐
│  AVANT (clés statiques)                                      │
│                                                              │
│  Clé privée ed25519 ────→ authorized_keys sur CHAQUE serveur │
│  • 1 clé compromise = TOUS les serveurs exposés              │
│  • Pas de durée de vie (valide pour toujours)                │
│  • Pas d'audit de qui se connecte avec quel cert             │
│  • Provisioning manuel (script par serveur)                  │
│  • Maintenance known_hosts pénible                           │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│  APRÈS (SSH CA par vault)                                    │
│                                                              │
│  Clé publique CA ────→ TrustedUserCAKeys sur CHAQUE serveur  │
│  (déployée 1 seule fois)                                     │
│                                                              │
│  Agent/Humain :                                              │
│    1. Envoie sa clé publique à MCP Vault                     │
│    2. Reçoit un certificat signé (ex: 30 min)                │
│    3. Se connecte avec le certificat                         │
│    4. Le certificat expire → rien à nettoyer                 │
│                                                              │
│  • 1 cert compromis = valide 30 min max (pas tous les srv)   │
│  • Audit complet (qui, quand, quel rôle, quel serial)        │
│  • Provisioning = 1 fichier CA sur chaque serveur            │
│  • Pas de known_hosts à maintenir                            │
└──────────────────────────────────────────────────────────────┘
```

### 7.2 Modèle de sécurité — CA isolée par vault

Chaque vault possède sa **propre CA SSH** — il n'y a pas de CA globale. Cela
garantit une **isolation cryptographique complète** entre les domaines de confiance.

```
┌──────────────────────────────────────────────────────────────────┐
│  MCP VAULT                                                       │
│                                                                  │
│  ┌────────────────────────────┐  ┌────────────────────────────┐  │
│  │ Vault: llmaas-infra        │  │ Vault: project-x           │  │
│  │                            │  │                            │  │
│  │  📁 Secrets KV v2          │  │  📁 Secrets KV v2          │  │
│  │  mount: vaults/llmaas-     │  │  mount: vaults/project-x/  │  │
│  │         infra/kv           │  │         kv                 │  │
│  │                            │  │                            │  │
│  │  🔑 SSH CA PROPRE          │  │  🔑 SSH CA PROPRE          │  │
│  │  mount: ssh-ca-llmaas-     │  │  mount: ssh-ca-project-x   │  │
│  │         infra              │  │                            │  │
│  │  • CA key pair A           │  │  • CA key pair B           │  │
│  │  • rôle "adminct" (1h)     │  │  • rôle "deploy" (30m)    │  │
│  │  • rôle "agentic" (30m)    │  │  • rôle "ci-cd" (15m)     │  │
│  └────────────────────────────┘  └────────────────────────────┘  │
│                                                                  │
│  🎫 TOKENS                                                      │
│  • Token "agent-cline"  → vault_ids: ["llmaas-infra"]           │
│    ✅ Signe avec CA llmaas-infra                                 │
│    ❌ Ne peut PAS signer avec CA project-x                       │
│  • Token "ci-pipeline"  → vault_ids: ["project-x"]              │
│    ❌ Ne peut PAS signer avec CA llmaas-infra                    │
│    ✅ Signe avec CA project-x                                    │
└──────────────────────────────────────────────────────────────────┘
```

**3 niveaux d'isolation** :

| Niveau       | Mécanisme                                      | Protection                                                                                                                     |
| ------------ | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| **Vault**    | Chaque vault = son propre mount SSH CA OpenBao | Les CA sont **cryptographiquement différentes**. Un cert de vault A ne fonctionne pas sur les serveurs configurés pour vault B |
| **Token**    | `vault_ids` dans le token MCP                  | Un agent ne peut **même pas appeler** les outils SSH d'un vault non autorisé                                                   |
| **Rôle SSH** | `allowed_users` + `ttl` par rôle               | Le rôle "agentic" ne peut signer un cert que pour les utilisateurs listés, avec un TTL borné                                   |

### 7.3 Implémentation OpenBao

Chaque vault utilise un **mount SSH secrets engine dédié** :

```python
# Mount point SSH par vault
SSH_MOUNT_PREFIX = "ssh-ca-"

def _ssh_mount_point(vault_id: str) -> str:
    return f"{SSH_MOUNT_PREFIX}{vault_id}"
    # "llmaas-infra" → "ssh-ca-llmaas-infra"
```

**Opérations OpenBao** :

| Opération            | API OpenBao (via hvac)                                            |
| -------------------- | ----------------------------------------------------------------- |
| Monter le SSH engine | `sys.enable_secrets_engine("ssh", path="ssh-ca-{vault_id}")`      |
| Générer la CA        | `write("ssh-ca-{vault_id}/config/ca", generate_signing_key=True)` |
| Créer un rôle        | `write("ssh-ca-{vault_id}/roles/{role}", key_type="ca", ...)`     |
| Signer une clé       | `write("ssh-ca-{vault_id}/sign/{role}", public_key="...")`        |
| Lire la CA publique  | `read("ssh-ca-{vault_id}/config/ca")`                             |
| Lister les rôles     | `list("ssh-ca-{vault_id}/roles")`                                 |
| Info rôle            | `read("ssh-ca-{vault_id}/roles/{role}")`                          |

### 7.4 Rôles SSH

Un rôle SSH définit **qui peut signer quoi** :

| Paramètre                 | Description                                 | Exemple                                   |
| ------------------------- | ------------------------------------------- | ----------------------------------------- |
| `role_name`               | Identifiant du rôle                         | `"adminct"`, `"agentic"`                  |
| `allowed_users`           | Utilisateurs système autorisés dans le cert | `"adminct"`, `"agentic,iaagentic"`, `"*"` |
| `default_user`            | Utilisateur par défaut si non spécifié      | `"adminct"`                               |
| `ttl`                     | Durée de vie par défaut du certificat       | `"1h"`, `"30m"`                           |
| `max_ttl`                 | Durée de vie maximale                       | `"24h"`                                   |
| `allow_user_certificates` | Autorise les user certs (vs host certs)     | `true`                                    |
| `allowed_extensions`      | Extensions SSH autorisées                   | `"permit-pty,permit-port-forwarding"`     |

### 7.5 Workflow concret — Exemple LLMaaS

L'infrastructure LLMaaS comprend ~50 serveurs (GPU, load balancers, bases de
données, monitoring) accessibles via un bastion (`bastion01-prod`). Deux profils
utilisateur : `adminct` (admin sudo) et `agentic/iaagentic` (service automatisé).

#### Étape 1 — Setup initial (ONE-TIME)

```python
# 1. Créer le vault dédié à l'infra SSH LLMaaS
vault_create("llmaas-infra", description="SSH CA + secrets LLMaaS")

# 2. Configurer la CA SSH + rôles
ssh_ca_setup("llmaas-infra", "adminct",
    allowed_users="adminct",
    default_user="adminct",
    ttl="1h")
    
ssh_ca_setup("llmaas-infra", "agentic",
    allowed_users="agentic,iaagentic",
    default_user="agentic",
    ttl="30m")

# 3. Récupérer la clé publique CA
result = ssh_ca_public_key("llmaas-infra")
ca_pub = result["public_key"]
# → "ssh-ed25519 AAAA... (CA key)"
```

#### Étape 2 — Déployer la CA sur les serveurs (ONE-TIME)

```bash
# Sur chaque serveur (via le bastion, scriptable) :
# 1. Déployer la clé publique CA
echo "<CA_PUBLIC_KEY>" > /etc/ssh/trusted-user-ca-keys.pem

# 2. Configurer sshd pour faire confiance à la CA
echo "TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pem" >> /etc/ssh/sshd_config

# 3. (Optionnel) Configurer AuthorizedPrincipals pour restreindre les users
mkdir -p /etc/ssh/auth_principals
echo "adminct" > /etc/ssh/auth_principals/adminct
echo "agentic" > /etc/ssh/auth_principals/agentic
echo "iaagentic" >> /etc/ssh/auth_principals/agentic
echo "AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u" >> /etc/ssh/sshd_config

# 4. Redémarrer sshd
systemctl restart sshd
```

> ⚠️ **Les clés statiques continuent de fonctionner** en parallèle (`authorized_keys`).
> La SSH CA est un mécanisme ADDITIONNEL. Migration progressive possible.

#### Étape 3 — Usage quotidien

**Humain (admin) :**

```bash
# 1. Demander un certificat (CLI mcp-vault)
python scripts/mcp_cli.py ssh sign llmaas-infra adminct \
    --key ./ssh-keys/adminct/id_ed25519.pub --ttl 2h
# → Certificat écrit dans ./ssh-keys/adminct/id_ed25519-cert.pub

# 2. Se connecter comme d'habitude (OpenSSH détecte le -cert.pub automatiquement)
ssh -F ./ssh-keys/adminct/config ia01
```

**Agent MCP (automatique) :**

```python
# 1. L'agent signe sa clé publique
cert = await call_tool("ssh_sign_key", {
    "vault_id": "llmaas-infra",
    "role_name": "agentic",
    "public_key": "ssh-ed25519 AAAA...",
    "ttl": "30m"
})
# → cert["signed_key"] = certificat signé, valide 30 min

# 2. L'agent utilise le cert pour SSH (via mcp-tools)
result = await call_tool("ssh", {
    "host": "ia01", "username": "agentic",
    "command": "nvidia-smi",
    "private_key": agent_private_key,
    "certificate": cert["signed_key"]
})
# → 30 min plus tard : cert expiré, aucun risque résiduel
```

### 7.6 Suppression automatique de la CA avec le vault

Quand un vault est supprimé (`vault_delete`), son mount SSH CA est également
supprimé. Cela garantit qu'aucune CA orpheline ne subsiste :

```python
vault_delete("llmaas-infra")
# → Supprime le mount KV v2 (secrets)
# → Supprime le mount ssh-ca-llmaas-infra (CA + rôles)
# → Les certs déjà émis continuent de fonctionner jusqu'à expiration
# → Aucun nouveau cert ne peut être émis
```

### 7.7 Comparatif clés statiques vs SSH CA

| Aspect               | Clés statiques                           | SSH CA (MCP Vault)                          |
| -------------------- | ---------------------------------------- | ------------------------------------------- |
| Provisioning serveur | Copier clé publique sur chaque serveur   | Copier 1 fichier CA (une seule fois)        |
| Durée de vie         | Permanente                               | Éphémère (configurable, ex: 30min)          |
| Révocation           | Supprimer manuellement de chaque serveur | Le cert expire tout seul                    |
| Compromission        | Accès à TOUS les serveurs, pour toujours | Accès limité au TTL du cert                 |
| Audit                | Aucun (qui utilise quelle clé ?)         | Serial number + audit OpenBao               |
| Multi-profil         | 1 clé par profil, copiée partout         | 1 rôle par profil, cert à la demande        |
| Rotation             | Très pénible (changer partout)           | Naturelle (nouveaux certs à chaque session) |
| Agents IA            | Clé stockée quelque part (risque)        | Cert éphémère en mémoire, jamais stocké     |

### 7.8 Checklist de sécurité opérationnelle SSH CA

Cette checklist couvre les bonnes pratiques de sécurité pour le déploiement et
l'exploitation de la SSH CA de MCP Vault en production.

#### 7.8.1 Configuration des rôles SSH

| Règle                        | Priorité     | Description                                                                                                                                       |
| ---------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| **TTL courts par défaut**    | 🔴 Critique | `ttl` ≤ 1h pour les humains, ≤ 30m pour les agents IA. Plus le TTL est court, plus la fenêtre d'exposition en cas de compromission est réduite    |
| **max_ttl borné**            | 🔴 Critique | Toujours définir un `max_ttl` (ex: 24h) pour empêcher les demandes de certificats longue durée                                                    |
| **allowed_users explicites** | 🔴 Critique | Ne **jamais** utiliser `"*"` en production. Lister explicitement les utilisateurs autorisés (ex: `"adminct"`, `"agentic,iaagentic"`)              |
| **Un rôle = un profil**      | 🟠 Élevée   | Créer un rôle SSH distinct par profil de connexion (admin, agent, CI/CD). Ne pas mélanger les périmètres                                          |
| **Extensions minimales**     | 🟠 Élevée   | Limiter les extensions SSH au strict nécessaire : `permit-pty` pour les shells interactifs, pas de `permit-port-forwarding` sauf besoin explicite |
| **Pas de rôle wildcard**     | 🟡 Moyenne  | Éviter les rôles avec `allowed_users="*"` même pour les admins — préférer un rôle `admin-emergency` séparé, audité                                |

#### 7.8.2 Déploiement sur les serveurs cibles

| Règle                             | Priorité     | Description                                                                                                                                          |
| --------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| **TrustedUserCAKeys obligatoire** | 🔴 Critique | Configurer `TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pem` dans `sshd_config` sur **chaque** serveur cible                                     |
| **AuthorizedPrincipalsFile**      | 🟠 Élevée   | Toujours configurer `AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u` pour restreindre quels principals sont acceptés par utilisateur système   |
| **Migration progressive**         | 🟠 Élevée   | Maintenir les `authorized_keys` existants pendant la transition. La SSH CA est un mécanisme **additionnel**, pas un remplacement immédiat            |
| **Fichier CA en lecture seule**   | 🟡 Moyenne  | `chmod 644 /etc/ssh/trusted-user-ca-keys.pem` — le fichier CA ne contient que la clé publique, mais sa modification permettrait une usurpation de CA |
| **Déploiement automatisé**        | 🟡 Moyenne  | Utiliser un outil de configuration (Ansible, Salt, etc.) pour déployer la clé CA et la config sshd de manière reproductible                          |
| **Test de non-régression**        | 🟡 Moyenne  | Après déploiement, vérifier que les connexions par clé statique ET par certificat fonctionnent                                                       |

#### 7.8.3 Gestion du cycle de vie des CA

| Règle                                  | Priorité     | Description                                                                                                                                                                                                   |
| -------------------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1 CA par domaine de confiance**      | 🔴 Critique | Ne jamais partager une CA entre des environnements non liés (prod/staging, clients différents). Utiliser un vault distinct par domaine                                                                        |
| **Rotation CA planifiée**              | 🟠 Élevée   | Planifier une rotation de la CA tous les **12-24 mois**. Workflow : créer un nouveau vault avec nouvelle CA → déployer la nouvelle clé CA sur les serveurs → migrer les signatures → supprimer l'ancien vault |
| **Période de chevauchement**           | 🟠 Élevée   | Pendant la rotation, configurer **deux** clés CA dans `TrustedUserCAKeys` (ancienne + nouvelle) pendant une période de transition (2-4 semaines)                                                              |
| **Suppression vault = suppression CA** | 🟡 Moyenne  | Rappel : `vault_delete()` supprime automatiquement le mount SSH CA. Les certificats déjà émis restent valides jusqu'à expiration                                                                              |
| **Backup avant rotation**              | 🟡 Moyenne  | Exporter le vault (`vault_export`) avant toute rotation pour permettre une restauration en cas de problème                                                                                                    |

#### 7.8.4 Audit et monitoring

| Règle                                | Priorité     | Description                                                                                                              |
| ------------------------------------ | ------------ | ------------------------------------------------------------------------------------------------------------------------ |
| **Audit OpenBao activé**             | 🔴 Critique | L'audit device OpenBao trace chaque signature (serial number, rôle, principal, TTL, timestamp). Vérifier qu'il est actif |
| **Alertes sur signatures anormales** | 🟠 Élevée   | Monitorer les signatures hors horaires normaux, les TTL inhabituellement longs, ou les rafales de signatures             |
| **Inventaire des CA actives**        | 🟡 Moyenne  | Maintenir un inventaire des vaults avec SSH CA active (`ssh_ca_list_roles` sur chaque vault)                             |
| **Revue périodique des rôles**       | 🟡 Moyenne  | Tous les 3 mois, auditer les rôles SSH CA : utilisateurs autorisés toujours pertinents ? TTL toujours adaptés ?          |
| **Corrélation logs SSH**             | 🟡 Moyenne  | Croiser les logs `auth.log` des serveurs cibles avec l'audit OpenBao pour détecter les certificats utilisés vs émis      |

#### 7.8.5 Scénarios de compromission

| Scénario                           | Impact                                                     | Réponse                                                                                                                                                    |
| ---------------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Clé privée agent compromise**    | Limité au TTL du dernier cert émis (ex: 30 min max)        | Révoquer le token MCP de l'agent → plus de nouvelle signature possible. Attendre l'expiration du cert                                                      |
| **Token MCP admin compromis**      | Peut créer de nouveaux rôles et signer des certs           | Révoquer le token immédiatement. Auditer les signatures récentes. Créer un nouveau token admin                                                             |
| **Clé CA compromise** (worst case) | Tous les certificats émis par cette CA sont suspects       | 1. Supprimer le vault (supprime la CA). 2. Retirer la clé CA des serveurs (`TrustedUserCAKeys`). 3. Créer un nouveau vault avec nouvelle CA. 4. Redéployer |
| **Serveur cible compromis**        | L'attaquant peut utiliser les certs valides sur CE serveur | Isoler le serveur. La CA n'est pas compromise — les autres serveurs restent sûrs                                                                           |
| **Bootstrap key compromise**       | Peut unseal OpenBao → accès à toutes les CA                | Rotation complète : nouvelle bootstrap key, re-chiffrement des unseal keys, rotation de toutes les CA                                                      |

---

## 8. Démarrage et Unseal

### 8.0 Modèle de sécurité des clés unseal

> **Principe fondamental** : les clés unseal ne doivent **jamais** résider en clair
> sur le même système que les données chiffrées. Un attaquant qui compromet le
> conteneur ne doit pas pouvoir accéder aux clés ET aux données simultanément.

**Option C — Compromis pragmatique (v0.2.1)** :

```
┌─────────────────────────────────────────────────────────────────┐
│  SÉPARATION PHYSIQUE DONNÉES / CLÉS                             │
│                                                                 │
│  Données chiffrées (barrier OpenBao)                            │
│  └─ Volume Docker local + S3 (_storage/openbao-data.tar.gz)    │
│     ⟶ Chiffrement XChaCha20-Poly1305 par OpenBao               │
│     ⟶ Illisibles sans unseal key                                │
│                                                                 │
│  Clés unseal                                                    │
│  └─ S3 UNIQUEMENT (_init/init_keys.json.enc)                   │
│     ⟶ Chiffrées AES-256-GCM (clé dérivée ADMIN_BOOTSTRAP_KEY) │
│     ⟶ JAMAIS en clair sur le filesystem local                   │
│     ⟶ Téléchargées → déchiffrées → utilisées → effacées         │
│     ⟶ Ne restent qu'en MÉMOIRE pendant le runtime              │
│                                                                 │
│  ADMIN_BOOTSTRAP_KEY                                            │
│  └─ Variable d'environnement UNIQUEMENT                         │
│     ⟶ Jamais sur S3, jamais sur disque                          │
│     ⟶ Nécessaire pour déchiffrer les clés unseal               │
│                                                                 │
│  Pour accéder aux secrets, un attaquant doit compromettre :     │
│  ✗ Le bucket S3 (données + clés chiffrées)                     │
│  ✗ ET la variable d'environnement ADMIN_BOOTSTRAP_KEY           │
│  ✗ OU le processus en mémoire pendant le runtime               │
└─────────────────────────────────────────────────────────────────┘
```

**Chiffrement des clés unseal** :

| Paramètre         | Valeur                                                               |
| ----------------- | -------------------------------------------------------------------- |
| Algorithme        | AES-256-GCM (via `cryptography` Python)                              |
| Dérivation de clé | PBKDF2-HMAC-SHA256, 600 000 itérations                               |
| Sel               | 16 bytes aléatoires (stocké avec le ciphertext)                      |
| IV/Nonce          | 12 bytes aléatoires (requis par GCM)                                 |
| Format stocké     | `salt (16B) || nonce (12B) || ciphertext || tag (16B)` encodé base64 |
| Clé source        | `ADMIN_BOOTSTRAP_KEY` (variable d'environnement)                     |

**Roadmap v0.3.0** : Transit Auto-Unseal via une instance OpenBao dédiée
(KMS interne Cloud Temple), éliminant le besoin de stocker les clés unseal.

### 8.1 Première exécution (init)

```python
async def first_time_init(self):
    """Première exécution : init OpenBao et sauvegarder les clés sur S3."""
    # 1. Init OpenBao (Shamir shares=1, threshold=1 pour embedded)
    init_result = self.hvac.sys.initialize(
        secret_shares=1,
        secret_threshold=1
    )
    
    # 2. Chiffrer les clés avec ADMIN_BOOTSTRAP_KEY (AES-256-GCM + PBKDF2)
    init_data = {
        "unseal_key": init_result["keys"][0],
        "root_token": init_result["root_token"]
    }
    encrypted = encrypt_with_bootstrap_key(json.dumps(init_data))
    
    # 3. Sauvegarder UNIQUEMENT sur S3 (jamais en clair localement)
    await s3.put("_init/init_keys.json.enc", encrypted)
    # ⚠️ Aucun fichier local — les clés ne touchent jamais le disque en clair
    
    # 4. Unseal avec la clé (en mémoire)
    self.hvac.sys.submit_unseal_key(init_result["keys"][0])
    
    # 5. Stocker root_token et unseal_key en mémoire uniquement
    self._in_memory_keys = init_data  # Garbage collected au shutdown
    
    # 6. Configurer l'audit device
    self.hvac.sys.enable_audit_device(
        device_type="file",
        options={"file_path": "/tmp/openbao-audit.log"}
    )
    
    # 7. Activer SSH CA
    self.hvac.sys.enable_secrets_engine("ssh", path="ssh")
    self.hvac.secrets.ssh.create_ca(generate_signing_key=True)
```

### 8.2 Exécutions suivantes (unseal depuis S3)

```python
async def unseal_from_s3(self):
    """Télécharge les clés chiffrées depuis S3, déchiffre, unseal, puis efface."""
    # 1. Download depuis S3
    encrypted = await s3.get("_init/init_keys.json.enc")
    
    # 2. Déchiffrer avec ADMIN_BOOTSTRAP_KEY (AES-256-GCM + PBKDF2)
    init_data = json.loads(decrypt_with_bootstrap_key(encrypted))
    
    # 3. Unseal OpenBao
    self.hvac.sys.submit_unseal_key(init_data["unseal_key"])
    self.hvac.token = init_data["root_token"]
    
    # 4. Stocker en mémoire uniquement (pas sur disque)
    self._in_memory_keys = init_data
    
    # ⚠️ init_data n'est JAMAIS écrit sur le filesystem local
    # Les clés ne vivent qu'en mémoire pendant le runtime
```

### 8.3 Résumé du flux des clés unseal

```
INIT (1ère fois) :
  OpenBao.init() → clés en mémoire → chiffrement AES-256-GCM → upload S3
                                    → unseal immédiat
                                    → PAS de fichier local

STARTUP (suivants) :
  S3 download → déchiffrement AES-256-GCM → clés en mémoire → unseal
                                           → PAS de fichier local

RUNTIME :
  Clés uniquement en mémoire (variable Python)
  → Garbage collected au shutdown du processus

SHUTDOWN :
  seal → upload S3 (données) → stop processus → mémoire libérée
```

**Sécurité** : À aucun moment les clés unseal n'existent en clair sur le
filesystem. Elles transitent uniquement en mémoire pendant le runtime.
Un crash du processus efface automatiquement les clés de la mémoire.

---

## 9. Configuration (.env)

```env
# --- MCP Vault ---
MCP_SERVER_NAME=mcp-vault
MCP_SERVER_PORT=8030

# --- WAF ---
WAF_PORT=8085                    # Port d'écoute externe du WAF Caddy+Coraza

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
│       ├── commands.py        # CLI Click (vault, secret, ssh, token, audit)
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
Couche 4 : AuthMiddleware + ContextVar — Bearer Token + permissions + vault_ids, request-scoped
Couche 5 : LoggingMiddleware           — Audit trail HTTP (ring buffer 200 entrées)
Couche 6 : OpenBao policies            — HCL fine-grained access control
Couche 7 : OpenBao barrier             — XChaCha20-Poly1305 encryption at rest
Couche 8 : Seal/Unseal                 — Sans les unseal keys, les données sont illisibles
Couche 9 : S3                          — Données chiffrées par OpenBao avant écriture (3AZ)
```

### 11.2 Détails des mécanismes de sécurité applicatifs

**ContextVar (request-scoped auth)** — Le middleware `AuthMiddleware` valide le
Bearer token et stocke les informations d'identité (client_name, permissions,
vault_ids) dans un `contextvars.ContextVar`. Chaque outil MCP appelle ensuite
`check_access(vault_id)` qui lit cette variable. Le mécanisme est :
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

### 11.3 Gestion sécurisée des clés unseal (Option C)

La gestion des clés unseal est le point critique de la sécurité. Le principe
fondamental est la **séparation physique** entre les données chiffrées et les
clés de déchiffrement :

```
┌──────────────────────────────────────────────────────────────┐
│  3 FACTEURS nécessaires pour accéder aux secrets             │
│                                                              │
│  1. Données chiffrées  → S3 + volume Docker local           │
│     (openbao-data.tar.gz, barrier XChaCha20-Poly1305)       │
│                                                              │
│  2. Clés unseal        → S3 (_init/init_keys.json.enc)      │
│     (chiffrées AES-256-GCM, dérivation PBKDF2)              │
│                                                              │
│  3. Bootstrap key      → Variable d'environnement           │
│     (jamais sur S3, jamais sur disque)                       │
│                                                              │
│  Compromettre 1 seul facteur = insuffisant                   │
│  Compromettre 2 facteurs (1+2 sans 3) = insuffisant          │
│  Les 3 sont nécessaires simultanément                        │
└──────────────────────────────────────────────────────────────┘
```

**Invariants de sécurité** :

| Invariant                      | Description                                                                                 |
| ------------------------------ | ------------------------------------------------------------------------------------------- |
| Pas de clé en clair sur disque | Les clés unseal ne sont JAMAIS écrites en clair sur le filesystem                           |
| Séparation données/clés        | Les données (barrier) et les clés (enc) sont sur S3 mais ne se déchiffrent pas mutuellement |
| Mémoire seule au runtime       | Pendant l'exécution, les clés ne vivent qu'en mémoire Python                                |
| Crash = effacement             | Un crash du processus efface automatiquement les clés de la mémoire                         |
| Bootstrap key externe          | La clé de déchiffrement des unseal keys n'est jamais persistée                              |

**Roadmap** :

| Version             | Approche                                                   | Sécurité       |
| ------------------- | ---------------------------------------------------------- | -------------- |
| **v0.2.x** (actuel) | Option C — Clés sur S3 chiffrées, mémoire seule au runtime | 🟡 Bonne      |
| **v0.3.0** (futur)  | Transit Auto-Unseal via OpenBao dédié (KMS Cloud Temple)   | 🟢 Excellente |
| **v2.0** (prod)     | 🔐 Connexion HSM (Hardware Security Module) Cloud Temple  | 🟢 Maximale   |

#### v0.3.0 — Transit Auto-Unseal (KMS Cloud Temple)

Le Transit Auto-Unseal utilise une **deuxième instance OpenBao dédiée** comme
service de chiffrement (KMS). L'instance MCP Vault n'a plus besoin de connaître
les clés unseal — elle délègue le déchiffrement au KMS.

```
┌─────────────────────────────────────────────────────────────────┐
│  v0.3.0 — TRANSIT AUTO-UNSEAL                                  │
│                                                                 │
│  MCP Vault (instance applicative)                               │
│  └─ OpenBao embedded (sealed au démarrage)                      │
│     ⟶ Demande unseal au KMS via Transit                         │
│     ⟶ N'a JAMAIS accès aux clés unseal en clair                 │
│     ⟶ Pas de bootstrap key nécessaire                           │
│                                                                 │
│  KMS OpenBao (instance dédiée, réseau interne)                  │
│  └─ Transit secrets engine activé                               │
│     ⟶ Clé de transit "mcp-vault-unseal"                         │
│     ⟶ Déchiffre les clés unseal à la demande                    │
│     ⟶ Clés de transit protégées par son propre seal             │
│     ⟶ Unsealed via Shamir (3/5 shares détenues par 5 admins)    │
│                                                                 │
│  Avantages :                                                    │
│  ✅ Pas de bootstrap key en variable d'environnement            │
│  ✅ Séparation physique MCP Vault ↔ KMS                         │
│  ✅ Rotation de la clé de transit sans downtime                  │
│  ✅ Audit complet des opérations de déchiffrement                │
│                                                                 │
│  Prérequis :                                                    │
│  • Instance OpenBao dédiée (bare metal ou VM, pas containerisée)│
│  • Shamir 5 shares / threshold 3 (5 administrateurs Cloud Temple)│
│  • Réseau privé entre MCP Vault et KMS (pas d'accès Internet)  │
│  • Monitoring + alertes sur le seal status du KMS               │
└─────────────────────────────────────────────────────────────────┘
```

**Étapes de migration v0.2.x → v0.3.0** :

| #   | Étape                       | Description                                                           |
| --- | --------------------------- | --------------------------------------------------------------------- |
| 1   | Déployer le KMS             | Installer OpenBao dédié, init avec Shamir 5/3, activer Transit engine |
| 2   | Créer la clé de transit     | `bao write transit/keys/mcp-vault-unseal type=aes256-gcm256`          |
| 3   | Re-chiffrer les clés unseal | Déchiffrer avec ADMIN_BOOTSTRAP_KEY → re-chiffrer avec Transit        |
| 4   | Configurer MCP Vault        | `seal "transit"` dans la config HCL, pointer vers le KMS              |
| 5   | Tester le cycle complet     | Startup → auto-unseal via KMS → runtime → shutdown                    |
| 6   | Retirer ADMIN_BOOTSTRAP_KEY | La variable d'environnement n'est plus nécessaire                     |

#### v2.0 — HSM Cloud Temple : Thales Luna (PKCS#11)

> ⚠️ **Design-only** — Le HSM Thales Luna n'est pas encore disponible chez
> Cloud Temple. Cette section documente le chemin technique pour être prêts
> le jour où le matériel sera opérationnel.

Le HSM (Hardware Security Module) est le niveau de sécurité **maximal**. Les clés
de chiffrement ne quittent **jamais** le module matériel certifié. Le HSM assure
le unsealing automatique via l'interface cryptographique PKCS#11.

**Matériel cible** : **Thales Luna Network HSM** (anciennement SafeNet Luna SA)
- Certification **FIPS 140-2 Level 3** (ou **FIPS 140-3** selon le modèle)
- Interface **PKCS#11** native (pas de serveur KMIP nécessaire)
- Support HA avec failover automatique entre HSM primaire et secondaire

```
┌─────────────────────────────────────────────────────────────────┐
│  v2.0 — THALES LUNA HSM (PKCS#11)                               │
│                                                                 │
│  MCP Vault (conteneur Docker)                                   │
│  └─ OpenBao embedded                                            │
│     ⟶ seal "pkcs11" dans la config HCL                          │
│     ⟶ Auto-unseal via appel PKCS#11 au Luna                     │
│     ⟶ La clé master ne quitte JAMAIS le HSM                     │
│                                                                 │
│          ┌──────────────────────────┐                           │
│          │  Luna Client v10.x       │                           │
│          │  libpkcs11.so            │                           │
│          └───────────┬──────────────┘                           │
│                      │ NTLS (Network TLS)                       │
│                      ▼                                          │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Thales Luna Network HSM (matériel Cloud Temple)         │   │
│  │                                                          │   │
│  │  • FIPS 140-2 Level 3 / FIPS 140-3                       │   │
│  │  • Anti-tampering physique (détection d'ouverture)       │   │
│  │  • Partition dédiée "mcp-vault"                          │   │
│  │  • Rôles : Crypto Officer + Crypto User                  │   │
│  │                                                          │   │
│  │  Clés sur le HSM (non-exportables) :                     │   │
│  │  ├─ "mcp-vault-aes" (AES-256, CKM_AES_GCM)             │   │
│  │  │  └─ Utilisée pour seal/unseal OpenBao                 │   │
│  │  └─ "mcp-vault-hmac" (HMAC-256)                         │   │
│  │     └─ Utilisée pour l'intégrité des données             │   │
│  │                                                          │   │
│  │  ⚠️ Les clés ne quittent JAMAIS le HSM                   │   │
│  │  ⚠️ Les opérations crypto se font IN-HSM                 │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                 │
│  Avantages :                                                    │
│  ✅ Aucune clé en mémoire logicielle                            │
│  ✅ Protection matérielle contre l'extraction                    │
│  ✅ Certification FIPS 140-2/3 Level 3                           │
│  ✅ Conformité SecNumCloud, HDS, ISO 27001                      │
│  ✅ Auto-unseal instantané au démarrage                          │
│  ✅ Rotation des clés possible sans downtime                     │
│  ✅ Plus besoin de ADMIN_BOOTSTRAP_KEY                           │
└─────────────────────────────────────────────────────────────────┘
```

##### Prérequis Cloud Temple

| Prérequis | Description | Statut |
|-----------|-------------|--------|
| **HSM Thales Luna** | Partition dédiée sur Luna Network HSM Cloud Temple | ⏳ En attente |
| **Luna Client v10.x** | Installé dans l'image Docker MCP Vault (`/opt/luna/`) | 📋 À faire |
| **Bibliothèque PKCS#11** | `/opt/luna/lib/libpkcs11.so` montée dans le conteneur | 📋 À faire |
| **Connectivité NTLS** | Réseau privé entre conteneur Docker et Luna HSM | 📋 À faire |
| **Partition initialisée** | Rôles Crypto Officer + Crypto User créés | 📋 À faire |
| **Clés générées** | AES-256 + HMAC-256 générées sur le HSM via `lunacm` | 📋 À faire |
| **OpenBao PKCS#11** | OpenBao compilé avec support PKCS#11 (natif depuis v2.x) | ✅ Supporté |

##### Configuration HCL cible

```hcl
# Configuration seal PKCS#11 pour Thales Luna
seal "pkcs11" {
  # Bibliothèque PKCS#11 Thales Luna
  lib            = "/opt/luna/lib/libpkcs11.so"

  # Slot de la partition dédiée MCP Vault
  slot           = "0"

  # PIN Crypto User — TOUJOURS via variable d'environnement
  pin            = "env://LUNA_HSM_PIN"

  # Clés sur le HSM (non-exportables, générées via lunacm)
  key_label      = "mcp-vault-aes"
  hmac_key_label = "mcp-vault-hmac"

  # Algorithme : AES-256-GCM (mechanism PKCS#11)
  mechanism      = "0x1085"    # CKM_AES_GCM

  # Ne PAS générer les clés automatiquement — elles doivent
  # être créées manuellement sur le HSM par le Crypto Officer
  generate_key   = "false"
}
```

##### Étapes de migration v0.2.x → v2.0 (quand le Luna sera disponible)

> **Note** : la migration directe v0.2.x → v2.0 est possible grâce à
> `bao operator migrate`. L'étape Transit (v0.3.0) est **optionnelle** —
> elle n'est utile que si on veut une étape intermédiaire de validation.

| #   | Étape | Responsable | Description |
|-----|-------|-------------|-------------|
| 1   | **Provisionner la partition** | Admin Cloud Temple | Créer une partition dédiée "mcp-vault" sur le Luna Network HSM |
| 2   | **Initialiser les rôles** | Admin HSM | Initialiser Crypto Officer + Crypto User avec des PINs forts |
| 3   | **Générer les clés** | Crypto Officer | Via `lunacm` : clé AES-256 `mcp-vault-aes` + HMAC `mcp-vault-hmac` (non-exportables) |
| 4   | **Installer Luna Client** | DevOps | Ajouter Luna Client v10.x dans le Dockerfile MCP Vault, monter `/opt/luna/` |
| 5   | **Configurer NTLS** | Réseau | Assurer la connectivité TLS entre le conteneur et le Luna HSM (réseau privé) |
| 6   | **Tester la connexion** | DevOps | Vérifier via `lunacm` depuis le conteneur : `partition list`, `slot list` |
| 7   | **Modifier la config HCL** | DevOps | Ajouter le stanza `seal "pkcs11"` avec les paramètres Luna |
| 8   | **Migrer le seal** | Admin | `bao operator migrate -config=new_config.hcl` (re-wrap du master key par le HSM) |
| 9   | **Valider le cycle complet** | Test | Startup → auto-unseal via HSM → runtime → seal → re-unseal |
| 10  | **Retirer ADMIN_BOOTSTRAP_KEY** | Sécurité | La variable d'environnement n'est plus nécessaire (le HSM est la root of trust) |
| 11  | **Documenter et auditer** | Sécurité | Mettre à jour la documentation, auditer la chaîne de confiance |

##### Commandes Luna de préparation (référence)

```bash
# ── Depuis lunacm (Luna Client Management) ──

# 1. Vérifier la partition
lunacm
> partition list
# → Doit afficher "mcp-vault" avec son slot number

# 2. Générer la clé AES-256 (non-exportable)
> key generate -mechanism AES -label mcp-vault-aes \
    -size 256 -encrypt true -decrypt true

# 3. Générer la clé HMAC (non-exportable)
> key generate -mechanism GENERIC -label mcp-vault-hmac \
    -size 256 -sign true -verify true

# 4. Vérifier les clés
> key list
# → Doit afficher les 2 clés avec leurs handles

# ── Test de connectivité depuis le conteneur Docker ──
docker exec mcp-vault /opt/luna/bin/lunacm -c "slot list"
```

##### Considérations de sécurité spécifiques Luna

| Aspect | Recommandation |
|--------|----------------|
| **PIN management** | PIN Crypto User stocké dans `LUNA_HSM_PIN` (env var), jamais dans la config HCL ni sur S3 |
| **Clés non-exportables** | Les clés AES/HMAC doivent être générées directement sur le HSM — jamais importées |
| **Labels avec timestamp** | Utiliser des labels versionnés (ex: `mcp-vault-aes-2026-06`) pour faciliter la rotation |
| **Connectivité HSM** | Si le Luna est inaccessible → OpenBao ne peut PAS s'unsealer. Prévoir un monitoring + alertes |
| **HA HSM** | Configurer le failover Luna (primaire + secondaire) pour éviter un SPOF matériel |
| **Backup des clés** | Le backup des clés HSM se fait via les mécanismes natifs Luna (HSM-to-HSM backup) |
| **Audit Luna** | Activer le logging sur le Luna pour tracer toutes les opérations crypto (seal/unseal) |

> **Résumé de la trajectoire sécurité** : chaque version élimine un facteur
> d'exposition des clés, jusqu'à atteindre le niveau où **aucune clé n'existe
> jamais en dehors du matériel certifié**.
>
> ```
> v0.2.x : Clés en mémoire Python (bootstrap key + AES-256-GCM)
>     ↓
> v0.3.0 : Clés dans un KMS dédié (Transit auto-unseal)
>     ↓
> v2.0   : Clés dans un HSM matériel (PKCS#11, jamais extractibles)
> ```

### 11.4 Menaces et mitigations

| Menace                           | Mitigation                                                                                                            |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| Vol du bucket S3                 | Données chiffrées (barrier OpenBao). Clés unseal chiffrées (AES-256-GCM). Sans `ADMIN_BOOTSTRAP_KEY` → tout illisible |
| Compromission du container       | Clés uniquement en mémoire, pas sur disque. Sealed au shutdown. Crash = mémoire effacée                               |
| Vol de la bootstrap key seule    | Insuffisant : il faut aussi le bucket S3 (clés chiffrées + données)                                                   |
| Vol S3 + bootstrap key           | Scénario le plus grave. Mitigation : WAF + réseau privé + rotation de bootstrap key                                   |
| Lecture mémoire du processus     | Nécessite accès root au conteneur. Mitigation : user non-root, seccomp, no-new-privileges                             |
| Accès non autorisé à un espace   | Tokens MCP avec vault_ids + OpenBao policies HCL                                                                      |
| Fuite de la bootstrap key        | Uniquement en variable d'env, jamais sur S3 en clair. Rotation recommandée                                            |
| Perte du storage                 | S3 3AZ (répliqué sur 3 zones) + sync toutes les 60s (configurable)                                                    |
| Agent lit un secret non autorisé | Token MCP scopé (ContextVar) + OpenBao policy par rôle                                                                |
| Audit trail altéré               | File audit device OpenBao (non modifiable par les outils MCP)                                                         |
| XSS/injection sur la console     | WAF OWASP CRS + console admin SPA (pas de SSR) + CORS strict                                                          |
| Path traversal via /admin/static | AdminMiddleware normalise les chemins, bloque `../`                                                                   |
| DDoS sur le service              | WAF Caddy rate limiting + service non exposé directement                                                              |
| Unseal/seal inattendu            | Monitoring + alertes sur les événements seal/unseal anormaux                                                          |

### 11.5 Recommandations production

| Recommandation                                                           | Priorité     |
| ------------------------------------------------------------------------ | ------------ |
| ADMIN_BOOTSTRAP_KEY ≥ 64 caractères aléatoires                           | 🔴 Critique |
| TLS via WAF (HTTPS)                                                      | 🔴 Critique |
| WAF_PORT non accessible publiquement (réseau privé)                      | 🔴 Critique |
| Clés unseal jamais en clair sur disque (Option C)                        | 🔴 Critique |
| Rotation périodique des secrets                                          | 🟠 Élevée   |
| Rotation de la ADMIN_BOOTSTRAP_KEY (avec re-chiffrement des clés unseal) | 🟠 Élevée   |
| Monitoring des seal/unseal events (alertes temps réel)                   | 🟠 Élevée   |
| Backup S3 séparé du bucket vault                                         | 🟡 Moyenne  |
| Shamir secret sharing (5 shares, threshold 3) pour production            | 🟡 Moyenne  |
| Transit Auto-Unseal via OpenBao dédié (v0.3.0)                           | 🟡 Moyenne  |
| Monitoring de la console admin (logs d'accès)                            | 🟡 Moyenne  |
| User non-root + seccomp profile dans Docker                              | 🟡 Moyenne  |

### 11.6 WAF Coraza — Architecture et Fine-tuning

Le WAF (Web Application Firewall) est la **première couche de sécurité** du
MCP Vault. Il intercepte toutes les requêtes HTTP avant qu'elles n'atteignent
l'application, bloquant les attaques L7 connues (injections, XSS, LFI, RCE...).

#### 11.6.1 Architecture du WAF

```
                     Internet / Réseau interne
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  WAF Caddy + Coraza (:8085, configurable WAF_PORT)              │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  Caddy v2.11.2 (compilé avec xcaddy)                       │  │
│  │  └─ Plugin coraza-caddy v2.2.0                             │  │
│  │     └─ OWASP CoreRuleSet (CRS) v4.7.0                     │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  Rôles :                                                         │
│  1. Reverse proxy → mcp-vault:8030 (réseau interne Docker)      │
│  2. Détection et blocage des attaques (anomaly scoring CRS)     │
│  3. Headers de sécurité (CSP, X-Frame-Options, nosniff...)      │
│  4. Timeouts adaptés MCP (120s pour les appels longs)           │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼ reverse proxy (réseau Docker mcp-net)
┌──────────────────────────────────────────────────────────────────┐
│  MCP Vault (:8030, expose uniquement — PAS de ports:)           │
│  Non accessible directement depuis l'extérieur                   │
└──────────────────────────────────────────────────────────────────┘
```

**Build multi-stage du Dockerfile WAF** (`waf/Dockerfile`) :

| Stage              | Image              | Rôle                                                |
| ------------------ | ------------------- | --------------------------------------------------- |
| `builder`          | `caddy:2-builder`   | Compile Caddy avec le plugin `coraza-caddy/v2`      |
| `crs-downloader`   | `alpine:latest`     | Télécharge les règles OWASP CRS v4.7.0 depuis GitHub |
| Image finale       | `caddy:2-alpine`    | Image minimale avec binaire compilé + règles CRS    |

#### 11.6.2 Règles OWASP CRS chargées

Le fichier `waf/coraza.conf` charge **19 fichiers de règles CRS** couvrant
l'ensemble du spectre d'attaques L7 :

**Règles de requête (REQUEST)** — Analysent les requêtes entrantes :

| Fichier CRS                              | Protection                                            |
| ---------------------------------------- | ----------------------------------------------------- |
| `REQUEST-901-INITIALIZATION`             | Initialisation du moteur CRS, variables de scoring     |
| `REQUEST-905-COMMON-EXCEPTIONS`          | Exceptions communes (crawlers légitimes, etc.)        |
| `REQUEST-911-METHOD-ENFORCEMENT`         | Méthodes HTTP autorisées (GET, POST, PUT, DELETE...)  |
| `REQUEST-913-SCANNER-DETECTION`          | Détection de scanners de vulnérabilités (Nikto, etc.) |
| `REQUEST-920-PROTOCOL-ENFORCEMENT`       | Conformité protocole HTTP (encodages, longueurs...)   |
| `REQUEST-921-PROTOCOL-ATTACK`            | Attaques protocolaires (HTTP smuggling, etc.)         |
| `REQUEST-930-APPLICATION-ATTACK-LFI`     | Local File Inclusion (path traversal `../../etc/passwd`) |
| `REQUEST-931-APPLICATION-ATTACK-RFI`     | Remote File Inclusion (inclusion de fichiers distants) |
| `REQUEST-932-APPLICATION-ATTACK-RCE`     | Remote Code Execution (commandes shell, PowerShell)   |
| `REQUEST-933-APPLICATION-ATTACK-PHP`     | Injections PHP (fonctions dangereuses, wrappers)      |
| `REQUEST-934-APPLICATION-ATTACK-GENERIC` | Attaques génériques (injections de code)              |
| `REQUEST-941-APPLICATION-ATTACK-XSS`     | Cross-Site Scripting (`<script>`, événements JS)      |
| `REQUEST-942-APPLICATION-ATTACK-SQLI`    | SQL Injection (UNION, OR 1=1, commentaires SQL)       |
| `REQUEST-943-SESSION-FIXATION`           | Fixation de session (vol de cookies)                  |
| `REQUEST-944-APPLICATION-ATTACK-JAVA`    | Injections Java (OGNL, deserialization)               |
| `REQUEST-949-BLOCKING-EVALUATION`        | Évaluation du score d'anomalie → décision de blocage  |

**Règles de réponse (RESPONSE)** — Analysent les réponses du serveur :

| Fichier CRS                         | Protection                                            |
| ------------------------------------ | ----------------------------------------------------- |
| `RESPONSE-950-DATA-LEAKAGES`        | Fuites de données dans les réponses                   |
| `RESPONSE-951-DATA-LEAKAGES-SQL`    | Fuites de messages d'erreur SQL                       |
| `RESPONSE-952-DATA-LEAKAGES-JAVA`   | Fuites de stack traces Java                           |
| `RESPONSE-953-DATA-LEAKAGES-PHP`    | Fuites d'erreurs PHP                                  |
| `RESPONSE-954-DATA-LEAKAGES-IIS`    | Fuites spécifiques IIS/ASP.NET                        |
| `RESPONSE-959-BLOCKING-EVALUATION`  | Évaluation du score d'anomalie côté réponse           |
| `RESPONSE-980-CORRELATION`          | Corrélation requête/réponse pour le scoring final     |

#### 11.6.3 Mode de fonctionnement — Anomaly Scoring

Les CRS fonctionnent en **mode anomaly scoring** (mode par défaut, recommandé) :

```
Requête entrante
     │
     ├─ Règle 920xxx matche → score += 3 (WARNING)
     ├─ Règle 942xxx matche → score += 5 (CRITICAL)
     ├─ Règle 941xxx matche → score += 5 (CRITICAL)
     │
     ▼
  Score total = 13
     │
     ├─ Seuil (inbound_anomaly_score_threshold) = 5
     │
     ▼
  Score 13 ≥ Seuil 5 → BLOQUÉ (403 Forbidden)
```

**Avantage du mode anomaly scoring** : une seule règle de faible gravité
(score 2-3) ne bloque pas la requête. Il faut accumuler suffisamment de
signaux suspects pour dépasser le seuil. Cela **réduit les faux positifs**
tout en maintenant une détection efficace.

Le mode de MCP Vault est **BLOCKING** (`SecRuleEngine On`) sur **tous les
endpoints** : `/health`, `/mcp` et `/admin/api`.

#### 11.6.4 Exclusions ciblées (fine-tuning)

Après activation du mode blocking, un fine-tuning a été réalisé en exécutant
les 295 tests e2e via le WAF. Deux règles CRS généraient des **faux positifs**
légitimes sur les payloads JSON-RPC et REST de MCP Vault :

##### Faux positif 1 — Règle 920540 (Unicode bypass)

| Aspect        | Détail                                                                      |
| ------------- | --------------------------------------------------------------------------- |
| **Règle CRS** | `REQUEST-920-PROTOCOL-ENFORCEMENT` / ID 920540                             |
| **Description**| "Possible Unicode character bypass detected"                                |
| **Cause**     | Les payloads JSON contiennent des caractères français encodés UTF-8 :       |
|               | `\u00e9` (é), `\u00e8` (è), `\u2014` (—) dans les descriptions de vaults, |
|               | policies et secrets. Le CRS les interprète comme une tentative de bypass.   |
| **Impact**    | Bloque les créations/mises à jour de vaults et policies avec accents        |
| **Exclusion** | `SecRule REQUEST_URI "@beginsWith /mcp" ... ctl:ruleRemoveById=920540`      |
| **Scope**     | `/mcp` (JSON-RPC) et `/admin/api` (REST JSON) uniquement                   |
| **Risque**    | Faible — l'authentification Bearer + policies MCP protègent déjà ces endpoints |
| **ID interne**| Règles 10001 et 10002 dans `coraza.conf`                                   |

##### Faux positif 2 — Règle 932120 (PowerShell RCE)

| Aspect        | Détail                                                                      |
| ------------- | --------------------------------------------------------------------------- |
| **Règle CRS** | `REQUEST-932-APPLICATION-ATTACK-RCE` / ID 932120                           |
| **Description**| "Remote Command Execution: Windows PowerShell Command Found"                |
| **Cause**     | Les noms de policies comme `"test-path-restrict"` contiennent `"test-path"` |
|               | qui matche le cmdlet PowerShell `Test-Path`. Les noms d'outils MCP comme   |
|               | `"secret_write"` ou `"vault_delete"` peuvent aussi déclencher cette règle. |
| **Impact**    | Bloque les créations de policies et certains appels MCP avec policy_id      |
| **Exclusion** | `SecRule REQUEST_URI "@beginsWith /mcp" ... ctl:ruleRemoveById=932120`      |
| **Scope**     | `/mcp` (JSON-RPC) et `/admin/api` (REST JSON) uniquement                   |
| **Risque**    | Faible — MCP Vault ne traite aucune commande PowerShell. La couche MCP     |
|               | valide et typifie tous les inputs avant traitement.                         |
| **ID interne**| Règles 10003 et 10004 dans `coraza.conf`                                   |
| **Note**      | La règle 932120 reste **active** sur `/health` pour sécurité maximale       |

##### Récapitulatif des exclusions

| ID interne | Endpoint        | Règle CRS | Motif du faux positif                    |
| ---------- | --------------- | --------- | ---------------------------------------- |
| 10001      | `/mcp`          | 920540    | Unicode français dans les payloads JSON  |
| 10002      | `/admin/api`    | 920540    | Unicode français dans les payloads JSON  |
| 10003      | `/mcp`          | 932120    | `test-path` dans les noms de policies    |
| 10004      | `/admin/api`    | 932120    | `test-path` dans les noms de policies    |

#### 11.6.5 Headers de sécurité

Le Caddyfile injecte les headers de sécurité suivants sur toutes les réponses :

| Header                          | Valeur                                                                        | Protection                                    |
| ------------------------------- | ----------------------------------------------------------------------------- | --------------------------------------------- |
| `X-Content-Type-Options`        | `nosniff`                                                                     | Empêche le MIME sniffing                      |
| `X-Frame-Options`               | `DENY`                                                                        | Empêche l'intégration en iframe (clickjacking)|
| `Referrer-Policy`               | `strict-origin-when-cross-origin`                                             | Limite les informations envoyées au referer   |
| `X-XSS-Protection`              | `1; mode=block`                                                               | Active le filtre XSS du navigateur (legacy)   |
| `Content-Security-Policy`       | `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;` | Restreint les sources de contenu |
| `-Server`                       | *(supprimé)*                                                                  | Masque l'identité du serveur Caddy            |

> **Note** : `unsafe-inline` est nécessaire dans `script-src` et `style-src`
> car la SPA admin utilise du JavaScript et CSS inline. C'est mitigé par le fait
> que la console admin est protégée par authentification Bearer admin.

#### 11.6.6 Configuration réseau et timeouts

| Paramètre                     | Valeur  | Justification                                          |
| ----------------------------- | ------- | ------------------------------------------------------ |
| Port WAF externe              | 8085    | Configurable via `WAF_PORT` (`.env`)                   |
| Port MCP interne              | 8030    | `expose` uniquement (non accessible depuis l'extérieur)|
| `dial_timeout`                | 10s     | Temps max pour établir la connexion vers mcp-vault     |
| `response_header_timeout`     | 120s    | Appels MCP potentiellement longs (ingestion, SSH sign) |
| `read_timeout`                | 120s    | Idem, pour la lecture de la réponse complète            |
| `write_timeout`               | 120s    | Idem, pour l'envoi de la requête                       |
| `SecRequestBodyLimit`         | 10 MB   | Taille max du corps de requête (payloads MCP JSON)     |
| `SecRequestBodyNoFilesLimit`  | 5 MB    | Taille max sans fichiers uploadés                      |
| Admin Caddy                   | `off`   | L'API d'administration Caddy est désactivée (sécurité) |

#### 11.6.7 Méthodes HTTP autorisées

Le WAF n'autorise que les méthodes nécessaires au protocole MCP et à l'API admin :

```
GET HEAD POST OPTIONS PUT PATCH DELETE
```

Configuré via `SecAction id:900200` avant le chargement des CRS. La méthode
`DELETE` est requise par le protocole MCP pour fermer les sessions SSE.
`PUT` est utilisé par l'API admin pour mettre à jour les tokens.

#### 11.6.8 Procédure de diagnostic et ajout d'exclusions

Quand des tests échouent après un changement de configuration WAF, voici la
procédure de diagnostic :

```
1. Exécuter les tests via le WAF
   $ MCP_URL=http://localhost:8085 MCP_TOKEN="$ADMIN_BOOTSTRAP_KEY" \
     python tests/test_e2e.py

2. Identifier les tests en échec
   → Un test en échec retourne status=error avec "MCP call failed"

3. Consulter les logs Coraza
   $ docker compose logs waf 2>&1 | grep "Coraza\|id \"9"
   → Chercher les lignes avec "id" suivi du numéro de règle
   → Exemple : "id \"932120\"" identifie la règle 932120

4. Comprendre la règle
   → Consulter https://coreruleset.org/docs/ (documentation CRS)
   → Vérifier si c'est un faux positif (payload légitime détecté comme attaque)

5. Ajouter une exclusion ciblée dans waf/coraza.conf
   SecRule REQUEST_URI "@beginsWith /mcp" \
       "id:100XX,phase:1,pass,nolog,\
        ctl:ruleRemoveById=XXXXXX"
   → Toujours limiter le scope à l'endpoint concerné
   → Toujours documenter le motif du faux positif en commentaire
   → Utiliser des IDs internes à partir de 10005

6. Rebuild et retester
   $ docker compose build waf && docker compose up -d waf
   $ MCP_URL=http://localhost:8085 MCP_TOKEN="$ADMIN_BOOTSTRAP_KEY" \
     python tests/test_e2e.py
```

> ⚠️ **Règle d'or** : ne jamais désactiver une règle CRS globalement.
> Toujours limiter l'exclusion au scope minimum (`@beginsWith /mcp`
> ou `@beginsWith /admin/api`). Les règles restent actives sur `/health`
> et tout autre endpoint non spécifiquement exclu.

#### 11.6.9 Tests e2e WAF dédiés (TEST 15)

Les tests e2e incluent un groupe dédié (`--test waf_security`) qui valide
que le WAF bloque bien les attaques simulées :

| Catégorie         | Attaque simulée                                            | Résultat attendu |
| ----------------- | ---------------------------------------------------------- | ---------------- |
| **LFI**           | `GET /admin/static/../../etc/passwd`                       | 403 Forbidden    |
| **LFI**           | `GET /../../../etc/shadow`                                 | 403 Forbidden    |
| **SQLi**           | `POST /mcp` avec `' OR 1=1 --` dans le body               | 403 Forbidden    |
| **SQLi**           | `POST /mcp` avec `UNION SELECT` dans le body               | 403 Forbidden    |
| **XSS**           | `POST /mcp` avec `<script>alert(1)</script>` dans le body  | 403 Forbidden    |
| **XSS**           | `POST /admin/api` avec `<img onerror=alert(1)>` dans data  | 403 Forbidden    |
| **RCE**           | `POST /mcp` avec `; cat /etc/passwd` dans le body          | 403 Forbidden    |
| **RCE**           | `POST /mcp` avec `$(whoami)` dans le body                  | 403 Forbidden    |
| **Scanner**       | `GET /health` avec `User-Agent: Nikto`                     | 403 Forbidden    |
| **Non-régression**| Requête MCP légitime via le WAF                            | 200 OK           |
| **Non-régression**| Payload JSON avec accents français (Unicode)               | 200 OK           |
| **Non-régression**| Création de policy avec `test-path` dans le nom            | 200 OK           |

> **Note** : ces tests ne s'exécutent que quand `MCP_URL` pointe vers le WAF
> (`:8085`). Si les tests tournent directement contre mcp-vault (`:8030`),
> le groupe WAF est automatiquement skippé.

---

## 12. Exemple d'utilisation

### 12.1 Setup initial (admin)

```bash
# CLI : créer le premier token admin
python scripts/mcp_cli.py --token $ADMIN_BOOTSTRAP_KEY admin create-token \
  --name "vault-admin" --permissions admin

# CLI : créer un espace pour les serveurs de prod
python scripts/mcp_cli.py vault create serveurs-prod \
  --description "Clés SSH et passwords des serveurs de production"

# CLI : stocker une clé SSH
python scripts/mcp_cli.py secret store serveurs-prod ssh-key-web-prod-01 \
  --value "$(cat ~/.ssh/id_ed25519)" --type ssh_private_key

# CLI : créer un token pour le MCP Agent (lecture seule, espace serveurs-prod)
python scripts/mcp_cli.py admin create-token \
  --name "mcp-agent-sre" --permissions read --vault-ids serveurs-prod
```

### 12.2 Utilisation par un agent (via MCP)

```python
# L'agent (via MCP Agent → MCP Vault) récupère un secret :
result = await vault_client.call("secret_get", {
    "vault_id": "serveurs-prod",
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
