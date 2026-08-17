# Architecture — MCP Vault

> **Version** : 0.16.0 | **Date** : 2026-08-17 | **Auteur** : Cloud Temple
> **Projet** : mcp-vault | **Licence** : Apache 2.0  
> **Statut** : ✅ Implémenté — Production-ready (PKI interne v0.5.x + C18 v0.6.x)

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
    Humain (CLI Click)       Mission Controller       MCP Agent (instances)
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
│  │  Pile Middleware ASGI (6 couches, voir §2.3)               │  │
│  │                                                            │  │
│  │  PkiMiddleware          → /acme/*, /pki/ca/*.pem (no-auth) │  │
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
│  │  • API REST admin (REST routes, auth admin)                │  │
│  │  • Design Cloud Temple (dark theme #0f0f23, accent #41a890)│  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  36 Outils MCP (façade)                                    │  │
│  │                                                            │  │
│  │  Vaults :  vault_create, _list, _info, _update, _delete    │  │
│  │  Secrets : secret_write, _read, _list, _delete             │  │
│  │  Types :   secret_types, secret_generate_password          │  │
│  │  Wrap :    secret_wrap, _revoke_wrap, _wrap_lookup,        │  │
│  │            secret_consume (JIT broker + C18)               │  │
│  │  SSH CA :  ssh_ca_setup, _sign_key, _public_key,           │  │
│  │            _list_roles, _role_info                         │  │
│  │  PKI :     pki_ca_setup, _public_key, _list_roles,         │  │
│  │            _role_info, pki_list_certs, pki_issue_cert,     │  │
│  │            _revoke_cert, pki_ca_rotate_intermediate        │  │
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
| **PkiMiddleware**         | Proxy ACME + distribution CA (`/acme/*`, `/pki/ca/*.pem`) non-auth | ASGI middleware (v0.5.0) |
| **AdminMiddleware**       | Console admin web + API REST admin               | ASGI middleware (starter-kit) |
| **HealthCheckMiddleware** | Health check HTTP (/health, /healthz, /ready)    | ASGI middleware               |
| **AuthMiddleware**        | Auth Bearer Token + **PEP mission JWT** (#47) + **octroi périmètre vault** (MissionBindingStore, #69) + ContextVar | ASGI middleware (starter-kit) |
| **LoggingMiddleware**     | Logging requêtes + ring buffer mémoire           | ASGI middleware (starter-kit) |
| **Outils MCP**            | Façade MCP (39 outils)                           | FastMCP (starter-kit)         |
| **hvac client**           | Client Python vers OpenBao                       | `hvac` library                |
| **OpenBao process**       | Moteur de secrets (chiffrement, policies, audit) | Binaire `bao` (Go, embedded)  |
| **S3 Sync Manager**       | Synchronisation storage local ↔ S3               | boto3 + tar/gzip              |
| **Token Manager**         | Gestion des tokens MCP, cache mémoire TTL 5min   | JSON sur S3 (starter-kit)     |

### 2.3 Pile middleware ASGI

L'application MCP Vault est assemblée en 6 couches ASGI, empilées de l'extérieur
vers l'intérieur. Chaque couche intercepte les requêtes avant de les passer à la suivante :

```
PkiMiddleware → AdminMiddleware → HealthCheckMiddleware → AuthMiddleware → LoggingMiddleware → FastMCP
```

| Couche (ext → int)        | Intercepte                                  | Passe au suivant si        |
| ------------------------- | ------------------------------------------- | -------------------------- |
| **PkiMiddleware**         | `/acme/*`, `/pki/ca/*.pem` (non-auth, RFC 8555) | Pas un chemin PKI/ACME |
| **AdminMiddleware**       | `/admin`, `/admin/static/*`, `/admin/api/*` | Pas un chemin admin        |
| **HealthCheckMiddleware** | `/health`, `/healthz`, `/ready`             | Pas un chemin health       |
| **AuthMiddleware**        | Toutes les requêtes MCP (Bearer **ou** PEP mission JWT) | Token valide → ContextVar  |
| **LoggingMiddleware**     | Toutes les requêtes                         | Log + ring buffer 200 ent. |
| **FastMCP app**           | MCP Protocol (Streamable HTTP)              | —                          |

`PkiMiddleware` (v0.5.0) est la couche la plus externe : les endpoints ACME/PKI
sont délibérément non-authentifiés (standard PKI/ACME — JWS RFC 8555), avec
validation anti-traversal des paths et `follow_redirects=False` (anti-SSRF).

**Assemblage dans `create_app()`** :

```python
def create_app():
    from .auth.middleware import AuthMiddleware, LoggingMiddleware
    from .admin.middleware import AdminMiddleware
    from .pki_middleware import PkiMiddleware

    app = mcp.streamable_http_app()       # FastMCP (innermost)
    app = LoggingMiddleware(app)           # Logging + ring buffer
    app = AuthMiddleware(app)              # Auth Bearer + ContextVar
    app = HealthCheckMiddleware(app)       # /health, /healthz, /ready
    app = AdminMiddleware(app, mcp)        # /admin
    app = PkiMiddleware(app)               # /acme/*, /pki/ca/*.pem (outermost)

    return app
```

**HealthCheckMiddleware** — Middleware ASGI dédié qui intercepte les endpoints
de health check et retourne un JSON directement, **sans passer par MCP** ni par
l'auth. Ceci permet au WAF/load balancer de vérifier l'état du service.

Depuis l'issue #103, ces endpoints répondent à **deux questions distinctes** :

| Endpoint | Question | Sain | Dégradé |
| --- | --- | --- | --- |
| `/healthz` | *liveness* — le processus répond-il ? | 200 `alive` | **200 `alive`** |
| `/health`, `/ready` | *disponibilité* — le coffre peut-il servir ? | 200 `healthy` | **503** |

```json
{"status": "healthy", "service": "mcp-vault", "version": "0.15.0", "transport": "streamable-http"}
```

`status` appartient à une **énumération fermée**, une par question :

- disponibilité (`/health`, `/ready`) : `healthy` | `sealed` | `unavailable` ;
- liveness (`/healthz`) : `alive`.

Aucun détail de dépendance n'est exposé sur ces surfaces publiques — le
diagnostic vit dans les journaux et sur `/admin/api/health`, qui exige un bearer
valide (route « tout token », pas réservée aux admins).

`/healthz` ne sonde **jamais** OpenBao : c'est la cible sûre pour une sonde de
liveness ou un autoheal. Rendre ce chemin rouge sur une dépendance indisponible
ferait redémarrer en boucle un coffre **scellé**, ce qui ne le descelle pas.

**AuthMiddleware + ContextVar** — Le middleware stocke les infos du token
authentifié dans un `contextvars.ContextVar` Python, accessible ensuite par
chaque outil MCP via `check_access()`, `check_write()`, `check_admin()`.
Ce mécanisme est **request-scoped** (isolé par requête, thread-safe en asyncio).

**AuthMiddleware = PEP mission JWT à la porte `/mcp` (#47, v0.8.0)** — En plus du
Bearer opaque historique, `AuthMiddleware` est le **second point d'application** du
`mission_token` JWT ES256 de mcp-mission (le premier étant `secret_consume`/C18, à la
consommation). Il en est l'**unique lecteur du header** et l'unique writer du
ContextVar sur `/mcp`. Depuis le Lot 2 (#86), les deux points d'application délèguent
à la **même** fonction de validation (`mission_jwt.validate_mission_token()`) : un
JWT authentique mais destiné à une autre instance (aud multiple, `component_id`
différent) est rejeté de façon identique aux deux portes, plus seulement à celle-ci.
Piloté par `MCP_AUTH_MODE` :

- `bearer` *(défaut)* — bearer opaque **valide exigé** : sans jeton, ou jeton
  invalide, **401** au middleware (#116, cf. §11.3e) ;
- `bearer-anonymous` — ⚠️ **mode d'exception** : ancien comportement de `bearer`,
  un appelant sans identité atteint les outils. `CRITICAL` au démarrage ;
- `jwt` — `mission_token` JWT ES256 obligatoire (bearer opaque refusé) ;
- `dual-stack` — JWT valide **ou** bearer opaque valide (migration).

En `jwt`/`dual-stack`, le middleware **refuse activement** (jamais d'injection
silencieuse de `None`) : `401` (token absent/opaque/JWT invalide, `exp` strict
leeway=0, `iat` hors tolérance `MISSION_TOKEN_LEEWAY_SECONDS`), `403` (`aud` ne
contient pas `MCP_INSTANCE_ID`, `component_id[MCP_COMPONENT_KIND] ≠ MCP_INSTANCE_ID`,
mission inactive), `503` (JWKS indisponible — fail-close). Un JWT structurellement
invalide (`alg=none`/`HS256`) part vers la validation et finit en `401` — **jamais**
de fallback vers le bearer. La bootstrap key admin reste acceptée (break-glass,
constant-time avant tout dispatch JWT).

Le **cache JWKS est unique au processus** (`auth/mission_jwt.py` : backoff exponentiel +
jitter, ETag/304, fail-close, throttle anti-DoS sur `kid` inconnu) et partagé avec
`secret_consume` (fin de tout second cache divergent). Audience = **source unique**
`resolved_mission_aud` (= `MCP_INSTANCE_ID`, alias legacy `MISSION_TOKEN_AUD` ; divergence
→ fail-fast au boot). Vérification mission active en allow-list `{RUNNING, WAITING_HUMAN,
PAUSED}` (fail-close). Chaque refus est audité (`decision_id` local + `decision_id`
émetteur via `provenance`) **sans jamais** le token ni un secret.

> Une identité mission valide est **authentifiée et liée à l'instance**, puis mcp-vault
> (**PDP local**) lui résout un périmètre vault provisionné localement (voir ci-dessous).
> Sans octroi → **aucun accès** (deny-by-default — `check_access` refuse une identité
> `mission_jwt` sans périmètre, jamais owner-based). L'**Admin API** (`/admin/api/*`) reste
> une surface séparée **bearer/bootstrap-only** : un mission JWT y est refusé (401).
> Endpoint admin `POST /admin/api/auth/jwks/reload` = rechargement forcé du JWKS.

**MissionBindingStore = octroi de périmètre vault local (#69, v0.8.0)** — Le `mission_token`
ne porte **aucune** autorisation vault ; mcp-vault est le **PDP** qui provisionne et applique
l'autorisation localement, indexée par `tenant_id`. `AuthMiddleware._validate_mission_jwt`, après
validation JWT + mission active, appelle `MissionBindingStore.resolve(tenant_id)` et injecte
`allowed_resources`/`permissions`/`policy_id` dans le `token_info` — sinon deny-all préservé.

- **Stockage** : un **fichier S3 par instance** (`_system/mission_bindings/{encoded_instance_id}.json`),
  cache TTL 5 min, calqué sur PolicyStore/TokenStore. Le fichier-par-instance réduit le
  last-write-wins cross-instance (bucket partagé) ; `instance_id` est filtré à la lecture
  (défense en profondeur). Révocation instantanée inter-instance (CAS/ETag) = hors périmètre (#51).
- **Contrat d'octroi** : `permissions ∈ {['read'], ['read','write']}` (jamais `write` seul, `[]`
  ni `admin`) ; `allowed_resources` = vrais `vault_id` non vides/dédupliqués/sans `*` ; `policy_id`
  optionnel à intégrité référentielle. **Data-plane strict** : l'allow-list d'outils mission exclut
  l'admin-plane (`vault_create/update/delete`, `ssh_*`) — une mission ne fait jamais d'administration.
- **Modèle de menace / fail-close** : (1) clé de résolution = `tenant_id` **cryptographiquement
  validé** (anti fail-open par confusion de clé) ; (2) binding absent/désactivé/expiré → deny-all ;
  (3) **store configuré mais indisponible/corrompu → `503 binding_store_unavailable`** (état
  `available/invalid` explicite, refus **observable** audité, jamais un deny silencieux masquant une
  panne du PDP ; **aucune écriture** tant que l'état est invalide → pas d'écrasement destructeur d'un
  fichier corrompu) ; (4) cross-tenant impossible : un binding tenant A n'ouvre rien pour tenant B.
- **Granularité tenant-wide (assumée)** : toutes les missions actives d'un `tenant_id` partagent le
  périmètre. Fenêtre de propagation d'une révocation = TTL cache (≤ 5 min) inter-instance. Grain
  par mission = déjà présent à la consommation (`secret_consume`/C18), évolution future sur ce chemin.
- **Administration** : `GET/POST/DELETE /admin/api/mission-bindings[/{tenant_id}]` + `.../purge`,
  **bearer/bootstrap-only** (jamais via mission JWT), piloté par le CLI Click (le groupe `mission-binding` n'est pas exposé dans la console), audit `decision_id` en tête.

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
AdminMiddleware (ASGI, derrière PkiMiddleware)
    │
    ├── GET /admin           → SPA HTML (admin.html)
    ├── GET /admin/static/*  → fichiers statiques (CSS, JS, images)
    └── */admin/api/*        → API REST admin (Bearer valide requis ;
                               autorisation selon la route : lecture, `write`
                               ou `admin`)
            │
            ├── GET  /admin/api/health          → état du serveur + OpenBao status
            ├── GET  /admin/api/vaults          → lister les vaults
            ├── POST /admin/api/vaults          → créer un vault
            ├── GET  /admin/api/vaults/{id}/secrets[?prefix=] → lister un niveau (nav dossier, #81)
            ├── GET  /admin/api/vaults/{id}/secrets/{path}    → lire un secret (feuille)
            ├── POST /admin/api/vaults/{id}/secrets           → upsert ; `create_only: true` impose KV v2 CAS=0 (#92)
            ├── GET  /admin/api/tokens          → lister les tokens S3
            ├── POST /admin/api/tokens          → créer un token
            ├── PUT  /admin/api/tokens/{name}   → modifier un token (policy / permissions / vaults)
            ├── DELETE /admin/api/tokens/{name}  → révoquer un token
            ├── POST /admin/api/tokens/purge    → purger les tokens révoqués (rétention + dry-run)
            ├── GET  /admin/api/logs            → activité récente (ring buffer 200)
            └── … + policies, PKI (CA/ACME), audit, whoami, generate-password (cf. admin/api.py)
```

#### 4 vues

| Vue           | Description                                                                                                |
| ------------- | ---------------------------------------------------------------------------------------------------------- |
| **Dashboard** | État du serveur (version, OpenBao sealed/unsealed, S3 sync status, last sync, vaults count), stats tokens  |
| **Vaults**    | Grille des vaults avec nombre d'**entrées** (1er niveau), date de création. Clic = détail + **navigation par dossier** KV v2 : dossiers dépliables, feuilles lisibles (pas les valeurs en liste ; #81) |
| **Tokens**    | Table CRUD : créer (checkboxes vault_ids, permissions), info, révoquer, purger les révoqués (dry-run). Token brut affiché une seule fois  |
| **Activité**  | Logs temps réel (ring buffer mémoire 200 entrées, auto-refresh 5s). Méthode, path, status, durée           |

#### Sécurité de la console admin

- **Authentification admin** : seul le `ADMIN_BOOTSTRAP_KEY` ou un token S3 avec permission `admin` donne accès à l'API
- **HTML/CSS/JS publics** : la page de login est servie sans auth (l'auth se fait côté API)
- **CORS preflight** : OPTIONS géré pour les appels AJAX cross-origin
- **Path traversal** : protection contre les `../` dans les chemins statiques ; validation canonique par segments des chemins de secrets (rejet `//`, `.`, `..`, slash terminal ; #81)
- **Listing contrôlé + moindre privilège (#81)** : le contenu d'un vault (noms **et** cardinalité) n'est exposé qu'aux identités ayant le droit `secret_list` (policy vérifiée). La fiche vault ne liste plus les noms ; le compteur d'entrées (tableau, tableau de bord, outil `vault_info`) est conditionné à ce droit via un test **silencieux** (`can_read_vault_content`, sans faux événement d'audit)

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
|  = Sync periodique (toutes les N secondes, SEULEMENT si change)   |
+-------------------------------------------------------------------+
```

Le File storage OpenBao pointe sur un **volume Docker persistant** (pas /tmp).
Le S3 sert de **backup distant** synchronise regulierement.

### 4.3 Strategies de sync S3

Trois niveaux de protection, configurables :

| Strategie             | Quand                                   | Perte max en cas de crash | Cout                             |
| --------------------- | --------------------------------------- | ------------------------- | -------------------------------- |
| **write-through**     | Apres chaque secret_store/rotate/delete | 0                         | Eleve (1 upload S3 par ecriture) |
| **periodic** (defaut) | Toutes les N secondes, SI l'etat a change (defaut 60s) | N secondes | Faible a l'idle, modere sinon |
| **lazy**              | Toutes les N minutes (defaut 5min)      | N minutes                 | Faible                           |

Recommandation : **periodic** a 60 secondes pour un bon compromis.

**Detection de changement (2026-07)** : le PUT periodique est conditionne a une
empreinte de l'etat source (chemins, contenu, type — jamais le tar.gz genere,
dont les metadonnees varient sans changement metier). Sans cette garde, un
bucket avec versioning S3 active et sans lifecycle accumule une version par
cycle indefiniment (incident constate en production : 6000+ versions, 600+ Mo
en quelques jours). Voir `s3_sync.py` (`TECHNICAL.md` §3.3) pour le mecanisme.

### 4.4 Cycle de vie complet

```
DEMARRAGE (startup) — cf. `lifecycle.py::vault_startup()`
  |
  +-- 1. Charger le Token Store depuis S3
  |
  +-- 2. Verifier si le volume Docker /openbao/file/ contient des donnees
  |     FIABLES (`_check_local_data_status()`) : la seule PRESENCE du
  |     marqueur `_RESTORE_MARKER_FILENAME` (cf. encadre ci-dessous) invalide
  |     tout contenu physique, quel qu'il soit — pas de comparaison de
  |     timestamp, juste local-fiable vs pas-encore-restaure-avec-certitude
  |     -> Si oui (fiable) : le volume local EST la source de verite (crash
  |        recovery)
  |     -> Si non (vide, ou marqueur present) : tentative de restauration
  |        depuis S3 (`download_from_s3()`, resultat a 3 etats — voir
  |        encadre ci-dessous)
  |        -> RESTORED         : extraction dans un STAGING interne a data_dir
  |           (meme filesystem que data_dir — le volume Docker est monte
  |           EXACTEMENT sur data_dir, pas sur son parent), PUIS promotion par
  |           renommages INDIVIDUELS (chacun atomique, la BOUCLE ne l'est PAS)
  |           uniquement si l'extraction est INTEGRALE. Une extraction qui
  |           echoue apres avoir deja ecrit certains membres ne laisse alors
  |           RIEN dans data_dir (1er bloquant "restauration non atomique").
  |           Un marqueur durable, pose AVANT tout nettoyage/extraction et
  |           retire SEULEMENT ici (promotion integralement reussie), protege
  |           contre le residu d'une promotion PARTIELLE (crash/erreur I/O
  |           au milieu de la boucle de renommages — 2e bloquant distinct,
  |           trouve dans un round de revue de diff ULTERIEUR au premier)
  |        -> CONFIRMED_ABSENT : premiere execution legitime (S3 confirme
  |           l'absence, 404/NoSuchKey) — on continue, coffre vide
  |        -> FAILED           : erreur AMBIGUE (reseau, archive corrompue...)
  |           — DEMARRAGE REFUSE (vault_startup retourne False). On ne risque
  |           jamais d'initialiser un coffre vide par-dessus une sauvegarde
  |           distante potentiellement valide (durcissement 2026-07, cf.
  |           incident versions S3 ci-dessous). Ce refus n'est effectif que
  |           combine a la garde du shutdown ci-dessous (ARRET PROPRE, pt. 3)
  |
  +-- 3. Demarrer le process OpenBao (subprocess, bao server)
  |
  +-- 4. Initialiser si premiere fois (Shamir shares=1, threshold=1)
  |
  +-- 5. Unseal
  |
  +-- 6. Demarrer le sync S3 periodique (conditionnel, voir OPERATIONS NORMALES)
  |
  +-- 7. MCP Vault est pret a servir

OPERATIONS NORMALES
  |
  +-- Les outils MCP appellent OpenBao via hvac
  |
  +-- Certaines operations PKI (setup CA, emission/revoke/rotate certificat)
  |   forcent un upload S3 IMMEDIAT (`upload_to_s3()` sans argument, TOUJOURS
  |   inconditionnel) — les autres ecritures (secret_store, rotate, delete,
  |   vault_create/delete) ne forcent RIEN : elles s'appuient sur le sync
  |   periodique ci-dessous.
  |
  +-- Sync S3 periodique (boucle asyncio, toutes les VAULT_S3_SYNC_INTERVAL
      secondes, defaut 60s) — `_periodic_sync_tick()` appelle
      `upload_to_s3(skip_if_unchanged=True)` :
      -> Construit l'archive tar.gz ET une empreinte de l'etat source DANS LA
         MEME PASSE (`_snapshot_and_archive`) — chemins relatifs tries, contenu
         des fichiers, type (fichier/repertoire/symlink). PAS le tar.gz lui-meme
         (ses metadonnees varient sans changement metier).
      -> Si l'empreinte est IDENTIQUE a celle du dernier PUT CONFIRME reussi ET
         qu'aucun echec ambigu n'est en attente : skip (pas d'upload inutile).
      -> Sinon : PUT reel. La reference n'avance QU'APRES un PUT confirme
         reussi — un echec (y compris un timeout apres envoi) la laisse
         inchangee et interdit tout skip jusqu'au prochain PUT reussi.

  ENCADRE — Incident versions S3 (2026-07) : le bucket de production a le
  versioning S3 active SANS lifecycle. Avant ce durcissement, le PUT etait
  INCONDITIONNEL a chaque cycle -> 6000+ versions, 600+ Mo accumules en
  quelques jours sans aucune ecriture OpenBao reelle. Voir `TECHNICAL.md` §3.3.

ARRET PROPRE (SIGTERM) — cf. `lifecycle.py::vault_shutdown(skip_upload=...)`
  |
  +-- 1. Arreter le sync periodique (plus d'upload en parallele)
  +-- 2. Seal OpenBao + effacer les cles unseal en memoire
  +-- 3. Upload S3 final (`upload_to_s3()` sans argument, TOUJOURS incondi-
  |      tionnel par rapport a l'etat inchange/change — SAUF si le demarrage
  |      n'a PAS abouti : `server.py` calcule skip_upload=not ok a partir du
  |      booleen deja retourne par vault_startup(). Sans cette garde, le
  |      refus de demarrer (DEMARRAGE, pt. 2, cas FAILED) etait cosmetique :
  |      `server.py` continue en "mode degrade" meme apres un vault_startup
  |      en echec (comportement preexistant, non modifie ici), et cet upload
  |      final aurait quand meme pu ecraser une sauvegarde S3 valide avec
  |      l'etat local incomplet/jamais initialise (bloquant ferme en revue
  |      de diff — le plus serieux des 3 trouves a ce stade)
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
│   └── openbao-data.tar.gz      # Storage OpenBao compressé (tout le File backend).
│                                 # Aucun fichier de métadonnées séparé : la
│                                 # détection de changement (empreinte d'état,
│                                 # cf. §4.4) vit en mémoire process, pas sur S3.
│
├── _init/
│   └── init_keys.json.enc       # Clés unseal + root token (chiffrées)
│                                 # Chiffrement : AES-256-GCM
│                                 # Clé dérivée de ADMIN_BOOTSTRAP_KEY via PBKDF2
│                                 # ⚠️ JAMAIS stocké en clair — ni sur S3, ni localement
│                                 # Le fichier local est supprimé après unseal
│
└── _meta.json                   # {version: "0.8.0", created_at: "...", vaults_count: 5}
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

### 6.1b Isolation owner-based — durcissement canonicalisation `vault_id` (2026-07-23)

Quand `allowed_resources=[]` sur un token, l'accès retombe sur l'isolation
**owner-based** : `check_vault_owner()` (`vault/spaces.py`) autorise
uniquement si `_vault_meta.created_by == client_name` du bearer, et refuse
sinon (fail-close si la métadonnée est absente).

**Vulnérabilité fermée** : un `vault_id` **non canonique** (ex.
`"agentic-platform/"`, slash final) faisait traiter `check_vault_owner()`
comme « ce vault n'existe pas » — repli sur l'isolation owner-based, donc
accès autorisé — alors qu'OpenBao/hvac **normalisent** ce même `vault_id`
vers le **même mount réel** que sa forme canonique. Un bearer scopé sur un
vault dont il n'est PAS propriétaire pouvait ainsi contourner intégralement
l'isolation cross-tenant en présentant une variante non canonique du
`vault_id` d'un autre tenant. Pas spécifique à un outil : affecte tout
appelant vault-scoped en mode owner-based (`check_access()`,
`_check_vault_access()` REST Admin, `mission_bindings`, `wrapping`, la
réservation de coffre SSH JIT opérateur — cf. §6.3b).

**Correctif** : nouveau module feuille sans dépendance
`mcp_vault/vault_ids.py` (`is_valid_vault_id()`, ancré par `fullmatch` — pas
`match`, pour fermer le piège classique d'un `\n` final), consommé
systématiquement **avant** toute décision d'autorisation par
`check_access()`, `_check_vault_access()`, `_validate_vault_id()`
(`vault/spaces.py`), `validate_tenant_id()`/`validate_allowed_resources()`
(`auth/mission_bindings.py`), `_validate_inputs()` (`vault/wrapping.py`),
`_validate_role_name()` (`vault/ssh_ca.py`). Vérifié GO sur 4 rounds de
revue adversariale Codex indépendants (chacun a reproduit puis fermé une
variante distincte : slash final, double slash, encodage URL, bearer admin
légitime inclus). Voir CHANGELOG.md pour le détail complet.

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

### 6.3b Accès SSH JIT opérateur

Le parcours opérateur nominal ne réutilise pas `ssh_sign_key`, car cet outil
générique laisse le client choisir le coffre, le rôle et le TTL. Il expose deux
outils spécialisés :

| Outil | Perm | Contrat |
| --- | --- | --- |
| `ssh_operator_access_profiles()` | read | Retourne uniquement le profil, le coffre, la cible, le principal et le TTL autorisés |
| `ssh_request_operator_access(profile_id, public_key, reason)` | write | Accepte une clé publique pré-enrôlée et un motif, puis émet avec les attributs du profil |

Le profil serveur contient exactement `client_name`, `policy_id`,
`key_fingerprints`, `vault_id`, `role_name`, `principal`, `target` et
`ttl_seconds`. Il ne contient aucun token ni matériau privé. Le bearer doit
être nominatif, non-admin, disposer de `read,write`, être limité au coffre CA
et porter la policy exacte du profil. Bootstrap et Mission JWT sont refusés.

La policy dédiée doit autoriser uniquement les deux outils ci-dessus. MCP Vault
refuse l'émission si cette même policy autorise `ssh_sign_key` ou
`ssh_ca_setup`, même si le client appelle le bon endpoint. La clé est parsée au
format wire OpenSSH, limitée aux algorithmes `ssh-ed25519`/`ecdsa-sha2-nistp256`
(clés SSH standard, pas de RSA pour l'instant), comparée par son empreinte
SHA-256 enrôlée puis canonicalisée avant OpenBao. Le certificat fixe
`valid_principals` et un `key_id` unique.

> **Décision produit (2026-07-22)** : ce parcours n'exige PAS de dispositif
> matériel (clé de sécurité FIDO2/`sk-ssh-ed25519@openssh.com`, avec
> `verify-required` imposé sur le certificat) — c'était le design initial de
> l'issue #96/PR #97, décrit comme tel dans l'historique de durcissement
> ci-dessous ; ces mentions restent exactes pour l'époque où elles ont été
> écrites, mais ne décrivent plus le format de clé actuel. MCP Vault est
> avant tout un serveur MCP : l'identité de l'opérateur repose désormais
> uniquement sur le même mécanisme que le reste du système — un bearer
> token nominatif, scopé par une policy dédiée — sans cérémonie matérielle
> par personne. Un HSM Thales Luna, prévu ultérieurement, répond à un
> problème différent : protéger la clé privée de la CA elle-même au niveau
> infrastructure, pas prouver la présence physique d'un opérateur — les deux
> ne sont pas substituables. Le reste du modèle de sécurité décrit dans
> cette section (réservation de coffre, frontière structurelle, garde
> admin, test AST) est inchangé et reste pleinement d'actualité. Voir
> CHANGELOG.md pour le détail de la décision.

> **Bearer à durée bornée (2026-07-23, suite revue round 8)** : le bearer
> étant désormais la seule autorité d'émission, sa durée de vie doit être
> bornée. `SSH_OPERATOR_JIT_MAX_BEARER_EXPIRES_DAYS` (défaut 1 jour) refuse
> tout bearer sans expiration ou dont le temps restant dépasse ce plafond,
> contrôlé au point d'usage (`_current_operator_identity()`) — pas
> seulement à la création, puisque `TokenStore.update()` ne peut de toute
> façon pas modifier l'expiration d'un token existant. **Révocation
> multi-instance** : le cache TokenStore (300s) peut retarder la visibilité
> d'une révocation entre instances ; ce projet traite déjà ce type de race
> comme une limitation connue et différée pour PolicyStore/TokenStore
> (#51/#13) plutôt que de construire une synchronisation distribuée —
> même doctrine ici, assumée pour une première mise en production
> **mono-instance**. **Confirmé par Christophe (2026-07-23) : cette instance
> tourne en mono-instance à ce jour** — le compromis est donc valide
> aujourd'hui, mais devra être réévalué avant tout passage à plusieurs
> réplicas, blue/green ou rolling update avec chevauchement (aucun verrou de
> topologie technique dans le dépôt à ce jour, avis de revue Codex round 9).
> Voir CHANGELOG.md pour le détail complet.

**Fermeture du contournement par le signer générique** (durcissement post-revue
adversariale, 2 rounds) : la protection ci-dessus porte sur la policy
attachée au bearer opérateur lui-même — elle ne suffisait pas. Un bearer
*différent*, disposant légitimement d'un droit d'écriture générique sur le
même coffre (par exemple pour signer d'autres rôles SSH), pouvait obtenir via
`ssh_sign_key` ou `ssh_ca_setup` le même rôle OpenBao réservé (ex.
`bastion-operator`), avec une clé logicielle et sans `verify-required` — le
parcours FIDO2 dédié restait fermé, mais contournable par la porte à côté
(round 1). Un premier correctif limité au couple exact `(vault_id,
role_name)` s'est révélé **insuffisant** (round 2) : la CA SSH OpenBao est
partagée par *mount* (un seul mount par `vault_id`), donc le même bearer
pouvait créer un rôle **alternatif** (ex. `shadow-operator`, via
`ssh_ca_setup`) dans le même mount puis le signer génériquement — réserver un
nom de rôle n'est pas une frontière de sécurité tant que la CA elle-même
reste partagée et généralement inscriptible.

Le garde bloque désormais le **coffre entier** : les deux outils génériques
(tool MCP et route REST Admin `/admin/api/vaults/{vault_id}/ssh/{sign,setup}`)
refusent tout appel — quel que soit le rôle, existant ou à créer — sur tout
`vault_id` référencé par au moins un profil opérateur JIT configuré. Seul
`ssh_request_operator_access` peut émettre pour ces coffres.

Round 3 a trouvé un TROISIÈME contournement, encore différent : un `vault_id`
non canonique (`"agentic-platform/"`, slash final) échappait au garde par
comparaison de chaîne exacte, tout en désignant le MÊME mount OpenBao après
normalisation par `hvac`. Ce n'était pas un défaut spécifique à ce garde SSH :
c'était un bug pré-existant, plus large, dans `check_vault_owner()`
(`vault/spaces.py`) et sa duplication dans `_check_vault_access()`
(`admin/api.py`), affectant potentiellement TOUT outil vault-scoped pour un
bearer owner-based, pas seulement SSH. Corrigé à la racine (`vault_ids.py`,
validation centralisée de `vault_id` avant toute décision d'autorisation,
cf. section Isolation owner-based) plutôt que rapiécé localement dans
`ssh_operator.py`.

**Frontière structurelle** (durcissement supplémentaire, rounds 3-5) : après
trois contournements trouvés sur un garde placé uniquement aux points
d'entrée, l'invariant a été déplacé dans la primitive elle-même.
`sign_ssh_key_generic()`/`setup_ssh_ca_generic()` (`vault/ssh_ca.py`)
appliquent le garde de réservation AVANT de déléguer à
`sign_ssh_key()`/`setup_ssh_ca()`. Round 3 n'avait migré que les 2 tools
MCP (`server.py`) vers ces wrappers ; les 2 routes REST Admin
(`admin/api.py`) continuaient d'appeler les primitives brutes avec un garde
dupliqué en ligne — la revue round 4 a jugé, à raison, que ça invalidait la
prétention structurelle (« le commit ne modifie pas admin/api.py, malgré
son message »). Corrigé round 4 : les 4 points d'entrée génériques (tool
MCP ×2, route REST ×2) appellent désormais tous les wrappers `_generic`.

**BLOQUANT round 5** : `check_access()`/`_check_vault_access()` autorisent
un bearer ADMIN *avant* toute validation de format de `vault_id`
(court-circuit légitime pour leurs autres usages — un admin a accès total
par conception). Un admin fournissant `"agentic-platform/"` (slash final)
atteignait donc `check_not_reserved_for_operator()` avec un `vault_id` non
canonique que la comparaison stricte de l'ensemble réservé ne reconnaissait
pas — contournement complet de FIDO2/`verify-required` par un bearer admin
LÉGITIME, sans exécution de code, directement contraire au contrat non
négociable de l'issue #96 (« un token admin ne doit jamais contourner le
contrôle d'identité opérateur »). Corrigé : `check_not_reserved_for_operator()`
valide désormais lui-même `vault_id` (via `is_valid_vault_id()`), sans
dépendre de ce que `check_access()` a ou n'a pas déjà validé pour l'appelant
— le garde de réservation devient robuste indépendamment de qui l'appelle.

Un test structurel (analyse AST du code source) vérifie aussi qu'aucun
module en dehors de `vault/ssh_ca.py` et `ssh_operator.py` n'appelle
directement `sign_ssh_key()`/`setup_ssh_ca()` — une violation future serait
détectée en CI plutôt que silencieuse. Round 5 a montré que la première
version de ce test se contournait par aliasing d'import
(`from ... import sign_ssh_key as x`) ; corrigé en résolvant les alias vers
leur nom d'origine avant comparaison. Ce test ne protège que contre un
nouvel appelant Python involontaire, pas contre une exécution de code
arbitraire dans le processus (RCE) : à ce niveau de compromission, aucun
garde applicatif ne tient — c'est un changement de modèle de menace, pas une
faille de ce parcours. Une séparation encore plus forte (CA/mount dédié
exclusivement à l'usage opérateur, avec ACL OpenBao propres) reste une
piste de durcissement future, non nécessaire pour fermer les contournements
démontrés mais plus robuste structurellement si l'infrastructure le permet.

**Store d'identité indisponible** : si le Token Store est diagnostiqué
indisponible (panne/corruption S3 détectée après TTL — cf. Token Store,
`auth/token_store.py`), ce parcours refuse explicitement plutôt que de servir
un bearer depuis un cache potentiellement périmé (y compris après une
révocation distante non encore rechargée). Ce fail-close est spécifique à ce
parcours ; il ne modifie pas le comportement diagnostique du Token Store pour
les autres usages (chantier séparé et plus large — deny-all bearer pendant une
panne S3 — volontairement hors périmètre ici).

**Diagnostics backend** : cinq fonctions de `vault/ssh_ca.py` qui parlent à
OpenBao (`setup_ssh_ca`, `sign_ssh_key`, `get_ca_public_key`,
`list_ssh_roles`, `get_ssh_role_info`) ne journalisent ni ne retournent plus
jamais le message brut d'une exception — seul le type d'exception est loggé
côté serveur, le client reçoit un message constant. Round 1 n'avait couvert
que les deux premières (chemin d'écriture) ; round 2 a étendu le même
correctif aux trois fonctions de lecture, qui présentaient exactement le même
défaut sur des routes tout aussi publiques. `cleanup_ssh_ca` conserve un
`logger.warning` avec le message brut, mais ne le retourne à aucun appelant
(opération admin-only, appelée uniquement par `vault_delete`) — non traité
dans ce lot, signalé comme amélioration mineure possible.

**Enrôlement des empreintes de clé** : décision assumée — l'enrôlement ou le
retrait d'une empreinte se fait par modification de
`SSH_OPERATOR_PROFILES_JSON`/`_B64` puis redéploiement, pas par une action
d'administration à chaud. Choix cohérent avec le modèle déjà statique de
`MissionBindingStore`, qui réduit la surface de mutation à sécuriser. Une
vraie surface d'administration live (ajout/retrait d'empreinte sans
redéploiement) reste un suivi séparé, à ouvrir explicitement si le besoin
opérationnel le justifie — ce n'est pas un oubli, c'est un choix de périmètre.

La console Web, le REST Admin et le CLI Click sont trois canaux vers cette
même décision ; ils ne sont jamais l'autorité. Le vrai breaking-glass reste un
credential humain externe et indépendant de cette instance Vault.

Le champ `target` est une cible logique de policy et d'audit, pas une extension
native du certificat utilisateur SSH. Le confinement de destination doit être
assuré par une CA ou un principal distinct et par la distribution de
`TrustedUserCAKeys`/`AuthorizedPrincipalsFile` uniquement aux hôtes du profil.
Réutiliser la même CA et le même principal sur plusieurs hôtes élargirait
réellement la portée du certificat, même si le profil affiche une seule cible.

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

##### 🔑 `operator-ssh-jit` — Opérateur humain au moindre privilège

Pour un opérateur humain qui demande exceptionnellement un certificat sur un
profil pré-enrôlé. Cette policy ne donne aucun accès à la signature générique
ni aux secrets KV.

```json
{
  "policy_id": "operator-ssh-jit",
  "description": "Demande SSH JIT sur profils serveur fermés",
  "allowed_tools": [
    "ssh_operator_access_profiles",
    "ssh_request_operator_access"
  ],
  "denied_tools": [
    "ssh_sign_key", "ssh_ca_setup",
    "vault_*", "secret_*",
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

**Fail-close sur panne/corruption S3 détectée après TTL** *(issue #86 Lot 3)* : même état
observable `available`/`last_error` que le MissionBindingStore (§2.3 ci-dessus) — après TTL,
une indisponibilité ou corruption détectée ne sert plus une policy périmée ; le PEP refuse de
manière observable (`PolicyStoreUnavailable` → dict d'erreur MCP structuré / HTTP 503 REST),
jamais un fail-open silencieux. Ferme UNIQUEMENT ce sous-cas — pas la race d'écriture
multi-instance générale (#51/#13, hors scope, cf. §3.12 TECHNICAL.md).

### 6.4b Permission `wrap` — broker JIT non-admin *(issue #115)*

Quatrième flag de permission (non hiérarchique, aux côtés de `read`/`write`/
`admin`), destiné au jeton du `CredentialBrokerService` mcp-mission. Avant #115,
les quatre outils wrap exigeaient `admin` — inacceptable en moindre privilège
(le flag `admin` court-circuite policies et chemins partout).

> ⚠️ **Depuis #78, en mode durci** (`ENFORCE_MISSION_TOKEN_VALIDATION=true`, porte
> **indépendante** du PEP transport — elle peut être active en mode `bearer`) :
> `secret_wrap` **refuse** un appel sans `tenant_id` (`binding_incomplete`), et
> `secret_consume` refuse une entrée dont `tenant_id` **ou** `expected_aud`
> manque — avant `try_mark_consuming` et avant tout appel OpenBao, donc sans
> brûler le wrap ni laisser d'état `consuming` orphelin. Une `expected_aud`
> absente ou blanche est en revanche **enrichie** depuis la configuration : elle
> a une source serveur, le locataire non.

> ⚠️ **Cloisonnement inter-missions** : `secret_wrap_lookup` et
> `secret_wrap_status` exigent désormais `mission_id`. Le scoping d'identité
> ci-dessous borne au VAULT et aux CHEMINS, **pas à la mission** — le broker
> porte un seul jeton pour toutes. Sans le couple, la compensation d'un orphelin
> révoquait la provision vivante d'une autre mission, et la lecture d'état la
> divulguait. `mark_active`/`mark_failed` sélectionnent aussi le couple ;
> absence ou ambiguïté n'écrivent RIEN (une sauvegarde no-op écraserait l'état
> d'une autre instance — last-write-wins, #51).

**Séquence de gardes des 4 outils** (`secret_wrap`, `secret_revoke_wrap`,
`secret_wrap_lookup`, `secret_wrap_status`) :

1. `check_policy(<tool>)` — policy applicative (`allowed_tools`/`denied_tools`),
   deny-by-default mission JWT, verrou wrap-only ; bypass admin inchangé ;
2. `check_wrap_permission()` — `wrap` ou `admin` requis. Pour un jeton `wrap`
   non-admin, l'invariant de provisioning est **exécutable au runtime** :
   `allowed_resources` non vide (pas de fallback owner-based), `policy_id` non
   vide, `allowed_tools` **explicites** dans la policy (une policy « vide »,
   permissive via `is_tool_allowed`, est refusée), fail-close si PolicyStore
   indisponible ;
3. (`secret_wrap` seul) `check_access(vault_id)` + **évaluation stricte** du
   chemin (`is_wrap_path_strictly_allowed` : même first-match-wins que
   `is_path_allowed`, mais *pas de règle matchante = refus* et *`allowed_paths`
   vide = refus*).

**Verrou wrap-only** (`enforce_wrap_only_token`) : un jeton portant `wrap` sans
read/write/admin est confiné à ces 4 outils. Refus sur tous les autres outils
MCP (appliqué dans `check_policy` + en première ligne des 5 outils sans
check_policy : `system_health`, `system_about`, `secret_types`,
`secret_generate_password`, `secret_consume`) et **403 uniforme sur tout
`/admin/api/*`**. Un composite (`read,wrap`) n'est pas wrap-only — choix
explicite, averti par la SPA.

**Scoping du registre** (garde dans les primitives, pattern anti-contournement) :
revoke/lookup/status opèrent sur une **sélection défensive** du registre
(`_select_wrap_entries` — aucune clé lue sans garde de type) filtrée par
l'identité courante (`_visible_entries` : `check_access` + évaluation stricte du
chemin par entrée — symétrie création/visibilité). Hors scope = `not_found`
(aucune fuite d'existence inter-tenant), aucun appel OpenBao, et les mutations
(`mark_entries_revoked`) ne touchent **que** la sélection visible — jamais une
entrée invisible partageant le même accessor. Contexte absent = fail-close
(jamais traité admin). Le refresh du cache (`_maybe_refresh`) reste appelé une
fois en tête de primitive ; `status` conserve la détection de panne S3
(`_last_load_ok`).

**⚠️ Downgrade ≤ 0.9.2** : la whitelist des anciennes versions rejette
ATOMIQUEMENT un `tokens.json` contenant `wrap` (fail-close — seuls les
bootstrap admin survivent au redémarrage). Révoquer puis purger les jetons
`wrap` AVANT tout rollback (cf. CHANGELOG).

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

**Total : 39 outils MCP** (5 vaults + 6 secrets + 5 wrap/broker C18 + 5 SSH CA + 2 SSH JIT opérateur + 8 PKI + 4 policies + 1 token + 1 audit + 2 system)

#### 6.7.1 Architecture du journal d'audit

Le système d'audit trace **toutes** les opérations MCP — et, depuis v0.7.0 (#49), les mutations du plan de contrôle d'accès via l'**API REST admin** (`token_create`, `token_update`, `token_revoke`, `token_purge`, `policy_create`, `policy_delete` ; les échecs de persistance des opérations de **retrait** — révocation, purge, suppression de policy — sont également tracés). ⚠️ **Un seul support persistant** : le fichier JSONL local. Le ring buffer mémoire n'est qu'un cache de lecture (5 000 dernières entrées), perdu à chaque redémarrage — parler de « double persistance » était faux :

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

**Roadmap (v1.0)** : Transit Auto-Unseal via une instance OpenBao dédiée
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

> **Source unique du contrat de configuration** : [`.env.example`](../../.env.example)
> à la racine du dépôt. Ce fichier documente les **45** variables réellement
> consommées par `Settings` (`src/mcp_vault/config.py`), une par une, avec leur
> défaut. Le bloc ci-dessous n'en montre que le **minimum viable** ; il ne le
> remplace pas.
>
> `Settings` est en `extra="forbid"` : toute clé absente de `.env.example` portant
> une valeur non vide dans un `.env` **fait échouer le démarrage**. Ne jamais
> composer un `.env` depuis une autre source que `.env.example`.

```env
# --- Serveur MCP ---
MCP_SERVER_NAME=mcp-vault
MCP_SERVER_PORT=8030
MCP_ALLOWED_HOSTS=vault.mcp.cloud-temple.app

# --- WAF (port d'écoute externe du WAF Caddy+Coraza) ---
WAF_PORT=8085

# --- Auth MCP ---
# Aucune valeur par défaut utilisable : le serveur refuse de démarrer tant que
# REQUIRED n'a pas été substitué par une clé forte (≥ 32 caractères, ≥ 3 classes
# de caractères). Générer avec : secrets.token_urlsafe(48)
ADMIN_BOOTSTRAP_KEY=REQUIRED

# --- OpenBao embarqué ---
OPENBAO_ADDR=http://127.0.0.1:8200
OPENBAO_SHARES=1
OPENBAO_THRESHOLD=1
OPENBAO_DATA_DIR=/openbao/file
OPENBAO_CONFIG_DIR=/openbao/config

# --- S3 (token store + backup du file backend OpenBao) ---
# Bornes réseau (issue #110) : sans elles, une lenteur S3 gèle le service.
S3_CONNECT_TIMEOUT=5
S3_READ_TIMEOUT=30
S3_MAX_ATTEMPTS=2
UVICORN_GRACEFUL_TIMEOUT=10
S3_ENDPOINT_URL=https://your-s3-endpoint.example.com
S3_ACCESS_KEY_ID=your_access_key_here
S3_SECRET_ACCESS_KEY=your_secret_key_here
S3_BUCKET_NAME=your-bucket-name
S3_REGION_NAME=fr1
VAULT_S3_PREFIX=_storage
VAULT_S3_SYNC_INTERVAL=60
```

Variables optionnelles non montrées ici — PKI interne, PEP mission JWT, accès SSH
JIT opérateur, bornes `SSH_OPERATOR_JIT_*` : voir les groupes 6 à 8 de
[`.env.example`](../../.env.example).

---

## 10. Structure fichiers (starter-kit)

```
mcp-vault/
├── src/mcp_vault/
│   ├── __init__.py
│   ├── __main__.py            # python -m mcp_vault
│   ├── server.py              # 39 outils MCP + create_app() + middlewares + bannière
│   ├── config.py              # Config Pydantic-settings (S3, OpenBao, sync, WAF)
│   ├── admin/                 # Console d'administration web (/admin)
│   │   ├── __init__.py
│   │   ├── middleware.py      # AdminMiddleware ASGI (static + API routing + CORS)
│   │   └── api.py             # REST API admin (toutes routes admin)
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
│       └── display.py         # Affichage Rich
├── Dockerfile                 # Python 3.12 + binaire OpenBao
├── docker-compose.yml         # WAF + mcp-vault + volume + réseau
├── requirements.lock          # versions installées dans l'image (fait foi)
├── requirements.txt           # contraintes déclarées + outillage de test
├── .env.example
└── VERSION
```

### 10.1 Dockerfile et dépendances

La recette exacte fait foi dans le dépôt (`Dockerfile`, `requirements.lock`,
`requirements.txt`) ; elle n'est pas dupliquée ici — une copie de courtoisie
avait divergé au point de contredire le code (issue #125). Trois invariants
structurent la construction :

1. **Le verrou fait foi pour les versions d'exécution.** La cible `production`
   installe `requirements.lock` seul. `requirements.txt` déclare des
   CONTRAINTES (majoritairement des planchers, plus une borne haute sur `mcp` et
   une égalité stricte sur `uvicorn`), et non des versions résolues : le laisser
   piloter l'image la rend dépendante de ce qui est publié en amont le jour de
   la construction — c'est exactement ainsi que la
   parution de `mcp 2.0.0`, qui a supprimé `mcp.server.fastmcp`, a rendu
   l'image non démarrable sur toutes les versions depuis la v0.4.5.
2. **La construction vérifie l'import critique.** Chaque stage qui installe des
   dépendances exécute `python -c "from mcp.server.fastmcp import FastMCP"` :
   une résolution incompatible fait échouer le `build`, et non le démarrage du
   conteneur en production.
3. **L'outillage de test reste hors de l'image de production.** Le verrou ne
   contient pas `pytest` ; la cible `test` reçoit donc le verrou ET
   `requirements.txt` en une seule invocation pip, dont l'intersection préserve
   les versions verrouillées.

Le contrat est verrouillé par `tests/test_packaging_contract_125.py`, qui vérifie
notamment que le verrou satisfait TOUTES les contraintes déclarées — sans quoi une
régénération du verrou pourrait repasser sous `boto3>=1.38.43`
(`PutObject.IfMatch`, #121) ou sous `uvicorn==0.42.0` (ré-émission du SIGTERM
dont dépend le chemin d'arrêt, #110).

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

**Validation stricte `permissions`/`allowed_resources`** *(issue #86)* :
`create()`, `update()` et `load()` partagent la même validation — jamais permissive
par défaut. Corrige une élévation de privilège : un `dict`/une chaîne malformés
(ex. `{"admin": true}`) pouvaient auparavant passer une validation par simple
itération et rendre un token admin total. `load()` est atomique (tout-ou-rien) :
un seul token non conforme invalide tout le chargement, cache précédent conservé.
⚠️ Limite assumée : `available`/`last_error` sont diagnostiques dans cette version —
l'authentification bearer continue de servir le cache après une panne S3 détectée
(pas de fail-close complet, contrairement à `PolicyStore`/`MissionBindingStore`).

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
| **v0.6.x** (actuel) | Option C — Clés sur S3 chiffrées, mémoire seule au runtime | 🟡 Bonne      |
| **v1.0** (futur)    | Transit Auto-Unseal via OpenBao dédié (KMS Cloud Temple)   | 🟢 Excellente |
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

### 11.3b Une seule analyse d'arguments côté CLI *(#128)*

**Décision** : le shell interactif est supprimé ; le mode Click est la seule
surface de ligne de commande.

**Pourquoi.** Les deux modes exposaient les mêmes commandes avec deux analyseurs
d'arguments distincts. Celui du shell était écrit à la main, seize boucles
indépendantes, et **ignorait silencieusement tout jeton non reconnu**. Une faute
de frappe n'y produisait pas une erreur mais **une opération différente de celle
demandée** : `ssh setup … --user deploy` créait un rôle ouvert à tous les
principals, `policy create no-ssh --denied ssh_*'` posait une liste de refus
inopérante — donc une policy « no-ssh » autorisant SSH.

**Principe retenu, applicable au-delà de ce cas** : une surface qui décide d'une
frontière de sécurité ne doit **jamais deviner**. Un argument non reconnu est un
refus, pas un silence. Deux analyseurs pour un même contrat, c'est un contrat qui
diverge — et c'est toujours le plus permissif qui définit la sécurité réelle.

**Limites assumées, documentées dans #128.** Click ne couvre pas tout : il accepte
une option consommée comme valeur (`pki setup --ttl --prod`), ignore la sémantique
des motifs `fnmatch` (la validation doit vivre dans `PolicyStore`, pas dans le
client), et ne devine pas les exclusions mutuelles (`--prod` / `--lab`). Ces trois
points restent ouverts et concernent la surface conservée.

### 11.3c Sûreté d'état des opérations de purge

`token purge-revoked` et `mission-binding purge` sont les deux opérations de
**purge en masse** du CLI. Elles ne sont pas les seules commandes irréversibles —
`vault delete`, `secret delete` et `policy delete` le sont aussi, et sont
protégées par une confirmation (`abort=True`) — mais elles sont les seules à
supprimer un ENSEMBLE déterminé par un critère plutôt qu'une cible nommée. C'est
ce qui justifie une chaîne de garanties propre.

Elles appliquent la doctrine de sûreté d'état du projet : **une décision
destructive se prend sur une preuve positive stricte, jamais sur un signal
ambigu.**

| Garantie | Ce qu'elle empêche |
| --- | --- |
| Aperçu préalable systématique | Supprimer sans avoir obtenu de décompte |
| Aperçu en échec → aucune purge | Supprimer sur la foi d'un décompte qu'on n'a pas |
| Décompte = entier strictement positif | `-1`, `True` et `"0"` déclenchaient une suppression |
| Confirmation (`abort=True`) hors `--yes` | Purge lancée par inadvertance |
| Rétention par défaut 30 j, bornée à `>= 0` | Une valeur négative sélectionnerait tout |
| Aucune reprise après échec réseau | Double suppression sur une sélection recalculée |

Chacune est prouvée par une mutation mesurée
(`tests/cli/test_purge_destructive.py`).

> **Fenêtre non fermée, à traiter côté serveur.** L'aperçu est **indicatif** : la
> purge ne transmet que la durée de rétention, et le serveur **recalcule** la
> sélection. Un enregistrement devenu éligible entre l'aperçu et la confirmation
> est supprimé sans avoir été présenté à l'opérateur. Aucune garde côté client ne
> ferme cette fenêtre — il faudrait que la purge porte l'empreinte de l'aperçu
> (identifiants, ou version côté serveur).

### 11.3d Les appels S3 du cycle de vie sortent de la boucle *(#122, lot 2 de #110)*

> **Portée exacte, à ne pas élargir.** Ce lot traite **cinq** points d'appel :
> sauvegarde (archive + envoi), restauration au démarrage, sonde de
> connectivité, et les deux opérations sur les clés chiffrées d'OpenBao. Les
> magasins d'autorisation — jetons, policies, liaisons de mission, registre de
> wrapping — exécutent **toujours** boto3 de façon synchrone dans la boucle :
> **un stockage lent sur ces chemins peut encore figer le coffre**, jusqu'au
> lot 3 (#123).

**Le défaut.** Les appels S3 (boto3) sont synchrones. Exécutés dans la boucle
d'événements, ils monopolisent l'unique fil qui sert toutes les requêtes : un
ralentissement du stockage rendait le coffre **totalement indisponible**, sonde
de santé comprise — donc expiration du healthcheck, redémarrage, et blocage à
nouveau au chargement du magasin de jetons. 488 s mesurées en production.

**Le principe retenu** : les appels bloquants **du périmètre** sortent de la
boucle, mais **le verrou qui sérialise l'état n'est jamais relâché avant la fin
réelle du travail**. C'est l'invariant central, et il est plus subtil qu'il n'y paraît —
trois pièges ont été vérifiés expérimentalement plutôt que déduits :

| Piège | Ce qui se passe réellement |
| --- | --- |
| `await asyncio.shield(tâche)` | L'annulation de l'attente fait sortir l'appelant — donc relâche son verrou — alors que le fil d'exécution continue d'écrire sur S3. |
| `tâche.done()` / `tâche.cancelled()` | Ne prouvent **pas** la fin du travail : annuler la tâche asyncio n'interrompt pas un fil bloqué en Python. |
| Une `Task` autour de `to_thread` | Elle est annulée par le teardown de la boucle. `shield` ne protège que de l'annulation propagée, pas d'une annulation directe. L'attente part alors en rotation à vide : **1 411 649 tours mesurés en 0,5 s**. |

D'où la primitive `async_offload.run_blocking` : le travailleur est un `Future`
d'exécuteur (invisible pour le teardown, contrairement à une `Task`), la preuve
de fin est un `threading.Event` posé **depuis le fil lui-même**, et une
annulation reçue pendant l'attente est **mémorisée puis re-levée après** la fin
du travail. L'attente n'est bornée par aucun compteur : une borne qui rendrait
la main relâcherait le verrou avec une écriture en vol, c'est-à-dire violerait
l'invariant qu'elle prétendrait protéger. Ce qui la termine, c'est la fin du
fil. Les appels réseau sont bornés par le lot 1, mais **pas tout ce qui est
offloadé** : construction de l'archive, dérivation PBKDF2 et attente d'un
worker libre n'ont aucune borne propre. Un travail qui ne se terminerait jamais
bloquerait cette attente — choix assumé face à l'alternative, qui serait de
relâcher le verrou sur une écriture en vol.

**Aucune boucle de sync ne peut apparaître là où l'arrêt ne la verrait pas.**
Un arrêt verrouille la sync, et ce verrou tient au-delà du drainage : l'arrêt
se poursuit par le seal puis la sauvegarde finale, deux points où le service
rend la main. Seul le démarrage d'un nouveau cycle de vie rouvre la sync — un
même processus peut enchaîner deux lifespans. Si une boucle du cycle précédent
vit encore, le nouveau démarrage est **refusé** avant tout redémarrage
d'OpenBao : elle pourrait publier un état antérieur par-dessus les écritures du
nouveau cycle, qui n'aurait pas même de sync périodique pour rattraper.
Symétriquement, un démarrage **pendant** un arrêt en cours est refusé : cet
arrêt se poursuit après le drainage, et ne drainerait jamais une boucle créée
entre-temps. Sur échec de drainage, la référence à la tâche
est en outre conservée : l'effacer perdrait la seule trace d'un travail encore
capable d'écrire.

**Sonde de santé en single-flight.** Une seule vérification réelle est en vol à
la fois ; les appelants suivants s'y raccrochent, chacun avec sa propre
échéance, qui n'annule pas la sonde partagée. **Sans cache de résultat** : un
cache permettrait de répondre « stockage disponible » après la panne, ce qui
serait une régression de contrat déguisée en optimisation.

**Arrêt : drainage, jamais d'annulation.** Une sauvegarde annulée n'est pas
interrompue ; elle peut se terminer *après* la sauvegarde finale et publier un
état plus ancien. L'arrêt demande donc la sortie de la boucle de sync et
l'attend. Drainage non abouti ⇒ **aucune sauvegarde finale**, message CRITICAL.

> **Perte de durabilité assumée.** La copie S3 peut alors rester périmée. Le
> volume local demeure l'autorité de reprise, donc le coffre n'est pas perdu ;
> c'est le prix de l'invariant « ne jamais écraser une archive plus récente par
> une plus ancienne ».

**Le budget d'arrêt est un dimensionnement, pas une couverture démontrée.**
Quatre étapes n'ont aucune borne : construction de l'archive, `seal_vault()`
(hvac synchrone sans timeout), `stop_openbao()` (`kill()` puis attente non
bornée), et l'acquisition du verrou de sauvegarde quand une opération PKI le
détient. Le backoff botocore avec jitter n'est pas déterministe. Un dépassement
de `stop_grace_period` — donc un arrêt forcé — reste possible. Aucun validateur
de budget n'a été ajouté : il aurait produit une assurance fausse.

**Hors périmètre**, traité au lot 3 (#123) : les magasins d'autorisation. Les
appels hvac synchrones du cycle de vie OpenBao restent également hors périmètre.

### 11.3e Le mode par défaut exige une identité *(#116)*

**Le défaut.** En mode `bearer` — le **défaut** — le middleware injectait
`token_info=None` et poursuivait quand aucun jeton n'était présenté, ou quand
il était invalide. Les gardes répondent à « *cette* identité a-t-elle le
droit ? » ; celles des outils **alors exposés** ne posaient jamais « y a-t-il
seulement une identité ? » : `get_listing_filter(None)` rend `visible: True`,
`check_policy(None)` rend « autorisé », et les gardes mission/wrap refusent des
identités *particulières* sans exiger d'être authentifié. `check_access` fait
exception et refuse bien sans identité — c'est ce qui a protégé les secrets.

Conséquence, relevée par un tiers sur une instance en service : divulgation non
authentifiée de l'inventaire des coffres, des **certificats émis — donc des
noms de domaine et adresses du parc**, du nom du bucket, de l'adresse interne
d'OpenBao et des versions. Aucune lecture de secret (`check_access` refuse) :
c'est une divulgation, pas une compromission.

**Le correctif est à l'entrée, pas dans les outils.** Refuser au middleware
ferme la surface des outils MCP d'un seul geste — `initialize` et `tools/list`
compris, donc **aussi tout outil ajouté plus tard**. Une correction outil par
outil aurait rouvert le trou au prochain ajout, en donnant l'illusion d'être
exhaustive.

| Mode | Comportement |
| --- | --- |
| `bearer` *(défaut)* | Jeton valide **exigé**. Absent ou invalide ⇒ `401` + `WWW-Authenticate: Bearer`, motif fermé en audit, réponse générique (jamais un oracle distinguant les deux causes). |
| `bearer-anonymous` | Ancien comportement, **mode d'exception**. `CRITICAL` au démarrage. N'exige aucun paramètre mission, pour rester utilisable en urgence. |
| `jwt` / `dual-stack` | Inchangés. |

**Ce qui reste joignable sans jeton**, par conception et vérifié dans le code —
aucune de ces surfaces n'expose d'outil MCP :

| Surface | Traitée par | Pourquoi |
| --- | --- | --- |
| `/acme/*`, `/v1/_sys_pki_int/acme/*` | `PkiMiddleware` | Protocole ACME : le client n'a pas encore de certificat |
| `/pki/ca/*.pem` | `PkiMiddleware` | Chaîne de confiance publique par nature |
| `/admin`, `/admin/` et ses fichiers statiques | `AdminMiddleware` | La SPA elle-même ; **son API `/admin/api/*` exige un jeton valide**, l'autorisation dépendant de la route |
| `OPTIONS /admin/api/*` | `AdminMiddleware` | Préflight CORS, sans effet de bord |
| `/health`, `/healthz`, `/ready`, `/` | `HealthCheckMiddleware` | Sondes d'orchestrateur |
| `/favicon.ico` | `AuthMiddleware` (`PUBLIC_PATHS`) | Ressource inerte |

La formule exacte est donc « toute la surface des **outils MCP** », jamais
« toute la surface ».

**Piège latent fermé au passage.** `MCP_AUTH_MODE != "bearer"` décidait
« PEP mission actif ? » en trois endroits — une négation qui range du côté
« actif » tout mode futur. Le mode de repli aurait donc exigé un JWKS et une
audience, c'est-à-dire aurait été inutilisable au moment précis où on en a
besoin. Remplacé par `Settings.mission_pep_active`, une appartenance explicite
à `{jwt, dual-stack}`.

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
│  │  └─ Plugin coraza-caddy v2.5.0 (coraza v3.7.0)             │  │
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
les 295 tests e2e via le WAF. Plusieurs règles CRS généraient des **faux
positifs** légitimes sur les payloads JSON-RPC et REST de MCP Vault.

Deux mécanismes d'exclusion coexistent, avec des **sémantiques inverses** — les
confondre rend l'exclusion silencieusement inopérante :

| Mécanisme                    | Agit sur          | Placement requis          |
| ---------------------------- | ----------------- | ------------------------- |
| `ctl:ruleRemoveById`         | la transaction    | **AVANT** l'Include CRS (cf. #42) |
| `SecRuleUpdateTargetById`    | la définition     | **APRÈS** l'Include CRS (cf. #107) |

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

##### Faux positif 3 — Règle 930120 (OS File Access Attempt) — issue #107

Signalé en production sur la v0.8.6 : un `secret_write` légitime émis par un
client Codex recevait `HTTP 403` **avant** le handler MCP — aucune trace dans
l'audit Vault, ni refus d'authentification ni refus de policy.

| Aspect         | Détail                                                                       |
| -------------- | ---------------------------------------------------------------------------- |
| **Règle CRS**  | `REQUEST-930-APPLICATION-ATTACK-LFI` / ID 930120 (`phase:2`)                 |
| **Opérateur**  | `@pmFromFile lfi-os-files.data` — `.env` y figure (ligne 36, CRS 4.7.0)       |
| **Cibles**     | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*`           |
| **Cause racine**| **Coraza ne parsait pas le corps JSON.** Faute de `ctl:requestBodyProcessor=JSON`, le processeur `URLENCODED` s'appliquait au JSON-RPC : le **corps entier** devenait **UNE** variable unique — `ARGS_NAMES:{"jsonrpc": "2.0", …}` — mesuré à exactement 1 `ARGS_NAMES` et 1 `ARGS`. |
| **Impact 1**   | Toute chaîne de `lfi-os-files.data` présente **n'importe où** dans le corps — y compris dans une **valeur de secret** — déclenchait 930120 (score 5) puis 949110. Le type de secret `env_file` (« Fichier .env ») était donc structurellement inutilisable à travers le WAF. |
| **Impact 2**   | **Aucun scoping fin n'était possible** : avec une seule cible, on ne peut pas distinguer un nom d'argument d'une valeur. |
| **Correctif 1**| Règle interne **10008** : `ctl:requestBodyProcessor=JSON`, chaînée sur `POST` + chemin ancré `^/mcp(?:[/?]|$)` + `Content-Type` `(?:^|,)[ \t]*application/json[ \t]*(?:[;,]|$)` (grammaire alignée sur celle du handler, cf. §11.6.4-quater), avec `ctl:requestBodyLimit=65536` pour borner le coût du parseur (cf. §11.6.4-bis). Restaure la granularité (`json.params.arguments.data.notes`, …) et **renforce** la détection : 930100/930110 (path traversal) se déclenchent désormais sur `path`, ce qui n'était pas le cas avant. |
| **Correctif 2**| `SecRuleUpdateTargetById 930120 "!ARGS_NAMES:/^json\.params\._meta\./"` — l'aplatissement JSON concatène les clés avec un point, donc une clé `environment` produit `.env` dans le **nom** d'argument (`…x-codex-turn-metadata.environment.cwd`). Portée : **noms seuls**, les valeurs sous `_meta` restent inspectées. |
| **Correctif 3**| `SecRuleUpdateTargetById 930120 "!ARGS:/^json\.params\.arguments\.data\./"` — `secret_write(data: dict)` est aujourd'hui le seul outil MCP à recevoir une charge opaque. Ce contenu est transmis à OpenBao qui le chiffre **au repos** ; mcp-vault ne l'interprète jamais comme chemin, requête SQL ou commande. Portée : **valeurs** de ce sous-arbre seulement. **Honnêteté du scoping** : le sélecteur porte sur le chemin JSON `params.arguments.data.*`, **pas** sur `params.name == "secret_write"` — le WAF ne connaît pas le schéma des outils. La propriété repose sur l'état actuel des signatures, pas sur une garantie du WAF. |
| **Correctif 4**| Gardes **10009** / **10010** (anti-évasion, cf. §11.6.4-bis) : les exclusions ci-dessus sont des directives GLOBALES dont le sélecteur est un NOM d'argument, donc une chaîne choisie par le client. Elles ne sont PAS inertes hors `/mcp` : `ARGS`/`ARGS_NAMES` agrègent aussi query string et formulaire. Les gardes refusent tout nom préfixé `json.` hors du corps JSON MCP analysé. |
| **Étroitesse** | Restent bloqués et vérifiés par test : `.env` dans `path`, dans `tags`, dans le nom d'outil, dans une **valeur** sous `_meta` ; traversal dans une valeur **et** dans un nom sous `data.*` ; noms `json.*` forgés en query string ou en formulaire ; corps JSON tronqué ou très imbriqué contenant une LFI. |
| **Risque**     | Faible — exclure 930120 des valeurs de `data.*` n'ouvre pas de LFI : une traversal y reste bloquée par **930100**, **930110** et **932160** (vérifié empiriquement). Un simple nom de fichier sensible **sans** traversal n'y est en revanche plus détecté : c'est l'effet recherché. |
| **Pourquoi pas `ctl:ruleRemoveTargetById`** (qui serait scopable par URI) : vérifié, la forme **regex** de cible n'est pas supportée — seul un nom exact fonctionne. Les clés de métadonnées client étant arbitraires, une liste de noms exacts n'est pas tenable. |

##### 11.6.4-bis Anti-évasion des exclusions `json.*` (gardes 10009 / 10010)

La première version du correctif #107 supposait les exclusions statiques
« limitées à `POST /mcp` par construction, puisque les variables `json.*`
n'existent que là où le parseur JSON a tourné ». **Cette affirmation était
fausse** ; la revue adversariale indépendante l'a qualifiée de bloquante.

`ARGS` et `ARGS_NAMES` agrègent aussi les paramètres de **query string** et de
**formulaire**, dont le nom est choisi par le client. Mesure sur Coraza réel avant
correction :

| Requête | Avant gardes | Après gardes |
| --- | --- | --- |
| `GET /health?json.params.arguments.data.x=.env` | **200** (évasion) | **403** |
| `GET /health?legit=.env` (témoin) | 403 | 403 |
| `POST /admin/api` formulaire, nom forgé | **200** (évasion) | **403** |

Il suffisait donc de nommer un paramètre `json.params.arguments.data.<quelconque>`
pour neutraliser 930120 **sur tous les endpoints**.

| Garde | Cible | Justification |
| ----- | ----- | ------------- |
| **10009** | `ARGS_GET_NAMES` préfixés `json.`, tous endpoints | Aucun client légitime n'en produit : le transport MCP Streamable HTTP place tout dans le corps, et l'authentification est Bearer-only (pas de repli `?token=`). |
| **10010** | `ARGS_NAMES` préfixés `json.` quand le corps n'a PAS été analysé en JSON | Discriminé par le drapeau `tx.mcp_json_body`, posé côté serveur donc **non forgeable**. |

Deux pièges rencontrés, tous deux détectés par la mesure et non par la relecture :

1. Une `SecRule TX:<var>` dont la variable **n'existe pas** ne s'évalue pas du tout
   (aucune variable à tester → aucun match → la chaîne ne se termine jamais). Sans
   l'initialisation explicite `setvar:'tx.mcp_json_body=0'` (règle 10007100,
   phase 1, déclarée avant 10008), la garde 10010 était silencieusement inopérante.
2. `@beginsWith /mcp` matcherait aussi `/mcpfoo`. Le déclencheur du parseur est
   ancré (`^/mcp(?:[/?]|$)`) et son `Content-Type` aligné sur ce que FastMCP
   accepte réellement.

`SecRequestBodyLimitAction Reject` est rendu explicite plutôt que laissé au défaut :
un corps dépassant `SecRequestBodyLimit` est refusé, jamais analysé partiellement —
une analyse partielle laisserait sa fin non inspectée.

**Hypothèse de revue non confirmée.** La revue suspectait qu'une erreur du parseur
JSON crée un angle mort non bloquant (`REQBODY_ERROR`). Mesure sur Coraza 3.3.3 :
aucune variable `REQBODY_ERROR` n'est levée sur JSON malformé. Le parseur est
**permissif** (`gjson.Parse` ne remonte pas d'erreur de syntaxe) : un corps
tronqué est partiellement extrait, et la détection subsiste — un corps tronqué
contenant `/etc/passwd` reste refusé (403), mesuré. Aucune règle n'a donc été ajoutée pour une condition inatteignable ;
la propriété qui compte est verrouillée par test.

##### 11.6.4-ter Profondeur JSON — DoS borné sans créer d'évasion (#107)

L'activation du parseur JSON exposait un **DoS critique non authentifié** sur
`POST /mcp`. Le parseur de coraza 3.3.3 (`internal/bodyprocessors/json.go`,
`readItems()`) récurse **sans plafond de profondeur** — « TODO add some anti DOS
protection » en commentaire — et alloue une clé de map par niveau : coût
quadratique. `SecRequestBodyLimit` borne les **octets**, jamais la **profondeur** ;
un corps `[`×N + `0` + `]`×N coûte 2 octets par niveau.

Mesures, conteneur aux limites de production (512 Mo / 1 CPU) :

| Corps | Sans parseur | coraza 3.3.3 + parseur | coraza 3.7.0 + limites |
| --- | --- | --- | --- |
| 3,9 Ko (prof. 2 000) | 39 ms | **24 035 ms** | 400 en 11 ms |
| 15,6 Ko (prof. 8 000) | 82 ms | **timeout > 60 s** | 400 en 6 ms |
| 64,0 Ko (prof. 32 767) | 323 ms | connexion réinitialisée | 400 en 10 ms |
| **État du WAF** | vivant | **`OOMKilled: true`** | vivant |

`SecRequestBodyJsonDepthLimit` n'existe qu'à partir de **coraza v3.4.0** : c'est la
raison exacte de la montée `coraza-caddy/v2@v2.2.0` → **v2.5.0** (coraza **v3.7.0**)
dans `waf/Dockerfile`. Contre-mesures écartées, toutes mesurées : borne en octets
(le vecteur tient sous 64 Ko), filtrage avant parseur (impossible en seclang — le
corps n'existe qu'en phase 2), et `ctl:ruleRemoveTargetById` sur collection nue sans
parseur (ne corrige pas le faux positif).

**Le piège.** La limite de profondeur seule échange un défaut contre un autre :
au-delà du seuil, coraza cesse d'alimenter `ARGS` et le corps n'est plus inspecté.

| Charge enfouie à 40 niveaux | Limite seule | Limite + règle 10011 |
| --- | --- | --- |
| LFI, SQLi, XSS, RCE | **200 — passent toutes** | 400 |
| Les mêmes à 31 niveaux | 403 | 403 |

coraza 3.7.0 expose la condition (`REQBODY_ERROR=1`, « JSON: max recursion reached
while reading json object »). La **règle 10011** refuse donc explicitement tout
corps déclaré non analysable, sur la seule surface analysée en JSON
(`tx.mcp_json_body`) : un corps qu'un WAF ne peut pas inspecter n'atteint pas
l'application. Cette règle avait été proposée au 1er round de revue puis écartée
sur mesure — coraza 3.3.3 ne levait jamais `REQBODY_ERROR`. L'intuition était juste
pour la configuration montée, pas pour l'ancienne.

Seuil retenu : **32**. L'enveloppe MCP la plus profonde légitime atteint 5 niveaux
(`params._meta.x-codex-turn-metadata.environment.cwd`), le payload de secret 4.

`ctl:requestBodyLimit=65536` et `SecRequestBodyLimitAction Reject` sont conservés :
ils bornent le coût de l'évaluation CRS sur les gros corps, indépendamment de la
profondeur (413 en 1-3 ms au-delà).

> **Défaut préexistant, hors périmètre.** Le DoS par gros corps est antérieur et
> concerne toutes les surfaces : sans aucun parseur JSON, une requête de 2,9 Mo
> coûte **20,4 s** de CPU en évaluation CRS. `SecRequestBodyLimit` vaut 10 Mo.

##### 11.6.4-quater Grammaire du `Content-Type` alignée sur le handler (#107)

Le déclencheur du parseur JSON doit reconnaître **tout** ce que le handler accepte,
sinon le POST atteint l'application en échappant aux quatre bornes (parseur,
taille, profondeur, refus des corps non analysables).

`mcp/server/streamable_http.py:415` (SDK 1.26) :

```python
content_type_parts = [part.strip() for part in content_type.split(";")[0].split(",")]
return any(part == CONTENT_TYPE_JSON for part in content_type_parts)
```

Le handler accepte donc `text/plain, application/json`. Un ancrage WAF en
`^application/json` laissait passer cette forme **sans aucune borne** — mesuré :

| `Content-Type` | Ancrage `^application/json` | Grammaire alignée |
| --- | --- | --- |
| `application/json` | 400 | 400 |
| `application/json; charset=utf-8` | 400 | 400 |
| `text/plain, application/json` | **200 — contournait** | **400** |
| `application/json, text/plain` | **200 — contournait** | **400** |

D'où `@rx (?:^|,)[ \t]*application/json[ \t]*(?:[;,]|$)` : `application/json`
reconnu comme jeton de média, en tête ou après une virgule. **Sur-couvrir est
délibéré** (on borne davantage, l'application renvoie 415 le cas échéant) ;
sous-couvrir rouvre le contournement. `application/jsonp` et
`application/json-patch+json` ne matchent pas — le caractère suivant `json` doit
être `;`, `,` ou la fin de chaîne. Vérifié : une LFI envoyée avec ces deux types
reste bloquée (403), car un corps non structuré est inspecté en bloc.

##### Récapitulatif des exclusions

| ID interne | Endpoint                    | Règle CRS        | Motif du faux positif                          |
| ---------- | --------------------------- | ---------------- | ---------------------------------------------- |
| 10001      | `/mcp`                      | 920540           | Unicode français dans les payloads JSON        |
| 10002      | `/admin/api`                | 920540           | Unicode français dans les payloads JSON        |
| 10003      | `/mcp`                      | 932120           | `test-path` dans les noms de policies          |
| 10004      | `/admin/api`                | 932120           | `test-path` dans les noms de policies          |
| 10005      | `/pki/ca/{root,chain,crl}.pem` | 920440, 920540, 932120 | Distribution CA/CRL publique (extension `.pem`) |
| 10006      | `/acme/*`                   | 920420, 920540, 932120 | Content-Type `application/jose+json` (RFC 8555) |
| 10007      | `/v1/_sys_pki_int/acme/*`   | 920420, 920540, 932120 | Paths ACME générés par OpenBao              |
| 10007100   | *(toutes)*                  | *(aucune)*       | Initialise `tx.mcp_json_body=0` — sans quoi la garde 10010 est inopérante |
| 10008      | `POST /mcp` (JSON)          | *(aucune)*       | Active le parseur JSON — prérequis du scoping fin |
| 10009      | *(toutes)*                  | *(deny 403)*     | Refuse un nom de paramètre `json.*` forgé en query string |
| 10010      | *(toutes)*                  | *(deny 403)*     | Refuse un nom `json.*` hors corps JSON MCP analysé |
| 10011      | `POST /mcp` (JSON)          | *(deny 400)*     | Refuse un corps JSON non analysable (`REQBODY_ERROR`) — évite l'évasion par profondeur |

| Exclusion de cible (après Include)                          | Règle CRS | Portée                                   |
| ----------------------------------------------------------- | --------- | ---------------------------------------- |
| `!ARGS_NAMES:/^json\.params\._meta\./`                      | 930120    | **Noms** sous l'enveloppe MCP `_meta`    |
| `!ARGS:/^json\.params\.arguments\.data\./`                  | 930120    | **Valeurs** du payload opaque `secret_write` |

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
> que la console admin est protégée par authentification Bearer.

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

*Document mis à jour le 16 août 2026 — MCP Vault v0.15.0. Depuis la v0.12.0 : clé de provisionnement à usage unique SANS CONDITION et cinq codes de refus nommés d'après ce que l'appelant peut faire (v0.13.0/v0.14.0), révocation confirmée mais non inscrite désormais annoncée à l'appelant (v0.14.1), limite de durabilité ARBITRÉE et publiée plutôt que laissée en attente (#123), et magasins d'autorisation sortis de la boucle d'événements — le point de décision lit la mémoire, jamais le réseau (#110 lot 3). État antérieur conservé ci-dessous pour mémoire — v0.12.0 (contrat de consommation d'un wrap honnête : un secret sans contenu exploitable ne sort plus en `status: ok`, états terminaux `unusable`/`consume_outcome_unknown` non réessayables, binding de mission exigé aux DEUX bouts en mode durci (#78) ; cloisonnement inter-missions du registre : la compensation et la lecture d'état portent sur le couple `(operation_id, mission_id)`, la compensation d'un orphelin d'une mission ne révoque plus la provision vivante d'une autre ; 39 outils MCP, sondes de santé honnêtes : liveness `/healthz` toujours verte, disponibilité `/health`/`/ready` en 503 avec énumération fermée healthy|sealed|unavailable, sonde OpenBao offloadée, bornée et single-flight (#103), mode `bearer` exigeant un jeton valide (#116), appels S3 du cycle de vie hors boucle d'événements (#122), suppression du shell interactif au profit d'une seule analyse d'arguments côté CLI et sûreté d'état des purges (#128), reproductibilité de l'image : verrou consommé par le Dockerfile et garde d'import à la construction (#125), CI d'exécution des tests, avec démarrage du conteneur et sonde de santé (#113), bornes réseau S3 et chemin d'arrêt porté par le lifespan ASGI (#110 lot 1), échec bruyant sur clés d'unseal inexploitables (#121), permission dédiée `wrap` non-admin pour le broker JIT (verrou wrap-only, policy stricte obligatoire, registre scopé vault+chemins, #115), WAF Coraza v3.7.0 avec parsing JSON borné sur /mcp (profondeur, taille, refus des corps non analysables) et exclusions de cibles anti-évasion, accès SSH JIT opérateur (bearer nominatif + policy dédiée, clé publique pré-enrôlée), pile ASGI 6 couches avec PkiMiddleware, PEP mission JWT à la porte /mcp + MissionBindingStore (PDP local, deny-by-default par tenant), PKI interne CA + ACME, JIT Wrap Broker + consommation médiée C18, audit du cycle de vie des accès, purge des tokens révoqués, console admin web, WAF docker-compose, ContextVar, token cache TTL, ring buffer, écriture create-only atomique (CAS), sync S3 conditionnelle, contrat de configuration `.env.example` déterministe et testé)*
