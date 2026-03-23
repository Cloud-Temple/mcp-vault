# 🔐 MCP Vault

> **Gestion sécurisée des secrets pour agents IA — OpenBao embedded**

MCP Vault est un serveur [MCP](https://modelcontextprotocol.io/) qui fournit un coffre-fort de secrets pour les agents IA et les missions. Il embarque [OpenBao](https://openbao.org/) (fork open-source de HashiCorp Vault, Linux Foundation) comme moteur de chiffrement.

**Pensez 1Password, mais pour vos agents IA.**

### 📸 Console d'administration

|               Dashboard                |          Vaults & Secrets           |          Audit & Alertes           |
| :------------------------------------: | :---------------------------------: | :--------------------------------: |
| ![Dashboard](screenshoots/screen1.png) | ![Vaults](screenshoots/screen2.png) | ![Audit](screenshoots/screen3.png) |

---

## 📖 Documentation

| Document                                                | Description                                                                                                                                                                  |
| ------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [**ARCHITECTURE.md**](DESIGN/mcp-vault/ARCHITECTURE.md) | Spécification complète — vision, architecture ASGI 5 couches, vaults, SSH CA, policies MCP (6 exemples prêts à l'emploi), sécurité des clés unseal (3 facteurs), roadmap HSM |
| [**TECHNICAL.md**](DESIGN/mcp-vault/TECHNICAL.md)       | Documentation technique — 14 modules source, modèle de données, Docker, ~290 tests e2e, dépendances, roadmap                                                                |
| [**scripts/README.md**](scripts/README.md)              | Guide CLI complet — 7 groupes de commandes, shell interactif, exemples                                                                                                       |
| [**tests/README.md**](tests/README.md)                  | Guide d'exécution des tests — 4 niveaux, ~575 tests, commandes pour auditeurs                                                                                                |
| [**TEST_CATALOG.md**](tests/TEST_CATALOG.md)            | Catalogue des tests e2e — 14 catégories, ~290 assertions, objectif de chaque section (pour auditeurs)                                                                        |

---

## ⚡ Démarrage rapide

```bash
# 1. Cloner et configurer
cp .env.example .env
# Adapter les credentials S3 dans .env

# 2. Build et démarrer
docker compose build
docker compose up -d

# 3. Vérifier (depuis le conteneur)
docker compose exec mcp-vault python scripts/mcp_cli.py health

# 4. Tester (~290 tests e2e)
docker compose exec mcp-vault python tests/test_e2e.py
```

### Lifecycle automatique

Au démarrage, MCP Vault :
1. Charge les tokens depuis S3
2. Restaure les données OpenBao (volume Docker ou S3)
3. Démarre OpenBao, l'initialise (1ère fois) et le déverrouille
4. **Clés unseal** : chiffrées (AES-256-GCM) sur S3, jamais en clair sur disque — uniquement en mémoire
5. Active le sync S3 périodique (60s)

À l'arrêt (`docker compose stop`) :
1. Scelle OpenBao 🔒
2. Upload final vers S3 📤
3. Arrête le processus — clés effacées de la mémoire

---

## 🛠️ Outils MCP (24)

### System (2)

| Outil           | Description                                        |
| --------------- | -------------------------------------------------- |
| `system_health` | État de santé (OpenBao + S3)                       |
| `system_about`  | Informations service (version, outils, plateforme) |

> 💡 **Introspection** : l'endpoint `/admin/api/whoami` et la commande CLI `whoami` permettent de vérifier l'identité et les permissions du token courant.

### Vaults — coffres de secrets (5)

| Outil                                  | Perm  | Description                                             |
| -------------------------------------- | ----- | ------------------------------------------------------- |
| `vault_create(vault_id, description?)` | write | Crée un vault (mount KV v2) + métadonnées (owner, date) |
| `vault_list()`                         | read  | Liste les vaults accessibles (filtrés par token)        |
| `vault_info(vault_id)`                 | read  | Détails d'un vault (métadonnées, secrets_count, owner)  |
| `vault_update(vault_id, description)`  | write | Met à jour la description d'un vault                    |
| `vault_delete(vault_id, confirm)`      | admin | Supprime un vault et tous ses secrets ⚠️              |

### Secrets (6)

| Outil                                       | Perm  | Description                                    |
| ------------------------------------------- | ----- | ---------------------------------------------- |
| `secret_write(vault_id, path, data, type?)` | write | Écrit un secret typé                           |
| `secret_read(vault_id, path, version?)`     | read  | Lit un secret (dernière version ou spécifique) |
| `secret_list(vault_id, path?)`              | read  | Liste les clés d'un vault                      |
| `secret_delete(vault_id, path)`             | write | Supprime un secret et toutes ses versions      |
| `secret_types()`                            | read  | Liste les 14 types de secrets                  |
| `secret_generate_password(length?, ...)`    | read  | Génère un mot de passe CSPRNG                  |

### SSH Certificate Authority (5)

Chaque vault possède sa **propre CA SSH isolée** — les CA sont cryptographiquement différentes entre vaults. Un certificat signé par la CA d'un vault ne fonctionne PAS sur les serveurs configurés pour un autre vault.

| Outil                                                | Perm  | Description                                                 |
| ---------------------------------------------------- | ----- | ----------------------------------------------------------- |
| `ssh_ca_setup(vault_id, role, allowed_users?, ttl?)` | write | Configure une CA SSH + rôle dans un vault                   |
| `ssh_sign_key(vault_id, role, public_key, ttl?)`     | read  | Signe une clé publique → certificat éphémère                |
| `ssh_ca_public_key(vault_id)`                        | read  | Clé publique CA (pour `TrustedUserCAKeys` sur les serveurs) |
| `ssh_ca_list_roles(vault_id)`                        | read  | Liste les rôles SSH CA configurés dans un vault             |
| `ssh_ca_role_info(vault_id, role)`                   | read  | Détails d'un rôle (TTL, allowed_users, extensions)          |

### Policies MCP — contrôle d'accès granulaire (4)

Les policies permettent de restreindre finement les outils accessibles par token, avec support des **wildcards** (`system_*`, `ssh_*`...) et des **règles par vault** (`prod-*` → lecture seule).

| Outil                                                                                | Perm  | Description                                         |
| ------------------------------------------------------------------------------------ | ----- | --------------------------------------------------- |
| `policy_create(policy_id, description?, allowed_tools?, denied_tools?, path_rules?)` | admin | Crée une policy avec règles d'accès                 |
| `policy_list()`                                                                      | admin | Liste les policies avec compteurs                   |
| `policy_get(policy_id)`                                                              | admin | Détails complets (allowed/denied tools, path_rules) |
| `policy_delete(policy_id, confirm)`                                                  | admin | Supprime une policy ⚠️                            |

> 📋 6 policies prêtes à l'emploi documentées dans [ARCHITECTURE.md §6.4.1](DESIGN/mcp-vault/ARCHITECTURE.md) : `readonly`, `ssh-operator`, `developer`, `prod-reader-dev-writer`, `ci-cd-agent`, `security-auditor`

### Token Management (1)

| Outil                                                          | Perm  | Description                                              |
| -------------------------------------------------------------- | ----- | -------------------------------------------------------- |
| `token_update(hash_prefix, policy_id?, permissions?, vaults?)` | admin | Modifier un token existant (policy, permissions, vaults) |

### Audit (1)

| Outil                                                                      | Perm  | Description                                                             |
| -------------------------------------------------------------------------- | ----- | ----------------------------------------------------------------------- |
| `audit_log(limit?, client?, vault_id?, tool?, category?, status?, since?)` | admin | Journal d'audit filtrable (ring buffer 5000 entrées + JSONL persistant) |

<details>
<summary>💡 Workflow SSH CA typique (ex: infrastructure LLMaaS)</summary>

```python
# 1. Setup initial (ONE-TIME) — créer vault + rôles SSH
vault_create("llmaas-infra", description="SSH CA LLMaaS")
ssh_ca_setup("llmaas-infra", "adminct", allowed_users="adminct", ttl="1h")
ssh_ca_setup("llmaas-infra", "agentic", allowed_users="agentic,iaagentic", ttl="30m")

# 2. Déployer la CA sur les serveurs (ONE-TIME)
result = ssh_ca_public_key("llmaas-infra")
# → Mettre result["public_key"] dans /etc/ssh/trusted-user-ca-keys.pem

# 3. Usage quotidien — signer une clé publique
cert = ssh_sign_key("llmaas-infra", "adminct", public_key="ssh-ed25519 AAAA...", ttl="1h")
# → cert["signed_key"] = certificat signé, valide 1h
# → OpenSSH l'utilise automatiquement si placé à côté de la clé privée
```

</details>

---

## 🔑 Types de secrets (style 1Password)

| Type            | Icône | Champs requis            | Usage                |
| --------------- | ----- | ------------------------ | -------------------- |
| `login`         | 🔑   | username, password       | Identifiants web/app |
| `password`      | 🔒   | password                 | Mot de passe simple  |
| `secure_note`   | 📝   | content                  | Notes sécurisées     |
| `api_key`       | 🔌   | key                      | Clés API             |
| `ssh_key`       | 🗝️ | private_key              | Paires de clés SSH   |
| `database`      | 🗄️ | host, username, password | Connexions BDD       |
| `server`        | 🖥️ | host, username           | Accès serveur        |
| `certificate`   | 📜   | certificate, private_key | Certificats TLS/SSL  |
| `env_file`      | 📄   | content                  | Fichiers .env        |
| `credit_card`   | 💳   | number, expiry, cvv      | Cartes bancaires     |
| `identity`      | 👤   | name                     | Identités            |
| `wifi`          | 📶   | ssid, password           | Réseaux Wi-Fi        |
| `crypto_wallet` | ₿     | *(tout optionnel)*       | Wallets crypto       |
| `custom`        | ⚙️  | *(champs libres)*        | Tout le reste        |

Chaque secret supporte : `tags`, `favorite`, versioning KV v2 automatique.

---

## 🔒 Authentification

> ⚠️ **Seul le header `Authorization: Bearer <token>` est accepté.** L'authentification par query string (`?token=`) a été supprimée pour des raisons de sécurité (v0.3.1).

```
Authorization: Bearer <token>
```

| Permission | Lecture | Écriture | Admin |
| ---------- | ------- | -------- | ----- |
| `read`     | ✅      | ❌       | ❌    |
| `write`    | ✅      | ✅       | ❌    |
| `admin`    | ✅      | ✅       | ✅    |

**3 couches d'isolation** :
1. **Vault-level** : `allowed_resources=[]` → owner-based (seuls les vaults créés par le token), ou liste explicite
2. **Tool-level** : policies avec `allowed_tools`/`denied_tools` (wildcards fnmatch)
3. **Path-level** : `allowed_paths` dans les `path_rules` → contrôle par secret individuel

---

## 🖥️ CLI

MCP Vault inclut un CLI complet avec Click + Rich + shell interactif :

```bash
# Commandes scriptables
python scripts/mcp_cli.py health
python scripts/mcp_cli.py about
python scripts/mcp_cli.py whoami                       # Identité du token courant
python scripts/mcp_cli.py vault list
python scripts/mcp_cli.py vault create serveurs-prod -d "Clés SSH prod"
python scripts/mcp_cli.py secret write serveurs-prod web/github -d '{"username":"me","password":"s3cr3t"}' -t login
python scripts/mcp_cli.py secret read serveurs-prod web/github
python scripts/mcp_cli.py secret password -l 32
python scripts/mcp_cli.py token create agent-sre --vaults prod --policy readonly
python scripts/mcp_cli.py token list
python scripts/mcp_cli.py policy create no-ssh -d "Pas de SSH" --denied "ssh_*"
python scripts/mcp_cli.py policy create team-x --allowed "secret_*" --path-rules '[{"vault_pattern":"shared-*","allowed_paths":["shared/*"]}]'
python scripts/mcp_cli.py audit --status denied --limit 10

# Shell interactif
python scripts/mcp_cli.py shell
```

> L'aide `--help` de chaque commande explique le modèle de sécurité à 3 couches et guide l'utilisateur.

Voir [scripts/README.md](scripts/README.md) pour la documentation complète du CLI.

---

## 🏗️ Architecture

> 📐 **Documentation complète** : le dossier [`DESIGN/mcp-vault/`](DESIGN/mcp-vault/) contient la spécification détaillée ([ARCHITECTURE.md](DESIGN/mcp-vault/ARCHITECTURE.md) — vision, sécurité, SSH CA, policies, roadmap HSM) et la documentation technique ([TECHNICAL.md](DESIGN/mcp-vault/TECHNICAL.md) — modules, Docker, tests, dépendances).

```
Internet → WAF (Caddy + Coraza :8085) → MCP Vault (Python :8030) → OpenBao (:8200 localhost)
                  ↕ OWASP CRS v4                  ↕
              Protection L7                 S3 Dell ECS (persistance)
```

### WAF — Caddy + Coraza (OWASP CRS v4)

Le WAF protège l'API contre les attaques L7 (injections SQL, XSS, LFI, RCE, SSRF) :
- **Caddy v2.11.2** compilé avec **coraza-caddy v2.2.0** via `xcaddy`
- **24 règles OWASP CoreRuleSet v4.7.0** chargées
- Mode **Blocking** pour les chemins non-authentifiés (statiques, health)
- Mode **DetectionOnly** pour les APIs authentifiées (`/mcp`, `/admin/api`) — déjà protégées par Bearer token + policies
- **Headers de sécurité** : CSP, X-Frame-Options DENY, X-XSS-Protection, nosniff
- Méthodes autorisées adaptées au protocole MCP : GET, POST, DELETE, PUT, PATCH

### Stack ASGI (5 couches)
```
AdminMiddleware → HealthCheckMiddleware → AuthMiddleware → LoggingMiddleware → FastMCP
```

### Lifecycle OpenBao
```
STARTUP:  S3 download → bao server → init/unseal → periodic sync
RUNTIME:  secrets via hvac → sync S3 toutes les 60s
SHUTDOWN: seal → S3 upload final → stop process
CRASH:    Docker volume local → redémarrage immédiat
```

### Sécurité des clés unseal

Les clés unseal d'OpenBao sont protégées par **séparation physique à 3 facteurs** :

| Facteur                                 | Stockage                  | Compromis seul = insuffisant       |
| --------------------------------------- | ------------------------- | ---------------------------------- |
| **Données chiffrées** (barrier OpenBao) | Volume Docker + S3        | Illisibles sans unseal key         |
| **Clés unseal** (chiffrées AES-256-GCM) | S3 uniquement             | Indéchiffrables sans bootstrap key |
| **ADMIN_BOOTSTRAP_KEY**                 | Variable d'env uniquement | Inutile sans les clés chiffrées    |

**Invariants** : les clés unseal ne sont **jamais** en clair sur disque — uniquement en mémoire pendant le runtime. Un crash efface automatiquement les clés.

**Roadmap sécurité** :

| Version             | Approche                                                                                                            |
| ------------------- | ------------------------------------------------------------------------------------------------------------------- |
| **v0.3.x** (actuel) | Clés sur S3 chiffrées AES-256-GCM, mémoire seule au runtime — console SPA parité CLI                                |
| **v0.4.0**          | Transit Auto-Unseal via OpenBao dédié (KMS Cloud Temple)                                                            |
| **v2.0**            | **Connexion HSM** (Hardware Security Module) Cloud Temple — les clés ne quittent jamais le module matériel certifié |

> 📖 Voir [DESIGN/mcp-vault/ARCHITECTURE.md](DESIGN/mcp-vault/ARCHITECTURE.md) §8 et §11 pour les détails complets.

---

## 📋 Tests (~590 tests, zéro mocking)

> 📖 Voir [tests/README.md](tests/README.md) pour le guide complet d'exécution.

```bash
# 1. Tests CLI — parsing + affichage (197 tests, SANS serveur)
python tests/test_cli_all.py

# 2. Tests CLI LIVE — cycle complet (79 tests, serveur réel)
MCP_URL=http://localhost:8085 MCP_TOKEN=<key> python tests/test_cli_live.py

# 3. Tests e2e MCP (~290 tests, dans Docker)
docker compose exec mcp-vault python tests/test_e2e.py

# 4. Tests crypto (16 tests, SANS serveur — AES-256-GCM + validation entropie)
python tests/test_crypto.py

# Un seul groupe CLI
python tests/test_cli_all.py --only policy

# Un seul groupe e2e
docker compose exec mcp-vault python tests/test_e2e.py --test enforcement
```

### Couverture e2e (276 tests, 14 catégories)

| Catégorie              | Tests  | Description                                                                        |
| ---------------------- | ------ | ---------------------------------------------------------------------------------- |
| Système                | 7      | health, about, services, tools_count (24)                                          |
| Vault CRUD             | 28     | create + métadonnées, list, info + owner, update, delete, confirm, erreurs         |
| Secrets CRUD           | 24     | 10 types écrits, read/list/delete, validation                                      |
| Versioning             | 8      | v1→v2→v3, read latest, read spécifique                                             |
| Passwords              | 14     | longueurs, options, exclusions, CSPRNG                                             |
| Isolation              | 7      | secrets cloisonnés entre vaults                                                    |
| Erreurs                | 10     | edge cases, vault inexistant, type invalide, protection `_vault_meta`              |
| S3 Sync                | 3      | archive tar.gz sur S3                                                              |
| SSH CA                 | 33     | setup, rôles multiples, signature ed25519, list/info roles, isolation CA, cleanup  |
| Types                  | 14     | 14 types vérifiés individuellement                                                 |
| Admin API              | 15     | health, whoami, generate-password, logs, unicité CSPRNG                            |
| Policies MCP           | 43     | CRUD, validation, wildcards, path_rules, doublons, erreurs, Admin API REST         |
| **Policy Enforcement** | **37** | check_policy, token_update, denied/allowed, changement policy, Admin API           |
| **Audit Log**          | **31** | audit_log MCP, filtres (category/tool/status/since/limit), stats, Admin API /audit |

---

## 📁 Structure du projet

```
mcp-vault/
├── .env.example              # Configuration (copier en .env)
├── docker-compose.yml        # WAF + MCP Vault + volumes
├── Dockerfile                # Multi-stage (OpenBao 2.5.1 + Python 3.12)
├── requirements.txt          # Dépendances Python
├── VERSION                   # 0.3.1
├── DESIGN/mcp-vault/
│   ├── ARCHITECTURE.md       # Spécification détaillée (v0.2.2-draft)
│   └── TECHNICAL.md          # Documentation technique (v0.2.0)
├── scripts/
│   ├── mcp_cli.py            # CLI entry point
│   ├── README.md             # Documentation CLI
│   └── cli/                  # Module CLI (Click + Rich + prompt-toolkit)
│       ├── __init__.py       # Config (.env, BASE_URL, TOKEN)
│       ├── client.py         # MCPClient (Streamable HTTP)
│       ├── commands.py       # 7 groupes Click
│       ├── display.py        # Affichage Rich
│       └── shell.py          # Shell interactif
├── src/mcp_vault/
│   ├── config.py             # Configuration pydantic-settings
│   ├── server.py             # FastMCP + 24 outils MCP + lifecycle + audit
│   ├── lifecycle.py          # Orchestrateur startup/shutdown
│   ├── s3_client.py          # Client S3 hybride SigV2/SigV4
│   ├── s3_sync.py            # Sync file backend ↔ S3
│   ├── auth/                 # Bearer tokens, check_access, ContextVar
│   ├── admin/                # Console web /admin + API REST
│   ├── openbao/              # Process manager, HCL config, lifecycle
│   ├── vault/                # Spaces, secrets, SSH CA, types
│   └── static/               # Console admin SPA (parité CLI 100%)
│       ├── admin.html        # HTML structure + 7 modals
│       ├── css/admin.css     # Design Cloud Temple (dark theme)
│       ├── js/               # 8 modules JS (config, api, app, dashboard, vaults, tokens, policies, activity)
│       └── img/              # logo-cloudtemple.svg
├── tests/
│   ├── README.md             # Guide d'exécution des tests (auditeurs)
│   ├── TEST_CATALOG.md       # Catalogue des tests pour auditeurs
│   ├── test_cli_all.py       # 197 tests CLI parsing (sans serveur)
│   ├── test_cli_live.py      # 79 tests CLI live (serveur réel)
│   ├── test_e2e.py           # ~290 tests MCP e2e (14 catégories)
│   ├── test_crypto.py        # 9 tests AES-256-GCM
│   ├── test_service.py       # 78 tests bas niveau
│   ├── test_integration.py   # Tests pytest
│   └── cli/                  # Tests CLI découpés par groupe (7 fichiers)
└── waf/                      # WAF Caddy + Coraza (OWASP CRS v4)
    ├── Dockerfile            # Multi-stage (xcaddy + CRS v4.7.0)
    ├── Caddyfile             # Reverse proxy + coraza_waf
    └── coraza.conf           # Config Coraza + exceptions MCP
```

---

## 🌐 Écosystème MCP Cloud Temple

| Serveur          | Rôle                              | Port  |
| ---------------- | --------------------------------- | ----- |
| **MCP Tools**    | Boîte à outils (SSH, HTTP, shell) | :8010 |
| **Live Memory**  | Mémoire de travail partagée       | :8002 |
| **Graph Memory** | Mémoire long terme (graphe)       | :8080 |
| **MCP Vault**    | 🔐 Coffre-fort à secrets         | :8030 |
| **MCP Agent**    | Runtime d'agents autonomes        | :8040 |
| **MCP Mission**  | Orchestrateur de missions         | :8020 |

---

**Licence** : Apache 2.0 | **Auteur** : Cloud Temple | **Version** : 0.3.1
