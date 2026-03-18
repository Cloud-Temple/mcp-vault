# 🔐 MCP Vault

> **Gestion sécurisée des secrets pour agents IA — OpenBao embedded**

MCP Vault est un serveur [MCP](https://modelcontextprotocol.io/) qui fournit un coffre-fort de secrets pour les agents IA et les missions. Il embarque [OpenBao](https://openbao.org/) (fork open-source de HashiCorp Vault, Linux Foundation) comme moteur de chiffrement.

**Pensez 1Password, mais pour vos agents IA.**

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

# 4. Tester (118 tests e2e)
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

## 🛠️ Outils MCP (17)

### System (2)

| Outil | Description |
|-------|-------------|
| `system_health` | État de santé (OpenBao + S3) |
| `system_about` | Informations service (version, outils, plateforme) |

### Vaults — coffres de secrets (5)

| Outil | Perm | Description |
|-------|------|-------------|
| `vault_create(vault_id, description?)` | write | Crée un vault (mount KV v2) + métadonnées (owner, date) |
| `vault_list()` | read | Liste les vaults accessibles (filtrés par token) |
| `vault_info(vault_id)` | read | Détails d'un vault (métadonnées, secrets_count, owner) |
| `vault_update(vault_id, description)` | write | Met à jour la description d'un vault |
| `vault_delete(vault_id, confirm)` | admin | Supprime un vault et tous ses secrets ⚠️ |

### Secrets (6)

| Outil | Perm | Description |
|-------|------|-------------|
| `secret_write(vault_id, path, data, type?)` | write | Écrit un secret typé |
| `secret_read(vault_id, path, version?)` | read | Lit un secret (dernière version ou spécifique) |
| `secret_list(vault_id, path?)` | read | Liste les clés d'un vault |
| `secret_delete(vault_id, path)` | write | Supprime un secret et toutes ses versions |
| `secret_types()` | read | Liste les 14 types de secrets |
| `secret_generate_password(length?, ...)` | read | Génère un mot de passe CSPRNG |

### SSH Certificate Authority (3)

| Outil | Perm | Description |
|-------|------|-------------|
| `ssh_ca_setup(vault_id, role, ...)` | write | Configure un rôle SSH CA |
| `ssh_sign_key(vault_id, role, public_key)` | read | Signe une clé publique → certificat éphémère |
| `ssh_ca_public_key(vault_id)` | read | Clé publique CA (pour `TrustedUserCAKeys`) |

---

## 🔑 Types de secrets (style 1Password)

| Type | Icône | Champs requis | Usage |
|------|-------|---------------|-------|
| `login` | 🔑 | username, password | Identifiants web/app |
| `password` | 🔒 | password | Mot de passe simple |
| `secure_note` | 📝 | content | Notes sécurisées |
| `api_key` | 🔌 | key | Clés API |
| `ssh_key` | 🗝️ | private_key | Paires de clés SSH |
| `database` | 🗄️ | host, username, password | Connexions BDD |
| `server` | 🖥️ | host, username | Accès serveur |
| `certificate` | 📜 | certificate, private_key | Certificats TLS/SSL |
| `env_file` | 📄 | content | Fichiers .env |
| `credit_card` | 💳 | number, expiry, cvv | Cartes bancaires |
| `identity` | 👤 | name | Identités |
| `wifi` | 📶 | ssid, password | Réseaux Wi-Fi |
| `crypto_wallet` | ₿ | *(tout optionnel)* | Wallets crypto |
| `custom` | ⚙️ | *(champs libres)* | Tout le reste |

Chaque secret supporte : `tags`, `favorite`, versioning KV v2 automatique.

---

## 🔒 Authentification

```
Authorization: Bearer <token>
```

| Permission | Lecture | Écriture | Admin |
|------------|--------|----------|-------|
| `read` | ✅ | ❌ | ❌ |
| `write` | ✅ | ✅ | ❌ |
| `admin` | ✅ | ✅ | ✅ |

**Isolation par vault** : chaque token est scopé à des `vault_ids` (vide = tous).

---

## 🖥️ CLI

MCP Vault inclut un CLI complet avec Click + Rich + shell interactif :

```bash
# Commandes scriptables
python scripts/mcp_cli.py health
python scripts/mcp_cli.py about
python scripts/mcp_cli.py vault list
python scripts/mcp_cli.py vault create serveurs-prod -d "Clés SSH prod"
python scripts/mcp_cli.py secret write serveurs-prod web/github -d '{"username":"me","password":"s3cr3t"}' -t login
python scripts/mcp_cli.py secret read serveurs-prod web/github
python scripts/mcp_cli.py secret password -l 32
python scripts/mcp_cli.py token list

# Shell interactif
python scripts/mcp_cli.py shell
```

Voir [scripts/README.md](scripts/README.md) pour la documentation complète du CLI.

---

## 🏗️ Architecture

```
Internet → WAF (Caddy :8082) → MCP Vault (Python :8030) → OpenBao (:8200 localhost)
                                     ↕
                              S3 Dell ECS (persistance)
```

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

### 🔐 Sécurité des clés unseal (Option C)

Les clés unseal d'OpenBao sont protégées par **séparation physique à 3 facteurs** :

| Facteur | Stockage | Compromis seul = insuffisant |
|---------|----------|------------------------------|
| **Données chiffrées** (barrier OpenBao) | Volume Docker + S3 | Illisibles sans unseal key |
| **Clés unseal** (chiffrées AES-256-GCM) | S3 uniquement | Indéchiffrables sans bootstrap key |
| **ADMIN_BOOTSTRAP_KEY** | Variable d'env uniquement | Inutile sans les clés chiffrées |

**Invariants** : les clés unseal ne sont **jamais** en clair sur disque — uniquement en mémoire pendant le runtime. Un crash efface automatiquement les clés.

> 📖 Voir [DESIGN/mcp-vault/ARCHITECTURE.md](DESIGN/mcp-vault/ARCHITECTURE.md) §8 et §11 pour les détails complets.

---

## 📋 Tests

```bash
# Tests e2e MCP (118 tests, OpenBao réel)
docker compose exec mcp-vault python tests/test_e2e.py

# Tests bas niveau (78 tests, S3, auth, types)
docker compose exec mcp-vault python tests/test_service.py --no-docker

# Tests pytest (intégration S3/auth)
docker compose exec mcp-vault python -m pytest tests/test_integration.py -v

# Test spécifique
docker compose exec mcp-vault python tests/test_e2e.py --test secrets
docker compose exec mcp-vault python tests/test_e2e.py --test password
```

### Couverture e2e (118 tests)

| Catégorie | Tests | Description |
|-----------|-------|-------------|
| Système | 7 | health, about, services |
| Vault CRUD | 22 | create + métadonnées, list, info + owner, update, delete, confirm, erreurs |
| Secrets CRUD | 24 | 10 types écrits, read/list/delete, validation |
| Versioning | 8 | v1→v2→v3, read latest, read spécifique |
| Passwords | 14 | longueurs, options, exclusions, CSPRNG |
| Isolation | 7 | secrets cloisonnés entre vaults |
| Erreurs | 10 | edge cases, vault inexistant, type invalide, protection `_vault_meta` |
| S3 Sync | 3 | archive tar.gz sur S3 |
| SSH CA | 2 | setup, public key |
| Types | 16 | 14 types vérifiés individuellement |

---

## 📁 Structure du projet

```
mcp-vault/
├── .env.example              # Configuration (copier en .env)
├── docker-compose.yml        # WAF + MCP Vault + volumes
├── Dockerfile                # Multi-stage (OpenBao 2.5.1 + Python 3.12)
├── requirements.txt          # Dépendances Python
├── VERSION                   # 0.1.0
├── DESIGN/mcp-vault/
│   ├── ARCHITECTURE.md       # Spécification détaillée (v0.2.1-draft)
│   └── TECHNICAL.md          # Documentation technique
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
│   ├── server.py             # FastMCP + 17 outils MCP + lifecycle
│   ├── lifecycle.py          # Orchestrateur startup/shutdown
│   ├── s3_client.py          # Client S3 hybride SigV2/SigV4
│   ├── s3_sync.py            # Sync file backend ↔ S3
│   ├── auth/                 # Bearer tokens, check_access, ContextVar
│   ├── admin/                # Console web /admin + API REST
│   ├── openbao/              # Process manager, HCL config, lifecycle
│   ├── vault/                # Spaces, secrets, SSH CA, types
│   └── static/               # admin.html (SPA)
├── tests/
│   ├── test_e2e.py           # 118 tests MCP e2e
│   ├── test_service.py       # 78 tests bas niveau
│   └── test_integration.py   # Tests pytest
└── waf/                      # Caddy reverse proxy
```

---

## 🌐 Écosystème MCP Cloud Temple

| Serveur | Rôle | Port |
|---------|------|------|
| **MCP Tools** | Boîte à outils (SSH, HTTP, shell) | :8010 |
| **Live Memory** | Mémoire de travail partagée | :8002 |
| **Graph Memory** | Mémoire long terme (graphe) | :8080 |
| **MCP Vault** | 🔐 Coffre-fort à secrets | :8030 |
| **MCP Agent** | Runtime d'agents autonomes | :8040 |
| **MCP Mission** | Orchestrateur de missions | :8020 |

---

**Licence** : Apache 2.0 | **Auteur** : Cloud Temple | **Version** : 0.1.0
