# 🔐 MCP Vault

> **Gestion sécurisée des secrets pour agents IA — OpenBao embedded**

> 🇬🇧 [English version](README.en.md)

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
| [**ARCHITECTURE.md**](DESIGN/mcp-vault/ARCHITECTURE.md) | Spécification complète — vision, architecture ASGI 6 couches, vaults, SSH CA, policies MCP (6 exemples prêts à l'emploi), sécurité des clés unseal (3 facteurs), roadmap HSM |
| [**TECHNICAL.md**](DESIGN/mcp-vault/TECHNICAL.md)       | Documentation technique — modules source (incl. PKI v0.5.1), stack ASGI 6 couches, Docker, tests, dépendances, roadmap                                                     |
| [**SECURITY_AUDIT.md**](DESIGN/mcp-vault/SECURITY_AUDIT.md) | Rapport d'audit de sécurité consolidé — 60 findings V2.1, 28 corrigés, 13 résiduels documentés                                                                         |
| [**scripts/README.md**](scripts/README.md)              | Guide CLI complet — 7 groupes de commandes, shell interactif, exemples                                                                                                       |
| [**tests/README.md**](tests/README.md)                  | Guide d'exécution des tests — 4 niveaux, ~600 tests, commandes pour auditeurs                                                                                                |
| [**TEST_CATALOG.md**](tests/TEST_CATALOG.md)            | Catalogue des tests e2e — 15 catégories, 312 assertions, objectif de chaque section (pour auditeurs)                                                                        |

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

# 4. Tester (312 tests e2e)
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

## 🛠️ Outils MCP (36)

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

> **Purge des tokens révoqués** *(v0.7.0 — opération **admin**, exposée en REST / CLI / SPA ; ce n'est PAS un outil MCP)* : supprime définitivement les tokens révoqués depuis plus de N jours (rétention, défaut 30). **Fail-close** (jamais un token actif ni un token expiré non révoqué), **dry-run + confirmation**, rollback si S3 indisponible, chaque purge **auditée**. Via `POST /admin/api/tokens/purge`, la commande CLI `token purge-revoked`, ou le bouton « 🧹 Purger révoqués » de la console `/admin`.

### PKI interne — CA + ACME (8) *(v0.5.0)*

CA souveraine pour l'écosystème : les WAF Caddy s'enrôlent via ACME exactement comme avec Let's Encrypt, mais sur une CA interne isolée du réseau public. Utilisable en lab (`*.lesur.lan`) et en prod air-gapped.

| Outil | Perm | Description |
| --- | --- | --- |
| `pki_ca_setup(lab_mode, allowed_domains, leaf_ttl)` | admin | Initialise CA racine + intermédiaire + rôle ACME |
| `pki_ca_public_key()` | read | CA racine PEM, empreinte SHA-256, URL stable |
| `pki_ca_list_roles()` | read | Liste les rôles d'émission |
| `pki_ca_role_info(role_name)` | read | Détails rôle (domaines, TTL, flags TLS) |
| `pki_list_certs(limit?, offset?)` | admin | Inventaire paginé des certificats émis |
| `pki_issue_cert(common_name, ttl?, alt_names?, ip_sans?)` | admin | Émission manuelle d'un certificat (hors ACME) — clé privée one-shot |
| `pki_revoke_cert(serial_number)` | admin | Révocation + mise à jour CRL |
| `pki_ca_rotate_intermediate(keep_old_issuer?, overlap_ttl?)` | admin | Rotation CA intermédiaire sans coupure |

> Endpoints publics (non-auth, standard ACME/PKI) : `/acme/directory`, `/pki/ca/root.pem`, `/pki/ca/chain.pem`, `/pki/ca/crl.pem`
>
> **`PKI_BASE_URL`** (optionnel) : URL de base pour les CDPs et le cluster path OpenBao ACME. Vide = déduit de `MCP_ALLOWED_HOSTS`. Override test Docker : `http://mcp-vault:8030`. Doit être `http(s)://`.

### JIT Wrap Broker + consommation médiée — C18 (4) *(v0.4.13 / v0.6.x)*

Contrat pour le `CredentialBrokerService` de mcp-mission : livraison de credentials single-use via response wrapping OpenBao (cubbyhole), registry write-ahead sur S3 pour la compensation des orphelins, et validation anti-confused-deputy (C18).

| Outil | Perm | Description |
| --- | --- | --- |
| `secret_wrap(vault_id, secret_path, mission_id, operation_id, ttl_seconds?, tenant_id?, expected_aud?)` | admin | Crée un wrap token single-use (write-ahead registry) |
| `secret_revoke_wrap(lease_id)` | admin | Révocation idempotente d'un wrap token (introuvable = succès) |
| `secret_wrap_lookup(operation_id)` | admin | Retrouve & révoque les wraps par operation_id (compensation orphelins #74) |
| `secret_consume(wrap_token, operation_id, mission_token)` | admin | Valide JWT ES256/JWKS, vérifie binding complet (mission_id, tenant_id, aud), unwrap OpenBao (C18) |

> Activer la validation C18 avec `ENFORCE_MISSION_TOKEN_VALIDATION=true`. Par défaut (false) : log warning, continue — zéro impact standalone sans mcp-mission.
> `tenant_id` et `expected_aud` dans `secret_wrap` alimentent le binding C18 complet côté `secret_consume` *(v0.6.8)*.

### PEP mission JWT — porte `/mcp` *(v0.8.0, #47 + #69)*

Second point d'application (PEP) du `mission_token` JWT ES256 de mcp-mission, **à l'entrée `/mcp`** (le premier étant `secret_consume`/C18, à la consommation). Piloté par `MCP_AUTH_MODE` :

| Mode | Comportement `/mcp` |
| --- | --- |
| `bearer` *(défaut)* | Bearer opaque uniquement — comportement historique, **zéro impact**. |
| `jwt` | `mission_token` JWT ES256 **obligatoire** (bearer opaque refusé). |
| `dual-stack` | JWT valide **OU** bearer opaque valide (migration). |

En `jwt`/`dual-stack`, le middleware **refuse activement** : `401` (token absent/opaque/JWT invalide), `403` (`aud`/`component_id` ≠ instance, mission inactive), `503` (JWKS indisponible — fail-close). Un JWT invalide ne retombe **jamais** sur le bearer. Le token est vérifié contre le contrat réel mcp-mission (`aud` contient `MCP_INSTANCE_ID`, `component_id["vault"] == MCP_INSTANCE_ID`, `iss`, `exp` leeway 0, `iat` anti-skew). La bootstrap key admin reste acceptée (break-glass).

> Une identité mission valide est **authentifiée et liée à l'instance**, puis mcp-vault (**PDP local**) lui résout un **périmètre vault provisionné localement**. Sans octroi, **aucun accès** (deny-by-default) ; les outils d'infra (`system_*`, inventaire PKI) et l'admin-plane (`vault_create/delete`, `ssh_*`) lui sont refusés. L'endpoint admin `POST /admin/api/auth/jwks/reload` force le rechargement du JWKS (révocation urgente de `kid`).

#### Octroi de périmètre vault — `MissionBindingStore` *(#69)*

Le `mission_token` ne porte **aucune** autorisation vault : l'octroi est **provisionné localement**, indexé par `tenant_id` (claim stable), et stocké un **fichier par instance** sur S3.

- Un octroi (« binding ») = `{tenant_id, allowed_resources:[coffres…], permissions, policy_id?, enabled, expires_at?}`.
- **Permissions strictes** : `read` ou `read,write` (jamais `write` seul, jamais `admin`). **Data-plane uniquement** : lire/écrire des secrets dans les coffres autorisés — **jamais** créer/détruire un coffre ni gérer une CA SSH.
- **Fail-close** : binding absent/désactivé/expiré → aucun accès. **Registre indisponible/corrompu → `503`** (refus observable, jamais un deny silencieux ni un écrasement destructeur).
- **Administration** (bearer/bootstrap admin uniquement — jamais via mission JWT) :

```bash
# Octroyer un périmètre lecture à un client mission
mcp-cli mission-binding create acme-corp --vaults prod-app --permissions read
# Lecture + écriture sur plusieurs coffres
mcp-cli mission-binding create acme-corp --vaults prod-app,staging --permissions read,write
mcp-cli mission-binding list
mcp-cli mission-binding get acme-corp
mcp-cli mission-binding delete acme-corp
mcp-cli mission-binding purge --older-than 30 --dry-run   # bindings expirés
```

> **Granularité tenant** : toutes les missions actives d'un même client (`tenant_id`) partagent le périmètre octroyé. Le grain fin par mission existe déjà à la consommation (`secret_consume`/C18).

### Audit (1)

| Outil                                                                      | Perm  | Description                                                             |
| -------------------------------------------------------------------------- | ----- | ----------------------------------------------------------------------- |
| `audit_log(limit?, client?, vault_id?, tool?, category?, status?, since?)` | admin | Journal d'audit filtrable (ring buffer 5000 entrées + JSONL persistant) |

> **Traçabilité du cycle de vie des accès** *(v0.7.0 — conformité SecNumCloud/HDS)* : toute mutation du plan de contrôle — création / mise à jour / révocation / purge de token, création / suppression de policy — est journalisée, via l'**API REST admin** comme via les **outils MCP**. Les échecs de persistance des opérations de **retrait** (révocation, purge, suppression de policy — celles qui laissent un accès actif si elles échouent) sont également tracés. La trace vit dans `audit-mcp.jsonl`, **physiquement indépendant de `_system/tokens.json`** → elle survit à une purge. Le token brut n'apparaît jamais dans le détail d'audit.

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
python scripts/mcp_cli.py token purge-revoked --older-than 30 --dry-run    # aperçu (rien supprimé)
python scripts/mcp_cli.py token purge-revoked --older-than 30 --yes        # purge effective
python scripts/mcp_cli.py policy create no-ssh -d "Pas de SSH" --denied "ssh_*"
python scripts/mcp_cli.py policy create team-x --allowed "secret_*" --path-rules '[{"vault_pattern":"shared-*","allowed_paths":["shared/*"]}]'
python scripts/mcp_cli.py audit --status denied --limit 10

# PKI interne (v0.5.0)
python scripts/mcp_cli.py pki setup --lab --domains '*.lesur.lan,lesur.lan'
python scripts/mcp_cli.py pki ca-key
python scripts/mcp_cli.py pki certs
python scripts/mcp_cli.py pki revoke 12:34:ab:cd:ef:12:34:56

# Shell interactif
python scripts/mcp_cli.py shell
```

> L'aide `--help` de chaque commande explique le modèle de sécurité à 3 couches et guide l'utilisateur.

Voir [scripts/README.md](scripts/README.md) pour la documentation complète du CLI.

---

## ⚙️ Variables d'environnement

Copier `.env.example` → `.env` et adapter. Les variables sont groupées par domaine :

| Groupe | Variables | Obligatoire |
|--------|-----------|-------------|
| **Serveur** | `MCP_SERVER_NAME`, `MCP_SERVER_PORT`, `MCP_ALLOWED_HOSTS` | Oui |
| **Auth** | `ADMIN_BOOTSTRAP_KEY` | Oui |
| **S3** | `S3_ENDPOINT_URL`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_BUCKET_NAME`, `S3_REGION_NAME` | Oui |
| **OpenBao** | `OPENBAO_ADDR`, `OPENBAO_SHARES`, `OPENBAO_THRESHOLD` | Oui |
| **Storage sync** | `VAULT_S3_PREFIX`, `VAULT_S3_SYNC_INTERVAL` | Non |
| **PKI** *(v0.5.x)* | `PKI_BASE_URL` | Non — override URL ACME en test Docker |
| **Mission JWT** *(v0.6.0)* | `ENFORCE_MISSION_TOKEN_VALIDATION`, `MISSION_JWKS_URL`, `MISSION_TOKEN_AUD`, `MISSION_JWKS_CACHE_TTL`, `MISSION_STATUS_URL` | Non — standalone sans mcp-mission |
| **PEP mission JWT** *(v0.8.0)* | `MCP_AUTH_MODE` (`bearer`/`jwt`/`dual-stack`), `MCP_INSTANCE_ID`, `MCP_COMPONENT_KIND` | Non — défaut `bearer` = zéro impact. `jwt`/`dual-stack` exigent `MISSION_JWKS_URL` + `MCP_INSTANCE_ID` |
| **CLI tokens** | `VAULT_WRAP_TOKEN`, `VAULT_MISSION_TOKEN` | Non — exporter avant la commande, jamais dans `.env` |

> **Tokens sensibles CLI** : `VAULT_WRAP_TOKEN` et `VAULT_MISSION_TOKEN` ne doivent PAS être stockés dans `.env` — ils changent à chaque opération. Passer via `export` ou inline :
> ```bash
> VAULT_WRAP_TOKEN=hvs.CAES... mcp-vault secret consume op-123
> ```

Voir `.env.example` pour la documentation complète de chaque variable.

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
- Mode **Blocking sur TOUS les endpoints** (health, `/mcp`, `/admin/api`)
- **Exclusions ciblées** (faux positifs JSON-RPC : Unicode français 920540, noms PowerShell 932120 ; distribution CA/CRL `.pem` 920440) déclarées **avant l'Include CRS** (pattern « exclusions before CRS ») — requis pour neutraliser les règles CRS en phase:1
- **Headers de sécurité** : CSP, X-Frame-Options DENY, X-XSS-Protection, nosniff
- Méthodes autorisées adaptées au protocole MCP : GET, POST, DELETE, PUT, PATCH

### Stack ASGI (6 couches)
```
PkiMiddleware → AdminMiddleware → HealthCheckMiddleware → AuthMiddleware → LoggingMiddleware → FastMCP
```

`PkiMiddleware` (v0.5.0) est la couche la plus externe — intercepte `/acme/*` et `/pki/ca/*.pem` avant l'auth (endpoints publics par design PKI/ACME).

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

| Version              | Approche                                                                                                            |
| -------------------- | ------------------------------------------------------------------------------------------------------------------- |
| **v0.7.0** (actuel)  | Clés sur S3 chiffrées AES-256-GCM+AAD, mémoire seule au runtime |
| **v1.0**             | Transit Auto-Unseal via OpenBao dédié (KMS Cloud Temple)                                                            |
| **v2.0**             | **Connexion HSM** (Hardware Security Module) Cloud Temple — les clés ne quittent jamais le module matériel certifié |

> 📖 Voir [DESIGN/mcp-vault/ARCHITECTURE.md](DESIGN/mcp-vault/ARCHITECTURE.md) §8 et §11 pour les détails complets.

---

## 📋 Tests (~600 tests, zéro mocking)

> 📖 Voir [tests/README.md](tests/README.md) pour le guide complet d'exécution.

```bash
# 1. Tests CLI — parsing + affichage (197 tests, SANS serveur)
python tests/test_cli_all.py

# 2. Tests CLI LIVE — cycle complet (79 tests, serveur réel)
MCP_URL=http://localhost:8085 MCP_TOKEN=<key> python tests/test_cli_live.py

# 3. Tests e2e MCP (312 tests, dans Docker)
docker compose exec mcp-vault python tests/test_e2e.py

# 4. Tests crypto (18 tests, SANS serveur — AES-256-GCM + AAD + validation entropie)
python tests/test_crypto.py

# Un seul groupe CLI
python tests/test_cli_all.py --only policy

# Un seul groupe e2e
docker compose exec mcp-vault python tests/test_e2e.py --test enforcement
```

### Couverture e2e (312 tests, 15 catégories)

| Catégorie              | Tests  | Description                                                                        |
| ---------------------- | ------ | ---------------------------------------------------------------------------------- |
| Système                | 7      | health, about, services, tools_count (36)                                          |
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
| **WAF Security**       | **17** | LFI, SQLi, XSS, RCE, Scanner Detection → 403 + non-régression requêtes légitimes |

---

## 📁 Structure du projet

```
mcp-vault/
├── .env.example              # Configuration (copier en .env)
├── docker-compose.yml        # WAF + MCP Vault + volumes
├── Dockerfile                # Multi-stage (OpenBao 2.5.1 + Python 3.12)
├── requirements.txt          # Dépendances Python
├── requirements.lock         # Dépendances pinnées (versions exactes)
├── VERSION                   # 0.7.0
├── DESIGN/mcp-vault/
│   ├── ARCHITECTURE.md       # Spécification détaillée (v0.7.0)
│   ├── TECHNICAL.md          # Documentation technique (v0.7.0)
│   └── SECURITY_AUDIT.md     # Rapport d'audit consolidé (60 findings V2.1)
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
│   ├── server.py             # FastMCP + 36 outils MCP + lifecycle + audit
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
│       ├── js/               # 9 modules JS (config, api, app, dashboard, vaults, tokens, policies, activity, pki)
│       └── img/              # logo-cloudtemple.svg
├── tests/
│   ├── README.md             # Guide d'exécution des tests (auditeurs)
│   ├── TEST_CATALOG.md       # Catalogue des tests pour auditeurs
│   ├── test_cli_all.py       # 197 tests CLI parsing (sans serveur)
│   ├── test_cli_live.py      # 79 tests CLI live (serveur réel)
│   ├── test_e2e.py           # 312 tests MCP e2e (15 catégories)
│   ├── test_crypto.py        # 18 tests AES-256-GCM + AAD
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

**Licence** : Apache 2.0 | **Auteur** : Cloud Temple | **Version** : 0.7.0
