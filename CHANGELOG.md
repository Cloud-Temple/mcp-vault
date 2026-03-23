# Changelog — MCP Vault

## [0.2.0] — 2026-03-23

### Security — 3 couches d'isolation

#### Owner-based vault isolation (Phase 8d)
- **BREAKING**: `allowed_resources=[]` → accès uniquement aux vaults créés par le token (`created_by`), et non plus à tous les vaults
- **Fix**: Bug `vault_ids` → `allowed_resources` — les restrictions de vaults ne s'appliquaient jamais côté MCP tools
- `check_vault_owner()` vérifie `_vault_meta.created_by` pour l'isolation par propriétaire
- `list_spaces(owner_filter)` filtre les vaults par créateur

#### Path-level enforcement (Phase 8e)
- **Nouveau** : `allowed_paths` dans les `path_rules` des policies — contrôle d'accès au niveau secret individuel
- `is_path_allowed(policy_id, vault_id, path)` dans PolicyStore — matching fnmatch sur les chemins
- `check_path_policy(vault_id, path)` dans context.py — appelé par `secret_read`, `secret_write`, `secret_delete`
- Scénario testé : Alice/Bob partagent un vault, mais seuls les chemins `shared/*` sont accessibles — `private/*` est bloqué

### Features
- **SPA**: Modal d'édition des tokens (permissions, vaults autorisés, policy_id)
- **SPA**: Bouton Modifier sur chaque token
- Label "vide = tous" → "vide = mes vaults" partout

### CLI — Mise à jour complète

#### Nouvelles options
- **`policy create --path-rules/-R`** : création de policies avec restriction par chemin (JSON, fnmatch wildcards)
- **`token create --policy`** : assignation d'une policy dès la création du token

#### Affichage amélioré (display.py)
- **Policy get** : affichage détaillé des `allowed_paths` par path_rule (vault_pattern → permissions → chemins)
- **Token list** : colonnes `Vaults` + `Policy` (remplacent `Spaces` + `Email`)
- **Token create** : affiche policy_id assignée, "(tous — isolation par propriétaire)" si vaults vides
- **Vault list** : colonnes `Vault ID` + `Owner` (remplacent `Space ID`)
- **Whoami** : affiche la policy assignée au token

#### Aide pédagogique
- Aide racine : explication du modèle de sécurité à 3 couches (owner → vault → path)
- Aide vault : explique l'isolation owner-based
- Aide policy : explique la priorité denied > allowed, documention des path_rules avec exemples
- Aide token : explique le comportement par défaut (owner-based) et le rôle de --policy

### 🧪 Tests
- **~290 tests e2e** répartis en 14 catégories (anciennement 276)
- **TEST 13 réécrit** : owner-based isolation, cross-user Alice/Bob (vault-level + path-level), policy enforcement
- **197 tests CLI parsing** (`tests/test_cli_all.py`) : validation hors-ligne de TOUTES les commandes Click (aide, arguments, JSON, affichage Rich)
- **79 tests CLI live** (`tests/test_cli_live.py`) : cycle complet contre serveur réel (vault CRUD, secrets, policies+paths, tokens+enforcement, SSH CA, audit)
- **Tests CLI découpés** en 7 fichiers (`tests/cli/test_{system,vault,secret,ssh,policy,token,audit}.py`)
- Nouveau : `tests/TEST_CATALOG.md` — catalogue complet des tests pour auditeurs (19 sections avec objectifs)
- Nouveau : `tests/README.md` — guide d'exécution des tests pour auditeurs
- Environnement de recette isolé : bucket S3 `MCP-RECETTE` dédié aux tests

### Documentation
- `tests/README.md` : guide d'exécution de tous les tests (parsing, live, e2e)
- `tests/TEST_CATALOG.md` : catalogue d'audit des ~290 tests avec objectif par section
- DESIGN docs mis à jour (v0.2.0, owner isolation, path-level enforcement)

## [0.1.0] — 2026-03-22

### Added
- **24 outils MCP** : vaults (5), secrets (6), SSH CA (5), policies (4), token_update, audit_log, system (2)
- **14 types de secrets** style 1Password : login, password, api_key, database, server, certificate, etc.
- **SSH Certificate Authority** : CA isolée par vault, signature de clés éphémères ed25519
- **Policies MCP** : contrôle d'accès granulaire avec wildcards (fnmatch), path_rules par vault
- **Audit log** : ring buffer 5000 entrées + JSONL persistant, filtres combinables (category, status, since, tool, client)
- **Console admin SPA** (`/admin`) : dashboard, vaults, tokens, activité avec timeline, filtres et alertes
- **CLI complet** : Click + Rich + shell interactif (prompt-toolkit), 9 groupes de commandes
- **Route `GET /`** : status JSON public (nom, version, endpoints)
- **Mode `--demo`** : scénario réaliste avec tokens, policies, tentatives denied, SSH CA
- **276 tests e2e** répartis en 14 catégories (OpenBao réel, zéro mocking)
- **Sécurité Option C** : clés unseal chiffrées AES-256-GCM (PBKDF2 600k), stockées S3, mémoire seule au runtime
- **S3 sync** : périodique (60s), crash recovery via Docker volume, Dell ECS SigV2/SigV4
- **WAF** : Caddy reverse proxy + headers sécurité (port 8085)
- **Docker** : multi-stage (OpenBao 2.5.1 ARM64/x86_64 + Python 3.12), IPC_LOCK
- **Licence** : Apache 2.0, Cloud Temple

### Architecture
- Stack ASGI 5 couches : Admin → Health → Auth → Logging → FastMCP
- OpenBao embedded (localhost:8200, file backend, XChaCha20-Poly1305)
- Token Store S3 avec cache TTL 5 min
- Policy Store S3 avec cache TTL 5 min
- Audit Store double persistance (mémoire + JSONL)

### Documentation
- ARCHITECTURE.md v0.2.2-draft : spécification complète
- TECHNICAL.md v0.2.0 : 14 modules source documentés
- scripts/README.md : guide CLI complet
