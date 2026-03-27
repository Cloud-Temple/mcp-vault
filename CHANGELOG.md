# Changelog — MCP Vault

## [0.4.6] — 2026-03-26

### Bugfix — Suppression de `disable_mlock` (crash OpenBao au démarrage)

OpenBao ≥2.0 a supprimé le support du paramètre `disable_mlock` ([RFC mlock-removal](https://openbao.org/docs/rfcs/mlock-removal/)). Sa présence dans la config HCL générée provoquait un crash systématique au démarrage : `error loading configuration from /openbao/config/server.hcl: OpenBao has dropped support for mlock`.

#### Correctif

- **`src/mcp_vault/openbao/config.py`** : suppression totale de la ligne `disable_mlock = false` et du commentaire associé dans `HCL_TEMPLATE`. La protection mémoire est désormais gérée au niveau OS (swap désactivé dans le conteneur Docker).

#### Tests

- **`tests/test_integration.py`** : assertion mise à jour — vérifie que `disable_mlock` n'apparaît **plus** dans la config HCL générée (`assert "disable_mlock" not in content`).

#### Documentation mise à jour (5 fichiers)

- `DESIGN/mcp-vault/TECHNICAL.md` — exemple HCL §3.13 nettoyé, description config.py mise à jour
- `DESIGN/mcp-vault/ARCHITECTURE.md` — exemple HCL §4.5 nettoyé
- `DESIGN/mcp-vault/SECURITY_AUDIT.md` — V3-05 mis à jour (remédiation finale v0.4.6, lien RFC)

#### Fichiers modifiés (6)
- `src/mcp_vault/openbao/config.py` — suppression `disable_mlock`
- `tests/test_integration.py` — assertion inversée
- `DESIGN/mcp-vault/TECHNICAL.md` — doc HCL + description
- `DESIGN/mcp-vault/ARCHITECTURE.md` — doc HCL
- `DESIGN/mcp-vault/SECURITY_AUDIT.md` — V3-05 mise à jour
- `VERSION` — 0.4.5 → 0.4.6

---

## [0.4.5] — 2026-03-26

### Security — Hardening P2 : 8 correctifs de durcissement

Suite à l'audit de sécurité V2.1 (60 findings), après la remédiation P0 (4 élevés) et P1 (9 moyens) de la v0.4.0, cette release applique les **8 correctifs P2 (hardening)** restants.

#### 🟡 Corrections moyennes et durcissement (8)

- **V2-12 — Docker images pinnées par digest** (`Dockerfile`, `waf/Dockerfile`) : toutes les images base (python:3.12-slim, alpine:3.20, caddy:2-builder, caddy:2-alpine) sont désormais pinnées par SHA256 digest au lieu de tags mutables, protégeant contre les attaques supply chain par remplacement d'image.

- **V2-16 — Plugins Caddy pinnés en version** (`waf/Dockerfile`) : `coraza-caddy/v2@v2.2.0` et `caddy-ratelimit@v0.1.0` sont désormais pinnés en version exacte dans le build xcaddy, empêchant l'intégration silencieuse de versions non testées.

- **V3-08 — Lock file Python** (`requirements.lock`, nouveau) : fichier de dépendances avec versions exactes (`==`) généré depuis l'image Docker de production. Garantit des builds reproductibles et protège contre le typosquatting et le version hijacking.

- **V3-04 — AES-GCM AAD** (`openbao/crypto.py`) : ajout d'Associated Authenticated Data (`mcp-vault:unseal-keys:v1`) dans le chiffrement AES-256-GCM des clés unseal. Empêche la réutilisation d'un blob chiffré dans un contexte différent. Migration backward-compatible : le déchiffrement tente d'abord avec AAD, puis fallback sans AAD pour les données pré-v0.4.5.

- **V2-13 — HSTS** (`waf/Caddyfile`) : ajout du header `Strict-Transport-Security: max-age=31536000; includeSubDomains` pour forcer HTTPS sur tous les sous-domaines en production.

- **P2-6 — CORS preflight restrictif** (`waf/Caddyfile`) : les requêtes OPTIONS sont désormais gérées explicitement par le WAF avec des méthodes et headers restreints, sans `Access-Control-Allow-Origin` (bloque toute origine cross-origin).

- **P2-7 — Docker hardening** (`docker-compose.yml`) : ajout de `security_opt: [no-new-privileges:true]` sur tous les services, `read_only: true` pour le WAF avec tmpfs pour les chemins writable, et `tmpfs: /tmp` pour mcp-vault.

- **P2-8 — Tests hors image production** (`Dockerfile`, `docker-compose.yml`) : l'image production ne contient plus `tests/` ni `scripts/`. Un stage Docker dédié `test` (stage 3) est utilisé pour les tests d'intégration, réduisant la surface d'attaque de l'image de production.

#### 🧪 Tests

- **18/18 tests crypto** passent (16 existants + 2 nouveaux AAD : `test_aad_legacy_fallback`, `test_aad_context_binding`)
- Tests e2e : validation post-build requise (docker compose)

### Documentation

- **SECURITY_AUDIT.md réécrit** : consolidation des 3 audits (v0.2.0, v0.3.3, V2.1 externe) en un document unique avec V2.1 comme source de vérité. 60 findings cross-référencés : 28 corrigés, 13 résiduels documentés avec justification, 18 informationnels. Statuts vérifiés dans le code source.
- **README.md mis à jour** : version 0.4.5, tests 312/15 catégories, table docs enrichie (SECURITY_AUDIT.md), roadmap sécurité corrigée, structure projet avec requirements.lock.
- **TECHNICAL.md mis à jour** : header v0.4.5, statut Production-ready, suppression fallback `?token=`, correction `disable_mlock=false`, référence audit V2.1, roadmap enrichie (Phase 8e, 9, 10).
- **requirements.lock nettoyé** : suppression des dépendances de test (pytest, pytest-asyncio) — production-only conformément au stage Docker séparé (P2-8).

### Risques résiduels documentés (non corrigés)

- **CSP unsafe-inline** (§5.2) : le SPA admin utilise des scripts inline — refonte avec nonces/hashes CSP planifiée mais reportée (effort significatif).
- **Race conditions S3** (§5.4) : last-writer-wins en single-instance — risque faible, asyncio.Lock reporté.
- **Clés str en mémoire** (§5.5) : limitation fondamentale Python — les strings sont immuables et non-effaçables.

### Fichiers modifiés (8)
- `Dockerfile` — V2-12 (digests), P2-8 (stage test séparé), version label 0.4.5
- `waf/Dockerfile` — V2-12 (digests), V2-16 (plugins pinnés)
- `waf/Caddyfile` — V2-13 (HSTS), P2-6 (CORS preflight)
- `docker-compose.yml` — P2-7 (hardening), P2-8 (target stages)
- `src/mcp_vault/openbao/crypto.py` — V3-04 (AAD)
- `tests/test_crypto.py` — 2 tests AAD ajoutés (18 total)
- `requirements.lock` — **nouveau** (V3-08)
- `VERSION` — 0.4.0 → 0.4.5

---

## [0.4.0] — 2026-03-24

### Security — Audit complet v0.3.3 et correctifs majeurs

Suite à un **audit de sécurité complet** (19 fichiers analysés, 18 vulnérabilités identifiées), 7 correctifs de sécurité sont appliqués dans cette release majeure.

Rapport complet : [SECURITY_AUDIT.md](DESIGN/mcp-vault/SECURITY_AUDIT.md)

#### 🔴 Corrections critiques (3)

- **Admin API bypass des contrôles d'accès vault** (`admin/api.py`) : les routes `/admin/api/vaults/{id}`, `/admin/api/vaults/{id}/secrets/*` et `/admin/api/vaults/{id}/ssh/*` ne vérifiaient pas `check_access()`. Un token non-admin pouvait accéder à **tous** les vaults via l'API admin, contournant l'isolation owner-based et `allowed_resources`. Corrigé avec `_check_vault_access()` appliqué sur les 3 groupes de routes (vault detail, SSH CA, secrets).

- **Timing attack sur la bootstrap key** (`auth/middleware.py`, `admin/api.py`) : la comparaison `==` de la bootstrap key n'était pas constant-time. Remplacée par `hmac.compare_digest()` dans les 3 occurrences.

- **Path traversal via tarfile** (`s3_sync.py`) : `tar.extractall()` sans filtre permettait l'écriture de fichiers arbitraires via une archive S3 malveillante (CVE-2007-4559). Corrigé avec `filter='data'` (Python 3.12+).

#### 🟠 Corrections élevées (4)

- **CORS wildcard supprimé** (`admin/api.py`) : le header `Access-Control-Allow-Origin: *` a été retiré de toutes les réponses API admin. Les requêtes cross-origin depuis des domaines tiers sont désormais bloquées.

- **Fail-close sur policies supprimées** (`auth/policies.py`) : `is_tool_allowed()` retournait `True` si la policy référencée n'existait plus (fail-open). Désormais retourne `False` (fail-close) — un token dont la policy a été supprimée est bloqué.

- **Limite de taille du body HTTP** (`admin/api.py`) : `_read_body()` est désormais plafonné à 10 MB pour prévenir les attaques OOM (Out Of Memory).

- **Validation vault_id** (`vault/spaces.py`) : ajout de la validation du format vault_id (alphanumérique + tirets, 1-64 chars) avant passage à OpenBao, bloquant les injections de mount path.

- **Rate limiting WAF** (`waf/Caddyfile`) : ajout du plugin `caddy-rate-limit` avec limitation à 100 req/s par IP sur tous les endpoints. Protection contre le brute-force et le DoS applicatif.

#### 🟡 Corrections moyennes

- **Docker resource limits** (`docker-compose.yml`) : ajout de `mem_limit: 2g` et `cpus: 2.0` pour les services mcp-vault et waf.

### Fichiers modifiés (8)
- `src/mcp_vault/admin/api.py` — C1 (vault access), C2 (timing), E1 (CORS), E4 (body limit)
- `src/mcp_vault/auth/middleware.py` — C2 (timing attack)
- `src/mcp_vault/auth/policies.py` — E3 (fail-close)
- `src/mcp_vault/s3_sync.py` — C3 (tarfile filter)
- `src/mcp_vault/vault/spaces.py` — M1 (vault_id validation)
- `waf/Caddyfile` — E2 (rate limiting)
- `docker-compose.yml` — M3 (resource limits)
- `DESIGN/mcp-vault/SECURITY_AUDIT.md` — rapport complet v0.3.3

---

## [0.3.3] — 2026-03-23

### Documentation WAF complète (ARCHITECTURE.md §11.6)

Ajout de 9 sous-sections documentant en détail l'architecture du WAF Coraza :
- Architecture (Caddy v2.11.2 + coraza-caddy v2.2.0 + CRS v4.7.0), build multi-stage
- 19 règles CRS chargées (tableau complet REQUEST + RESPONSE)
- Mode anomaly scoring (fonctionnement, seuil de blocage)
- 4 exclusions ciblées documentées (920540 Unicode, 932120 PowerShell) avec motifs et risques
- Headers de sécurité (CSP, X-Frame-Options, nosniff...) avec valeurs et justifications
- Configuration réseau et timeouts
- Procédure de diagnostic pas-à-pas pour identifier et résoudre les faux positifs WAF

### Tests e2e WAF dédiés (TEST 15 — `--test waf_security`)

Nouveau groupe de tests (17 assertions) validant le WAF Coraza en mode blocking :
- **LFI** : 3 attaques path traversal → 403
- **SQLi** : 3 injections SQL → 403
- **XSS** : 2 cross-site scripting → 403
- **RCE** : 3 remote code execution → 403
- **Scanner** : 2 détections (Nikto, sqlmap) → 403
- **Non-régression** : 4 requêtes légitimes (health, MCP, Unicode, test-path) → 200
- Auto-skip si MCP_URL pointe vers `:8030` (sans WAF)

### Métriques

- **312/312 tests e2e** via WAF (15 catégories, ~15s)
- **197 tests CLI** inchangés
- **16 tests crypto** inchangés

### Fichiers modifiés (3)
- `DESIGN/mcp-vault/ARCHITECTURE.md` — section §11.6 WAF (9 sous-sections)
- `tests/test_e2e.py` — TEST 15 waf_security (17 assertions)
- `VERSION` — 0.3.2 → 0.3.3

---

## [0.3.2] — 2026-03-23

### WAF — Mode Blocking complet

Le WAF Coraza passe de **DetectionOnly** à **Blocking complet** sur tous les endpoints, y compris `/mcp` (JSON-RPC) et `/admin/api` (REST). Toutes les requêtes sont désormais inspectées et bloquées si elles dépassent le seuil d'anomalie CRS.

#### Fine-tuning des règles OWASP CRS

Méthodologie : suppression du mode DetectionOnly → exécution des 295 tests e2e → analyse des logs Coraza → exclusions chirurgicales.

- **230/262 tests** passaient sans aucune exclusion (88% de compatibilité native)
- **2 faux positifs identifiés** via les logs Coraza (`docker-compose logs waf`) :

| Règle CRS | Description | Cause du faux positif |
|-----------|-------------|----------------------|
| **920540** | Unicode character bypass | Les descriptions françaises en JSON contiennent `\u00e9`, `\u00e8`, `\u2014` — encodage Unicode standard |
| **932120** | Windows PowerShell RCE | Le policy_id `test-path-restrict` contient `test-path` → matche le cmdlet PowerShell `Test-Path` |

- **Exclusions ciblées** (SecRule id:10001-10004) : `ruleRemoveById` pour les 2 règles, **uniquement** sur `/mcp` et `/admin/api`. Les chemins publics (`/health`, `/admin/static`) gardent la protection complète.

#### Vérification post-tuning

- ✅ **295/295 tests e2e** passent en mode blocking complet
- ✅ **LFI** (`../../etc/passwd`) → 403
- ✅ **SQLi** (`OR 1=1`) → 403
- ✅ **XSS** (`<script>alert(1)</script>`) → 403
- ✅ **RCE** (`test-path` sur `/health`) → 403 (exclusion active uniquement sur les APIs)
- ✅ Trafic MCP légitime → 200/202

### Alignement `/health` sur le standard MCP Cloud Temple

Le endpoint `/health` retourne désormais le même format que Live Memory et MCP Tools :

```json
{"status": "healthy", "service": "mcp-vault", "version": "0.3.2", "transport": "streamable-http"}
```

Alignement avec :
- Live Memory : `{"status": "healthy", "service": "live-memory", "version": "0.9.0", "transport": "streamable-http"}`
- MCP Tools : `{"status": "healthy", "service": "mcp-tools", "version": "0.1.8", "transport": "streamable-http"}`

### Fichiers modifiés (3)
- `waf/coraza.conf` — mode Blocking complet + 4 exclusions documentées (suppression DetectionOnly)
- `src/mcp_vault/auth/middleware.py` — nouvelle méthode `_health_response()` dans `HealthCheckMiddleware`
- `VERSION` — 0.3.1 → 0.3.2

---

## [0.3.1] — 2026-03-23

### Security — Audit & Correctifs critiques

Suite à un **audit de sécurité complet** ([SECURITY_AUDIT.md](DESIGN/mcp-vault/SECURITY_AUDIT.md)), 5 vulnérabilités ont été identifiées et corrigées dans cette release.

#### 🔴 Corrections critiques

- **Arbitrary File Read (LFI)** dans `admin/middleware.py` : la route `/admin/static/` permettait de lire n'importe quel fichier du système via un chemin absolu (ex: `/admin/static//etc/passwd`). Corrigé avec `Path.resolve()` + vérification de parenté avec `static_dir` + rejet des chemins absolus et `..`.

- **WAF Coraza réel** : le Dockerfile WAF utilisait `caddy:2-alpine` brut sans Coraza. Reconstruit avec un **build multi-stage** :
  - Stage 1 : compilation Caddy + `coraza-caddy v2.2.0` via `xcaddy`
  - Stage 2 : téléchargement **OWASP CoreRuleSet v4.7.0** (24 fichiers de règles)
  - Stage 3 : image Alpine minimale avec config Coraza
  - Nouveau fichier `waf/coraza.conf` avec stratégie WAF documentée
  - Mode **Blocking** pour les chemins non-authentifiés
  - Mode **DetectionOnly** pour les APIs authentifiées (`/mcp`, `/admin/api`)
  - Headers de sécurité : CSP, X-Frame-Options DENY, X-XSS-Protection, nosniff

#### 🟠 Corrections moyennes

- **Auth par query string supprimée** : le fallback `?token=` dans `auth/middleware.py` a été supprimé. Seul le header `Authorization: Bearer <token>` est désormais accepté, éliminant le risque de fuite de tokens dans les logs HTTP, proxies et historiques navigateur.

- **Validation de l'entropie de la bootstrap key** : nouvelle fonction `validate_bootstrap_key()` dans `crypto.py` avec vérification au démarrage dans `lifecycle.py`. Exigences : ≥32 caractères, 3+ classes de caractères (majuscules, minuscules, chiffres, symboles), détection de la valeur par défaut et des patterns faibles (répétitions).

- **Zeroing mémoire des clés dérivées** : `_derive_key()` retourne un `bytearray` (mutable) au lieu de `bytes`. Nouvelle fonction `_zero_fill()` efface les clés dans les blocs `finally` après chaque opération crypto, limitant la fenêtre d'exposition en RAM.

### Tests

- **295/295 tests e2e** passent (dans le conteneur et via le WAF)
- **16/16 tests crypto** (anciennement 9) — 7 nouveaux tests de sécurité :
  - `validate_bootstrap_key` (clés valides, défaut rejeté, trop courte, faible diversité, répétitive)
  - `_zero_fill` (effacement mémoire)
  - `_derive_key` (retourne bytearray)
- **197/197 tests CLI** — zéro régression

### Fichiers modifiés (8)
- `src/mcp_vault/admin/middleware.py` — fix LFI (resolve + parenté)
- `src/mcp_vault/auth/middleware.py` — suppression `?token=`
- `src/mcp_vault/openbao/crypto.py` — validate_bootstrap_key, bytearray, _zero_fill
- `src/mcp_vault/lifecycle.py` — validation bootstrap key au startup
- `waf/Dockerfile` — multi-stage xcaddy + CRS v4.7.0
- `waf/Caddyfile` — `order coraza_waf first`, headers CSP, admin off
- `waf/coraza.conf` — **nouveau** (config Coraza + CRS + exceptions MCP)
- `tests/test_crypto.py` — 16 tests (7 nouveaux)

---

## [0.3.0] — 2026-03-23

### Console Admin SPA — Parité complète avec le CLI

La console web `/admin` atteint la **parité fonctionnelle totale** avec le CLI. Chaque fonctionnalité testée dans `tests/cli/` est désormais accessible visuellement dans l'interface web.

#### Nouvel onglet Policies (CRUD complet)
- **Liste des policies** : tableau avec colonnes (ID, Description, Mode allow/deny, Outils, Path Rules)
- **Détail d'une policy** : panneau avec outils autorisés/refusés, `path_rules` avec patterns `fnmatch` formatés
- **Création de policy** : modal guidé avec mode allow/deny, checkboxes des outils MCP catégorisés (Système, Vaults, Secrets, SSH CA, Policies, Tokens, Audit), ajout dynamique de règles de chemin
- **Suppression** avec confirmation
- Nouveau fichier : `static/js/policies.js`

#### SSH CA dans la SPA (5 opérations)
- **Setup SSH CA** : modal pour créer une CA + rôle (nom, utilisateur par défaut, TTL, utilisateurs autorisés)
- **Signer une clé SSH** : modal pour coller une clé publique et recevoir le certificat signé avec bouton copier
- **Clé publique CA** : affichage inline avec bouton copier et instructions serveur
- **Liste des rôles** : section dans le détail vault avec détail au clic (key_type, TTL, users)
- **5 nouveaux endpoints admin API** : `POST .../ssh/setup`, `POST .../ssh/sign`, `GET .../ssh/ca-key`, `GET .../ssh/roles`, `GET .../ssh/roles/{name}`

#### Tokens enrichis
- **Colonne Policy** dans le tableau des tokens (badge cliquable → navigation vers la policy)
- **Select `policy_id` dynamique** dans les modals de création et édition (chargé depuis l'API)
- Envoi du `policy_id` à la création du token
- Indication `owner` quand les vaults autorisés sont vides

#### Vaults enrichis
- **Vue tableau** avec 5 colonnes : Vault, Description, Secrets, Owner, Créé le
- **Badges Owner** : 👤 vert = propriétaire, 👥 bleu = partagé
- **Section SSH CA** dans le détail vault avec boutons setup, signer, clé CA

#### Dashboard enrichi
- **Compteur Policies** (admin) + cards cliquables vers les pages correspondantes
- **Générateur de mot de passe standalone** : CSPRNG 24 caractères avec bouton copier
- **Référence des 14 types de secrets** : grille avec champs requis/optionnels par type

#### UX Guidance
- **Tooltips ⓘ** sur tous les champs sensibles (permissions, vaults autorisés, policy, path_rules)
- **Help-text** sous chaque champ (ex: "Vide = accès uniquement aux vaults créés par ce token")
- **Descriptions des permissions** au survol (read/write/admin)
- **Aide contextuelle** pour les patterns fnmatch dans les path_rules

### Bug fixes
- **CORS middleware** : ajout de `PUT` dans `access-control-allow-methods` (manquait pour token update cross-origin)
- **Routage API** : fix du matching vault detail vs SSH routes (`/ssh/` exclu du routage vault)

### Fichiers modifiés (10)
- `static/js/policies.js` (nouveau — 310 lignes)
- `static/admin.html` (3 modals ajoutés, champs enrichis)
- `static/js/app.js` (sidebar + navigation policies)
- `static/js/tokens.js` (colonne Policy, select dynamique)
- `static/js/vaults.js` (tableau Owner, section SSH CA, 7 nouvelles fonctions)
- `static/js/dashboard.js` (compteur policies, générateur MdP, référence types)
- `static/css/admin.css` (styles help, tooltips, tools checklist, path rules)
- `admin/api.py` (5 endpoints SSH CA + fix routage)
- `admin/middleware.py` (CORS PUT)
- `VERSION` (0.2.0 → 0.3.0)

### Bilan SPA
- **25+ endpoints admin API** (Système 5, Vaults 5, Secrets 4, SSH CA 5, Policies 4, Tokens 4)
- **11 fichiers JS** (config, api, app, dashboard, vaults, tokens, policies, activity)
- **7 modals** (vault, secret, token create, token edit, policy, SSH setup, SSH sign)
- **Parité CLI 100%** : chaque commande testée dans `tests/cli/` a son équivalent SPA

---

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
