# Documentation Technique — MCP Vault

> **Version** : 0.17.0 | **Date** : 2026-08-19 | **Auteur** : Cloud Temple
> **Licence** : Apache 2.0 | **Statut** : ✅ Production-ready (audit V2.1 complété + PKI interne v0.5.1)

---

## 1. Vue d'ensemble

MCP Vault est un serveur MCP (Model Context Protocol) qui fournit une gestion sécurisée des secrets pour les agents IA. Il embarque **OpenBao 2.5.1** (fork open-source de HashiCorp Vault, Linux Foundation) comme moteur de chiffrement et de stockage de secrets.

### Principes fondamentaux

1. **OpenBao embedded** — Le binaire OpenBao tourne comme processus intégré dans le conteneur Docker, pas comme un service séparé
2. **File backend + S3 sync** — Les données sont stockées localement (file backend) et synchronisées périodiquement avec S3 (source de vérité froide)
3. **Types de secrets style 1Password** — 14 types prédéfinis avec validation des champs
4. **Même pattern que Live Memory** — Bearer tokens, `vault_ids`, `check_access()`, starter-kit Cloud Temple
5. **Les tests e2e sont réels** — S3 Dell ECS, Docker, OpenBao, sans double.
   ⚠️ La suite UNITAIRE, elle, mocke délibérément S3, `hvac` et les magasins
   (`tests/conftest.py`, `tests/doubles_magasins.py`) : elle ne doit dépendre
   ni d'un binaire OpenBao ni d'un réseau. Annoncer « zéro mocking » pour
   l'ensemble était faux.

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
│  │ Stack ASGI (6 couches)                                   │  │
│  │                                                          │  │
│  │  PkiMiddleware      → /acme/*, /pki/ca/*.pem (no-auth)   │  │
│  │  AdminMiddleware    → /admin, /admin/api/*               │  │
│  │  HealthCheckMiddleware → /health, /healthz, /ready       │  │
│  │  AuthMiddleware     → Bearer token → contextvars         │  │
│  │  LoggingMiddleware  → stderr + ring buffer (200 entrées) │  │
│  │  FastMCP            → /mcp (Streamable HTTP, 39 outils)  │  │
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

Les requêtes traversent 6 couches middleware dans cet ordre :

| #   | Middleware              | Rôle                                  | Routes interceptées             |
| --- | ----------------------- | ------------------------------------- | ------------------------------- |
| 0   | `PkiMiddleware`         | Proxy non-auth ACME + distribution CA | `/acme/*`, `/pki/ca/*.pem`      |
| 1   | `AdminMiddleware`       | Console admin web + API REST          | `/admin`, `/admin/api/*`        |
| 2   | `HealthCheckMiddleware` | Liveness 200 / disponibilité 200-503  | `/health`, `/healthz`, `/ready` |
| 3   | `AuthMiddleware`        | Extraction et validation Bearer token | Toutes sauf publiques           |
| 4   | `LoggingMiddleware`     | Log stderr + ring buffer mémoire      | Toutes les requêtes HTTP        |
| 5   | `FastMCP`               | Outils MCP via Streamable HTTP        | `/mcp`                          |

`PkiMiddleware` (v0.5.0) est la couche la plus externe — intercepte avant l'auth. Les endpoints `/acme/*` et `/pki/ca/*.pem` sont délibérément non-authentifiés (standard PKI/ACME). Sécurité : anti-traversal path, validation query string, `follow_redirects=False`.

---

## 3. Modules source

### 3.1 `config.py` — Configuration

Utilise `pydantic-settings` pour charger la configuration depuis les variables d'environnement ou le fichier `.env`.

> **Source unique du contrat** : [`.env.example`](../../.env.example) déclare les
> **41** champs de `Settings`, un par un, avec leur défaut. Le tableau ci-dessous
> en documente les principaux ; il n'est pas exhaustif et ne doit pas servir à
> composer un `.env`. `Settings` est en `extra="forbid"` : une clé inconnue portant
> une valeur non vide fait échouer le démarrage. La correspondance exacte entre ce
> contrat et les champs de `Settings` est verrouillée par
> [`tests/test_env_example_contract.py`](../../tests/test_env_example_contract.py).

| Variable                 | Défaut                    | Description                 |
| ------------------------ | ------------------------- | --------------------------- |
| `MCP_SERVER_NAME`        | `mcp-vault`               | Nom du service              |
| `MCP_SERVER_HOST`        | `0.0.0.0`                 | Interface d'écoute          |
| `MCP_SERVER_PORT`        | `8030`                    | Port d'écoute               |
| `MCP_SERVER_DEBUG`       | `false`                   | Niveau de log ASGI : `false` → `info`, `true` → `debug` |
| `MCP_ALLOWED_HOSTS`      | 2 FQDN Cloud Temple       | FQDN publics autorisés pour le header `Host` sur `/mcp` (anti-DNS-rebinding). Obligatoire derrière un reverse-proxy, sinon HTTP 421 (issue #3). Le loopback est toujours autorisé en plus |
| `MCP_ALLOWED_ORIGINS`    | *(vide)*                  | Origins HTTP supplémentaires ; `https://<fqdn>` est déjà dérivé de chaque FQDN ci-dessus |
| `WAF_PORT`               | `8085`                    | Port externe du WAF Caddy+Coraza. Champ de compatibilité : partagé avec `docker-compose.yml`, déclaré dans `Settings` uniquement pour que le `.env` mutualisé ne soit pas rejeté par `extra="forbid"` |
| `ADMIN_BOOTSTRAP_KEY`    | *aucun défaut utilisable* | Clé admin initiale + chiffrement des clés unseal. `.env.example` porte le marqueur `REQUIRED` : le serveur refuse de démarrer tant qu'il n'est pas substitué (le défaut interne `change_me_in_production` est explicitement rejeté) |
| `SSH_OPERATOR_PROFILES_JSON` | *(vide)* | Profils JIT opérateur ; vide = fonctionnalité désactivée |
| `SSH_OPERATOR_PROFILES_B64` | *(vide)* | Même JSON en Base64 URL-safe pour renderer `.env` strict ; exclusif du JSON direct |
| `SSH_OPERATOR_JIT_MAX_CONFIG_CHARS` | `65536` | Taille maximale de la source encodée et du JSON décodé |
| `SSH_OPERATOR_JIT_MIN_TTL_SECONDS` | `60` | TTL minimal accepté dans un profil opérateur |
| `SSH_OPERATOR_JIT_MAX_TTL_SECONDS` | `900` | TTL maximal accepté dans un profil opérateur |
| `SSH_OPERATOR_JIT_MAX_REASON_CHARS` | `512` | Taille maximale du motif opérateur |
| `SSH_OPERATOR_JIT_MAX_PUBLIC_KEY_CHARS` | `16384` | Taille maximale de la clé publique reçue |
| `SSH_OPERATOR_JIT_MAX_PROFILES` | `32` | Nombre maximal de profils configurés |
| `SSH_OPERATOR_JIT_MAX_BEARER_EXPIRES_DAYS` | `1` | Plafond de durée de vie restante du bearer pour être utilisable sur ce parcours ; refusé si absent ou dépassé |
| `S3_ENDPOINT_URL`        | *(vide)*                  | Endpoint S3 Dell ECS        |
| `S3_ACCESS_KEY_ID`       | *(vide)*                  | Access key S3               |
| `S3_SECRET_ACCESS_KEY`   | *(vide)*                  | Secret key S3               |
| `S3_BUCKET_NAME`         | *(vide)*                  | Nom du bucket S3            |
| `S3_CONNECT_TIMEOUT`     | `5`                       | Plafond de connexion S3 (s) — issue #110 |
| `S3_READ_TIMEOUT`        | `30`                      | Plafond d'inactivité socket S3 (s) — pas une durée totale de transfert |
| `S3_MAX_ATTEMPTS`        | `2`                       | Nombre TOTAL de tentatives S3 (`total_max_attempts`, 1 = aucun retry) |
| `UVICORN_GRACEFUL_TIMEOUT` | `10`                    | Plafond du pré-drain des connexions à l'arrêt (s) — issue #110 |
| `S3_REGION_NAME`         | `fr1`                     | Région S3                   |
| `OPENBAO_ADDR`           | `http://127.0.0.1:8200`   | Adresse OpenBao             |
| `OPENBAO_SHARES`         | `1`                       | Nombre de parts Shamir      |
| `OPENBAO_THRESHOLD`      | `1`                       | Seuil de déverrouillage     |
| `OPENBAO_DATA_DIR`       | `/openbao/file`           | Répertoire file backend     |
| `OPENBAO_CONFIG_DIR`     | `/openbao/config`         | Répertoire config HCL       |
| `VAULT_S3_PREFIX`        | `_storage`                | Préfixe S3 pour le sync     |
| `VAULT_S3_SYNC_INTERVAL` | `60`                      | Intervalle sync en secondes |
| `PKI_BASE_URL`           | *(vide)*                  | Override URL base PKI (ACME directory, CDPs). Utile en test Docker : `http://mcp-vault:8030`. Doit être http(s)://. |
| `MCP_AUTH_MODE`          | `bearer`                  | PEP mission JWT porte /mcp (#47). `bearer` = bearer valide **exigé** — sans jeton ou jeton invalide, 401 au middleware (#116). `bearer-anonymous` = ⚠️ mode d'exception, ancien comportement (appelant anonyme accepté), CRITICAL au démarrage. `jwt` = mission_token obligatoire. `dual-stack` = JWT valide OU bearer (migration). `jwt`/`dual-stack` exigent `MISSION_JWKS_URL` + `MCP_INSTANCE_ID` + `ENFORCE_MISSION_TOKEN_VALIDATION=true` + `MISSION_STATUS_URL` (fail-fast au boot, #86). |
| `MCP_INSTANCE_ID`        | *(vide)*                  | Identifiant d'instance de CE vault : doit figurer dans `aud` du mission_token ET valoir `component_id[MCP_COMPONENT_KIND]`. Source unique d'audience (`resolved_mission_aud`) — remplace `MISSION_TOKEN_AUD` (alias legacy ; divergence des deux = fail-fast boot). |
| `MCP_COMPONENT_KIND`     | `vault`                   | Clé de `component_id` vérifiée (`component_id[kind] == MCP_INSTANCE_ID`). |
| `ENFORCE_MISSION_TOKEN_VALIDATION` | `false` | `true` = hard-reject JWT dans secret_consume. `false` = log warning, continue (standalone compatible). Obligatoire dès `MCP_AUTH_MODE` ∈ {`jwt`, `dual-stack`} (fail-fast, #86 ; cf. `Settings.mission_pep_active`, #116) — sinon secret_consume resterait permissif malgré le PEP actif. Active seul (mode bearer), requiert aussi `MISSION_JWKS_URL`/audience/`MISSION_STATUS_URL`. **Depuis #78, ce mode durcit AUSSI le binding aux deux bouts** : `secret_wrap` refuse la création sans `tenant_id` (`binding_incomplete` — aucune source serveur ne peut le déduire ; une audience blanche est en revanche traitée comme absente et enrichie), et `secret_consume` refuse une entrée dont `tenant_id` OU `expected_aud` manque, AVANT tout appel à OpenBao (le wrap n'est donc pas brûlé). Voir aussi l'état terminal `empty_secret` : une réponse d'unwrap sans paire exploitable (`data.data` vide ou non-dict) est marquée `consumed` et non réessayable — la garde précédente testait l'enveloppe externe, toujours non vide, et était donc morte en production. Depuis le Lot 2 (#86), le validateur applique le contrat PEP complet (exp/iat/iss/aud/mission_id/jti/scope/tenant_id + `component_id`) ; audience vide = rejet explicite `misconfigured`, plus de mode permissif silencieux. |
| `MISSION_JWKS_URL`       | *(vide)*                  | JWKS public mcp-mission (`/.well-known/jwks.json`). Vide = validation désactivée. Requis dès que la validation mission_token est active (PEP ou `ENFORCE_MISSION_TOKEN_VALIDATION=true` seul). |
| `MISSION_TOKEN_AUD`      | *(vide)*                  | Audience attendue dans le JWT (anti-confused-deputy). Ex : `mcp-vault:prod:v1`. |
| `MISSION_JWKS_CACHE_TTL` | `60`                      | TTL cache JWKS en secondes. ⚠️ **Ce n'est pas un réglage de latence** : une clé révoquée DISPARAÎT du JWKS de `mcp-mission`, donc ce TTL est la **fenêtre de propagation d'une révocation de clé de signature**. Borné à `[10,60]`s dès que la validation mission est active — fail-fast au boot (#86). Trop grand : une clé révoquée reste acceptée ; nul ou négatif : un fetch par validation, donc amplification sur un endpoint mono-instance. |
| `MISSION_JWKS_MAX_REFRESH_PER_MIN` | `3`             | ⚠️ **SANS EFFET (#86)** — accepté puis ignoré par le validateur. La protection réelle du refresh JWKS est le throttle « kid inconnu » (10 s) + le backoff exponentiel + le déport hors boucle (#148). Conservé car le modèle refuse les variables inconnues — le retirer ferait échouer le démarrage des déploiements qui le posent ; avertissement au boot. |
| `MISSION_TOKEN_LEEWAY_SECONDS` | `10`                | Tolérance clock skew JWT en secondes — s'applique UNIQUEMENT à `iat` (anti-skew futur). `exp` est TOUJOURS strict (leeway=0), y compris pour secret_consume depuis le Lot 2 (#86). |
| `MISSION_STATUS_URL`     | *(vide)*                  | Template URL statut mission mcp-mission — **doit contenir littéralement `{mission_id}`** (fail-fast sinon, #86 : une URL statique validerait silencieusement n'importe quelle mission). Allow-list d'états actifs `{RUNNING, WAITING_HUMAN, PAUSED}` (fail-close : état inconnu = inactif). Requis dès que la validation mission_token est active (PEP ou `ENFORCE_MISSION_TOKEN_VALIDATION=true` seul) — fail-fast au boot (#86, remplace l'ancien mode dégradé signalé par un simple warning). |
| `MISSION_STATUS_CACHE_TTL` | `5`                     | TTL cache statut mission en secondes (court — fail-close rapide). Borné à `[0,30]`s dès que `MISSION_STATUS_URL` est requis (0 = pas de cache) — fail-fast au boot (#86). |

**Variables CLI (NE PAS stocker dans `.env`)** :

| Variable | Description |
|----------|-------------|
| `VAULT_WRAP_TOKEN` | Token de déballage OpenBao pour `secret consume` (single-use). |
| `VAULT_MISSION_TOKEN` | JWT mission_token ES256 pour `secret consume` (TTL court). |

Ces variables changent à chaque opération — les exporter avant la commande ou passer inline :
```bash
VAULT_WRAP_TOKEN=hvs.CAES... VAULT_MISSION_TOKEN=eyJ... mcp-vault secret consume op-123
```

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
STARTUP:  download_from_s3() → extrait dans un STAGING interne à data_dir →
          promotion par renommages individuels (marqueur durable posé AVANT
          tout, retiré SEULEMENT après promotion intégrale) → /openbao/file/
          Retour à 3 états (RestoreResult) : RESTORED / CONFIRMED_ABSENT / FAILED.
          FAILED (erreur ambiguë : réseau, archive corrompue...) fait échouer
          vault_startup() — jamais traité comme une première exécution.
RUNTIME:  start_periodic_sync() → upload CONDITIONNEL (skip_if_unchanged=True),
          toutes les vault_s3_sync_interval secondes (défaut 60s)
SHUTDOWN: upload_to_s3() → tar.gz final, SAUF si le démarrage n'a pas abouti
          (vault_shutdown(skip_upload=not ok) — cf. ci-dessous)
CRASH:    Docker volume local conservé → fallback
```

**Format de transport** : `_storage/openbao-data.tar.gz` sur S3.

**Sync conditionnelle (fix incident versions S3, 2026-07)** : le bucket de
production a le versioning S3 activé sans lifecycle — un PUT inconditionnel
toutes les 60s produisait une version par cycle (6000+ versions, 600+ Mo en
quelques jours), même sans écriture OpenBao entre deux cycles. Durci en 4
passes de revue adversariale (1 plan + 3 diff, ces dernières exécutées dans un
worktree jetable où le reviewer a lui-même lancé la suite et ses propres
reproductions à chaque round) : 6 bloquants trouvés en revue de plan, 5
bloquants supplémentaires trouvés en revue de diff (TOCTOU intra-entrée,
restauration extraite hors de data_dir, promotion non transactionnelle, purge
manquante sur absence confirmée consécutive à une promotion partielle — 3
rounds distincts sur la restauration, fail-closed contourné par l'upload
inconditionnel du shutdown) — tous corrigés ci-dessous.

`_snapshot_and_archive()` construit l'archive tar.gz ET une empreinte SHA-256 de
l'état source **dans la même passe**. Pour un fichier régulier, contenu ET
métadonnées archivés viennent du MÊME descripteur ouvert (`open()`+`fstat(fd)`+
`read()`), jamais d'un second stat par CHEMIN séparé — ferme la divergence
trouvée en revue de diff (une version intermédiaire combinait `lstat()` +
`tar.gettarinfo(chemin)` + `read_bytes()`, trois observations séparées capables
de diverger si l'entité changeait de type entre elles ; résidu assumé et non
exploitable avec l'usage réel du file backend OpenBao : la décision de
branchement fichier/répertoire/symlink repose sur un seul `lstat()` initial).
L'empreinte porte sur les chemins relatifs triés, le contenu (fichiers), le
type et la cible (symlinks), la présence (répertoires) — PAS sur le tar.gz
généré (mtime/permissions/métadonnées gzip varient sans changement métier).

`upload_to_s3(skip_if_unchanged: bool = False)` :
- Défaut `False` (comportement historique inchangé) pour TOUS les appelants
  existants : arrêt (`lifecycle.py`) et opérations PKI (`pki_ca.py`, "sync S3
  forcée"). Seule la boucle périodique (`_periodic_sync_tick`) passe `True`.
- Le PUT n'est sauté que si l'empreinte égale la référence **ET** qu'aucun échec
  ambigu n'est en attente (`_s3_state_uncertain`). La référence n'avance
  QU'APRÈS un PUT confirmé réussi — un échec (y compris un timeout après envoi,
  où l'objet a pu être écrit côté S3 malgré l'exception locale) la laisse
  inchangée et marque l'état incertain : le cycle suivant retente un vrai PUT,
  jamais un skip. La référence vit en mémoire process uniquement (jamais
  persistée) : un redémarrage force toujours un premier PUT réel.

`download_from_s3()` extrait dans un répertoire de staging **interne à
data_dir** (garanti même filesystem — le volume Docker est monté exactement
sur data_dir, pas sur son parent, un rename atomique entre les deux échouerait
avec `EXDEV`), puis promeut par renommages individuels UNIQUEMENT après une
extraction intégralement réussie. Sans ce staging, une extraction qui échoue
après avoir déjà écrit certains membres (archive corrompue, ou membre rejeté
par `filter='data'` après des membres valides) laissait ces membres dans
data_dir malgré l'échec global — le prochain démarrage les aurait pris pour
une donnée locale valide.

**La promotion elle-même N'EST PAS transactionnelle** (bloquant trouvé en
2e revue de diff) : chaque `rename()` est atomique unitairement, mais la
BOUCLE qui les enchaîne ne l'est pas — une erreur I/O ou un crash au milieu
laisse `data_dir` dans un état MIXTE (certaines entrées promues, d'autres
non), qu'aucun test de présence de fichiers ne peut distinguer d'une "vraie"
donnée locale. Fermé par un **marqueur durable** `_RESTORE_MARKER_FILENAME`,
posé AVANT tout nettoyage/extraction et retiré SEULEMENT après une promotion
INTÉGRALEMENT réussie, ou une absence confirmée **après purge de tout résidu
préexistant** (`_clear_data_dir_leftovers()`, helper partagé avec le nettoyage
pré-promotion — un round de revue ultérieur a montré qu'une absence confirmée
par S3 après une promotion partielle ratée ne rendait PAS ce résidu fiable :
lever le marqueur sans purger le laissait réapparaître comme donnée locale
« valide » au prochain calcul). `lifecycle.py::_check_local_data_status()`
traite la seule PRÉSENCE de ce marqueur comme autoritaire : `data_dir` n'est
jamais considéré fiable tant qu'il existe, quel que soit son contenu
physique — force une nouvelle tentative de restauration complète (qui nettoie
tout résidu avant de rejouer l'extraction+promotion, idempotent).

`vault_shutdown(skip_upload: bool = False)` : `server.py` calcule
`skip_upload=not ok` à partir du booléen déjà retourné par `vault_startup()`.
Sans cette garde, le fail-closed de restauration ci-dessus était cosmétique :
un `vault_startup()` en échec ne stoppe pas le processus (mode dégradé,
comportement préexistant de `server.py`, non modifié ici), et l'ancien upload
final inconditionnel à l'arrêt pouvait quand même écraser une sauvegarde S3
valide avec l'état local incomplet issu de ce démarrage raté.

### 3.4 `auth/context.py` — Gestion des droits

Utilise les `contextvars` Python pour injecter les infos du token sans dépendre du framework HTTP.

**Fonctions** :

| Fonction                    | Retour si OK      | Retour si refusé                        |
| --------------------------- | ----------------- | --------------------------------------- |
| `check_access(resource_id)` | `None`            | `{"status": "error", "message": "..."}` |
| `check_write_permission()`  | `None`            | `{"status": "error", "message": "..."}` |
| `check_admin_permission()`  | `None`            | `{"status": "error", "message": "..."}` |
| `check_wrap_permission()` *(#115)* | `None`     | `{"status": "error", ...}` — `wrap`/`admin` requis ; jeton `wrap` non-admin : allow-list + policy à `allowed_tools` explicites obligatoires (fail-close PolicyStore) |
| `check_wrap_path_policy(vault_id, path, audit=True)` *(#115)* | `None` | évaluation STRICTE des chemins (pas de règle = refus, `allowed_paths` vide = refus) |
| `enforce_wrap_only_token(tool)` *(#115)* | `None` | confinement d'un jeton wrap-only aux 4 outils du broker JIT |
| `get_current_client_name()` | `"nom-du-client"` | `"anonymous"`                           |

**Matrice de permissions** :

| Token                      | `check_access(own_vault)` | `check_access(other)` | `check_write`  | `check_admin` |
| -------------------------- | ------------------------- | --------------------- | -------------- | ------------- |
| Aucun                      | ❌                        | ❌                    | ❌             | ❌            |
| `read` + vaults restreints | ✅                        | ❌                    | ❌             | ❌            |
| `read` + vaults vides      | ✅ (owner-based)          | ❌ (sauf si owner)    | ❌             | ❌            |
| `read,write` + vaults      | ✅                        | ❌                    | ✅             | ❌            |
| `admin`                    | ✅                        | ✅                    | ✅ (implicite) | ✅            |

**Règles (v0.2.0 — owner-based isolation)** :
- `allowed_resources: []` (vide) → accès **uniquement** aux vaults dont `_vault_meta.created_by == client_name`
- `allowed_resources: ["a", "b"]` → accès **uniquement** à "a" et "b" (liste explicite)
- `admin` → accès à **tous** les vaults
- La comparaison est **case-sensitive** et **exacte** (pas de wildcard)
- `admin` implique `read` et `write`
- Si le vault n'existe pas encore (création) → accès autorisé
- Si le vault n'a pas de `_vault_meta` (legacy) → accès autorisé

**Owner-based isolation** :
Quand `allowed_resources` est vide (par défaut), `check_access()` vérifie la propriété
du vault via `check_vault_owner(vault_id, client_name)` dans `spaces.py`. Ce mécanisme
élimine le problème "vide = tous" qui permettait à un token d'accéder aux vaults créés par
d'autres tokens. La sémantique est désormais "vide = mes vaults".

**Durcissement canonicalisation `vault_id` (2026-07-23)** : un `vault_id` non canonique
(ex. slash final) faisait traiter `check_vault_owner()` comme "vault inexistant" → accès
autorisé (règle "si le vault n'existe pas encore → accès autorisé" ci-dessus, détournée),
alors qu'OpenBao/hvac normalisent ce même `vault_id` vers le même mount réel — contournement
complet de l'isolation owner-based. `check_access(resource_id)` valide désormais
`is_valid_vault_id()` (`vault_ids.py`, module feuille sans dépendance, `fullmatch`) avant
toute décision d'autorisation. Même correctif dans `_check_vault_access()` (admin/api.py),
`_validate_vault_id()` (spaces.py), `mission_bindings.py`, `wrapping.py`, `ssh_ca.py`. Voir
§6.1b ARCHITECTURE.md et CHANGELOG.md.

### 3.5 `auth/middleware.py` — Authentification HTTP

**Ordre de validation du token** :
1. Bootstrap key (`ADMIN_BOOTSTRAP_KEY`) → admin total
2. Token Store S3 (lookup par hash SHA-256) → permissions du token

**Extraction du token** :
1. Header `Authorization: Bearer <token>` (seule méthode acceptée depuis v0.3.1)

### 3.6 `auth/token_store.py` — Token Store S3

**Stockage** : `_system/tokens.json` sur S3.

**Cache** : Mémoire avec TTL de 5 minutes. Rafraîchissement automatique.

**Opérations** :
- `create(client_name, permissions, allowed_resources, expires_in_days, email)` → Crée un token, sauvegarde sur S3
- `get_by_hash(token_hash)` → Lookup + vérification expiration
- `list_all()` → Liste sans les hash complets
- `revoke(hash_prefix)` → Marque comme révoqué, sauvegarde sur S3
- `count()` → Nombre de tokens actifs
- `purge_revoked(older_than_days=30, dry_run=False)` → Supprime définitivement les tokens **révoqués** depuis plus de N jours (rétention). Fail-close si `revoked_at` absent/corrompu/sans fuseau ; rollback si `_save()` échoue ; `dry_run` retourne les candidats sans rien supprimer. N'affecte jamais un token actif ni un token expiré non révoqué. *(v0.7.0)*

**Validation stricte partagée (issue #86, extension Lot 3)** : `create()`, `update()` et
`load()` valident désormais `permissions`/`allowed_resources` via les MÊMES helpers
(`_validate_permissions`/`_validate_allowed_resources`), jamais une resaisie locale
divergente. Corrige un bug d'élévation de privilège : `update()` validait `permissions`
par simple itération (`all(isinstance(p,str) and p in VALID_PERMISSIONS for p in
permissions)`) SANS vérifier que c'était une liste — un `dict` `{"admin": true}` itéré
donne ses CLÉS (`"admin"`, une chaîne valide), passait donc la validation et était stocké
tel quel ; au moment de la décision (`context.py`, `"admin" in permissions`), tester
l'appartenance d'une clé de dict retournait `True` → le token devenait admin total. Même
bypass via un `tokens.json` corrompu chargé avec `permissions: "admin"` (string → test de
sous-chaîne). `load()` valide désormais chaque token (tout-ou-rien, cohérent avec
`PolicyStore.load()`), avec état observable `available`/`last_error`.

⚠️ **LIMITE EXPLICITE** : `available`/`last_error` sont **diagnostiques seulement** dans ce
lot — `get_by_hash()` ne les consulte pas. Une panne S3 détectée après TTL continue de
servir le cache bearer périmé (y compris après une révocation distante). Un fail-close
complet de l'authentification bearer (comme `PolicyStore`/`MissionBindingStore`) reste un
chantier séparé, à impact opérationnel plus large (deny-all bearer pendant une panne S3).

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
| `get_space_info(id)`        | Mounts info + `kv.v2.list_secrets()` pour le count                   | + `_vault_meta` ; `root_entries_count`/`secrets_count` = entrées 1er niveau, pas de récursif (#81) |
| `update_space(id, desc)`    | `sys.tune_mount_configuration()` + `_vault_meta`                     | Mise à jour description + updated_at/by  |
| `delete_space(id)`          | `sys.disable_secrets_engine(path=id)`                                | Supprime tout (secrets + métadonnées)    |

### 3.9 `vault/secrets.py` — Secrets CRUD

**Protection des chemins réservés** : le set `RESERVED_PATHS` (contenant `_vault_meta`)
empêche l'écriture directe, la suppression et masque ces chemins dans les listings.

| Opération                                  | OpenBao API                                | Notes                                                        |
| ------------------------------------------ | ------------------------------------------ | ------------------------------------------------------------ |
| `write_secret(vault_id, path, data, type)` | `kv.v2.create_or_update_secret()`          | Validation type + enrichissement + protection RESERVED_PATHS |
| `read_secret(vault_id, path, version)`     | `kv.v2.read_secret_version()`              | Version 0 = dernière                                         |
| `list_secrets(vault_id, path)`             | `kv.v2.list_secrets()`                     | Clés du niveau `path` (relatives), filtre `_vault_meta` ; validation canonique anti-traversal (#81) |
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

### 3.10b `ssh_operator.py` — Accès SSH JIT opérateur

Ce module résout un profil fermé à partir du bearer courant, valide le wire
format d'une clé publique OpenSSH standard (`ssh-ed25519`/
`ecdsa-sha2-nistp256` — pas de dispositif matériel FIDO2, décision produit
2026-07-22, cf. §6.3b ARCHITECTURE.md) et appelle `sign_ssh_key()` avec les
seuls attributs serveur. Il refuse bootstrap, admin, Mission JWT, policy
absente ou trop large, coffre non autorisé, PolicyStore indisponible et Token
Store diagnostiqué indisponible (fail-close spécifique à ce parcours, cf.
§6.3b ARCHITECTURE.md). La configuration est validée au démarrage par
`Settings.check_operator_ssh_jit_config()`.

`reserved_operator_vaults()`/`check_not_reserved_for_operator()` exposent
l'ensemble des `vault_id` réservés par les profils configurés — au niveau du
**coffre entier**, pas du couple `(vault_id, role_name)` : un premier garde
limité au rôle exact s'est révélé contournable (créer un rôle alternatif dans
le même mount CA OpenBao, cf. §6.3b ARCHITECTURE.md). Les tools/routes
génériques `ssh_sign_key`/`ssh_ca_setup` (MCP et REST Admin) le consultent
avant tout appel à `sign_ssh_key()`/`setup_ssh_ca()` — jamais l'inverse : ces
deux fonctions internes restent partagées et inchangées, le garde vit aux
points d'entrée génériques pour éviter un paramètre de confiance fragile.
`sign_ssh_key()`/`setup_ssh_ca()` ainsi que les trois fonctions de lecture
(`get_ca_public_key`, `list_ssh_roles`, `get_ssh_role_info`) ne
retournent/ne journalisent plus le message brut d'une exception OpenBao (type
d'exception seul en log, message constant au client).

Les surfaces MCP, REST, Click et Web délèguent toutes à
`request_operator_ssh_access()` ; aucune ne possède sa propre logique
d'autorisation. L'audit conserve l'empreinte, la cible, le principal, le motif
et le résultat, jamais la clé publique complète.

`target` est un attribut logique audité. OpenSSH n'encode pas l'hôte de
destination dans un certificat utilisateur : l'isolation réelle dépend du
couple CA/principal distribué sur les seules cibles autorisées.

`_current_operator_identity()` refuse aussi tout bearer sans `expires_at`
(`expires_in_days=0`, jamais expirer) ou dont le temps restant dépasse
`SSH_OPERATOR_JIT_MAX_BEARER_EXPIRES_DAYS` (défaut 1 jour) — le bearer étant
la seule autorité d'émission depuis le retrait de FIDO2, sa durée de vie doit
être bornée (2026-07-23, suite revue round 8, cf. §6.3b ARCHITECTURE.md).
Contrôlé au point d'usage plutôt qu'à la création, puisque
`TokenStore.update()` ne peut pas modifier l'expiration d'un token existant.

### 3.11b `vault/pki_ca.py` — PKI Certificate Authority *(v0.5.1)*

CA interne souveraine basée sur l'engine PKI d'OpenBao. CA globale (non par vault) — deux mounts réservés `_sys_pki_root/` (racine, TTL 10 ans) et `_sys_pki_int/` (intermédiaire, TTL 5 ans). Protégés contre `vault_delete` (mounts système).

| Fonction | Description |
| --- | --- |
| `setup_pki_ca(lab_mode, allowed_domains, leaf_ttl)` | CA racine + intermédiaire + rôle ACME + sync S3 forcée |
| `get_ca_root_pem()` | CA racine PEM + empreinte SHA-256 + URL stable |
| `get_pki_status()` | État PKI (expiration, ACME on/off, compteur certs) |
| `list_pki_roles()` | Rôles d'émission configurés |
| `get_pki_role_info(role_name)` | Détails rôle (domaines, TTL, flags TLS) |
| `list_issued_certs(limit, offset)` | Inventaire paginé des certificats émis |
| `revoke_cert(serial_number)` | Révocation + CRL + sync S3 forcée |
| `rotate_intermediate(keep_old_issuer, overlap_ttl)` | Rotation CA intermédiaire sans coupure + sync S3 |

**Sécurité** : validation regex `serial_number` (`^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2})+$`), validation FQDN/wildcard `allowed_domains`, `asyncio.Lock` sur `setup_pki_ca`, `follow_redirects=False` dans httpx.

**Sync S3 forcée** : `setup_pki_ca`, `revoke_cert`, `rotate_intermediate` appellent `upload_to_s3()` avant de retourner — la fenêtre de perte S3 est documentée comme acceptable si crash entre appel OpenBao et upload.

**Middleware ACME** (`pki_middleware.py`) : couche ASGI la plus externe, proxy transparent sur trois patterns :
- `/acme/*` → `/v1/_sys_pki_int/acme/*` (URL courte user-facing)
- `/v1/_sys_pki_int/acme/*` → idem (URL longue générée par OpenBao dans les réponses ACME directory)
- `/pki/ca/*.pem` → endpoints CA/CRL OpenBao (lecture publique)

Non-authentifié par design (RFC 8555 ACME + JWS). Anti-traversal sur acme_suffix et query_string. WAF Coraza : exclusions ciblées par regex sur les 3 paths PEM et endpoints ACME normalisés RFC 8555. **Ces exclusions `ctl:ruleRemoveById` sont déclarées AVANT l'`Include` du CRS** (pattern « exclusions before CRS ») — sinon les règles CRS en phase:1 (ex. 920440 sur l'extension `.pem`) s'évaluent et scorent avant le `ctl`, qui devient inopérant (issue #42, fix v0.6.8). ⚠️ **Sémantique inverse pour `SecRuleUpdateTargetById`** (exclusions de CIBLES, ajoutées en v0.9.2 / issue #107) : cette directive réécrit la définition de la règle, qui doit donc être **déjà chargée** — elle se déclare APRÈS l'`Include`. Confondre les deux rend l'exclusion silencieusement inopérante. Validé par test d'intégration à travers le WAF (`tests/pki/` T3d : `.pem` connus → 200, `.pem` arbitraire → 403).

**Cluster path** *(v0.5.1)* : requis par OpenBao 2.5.1 avant l'activation ACME. Configuré via `client._adapter.post("/v1/_sys_pki_int/config/cluster", json={"path": base_url + "/v1/_sys_pki_int"})` (collision paramètre `path` dans `hvac.write()`). URL déduite de `PKI_BASE_URL` (override) ou `MCP_ALLOWED_HOSTS`. **HTTPS requis pour la génération de nonces ACME** (OpenBao 2.5.1) — fonctionnel en production avec WAF TLS.

**Admin REST** *(v0.5.1)* : `GET /admin/api/pki/roles` et `GET /admin/api/pki/roles/{role_name}` — info non-secrète (configuration du rôle ACME), accessible à tout token valide pour diagnostic.

### 3.11c `auth/jwt_validator.py` — Validateur JWT mission_token *(v0.6.8, alignement PEP #86)*

Validation JWT ES256/JWKS pour l'anti-confused-deputy C18 (issue #26). Singleton process-wide depuis v0.6.8 (issue #29). Depuis le Lot 2 (#86), `validate()` délègue à `mission_jwt.validate_mission_token()` — le même contrat que le PEP `/mcp` (`AuthMiddleware`) : plus de logique `jwt.decode()` dupliquée.

| Classe/Fonction | Description |
| --- | --- |
| `MissionTokenValidator(jwks_url, expected_aud, cache_ttl, ..., component_kind="vault")` | Validateur thread-safe. Cache JWKS TTL-borné (60s), refresh kid inconnu, rate-limit 3/min. `expected_iss` non configurable (fixé à `"mcp-mission"`, `ValueError` sinon). |
| `validate(token_compact)` → dict | Délègue à `validate_mission_token()` : ES256, `iss=mcp-mission`, `exp` strict (leeway=0), `iat` (anti-skew, tolérance `leeway_seconds`), `aud`, `mission_id`, `jti`, `tenant_id`, `scope`, `component_id[component_kind] == aud` tous requis. `expected_aud` vide → rejet explicite (`misconfigured_expected_aud`). Jamais le token dans les erreurs. |
| `MissionTokenError(reason)` | reason = code machine, vocabulaire historique C18 préservé pour les cas pré-existants ("invalid_signature", "token_expired", "kid_unknown_or_revoked", "missing_claim:<claim>"...) + nouveaux codes (#86) : "iat_future", "bad_mission_id", "bad_jti", "bad_tenant_id", "bad_scope", "component_id_mismatch". |
| `init_mission_token_validator(jwks_url, ..., component_kind="vault")` | Initialise le singleton au startup (lifecycle.py step 1e). Retourne None si jwks_url vide. |
| `get_mission_token_validator()` | Retourne le singleton process-wide. None si non configuré. |

**Thread-safety** : le cache JWKS partagé (`auth/mission_jwt.py`, issue #47) est protégé par son propre `threading.Lock`.

**Singleton process-wide** : un seul `MissionTokenValidator` pour tout le processus, adossé au JWKSCache singleton partagé avec le PEP `/mcp`. `secret_consume` utilise `get_mission_token_validator()` — fail-close si absent en mode `ENFORCE=true`.

**Standalone** : si `MISSION_JWKS_URL` est vide, le validateur n'est pas instancié et `secret_consume` fonctionne en mode non-enforced.

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
- `_validate_and_normalize_policy()` (interne) : validation stricte partagée par `load()`
  (chaque policy du blob S3) et `create()` — champs `allowed_tools`/`denied_tools`/`path_rules`
  OBLIGATOIREMENT présents, `vault_pattern` non vide, `permissions` normalisée à `["read"]`
  si absente (JAMAIS un défaut admin/write). Une seule policy non conforme invalide TOUT le
  chargement (tout-ou-rien, jamais un chargement partiel).

**Fail-close sur panne/corruption S3 détectée après TTL** *(issue #86 Lot 3, finding 3)* :
même pattern `available`/`last_error` que `MissionBindingStore` (§3.12b). `_ensure_available()`
lève `PolicyStoreUnavailable` (jamais un fail-open silencieux sur cache périmé) — consommée par
`get()`, `list_all()`, `get_vault_permissions()`, `is_tool_allowed()`, `is_path_allowed()`.
`create()`/`delete()` retournent `{"status":"error","error_type":"policy_store_unavailable"}` /
`"policy_store_unavailable"` (refus AVANT toute écriture si déjà indisponible). Retry accéléré
10s (borné par processus) si invalide, TTL normal 300s sinon. Côté admin REST, un helper
centralisé (`_policy_error_response`) mappe `error_type=="policy_store_unavailable"` en HTTP 503
sur les ~18 sites `check_policy()`/`check_path_policy()`, distinct d'un refus de policy ordinaire
(403).

⚠️ **LIMITATION HORS SCOPE (non fermée par ce lot)** : ce mécanisme ferme le sous-cas
« panne/corruption détectée », PAS la race d'écriture multi-instance générale (deux instances
qui écrivent concurremment SANS aucune panne — last-write-wins structurel sur le fichier unique
partagé `_system/policies.json`, cf. #13/#51, nécessite un vrai CAS/ETag S3). `TokenStore`
partage la même limitation non traitée (résidu tracé séparément).

### 3.12b `auth/mission_bindings.py` — Mission Binding Store S3 *(#69, v0.8.0)*

Octroi de périmètre vault local pour les identités mission JWT. mcp-vault = **PDP** : le
`mission_token` ne portant aucune autz vault, l'autorisation est provisionnée ici, indexée par
`tenant_id`. Même pattern que PolicyStore/TokenStore (singleton + cache TTL 5 min), mais **un
fichier S3 par instance**.

**Stockage** : `_system/mission_bindings/{encoded_instance_id}.json` (`encoded` = slug + hash court
de `resolved_mission_aud`). Le fichier-par-instance réduit le last-write-wins cross-instance ;
`instance_id` est aussi stocké dans chaque entrée et **filtré à la lecture** (anti-fuite cross-instance).

**Singleton** : `init_mission_binding_store()` (lifecycle, après Policy Store) — actif si S3 configuré
ET `resolved_mission_aud` non vide ; `get_mission_binding_store()` (getter). Warning au boot si
`MCP_AUTH_MODE` ∈ {`jwt`, `dual-stack`} sans store (PEP actif mais aucun octroi possible → deny-all). Cf. `Settings.mission_pep_active` (#116) : la formulation `≠ bearer` était fausse dès l'ajout d'un 4e mode.

**Modèle de données** :

```python
{
    "instance_id": str,           # == resolved_mission_aud (défense en profondeur)
    "tenant_id": str,             # clé logique + id REST ; URL-safe ; 'purge' réservé
    "policy_id": str,             # optionnel ; si non vide, doit exister dans PolicyStore
    "allowed_resources": [str],   # vrais vault_id (regex), non vides, dédupliqués, pas de '*'
    "permissions": ["read"] | ["read","write"],  # 'write' seul / [] / 'admin' REFUSÉS
    "enabled": bool,
    "expires_at": str | None,     # ISO 8601 ; dépassé/corrompu → deny (fail-close)
    "created_at": str, "created_by": str,
}
```

**État observable (fail-close fort)** : `available` / `last_error`. `NoSuchKey`/404 → store vide
writable (nominal). Erreur réseau/403/timeout/**JSON corrompu** → état **invalid** : `resolve()`
lève `MissionBindingStoreUnavailable` (→ `503` au PEP), les mutations sont refusées et **aucune
écriture n'est tentée** (anti-écrasement destructeur). Re-tentative accélérée (10 s) hors TTL ;
`force_reload()` disponible.

**API** :
- `resolve(tenant_id)` → binding actif (enabled, non expiré, bonne instance) ou `None` ; lève si indispo. **Utilisé par le PEP**.
- `get(tenant_id)` / `list_all()` → vue admin (montre enabled/expired) ; lèvent si indispo.
- `create(...)` / `delete(tenant_id)` / `purge(older_than_days, dry_run)` → rollback mémoire si `_save` échoue ; `purge` = bindings expirés au-delà de la rétention (fail-close date corrompue).

**Endpoints admin** (bearer/bootstrap-only) : `GET/POST /admin/api/mission-bindings`,
`GET/DELETE /admin/api/mission-bindings/{tenant_id}`, `POST /admin/api/mission-bindings/purge`
(route `/purge` déclarée avant le segment variable). Audit des mutations avec `decision_id` en tête.
CLI Click : groupe `mission-binding` (create/list/get/delete/purge).

### 3.13 `openbao/` — OpenBao Process Manager

| Module         | Rôle                                                                         |
| -------------- | ---------------------------------------------------------------------------- |
| `manager.py`   | Démarrage/arrêt du process `bao server`, health check, client hvac singleton |
| `config.py`    | Génération du fichier HCL (file backend, listener localhost)                 |
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
api_addr = "http://127.0.0.1:8200"
ui = false
```

> **Note** : `disable_mlock` a été supprimé — OpenBao ≥2.0 ne supporte plus ce paramètre.
> La protection mémoire est gérée au niveau OS (swap désactivé dans le conteneur Docker).

### 3.14 `audit.py` — Audit Store MCP

Journal d'audit de toutes les opérations MCP. **Un seul support persistant** —
le fichier JSONL local ; le ring buffer mémoire n'est qu'un cache de lecture
(5 000 dernières entrées), perdu à chaque redémarrage :

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
│  │   au startup                 │  │ • Local, PAS sur S3    │  │
│  └──────────────────────────────┘  └────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

**Singleton** :
- `init_audit_store()` → Appelé au startup (dans `lifecycle.py`, après PolicyStore)
- `get_audit_store()` → Getter singleton
- `log_audit(tool, status, vault_id, detail, duration_ms, client_name)` → Helper global

**Chaque entrée d'audit contient** :

| Champ         | Type   | Description                                                                   |
| ------------- | ------ | ----------------------------------------------------------------------------- |
| `ts`          | string | Timestamp ISO 8601 UTC                                                        |
| `client`      | string | Nom du client (auto-détecté via `get_current_client_name()`)                  |
| `tool`        | string | Nom de l'outil MCP (ex: `vault_create`, `secret_read`)                        |
| `category`    | string | Catégorisation automatique (system, vault, secret, ssh, policy, token, audit) |
| `vault_id`    | string | Vault concerné (vide si non applicable)                                       |
| `status`      | string | Résultat (ok, created, deleted, error, updated, denied)                       |
| `detail`      | string | Détail additionnel (path du secret, message d'erreur…)                        |
| `duration_ms` | float  | Durée de l'opération en millisecondes                                         |

**Catégorisation automatique** : basée sur le préfixe du nom d'outil (`_categorize_tool()`).

| Préfixe   | Catégorie |
| --------- | --------- |
| `system_` | system    |
| `vault_`  | vault     |
| `secret_` | secret    |
| `ssh_`    | ssh       |
| `policy_` | policy    |
| `token_`  | token     |
| `audit_`  | audit     |
| *(autre)* | other     |

**Filtrage** (`get_entries()`) : tous les filtres sont combinables.

| Filtre     | Description                                     |
| ---------- | ----------------------------------------------- |
| `limit`    | Nombre max d'entrées (défaut 100, max 1000)     |
| `client`   | Filtrer par client_name exact                   |
| `vault_id` | Filtrer par vault_id exact                      |
| `tool`     | Filtrer par outil (supporte `*` via startswith) |
| `category` | Filtrer par catégorie                           |
| `status`   | Filtrer par statut                              |
| `since`    | Entrées après cette date ISO 8601               |

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
- Health check via `curl -sf` sur `/health` (et non `/admin/api/health`, qui
  exige un bearer valide) — depuis #103, cette sonde devient **rouge** quand le
  coffre ne peut pas servir

### 4.2 Docker Compose

```yaml
services:
  waf:        # Caddy reverse proxy (:8085 → :8030)
  mcp-vault:  # Python + OpenBao embedded
  test:       # Service ponctuel (profil "test")

volumes:
  openbao-data:  # Persistance locale (crash recovery)
  openbao-logs:  # Logs OpenBao ET journal d'audit applicatif — PAS optionnel
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

**312 tests** e2e via protocole MCP Streamable HTTP, 15 catégories :

| #   | Catégorie              | Tests  | Description                                                                 |
| --- | ---------------------- | ------ | --------------------------------------------------------------------------- |
| 1   | Système                | 7      | health, about, services, version, tools_count (37)                          |
| 2   | Vault Spaces CRUD      | ~28    | create, list, info, update, delete, metadata, erreurs                       |
| 3   | Secrets CRUD           | ~24    | 14 types, write/read/list/delete, validation                                |
| 4   | Versioning & Rotation  | 8      | v1/v2/v3, lecture version spécifique                                        |
| 5   | Password Generator     | 14     | longueurs, options, exclusions, unicité CSPRNG                              |
| 6   | Isolation inter-vaults | 7      | cloisonnement strict entre vaults                                           |
| 7   | Gestion d'erreurs      | ~10    | edge cases, _vault_meta protection                                          |
| 8   | S3 Sync                | 3      | HEAD bucket, list archives, archive existe                                  |
| 9   | SSH CA                 | ~33    | setup, roles multiples, signing ed25519, isolation                          |
| 10  | Secret Types           | 14     | validation des 14 types                                                     |
| 11  | Admin API              | 15     | health, whoami, generate-password, logs, CSPRNG                             |
| 12  | Policies MCP           | 43     | CRUD, validation, wildcards, path_rules, Admin API                          |
| 13  | **Policy Enforcement** | **37** | check_policy, token_update, denied/allowed, changement policy               |
| 14  | **Audit Log**          | **31** | audit_log MCP, filtres (category/tool/status/since/limit), stats, Admin API |
| 15  | **WAF Security**       | **17** | LFI, SQLi, XSS, RCE, Scanner Detection → 403 + non-régression               |

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

### 5.x Opérations destructives du CLI — `tests/cli/test_purge_destructive.py`

**40 tests**, paramétrés sur `token purge-revoked` ET `mission-binding purge`.
Portés depuis les tests du shell interactif lors de sa suppression (#128), et
complétés : trois des garanties qu'ils vérifient n'étaient couvertes par **aucune**
surface — ni le shell, ni Click.

Chaque protection est prouvée par une mutation mesurée :

| Mutation appliquée à `scripts/cli/commands.py` | Échecs |
| --- | --- |
| aperçu retiré (`dry_run=True` → `False`) | 22 |
| `if n == 0` au lieu d'une preuve positive stricte | 12 |
| `abort=True` → `abort=False` | 2 |
| rétention par défaut `30` → `0` | 2 |
| borne `IntRange(min=0)` retirée | 2 |
| en-têtes d'authentification retirés | 2 |
| endpoint tokens dirigé vers celui des bindings | 1 |
| reprise ajoutée après échec réseau de la purge | 1 |

Détail des garanties et fenêtre TOCTOU non fermée : ARCHITECTURE.md §11.3c.

### 5.y Sortie des appels S3 de la boucle — `tests/test_s3_offload_122.py`

**27 tests** (+ 4 ajoutés à `tests/test_lifecycle.py` pour le câblage du
drainage à l'arrêt).

**Preuve déterministe par barrières, sans aucun seuil de performance** — donc
rien qui devienne instable selon la charge de la machine. (Des délais
subsistent : plafonds de sécurité pour qu'un test en échec se termine, budgets
de drainage raccourcis ; aucun ne conditionne le verdict.) Le stub bloquant
signale son entrée puis
attend d'être libéré ; une coroutine témoin, dans la même boucle, progresse et
le libère ; **le stub échantillonne le témoin juste avant de sortir, depuis le
fil d'exécution** — c'est-à-dire entre son entrée effective et sa sortie. Si
l'appel était resté dans la boucle, le témoin n'aurait pas pu progresser :
l'échantillon vaut faux. Le RED est structurel, pas une course.

**Contrôle de l'instrument** : `test_le_temoin_detecte_un_appel_reste_dans_la_boucle`
applique le même témoin à un appel volontairement laissé dans la boucle et exige
un résultat négatif. Sans lui, un témoin cassé rendrait tous les autres tests
verts sans rien prouver — c'est arrivé deux fois sur ce dépôt.

| Mutation appliquée | Échecs |
| --- | --- |
| offload du PUT retiré | 3 |
| offload de la construction d'archive retiré | 1 |
| offload de la restauration retiré | 1 |
| offload de la sonde retiré | 2 |
| offload du PUT des clés OpenBao retiré | 1 |
| offload du GET des clés OpenBao retiré | 1 |
| verrou de sérialisation retiré | 1 |
| single-flight de la sonde retiré | 1 |
| annulation réintroduite dans le drainage | 2 |
| boucle réveillable re-remplacée par `sleep` | 5 |
| garde « drainage non abouti » retirée | 2 |
| `Future` remplacé par une `Task` (rotation à vide au teardown) | 1 |
| attente rendue sur annulation (verrou relâché) | 2 |
| priorité exception métier / annulation inversée | 1 |
| garde anti-seconde-boucle non drainée retirée | 2 |
| verrou de la sync retiré (démarrage toujours accepté) | 2 |
| verrou posé seulement s'il y a une boucle à drainer | 2 |
| verrou relâché à la fin du drainage (transitoire) | 1 |
| nettoyage inconditionnel (2e barrière retirée) | 2 |
| référence perdue après un drainage échoué | 2 |
| réouverture non câblée dans `vault_startup` | 1 |
| réouverture inconditionnelle (boucle vivante ignorée) | 2 |
| refus de démarrage ignoré par `vault_startup` | 1 |
| garde « arrêt en cours » retirée du démarrage | 1 |

Les 24 mutations sont détectées. **Trois enseignements sur l'instrument
lui-même**, chacun après une mesure trompeuse observée :

1. **Valider la syntaxe** (`ast.parse`) avant d'écrire une mutation — un fichier
   invalide produit des *erreurs de collecte* et non des *échecs*, ce qu'un
   compteur naïf affiche comme un « 0 échec » faussement rassurant.
2. **Borner le temps d'exécution** — la mutation « boucle réveillable
   re-remplacée par `sleep` » faisait initialement **figer** un test au lieu de
   le faire échouer : la mesure restait suspendue sans rien rapporter. Le test
   concerné borne désormais son attente, et l'instrument signale un figeage au
   lieu de le confondre avec un succès.
3. **Un « 0 échec » signale une protection NON COUVERTE, pas une protection
   inutile.** La garde anti-seconde-boucle est tombée à 0 quand le verrou
   définitif a été ajouté : celui-ci masquait son cas dans tous les scénarios
   testés. Le cas propre à cette garde — deux démarrages sans arrêt entre eux —
   n'était couvert par aucun test. Un test dédié a été ajouté plutôt que la
   garde retirée.

Principe et pièges : ARCHITECTURE.md §11.3d.

### 5.z Authentification du mode par défaut — `tests/test_bearer_auth_116.py`

**24 tests.** La preuve centrale n'est pas le code de statut mais un **compteur
de passage** sur l'application en aval : un refus doit laisser ce compteur à
zéro. Vérifier seulement le `401` ne dirait pas si les outils ont malgré tout
été atteints.

| Mutation appliquée | Échecs |
| --- | --- |
| refus retiré (retour au passthrough) | 8 |
| refus limité au jeton ABSENT (un jeton invalide passe) | 3 |
| clé de bootstrap non exemptée | 3 |
| `PUBLIC_PATHS` ignoré | 4 |
| `bearer-anonymous` non reconnu | 3 |
| `mission_pep_active` retombant sur `!= "bearer"` | 3 |
| avertissement de démarrage retiré | 1 |
| audit du refus retiré | 2 |

Les 8 mutations sont détectées. Deux tests méritent d'être signalés :

- **non-divulgation du jeton refusé** : un jeton invalide est souvent un jeton
  VALIDE d'un autre environnement. Le test présente une valeur SENTINELLE et
  exige son absence de l'audit **et** des logs capturés. Un refus « sans
  jeton » ne pourrait rien prouver ici — il n'y a pas de jeton à divulguer.
- **`mission_pep_active`** : la mutation qui le fait retomber sur
  `!= "bearer"` reproduit exactement la régression trouvée en revue de plan —
  le mode de repli devenant inutilisable parce qu'il exigerait un JWKS.

Principe et portée : ARCHITECTURE.md §11.3e.

---

## 6. Sécurité

> **Audit de Sécurité** : Trois audits ont été réalisés (v0.2.0, v0.3.3, V2.1 externe). L'audit V2.1 (60 findings) est la référence unique : 28 corrigés (v0.3.1→v0.4.5), 13 résiduels documentés, 18 informationnels. Aucune vulnérabilité Élevée ouverte. Voir [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md) pour le rapport consolidé.

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

Le parcours humain JIT ajoute une barrière distincte : bearer nominatif à
expiration bornée, policy exacte limitée aux deux outils JIT, clé publique
standard (`ssh-ed25519`/`ecdsa-sha2-nistp256`) pré-enrôlée par empreinte
(plus d'exigence FIDO2/`verify-required`, décision produit 2026-07-22 — cf.
§6.3b ARCHITECTURE.md). L'IHM et les CLI restent de simples canaux de
demande. Le credential breaking-glass externe n'est jamais lu par ce
parcours.

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
| **v0.8.0** (actuel) | AES-256-GCM+AAD + PBKDF2 + bootstrap key env | Mémoire Python au runtime  | 🟡 Bonne      |
| **v1.0**            | Transit Auto-Unseal via OpenBao KMS dédié    | KMS dédié (Shamir 5/3)     | 🟢 Excellente |
| **v2.0**            | HSM matériel (PKCS#11 / KMIP)                | HSM certifié FIPS 140-2 L3 | 🟢 Maximale   |

Voir `ARCHITECTURE.md §11.3` pour les diagrammes d'architecture et les étapes de migration détaillées.

---

## 7. Dépendances

| Package             | Version | Rôle                                          |
| ------------------- | ------- | --------------------------------------------- |
| `mcp[cli]`          | ≥1.23.0,<2 | Framework MCP (FastMCP, Streamable HTTP). Plancher : CVE-2025-53366 / CVE-2025-66416 (V3-01). Borne haute : `mcp 2.0.0` supprime `mcp.server.fastmcp` (#125) |
| `pydantic-settings` | ≥2.0    | Configuration env vars                        |
| `boto3`             | ≥1.38.43 | Client S3 Dell ECS — plancher imposé par `PutObject.IfMatch` (écriture conditionnelle, issue #121) |
| `hvac`              | ≥2.3.0  | Client Python pour OpenBao/Vault              |
| `cryptography`      | ≥42.0   | Chiffrement clés unseal (AES-256-GCM, PBKDF2) |
| `uvicorn[standard]` | ==0.42.0 | Serveur ASGI — **épinglé** (issue #110) : la sémantique de ré-émission du SIGTERM conditionne l'exécution du lifespan d'arrêt |
| `pytest`            | ==9.1.1 | Tests — épinglé (#125) : la chaîne de test garde la release (`release.yml` en dépend) ; la laisser flotter reproduirait le défaut corrigé |
| `pytest-asyncio`    | ==1.4.0 | Tests async — épinglé (#125)                  |
| `pluggy` / `iniconfig` | ==1.6.0 / ==2.3.0 | Transitives de pytest — épinglées (#125). Hors verrou, donc absentes de l'image de production |

### Composants du WAF (hors Python, cf. `waf/Dockerfile`)

| Composant                    | Version | Rôle                                                            |
| ---------------------------- | ------- | --------------------------------------------------------------- |
| `caddy`                      | 2.x     | Reverse proxy, terminaison TLS, rate limiting                    |
| `corazawaf/coraza-caddy/v2`  | v2.5.0  | Plugin WAF (embarque coraza v3.7.0)                             |
| `corazawaf/coraza/v3`        | v3.7.0  | Moteur WAF — **relevé en v0.9.2** (issue #107) : `SecRequestBodyJsonDepthLimit` n'existe qu'à partir de v3.4.0, et sans plafond de profondeur le parseur JSON était vulnérable à un DoS par imbrication |
| `mholt/caddy-ratelimit`      | v0.1.0  | Limitation de débit par IP                                      |
| OWASP CoreRuleSet            | 4.7.0   | 23 fichiers de règles chargés                                   |

**Runtime** :
- Python 3.12+
- OpenBao 2.5.1 (binaire embarqué)
- Docker + Docker Compose
- S3 Dell ECS Cloud Temple

---

## 8. Roadmap

| Phase                            | Statut | Description                                                                                                                                                                                                                    |
| -------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Phase 0 — Bootstrap              | ✅     | Starter-kit, structure, config, Docker                                                                                                                                                                                         |
| Phase 1 — S3 + Auth              | ✅     | Client S3 hybride, Token Store, middleware                                                                                                                                                                                     |
| Phase 2 — Types                  | ✅     | 14 types de secrets, validation, password generator                                                                                                                                                                            |
| Phase 3 — Tests                  | ✅     | 78 tests e2e (permissions, S3, admin)                                                                                                                                                                                          |
| Phase 4 — OpenBao lifecycle      | ✅     | Init/unseal/seal intégré, clés chiffrées AES-256-GCM sur S3, 104 tests                                                                                                                                                         |
| Phase 5 — Vault Spaces CRUD      | ✅     | Métadonnées (owner, dates), vault_update, filtrage token, protection _vault_meta                                                                                                                                               |
| Phase 6 — SSH CA                 | ✅     | CA isolée par vault, 5 outils MCP (setup, sign, public_key, list_roles, role_info), 148 tests e2e, CLI ssh complet, cleanup CA auto                                                                                            |
| Phase 7 — Interface web          | ✅     | Console admin SPA modulaire (sidebar, CRUD vaults/secrets, permissions granulaires, 15 endpoints API, 10 fichiers frontend < 200 lignes)                                                                                       |
| Phase 8a — Policies CRUD         | ✅     | PolicyStore S3-backed, 4 outils MCP (create, list, get, delete), wildcards fnmatch, path_rules, Admin API, 206 tests e2e                                                                                                       |
| Phase 8b — Policy Enforcement    | ✅     | `check_policy()` dans 15 outils MCP, champ `policy_id` dans tokens, outil `token_update`, 310 tests e2e / 15 catégories                                                                                                        |
| Phase 8c — Audit Log             | ✅     | AuditStore (ring buffer 5000 + JSONL), outil `audit_log` filtrable, timeline SPA, CLI audit, catégorisation auto, stats dashboard                                                                                              |
| Phase 8d — Owner Isolation       | ✅     | **Owner-based vault isolation** : `vide = mes vaults` (au lieu de `vide = tous`). Fix bug `vault_ids` → `allowed_resources`. `check_vault_owner()`, `list_spaces(owner_filter)`. SPA : modal édition token + label mis à jour. |
| Phase 8e — Path Enforcement      | ✅     | `allowed_paths` dans les `path_rules`, `is_path_allowed()` dans PolicyStore, `check_path_policy()` dans context.py. Intégré dans secret_read/write/delete.                                                                     |
| Phase 9 — Sécurité v0.3.1-v0.4.5 | ✅     | **3 audits** (interne v0.2.0, interne v0.3.3, externe v0.4.0). 60 findings identifiés, 28 corrigés (P0/P1/P2), 13 résiduels documentés. WAF Coraza blocking, Docker hardening, AES-GCM AAD, HSTS, images par digest.           |
| Phase 10 — HSM Integration       | ⏳      | **En attente HSM** — Design et prérequis documentés (ARCHITECTURE.md §11.3). Bloqué par la disponibilité du Thales Luna chez Cloud Temple. Config HCL cible, migration 11 étapes, commandes Luna préparées.                    |
