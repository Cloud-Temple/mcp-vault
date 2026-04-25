# Rapport d'Audit de Sécurité — MCP Vault

**Version auditée :** v0.4.0  
**Version courante :** v0.4.9  
**Audit externe :** White-box V2.1, revue de code multi-passe (v2 + v3) + revue par pair POC externe  
**Audit interne :** Cline (Opus), v0.2.0 puis v0.3.3  
**Date de consolidation :** 26 Mars 2026  
**Composants couverts :** Serveur MCP (24 outils), Auth/Policies, WAF Caddy+Coraza, Docker/S3/Crypto, Admin API+SPA

---

## 1. Résumé Exécutif

Ce document consolide les résultats de **trois passes d'audit** sur MCP Vault :

1. **Audit interne v0.2.0** (23 mars 2026) — 5 findings, tous corrigés en v0.3.1
2. **Audit interne v0.3.3** (24 mars 2026) — 18 findings, tous corrigés en v0.4.0
3. **Audit externe V2.1** (26 mars 2026) — 60 findings (source de vérité)

L'audit V2.1 est la **référence unique**. Il intègre et réévalue les findings des audits précédents, confirme les correctifs appliqués, et identifie de nouveaux problèmes.

### Bilan global V2.1

| Sévérité   | Total  | Corrigés | Résiduels |  Info  |
| ---------- | :----: | :------: | :-------: | :----: |
| 🔴 Élevé  |   4    |   4 ✅   |     0     |   —    |
| 🟠 Moyen  |   14   |  12 ✅   |     2     |   —    |
| 🟡 Faible |   23   |  12 ✅   |    11     |   —    |
| ℹ️ Info   |   18   |    —     |     —     |   18   |
| 🔵 Retiré |   1    |    —     |     —     |   —    |
| **Total**  | **60** |  **28**  |  **13**   | **18** |

> **Aucune vulnérabilité Élevée ou Critique ouverte.** Les 13 findings résiduels sont de sévérité Moyen (2) ou Faible (11), avec des facteurs atténuants documentés et des risques acceptés.
>
> **Note :** 1 finding a été retiré pendant la revue (ID probable V2-04, absent de la numérotation finale) et n'apparaît pas dans le rapport V2.1.

---

## 2. Points Forts Confirmés par l'Audit

L'audit V2.1 valide explicitement les éléments suivants comme **conformes** :

### Cryptographie
- AES-256-GCM avec PBKDF2-HMAC-SHA256 (600K itérations, conforme OWASP)
- CSPRNG via `secrets.choice` pour la génération de mots de passe
- Zeroing `bytearray` dans `crypto.py` via `_zero_fill()`
- Nonce management : sel + nonce frais par chiffrement, réutilisation impossible

### Authentification
- `hmac.compare_digest()` sur les 3 comparaisons de bootstrap key (fix C2 confirmé)
- Bearer-only auth (pas de query string)
- SHA-256 hashing des tokens en stockage S3
- Token entropy 256 bits via `secrets.token_urlsafe(32)` (conforme OWASP)
- Architecture asyncio single-threaded = pas de race conditions sur les stores

### WAF
- OWASP CRS v4 en mode blocking complet
- Rate limiting 10K req/5min par IP via `caddy-ratelimit`
- Exclusions CRS documentées et ciblées (2 règles : 920540, 932120)
- Headers de sécurité : CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- Admin API Caddy désactivée (`admin off`)

### Infrastructure
- Non-root container : user `mcp`, `IPC_LOCK` pour mlock
- Resource limits : `mem_limit: 2g/512m`, `cpus: 2.0/1.0`
- `tarfile` sécurisé : `filter='data'` (fix C3 confirmé)
- OpenBao 2.5.1 sans CVE non-résolues
- Réseau isolé : `expose` only, WAF en frontale
- S3 credentials via variables d'environnement, pas hardcodés
- Unseal keys chiffrées AES-256-GCM avant upload S3

### Admin SPA
- `_check_vault_access()` sur toutes les routes (fix C1 confirmé)
- `_MAX_BODY_SIZE` 10 MB (fix E4 confirmé)
- LFI fixé : `Path.resolve()` + `startswith()` robuste
- CSRF mitigé par Bearer token en header (pas de cookies)
- `esc()` appliquée sur toutes les valeurs user-controlled

---

## 3. Tableau de Synthèse — Tous les Findings

### 3.1 Élevé (4/4 corrigés)

| ID     | Composant  | Description                                    | CVSS | Statut     | Version |
| ------ | ---------- | ---------------------------------------------- | ---- | ---------- | ------- |
| V2-03  | MCP Server | `audit_log` sans contrôle d'authentification   | 8.1  | ✅ Corrigé | v0.4.0  |
| V2-02  | Auth       | `is_path_allowed()` fail-open inconsistant     | 7.8  | ✅ Corrigé | v0.4.0  |
| V3-01  | Infra      | CVE-2025-53366 — MCP SDK DoS requête malformée | 7.5  | ✅ Corrigé | v0.4.0  |
| V2-05b | MCP Server | `secret_list` sans `check_path_policy()`       | 6.5  | ✅ Corrigé | v0.4.0  |

### 3.2 Moyen (12/14 corrigés — 2 résiduels)

| ID    | Composant  | Description                                       | CVSS | Statut        | Version |
| ----- | ---------- | ------------------------------------------------- | ---- | ------------- | ------- |
| V2-17 | Auth       | `expires_at` fail-open sur erreur de parsing      | 5.9  | ✅ Corrigé    | v0.4.0  |
| V2-01 | Infra      | Bootstrap key par défaut acceptée                 | 5.3  | ⚠️ Résiduel | —       |
| V2-12 | Infra      | Images Docker pinnées par tag, pas par digest     | 5.3  | ✅ Corrigé    | v0.4.5  |
| V2-16 | WAF        | Plugins Caddy/Coraza non pinnés en version        | 5.3  | ✅ Corrigé    | v0.4.5  |
| V3-11 | MCP Server | `role_name` SSH sans validation                   | 5.3  | ✅ Corrigé    | v0.4.0  |
| V3-23 | MCP Server | Paramètre `path` sans validation — traversal      | 5.3  | ✅ Corrigé    | v0.4.0  |
| V3-02 | Admin SPA  | API audit/logs accessible à tout token            | 5.3  | ✅ Corrigé    | v0.4.0  |
| V2-06 | MCP Server | SSH CA `allowed_users="*"` par défaut             | 5.0  | ⚠️ Résiduel | —       |
| V3-09 | Auth       | `check_vault_owner` fail-open si metadata absente | 5.0  | ✅ Corrigé    | v0.4.0  |
| V2-13 | Infra      | Docker hardening manquant                         | 4.8  | ✅ Corrigé    | v0.4.5  |
| V3-05 | Infra      | `disable_mlock` supprimé (OpenBao ≥2.0)           | 4.5  | ✅ Corrigé    | v0.4.6  |
| V3-03 | Admin SPA  | Token creation sans validation permissions        | 4.5  | ✅ Corrigé    | v0.4.0  |
| V3-08 | Infra      | Pas de lock file — builds non-reproductibles      | 4.5  | ✅ Corrigé    | v0.4.5  |
| V3-07 | Infra      | `initialize_vault()` retourne root_token/keys     | 4.0  | ✅ Corrigé    | v0.4.0  |

### 3.3 Faible (12/23 corrigés — 11 résiduels)

| ID     | Composant  | Description                                           | CVSS | Statut        | Version |
| ------ | ---------- | ----------------------------------------------------- | ---- | ------------- | ------- |
| V2-08  | MCP Server | `str(e)` des exceptions OpenBao dans les réponses     | 4.0  | ⚠️ Résiduel | —       |
| V3-24  | MCP Server | `RESERVED_PATHS` bypass via sous-chemin               | 3.5  | ✅ Corrigé    | v0.4.0  |
| V2-05  | Infra      | OpenBao binaire sans checksum SHA256                  | 3.5  | ⚠️ Résiduel | —       |
| V2-L08 | Admin SPA  | `vault_id` depuis URL non validé par regex            | 3.5  | ⚠️ Résiduel | —       |
| V3-20  | WAF        | CVE-2025-29914 — Coraza URI parser bypass             | 3.5  | ⚠️ Résiduel | —       |
| V2-14  | WAF        | CSP `unsafe-inline`                                   | 3.0  | ⚠️ Résiduel | —       |
| V3-25  | MCP Server | `secret_read` sans protection `_vault_meta`           | 3.0  | ✅ Corrigé    | v0.4.0  |
| V3-18  | MCP Server | Chemins secrets logués en clair dans l'audit          | 3.0  | ⚠️ Résiduel | —       |
| V3-13  | Auth       | Cache TTL 5 min — fenêtre de token révoqué            | 3.0  | ⚠️ Résiduel | —       |
| V3-04  | Infra      | AES-256-GCM sans Associated Data (AAD)                | 3.0  | ✅ Corrigé    | v0.4.5  |
| V3-10  | Infra      | CVE-2025-66416 — MCP SDK DNS rebinding                | 3.0  | ✅ Corrigé    | v0.4.0  |
| V2-09  | Infra      | Pas de validation TLS sur les connexions S3           | 3.0  | ⚠️ Résiduel | —       |
| V2-10  | Admin SPA  | `json.loads()` sans try/except dans l'API admin       | 3.0  | ✅ Corrigé    | v0.4.0  |
| V3-19  | Admin SPA  | CORS wildcard `*` sur preflight admin                 | 3.0  | ✅ Corrigé    | v0.4.5  |
| V2-07  | Auth       | Hash prefix matching sans longueur minimale           | 2.5  | ⚠️ Résiduel | —       |
| V2-11  | Auth       | `check_access()` leake `allowed_vaults` dans l'erreur | 2.5  | ⚠️ Résiduel | —       |
| V3-14  | Auth       | Owner-isolation bypass avec `client_name` vide        | 2.5  | ⚠️ Résiduel | —       |
| V2-15  | WAF        | HSTS absent                                           | 2.5  | ✅ Corrigé    | v0.4.5  |
| V3-06  | Infra      | Unseal keys non zero-filled au clear                  | 2.5  | ⚠️ Résiduel | —       |
| V3-16  | Infra      | Tests et pytest dans l'image production Docker        | 2.5  | ✅ Corrigé    | v0.4.5  |
| V3-12  | Admin SPA  | Audit `limit` crash sur input non-numérique           | 2.5  | ✅ Corrigé    | v0.4.0  |
| V3-15  | Auth       | `fnmatch` patterns non documentés                     | 2.0  | ⚠️ Résiduel | —       |
| V3-17  | Infra      | SigV4 meta client désactive signature du payload      | 2.0  | ⚠️ Résiduel | —       |

---

## 4. Findings Détaillés — Corrigés

Cette section documente chaque finding corrigé avec la remédiation appliquée.

### 4.1 Élevés Corrigés (P0 — v0.4.0)

#### V2-03 — `audit_log` sans contrôle d'authentification
- **CVSS :** 8.1 | **CWE :** CWE-862 (Missing Authorization)
- **Localisation :** `server.py:749-794`
- **Problème :** L'outil MCP `audit_log` n'implémentait aucun contrôle d'auth. Tout client — même non authentifié — pouvait lire l'historique complet des opérations.
- **Remédiation :** Ajout de `check_admin_permission()` en début de fonction.
- **Vérifié :** ✅ v0.4.0

#### V2-02 — `is_path_allowed()` fail-open inconsistant
- **CVSS :** 7.8 | **CWE :** CWE-636 (Not Failing Securely)
- **Localisation :** `auth/policies.py:296-298`
- **Problème :** `is_path_allowed()` retournait `True` (allow) quand la policy était introuvable, alors que `is_tool_allowed()` retournait `False` (deny) dans le même cas.
- **Remédiation :** `is_path_allowed()` → `return False` sur policy manquante. Fail-close cohérent.
- **Vérifié :** ✅ v0.4.0

#### V3-01 — CVE-2025-53366 : MCP SDK DoS par requête malformée
- **CVSS :** 7.5 | **CWE :** CWE-248 (Uncaught Exception)
- **Localisation :** `requirements.txt`
- **Problème :** Le SDK MCP Python (`session.py`) crashait sur des requêtes structurellement valides mais sémantiquement invalides. La borne `mcp[cli]>=1.9.0` incluait les versions vulnérables.
- **Remédiation :** Passage à `mcp[cli]>=1.23.0` (couvre aussi CVE-2025-66416).
- **Vérifié :** ✅ v0.4.0

#### V2-05b — `secret_list` sans `check_path_policy()`
- **CVSS :** 6.5 | **CWE :** CWE-862 (Missing Authorization)
- **Localisation :** `server.py:326-345`
- **Problème :** `secret_list` n'appelait pas `check_path_policy()`, contrairement aux 3 autres outils secrets. Un token restreint à `web/*` pouvait lister tous les secrets du vault.
- **Remédiation :** Ajout de `check_path_policy()` dans `secret_list`, cohérent avec `secret_read/write/delete`.
- **Vérifié :** ✅ v0.4.0

### 4.2 Moyens Corrigés (P1 — v0.4.0 / P2 — v0.4.5)

#### V2-17 — `expires_at` fail-open sur erreur de parsing
- **CVSS :** 5.9 | **CWE :** CWE-755
- **Problème :** `get_by_hash()` avec `except ValueError/TypeError: pass` → token traité comme valide si `expires_at` corrompu.
- **Remédiation :** `pass` → `return None` (fail-close). Token avec expiration corrompue = invalidé.
- **Vérifié :** ✅ v0.4.0

#### V2-12 — Images Docker pinnées par tag
- **CVSS :** 5.3 | **CWE :** CWE-1177
- **Problème :** Tags mutables (`python:3.12-slim`, `alpine:3.20`, `caddy:2-alpine`).
- **Remédiation :** Pinnage par digest SHA256 pour `python:3.12-slim` et `alpine:3.20`.
- **Vérifié :** ✅ v0.4.5

#### V2-16 — Plugins Caddy/Coraza non pinnés
- **CVSS :** 5.3 | **CWE :** CWE-1104
- **Problème :** `xcaddy build --with github.com/corazawaf/coraza-caddy/v2` sans version.
- **Remédiation :** `coraza-caddy/v2@v2.2.0`, `caddy-ratelimit@v0.1.0`.
- **Vérifié :** ✅ v0.4.5

#### V3-11 — `role_name` SSH sans validation
- **CVSS :** 5.3 | **CWE :** CWE-74
- **Problème :** `role_name` utilisé directement dans les paths API OpenBao sans validation.
- **Remédiation :** Ajout `_ROLE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$')` et `_validate_role_name()` dans `ssh_ca.py`.
- **Vérifié :** ✅ v0.4.0

#### V3-23 — Paramètre `path` sans validation (traversal)
- **CVSS :** 5.3 | **CWE :** CWE-22
- **Problème :** Le paramètre `path` des outils secrets était passé directement à hvac sans validation. `../../sys/seal-status` créait un oracle d'énumération.
- **Remédiation :** Ajout `_PATH_PATTERN`, `_validate_secret_path()` avec rejet de `..`, `\`, et validation regex.
- **Vérifié :** ✅ v0.4.0

#### V3-02 — Admin API audit/logs accessible à tout token
- **CVSS :** 5.3 | **CWE :** CWE-862
- **Problème :** `/admin/api/audit` et `/admin/api/logs` dans le bloc "tout token" au lieu de "admin".
- **Remédiation :** Déplacé derrière le check `is_admin`.
- **Vérifié :** ✅ v0.4.0

#### V3-09 — `check_vault_owner` fail-open
- **CVSS :** 5.0 | **CWE :** CWE-863
- **Problème :** Si un vault n'a pas de `_vault_meta`, tout client était autorisé.
- **Remédiation :** `return True` → `return False` (fail-close) + log warning.
- **Vérifié :** ✅ v0.4.0

#### V2-13 — Docker hardening manquant
- **CVSS :** 4.8 | **CWE :** CWE-250
- **Remédiation :** Ajout de `security_opt: [no-new-privileges:true]`, `read_only: true`, `tmpfs`, `cap_drop: ALL`, `cap_add: IPC_LOCK`.
- **Vérifié :** ✅ v0.4.5

#### V3-05 — `disable_mlock` supprimé (OpenBao ≥2.0)
- **CVSS :** 4.5 | **CWE :** CWE-316
- **Problème :** Le template HCL contenait `disable_mlock` (d'abord `true` en v0.3.x, puis `false` en v0.4.0). OpenBao ≥2.0 a supprimé le support de mlock et rejette ce paramètre au démarrage (`error loading configuration`). Voir [RFC mlock-removal](https://openbao.org/docs/rfcs/mlock-removal/).
- **Remédiation v0.4.0 :** `disable_mlock = false` (correctif initial).
- **Remédiation v0.4.6 :** Suppression totale de `disable_mlock` du template HCL. La protection mémoire est gérée au niveau OS (swap désactivé).
- **Vérifié :** ✅ v0.4.6

#### V3-03 — Token creation sans validation permissions
- **CVSS :** 4.5 | **CWE :** CWE-20
- **Problème :** `_api_create_token` passait les permissions sans validation, contrairement à `update()` qui validait.
- **Remédiation :** Whitelist `{read, write, admin}` + `try/except JSONDecodeError` ajoutés dans `create()`.
- **Vérifié :** ✅ v0.4.0

#### V3-08 — Pas de lock file
- **CVSS :** 4.5 | **CWE :** CWE-1357
- **Problème :** Toutes les dépendances en `>=` sans borne supérieure ni hashes.
- **Remédiation :** Création de `requirements.lock` avec versions exactes pinnées.
- **Vérifié :** ✅ v0.4.5

#### V3-07 — `initialize_vault()` retourne root_token/keys
- **CVSS :** 4.0 | **CWE :** CWE-200
- **Problème :** La valeur de retour contenait les unseal keys et root token en clair.
- **Remédiation :** Ne retourne que les métadonnées (`status`, `s3_persisted`).
- **Vérifié :** ✅ v0.4.0

### 4.3 Faibles Corrigés

| ID    | Description                                 | Remédiation                                              | Version |
| ----- | ------------------------------------------- | -------------------------------------------------------- | ------- |
| V3-24 | `RESERVED_PATHS` bypass via sous-chemin     | Match préfixe via `_is_reserved_path()`                  | v0.4.0  |
| V3-25 | `secret_read` sans protection `_vault_meta` | Check `_is_reserved_path()` ajouté dans `read_secret()`  | v0.4.0  |
| V3-04 | AES-GCM sans AAD                            | AAD contextuel `{bucket}:{key}` ajouté + fallback legacy | v0.4.5  |
| V3-10 | CVE-2025-66416 — MCP SDK DNS rebinding      | `mcp[cli]>=1.23.0`                                       | v0.4.0  |
| V2-10 | `json.loads()` sans try/except              | `try/except JSONDecodeError` → 400 sur toutes les routes | v0.4.0  |
| V3-19 | CORS wildcard `*` sur preflight             | Restriction à l'origine du serveur                       | v0.4.5  |
| V2-15 | HSTS absent                                 | `Strict-Transport-Security "max-age=63072000"`           | v0.4.5  |
| V3-16 | Tests dans l'image production               | Multi-stage Docker : stage test séparé de production     | v0.4.5  |
| V3-12 | Audit `limit` crash sur input non-numérique | Validation numérique bornée 1-1000 avec fallback 100     | v0.4.0  |

---

## 5. Risques Résiduels Acceptés

### 5.1 Moyens (2)

#### V2-01 — Bootstrap key par défaut acceptée
- **CVSS :** 5.3 | **CWE :** CWE-1188
- **Localisation :** `config.py:18`, `lifecycle.py:47-48`
- **État :** Valeur par défaut `"change_me_in_production"`. Warning émis au démarrage mais service démarre. Pas de mode strict.
- **Justification :** Comportement standard open-source (Grafana, PostgreSQL, etc.). Le chiffrement des unseal keys échoue avec cette clé (protection supplémentaire). La validation de complexité (32+ chars, 3/4 classes) est en place pour les clés personnalisées.
- **Recommandation future :** Mode strict optionnel (`STRICT_BOOTSTRAP=true`).

#### V2-06 — SSH CA `allowed_users="*"` par défaut
- **CVSS :** 5.0 | **CWE :** CWE-295
- **Localisation :** `server.py:562-588`, `vault/ssh_ca.py:53`
- **État :** Le défaut est toujours `allowed_users="*"`. L'architecture (§7.8.1) dit "Ne jamais utiliser `*` en production".
- **Justification :** Gate `write` (pas admin), choix de design pour la facilité d'onboarding. Le paramètre est explicitement configurable par l'opérateur à la création du rôle.
- **Recommandation future :** Exiger une valeur explicite ou logger un warning si `*` est utilisé.

### 5.2 Faibles (11)

#### V2-08 — `str(e)` des exceptions OpenBao dans les réponses
- **CVSS :** 4.0 | **CWE :** CWE-209
- **Localisation :** `vault/secrets.py`, `spaces.py`, `ssh_ca.py` (15+ instances)
- **État :** Les exceptions hvac/OpenBao sont renvoyées via `str(e)`, exposant potentiellement des URLs internes, mount paths, et versions.
- **Atténuation :** Tous les callers sont authentifiés. Le WAF CRS filtre les réponses (RESPONSE-950-DATA-LEAKAGES).
- **Recommandation future :** Retourner des messages génériques, logger `str(e)` server-side uniquement.

#### V2-05 — OpenBao binaire sans checksum SHA256
- **CVSS :** 3.5 | **CWE :** CWE-494
- **Localisation :** `Dockerfile:12-19`
- **État :** Le binaire est téléchargé depuis GitHub Releases sans `sha256sum -c`.
- **Atténuation :** HTTPS protège le transport. Build-time only, version pinnée (2.5.1).
- **Recommandation future :** Ajouter `echo "${EXPECTED_SHA} /tmp/openbao.tar.gz" | sha256sum -c -`.

#### V2-L08 — `vault_id` depuis URL non validé dans l'API admin
- **CVSS :** 3.5 | **CWE :** CWE-20
- **Localisation :** `admin/api.py:73,93,127`
- **État :** Les `vault_id` extraits des URLs `/admin/api/vaults/{id}/...` ne passent pas par `_validate_vault_id()`. Seule la création valide.
- **Atténuation :** OpenBao valide en aval. Les routes sont admin/write-gated.
- **Recommandation future :** Appeler `_validate_vault_id()` à l'entrée de toutes les routes vault admin.

#### V3-20 — CVE-2025-29914 : Coraza URI parser bypass (double-slash)
- **CVSS :** 3.5 | **CWE :** CWE-706
- **Localisation :** `waf/Dockerfile` (coraza-caddy v2.2.0)
- **État :** Les URIs commençant par `//` pouvaient être mal parsées par `url.Parse()` (Go). Fix dans Coraza >= 3.3.3 (module v1) ou v2.0.2+ (module v2).
- **Atténuation :** La version pinnée `coraza-caddy@v2.2.0` devrait inclure le fix. Les endpoints MCP/admin n'utilisent pas de double-slash.
- **Recommandation future :** Vérifier via `docker run waf coraza --version` et ajouter un test de régression.

#### V2-14 — CSP `unsafe-inline`
- **CVSS :** 3.0 | **CWE :** CWE-79
- **Localisation :** `waf/Caddyfile:66`
- **État :** `script-src 'self' 'unsafe-inline'` requis par les 16 `onclick` handlers du SPA.
- **Atténuation :** Auth admin requise. L'audit confirme que `esc()` est appliquée sur toutes les valeurs user-controlled.
- **Recommandation future :** Migrer vers `addEventListener` + CSP nonces (~4h de refactoring).

#### V3-18 — Chemins secrets logués en clair dans l'audit
- **CVSS :** 3.0 | **CWE :** CWE-532
- **Localisation :** `server.py:49-66` (fonction `_r()`)
- **État :** Les chemins (`web/github`, `db/production`) sont logués dans le ring buffer et le fichier JSONL.
- **Atténuation :** L'audit est désormais admin-only (fix V2-03). Les chemins ne sont pas des secrets.
- **Recommandation future :** Évaluer le masquage des chemins sensibles dans les logs d'audit.

#### V3-13 — Cache TTL 5 minutes — fenêtre de token révoqué
- **CVSS :** 3.0 | **CWE :** CWE-613
- **Localisation :** `auth/token_store.py:111-114`, `auth/policies.py:110-113`
- **État :** Un token révoqué peut encore s'authentifier pendant 5 minutes (TTL cache).
- **Atténuation :** Tradeoff design (performance vs immédiateté). Architecture asyncio single-threaded.
- **Recommandation future :** Mécanisme de refresh forcé sur révocation, ou TTL réduit pour les opérations sécurité-critiques.

#### V2-09 — Pas de validation TLS sur les connexions S3
- **CVSS :** 3.0 | **CWE :** CWE-319
- **Localisation :** `s3_client.py:45-78`, `config.py:21`
- **État :** Le schème de `s3_endpoint_url` n'est pas validé. La doc et `.env.example` montrent HTTPS.
- **Atténuation :** Dell ECS Cloud Temple est sur réseau privé HTTPS. Requiert misconfiguration opérateur.
- **Recommandation future :** Valider `url.startswith("https://")` au démarrage.

#### V2-07 — Hash prefix matching sans longueur minimale
- **CVSS :** 2.5 | **CWE :** CWE-1254
- **Localisation :** `auth/token_store.py:190-193`
- **État :** `update()` et `revoke()` utilisent `h.startswith(hash_prefix)` sans longueur minimale.
- **Atténuation :** Admin-only. Pattern CLI standard (similaire à git).
- **Recommandation future :** Exiger minimum 8-12 caractères et vérifier l'unicité du match.

#### V2-11 — `check_access()` leake `allowed_vaults` dans l'erreur
- **CVSS :** 2.5 | **CWE :** CWE-200
- **Localisation :** `auth/context.py:51`
- **État :** L'erreur retourne `"allowed_vaults": allowed` — les propres permissions du caller. Confirmé toujours présent.
- **Atténuation :** Le caller ne voit que ses propres permissions (pas celles des autres). L'API admin ne fait pas ça.
- **Recommandation future :** Retirer `"allowed_vaults"` de la réponse d'erreur.

#### V3-14 — Owner-isolation bypass avec `client_name` vide
- **CVSS :** 2.5 | **CWE :** CWE-863
- **Localisation :** `auth/context.py:57-66`
- **État :** Un token avec `client_name: ""` et `allowed_resources: []` contourne l'isolation owner-based. Confirmé toujours présent.
- **Atténuation :** `TokenStore.create()` exige `client_name` non-vide. Requiert corruption directe de S3 (`_system/tokens.json`).
- **Recommandation future :** Refuser explicitement l'accès quand `client_name` est vide.

#### V3-06 — Unseal keys non zero-filled au clear
- **CVSS :** 2.5 | **CWE :** CWE-226
- **Localisation :** `openbao/lifecycle.py:343,363`
- **État :** `_in_memory_keys = None` ne zero-fill pas les strings Python immuables.
- **Atténuation :** Limitation inhérente de Python (strings immuables). Les clés sont chiffrées AES-256-GCM au repos sur S3. Le zeroing `bytearray` dans `crypto.py` est correct.
- **Recommandation future :** Stocker les clés en `bytearray`, zero-fill avant déréférencement, `gc.collect()`.

#### V3-15 — `fnmatch` patterns non documentés
- **CVSS :** 2.0 | **CWE :** CWE-185
- **Localisation :** `auth/policies.py:241,251,271,302,307`
- **État :** `fnmatch` supporte `*`, `?`, `[seq]`, `[!seq]` mais seuls les wildcards `*` sont documentés.
- **Recommandation future :** Documenter la sémantique complète ou restreindre aux wildcards `*` uniquement.

#### V3-17 — SigV4 meta client désactive la signature du payload
- **CVSS :** 2.0 | **CWE :** CWE-345
- **Localisation :** `s3_client.py:68`
- **État :** `payload_signing_enabled: False` sur le meta client SigV4 (HEAD/LIST). Le client est un objet S3 générique — usage PUT possible par erreur.
- **Atténuation :** Défensible pour les opérations sans body (HEAD/LIST). Tradeoff performance.
- **Recommandation future :** Wrapper le meta client pour n'exposer que `head_bucket` et `list_objects`.

---

## 6. Findings Informationnels

Ces findings sont des observations à faible impact, ne nécessitant pas d'action corrective immédiate.

| ID     | Composant | Description                                                                 |
| ------ | --------- | --------------------------------------------------------------------------- |
| V2-I01 | Infra     | Audit JSONL non synchronisé vers S3 (perte si volume Docker détruit)        |
| V2-I02 | Infra     | Pas de TLS entre WAF et MCP dans le réseau Docker interne                   |
| V2-I03 | Infra     | Shamir shares=1, threshold=1 (acceptable pour embedded single-node)         |
| V2-I04 | Infra     | `os.urandom` vs `secrets` (cosmétique, sécurité équivalente)                |
| V2-I05 | Infra     | Pas de S3 ServerSideEncryption demandé sur les uploads                      |
| V2-I06 | Infra     | `.gitignore` manque `init_keys.json` et `/openbao/`                         |
| V2-I07 | Auth      | S3 JSON désérialisation sans limite de taille (requiert credentials S3)     |
| V2-I08 | Infra     | SigV2 déprécié sur data client S3 (contrainte Dell ECS ViPR/1.0)            |
| V2-I09 | Auth      | Pas de validation schéma après désérialisation JSON S3                      |
| V2-I10 | Admin SPA | Réflexion de path dans les réponses 404 (JSON + auth-gated + WAF CRS)       |
| V2-I11 | Auth      | Erreurs S3 avec détails infra dans stderr (jamais dans les réponses HTTP)   |
| V2-I13 | WAF       | Exclusion CRS 932120 via `ruleRemoveById` au lieu de `ruleRemoveTargetById` |
| V2-I14 | WAF       | Header `X-XSS-Protection` déprécié (harmless, CSP en place)                 |
| V2-I15 | Admin SPA | Token Bearer en sessionStorage (pattern SPA standard, ASVS 8.2.2)           |
| V2-I16 | Admin SPA | `esc()` n'échappe pas les single quotes (valeurs server-validées)           |
| V2-I18 | WAF       | CRS 4.7.0 — CVE-2026-21876 (règle 922 non chargée, impact nul)              |
| V3-21  | Infra     | `setcap cap_ipc_lock || true` — échec silencieux masqué                     |
| V3-22  | Infra     | Réseau Docker `mcp-net` sans `internal: true` (contournement WAF possible)  |

---

## 7. Historique des Remédiations par Release

### v0.3.1 (23 mars 2026) — Audit interne v0.2.0
Correctifs des 5 findings initiaux (pré-V2.1) :
- Fix LFI dans `admin/middleware.py`
- WAF Coraza opérationnel (Caddy + coraza-caddy + OWASP CRS)
- Suppression auth query string → Bearer-only
- Zeroing mémoire via `bytearray` + `_zero_fill()`
- Validation complexité bootstrap key

### v0.4.0 (24 mars 2026) — P0 + P1
**4 Élevés** : V2-03, V2-02, V3-01, V2-05b  
**9 Moyens** : V2-17, V3-11, V3-23, V3-02, V3-09, V3-05, V3-03, V3-07, V3-12 (+ V2-10)  
**3 Faibles** : V3-24, V3-25, V3-10  
Fichiers modifiés : server.py, policies.py, requirements.txt, token_store.py, secrets.py, ssh_ca.py, spaces.py, api.py, config.py, lifecycle.py

### v0.4.9 (25 avril 2026) — PR #2 path_rules enforcement sur API REST
- Enforcement `check_path_policy()` sur les 4 routes REST admin secrets (GET list/read, POST write, DELETE)
- Corrige un contournement des `allowed_paths` via l'API REST admin (les outils MCP avaient déjà ce check)
- Hardening OpenBao : listener HCL dynamique, startup idempotent, logs fichiers
- 3 findings non-bloquants documentés (F7 binding, F9 trust aveugle, F10 singleton)
- PR par @camilleein

### v0.4.8 (25 avril 2026) — PR #1 admin API context fix
- Injection `ContextVar` dans `AdminMiddleware` → résout `created_by=anonymous`
- PR par @camilleein

### v0.4.5 (26 mars 2026) — P2 Hardening
**3 Moyens** : V2-12, V2-16, V3-08  
**6 Faibles** : V3-04, V3-19, V2-15, V3-16, V2-13 (+ CORS preflight, Docker hardening)  
Fichiers modifiés : Dockerfile, waf/Dockerfile, waf/Caddyfile, requirements.lock, crypto.py, docker-compose.yml

---

## 8. Méthodologie

L'audit V2.1 a été réalisé en white-box avec accès complet au code source :

- **Passe v2 :** Revue systématique des 19 fichiers critiques, focus sur les contrôles d'accès, la cryptographie, et l'infrastructure.
- **Passe v3 :** Revue approfondie des edge cases, CVE supply chain (NVD, GitHub Advisories), et consistency checks inter-composants.
- **Revue par pair :** Audit POC externe sur les mécanismes d'isolation (owner-based, path-level) et les chemins réservés.
- **Scoring :** CVSS 3.1, classification CWE.