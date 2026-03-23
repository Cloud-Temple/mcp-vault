# Catalogue des Tests E2E — MCP Vault

> **Version** : v0.3.1 — Phase sécurité (audit + correctifs critiques + WAF Coraza)
> **Dernière exécution** : ~295 assertions au total (14 catégories e2e + 16 tests crypto)
> **Durée** : ~5 secondes (e2e) + <1s (crypto)
> **Environnement** : Docker (OpenBao embedded + S3 Dell ECS + WAF Caddy/Coraza CRS v4)

---

## 1. Système (7 tests)

**Objectif** : Vérifier que le service MCP Vault démarre correctement et que tous ses composants internes (OpenBao pour le chiffrement, S3 pour la persistance) sont opérationnels. C'est le premier contrôle qu'un opérateur ou un agent IA effectue avant toute interaction. Un service dégradé (OpenBao sealed ou S3 inaccessible) doit être détecté immédiatement.

| #   | Test                     | Comportement attendu                                    |
| --- | ------------------------ | ------------------------------------------------------- |
| 1.1 | `system_health`          | Retourne `status=ok`, OpenBao `unsealed`, S3 accessible |
| 1.2 | OpenBao status           | `ok` avec détail "unsealed, initialized"                |
| 1.3 | S3 status                | `ok` avec nom du bucket                                 |
| 1.4 | `system_about` — nom     | Retourne `mcp-vault`                                    |
| 1.5 | `system_about` — version | Version présente (ex: `0.2.0`)                          |
| 1.6 | Nombre d'outils MCP      | > 10 (24 actuellement)                                  |
| 1.7 | Adresse OpenBao          | Présente dans la réponse                                |

---

## 2. Vaults CRUD (25 tests)

**Objectif** : Valider le cycle de vie complet d'un coffre de secrets — création, consultation, mise à jour et suppression. Chaque vault correspond à un mount KV v2 dans OpenBao. On vérifie aussi les métadonnées automatiques (`created_at`, `created_by`) qui servent à l'isolation owner-based, ainsi que la protection contre les suppressions accidentelles (confirm requis).

| #    | Test                                   | Comportement attendu                                      |
| ---- | -------------------------------------- | --------------------------------------------------------- |
| 2.1  | Créer vault `alpha`                    | `status=created`                                          |
| 2.2  | Métadonnées `created_at`               | Timestamp ISO présent                                     |
| 2.3  | Métadonnées `created_by`               | Nom du créateur présent                                   |
| 2.4  | Créer vault `beta`                     | `status=created`                                          |
| 2.5  | Créer vault `gamma` (sans description) | `status=created`                                          |
| 2.6  | Lister les vaults                      | Les 3 vaults sont visibles                                |
| 2.7  | `alpha` dans la liste                  | ✅                                                        |
| 2.8  | `beta` dans la liste                   | ✅                                                        |
| 2.9  | `gamma` dans la liste                  | ✅                                                        |
| 2.10 | Info vault `alpha`                     | `vault_id`, `created_at`, `created_by`, `secrets_count=0` |
| 2.11 | Update description vault               | `status=updated`, description changée                     |
| 2.12 | `updated_at` / `updated_by`            | Présents après update                                     |
| 2.13 | Vérification description après update  | Reflète la nouvelle valeur                                |
| 2.14 | Update vault inexistant                | `status=error`                                            |
| 2.15 | Delete sans `confirm=True`             | `status=error` (sécurité)                                 |
| 2.16 | Delete avec `confirm=True`             | `status=deleted`                                          |
| 2.17 | Vault supprimé absent du listing       | ✅                                                        |
| 2.18 | Info sur vault inexistant              | `status=error`                                            |

---

## 3. Secrets CRUD — 14 types (24 tests)

**Objectif** : Vérifier que les secrets peuvent être écrits, lus, listés et supprimés dans un vault. MCP Vault supporte 14 types de secrets inspirés de 1Password (login, database, api_key, etc.), chacun avec des champs spécifiques et un enrichissement automatique (`_type`, `_tags`, `_created_at`). On s'assure que les données écrites sont restituées fidèlement.

| #        | Test                            | Comportement attendu                                                                                                            |
| -------- | ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| 3.1–3.10 | Écriture de 10 types de secrets | `status=ok` pour chaque type (login, database, api_key, password, secure_note, server, certificate, env_file, custom, identity) |
| 3.11     | Lecture `web/github` (login)    | Champs `username`, `password`, `url` corrects                                                                                   |
| 3.12     | Vérification `_type=login`      | Type enrichi automatiquement                                                                                                    |
| 3.13     | Vérification `_tags`            | Tags "prod,github" présents                                                                                                     |
| 3.14     | Lecture `db/postgres-prod`      | Host correct                                                                                                                    |
| 3.15     | Lecture `api/openai`            | Clé API correcte                                                                                                                |
| 3.16     | Liste tous les secrets          | ≥ 5 préfixes de dossiers                                                                                                        |
| 3.17     | Liste avec préfixe `web/`       | Filtre fonctionnel                                                                                                              |
| 3.18     | Suppression d'un secret         | `status=deleted`                                                                                                                |
| 3.19     | Lecture après suppression       | `status=error`                                                                                                                  |

---

## 4. Versioning & Rotation (8 tests)

**Objectif** : Valider le versioning natif de KV v2. Chaque écriture sur un même chemin crée une nouvelle version. On doit pouvoir lire n'importe quelle version passée (utile pour la rotation de credentials ou le rollback). C'est une garantie d'auditabilité : aucune donnée n'est écrasée silencieusement.

| #   | Test                          | Comportement attendu              |
| --- | ----------------------------- | --------------------------------- |
| 4.1 | Écriture v1                   | `status=ok`, `version=1`          |
| 4.2 | Écriture v2 (rotation)        | `version=2`, `v2 > v1`            |
| 4.3 | Écriture v3                   | `status=ok`                       |
| 4.4 | Lecture dernière version      | Retourne v3 (`key=key-version-3`) |
| 4.5 | Lecture version spécifique v1 | Retourne v1 (`key=key-version-1`) |

---

## 5. Générateur de mots de passe CSPRNG (14 tests)

**Objectif** : S'assurer que le générateur de mots de passe utilise un source cryptographiquement sûre (CSPRNG — `secrets` Python) et respecte les contraintes demandées (longueur, jeu de caractères, exclusions). L'unicité entre deux appels consécutifs prouve l'absence de seed prévisible. Les agents IA utilisent cet outil pour provisionner des credentials aléatoires.

| #   | Test                              | Comportement attendu                        |
| --- | --------------------------------- | ------------------------------------------- |
| 5.1 | Longueur 24 (défaut)              | Exactement 24 caractères                    |
| 5.2 | Longueur 8 (minimum)              | ≥ 8 caractères                              |
| 5.3 | Longueur 128 (maximum)            | Exactement 128 caractères                   |
| 5.4 | Sans symboles                     | Seulement alphanumériques                   |
| 5.5 | Sans majuscules                   | Aucune lettre majuscule                     |
| 5.6 | Chiffres uniquement               | Que des digits 0-9                          |
| 5.7 | Exclusion de caractères (`lI10O`) | Aucun caractère exclu présent               |
| 5.8 | Unicité CSPRNG                    | 2 mots de passe consécutifs sont différents |

---

## 6. Isolation inter-vaults (7 tests)

**Objectif** : Prouver que deux vaults distincts sont hermétiquement cloisonnés. Un secret écrit dans le vault alpha ne doit jamais apparaître dans beta, même via le listing ou une lecture directe croisée. C'est la garantie de base du multi-tenancy.

| #   | Test                                                | Comportement attendu         |
| --- | --------------------------------------------------- | ---------------------------- |
| 6.1 | Écriture dans vault `alpha`                         | `status=ok`                  |
| 6.2 | Écriture dans vault `beta`                          | `status=ok`                  |
| 6.3 | Liste `alpha` ne contient pas les secrets de `beta` | ✅                           |
| 6.4 | Liste `beta` ne contient pas les secrets de `alpha` | ✅                           |
| 6.5 | Lecture secret `alpha` depuis `alpha`               | `status=ok`, valeur correcte |
| 6.6 | Lecture secret `alpha` depuis `beta`                | `status=error` (isolation)   |

---

## 7. Gestion d'erreurs (10 tests)

**Objectif** : Vérifier que le service se comporte correctement face à des entrées invalides, des ressources inexistantes ou des opérations interdites. Aucune de ces situations ne doit provoquer de crash. Le chemin réservé `_vault_meta` (métadonnées internes) doit être protégé contre toute manipulation directe.

| #    | Test                                 | Comportement attendu    |
| ---- | ------------------------------------ | ----------------------- |
| 7.1  | Lecture dans vault inexistant        | `status=error`          |
| 7.2  | Écriture dans vault inexistant       | `status=error`          |
| 7.3  | Lecture secret inexistant            | `status=error`          |
| 7.4  | Suppression secret inexistant        | Pas de crash            |
| 7.5  | Création vault doublon               | `status=error`          |
| 7.6  | Liste vault vide                     | Pas de crash, `keys=[]` |
| 7.7  | Écriture sur `_vault_meta` (réservé) | **REFUSÉ**              |
| 7.8  | Suppression de `_vault_meta`         | **REFUSÉ**              |
| 7.9  | `_vault_meta` invisible dans listing | ✅                      |
| 7.10 | Type de secret invalide              | `status=error`          |

---

## 8. Synchronisation S3 (3 tests)

**Objectif** : Vérifier que le file backend OpenBao est bien synchronisé vers S3 (source de vérité froide). En cas de crash du conteneur, les données doivent pouvoir être restaurées depuis cette archive. Le sync se fait toutes les 60 secondes + au shutdown.

| #   | Test                                    | Comportement attendu |
| --- | --------------------------------------- | -------------------- |
| 8.1 | `HEAD bucket` accessible                | HTTP 200             |
| 8.2 | Archive(s) présente(s) dans `_storage/` | ≥ 1 objet            |
| 8.3 | `openbao-data.tar.gz` existe            | Taille > 100 bytes   |

---

## 9. SSH Certificate Authority (33 tests)

**Objectif** : Valider le fonctionnement complet de la CA SSH intégrée — création de CA par vault, rôles multiples, signature de clés ed25519, isolation cryptographique entre vaults (chaque vault a sa propre CA), et nettoyage automatique lors de la suppression d'un vault. Remplace les clés SSH statiques par des certificats éphémères (TTL court).

| #    | Test                                      | Comportement attendu                           |
| ---- | ----------------------------------------- | ---------------------------------------------- |
| 9.1  | Setup CA + rôle `adminct`                 | `status=ok`, vault_id et role_name retournés   |
| 9.2  | Setup 2ème rôle `agentic`                 | `status=ok`                                    |
| 9.3  | Clé publique CA                           | Format SSH valide (`ssh-rsa ...`)              |
| 9.4  | Liste des rôles                           | ≥ 2 rôles configurés                           |
| 9.5  | Info rôle `adminct`                       | `key_type=ca`, `default_user`, `allowed_users` |
| 9.6  | Info rôle `agentic`                       | `allowed_users=agentic,iaagentic`              |
| 9.7  | Signature clé ed25519 (adminct)           | `signed_key` non vide, `serial_number` présent |
| 9.8  | Signature clé ed25519 (agentic)           | `status=ok`                                    |
| 9.9  | Signature avec rôle inexistant            | `status=error`                                 |
| 9.10 | Signature avec clé invalide               | `status=error`                                 |
| 9.11 | Info rôle inexistant                      | `status=error`                                 |
| 9.12 | **Isolation crypto** : CA alpha ≠ CA beta | Clés publiques différentes                     |
| 9.13 | Liste rôles vault sans CA                 | `status=error` ou liste vide                   |
| 9.14 | Suppression vault → CA nettoyée           | CA inaccessible après suppression              |

---

## 10. Types de secrets (16 tests)

**Objectif** : Vérifier que le catalogue complet des 14 types de secrets est disponible via l'API MCP. Chaque type (login, database, api_key, ssh_key, certificate, etc.) définit des champs requis et optionnels qui guident les agents IA lors de l'écriture de secrets structurés.

| #          | Test                | Comportement attendu                                                                                                                        |
| ---------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| 10.1       | `secret_types`      | Retourne 14 types                                                                                                                           |
| 10.2–10.15 | Chaque type présent | login, password, secure_note, api_key, ssh_key, database, server, certificate, env_file, credit_card, identity, wifi, crypto_wallet, custom |

---

## 11. Admin API REST (15 tests)

**Objectif** : Valider l'interface REST d'administration (`/admin/api`), distincte du protocole MCP. Elle est utilisée par la console web SPA et les outils de supervision. On teste le health check, l'introspection du token (whoami), la génération de mots de passe, et l'accès aux logs.

| #         | Test                                         | Comportement attendu           |
| --------- | -------------------------------------------- | ------------------------------ |
| 11.1      | `GET /admin/api/health`                      | `status=ok`, `tools_count > 0` |
| 11.2      | `GET /admin/api/whoami`                      | `client_name` présent          |
| 11.3      | `GET /admin/api/generate-password`           | 24 chars, `status=ok`          |
| 11.4      | Unicité CSPRNG (2 mots de passe)             | Différents                     |
| 11.5–11.8 | Complexité (maj + min + chiffres + symboles) | Tous présents                  |
| 11.9      | `GET /admin/api/logs`                        | `count >= 0`                   |

---

## 12. Policies MCP — CRUD (43 tests)

**Objectif** : Tester le cycle de vie complet des policies de contrôle d'accès — création, lecture, listing et suppression. Une policy définit quels outils MCP sont autorisés/interdits (via wildcards fnmatch) et quelles règles s'appliquent par vault. On vérifie aussi la validation stricte des entrées (ID invalide, doublon, permissions incorrectes).

| #     | Test                                             | Comportement attendu                              |
| ----- | ------------------------------------------------ | ------------------------------------------------- |
| 12.1  | Liste initiale                                   | `status=ok`, comptage initial                     |
| 12.2  | Créer policy `test-readonly`                     | `status=created`, `allowed_tools`, `denied_tools` |
| 12.3  | Créer policy `test-ssh-only` (wildcards `ssh_*`) | `status=created`                                  |
| 12.4  | Créer policy avec `path_rules`                   | 2 règles, patterns et permissions corrects        |
| 12.5  | Liste après création                             | +3 policies                                       |
| 12.6  | Lecture détaillée d'une policy                   | Tous les champs présents                          |
| 12.7  | Policy inexistante                               | `status=error`                                    |
| 12.8  | Doublon                                          | `status=error`                                    |
| 12.9  | ID invalide (espaces)                            | `status=error`                                    |
| 12.10 | ID trop long (65 chars)                          | `status=error`                                    |
| 12.11 | `path_rule` sans `vault_pattern`                 | `status=error`                                    |
| 12.12 | Permission invalide (`destroy`)                  | `status=error`                                    |
| 12.13 | Delete sans confirm                              | `status=error`                                    |
| 12.14 | Delete policy inexistante                        | `status=error`                                    |
| 12.15 | Delete effective                                 | `status=deleted`                                  |
| 12.16 | Admin API policies list                          | `status=ok`                                       |
| 12.17 | Admin API policy detail                          | `policy_id` correct                               |
| 12.18 | Admin API policy 404                             | HTTP 404                                          |

---

## 13. Enforcement — Isolation & Policies (56 tests)

**Objectif** : C'est le test le plus critique du point de vue sécurité. Il valide les 3 couches de contrôle d'accès empilées : isolation par propriétaire (owner-based), partage sélectif entre utilisateurs (vault-level), restriction au niveau secret (path-level), et enforcement des policies (tool-level). Chaque sous-section simule un scénario réaliste multi-utilisateurs.

### 13a. Owner-based isolation (11 tests)

**Objectif** : Un token sans liste de vaults explicite (`allowed_resources=[]`) ne voit que les vaults qu'il a créés lui-même. C'est le comportement par défaut, qui empêche tout accès croisé accidentel.

| #    | Test                                    | Comportement attendu                          |
| ---- | --------------------------------------- | --------------------------------------------- |
| 13.1 | Token créé avec `allowed_resources=[]`  | `status=created`                              |
| 13.2 | Lecture vault admin → **REFUSÉ**        | `status=error` (pas propriétaire)             |
| 13.3 | Agent crée son vault                    | `status=created` (il en devient propriétaire) |
| 13.4 | Agent écrit dans son vault              | `status=ok`                                   |
| 13.5 | Agent lit son vault                     | `status=ok`                                   |
| 13.6 | `vault_list` ne retourne que ses vaults | Vault admin absent de la liste                |

### 13b. Partage cross-user vault-level (8 tests)

**Objectif** : Deux utilisateurs (Alice et Bob) créent chacun 2 vaults (privé + partagé). L'admin partage explicitement le vault "shared" de chacun avec l'autre. On vérifie que chaque utilisateur accède au vault partagé de l'autre mais PAS au vault privé.

> **Scénario** : Alice et Bob créent chacun 2 vaults (`private` + `shared`).
> L'admin partage le vault `shared` de chacun avec l'autre.

| #     | Test                    | Comportement attendu                                                 |
| ----- | ----------------------- | -------------------------------------------------------------------- |
| 13.7  | Alice lit `bob-shared`  | ✅ `status=ok`, voit "bob-shared"                                    |
| 13.8  | Alice lit `bob-private` | ❌ `status=error` (pas dans sa liste)                                |
| 13.9  | Bob lit `alice-shared`  | ✅ `status=ok`, voit "alice-shared"                                  |
| 13.10 | Bob lit `alice-private` | ❌ `status=error`                                                    |
| 13.11 | `vault_list` Alice      | Voit `alice-private + alice-shared + bob-shared` (pas `bob-private`) |
| 13.12 | `vault_list` Bob        | Voit `bob-private + bob-shared + alice-shared` (pas `alice-private`) |

### 13c. Path-level enforcement — accès par secret (7 tests)

**Objectif** : Dans un vault partagé contenant plusieurs secrets, une policy avec `allowed_paths` restreint l'accès à certains chemins seulement (ex: `shared/*`). On vérifie qu'Alice peut lire `shared/for-other` chez Bob mais PAS `private/secret1` ni `private/secret2`.

> **Scénario** : Dans le vault partagé, chacun écrit 3 secrets :
> `shared/for-other`, `private/secret1`, `private/secret2`.
> Une policy restreint l'accès aux chemins `shared/*` uniquement.

| #     | Test                                        | Comportement attendu                 |
| ----- | ------------------------------------------- | ------------------------------------ |
| 13.13 | Alice lit `bob-shared` → `shared/for-other` | ✅ Autorisé (path matche `shared/*`) |
| 13.14 | Alice lit `bob-shared` → `private/secret1`  | ❌ **REFUSÉ** (path ne matche pas)   |
| 13.15 | Alice lit `bob-shared` → `private/secret2`  | ❌ **REFUSÉ**                        |
| 13.16 | Bob lit `alice-shared` → `shared/for-other` | ✅ Autorisé                          |
| 13.17 | Bob lit `alice-shared` → `private/secret1`  | ❌ **REFUSÉ**                        |

### 13d. Policy tool-level enforcement (20+ tests)

**Objectif** : Tester l'enforcement des outils MCP via les policies. Une policy `deny-write` bloque `secret_write`/`secret_delete`/`vault_create` mais autorise `vault_list` et `secret_read`. Une policy `readonly-only` avec `allowed_tools` restrictif ne permet que les opérations de lecture. Le retrait de la policy restaure l'accès complet.

| #     | Test                                            | Comportement attendu      |
| ----- | ----------------------------------------------- | ------------------------- |
| 13.18 | Assigner policy `deny-write`                    | `status=updated`          |
| 13.19 | `secret_write` → **REFUSÉ**                     | Message contient "policy" |
| 13.20 | `secret_delete` → **REFUSÉ**                    | `status=error`            |
| 13.21 | `vault_create` → **REFUSÉ**                     | `status=error`            |
| 13.22 | `vault_list` → autorisé                         | `status=ok`               |
| 13.23 | `secret_read` → autorisé                        | `status=ok`               |
| 13.24 | `system_health` → autorisé (exempté)            | `status=ok`               |
| 13.25 | Changer vers policy `readonly-only`             | `status=updated`          |
| 13.26 | `vault_list` → autorisé                         | `status=ok`               |
| 13.27 | `secret_read` → autorisé                        | `status=ok`               |
| 13.28 | `secret_write` → **REFUSÉ**                     | `status=error`            |
| 13.29 | `vault_create` → **REFUSÉ**                     | `status=error`            |
| 13.30 | `ssh_ca_list_roles` → **REFUSÉ**                | `status=error`            |
| 13.31 | Retirer la policy                               | `policy_id=""`            |
| 13.32 | `secret_write` → autorisé (plus de restriction) | `status=ok`               |

### 13e. Token update & Admin API (10 tests)

**Objectif** : Vérifier que les modifications de token (permissions, vaults autorisés, policy assignée) fonctionnent via l'outil MCP et l'Admin API REST, et que les erreurs (hash inexistant, policy introuvable) sont correctement gérées.

| #     | Test                                  | Comportement attendu    |
| ----- | ------------------------------------- | ----------------------- |
| 13.33 | Modifier permissions via MCP          | `status=updated`        |
| 13.34 | Modifier vaults autorisés via MCP     | `status=updated`        |
| 13.35 | Hash inexistant                       | `status=error`          |
| 13.36 | Policy inexistante                    | `status=error`          |
| 13.37 | Admin API PUT token update            | `status=updated`        |
| 13.38 | Admin API token list avec `policy_id` | Visible dans le listing |

---

## 14. Audit Log (31 tests)

**Objectif** : Valider le journal d'audit qui trace toutes les opérations MCP. Chaque action génère une entrée horodatée avec le client, l'outil, le vault, le statut et un détail lisible. Les filtres combinables (catégorie, outil, statut, date) permettent l'investigation. Les événements "denied" (refus de policy) doivent être loggés pour détecter les tentatives d'accès non autorisées.

| #     | Test                                          | Comportement attendu                                     |
| ----- | --------------------------------------------- | -------------------------------------------------------- |
| 14.1  | `audit_log` basique                           | Entrées présentes, `total_in_buffer > 0`                 |
| 14.2  | Structure d'une entrée                        | `ts`, `client`, `tool`, `category`, `status`, `vault_id` |
| 14.3  | Catégorie valide                              | Parmi `system, vault, secret, ssh, policy, token, audit` |
| 14.4  | Filtre `category=vault`                       | Toutes les entrées sont `vault`                          |
| 14.5  | Filtre `tool=secret_*` (wildcard)             | Toutes commencent par `secret_`                          |
| 14.6  | Filtre `status=ok`                            | Tous les status sont `ok`                                |
| 14.7  | Filtre combiné `category+status`              | Intersection correcte                                    |
| 14.8  | Stats `by_category`, `by_status`, `by_client` | Présentes et non vides                                   |
| 14.9  | Filtre `since` (date future)                  | 0 résultat                                               |
| 14.10 | Limite respectée (`limit=3`)                  | ≤ 3 entrées                                              |
| 14.11 | Admin API `/audit`                            | `status=ok`, entrées présentes                           |
| 14.12 | Admin API filtre                              | `category=vault&limit=5` fonctionne                      |
| 14.13 | Événements `denied` loggés                    | ≥ 1 refus de policy dans l'audit                         |

---

## Résumé des couches de sécurité testées

```
┌─────────────────────────────────────────────────────┐
│  Couche 1 — VAULT-LEVEL                             │
│  allowed_resources=[] → owner-based (created_by)    │
│  allowed_resources=["v1","v2"] → liste explicite    │
│  Admin → accès total                                │
├─────────────────────────────────────────────────────┤
│  Couche 2 — TOOL-LEVEL (Policies)                   │
│  denied_tools: ["secret_write", "ssh_*"]            │
│  allowed_tools: ["system_*", "secret_read"]         │
│  Wildcards fnmatch, denied prioritaire              │
├─────────────────────────────────────────────────────┤
│  Couche 3 — PATH-LEVEL (Policies path_rules)        │
│  allowed_paths: ["shared/*"]                        │
│  Restreint l'accès à des chemins spécifiques        │
│  dans un vault partagé                              │
└─────────────────────────────────────────────────────┘
```

---

## 15. Cryptographie et Sécurité — `test_crypto.py` (16 tests)

> ⚠️ Ces tests sont dans un fichier séparé (`tests/test_crypto.py`), pas dans `test_e2e.py`.

**Objectif** : Valider le module de chiffrement AES-256-GCM utilisé pour sécuriser les clés unseal d'OpenBao, et les contrôles de sécurité ajoutés en v0.3.1 (validation entropie, zeroing mémoire).

| #    | Test                                  | Comportement attendu                                     |
| ---- | ------------------------------------- | -------------------------------------------------------- |
| 15.1 | Roundtrip simple                      | Chiffrer puis déchiffrer retourne le texte original      |
| 15.2 | Roundtrip JSON (clés unseal)          | Structure JSON restituée fidèlement                      |
| 15.3 | Mauvaise clé                          | `ValueError` avec message explicite                      |
| 15.4 | Données corrompues / trop courtes     | `ValueError`                                             |
| 15.5 | Base64 invalide                       | `ValueError`                                             |
| 15.6 | Clé trop courte (<32 chars)           | `ValueError` avec suggestion `secrets.token_urlsafe`     |
| 15.7 | Clé vide (encrypt + decrypt)          | `ValueError`                                             |
| 15.8 | Unicité CSPRNG                        | 2 chiffrements identiques → résultats différents         |
| 15.9 | Payload 10 KB                         | Roundtrip OK, taille préservée                           |
| 15.10 | Unicode (emojis, accents, CJK)       | Roundtrip fidèle                                         |
| 15.11 | Clés valides acceptées               | ≥32 chars, 3+ classes → `(True, "OK")`                  |
| 15.12 | Valeur par défaut rejetée            | `change_me_in_production` → `(False, "...")`             |
| 15.13 | Clé trop courte rejetée              | <32 chars → `(False, "...")`                             |
| 15.14 | Faible diversité rejetée             | Seulement 2 classes de chars → `(False, "...")`          |
| 15.15 | Patterns répétitifs rejetés          | Trop de caractères identiques → `(False, "...")`         |
| 15.16 | `_zero_fill()` efface la mémoire     | Tous les bytes à 0 après appel                           |

---

## Comment lancer les tests

```bash
# ── Méthode 1 — Dans le conteneur (recommandé) ──

# Suite e2e complète (~295 tests, ~5s)
docker compose exec mcp-vault python tests/test_e2e.py

# Un groupe spécifique
docker compose exec mcp-vault python tests/test_e2e.py --test enforcement
docker compose exec mcp-vault python tests/test_e2e.py --test ssh_ca
docker compose exec mcp-vault python tests/test_e2e.py --test policies

# Mode démo visuel (pour /admin)
docker compose exec mcp-vault python tests/test_e2e.py --demo

# ── Méthode 2 — Depuis l'hôte via le WAF (:8085) ──

# Exporter les variables .env (OBLIGATOIRE)
set -a && source .env && set +a

# Lancer les tests via le WAF Coraza
MCP_URL=http://localhost:8085 MCP_TOKEN="$ADMIN_BOOTSTRAP_KEY" python tests/test_e2e.py

# ── Tests crypto (sans serveur) ──
python tests/test_crypto.py

# ── Tests CLI parsing (sans serveur) ──
python tests/test_cli_all.py
```
