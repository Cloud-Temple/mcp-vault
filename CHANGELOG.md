# Changelog — MCP Vault

## [Unreleased]

### Durcissement PEP mission JWT — fail-fast de configuration (issue #86, Lot 1)

Suite à une revue adversariale Codex du PEP mission JWT (#47) préalable à son activation en production (verdict NO-GO, 7 findings bloquants — issue #86). Premier lot : ferme le finding CRITIQUE (partie configuration) et le finding sur la révocation mission non bornée. Les lots suivants (alignement C18/PEP, Policy Store fail-close, durcissement async JWKS, TTL binding) restent à faire sur #86.

- **`ENFORCE_MISSION_TOKEN_VALIDATION` désormais obligatoire (fail-fast au boot)** dès que la validation mission_token est active — que ce soit via le PEP transport (`MCP_AUTH_MODE=jwt`/`dual-stack`) ou via l'enforcement C18 seul en mode `bearer` (mécanisme historique #26). Avant ce correctif, activer le PEP `/mcp` n'empêchait pas `secret_consume` de rester en mode permissif par défaut : une mission abortée passée en paramètre `mission_token` pouvait encore obtenir la libération d'un secret.
- **`MISSION_STATUS_URL` désormais obligatoire** dans les mêmes conditions — sans elle, une mission abortée conservait l'accès jusqu'à expiration du `mission_token` (jusqu'à 1h). L'URL doit en outre contenir le placeholder littéral `{mission_id}` (fail-fast si absent) : une URL statique aurait pu valider silencieusement n'importe quelle mission comme active.
- **`MISSION_STATUS_CACHE_TTL` désormais borné à `[0,30]` secondes** (0 = pas de cache) dans les mêmes conditions — une valeur hors bornes retardait arbitrairement la détection d'une mission abortée.
- **Code mort retiré** — les avertissements `logger.warning` devenus inatteignables (le fail-fast de configuration s'exécute avant) ont été supprimés de `create_app()` et `main()`.
- **Tests** — `tests/test_mission_jwt.py::TestMissionPepConfig` (13 nouveaux cas non-complaisants : chaque nouvelle règle testée en échec ET en succès, y compris le cas bearer + enforcement C18 seul) ; `tests/test_jwt_validator.py` (test de bout en bout prouvant qu'une mission confirmée inactive dans le paramètre `mission_token` est bloquée avant tout appel à `consume_wrap_secret`, quelle que soit l'identité active sur le transport). Revue de plan Codex adversariale avant implémentation (a trouvé l'angle mort du mode bearer + enforcement C18 seul, absent du plan initial).

### Broker de secrets — consultation d'état en lecture seule (issue #77)

`secret_wrap_lookup` **révoque** volontairement les wraps (compensation des provisions orphelines #74), mais son nom laissait croire à une consultation : un consommateur vérifiant l'état d'un wrap le **révoquait** (piège d'intégration remonté par mcp-mission au pré-canari). Aucun moyen de lire l'état sans effet de bord n'existait.

- **Nouvel outil MCP `secret_wrap_status(operation_id)` (lecture seule)** — retourne l'état d'un wrap (`not_found | pending | active | consuming | consumed | revoked | failed | ambiguous | registry_inconsistent`, ou `backend_unavailable`) **sans révocation ni écriture durable**. Contrat = **instantané best-effort** du registre (cache court, S3 *last-write-wins*) : `active` signifie « actif dans l'instantané », **pas** une garantie de consommabilité (un wrap expiré côté OpenBao peut encore ressortir `active`). Ne renvoie **jamais** l'`accessor` ni le `wrap_token` (projection neuve — aucune mutation d'une référence vivante du registre). **Admin-only** (V1) ; l'ouverture aux identités mission relève de #78 Lot C.
- **`secret_wrap_lookup` clarifié** — docstring corrigée : avertissement explicite qu'il **RÉVOQUE**, renvoi vers `secret_wrap_status` ; l'état `found_unattached` est décrit correctement (provision orpheline sans accessor, **non** révoquée). Comportement **inchangé** (#74 intact).
- **Parité CLI** — `secret wrap-status <operation_id>` (miroir lecture seule de `secret wrap-lookup`).
- **Tests** — `tests/test_wrap_status_77.py` : classification de chaque état sans effet de bord, non-mutation de la référence registre, non-exposition `accessor`/`wrap_token`, admin-only, validation `operation_id` ; intégration OpenBao réel (`wrap → status → consume` **réussit**, prouvant l'absence de révocation ; contraste avec `secret_wrap_lookup` qui révoque).

## [0.8.2] — 2026-07-17

### Console admin — navigation par dossier des secrets (KV v2) + durcissements (issue #81)

Correctif du bug d'affichage : dans la console `/admin`, un vault contenant des **dossiers** KV v2 (préfixes, ex. `bootstrap/`, `mcp-teleport/`) affichait « Secret non trouvé » au clic, car l'UI tentait de **lire** un dossier comme un secret. La navigation par dossier manquait côté console — elle existait déjà côté agent MCP (`secret_list(vault_id, prefix)`). Plan validé par revue adversariale (Codex, OpenBao réel).

- **Navigation par dossier (console + API admin)** — `GET /admin/api/vaults/{id}/secrets?prefix=<sous-dossier>` liste le contenu d'un niveau ; l'UI distingue **dossier** (suffixe `/`, dépliable) et **feuille** (secret, lisible), avec expansion niveau par niveau. Les clés listées étant relatives au préfixe, l'UI reconstruit le chemin complet.
- **Moindre privilège sur le contenu (defense-in-depth)** — plus aucune surface ne divulgue le contenu d'un vault (noms **ou** simple cardinalité) à une identité sans droit de **lister** :
  - la fiche d'un vault (`GET /admin/api/vaults/{id}`) ne renvoie plus les noms (`secret_keys` retiré) ni de compteur (`get_space_info(count=False)`, aucun `list` indirect) ; la console affiche le nombre d'entrées à partir du **listing contrôlé** ;
  - le listing (racine incluse) passe **toujours** par `check_policy("secret_list")` + `check_path_policy` ;
  - la **cardinalité** (`root_entries_count`/`secrets_count`) exposée par le tableau des vaults, le tableau de bord et l'outil agent `vault_info` est désormais **conditionnée au droit de lister** (`can_read_vault_content`, test **silencieux** — pas de faux `denied`). Une identité autorisée conserve le compteur (contrat inchangé) ; sinon il est **omis** (UI : « — »).
- **Contournement de policy fermé (« validate vs use »)** — le préfixe de listing est **canonicalisé avant** `check_path_policy` (`normalize_list_path`, côté console **et** agent MCP), pour que le contrôle de droits et l'appel OpenBao portent sur la **même** valeur. Sinon `?prefix=%2F` (→ `/`), autorisé par une policy sur `/`, listait la racine (`""`). Le préfixe `/` seul est rejeté.
- **Compteur honnête** — l'ancien « Secrets : N » comptait en réalité les **entrées de premier niveau** (dossiers compris). Libellé corrigé en « Entrées » ; nouveau champ `root_entries_count` (sémantique explicite, sans parcours récursif). Une **erreur backend** n'est plus présentée comme « 0 » : la cardinalité inconnue est **omise** (UI : « — »), distincte d'un vault vide (0). `secrets_count` conservé (compat MCP `vault_info` / CLI), même valeur, sémantique documentée (entrées, pas feuilles).
- **Validation de chemin canonique (anti-traversal, cohérent #78)** — `_validate_secret_path` valide désormais **par segments** : rejet des segments vides (`//`, slash terminal), de `.` et `..`, contrôle de type, et **message constant** (la valeur rejetée n'est plus réinjectée dans la réponse ni dans l'audit MCP → vecteur d'injection de journal fermé). `list_secrets` applique cette validation **avant** tout appel OpenBao (elle en était dépourvue), ce qui durcit aussi l'outil MCP `secret_list`.
- **Routage admin durci** — le segment `/secrets` est reconnu exactement (écarte `/secretsfoo`) et les doubles slashs ne sont plus masqués silencieusement.
- **UI** — identifiants d'éléments dépliables rendus bijectifs (hex UTF-8) pour éviter la collision `a/b` vs `a_b`.
- **Tests** — `tests/test_secrets_folder_nav_81.py` (28 tests unitaires : validation canonique, canonicalisation `normalize_list_path` + non-contournement `?prefix=/`, routage, fuite noms **et** cardinalité, gating moindre-privilège `can_read_vault_content` (admin/mission/token/policy) sans faux audit, comptage `count=False`/erreur≠0, `domId` bijectif et somme `sumRootEntries` du dashboard exécutés sous Node) + `tests/test_secrets_folder_nav_openbao_81.py` (5 tests d'intégration OpenBao réel : dossiers/feuilles, clés relatives, collision feuille+dossier, lecture d'un dossier, préfixes piégés rejetés). Non-complaisance vérifiée par sabotage (4 rounds de revue adversariale Codex sur OpenBao + PolicyStore réels).

## [0.8.1] — 2026-07-15

### Durcissement `secret_consume` — hygiène & anti-injection de journal (issue #78, Lot A)

Premier lot du durcissement de `secret_consume`, issu d'une revue adversariale (5 rounds, OpenBao réel) du contrat de sortie du broker de secrets. Correctifs **autonomes**, **sans impact sur le contrat de succès**. Les lots B (états terminaux + HMAC anti-DoS sur l'unwrap) et C (autorisation consommateur / cohérence mode `jwt`) suivront.

- **Validation stricte des identifiants (`fullmatch`)** — `_SAFE_ID_RE.match()` acceptait une fin de ligne (`op\n` : le `$` matche avant un `\n` final), laissant passer une injection de saut de ligne dans les journaux. Nouveau validateur centralisé `is_safe_id()` (`fullmatch` + refus des non-`str`, fail-close), appliqué à `secret_consume` (qui ne validait pas `operation_id`), `secret_wrap`, `secret_revoke_wrap`, `secret_wrap_lookup` et au cœur `_validate_inputs` (dont `vault_id`/`secret_path`) — **avant tout audit**. `secret_revoke_wrap` ne reflète plus un `lease_id` non validé.
- **Défense centrale d'audit** — `AuditStore` neutralise les caractères de contrôle (C0 + DEL + C1 dont U+0085 NEL + séparateurs Unicode U+2028/U+2029) sur tous les champs, à l'**écriture** et au **rechargement** (`load_recent`) ; `sanitize_audit_field()` (publique) est robuste sur les valeurs non-`str`.
- **Codes d'erreur fermés (anti-reflection)** — les `reason` qui interpolaient une valeur non vérifiée ne le font plus : `unsupported_algorithm:{alg}` → `unsupported_algorithm` ; `mission_status:{state}` / `mission_status_http:{code}` → `mission_inactive` / `mission_status_error` ; `jwks_http_{status}` → `jwks_http_error`. Les valeurs brutes restent en log serveur, **jamais** renvoyées au client ni versées à l'audit humain. `service_unavailable` (logique 503 du middleware) préservé.
- **Messages client génériques** — `secret_consume` ne renvoie plus le `reason`/`status_reason` détaillé (`"Mission token invalide"`, `"Mission non active"`).
- **Journaux serveur anti-injection** — les valeurs externes (claims du refus PEP sur `stderr`, état de mission, `operation_id`/`mission_id`/`vault_id`/`secret_path` issus du registre ou d'un claim) sont sanitisées ou journalisées via `repr`.
- **Tests** — nouveau `tests/test_consume_hygiene_78.py` (23 tests non-complaisants : `fullmatch`, sanitisation d'audit + rechargement + C1/Unicode, non-reflection des `reason`, non-injection `stderr` PEP, log du broker) + renforcement des tests d'injection existants.

### Fiabilité du harnais de test (issue #64)

Durcissement **test-only** (aucun code de production) mergé après la 0.8.0 : stub `hvac` déterministe fail-close, `sys.path` centralisé, markers `needs_server`/`needs_s3` + opt-in `MCP_VAULT_E2E`, fixtures anti-complaisance (`assert FAIL == 0`), migration du contrat `space_ids` → `allowed_resources`. Fiabilise la suite de tests sans changer le comportement produit.

## [0.8.0] — 2026-07-10

### PEP mission JWT — durcissement de la porte /mcp (issue #47, PR1)

Second point d'application (PEP) pour les `mission_token` JWT ES256 émis par mcp-mission, **à l'entrée `/mcp`** — complémentaire du PEP existant à la consommation (`secret_consume`, C18 #26/#29). Contrat validé factuellement contre le code émetteur mcp-mission v0.5.0 (le token ne porte **aucune** autorisation vault : `aud`=liste de refs d'instance, `component_id={kind:ref}`, `tenant_id`/`mission_id`/`jti`/`scope` opaque ; **pas** de claims `vaults`/`permissions`).

**Périmètre PR1 (durcissement + authN)** : une identité mission JWT est authentifiée et liée à l'instance, mais n'a **aucun accès vault** (deny-by-default). L'octroi d'un périmètre vault local (MissionBindingStore keyé par `tenant_id`) est livré en PR2.

- Nouveau `mcp_auth_mode` (`bearer` par défaut — **zéro impact** — / `jwt` / `dual-stack`), `mcp_instance_id`, `mcp_component_kind` + `resolved_mission_aud` (source unique d'audience) + `check_mission_pep_config()` **fail-fast au boot** (jwks_url/audience requis en mode ≠ bearer ; refus si `mcp_instance_id`/`mission_token_aud` divergent).
- **`AuthMiddleware`** = unique lecteur du header et writer du contextvar sur `/mcp`, avec **refus ACTIF** au middleware : `401` (token absent/opaque/JWT invalide), `403` (`aud`/`component_id` ≠ instance, mission inactive), `503` (JWKS indisponible — fail-close). Bootstrap key admin acceptée en break-glass (testée en constant-time **avant** tout dispatch JWT). En `dual-stack`, un JWT invalide **ne retombe jamais** sur le chemin bearer (pas de fallback silencieux). Détection JWT **structurelle** (anti alg-confusion : un compact `alg=none`/`HS256` → 401, jamais bearer).
- **Cache JWKS unique** du processus (`auth/mission_jwt.py` : backoff exponentiel + jitter, ETag/`If-None-Match`→304, **fail-close** — un cache expiré n'est jamais servi). `MissionTokenValidator` (secret_consume) y délègue désormais sa résolution de clé : plus de second cache/rate-limit divergent.
- **Autorisation locale deny-by-default** pour `auth_type="mission_jwt"` : `check_access` refuse sans périmètre explicite (jamais d'owner-based) ; `get_listing_filter()` centralise le filtrage de `vault_list` (0 vault visible pour une identité mission non provisionnée) ; `enforce_mission_jwt_tool()` restreint les outils à une allowlist data-plane + utilitaires publics — `system_health`/`system_about` (métadonnées d'infra) et l'inventaire PKI sont **refusés** aux identités mission.
- **Vérification mission active** en allow-list `{RUNNING, WAITING_HUMAN, PAUSED}` (fail-close : un état inconnu = inactif — corrige l'ancienne deny-list ; `PAUSED` reçoit des tokens re-signés côté mcp-mission).
- **Endpoint admin** `POST /admin/api/auth/jwks/reload` (admin only) pour propager une révocation de `kid` sans attendre le TTL. L'Admin API reste **bearer/bootstrap-only** : un mission JWT y est refusé (401) sur toute la surface `/admin/api/*`.
- **Audit** immuable de chaque refus PEP (`decision_id` local + `decision_id` émetteur via `provenance` pour corrélation E2E, `tenant_id`, `mission_id`, `reason_code`) — **jamais** le token ni un secret.
- **Durcissement fail-close aligné MCP ↔ Admin REST** : `check_access`/`get_listing_filter` (MCP) et `_check_vault_access`/`GET /admin/api/vaults` (Admin REST) typent désormais `allowed_resources` en liste (un token mal formé ne peut plus provoquer un test de sous-chaîne) et refusent une identité incomplète (`client_name` vide) au lieu de lister tous les vaults. Anti-DoS sur le JWKS : throttle des refresh déclenchés par un `kid` inconnu (au plus un fetch réseau par fenêtre, quel que soit le volume).

### PEP mission JWT — octroi de périmètre vault local / MissionBindingStore (issue #69, PR2)

Suite de #47 (PR1). L'identité mission JWT, jusqu'ici authentifiée mais **sans aucun accès vault** (deny-by-default), peut désormais se voir **octroyer un périmètre vault provisionné localement** — mcp-vault jouant le rôle de **PDP local** (le `mission_token` ne porte aucune autorisation vault). L'octroi est indexé par `tenant_id` (claim stable) et reste **deny-by-default** : sans octroi, aucun accès.

- **Nouveau `MissionBindingStore`** (`auth/mission_bindings.py`) — store S3 **un fichier par instance** (`_system/mission_bindings/{encoded_instance_id}.json`, réduit le last-write-wins cross-instance), cache TTL 5 min, calqué sur PolicyStore/TokenStore. Un binding = `{tenant_id, allowed_resources:[vault…], permissions, policy_id?, enabled, expires_at?}`.
- **Contrat permissions STRICT** : un octroi vaut exactement `["read"]` ou `["read","write"]` — `["write"]` seul, `[]` et `admin` sont **refusés** (il n'existe pas de contrôle de lecture séparé : garantir `read` empêche qu'un octroi mal formé laisse lire).
- **Data-plane strict** : une identité mission ne peut faire que du data-plane secrets (`vault_list/info`, `secret_read/list/write/delete`). L'admin-plane (`vault_create/update/delete`, `ssh_*`) est **retiré de l'allow-list mission** — réservé aux bearers admin. Une mission ne se voit **jamais** déléguer de surface d'administration.
- **Résolution à la porte `/mcp`** (`AuthMiddleware`) : après validation JWT + mission active, `MissionBindingStore.resolve(tenant_id)` peuple `allowed_resources`/`permissions`/`policy_id`. Absent/désactivé/expiré → deny-all préservé. **Store indisponible/corrompu → `503 binding_store_unavailable`** (refus observable audité, jamais un deny silencieux ; état `available/invalid` explicite, aucune écriture destructrice sur un fichier corrompu).
- **CRUD admin** `GET/POST /admin/api/mission-bindings`, `GET/DELETE /admin/api/mission-bindings/{tenant_id}`, `POST .../purge` (bearer/bootstrap-only, **jamais** via mission JWT) + **parité CLI/shell** (`mission-binding create|list|get|delete|purge`). Purge des bindings expirés au-delà d'une rétention (fail-close sur date corrompue).
- **Validations défensives** : `tenant_id` URL-safe (segment `purge` réservé), `allowed_resources` = vrais `vault_id` (regex, non vides, dédupliqués, pas de `*`, taille bornée), intégrité référentielle du `policy_id` (refus si inexistant).
- **Granularité tenant-wide (assumée)** : toutes les missions actives d'un tenant partagent le périmètre octroyé. Le grain par mission existe déjà à la consommation (`secret_consume`/C18) ; le grain par mission sur ce chemin direct est une évolution future.
- **Audit** des mutations d'octroi (create/delete/purge) avec `decision_id` en tête du détail — jamais de secret. Le provisioning agentic (#62) écrira dans ce store (créer un binding tenant→coffres au lieu d'un bearer manuel).

### Correction fail-open `dry_run` — purge des tokens révoqués (dette task_a5346701)

Jumeau de la faille fermée en #69 (purge de bindings). `POST /admin/api/tokens/purge` faisait `dry_run = bool(data.get("dry_run", False))` : une valeur falsy **non booléenne** (`[]`, `0`, `""`, `null`) était coercée en `False` → déclenchant une purge **réelle** (destructive) qu'on croyait simuler.

- `dry_run` est désormais validé **strictement** (`isinstance(..., bool)`) : toute valeur non booléenne → `400`, **aucun appel** au store — alignement exact sur `_api_purge_mission_bindings` (le pattern déjà durci en #69).
- Tests de non-régression red-team : `dry_run ∈ {[], 0, "", null, "true", "false", 1, 1.0, {}, [1]}` → `400` sans purge (ni audit) ; régression inverse vérifiée (un vrai `True` simule encore, un vrai `False` purge bien).

### Validation de l'expiration des tokens à la création (issue #65)

La création de token gérait mal `expires_in_days`, des **deux côtés** : le frontend admin (`parseInt(v) || 90`) écrasait un `0` (illimité voulu) en 90 jours — l'UI ne pouvait **pas** créer de token sans expiration ; le backend, lui, ne validait rien — `null`/`-1`/`""` créaient un token **illimité par accident** et `"0"` (string) provoquait un `TypeError` → **HTTP 500**.

Décision : **tokens illimités autorisés mais EXPLICITES**. Contrat unique de `expires_in_days` sur tous les chemins : champ omis → `90` (défaut sûr) ; `0` → jamais expirer (illimité explicite) ; entier `[1, 36500]` → durée en jours ; **tout le reste rejeté** (négatif, hors borne, `bool`, `float`, string, `null`).

- **Source unique** `TokenStore.validate_expires_in_days()` (constante `MAX_EXPIRES_IN_DAYS = 36500`, borne de politique cohérente avec la purge), appelée par le **store** (défense en profondeur) et par la **frontière REST** `POST /admin/api/tokens` (→ `400`, plus jamais de `500`).
- **Frontend** : module isolé `static/js/expires.js` (`parseExpiresInDays`) — validation stricte sans coercition (`"1.5"`/`"1abc"`/`"0.0"` → erreur UI, **aucun envoi**), `0` honoré. Testé sous Node (`tests/js/expires_contract.test.js`).
- **CLI** : `--expires` en `IntRange(0, 36500)` (Click) ; **shell** : parse fail-close (`--expires` non entier / négatif / hors borne / manquant → aucune création).
- ⚠️ **Changement de contrat** : `POST /admin/api/tokens` **rejette désormais** `expires_in_days` envoyé en **string** (ex. `"90"`) ou toute valeur non entière. Un appelant qui envoyait une string doit envoyer un entier JSON.
- Hors périmètre (documenté) : les tokens **déjà** créés en illimité par accident restent inchangés (repérables via `token list`, colonne « jamais ») ; `token_update` ne gère pas l'expiration (inchangé).

### Observabilité AuditStore (issue #61)

`AuditStore.log()` avalait silencieusement toute erreur d'écriture du fichier JSONL (`except Exception: pass`). En cas de panne disque, répertoire absent ou problème de permission, aucune trace n'était produite.

- `AuditStore.log()` logue désormais sur `stderr` chaque échec d'écriture avec le chemin, le type d'exception et le message.
- Nouveau compteur `_write_errors` incrémenté à chaque échec.
- `get_stats()` expose `write_errors` dans tous les cas de retour (buffer vide inclus) — visible via l'outil MCP `audit_log` et l'API admin `/admin/api/audit`.
- Dead code `self._file = None` supprimé.

### Correction asymétrie vault_create MCP/REST — contrôle d'accès vault-level (issue #58)

`POST /admin/api/vaults` ne vérifiait pas l'accès vault-level (`check_access`) avant de créer un vault, contrairement au chemin MCP `vault_create`. Un token scopé (ex. `allowed_resources=["vault-a"]`) pouvait créer n'importe quel vault via l'API REST.

- **`_api_create_vault`** reçoit désormais `token_info` et appelle `_check_vault_access(token_info, vault_id)` après validation de `vault_id` — retourne 403 si le token n'est pas autorisé sur ce vault.
- Cohérent avec `_api_update_vault` / `_api_delete_vault` qui appliquaient déjà ce contrôle au routeur (vault_id dans l'URL).
- Pas de régression admin : un token admin passe toujours.
- Pas de régression owner-based : `check_vault_owner` retourne `True` pour un vault inexistant (création autorisée pour le créateur).

### CI — tag + GitHub Release automatiques au bump de VERSION (issue #56)

Premier workflow GitHub Actions du dépôt (`.github/workflows/release.yml`). Au merge sur `main` modifiant `VERSION`, crée automatiquement le tag annoté `vX.Y.Z` + la GitHub Release (notes = section correspondante du CHANGELOG). Idempotent et re-run safe (tag et release gérés indépendamment ; tag existant vérifié contre `GITHUB_SHA`) ; validation stricte de `VERSION` (`X.Y.Z`) ; `actions/checkout` épinglé par SHA. Corrige la cause de l'oubli du tag v0.7.0 (déploiement « par commit nu »).

### Cohérence documentaire + parité CLI (issue #59)

- README (fr + en) et DESIGN (ARCHITECTURE/TECHNICAL) alignés sur v0.7.0 : purge des tokens révoqués (#50) et audit du cycle de vie des accès (#49) documentés ; routes `/admin/api/*` à jour ; compteur d'endpoints périmé corrigé.
- Nouvelle commande CLI **`logs`** (click + shell) → `GET /admin/api/logs`, pour aligner le CLI sur la console admin ; aide PKI du shell complétée (`issue`).

## [0.7.0] — 2026-06-22

Milestone **« Durcissement auth & conformité »** : traçabilité d'audit du plan de contrôle d'accès (SecNumCloud/HDS), purge des tokens révoqués, et défense en profondeur sur la création de tokens.

### Purge des tokens révoqués (issue #50)

Opération admin pour purger les tokens révoqués accumulés dans `_system/tokens.json` (aucune GC n'existait). Exposée dans `/admin` et `mcpcli.py` (commande click + shell).

- **`TokenStore.purge_revoked(older_than_days=30, dry_run=False)`** : ne supprime que les tokens **révoqués** dont `revoked_at` est antérieur à la rétention (défaut 30 j ; la valeur est bornée `[0, 36500]` par la route REST). **Fail-close** : un token révoqué sans `revoked_at` parseable (absent / corrompu / sans fuseau) n'est jamais purgé. Discipline `_save()` + **rollback complet** si S3 indisponible (aucun token perdu).
- **N'affecte jamais** un token actif, ni un token **expiré mais non révoqué** — ce dernier doit rester visible (on a besoin de savoir qu'un token est expiré, quitte à le révoquer ensuite).
- **Route `POST /admin/api/tokens/purge`** réservée admin ; `dry_run` retourne le décompte des candidats sans rien supprimer.
- **Audit** : chaque token réellement purgé + un récapitulatif sont journalisés (`token_purge`). La trace vit dans `audit-mcp.jsonl`, indépendant de `tokens.json` → elle **survit** à la purge. Échec de persistance → 503 + audit `error`. Jamais de secret dans le détail.
- **dry-run + confirmation** : SPA (dry-run → confirmation du décompte → exécution), CLI click (`--older-than`, `--dry-run`, `--yes`), shell (exige `--yes` ; **fail-close** sur `--older-than` invalide/incomplet ou dry-run en échec).

### Traçabilité d'audit du cycle de vie des accès (issue #49)

Les mutations du plan de contrôle d'accès via l'API REST admin n'étaient **pas** journalisées (`log_audit` jamais appelé dans `admin/api.py`) — écart de traçabilité SecNumCloud/HDS.

- **REST** : audit ajouté sur `_api_create_token` (`token_create`), `_api_update_token` (`token_update`), `_api_revoke_token` (`token_revoke` — succès **et** échec de persistance), `_api_create_policy` (`policy_create`), `_api_delete_policy` (`policy_delete` — succès + échec).
- **MCP** : `policy_create` et `token_update` passent désormais par le helper `_r()` (comme `policy_delete`) ; `policy_delete` trace aussi le chemin « suppression non persistée ».
- Jamais le token brut dans le détail. La trace est physiquement indépendante de `tokens.json`.

### Validation des permissions à la création de token — défense en profondeur (issue #48)

- `TokenStore.create()` valide désormais les permissions (rejet : liste vide, non-liste, flag hors `{read, write, admin}`, élément non-hashable) **avant** toute écriture S3. Le point d'entrée HTTP validait déjà type et flags (V3-03) mais pas la liste vide ; ce correctif sécurise le store lui-même (liste vide incluse) quel que soit l'appelant.
- Source unique de vérité `TokenStore.VALID_PERMISSIONS` (frozenset), réutilisée par `create()`, `update()` et `admin/api.py` (suppression de 3 copies dupliquées).

### Tests

- `tests/test_token_permissions.py`, `tests/test_audit_lifecycle.py`, `tests/test_purge_revoked.py`, `tests/cli/test_purge_shell.py` — tests offline **non-complaisants** : garde admin 403, fail-close, rollback S3, audit par opération, token brut jamais exposé, fail-close du shell.

### Revue

Chaque lot a passé une revue **Codex** (read-only) jusqu'à `APPROUVÉ` ; #50 a aussi fait l'objet d'une **revue adversariale multi-agents**.

> **Note dette** : `AuditStore.log()` avale silencieusement les erreurs d'écriture JSONL (`except: pass`) — préexistant, à corriger séparément.

## [0.6.8] — 2026-06-11

### PKI/ACME — enrollment end-to-end fonctionnel (issue #41)

Première validation **réelle** de l'enrollment ACME de bout en bout : un WAF Caddy obtient un certificat TLS depuis la PKI interne (challenge tls-alpn-01 → finalize → cert émis), à travers le WAF en HTTPS. Le test révèle et corrige une cascade de blocages jusqu'alors invisibles (tests mockés + T1/T7 jamais exécutés en conditions réelles).

#### WAF (`waf/coraza.conf`)
- **920420** « Request content type not allowed » : exclu sur les paths ACME — ACME utilise `Content-Type: application/jose+json` (JWS, RFC 8555), non autorisé par le CRS par défaut.
- **Regex d'exclusion ACME élargie** au sous-arbre complet (`^/acme/[a-zA-Z0-9/_\-]{1,256}$` et `/v1/_sys_pki_int/acme/...`) : couvre les endpoints dynamiques `authorization/<id>`, `order/<id>`, `order/<id>/finalize`, `challenge/<id>`, `certificate/<id>` — auparavant 403. Anti-traversal assuré en amont par `PkiMiddleware`.

#### Rôle ACME (`vault/pki_ca.py`)
- `key_type` `rsa` → **`any`** : les clients ACME (Caddy) génèrent des clés EC par défaut ; imposer RSA causait `badCSR - requires rsa`.
- **`allow_bare_domains=True`** : émettre pour les domaines exactement listés (sinon `rejectedIdentifier` sur le FQDN nominal).
- **`allow_glob_domains=True`** : support des patterns `*.domain` dans `allowed_domains`.

#### WAF TLS paramétrable (`waf/Caddyfile`, `docker-compose.yml`)
- `WAF_TLS_DIRECTIVE` (vide par défaut = prod inchangée) : permet d'activer `tls internal` pour servir le directory ACME en HTTPS (Caddy refuse l'ACME sur une CA HTTP).

#### Infra de test E2E (`tests/pki/`)
- `docker-compose.test-tls.yml` (override TLS), alias réseau `test.lesur.lan`, Caddyfile pointant le directory HTTPS. Procédure documentée pour rejouer l'enrollment complet.

> **Prérequis de déploiement** : l'image mcp-vault doit être rebuildée (le tuning `allowed_response_headers` de #32, requis pour le header `Replay-Nonce`, n'était pas dans les images < v0.6.4).

## [0.6.7] — 2026-06-11

### Fix WAF — exclusions CRS inopérantes en phase:1 (issue #42, BLOQUANT prod)

Le fix #37 (v0.6.4) était **déployé mais inopérant** : `/pki/ca/*.pem` répondait toujours **403** à travers le WAF.

#### Cause racine
`ctl:ruleRemoveById` ne retire qu'une règle **pas encore évaluée** dans la transaction. Coraza évalue les règles d'une phase dans l'ordre du fichier. Les exclusions (`10001`-`10007`) étaient placées **après** l'`Include` du CRS ; or 920440 et 920540 sont en **phase:1** → elles s'exécutaient et scoraient **avant** le `ctl` → blocage en phase:2 (949110) sur le score accumulé. Seul 932120 (phase:2) était effectivement neutralisé.

#### Fix
`waf/coraza.conf` : bloc d'exclusions déplacé **AVANT l'`Include` du CRS** (pattern CRS standard « exclusions before CRS »). Les `ctl:ruleRemoveById` en phase:1 retirent alors les règles ciblées avant leur évaluation — phase:1 comprise. Régularise aussi 920540 (v0.5.1, inopérante depuis l'origine).

#### Validation — test d'intégration réel à travers le WAF (non négociable)
Rebuild WAF + `curl http://localhost:8085` :
- `/pki/ca/root.pem` · `/chain.pem` · `/crl.pem` → **200** (PEM valide)
- `/pki/ca/evil.pem` · `/test.pem` → **403** (920440 actif, exclusion strictement scopée)
- SQLi · XSS → **403** (WAF protège toujours) ; `/acme/directory` → **200** ; `/health` → **200**
- Test négatif **T3d** ajouté à `tests/pki/test_pki_integration.sh` (scoping strict).

Aucun impact CLI/SPA (conf Coraza transparente). Codex APPROUVÉ.

## [0.6.6] — 2026-06-11

### Génération de certificat depuis /admin + CLI (issue #41, partie 2/2)

Nouvel outil `pki_issue_cert` (36 outils MCP) : émission manuelle d'un certificat serveur signé par la CA intermédiaire, hors ACME — pour le debug, l'exploitation et les cas sans enrôlement automatique.

#### Backend (`vault/pki_ca.py`, `server.py`, `admin/api.py`)
- `pki_issue_cert(common_name, ttl?, alt_names?, ip_sans?)` (admin).
- **Rôle dédié `manual-servers`** (création idempotente) : `allow_ip_sans=True`, `no_store=False` (inventaire), wildcards refusés — distinct du rôle ACME (reco Codex).
- **Validation locale** avant émission : CN + SANs DNS contre les `allowed_domains` de la PKI, IP via `ipaddress`, format **et borne max** du TTL (vs `max_ttl` du rôle), wildcard interdit.
- **Clé privée one-shot** : retournée une seule fois, jamais stockée côté Vault, jamais journalisée ni auditée (audit filtre `private_key`/`certificate`/`ca_chain`).
- Route REST `POST /admin/api/pki/issue` (admin, codes 400/500).

#### CLI (`pki issue`)
- Click + shell : `pki issue <common_name> [--ttl] [--alt-names] [--ip-sans]`.
- Affichage avec alerte **SENSIBLE** sur la clé privée.

#### SPA `/admin`
- Bouton « Générer un certificat » + modale `modalPkiIssue`.
- Clé privée affichée via `textarea.value` (jamais `innerHTML`), **sans copie automatique** au presse-papier (décision Codex).

#### Tests
- `tests/test_pki.py::TestIssueCertificate` (9 tests) : nominal, domaine refusé, wildcard, TTL format + borne max, IP invalide, alt_name validé, `allowed_domains` en CSV, clé privée absente de l'audit. `tests/cli/test_pki.py` : `pki issue`. 44/44 PKI verts.

> Partie 1/2 (#41) livrée en v0.6.5 (refonte CSS du panneau PKI).

## [0.6.5] — 2026-06-11

### UI — panneau PKI /admin lisible (issue #41, partie 1/2)

Le panneau PKI s'affichait cassé : `pki.js` utilisait des classes CSS jamais définies dans `admin.css` (labels collés aux valeurs, pas de grille de cartes).

- `admin.css` : ajout (patch additif ciblé, recommandation Codex) des classes `card-grid`, `card-label/value/value-big/sub`, `section-title`, `url-list/row/label/value`, `btn-copy`, `btn-warn`, `badge-danger`, `mono-tiny/small`, `table-wrapper`, `empty-row`, `page-header`, `error-banner`, `success-banner`, `loading` — cohérentes avec le design system Cloud Temple.
- Responsive : `.table-wrapper` scroll horizontal, lignes URL empilées + header en colonne sur mobile.
- Aucune classe existante modifiée (hors spécialisation `.card-grid .card`).

> Partie 2/2 (issue #41) : génération de certificat `pki_issue_cert` (backend + CLI + modale) — PR séparée.

## [0.6.4] — 2026-06-11

### Fixes PKI prod — distribution CA/CRL + inventaire vide (issues #37, #38)

Deux correctifs bloquants/trompeurs détectés lors de l'audit prod v0.6.2 (suite #32).

#### #37 — WAF bloquait la distribution CA/CRL (BLOQUANT)
- `waf/coraza.conf` : la règle d'exclusion `10005` ne retirait pas la règle CRS **920440** (« URL file extension is restricted »), qui bloque l'extension `.pem`. Résultat : `/pki/ca/root.pem`, `/chain.pem`, `/crl.pem` répondaient **403** à travers le WAF (l'app les servait pourtant en 200).
- Correctif : ajout de `ctl:ruleRemoveById=920440`, **restreint aux 3 fichiers** `^/pki/ca/(root|chain|crl)\.pem$` (pas d'ouverture WAF sur d'autres paths).
- Sans CA/chain téléchargeables ni CRL accessible, aucun client ne pouvait établir la confiance — la distribution PKI n'avait jamais fonctionné via le WAF.

#### #38 — Inventaire PKI/SSH vide affiché comme erreur
- `hvac client.list()` retourne `None` sur un chemin vide (PKI/SSH fraîchement initialisée — état nominal) → `AttributeError: 'NoneType' object has no attribute 'get'`, affichée en bandeau rouge dans `/admin`.
- Helper commun `vault/_hvac_utils.py::safe_list_keys()` appliqué à 3 call-sites : `list_issued_certs`, `list_pki_roles` (pki_ca.py), `list_ssh_roles` (ssh_ca.py).
- Une PKI/SSH vierge retourne désormais `ok` / `total=0`.

#### Tests
- `tests/test_pki.py::TestEmptyInventoryNoneSafe` : helper + PKI vierge + rôles PKI/SSH vierges → `ok`, pas d'erreur.
- À valider en Docker (#37) : `curl http://waf:8085/pki/ca/root.pem` → 200 (test d'intégration à travers le WAF).

## [0.6.3] — 2026-06-11

### Synchronisation des surfaces — affichage EAB + JIT broker au CLI (issue #34)

Alignement des surfaces (SPA `/admin`, CLI Click, shell) sur le backend, suite à l'audit post-v0.6.2. Aucun changement de comportement serveur.

#### SPA `/admin`
- `pki.js` : le statut PKI affiche désormais l'état **EAB** (`eab_required` + `eab_policy`) dans une carte dédiée — un admin voit si l'enrôlement ACME est protégé (`esc()` appliqué, pas de régression XSS).

#### CLI — affichage
- `display.py` `show_pki_result()` : ajout de la ligne `eab_policy` (diagnostic `not-required` / `new-account-required`).

#### CLI — JIT Wrap Broker exposé (Click + shell)
- Nouvelles commandes `secret wrap`, `secret revoke-wrap`, `secret wrap-lookup` (contrat M2M mcp-mission), pour le debug, la révocation et les tests de contrat.
- `secret wrap` supporte le binding C18 (`--tenant-id`, `--expected-aud`) en Click **et** en shell (parité).
- `show_wrap_result()` : affiche le `wrap_token` avec alerte **SENSIBLE** et remonte toujours la `note` (ex. registry indisponible) en warning.
- **Décision (Codex)** : le broker n'est **pas** exposé en SPA (surface XSS / fuite presse-papier sur les wrap tokens).

#### Tests
- Tests CLI non-complaisant (`tests/cli/test_secret.py`) : vérifient les appels MCP réels (`secret_wrap`/`revoke_wrap`/`wrap_lookup`), le binding C18 transmis, et l'alerte SENSIBLE.

> **Note** : `secret_wrap`/`secret_revoke_wrap`/`secret_wrap_lookup` existaient depuis v0.4.13 (JIT broker, issue #7) mais n'étaient exposés sur aucune surface humaine. Couverture CLI désormais complète.

## [0.6.2] — 2026-06-11

### Fix PKI mode Prod — eab_policy invalide (issue #32)

L'initialisation de la PKI interne en mode **Prod** (`lab_mode=False`) échouait systématiquement à l'étape `config/acme`.

#### Bug bloquant
- `vault/pki_ca.py` : `eab_policy="required"` **n'existe pas** dans OpenBao (valeurs valides : `not-required`, `new-account-required`, `always-required`). Tout setup prod échouait avec `invalid eab policy name provided`.
- Correctif : `eab_policy = "not-required"` (lab) / `"new-account-required"` (prod) — l'EAB est exigé à la création de compte ACME, ce qui bloque l'enrôlement public non authentifié sans casser les comptes existants.

#### Bugs secondaires (cohérence status)
- `eab_required` était calculé via `eab_policy == "required"` (jamais vrai) → helper `_eab_required()` (`new-account-required`/`always-required` → True).
- `eab_policy` désormais exposé dans les retours `setup_pki_ca()` et `get_pki_status()`.

#### Réserves ACME traitées
- **`allowed_response_headers`** : le mount intermédiaire est tuné pour autoriser les headers ACME (`Replay-Nonce`, `Link`, `Location`) — sinon OpenBao les strippe et l'enrôlement ACME réel (T1/T7) échoue.
- **`sign-intermediate`** : `issuer_ref` déplacé du body vers le path `/issuer/mcp-vault-root/sign-intermediate` (forme documentée OpenBao).

#### Tests
- 8 tests non-complaisant (`tests/test_pki.py::TestEabPolicyProd`) : inspection du payload réel `config/acme`, helper `_eab_required`, tuning headers (+ fail-hard si KO), path sign-intermediate (setup + rotation). 43/43 tests PKI verts.

> **Note de remédiation prod** : l'échec laissait un état partiel (root + intermédiaire + rôle ACME créés, `config/acme` manquant). Le setup étant idempotent, un simple retry après ce fix termine l'initialisation — aucun nettoyage requis.

## [0.6.1] — 2026-06-11

### Hardening C18 — singleton JWT + binding complet tenant_id/aud (issue #29)

Corrections de sécurité post-audit Codex v0.6.0. Aucun changement d'interface publique.

#### P0 — MissionTokenValidator singleton process-wide
`secret_consume` réinstanciait `MissionTokenValidator` à chaque appel : le cache JWKS (60s) et le rate-limit (3 refreshes/min) étaient donc par-requête et non globaux.

- `auth/jwt_validator.py` : `init_mission_token_validator()` + `get_mission_token_validator()` — singleton module-level
- `lifecycle.py` : initialisation au startup (step 1e) — un seul validateur partagé pour tout le processus
- `server.py` : `secret_consume` utilise le singleton. Fail-close si singleton absent + `ENFORCE=true` (erreur `misconfigured`)

#### P1 — Binding C18 complet : tenant_id + expected_aud propagés
`tenant_id` et `expected_aud` étaient stockés dans le registry mais jamais renseignés par le flux réel (`secret_wrap` → `wrap_secret` → `register_pending` ne les passait pas) : le binding dans `consume_wrap_secret` était donc systématiquement ignoré en production.

- `vault/wrapping.py` : `wrap_secret()` + `register_pending()` acceptent `tenant_id` et `expected_aud`
- `server.py` : `secret_wrap` MCP accepte `tenant_id` et `expected_aud` (optionnels, rétrocompat)
- `server.py` : `expected_aud_from_jwt = settings.mission_token_aud` (audience validée par PyJWT, pas `jwt_claims["aud"]` qui peut être une liste non-ordonnée)
- Messages d'erreur `binding_mismatch` rendus génériques (ne révèlent plus le champ en échec)

#### Corrections additionnelles (3ème+4ème passe Codex)
- `secret_wrap` : en mode `ENFORCE=true` + JWKS, impose `expected_aud = settings.mission_token_aud` automatiquement si non fourni (wraps toujours bindés en mode enforced). Erreur `misconfigured` si `MISSION_TOKEN_AUD` est vide.
- `consume_wrap_secret` : en mode `enforce=True`, rejette les wraps sans `expected_aud` avec `binding_incomplete` (protège contre les wraps legacy en mode enforced)
- `expected_aud_from_jwt` dans `secret_consume` utilise `settings.mission_token_aud` (audience validée par PyJWT, pas `jwt_claims["aud"]` qui peut être une liste)

#### Tests non-complaisant ajoutés (10 tests)
- Singleton réutilisé entre appels (pas réinstancié)
- Fail-close si singleton absent + ENFORCE=true
- `secret_wrap` enrichit `expected_aud` automatiquement en mode ENFORCE=true
- `tenant_id` mismatch → rejeté avant `try_mark_consuming` (pas d'état orphelin)
- `expected_aud` mismatch → confused-deputy bloqué (message générique)
- Wrap legacy sans `expected_aud` → `binding_incomplete` en mode enforced
- Binding correct → consume nominal
- Rétrocompatibilité : champs vides dans le registry → binding ignoré (mode standalone)
- Propagation `tenant_id`/`expected_aud` de `wrap_secret` vers le registry
- Vérification que `try_mark_consuming` n'est pas appelé si binding mismatch

### Fichiers modifiés
- `src/mcp_vault/auth/jwt_validator.py` — singleton
- `src/mcp_vault/lifecycle.py` — init singleton au startup
- `src/mcp_vault/server.py` — secret_wrap + secret_consume
- `src/mcp_vault/vault/wrapping.py` — wrap_secret + consume_wrap_secret
- `tests/test_jwt_validator.py` — +2 tests non-complaisant
- `tests/test_wrap.py` — +6 tests non-complaisant

## [0.6.0] — 2026-06-10

### Anti-confused-deputy C18 — validation JWT mission_token ES256/JWKS (issue #26)

Alignement de mcp-vault sur la matrice E2E C18 : comme mcp-teleport, mcp-vault valide désormais l'identité de mission avant de libérer un secret. Purement additif — zéro impact sur les déploiements standalone (sans mcp-mission).

#### Nouvel outil MCP `secret_consume` (35 outils total)
```
secret_consume(wrap_token, operation_id, mission_token) → secret_data
```
- Valide le JWT mission_token ES256 (JWKS public mcp-mission)
- Vérifie les bindings registry : mission_id, tenant_id, aud (anti-confused-deputy)
- Vérifie la mission active côté mcp-mission (cache 5s, fail-close)
- Unwrap OpenBao cubbyhole + anti-replay (status: "consumed")
- Audit log sans données sensibles (wrap_token et mission_token jamais loggués)

#### `auth/jwt_validator.py` (nouveau module)
- `MissionTokenValidator` : cache JWKS TTL-borné (60s), refresh sur kid inconnu, rate-limit (3/min), détection kid révoqué post-refresh, thread-safe (threading.Lock)
- `MissionTokenError` : reason code machine, jamais le token compact dans le message
- Algorithme : ES256 uniquement

#### `vault/wrapping.py` — extensions C18
- `register_pending()` : +`tenant_id`, +`expected_aud` optionnels (binding JWT)
- `get_by_composite_key(operation_id, mission_id)` : lookup anti-collision (clé composite)
- `try_mark_consuming()` : atomic compare-and-swap "active" → "consuming" (anti-replay)
- `mark_consumed()` : "consuming" → "consumed" après succès OpenBao
- `rollback_consuming()` : "consuming" → "active" si OpenBao échoue
- Statuts étendus : `consuming`, `consumed`
- `consume_wrap_secret()` : unwrap médié complet

#### Nouveaux settings (8)
| Variable | Défaut | Description |
|----------|--------|-------------|
| `ENFORCE_MISSION_TOKEN_VALIDATION` | `false` | Hard-reject. False = log warning (migration) |
| `MISSION_JWKS_URL` | *(vide)* | JWKS public mcp-mission. Vide = validation désactivée |
| `MISSION_TOKEN_AUD` | *(vide)* | Audience vault_ref (anti-confused-deputy) |
| `MISSION_JWKS_CACHE_TTL` | `60` | TTL cache JWKS en secondes |
| `MISSION_JWKS_MAX_REFRESH_PER_MIN` | `3` | Rate-limit refresh JWKS |
| `MISSION_TOKEN_LEEWAY_SECONDS` | `10` | Tolérance clock skew |
| `MISSION_STATUS_URL` | *(vide)* | Vérification mission active (template {mission_id}) |
| `MISSION_STATUS_CACHE_TTL` | `5` | TTL cache statut mission (court — fail-close rapide) |

#### Corrections Codex (CRITIQUE×2 + ÉLEVÉ×1)
- thread-safety rate-limit JWKS (appelé sous threading.Lock par construction)
- `_mission_status_lock` créé au niveau module (anti-race création lazy)
- `rollback_consuming()` retourne bool + log si S3 fail

#### CLI — tokens sensibles via variables d'environnement
`secret consume` passe `wrap_token` et `mission_token` via `VAULT_WRAP_TOKEN` et
`VAULT_MISSION_TOKEN` (pas en arguments positionnels — évite l'exposition dans
`~/.bash_history`). Pattern identique à `MCP_TOKEN`/`ADMIN_BOOTSTRAP_KEY`.
`.env.example` documenté avec les 8 groupes de variables.

```bash
VAULT_WRAP_TOKEN=hvs.CAES... VAULT_MISSION_TOKEN=eyJ... \
mcp-vault secret consume op-123
```

#### Tests non-complaisant
- `tests/test_jwt_validator.py` (24 tests) : contrôle positif + 11 variantes C18 rejetées (signature, exp, iss, aud, mission_id, algo, kid révoqué, token compact jamais divulgué, malformé) + cache/rate-limit + WrapRegistry extensions + secret_consume standalone/enforce

### Fichiers modifiés
- `src/mcp_vault/auth/jwt_validator.py` *(nouveau)*
- `src/mcp_vault/vault/wrapping.py` — extensions C18
- `src/mcp_vault/server.py` — secret_consume + _check_mission_active
- `src/mcp_vault/config.py` — 8 settings JWT
- `requirements.txt` — PyJWT>=2.10.0
- `tests/test_jwt_validator.py` *(nouveau)* — 24 tests

## [0.5.1] — 2026-06-10

### Correctifs PKI ACME — validation en conditions réelles Docker (issue #15 T0-T10)

Tests d'intégration réels : **13/13 PASS** (T0, T3a/b/c, ACME directory, T5, T6a/b/c, T9a/b, T10).
T1/T7 (enrollment ACME) : nécessitent HTTPS sur le cluster path — fonctionnel en production avec WAF TLS.

#### Fixes bloquants
- **cluster path OpenBao ACME** : `config/cluster` désormais configuré avant `config/acme`. Appel via `client._adapter.post()` (hvac.write() a une collision de paramètre nommé `path`)
- **WAF bloquait `/pki/ca/*.pem`** : Coraza CRS retournait 403. Exclusions ajoutées avec regex stricte (seulement les 3 fichiers PEM/CRL connus + endpoints ACME normalisés RFC 8555)
- **CRL format** : proxy `/pki/ca/crl.pem` → `/v1/_sys_pki_int/crl/pem` (DER vs PEM)
- **setup_pki_ca idempotent** : `try/except "issuer name already in use"` exact pour root ET intermédiaire — évite de masquer d'autres erreurs
- **`PKI_BASE_URL` setting** : variable d'env pour override l'URL de base PKI (test Docker : `http://mcp-vault:8030`) avec validation anti-MITM

#### Nouveaux endpoints admin REST
- `GET /admin/api/pki/roles` — liste des rôles d'émission ACME
- `GET /admin/api/pki/roles/{role_name}` — détails d'un rôle (allow_any_name, domaines, TTL)

#### SPA /admin
- Section PKI : ajout du panneau "Rôles ACME" avec détails du rôle par défaut (`acme-servers`)

#### Proxy ACME étendu
- `PkiMiddleware` gère désormais aussi `/v1/_sys_pki_int/acme/*` (URL longue générée par OpenBao dans les réponses ACME directory)

#### Infrastructure de test
- `tests/pki/` : `docker-compose.test-pki.yml`, `docker-compose.fresh-start.yml`, `test_pki_integration.sh` (T0-T10 complets)

#### Corrections Codex (HAUT×3)
- `"already in use"` restreint à `"issuer name already in use"` exact
- WAF : `ruleEngine=Off` → `ruleRemoveById` ciblé sur regex stricte
- `pki_base_url_validated` : ValueError si non `http(s)://` (protection MITM ACME)

### Fichiers modifiés
- `src/mcp_vault/vault/pki_ca.py` — cluster path, idempotence, `PKI_BASE_URL`
- `src/mcp_vault/pki_middleware.py` — proxy long-path, CRL PEM
- `src/mcp_vault/admin/api.py` — routes `/pki/roles*`
- `src/mcp_vault/config.py` — `pki_base_url` setting validé
- `waf/coraza.conf` — exclusions PKI/ACME regex stricte
- `src/mcp_vault/static/js/pki.js` — panneau rôles ACME
- `tests/pki/` *(nouveau)* — infrastructure de test T0-T10

## [0.5.0] — 2026-06-10

### PKI interne — CA OpenBao + serveur ACME (issue #15)

Première release majeure post-v0.4.x : MCP Vault est désormais une **autorité de certification interne** pour l'écosystème Cloud Temple. Les WAF Caddy peuvent obtenir leurs certificats TLS via le protocole ACME standard, sans dépendance Internet ni CA publique.

#### Architecture PKI (PR #16)
- **`vault/pki_ca.py`** : CA racine + intermédiaire (OpenBao PKI engine), serveur ACME sur CA intermédiaire, rotation sans coupure (`rotate_intermediate`), révocation + CRL, inventaire paginé des certificats émis
- **`pki_middleware.py`** : middleware ASGI couche externe non-auth — proxy transparent `/acme/*` → OpenBao + distribution CA (`/pki/ca/root.pem`, `/pki/ca/chain.pem`, `/pki/ca/crl.pem`)
- **Mounts réservés** : `_sys_pki_root/` et `_sys_pki_int/` protégés contre `vault_delete` (double guard `spaces.py` + `server.py`, audit log)
- **Sync S3 forcée** après `setup_pki_ca`, `revoke_cert`, `rotate_intermediate` (durabilité critique)
- **Stack ASGI** : 6 couches — `PkiMiddleware → AdminMiddleware → HealthCheckMiddleware → AuthMiddleware → LoggingMiddleware → FastMCP`

#### Sécurité PKI (corrections Codex)
- Anti-traversal sur les paths ACME (`/../..` bloqué), validation `query_string`, `follow_redirects=False` (pas de SSRF)
- Validation regex `serial_number` (`^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2})+$`) dans `revoke_cert`
- `asyncio.Lock` sur `setup_pki_ca` (race condition multi-appel)
- Validation format FQDN/wildcard des `allowed_domains`
- Vérification retour `upload_to_s3()` (bool) sur toutes les mutations critiques

#### 7 nouveaux outils MCP (PR #16)
- `pki_ca_setup(lab_mode, allowed_domains, leaf_ttl)` — admin
- `pki_ca_public_key()` — CA racine PEM + SHA-256
- `pki_ca_list_roles()` — liste des rôles ACME
- `pki_ca_role_info(role_name)` — détails rôle
- `pki_list_certs(limit, offset)` — inventaire paginé
- `pki_revoke_cert(serial_number)` — admin
- `pki_ca_rotate_intermediate(keep_old_issuer, overlap_ttl)` — admin

Total outils MCP : **24 → 31**

#### Admin SPA /admin — section PKI (PR #17)
- Nouvelles routes REST : `GET /admin/api/pki/status`, `POST /admin/api/pki/setup`, `GET /admin/api/pki/certs`, `POST /admin/api/pki/certs/{serial}/revoke`, `POST /admin/api/pki/ca/rotate`
- Sidebar "PKI / TLS" (admins uniquement)
- Page PKI : statut CA (expiration racine/intermédiaire, empreinte SHA-256, ACME on/off), URLs de distribution copiables, inventaire certs avec révocation, modal setup
- Sécurité XSS : `JSON.stringify()` sur onclick serial et URL (pas de `esc()` insuffisant)
- `/pki/certs` requiert `is_admin` (inventaire = données sensibles)

#### CLI groupe `pki` (PR #18, `Closes #15`)
- **Click** : `pki setup`, `pki ca-key`, `pki roles`, `pki role-info <role>`, `pki certs`, `pki revoke <serial>`, `pki rotate`
- **Shell interactif** : `cmd_pki()` + `SHELL_COMMANDS["pki"]`
- **Display** : `show_pki_result()` affichage adaptatif (setup, ca-key, roles, inventaire, révocation, rotation)
- Options typées (`type=int` sur `--limit`/`--offset`), robustesse arg manquant

### Maintenance & Qualité (issues #12, #13, #14)

**#12 Tests comportementaux** (PR #19) : `TestAdminApiCodeStructure` — 3 tests à recherche textuelle réécrits en tests ASGI comportementaux :
- `test_whoami_returns_injected_client_name` : GET /whoami prouve l'injection ContextVar à l'exécution
- `test_contextvar_reset_after_request` : ContextVar resetté après requête (prouve le `finally`)
- `test_create_policy_created_by_uses_token_client_name` : mock store.create, vérifie `created_by=client_name`

**#14 Dashboard SPA** (PR #20) : compteur de tokens actifs excluait les révoqués mais pas les expirés. Fix : `.filter(t => !t.revoked && !t.expired)`.

**#13 Race S3** (PR #21) : limitation last-write-wins documentée dans `_save()` de `TokenStore` et `PolicyStore` (acceptable V1, single-instance). V2 : S3 conditional write ETag/CAS.

### Fichiers modifiés (résumé)
- `src/mcp_vault/vault/pki_ca.py` *(nouveau)*
- `src/mcp_vault/pki_middleware.py` *(nouveau)*
- `src/mcp_vault/server.py` — +7 outils MCP PKI + PkiMiddleware + guard vault_delete
- `src/mcp_vault/admin/api.py` — +5 routes REST PKI
- `src/mcp_vault/vault/spaces.py` — guard is_reserved_mount
- `src/mcp_vault/lifecycle.py` — check PKI au démarrage
- `src/mcp_vault/auth/token_store.py` — LIMITATION V1 documentée
- `src/mcp_vault/auth/policies.py` — LIMITATION V1 documentée
- `src/mcp_vault/static/admin.html` — page PKI + modal
- `src/mcp_vault/static/js/app.js` — sidebar PKI + routing
- `src/mcp_vault/static/js/pki.js` *(nouveau)*
- `src/mcp_vault/static/js/dashboard.js` — filtre tokens expirés
- `scripts/cli/commands.py` — groupe pki (7 commandes)
- `scripts/cli/shell.py` — cmd_pki + dispatcher
- `scripts/cli/display.py` — show_pki_result
- `tests/test_pki.py` *(nouveau)* — 22 tests
- `tests/test_pki_admin.py` *(nouveau)* — 12 tests
- `tests/cli/test_pki.py` *(nouveau)* — tests aide + rendus
- `tests/test_admin_context.py` — réécriture TestAdminApiCodeStructure

## [0.4.16] — 2026-06-08

### Tests & Security — Résiduels finaux (suite de l'audit complet)

#### Tests non-complaisant — test_admin_context.py (HAUT)
`test_admin_api_injects_contextvar` et `test_admin_api_bootstrap_token_contextvar` réécrits :
appellent maintenant `handle_admin_api()` via scope ASGI fake + patch `_get_token_info` + spy `_json_response`.
Capturent `get_current_client_name()` pendant la requête → non-complaisant.
Si l'injection ContextVar était supprimée d'`api.py`, les tests échoueraient.

#### Sécurité — `policies.py _save()` silencieux (même pattern que TokenStore)
- `_save()` retourne `bool` + `logger.error`
- `create()` : rollback `del` si S3 KO
- `delete()` retourne `True` / `False` / `"storage_error"` pour distinguer les 3 cas
- `admin/api.py` : HTTP 503 si `storage_error` sur create/delete policy
- `server.py policy_delete` : retourne `error_type=storage_unavailable`

#### Sécurité — `create_app()` fail-fast bootstrap key
`create_app()` valide maintenant `ADMIN_BOOTSTRAP_KEY` et lève `RuntimeError` si faible/par défaut.
Protège les déploiements ASGI directs (`uvicorn factory`) hors `server.main()`.

#### Correction clés de test
`test_admin_context.py` et `test_openbao_config.py` : clé de test `test-bootstrap-key-for-unit-tests` (2 classes de caractères → invalide) remplacée par `Test-Bootstrap-Key-2026-Pour-Tests!!`.

#### Mise à jour .clinerules
Règle ajoutée : revue Codex obligatoire avant tout merge (procédure explicite).

### Fichiers modifiés
- `src/mcp_vault/auth/policies.py` — _save bool + rollbacks + delete 3-valued
- `src/mcp_vault/server.py` — create_app fail-fast + policy_delete storage_error
- `src/mcp_vault/admin/api.py` — HTTP 503 create/delete policy + revoke 400/503
- `tests/test_admin_context.py` — réécriture ASGI non-complaisant + clé test forte
- `tests/test_openbao_config.py` — clé test forte

## [0.4.15] — 2026-06-07

### Security & Tests — Audit complet non-complaisance + résiduels auth

#### Sécurité auth — 3 correctifs

**hash_prefix non validé** (`token_store.py`) : `update()` et `revoke()` acceptaient un préfixe vide ou d'un seul caractère, matchant le premier token de la liste. Ajout de `_validate_hash_prefix()` (minimum 12 chars, hexadécimal, non ambigu) et `_resolve_hash()` (erreur si 0 ou plusieurs matchs). `revoke()` appelait maintenant `_maybe_refresh()`.

**`TokenStore._save()` silencieux** : les exceptions S3 étaient avalées → `create/update/revoke` annonçaient succès sans persistance. `_save()` retourne maintenant `bool`, les appelants font un rollback mémoire et retournent une erreur HTTP 503-like si S3 indisponible. Une révocation non persistée est une faille critique.

**Tokens expirés affichés "actifs"** : `get_by_hash()` rejetait déjà les tokens expirés, mais `list_all()` et `count()` ne calculaient pas l'expiration. Ajout du helper `_is_expired(token)`, utilisé par `get_by_hash`, `list_all` (nouveau champ `expired: bool`) et `count` (exclut les expirés). Affichage "EXPIRÉ" en SPA (badge jaune) et CLI.

#### Tests — Correction du défaut structurel CLI et réécriture des tests complaisant

**Défaut structurel CLI (HAUT)** : `tests/cli/__init__.py` — `check()` ne levait jamais d'exception → pytest considérait tous les tests CLI comme réussis. Fix : `tests/cli/conftest.py` avec fixture `@pytest.fixture(autouse=True)` qui reset les compteurs avant et assert `FAIL == 0` après chaque test.

**`tests/test_admin_path_policy.py`** : réécriture complète. Les 3 tests (recherches textuelles dans le source) remplacés par 4 tests comportementaux ASGI qui appellent réellement `handle_admin_api()` et vérifient que `check_path_policy` est appelé et bloque avec HTTP 403.

**`tests/test_openbao_manager.py`** : réécriture complète. Les 2 tests (recherches textuelles) remplacés par des tests comportementaux : `start_openbao()` ne lance pas `Popen` si OpenBao est reachable, et redirige bien stdout/stderr vers des fichiers (pas `subprocess.PIPE`).

**`tests/test_crypto.py` — `test_aad_context_binding`** : réécrit pour passer par les fonctions publiques `encrypt/decrypt_with_bootstrap_key()`. L'ancienne version testait `AESGCM` directement et aurait passé même si `_AAD` était retiré de la production.

### Fichiers modifiés
- `src/mcp_vault/auth/token_store.py` — hash_prefix validation, _save fail-closed, _is_expired
- `scripts/cli/display.py` — affichage EXPIRÉ
- `src/mcp_vault/static/js/tokens.js` — badge "expiré" (jaune)
- `tests/cli/conftest.py` — NOUVEAU : fixture autouse CLI
- `tests/test_admin_path_policy.py` — réécriture comportementale
- `tests/test_openbao_manager.py` — réécriture comportementale
- `tests/test_crypto.py` — test_aad_context_binding non-complaisant

## [0.4.14] — 2026-06-07

### Security — Correctifs auth CRITIQUE + ÉLEVÉ (audit codex)

#### CRITIQUE — `ssh_sign_key` ne vérifiait pas la permission `write`
Un token `read` ayant accès au vault pouvait signer des clés SSH (opération d'émission de credential).
**Correctif** : `check_write_permission()` ajouté dans `ssh_sign_key` ([server.py](src/mcp_vault/server.py)), cohérent avec `ssh_ca_setup`.

#### ÉLEVÉ — Policy enforcement fail-open si `PolicyStore` absent
`check_policy()` et `check_path_policy()` retournaient `None` si le PolicyStore était absent, même si le token portait un `policy_id` — bypass complet des restrictions.
**Correctif** : fail-close avec audit explicite si `policy_id` présent sans PolicyStore disponible ([context.py](src/mcp_vault/auth/context.py)).

#### ÉLEVÉ — `GET /admin/api/vaults/{vault_id}` sans `check_policy()`
La route de détail vault listait tous les secrets/rôles SSH sans vérification de policy — bypass enumération pour tokens avec `path_rules`.
**Correctif** : `check_policy("vault_info")` ajouté avant `_api_vault_detail()`.

#### ÉLEVÉ — Routes REST SSH read (`ca-key`, `roles`, `role-info`) sans `check_policy()`
Incohérence avec les outils MCP équivalents qui appellent bien `check_policy()`.
**Correctif** : `check_policy("ssh_ca_public_key/list_roles/role_info")` ajoutés sur les 3 routes GET SSH.

#### Complément — `GET /admin/api/vaults` sans `check_policy("vault_list")`
Manquait pour compléter la parité REST/MCP sur la liste des vaults.
**Correctif** : `check_policy("vault_list")` ajouté.

### Revue codex
APPROUVÉ — tous les noms d'outils vérifiés cohérents avec `_TOOL_LABELS` et outils MCP.

### Fichiers modifiés
- `src/mcp_vault/server.py` — `ssh_sign_key` : check_write_permission
- `src/mcp_vault/auth/context.py` — check_policy + check_path_policy : fail-close PolicyStore absent
- `src/mcp_vault/admin/api.py` — check_policy sur vault_list, vault_info, SSH read routes

## [0.4.13] — 2026-06-07

### Feature — JIT Wrap Broker pour mcp-mission V1 (issue #7)

Implémentation du contrat `VaultClient` attendu par `mcp-mission/CredentialBrokerService` (#110, #72, #74).

#### 3 nouveaux outils MCP (accès admin requis)

| Outil | Contrat |
|---|---|
| `secret_wrap(vault_id, secret_path, mission_id, operation_id, ttl_seconds)` | Crée un wrap token single-use OpenBao (cubbyhole) scopé à la mission. Retourne `{wrap_token, secret_id, accessor, vault_url, expires_at, intended_use}`. |
| `secret_revoke_wrap(lease_id)` | Révoque un wrap token — **idempotent** : `not_found` / `already_revoked` → status OK. Erreur réseau → erreur réelle. |
| `secret_wrap_lookup(operation_id)` | Retrouve et révoque les wraps orphelins par `operation_id`. États : `not_found` \| `found_unattached` \| `already_revoked` \| `revoked` \| `ambiguous`. |

#### Architecture write-ahead (compensation #74)

Le `WrapRegistry` (S3 `_system/wrap_registry.json`) implémente un write-ahead strict :
1. Enregistrement `"pending"` **avant** l'appel OpenBao
2. Passage `"active"` avec l'accessor **après** succès
3. Si crash entre 1 et 2 → `lookup` retourne `"found_unattached"` ; le TTL Vault gérera l'expiration

#### Invariants de sécurité

- `wrap_token` jamais loggué, stocké dans le registry, ni inclus dans les erreurs
- Registry ne stocke que l'`accessor` (non utilisable seul pour unwrap)
- `revoke_wrap` refuse tout accessor absent du registry (pas de révocation hors scope)
- `wrap_secret` fail-close si registry S3 indisponible (compensation impossible)
- `mark_active` en échec → révocation immédiate de l'accessor + erreur
- `check_access` + `check_path_policy` appliqués avant wrap

#### Limitations V1 documentées

- WrapRegistry : last-write-wins (pas de CAS S3) → single broker en V1
- `found_unattached` : pas de révocation possible sans accessor (TTL 300s max)

#### Tests

- `tests/test_wrap.py` — **15 tests** (15/15) : write-ahead, idempotence revoke, états lookup, anti-fuite, rollback registry, fail-close registry=None, chemins réservés, validation server

#### Revues codex

5 passes itératives → APPROUVÉ. 10 findings traités (2 CRITICAL, 5 HIGH, 3 MEDIUM).

### Fichiers modifiés
- `src/mcp_vault/vault/wrapping.py` — NOUVEAU (WrapRegistry + wrap/revoke/lookup)
- `src/mcp_vault/server.py` — 3 outils MCP (secret_wrap, secret_revoke_wrap, secret_wrap_lookup)
- `src/mcp_vault/lifecycle.py` — init_wrap_registry au startup
- `tests/test_wrap.py` — NOUVEAU (15 tests)

## [0.4.12] — 2026-06-07

### Security — Résultats de l'audit de synchronisation CLI/Shell/Admin

#### BLOQUANT 1 — API REST admin contournait les policies tool-level (F1)
Les outils MCP appelaient `check_policy()` avant chaque action, mais les routes REST `/admin/api` ne le faisaient pas. Un token `write` avec une policy interdisant `secret_write` ou `vault_create` pouvait contourner la restriction via l'interface `/admin`.

**Correctif** : `check_policy("vault_create")`, `check_policy("vault_update")`, `check_policy("vault_delete")`, `check_policy("secret_list")`, `check_policy("secret_read")`, `check_policy("secret_write")`, `check_policy("secret_delete")`, `check_policy("ssh_ca_setup")`, `check_policy("ssh_sign_key")` ajoutés dans `admin/api.py` sur toutes les routes CRUD correspondantes. Les tokens admin contournent toujours les policies (comportement inchangé).

#### BLOQUANT 2 — `path_rules.permissions` stockées mais jamais appliquées (F2)
Le modèle de policy acceptait `read/write/admin` par chemin de secret, mais `check_path_policy()` ne vérifiait que les `allowed_paths`. Un token avec `permissions: ["read"]` pouvait écrire/supprimer dans les chemins autorisés.

**Correctif** :
- `is_path_allowed()` (`policies.py`) : nouveau paramètre `required_permission` vérifié contre `rule["permissions"]` ("write" couvre delete, "admin" couvre tout).
- `check_path_policy()` (`context.py`) : propagation du `required_permission` ("read", "write").
- Tous les appelants MCP et REST admin mis à jour avec la permission appropriée.

#### MOYEN 5 — Policy inexistante acceptée par l'API REST (F5)
L'API admin REST pouvait créer/modifier un token avec un `policy_id` invalide (alors que l'outil MCP `token_update` validait l'existence). Résultat : token bloqué fail-close.

**Correctif** : validation de l'existence de la policy dans `_api_create_token()` et `_api_update_token()`.

### Fichiers modifiés
- `src/mcp_vault/admin/api.py` — F1 (check_policy) + F5 (validation policy)
- `src/mcp_vault/auth/policies.py` — F2 (is_path_allowed avec required_permission)
- `src/mcp_vault/auth/context.py` — F2 (check_path_policy avec required_permission)
- `src/mcp_vault/server.py` — F2 (appelants MCP avec permission explicite)

## [0.4.11] — 2026-06-07

### Fix — Sentinel `_remove` stocké littéralement dans la policy des tokens (/admin)

**Bug** : dans l'interface `/admin`, modifier ou retirer la policy d'un token stockait la chaîne `_remove` comme valeur de `policy_id` au lieu de `""`. La policy enforcement cherchait alors une policy nommée `_remove` (inexistante) et bloquait tous les accès du token (fail-close).

**Cause** : `doUpdateToken()` dans `tokens.js` envoyait le sentinel MCP `_remove` à l'API REST `/admin/api/tokens/{hash}`, qui ne le gère pas (contrairement à l'outil MCP `token_update`).

**Deuxième bug** : ouvrir le modal d'édition pour un token sans policy affichait la policy sélectionnée lors du précédent appel (le `select` n'était réinitialisé à `""` que si `policyId` était truthy).

**Correctifs** :
- `tokens.js` — `doUpdateToken()` : envoie `policy_id: ""` au lieu de `"_remove"` pour retirer la policy.
- `tokens.js` — `openEditToken()` : le `select` est toujours réinitialisé à la valeur du token courant (`""` si aucune policy), même si `policyId` est vide.
- `token_store.py` — `update()` : le sentinel `_remove` est converti en `""` (robustesse vis-à-vis de l'outil MCP).
- `token_store.py` — `load()` : migration auto des valeurs `"_remove"` stockées → `""` au prochain rechargement du Token Store.
- `admin.html` : tooltip corrigé (suppression de la mention de `_remove` qui ne s'applique qu'à la CLI MCP).

### Fichiers modifiés
- `src/mcp_vault/static/js/tokens.js`
- `src/mcp_vault/auth/token_store.py`
- `src/mcp_vault/static/admin.html`

## [0.4.10] — 2026-06-07

### Fix — `/mcp` renvoie HTTP 421 « Invalid Host header » sur le FQDN public (issue #3)

**Bug bloquant** : aucun client MCP (Claude Code, Codex, …) ne pouvait se connecter via `https://vault.mcp.cloud-temple.app/mcp` — l'endpoint répondait `HTTP 421 Invalid Host header` **avant** la couche d'authentification.

**Cause racine** : `FastMCP()` était instancié sans paramètre `host`. Le SDK MCP (≥1.x) auto-active alors la protection anti-DNS-rebinding avec pour seuls hosts autorisés le loopback (`127.0.0.1`, `localhost`, `[::1]`). Tout `Host` correspondant au FQDN public était donc rejeté par le `TransportSecurityMiddleware`.

**Correctif** :
- `_build_transport_security()` (`server.py`) construit explicitement les `TransportSecuritySettings` : protection **maintenue active**, loopback **toujours** autorisé (health checks, tests e2e via WAF localhost) + FQDN publics issus de la config.
- Nouveaux réglages `MCP_ALLOWED_HOSTS` / `MCP_ALLOWED_ORIGINS` (`config.py`), défaut = `vault.mcp.cloud-temple.app,my.vault.mcp.cloud-temple.app`, surchargeables par variable d'environnement (liste CSV).
- Normalisation des FQDN en minuscules (DNS insensible à la casse) + déduplication ; dérivation automatique de l'origin `https://<fqdn>` et de la variante avec port (`<fqdn>:*`).

### Security — Durcissements complémentaires
- **Fail-fast `ADMIN_BOOTSTRAP_KEY`** (`server.py`) : le service refuse désormais de démarrer si la bootstrap key est vide / par défaut / faible (auparavant simple warning). Cette clé chiffre les clés unseal et sert de credential admin de secours.
- **`Settings` strict** (`config.py`) : champ `waf_port` déclaré explicitement (variable partagée avec docker-compose) ; `extra="forbid"` conservé → toute variable inconnue (typo de config) lève une erreur explicite au lieu d'être silencieusement ignorée.

### Tests
- `tests/test_transport_security.py` — 11 tests (FQDN acceptés, loopback, casse, dédup, IPv6 `[::1]`, host inconnu rejeté, protection active, override env).

### Fichiers modifiés
- `src/mcp_vault/server.py` — `_build_transport_security()` + `FastMCP(transport_security=…)` + fail-fast bootstrap key
- `src/mcp_vault/config.py` — `MCP_ALLOWED_HOSTS` / `MCP_ALLOWED_ORIGINS` / `waf_port`, normalisation CSV
- `src/mcp_vault/lifecycle.py` — validation bootstrap key en défense en profondeur
- `.env.example` — documentation des nouvelles variables
- `tests/test_transport_security.py` — nouveau

### Validation
- Revue de code complète (codex, 2 passes) → APPROUVÉ.
- 11/11 transport_security + 18/18 crypto.

## [0.4.9] — 2026-04-25

### Security — Enforcement `path_rules` sur l'API REST admin (PR #2)

**Faille corrigée** : les `allowed_paths` des policies étaient appliquées sur les outils MCP (`server.py`) mais **pas** sur les routes REST admin `/admin/api/vaults/{vault}/secrets/*`. Un token non-admin avec `allowed_paths: ["app/creds"]` pouvait lire `other/secret` via l'API REST.

**Correctifs (`admin/api.py`)** :
- `check_path_policy()` ajouté sur les 4 routes REST secrets : GET list, GET read, POST write, DELETE
- Ajout de `try/except json.JSONDecodeError` sur le POST (meilleure gestion du body invalide)
- Aligne le comportement REST admin avec les outils MCP (qui avaient déjà ces checks)

**Hardening OpenBao (`openbao/config.py`)** :
- L'adresse listener HCL est désormais dérivée de `OPENBAO_ADDR` au lieu d'être hardcodée `127.0.0.1:8200`
- Permet les environnements de test avec port custom

**Robustesse startup (`openbao/manager.py`)** :
- `start_openbao()` est idempotent : si OpenBao est déjà accessible, réutilise l'instance
- stdout/stderr redirigés vers des fichiers log (`/openbao/logs/`)
- Détection de crash immédiat avec affichage des 40 dernières lignes stderr

### Tests
- `tests/test_admin_path_policy.py` — 3 tests (vérification de l'import et de l'application de `check_path_policy`)
- `tests/test_openbao_config.py` — 2 tests fonctionnels (`_compute_openbao_listen_addr` port défaut + custom)
- `tests/test_openbao_manager.py` — 2 tests (redirection logs + réutilisation instance)

### Fichiers modifiés (6)
- `src/mcp_vault/admin/api.py` — enforcement `check_path_policy()` sur 4 routes secrets
- `src/mcp_vault/openbao/config.py` — listener dynamique via `_compute_openbao_listen_addr()`
- `src/mcp_vault/openbao/manager.py` — idempotency, logs fichiers, détection crash
- `tests/test_admin_path_policy.py` — nouveau
- `tests/test_openbao_config.py` — nouveau
- `tests/test_openbao_manager.py` — nouveau

### Audit Review — 3 findings non-bloquants documentés
- **F7** : Si `OPENBAO_ADDR=http://0.0.0.0:8200`, listener ouvert (mitigé : port non exposé dans Docker)
- **F9** : Réutilisation d'instance sans vérification d'identité (mitigé : réseau Docker isolé)
- **F10** : `_process=None` après réutilisation → `stop_openbao()` no-op (impact limité)

### Contributeur
- PR #2 par [@camilleein](https://github.com/camilleein)

---

## [0.4.8] — 2026-04-25

### Bugfix — Contexte d'authentification dans l'Admin API (PR #1)

Le `created_by` des vaults et policies créés via `/admin/api/*` était toujours `anonymous` au lieu du vrai `client_name` du token Bearer.

**Cause racine :**
- `AdminMiddleware` court-circuite la stack ASGI avant `AuthMiddleware`, donc la `ContextVar` `current_token_info` n'était jamais peuplée pour les requêtes admin API.

**Correctifs :**
- `handle_admin_api()` injecte désormais `current_token_info` (même pattern que `AuthMiddleware`) avec `try/finally/reset`
- Logique de routage extraite dans `_handle_admin_routes()` pour un scoping propre
- `_api_create_policy()` utilise `get_current_client_name()` au lieu de `'admin'` hardcodé

### Tests
- Nouveau `tests/test_admin_context.py` (15 tests, 0 dépendance S3/OpenBao)
  - `TestAdminApiContextVar` : injection, bootstrap, anonymous, isolation
  - `TestAuthContextPermissions` : access, write, admin, client_name
  - `TestAdminApiCodeStructure` : vérification AST du fix

### Fichiers modifiés (3)
- `src/mcp_vault/admin/api.py` — injection ContextVar dans handle_admin_api()
- `tests/test_admin_context.py` — nouvelle suite de 15 tests
- `.gitignore` — ajout d'entrée

### Contributeur
- PR #1 par [@camilleein](https://github.com/camilleein)

---

## [0.4.7] — 2026-03-31

### Bugfix — Affichage du token créé dans /admin + dates dans toutes les interfaces

#### 🔴 Token non affiché après création dans /admin SPA

Le token créé via la console `/admin` n'était **jamais affiché** à l'utilisateur — impossible de le copier.

**Triple cause racine :**
1. `tokens.js` vérifiait `data.token` alors que l'API retourne `data.raw_token` → condition toujours fausse
2. `loadTokens()` était appelé **après** l'affichage du token, recréant le DOM et écrasant le résultat
3. Aucun scroll vers le token affiché

**Correctifs :**
- `data.token` → `data.raw_token` dans la condition d'affichage
- `await loadTokens()` appelé **avant** l'affichage du token (le div `newTokenResult` est recréé par `loadTokens`, puis rempli)
- Ajout de `scrollIntoView()` pour garantir la visibilité du token
- Affichage enrichi : hash tronqué, date d'expiration, policy associée

#### 🟡 Dates de création et de révocation manquantes

Les dates de création et de révocation des tokens n'étaient pas visibles dans aucune des 3 interfaces (SPA, CLI Click, Shell interactif).

**Correctifs backend (`token_store.py`) :**
- `list_all()` retourne désormais `created_at` et `revoked_at`
- `revoke()` stocke `revoked_at` avec timestamp ISO UTC

**Correctifs SPA `/admin` (`tokens.js`) :**
- Nouvelle colonne **Créé le** (date + heure formatées en `fr-FR`)
- Colonne **Statut** enrichie : affiche la date de révocation sous le badge "révoqué"

**Correctifs CLI Click + Shell (`display.py`) :**
- Nouvelle colonne **Créé le** (date ISO tronquée `YYYY-MM-DD`)
- Colonne **Statut** unifiée : `actif → YYYY-MM-DD` (expiration) ou `RÉVOQUÉ YYYY-MM-DD`

### Fichiers modifiés (4)
- `src/mcp_vault/auth/token_store.py` — `list_all()` + `revoke()` enrichis
- `src/mcp_vault/static/js/tokens.js` — fix affichage token + colonnes dates
- `scripts/cli/display.py` — colonnes Créé le / Statut dans `show_token_result()`
- `VERSION` — 0.4.6 → 0.4.7

### Tests
- **18/18 tests crypto** — zéro régression
- **197/197 tests CLI** — zéro régression

---

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
