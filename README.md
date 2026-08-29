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
| [**scripts/README.md**](scripts/README.md)              | Guide CLI complet — groupes de commandes, exemples, confort d'utilisation                                                                                                       |
| [**tests/README.md**](tests/README.md)                  | Guide d'exécution des tests — 4 niveaux, ~600 tests, commandes pour auditeurs                                                                                                |
| [**TEST_CATALOG.md**](tests/TEST_CATALOG.md)            | Catalogue des tests e2e — 15 catégories, 349 assertions, objectif de chaque section (pour auditeurs)                                                                        |

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

# 4. Tester (349 tests e2e)
docker compose exec mcp-vault python tests/test_e2e.py
```

### Lifecycle automatique

Au démarrage, MCP Vault :
1. Charge les tokens depuis S3
2. Restaure les données OpenBao (volume Docker en priorité ; sinon S3 — un échec S3 ambigu, ex. réseau, refuse le démarrage plutôt que d'initialiser un coffre vide par-dessus une sauvegarde distante valide)
3. Démarre OpenBao, l'initialise (1ère fois) et le déverrouille
4. **Clés unseal** : chiffrées (AES-256-GCM) sur S3, jamais en clair sur disque — uniquement en mémoire
5. Active le sync S3 périodique (60s, **conditionnel** : un PUT n'est effectué que si l'état a changé depuis le dernier upload réussi — cf. `s3_sync.py`)

À l'arrêt (`docker compose stop`) :
1. Scelle OpenBao 🔒
2. Upload final vers S3 📤
3. Arrête le processus — clés effacées de la mémoire

---

## 🛠️ Outils MCP (39)

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

### Accès SSH JIT opérateur (2) *(v0.9.0)*

| Outil | Perm | Description |
| --- | --- | --- |
| `ssh_operator_access_profiles()` | read | Liste les profils fermés utilisables par le bearer nominatif courant |
| `ssh_request_operator_access(profile_id, public_key, reason)` | write | Émet un certificat court lié à une clé publique pré-enrôlée |

Le demandeur ne choisit jamais le coffre CA, le rôle, le principal, la cible
ou le TTL. L'identité de l'opérateur repose sur un bearer token nominatif
scopé par une policy dédiée (même mécanisme que le reste du système), plus
une clé publique SSH standard (`ssh-ed25519`/`ecdsa-sha2-nistp256`)
pré-enrôlée par empreinte. Ce parcours humain exceptionnel reste distinct du
breaking-glass externe et du parcours agentique.
Les profils peuvent être fournis par `SSH_OPERATOR_PROFILES_JSON` ou, pour un
renderer `.env` strict, par son équivalent Base64 URL-safe
`SSH_OPERATOR_PROFILES_B64` ; les deux sources sont mutuellement exclusives.

### Policies MCP — contrôle d'accès granulaire (4)

Les policies permettent de restreindre finement les outils accessibles par token, avec support des **wildcards** (`system_*`, `ssh_*`...) et des **règles par vault** (`prod-*` → lecture seule).

| Outil                                                                                | Perm  | Description                                         |
| ------------------------------------------------------------------------------------ | ----- | --------------------------------------------------- |
| `policy_create(policy_id, description?, allowed_tools?, denied_tools?, path_rules?)` | admin | Crée une policy avec règles d'accès                 |
| `policy_list()`                                                                      | admin | Liste les policies avec compteurs                   |
| `policy_get(policy_id)`                                                              | admin | Détails complets (allowed/denied tools, path_rules) |
| `policy_delete(policy_id, confirm)`                                                  | admin | Supprime une policy ⚠️                            |

> 📋 6 policies prêtes à l'emploi documentées dans [ARCHITECTURE.md §6.4.1](DESIGN/mcp-vault/ARCHITECTURE.md) : `readonly`, `operator-ssh-jit`, `developer`, `prod-reader-dev-writer`, `ci-cd-agent`, `security-auditor`
>
> 🔒 **Fail-close sur panne S3** *(v0.8.3, #86)* : après expiration du cache (5 min),
> une panne ou une corruption S3 détectée fait refuser explicitement les décisions
> de policy, plutôt que de continuer à servir silencieusement d'anciennes règles.

### Token Management (1)

| Outil                                                          | Perm  | Description                                              |
| -------------------------------------------------------------- | ----- | -------------------------------------------------------- |
| `token_update(hash_prefix, policy_id?, permissions?, vaults?)` | admin | Modifier un token existant (policy, permissions, vaults) |

> **Purge des tokens révoqués** *(v0.7.0 — opération **admin**, exposée en REST / CLI / SPA ; ce n'est PAS un outil MCP)* : supprime définitivement les tokens révoqués depuis plus de N jours (rétention, défaut 30). **Fail-close** (jamais un token actif ni un token expiré non révoqué), **dry-run + confirmation**, rollback si S3 indisponible, chaque purge **auditée**. Via `POST /admin/api/tokens/purge`, la commande CLI `token purge-revoked`, ou le bouton « 🧹 Purger révoqués » de la console `/admin`.
>
> 🔒 **Validation stricte** *(v0.8.3, #86)* : `permissions`/`allowed_resources` sont
> désormais validés strictement à la création, la modification et le chargement —
> jamais permissifs par défaut sur une entrée malformée (corrige une élévation de
> privilège possible via une valeur du mauvais type).

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

### JIT Wrap Broker + consommation médiée — C18 (5) *(v0.4.13 / v0.6.x)*

Contrat pour le `CredentialBrokerService` de mcp-mission : livraison de credentials single-use via response wrapping OpenBao (cubbyhole), registry write-ahead sur S3 pour la compensation des orphelins, et validation anti-confused-deputy (C18).

> ⚠️ **`ttl_seconds` borne la fenêtre pour OBTENIR le secret, PAS la durée de vie du secret OBTENU** *(#156)*. L'enveloppe est à usage unique et meurt à son TTL (borné ici entre **60 s et 3600 s** ; `mcp-mission` se plafonne à 300 s, ce qui est **son** choix et non notre plafond). MCP Vault **n'impose aucune expiration** au secret KV ni au credential qu'il contient, et **sa validité réelle dépend de son émetteur** — pas de nous.
> ⚠️ Et ni l'un ni l'autre de nos deux verbes ne suffit à l'invalider : `secret_write` **ajoute une version** (la précédente reste lisible par son numéro), et `secret_delete` retire les versions **du coffre**, pas le mot de passe de la machine ni la clé chez son fournisseur. **Seule une révocation ou une rotation coordonnée chez l'émetteur invalide effectivement un credential externe.**
> ⇒ Si une mission meurt après un déballage, **la durée d'exposition n'est bornée par personne**, et le remède n'est pas dans cet outil.
> Ce que nous **ne** gardons pas : aucune copie de la valeur déballée. Elle est rendue à l'appelant sans être stockée, le champ `data` est retiré de la piste d'audit, et aucun journal ne la porte. L'entrée de registre conserve l'accessor, `vault_id` et `secret_path` — **jamais la valeur**.

| Outil | Perm | Description |
| --- | --- | --- |
| `secret_wrap(vault_id, secret_path, mission_id, operation_id, ttl_seconds?, tenant_id?, expected_aud?)` | wrap | Crée un wrap token single-use (write-ahead registry). ⚠️ **`tenant_id` OBLIGATOIRE si `ENFORCE_MISSION_TOKEN_VALIDATION=true`** — le serveur ne peut pas le déduire, et une provision au binding incomplet serait refusée à la consommation *(#78)*. `expected_aud` absente (ou blanche) est complétée depuis la configuration ; une audience désignant une **autre** instance est refusée (`binding_mismatch`) car le wrap serait inconsommable ; configuration durcie incohérente (JWKS vide, audience non résoluble) → `misconfigured` |
| `secret_revoke_wrap(lease_id)` | wrap | Révocation idempotente, limitée au périmètre de l'appelant ; registre non initialisé → `error/registry_unavailable` *(#120)*. ⚠️ Un accessor introuvable **dans un registre disponible** rend `ok/not_found` : c'est un **succès d'appel**, pas une révocation — aucun appel OpenBao n'a été tenté (voir la table de recréation plus bas) |
| `secret_wrap_lookup(operation_id, mission_id)` | wrap | Retrouve & **révoque** les wraps du couple (compensation orphelins #74), limité au périmètre de l'appelant. ⚠️ `mission_id` REQUIS : un operation_id n'est pas unique entre missions, et sans lui la compensation d'un orphelin révoquait la provision vivante d'une AUTRE mission |
| `secret_wrap_status(operation_id, mission_id)` | wrap | Consulte l'état d'un wrap **sans le révoquer** — lecture seule, instantané best-effort (#77), limité au périmètre de l'appelant. ⚠️ `mission_id` REQUIS : sans lui, l'état des provisions d'une autre mission était divulgué |
| `secret_consume(wrap_token, operation_id, mission_token)` | admin | Valide JWT ES256/JWKS (contrat PEP complet depuis *(#86)* : exp/iat/iss/aud/mission_id/jti/scope/tenant_id + `component_id`), vérifie binding complet (mission_id, tenant_id, aud) — en mode durci les DEUX champs sont exigés *(#78)*, unwrap OpenBao (C18). Contrat d'erreurs non réessayables : `wrap_unusable`, `consume_outcome_unknown`, `empty_secret` *(#78)* |

> *(#115)* Permission `wrap` (ou `admin`) : un jeton `wrap` non-admin doit porter `allowed_resources` non vide **et** une policy explicite (`allowed_tools` nommés, `path_rule` avec `allowed_paths` non vides — évaluation stricte). Un jeton wrap-only (sans read/write/admin) est confiné à ces 4 outils (MCP) et refusé sur tout `/admin/api/*`. ⚠️ Downgrade ≤ 0.9.2 : révoquer/purger les jetons `wrap` d'abord (sinon `tokens.json` rejeté en bloc, cf. CHANGELOG).
> Activer la validation C18 avec `ENFORCE_MISSION_TOKEN_VALIDATION=true`. Par défaut (false) : un jeton **invalide** est journalisé puis non opposé — zéro impact standalone sans mcp-mission.
> ⚠️ *Rectifié en v0.16.3 (#154) : « continue » était trompeur.* Sans enforcement, un échec de validation laisse `mission_id` vide, donc la clé composite ne correspond à rien et la consommation est **refusée** au registre. Et surtout, ce qui exprime **notre propre incapacité** — service de clés injoignable, audience non résolue, validateur non initialisé — est refusé **dans les deux postures**, en `backend_unavailable` ou `misconfigured` : `enforce` arbitre si un jeton invalide est fatal, il n'arbitre pas si nous disons la vérité sur le motif du refus.
> `tenant_id` et `expected_aud` dans `secret_wrap` alimentent le binding C18 complet côté `secret_consume` *(v0.6.8)*.
> ⚠️ *(#86)* Dès que `ENFORCE_MISSION_TOKEN_VALIDATION=true` (seul, ou via le PEP `/mcp` ci-dessous), `MISSION_JWKS_URL`, `MCP_INSTANCE_ID`/`MISSION_TOKEN_AUD` **et** `MISSION_STATUS_URL` deviennent obligatoires (fail-fast au boot) — sans quoi une mission abortée conserverait l'accès jusqu'à expiration du `mission_token`.
> ⚠️ *(#86)* Le validateur applique désormais EXACTEMENT le même contrat que le PEP `/mcp` ci-dessous (mêmes claims requis, même vérification `component_id`) — un JWT authentique mais destiné à une autre instance vault est rejeté par les deux points d'application, pas seulement le premier.

#### Matrice d'effet externe — ce qu'un code d'erreur permet de DÉDUIRE *(v0.14.0)*

**Tous les codes métier arrivent en ENVELOPPE, `isError = false`.** Un appelant qui
ne regarde que `isError` les prend pour des succès. **Lire `status`, puis
`error_type`** — dans cet ordre, car certains refus n'ont pas encore de code
(voir la note en fin de section).

`isError = true` ne signale que deux choses : une **non-conformité au schéma**
(paramètre requis absent **ou** de mauvais type — le corps de l'outil n'a pas
tourné, donc aucune écriture, aucun appel OpenBao, aucune révocation), ou un
défaut non prévu. Un paramètre conforme au schéma mais **refusé sémantiquement**
revient en enveloppe.

**`secret_wrap`** — le nom du code ne suffit pas : une ressource peut exister.

| Code | Appel OpenBao | Ressource à compenser |
| --- | --- | --- |
| `invalid_input`, `backend_unavailable`, `operation_pending` | **absent** | non, pour cet appel |
| `operation_failed` *(v0.13.0)* | **absent** pour cet appel | ⚠️ **possiblement, d'une tentative ANTÉRIEURE** — sans accessor, donc non compensable |
| `operation_revocable` *(v0.13.0)* | **absent** pour cet appel | ⚠️ **possiblement, d'une provision ANTÉRIEURE** — mais elle porte un accessor, donc elle **est** compensable |
| `operation_terminated` *(v0.14.0)* | **absent** pour cet appel | non — provision antérieure tenue pour terminée, rien à compenser |
| `registry_inconsistent` *(v0.14.0)* | **absent** pour cet appel | ⚠️ **inconnu** — entrée illisible, rien ne peut en être déduit |
| `registry_unavailable` | **absent** | non |
| `wrap_created_revoked` | **wrap créé** | non — révocation confirmée |
| `wrap_created_orphaned` | **wrap créé** | ⚠️ **possiblement** — active jusqu'au TTL, **non compensable** |
| `not_found`, `backend_error` | **émis** | ⚠️ **inconnu** — ne pas rejouer la même clé |

⚠️ `backend_error` peut suivre un appel qu'OpenBao a reçu (délai dépassé, coupure) ;
`not_found` est déduit d'un motif cherché dans le texte de l'exception, donc non
prouvé. Dans les deux cas l'intention passe `failed` **sans accessor**.

**La clé est alors BLOQUÉE DÉFINITIVEMENT** — un rejeu rend `operation_failed`,
sans aucun appel OpenBao. *(Jusqu'en v0.12.1 elle redevenait rejouable, et le
rejeu créait un second wrap pendant que le premier pouvait vivre.)* Si la
persistance du marquage échoue, l'entrée revient `pending` et la clé est bloquée
sous `operation_pending` : le blocage est le même, seul le code diffère.
**Reprise = nouvel `operation_id`, dans tous les cas.**

> ⚠️ **v0.14.0 — UNE CLÉ EST À USAGE UNIQUE, SANS CONDITION.** La moindre entrée
> pour le couple `(operation_id, mission_id)` bloque `secret_wrap`, quel que soit
> son état, **entrée corrompue comprise** : une entrée illisible est une raison de
> refuser, jamais d'autoriser. **Plus rien ne libère une clé.**
>
> En v0.13.0, `revoked`, `consumed` et `unusable` la rouvraient — pour préserver
> la reprise « révoquer puis recréer » du broker. Celle-ci a été retirée de sa
> conception, et le recensement des porteurs de jeton `wrap` en production n'en a
> trouvé qu'un seul. Cette libération était aussi le dernier chemin par lequel un
> jeton **étranger** présenté à `secret_consume` pouvait marquer une entrée
> `unusable` — et libérer une clé dont le wrap réel vivait encore.
>
> ⚠️ **La garde ne porte QUE sur la création.** `secret_revoke_wrap`,
> `secret_wrap_status` et `secret_wrap_lookup` restent ouverts sur une clé
> engagée : sans cela l'appelant serait enfermé avec des ressources qu'il ne
> pourrait plus ni voir ni couper. Un test compte les appelants de la garde et
> échoue s'il en apparaît un second.
>
> ⚠️ **Deux contournements ne sont PAS fermés** : la perte du fichier de registre
> (registre vide = toutes les clés redeviennent vierges) et la course entre deux
> instances, faute de CAS/ETag *(#51)*. Ce ne sont pas des libérations métier,
> mais l'unicité n'est pas absolue pour autant.
>
> ⚠️ **Ce premier contournement était plus large que cette phrase ne le disait,
> jusqu'à v0.15.0 incluse** *(#149, corrigé en v0.16.0)*. Il ne fallait pas perdre
> le fichier : **il suffisait d'une erreur de stockage mal lue.** Le registre
> concluait « objet absent » dès que le texte de l'erreur *contenait* « 404 » —
> un identifiant de requête, un port, un 404 émis par un intermédiaire — puis
> repartait vide **en se déclarant fiable**, si bien que le refus fail-close ne
> se déclenchait pas et que la sonde ne signalait rien. **Une seconde porte
> menait au même effet sans aucune erreur** : une lecture qui réussissait en
> renvoyant un JSON valide mais sans la clé `wraps` (un `{}`, un corps tronqué)
> était prise pour un registre vide. Désormais, seule une absence authentifiée par
> le champ d'erreur structuré (`NoSuchKey`) vide le registre, et le document est
> validé avant toute mutation d'état ; tout le reste refuse la création. C'est la
> règle que les trois magasins d'autorisation appliquent depuis #69.

> Une intention `failed` (ou `pending`) sans accessor rend `found_unattached` sur `secret_wrap_lookup` : aucune révocation n'est possible, seul le TTL borne la ressource éventuelle. ⚠️ Ce verdict ne dit **pas** qu'une ressource existe — il dit que nous ne pouvons pas l'exclure. *(v0.12.1 : ce cas répondait `already_revoked`, affirmant une révocation inexistante.)*

**Les quatre autres outils**, sur les codes d'indisponibilité :

| Outil | Effet externe | Conduite |
| --- | --- | --- |
| `secret_revoke_wrap` — `ok` + `registry_persisted: false` *(v0.14.1)* | **révocation FAITE**, mais non inscrite au registre | rejouer la compensation plus tard — voir l'encadré ci-dessous |
| `secret_revoke_wrap` — `registry_unavailable`, `backend_unavailable` | **absent**, aucune révocation tentée | rejeu sûr **et nécessaire** |
| `secret_revoke_wrap` — `backend_error` | appel **émis**, effet **inconnu** | rejeu sûr (révocation idempotente) |
| `secret_wrap_lookup` — `backend_unavailable` | **absent** : les deux gardes fail-close précèdent toute révocation | attente puis rejeu, sûr |
| `secret_wrap_lookup` — `partial_revocation` | **inconnu** sur les entrées non comptées (`count_revoked` dit ce qui a abouti) | rejeu sûr, mais il ne résoudra pas les entrées figées |
| `secret_wrap_status` — `backend_unavailable` | **absent** : registre absent ou dernier rafraîchissement S3 échoué | rejeu toujours sûr |

> ⚠️ **UN EFFET CONFIRMÉ PEUT NE PAS SURVIVRE À UN REDÉMARRAGE** *(limite
> structurelle, #140 — **arbitrée**, cf. #123)*. Quand une révocation réussit
> côté coffre mais que l'écriture du registre échoue, le fait n'est inscrit
> **nulle part de durable** : au redémarrage, l'entrée **peut réapparaître non
> révoquée**, dans un état que nous venons d'annoncer révoqué à l'appelant.
>
> *« Peut » et non « va »* : une exception S3 ne prouve pas que l'écriture n'a
> pas abouti — un délai d'attente peut suivre une écriture déjà acceptée — et le
> registre est en **dernier-écrivain-gagne sans verrou**, une autre instance a pu
> écrire entre-temps. L'appelant ne peut donc pas déduire l'état durable de
> l'échec ; il ne peut que le tenir pour **indéterminé**.
>
> **Ce n'est pas réparable avec un seul support durable** — inscrire le fait
> exigerait un support disponible au moment précis où le support habituel ne
> l'est pas. Le tenir supposerait un **second support** : un journal local,
> rejoué en réconciliation **avant** de resservir le registre. Le volume local
> existe déjà dans le déploiement ; le mécanisme, non — et il serait **local à
> l'instance**, invisible d'une autre et perdu avec l'hôte.
>
> ⚠️ **DÉCISION (#123) : ce second support ne sera pas construit.** La limite est
> **assumée et publiée**, elle n'est pas en attente d'un correctif.
> **Ne dimensionnez pas votre contrat en supposant qu'elle disparaîtra.**
>
> Ce que nous faisons à la place, depuis **v0.14.1** : nous ne rendons pas le
> fait durable, mais nous **le disons** — la réponse porte alors
> `registry_persisted: false` et un `warning`. Le champ est **absent** sur le
> chemin nominal.
>
> ⚠️ **Le signal a la MÊME forme sur les DEUX verbes de révocation** —
> `secret_revoke_wrap` et `secret_wrap_lookup` : `registry_persisted: false`,
> `count_not_persisted` (le nombre d'entrées effectivement muées et non
> inscrites) et un `warning`. Sur la compensation il est porté **aussi par les
> sorties `partial_revocation` et `consume_terminal`** — l'appelant y gère déjà
> un incident, c'est le pire moment pour lui taire une révocation non consignée.
>
> ⇒ **Conduite** : traiter un retour portant `registry_persisted: false` comme
> une révocation **réelle mais non consignée** — ne pas clore son propre
> registre dessus, et repasser la compensation plus tard. La même limite touche
> la révocation d'urgence de `secret_wrap`, où l'entrée reste `pending` et où
> `secret_wrap_lookup` répondra `found_unattached` pour une ressource que nous
> **tenons pour** morte — le serveur traite un retour OpenBao sans exception
> comme une révocation confirmée, il ne relit rien pour l'attester.

> `secret_wrap_status` ne mute ni OpenBao ni le registre (cache et journal d'audit, eux, bougent). Il ne distingue **pas** le transitoire du durable : instantané best-effort. ⚠️ *Corrigé en v0.15.0* — une panne S3 survenant pendant la fenêtre de cache n'était alors **pas détectée du tout** ; le rafraîchisseur de fond la constate désormais à sa prochaine tentative (mi-TTL, puis toutes les 10 s), et `status` bascule en `backend_unavailable`. La détection n'est donc pas instantanée, mais elle a lieu.

#### Ce que le registre PROUVE — et ce qu'il ne prouve pas

🔴 **`secret_wrap_status` rend ce que le REGISTRE CROIT, pas un constat OpenBao.**
Aucun client OpenBao n'est appelé. Chaque réponse est une **croyance datée** :

- **`active` ne prouve pas qu'un wrap vit** — il a pu expirer, être consommé ou
  révoqué chez OpenBao sans qu'aucune transition de registre ne soit écrite.
- **`consuming` n'atteste pas qu'un déballage soit parti** : l'état est persisté
  **avant** l'appel d'unwrap.
- **`consumed`, `revoked`, `unusable` ne parlent que d'UNE entrée**, jamais du
  couple : plusieurs entrées peuvent coexister pour un même
  `(operation_id, mission_id)` — historiquement, parce que le verrou de clé ne
  regardait que `pending` jusqu'en v0.12.1. ⚠️ Un état terminal sur l'une ne dit
  **rien** des autres : une entrée `unusable` peut coexister avec une `active`.
- **`revoked`** est aussi posé quand OpenBao répond 400/404 : c'est de
  l'idempotence, pas une preuve du sort du jeton.

⚠️ **`ambiguous` de `secret_wrap_status` et `ambiguous` de `secret_wrap_lookup` ne
sont pas le même mot.** Le status est **pur** ; le lookup est **destructif** —
face à plusieurs entrées il révoque les actives. **Ne jamais appeler
`secret_wrap_lookup` pour comprendre un `ambiguous`** : il détruirait ce qu'on
cherche à diagnostiquer. Aucun verbe ne détaille un `ambiguous` (ni cardinalité,
ni état individuel) : c'est un refus terminal, sans investigation.

**Quand peut-on recréer après `secret_revoke_wrap` ?**

| Réponse | Recréer ? |
| --- | --- |
| `ok/revoked`, `ok/already_revoked` | ✅ révocation émise et acceptée, ou jeton déclaré invalide/absent par OpenBao |
| `ok/not_found` | ❌ **aucun appel OpenBao tenté** — accessor inconnu du registre ou hors périmètre |
| `backend_error`, `backend_unavailable`, `registry_unavailable` | ❌ rien d'attesté |

**`secret_consume`** — « aucun appel émis » ne veut **pas** dire « jeton intact » :
sur ces chemins nous ne regardons pas le jeton, qui peut avoir expiré ou avoir été
consommé en parallèle.

| Code | Cette invocation a présenté le wrap ? | État du jeton |
| --- | --- | --- |
| `invalid_input`, `misconfigured`, `jwt_invalid`, `mission_inactive` | non | **non constaté** |
| `registry_unavailable`, `backend_unavailable` | non | **non constaté** |
| `permission_denied` *(v0.12.1 — remplace une enveloppe sans code)* | non | **non constaté** |
| `binding_mismatch`, `not_found`, `already_consuming` | non | **non constaté** |
| `binding_incomplete` | non | inconsommable en mode durci → **reprovisionner** |
| `already_consumed` | non | dépensé ou révoqué |
| `wrap_unusable` | selon le chemin | **mort** |
| `consume_outcome_unknown` | **possible** | à considérer comme **perdu** |
| `empty_secret` | **oui** | **brûlé** |

⚠️ Là où l'état est **« non constaté »**, détruire l'accès de son propre fait est
une perte sèche. Mais une nouvelle tentative **n'est pas une sonde** : si la cause
du refus est levée, elle **peut consommer** le wrap.
⚠️ `backend_error` n'est **pas atteignable** sur `secret_consume` (toute exception
d'unwrap tombe en `wrap_unusable` ou `consume_outcome_unknown`), et `wrap_expired`
**n'existe pas** — il a figuré à tort dans une version antérieure de ce contrat.
⚠️ `already_consumed` regroupe `consumed` **et** `revoked` ; `secret_wrap_status`
ne désambiguïse que s'il n'existe **qu'une** entrée, sinon il rend `ambiguous`.

> **Refus sans `error_type`** — la taxonomie fermée (`unauthenticated`,
> `permission_denied`, `access_denied`, `invalid_input`, `invalid_token`,
> `policy_store_unavailable`) couvre les gardes d'autorisation partagées. Des
> refus de **validation** propres à des outils hors périmètre wrapping
> (`secret_list`, surfaces `/admin/api`) rendent encore une enveloppe sans code.
> **Tester `status` avant `error_type`.**

### PEP mission JWT — porte `/mcp` *(v0.8.0, #47 + #69)*

Second point d'application (PEP) du `mission_token` JWT ES256 de mcp-mission, **à l'entrée `/mcp`** (le premier étant `secret_consume`/C18, à la consommation). Piloté par `MCP_AUTH_MODE` :

| Mode | Comportement `/mcp` |
| --- | --- |
| `bearer` *(défaut)* | Bearer opaque **obligatoire** : une requête sans jeton, ou avec un jeton invalide, reçoit `401` au middleware (#116). |
| `bearer-anonymous` | ⚠️ **Mode d'exception** — ancien comportement de `bearer` : un appelant sans identité atteint les outils. Repli temporaire uniquement ; `CRITICAL` au démarrage. |
| `jwt` | `mission_token` JWT ES256 **obligatoire** (bearer opaque refusé). Requiert aussi `ENFORCE_MISSION_TOKEN_VALIDATION=true` et `MISSION_STATUS_URL` (fail-fast, #86). |
| `dual-stack` | JWT valide **OU** bearer opaque valide (migration). Mêmes exigences que `jwt` ci-dessus. |

En `jwt`/`dual-stack`, le middleware **refuse activement** : `401` (token absent/opaque/JWT invalide), `403` (`aud`/`component_id` ≠ instance, mission inactive), `503` (JWKS indisponible — fail-close). Un JWT invalide ne retombe **jamais** sur le bearer. Le token est vérifié contre le contrat réel mcp-mission (`aud` contient `MCP_INSTANCE_ID`, `component_id[MCP_COMPONENT_KIND] == MCP_INSTANCE_ID`, `iss`, `exp` leeway 0, `iat` anti-skew). La bootstrap key admin reste acceptée (break-glass).

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

MCP Vault inclut un CLI complet avec Click + Rich :

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

# Accès SSH JIT opérateur
python scripts/mcp_cli.py ssh profiles
python scripts/mcp_cli.py ssh request bastion-prod \
  --key ~/.ssh/id_ed25519.pub --reason "INC-230 maintenance bastion"

# PKI interne (v0.5.0)
python scripts/mcp_cli.py pki setup --lab --domains '*.lesur.lan,lesur.lan'
python scripts/mcp_cli.py pki ca-key
python scripts/mcp_cli.py pki certs
python scripts/mcp_cli.py pki revoke 12:34:ab:cd:ef:12:34:56
```

> L'aide `--help` de chaque commande explique le modèle de sécurité à 3 couches et guide l'utilisateur.

Voir [scripts/README.md](scripts/README.md) pour la documentation complète du CLI.

---

## ⚙️ Variables d'environnement

Copier `.env.example` → `.env` et adapter. **`.env.example` est le contrat de
configuration de référence** : il déclare exactement les **45** variables
consommées par `Settings` ([`src/mcp_vault/config.py`](src/mcp_vault/config.py)),
ni plus ni moins, et il est vérifié par
[`tests/test_env_example_contract.py`](tests/test_env_example_contract.py).

> ⚠️ **`extra="forbid"`** : une clé absente de ce contrat, portant une valeur non
> vide dans votre `.env`, **fait échouer le démarrage**. Ne composez jamais un
> `.env` depuis une autre source que `.env.example`.
>
> **Marqueur `REQUIRED`** : une variable dont la valeur d'exemple est `REQUIRED`
> n'a **aucun défaut utilisable**. Le marqueur échoue volontairement la
> validation — le service refuse de démarrer tant qu'un déploiement ne l'a pas
> substitué par une vraie valeur.

| Groupe | Variables | Obligatoire |
|--------|-----------|-------------|
| **Serveur** | `MCP_SERVER_NAME`, `MCP_SERVER_HOST`, `MCP_SERVER_PORT`, `MCP_SERVER_DEBUG`, `MCP_ALLOWED_HOSTS`, `MCP_ALLOWED_ORIGINS` | Non — tous ont un défaut. Mais derrière un reverse-proxy, `MCP_ALLOWED_HOSTS` doit lister les FQDN publics, sinon le SDK rejette le header `Host` en HTTP 421 (issue #3) |
| **WAF** | `WAF_PORT` | Non — défaut `8085` |
| **Auth** | `ADMIN_BOOTSTRAP_KEY` | **Oui — seule variable sans défaut utilisable.** Chiffre les clés unseal et sert de credential admin de secours. Minimum 32 caractères, ≥ 3 classes de caractères ; démarrage refusé sinon |
| **SSH JIT opérateur** *(v0.9.0)* | `SSH_OPERATOR_PROFILES_JSON` ou `SSH_OPERATOR_PROFILES_B64`, plus les 7 bornes `SSH_OPERATOR_JIT_*` | Non — vide = désactivé ; aucun secret dans le profil |
| **S3** | `S3_ENDPOINT_URL`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_BUCKET_NAME`, `S3_REGION_NAME` | **Oui pour un déploiement fonctionnel.** Le processus démarre sans S3, mais en **mode dégradé** : les stores restent en mémoire (tokens perdus à chaque redémarrage) et, sur un volume vierge, la tentative de restauration échoue de façon *ambiguë*, ce qui empêche OpenBao de démarrer (fail-close volontaire, cf. `lifecycle.py`) |
| **Storage sync** | `VAULT_S3_PREFIX`, `VAULT_S3_SYNC_INTERVAL` | Non |
| **OpenBao** | `OPENBAO_ADDR`, `OPENBAO_SHARES`, `OPENBAO_THRESHOLD`, `OPENBAO_DATA_DIR`, `OPENBAO_CONFIG_DIR` | Non |
| **PKI** *(v0.5.x)* | `PKI_BASE_URL` | Non — vide = déduit du premier FQDN ; override de l'URL ACME en test Docker |
| **Mission JWT** *(v0.6.0)* | `ENFORCE_MISSION_TOKEN_VALIDATION`, `MISSION_JWKS_URL`, `MISSION_TOKEN_AUD`, `MISSION_JWKS_CACHE_TTL`, `MISSION_JWKS_MAX_REFRESH_PER_MIN`, `MISSION_TOKEN_LEEWAY_SECONDS`, `MISSION_STATUS_URL`, `MISSION_STATUS_CACHE_TTL` | Non — standalone sans mcp-mission |
| **PEP mission JWT** *(v0.8.0)* | `MCP_AUTH_MODE` (`bearer`/`bearer-anonymous`/`jwt`/`dual-stack`), `MCP_INSTANCE_ID`, `MCP_COMPONENT_KIND` | ⚠️ **Oui depuis #116** — le défaut `bearer` exige désormais un jeton valide (401 sinon). Repli : `bearer-anonymous` (mode d'exception). `jwt`/`dual-stack` exigent `MISSION_JWKS_URL`, `MCP_INSTANCE_ID`, `MISSION_STATUS_URL` et `ENFORCE_MISSION_TOKEN_VALIDATION` à `true` (fail-fast au boot, #86) |

> **Tokens sensibles du CLI — ce ne sont PAS des variables du serveur.**
> `VAULT_WRAP_TOKEN` et `VAULT_MISSION_TOKEN` sont lus uniquement par le CLI
> (`scripts/cli/`) et ne figurent pas dans `Settings` : les placer dans `.env`
> ferait échouer le démarrage du serveur. Ils changent à chaque opération (usage
> unique, TTL court) — les passer inline devant la commande, jamais dans un
> fichier, sinon ils fuitent dans l'historique de votre shell système :
> ```bash
> VAULT_WRAP_TOKEN=hvs.CAES... mcp-vault secret consume op-123
> ```

Voir `.env.example` pour la documentation détaillée de chaque variable.

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
- **Caddy v2.11.2** compilé avec **coraza-caddy v2.5.0** (coraza v3.7.0) via `xcaddy` — montée depuis v2.2.0/coraza 3.3.3 en v0.9.2, requise par `SecRequestBodyJsonDepthLimit` (cf. #107)
- **23 fichiers de règles OWASP CoreRuleSet v4.7.0** chargés (décompte vérifiable : `grep -c '^Include /opt/crs/rules/' waf/coraza.conf`)
- Mode **Blocking sur TOUS les endpoints** (health, `/mcp`, `/admin/api`)
- **Corps JSON-RPC réellement parsé** sur `POST /mcp` (`ctl:requestBodyProcessor=JSON`, v0.9.2). Sans ce réglage, Coraza traitait le **corps entier comme une variable unique** : toute chaîne d'une liste de phrases CRS présente n'importe où — y compris dans une **valeur de secret** — déclenchait un blocage, et aucun ciblage fin d'exclusion n'était possible
- **Exclusions de RÈGLES** (`ctl:ruleRemoveById`) déclarées **avant l'Include CRS** — pattern « exclusions before CRS », requis pour neutraliser les règles évaluées en phase:1. Faux positifs couverts : Unicode français 920540, noms PowerShell 932120, distribution CA/CRL `.pem` 920440, Content-Type JOSE ACME 920420
- **Exclusions de CIBLES** (`SecRuleUpdateTargetById`) déclarées **après l'Include CRS** — sémantique inverse : cette directive modifie la *définition* de la règle, qui doit donc être déjà chargée. Couvre le faux positif 930120 sur `.env` (v0.9.2) : les **noms** d'arguments sous l'enveloppe MCP `params._meta` et les **valeurs** de la charge opaque de `secret_write` (seul outil à en recevoir une — transmise à OpenBao, qui la chiffre au repos). Le reste demeure inspecté — chemin, nom de coffre, étiquettes, nom d'outil, et toutes les règles de path traversal
- **Profondeur JSON bornée à 32** sur `POST /mcp` (`SecRequestBodyJsonDepthLimit`, v0.9.2). Sans elle, un corps de 15 Ko d'imbrication — JSON valide, 2 octets par niveau — faisait tomber le WAF en OOM. La limite **seule** créait toutefois une évasion silencieuse (au-delà du seuil, plus aucune inspection) : la règle **10011** refuse donc explicitement (400) tout corps déclaré non analysable par `REQBODY_ERROR`. ⚠️ **Limite de compatibilité** : un secret dont `data` dépasse ~28 niveaux d'imbrication interne est refusé — les types de secrets du produit sont des dictionnaires plats, aucun usage connu n'y touche
- **Gardes anti-évasion 10009/10010** (v0.9.2). Ces exclusions sont des directives *globales* dont le sélecteur est un **nom** d'argument, donc une chaîne choisie par le client : `ARGS`/`ARGS_NAMES` agrègent aussi query string et formulaire. Avant ces gardes, `GET /health?json.params.arguments.data.x=.env` passait (200) là où `GET /health?legit=.env` était refusé (403) — soit une neutralisation globale de 930120 par simple choix du nom de paramètre. Les gardes **refusent** désormais tout nom préfixé `json.` hors du corps JSON MCP analysé, discriminé par un drapeau serveur non forgeable. La propriété est imposée, pas supposée
- **Headers de sécurité** : CSP, X-Frame-Options DENY, X-XSS-Protection, nosniff
- Méthodes autorisées adaptées au protocole MCP : GET, POST, DELETE, PUT, PATCH

### Stack ASGI (6 couches)
```
PkiMiddleware → AdminMiddleware → HealthCheckMiddleware → AuthMiddleware → LoggingMiddleware → MCPServer
```

`PkiMiddleware` (v0.5.0) est la couche la plus externe — intercepte `/acme/*` et `/pki/ca/*.pem` avant l'auth (endpoints publics par design PKI/ACME).

Depuis la v0.20.0, le serveur utilise `mcp==2.1.1` et accepte à la fois le
protocole moderne `2026-07-28` et les clients legacy jusqu'à `2025-11-25`.
Le transport HTTP est **stateless** dans les deux ères : il n'exige plus
d'affinité de session. MCP Vault reste néanmoins **mono-instance** : OpenBao
embarqué, la synchronisation S3 last-write-wins et les caches d'autorisation ne
permettent pas encore un déploiement multi-réplica sûr. Le SDK annonce automatiquement la
capability `subscriptions/listen`, mais MCP Vault ne publie ni ressource ni
événement et ne configure aucun store de reprise ; cette capability est donc
inerte et doit être réauditée à chaque montée de version du SDK.

Après une fermeture de connexion sans réponse terminale, un client ne doit pas
réessayer automatiquement une mutation : son effet peut déjà avoir eu lieu.
Cela vaut notamment pour `secret_wrap_lookup`, qui révoque des wraps malgré son
nom de consultation.

### Le point de décision lit la mémoire, jamais le réseau *(v0.15.0, #123)*

Un appel S3 bloquant ne gelait pas une requête : il gelait **le service entier**,
sonde de santé comprise — 488 s mesurées en production (#110). La cause est
toujours la même : boto3 est synchrone, et un appel synchrone dans la boucle
asyncio monopolise l'unique thread qui sert toutes les requêtes.

Le lot 1 (v0.10.1) a borné la durée de ces appels, le lot 2 (#122) en a sorti
cinq de la boucle. Ce lot ferme les derniers, et ce sont les plus fréquents : les
**magasins d'autorisation**, interrogés à chaque requête authentifiée.

> **Plus aucun appel S3 ne part d'un point de décision.** Les gardes
> (`check_policy`, `check_path_policy`, `check_wrap_*`, `get_by_hash`,
> `resolve`) lisent un **instantané publié en mémoire**. Des tâches de fond — une
> par magasin — le renouvellent **hors boucle**, à la moitié du TTL, et toutes
> les 10 s après une panne.

✅ **Le dernier appel réseau synchrone du chemin d'authentification est fermé**
*(v0.16.1, #148)*. Le rafraîchissement du cache JWKS (`mission_jwt.py`,
`httpx.get` synchrone) était déclenché depuis la validation d'un jeton mission,
appelée **sans `await`** dans une coroutine. Même classe de défaut que #110, sur
un chemin aussi chaud. Il était **déclaré ici comme résidu** depuis v0.15.0 ;
il ne l'est plus.

Mesuré en production le 17/08 avant correction : **117,2 ms** de gel du service
entier par rafraîchissement, au plus une fois par TTL de 60 s. Trois chemins y
menaient, **tous des coroutines**, et les trois sont déportés hors boucle par
`run_blocking` :

| Site | Ce qui l'active |
| --- | --- |
| PEP transport (`AuthMiddleware`) | `MCP_AUTH_MODE ∈ {jwt, dual-stack}` |
| **`secret_consume`** | ⚠️ la simple **présence** de `MISSION_JWKS_URL` — c'est le chemin du déballage de chaque enveloppe de credentials |
| `POST /admin/api/auth/jwks/reload` | appel opérateur — le plus lent, il force le fetch |

> ⚠️ **`JWKSCache` n'est PAS réécrit.** Il est déjà thread-safe (`threading.Lock`) :
> plusieurs threads d'exécuteur s'y sérialisent, **un seul** fait le fetch, les
> autres trouvent l'instantané frais. Son **fail-close** (un cache périmé n'est
> jamais servi), son **backoff** et son **throttle « kid inconnu »** sont
> inchangés — les déplacer aurait transformé un gel en martèlement de l'endpoint
> de `mcp-mission`.

> ⚠️ **`MISSION_JWKS_CACHE_TTL` n'est pas un réglage de latence.** Une clé révoquée
> disparaît du JWKS de `mcp-mission` : ce TTL est donc la **fenêtre de propagation
> d'une révocation de clé de signature**. Il vaut **60 s**, cinq fois plus strict
> que le `max-age=300` qu'ils publient, et **il ne doit pas être allongé** pour
> espacer les appels.

| Ce qui change | Ce qui ne change pas |
| --- | --- |
| Le chargement quitte la boucle | Le **fail-close** de #86/#69 : sur le Policy Store, le Mission Binding Store et le registre wrap, un instantané périmé au-delà de son TTL ne sert plus aucune décision |
| Les mutations aussi (`acreate`, `adelete`, `arevoke`, …) | La **forme**, les **codes d'erreur** et les **signatures** des outils existants. Deux évolutions bornées : `system_health` gagne `stores` / `stores_stale`, et le **texte** du `warning` de révocation énonce désormais l'incertitude au lieu d'un futur certain |
| Une opération wrap est atomique vis-à-vis d'un rechargement | La posture du Token Store au point de décision : `available` y reste **diagnostique** et un instantané périmé continue techniquement d'authentifier. Depuis v0.20.1, la readiness passe néanmoins à `503` pour signaler que cette décision n'est plus garantie |

**Deux horloges, pas une.** Le code historique n'en portait qu'une, qui servait à
la fois à dater l'instantané et à brider les re-tentatives. Une panne les mettait
en désaccord : repousser la date pour ne pas marteler S3 rajeunissait aussi,
mécaniquement, un instantané jamais rechargé — un magasin en panne restait donc
« frais » indéfiniment. Elles sont désormais séparées, et en temps **monotone** :
un recul d'horloge murale ne peut plus rajeunir un état périmé.

**Copy-on-write** sur les trois magasins d'autorisation : une mutation construit
un candidat, le persiste, et ne le publie qu'après confirmation du PUT. Une garde
synchrone ne peut donc plus observer une policy créée mais non persistée, ni une
suppression que l'échec du PUT annulera. Les rollbacks disparaissent — donc aussi
le risque d'en oublier un.

> ⚠️ **Le registre wrap n'a délibérément PAS de copy-on-write.** Aucun lecteur
> synchrone ne l'interroge, et la publication-après-PUT y détruirait un acquis de
> v0.14.1 : `mark_entries_revoked` conserve **volontairement** en mémoire une
> révocation confirmée mais non inscrite, parce que la mémoire y dit la vérité et
> que c'est le support durable qui est en retard.

**Observabilité.** `system_health` porte désormais la fraîcheur de chaque magasin
(`stores`, et `stores_stale` s'il y a lieu). Sans cela, un rafraîchisseur mort ne
se verrait qu'au premier refus : le service répondrait normalement, puis
refuserait tout d'un coup.

Le registre wrap y ajoute sa **volumétrie** *(v0.16.0, #146)* : `entries`, le
nombre d'entrées, et `last_write_bytes`, le poids du dernier corps écrit — `null`
tant qu'aucune écriture n'a eu lieu depuis le démarrage. Le registre n'a ni purge
ni écriture incrémentale : il est réécrit **intégralement** à chaque transition,
et nous n'avions aucun chiffre pour dimensionner ce coût.

> ⚠️ **`last_write_bytes` est relevé à l'écriture, jamais calculé par la sonde.**
> Sérialiser le registre à chaque appel de supervision ferait de la sonde une
> cause du problème qu'elle mesure. `entries`, lui, est un simple décompte en
> mémoire.

> `/health` et `/ready` lisent désormais la fraîcheur **en mémoire** : un magasin
> configuré jamais chargé ou périmé rend le service `503 unavailable`, car les
> décisions d'autorisation ne peuvent plus être garanties. Ces sondes ne font
> aucun appel S3 ; les rafraîchisseurs existants peuvent les rétablir sans
> redémarrage. `/healthz` reste une liveness indépendante. `system_health` reste
> plus strict et vérifie en plus la connectivité S3 courante.

Ce fail-close de **readiness** est uniforme, y compris pour le Token Store : il
ne bloque pas lui-même une requête MCP déjà routée, mais demande à
l'orchestrateur de retirer l'instance. Le produit étant mono-instance, une panne
S3 assez longue pour périmer tous les magasins provoque donc une indisponibilité
totale côté load balancer. C'est le contrat explicitement retenu en v0.20.1 :
une décision d'autorisation non garantie ne doit pas être annoncée disponible.

⚠️ **Limite inchangée** : rien ici ne ferme la race d'écriture multi-instance
(#13/#51). Le dernier écrivain gagne toujours, et un rafraîchissement de fond
élargit même la fenêtre pendant laquelle deux instances peuvent diverger sans le
savoir.

### Sondes de santé *(v0.11.0, #103)*

Deux questions distinctes, deux contrats :

| Endpoint | Question | Sain | Dégradé |
| --- | --- | --- | --- |
| `/healthz` | *liveness* — le processus répond-il ? | `200` `alive` | **`200` `alive`** |
| `/health`, `/ready` | *disponibilité* — le coffre peut-il servir ? | `200` `healthy` | **`503`** |

`status` appartient à une énumération fermée, une par question : `healthy` \| `sealed` \| `unavailable` pour la disponibilité, `alive` pour la liveness. Un coffre scellé est donc identifiable de l'extérieur, sans qu'aucun détail de dépendance ne soit exposé — le diagnostic reste dans les journaux et sur `/admin/api/health`, qui exige un bearer valide.

Le `HEALTHCHECK` du conteneur vise `/health` : un coffre indisponible apparaît désormais `unhealthy`. Branchez une éventuelle sonde de *liveness* ou un autoheal sur `/healthz`, jamais sur `/health` — redémarrer un coffre **scellé** ne le descelle pas, et redémarrer ne rétablit pas S3.

Après un démarrage non abouti, l'état est **latché** : le signal ne repasse pas
au vert tout seul, un redémarrage est requis. Cette règle ne concerne pas un
magasin temporairement périmé après un démarrage abouti : son refresher peut
rétablir `/health` sans nouvelle génération.

### Lifecycle OpenBao
```
STARTUP:  S3 download (3 états : restauré / absence confirmée / échec ambigu —
          un échec ambigu refuse le démarrage) → bao server → init/unseal → periodic sync
RUNTIME:  secrets via hvac → sync S3 toutes les 60s, SEULEMENT si l'état a changé
SHUTDOWN: seal → S3 upload final (sauté si le démarrage n'a pas abouti, pour ne pas écraser une sauvegarde valide) → stop process
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
| **v0.8.0** (actuel)  | Clés sur S3 chiffrées AES-256-GCM+AAD, mémoire seule au runtime |
| **v1.0**             | Transit Auto-Unseal via OpenBao dédié (KMS Cloud Temple)                                                            |
| **v2.0**             | **Connexion HSM** (Hardware Security Module) Cloud Temple — les clés ne quittent jamais le module matériel certifié |

> 📖 Voir [DESIGN/mcp-vault/ARCHITECTURE.md](DESIGN/mcp-vault/ARCHITECTURE.md) §8 et §11 pour les détails complets.

---

## 📋 Tests (~1500 unitaires mockés + 349 e2e réels)

> 📖 Voir [tests/README.md](tests/README.md) pour le guide complet d'exécution.

```bash
# 1. Tests CLI — parsing + affichage (197 tests, SANS serveur)
python tests/test_cli_all.py

# 2. Tests CLI LIVE — cycle complet (79 tests, serveur réel)
MCP_URL=http://localhost:8085 MCP_TOKEN=<key> python tests/test_cli_live.py

# 3. Tests e2e MCP (349 tests, dans Docker)
docker compose exec mcp-vault python tests/test_e2e.py

# 4. Tests crypto (18 tests, SANS serveur — AES-256-GCM + AAD + validation entropie)
python tests/test_crypto.py

# Un seul groupe CLI
python tests/test_cli_all.py --only policy

# Un seul groupe e2e
docker compose exec mcp-vault python tests/test_e2e.py --test enforcement
```

### Couverture e2e (349 tests, 15 catégories)

| Catégorie              | Tests  | Description                                                                        |
| ---------------------- | ------ | ---------------------------------------------------------------------------------- |
| Système                | 7      | health, about, services, tools_count (37)                                          |
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
| **WAF Security**       | **62** | LFI, SQLi, XSS, RCE, scanners → 403 ; faux positif 930120 ; anti-évasion `json.*` ; bornes taille/profondeur JSON ; grammaire Content-Type ; non-régression requêtes légitimes |

---

## 📁 Structure du projet

```
mcp-vault/
├── .env.example              # Configuration (copier en .env)
├── docker-compose.yml        # WAF + MCP Vault + volumes
├── Dockerfile                # Multi-stage (OpenBao 2.5.1 + Python 3.12)
├── requirements.txt          # Dépendances Python
├── requirements.lock         # Dépendances pinnées (versions exactes)
├── VERSION                   # version courante du service
├── DESIGN/mcp-vault/
│   ├── ARCHITECTURE.md       # Spécification détaillée (v0.15.0)
│   ├── TECHNICAL.md          # Documentation technique (v0.15.0)
│   └── SECURITY_AUDIT.md     # Rapport d'audit consolidé (60 findings V2.1)
├── scripts/
│   ├── mcp_cli.py            # CLI entry point
│   ├── README.md             # Documentation CLI
│   └── cli/                  # Module CLI (Click + Rich)
│       ├── __init__.py       # Config (.env, BASE_URL, TOKEN)
│       ├── client.py         # MCPClient (Streamable HTTP)
│       ├── commands.py       # Groupes Click
│       └── display.py        # Affichage Rich
├── src/mcp_vault/
│   ├── config.py             # Configuration pydantic-settings
│   ├── server.py             # MCPServer + 39 outils MCP + lifecycle + audit
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
│   ├── test_e2e.py           # 349 tests MCP e2e (15 catégories)
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

**Licence** : Apache 2.0 | **Auteur** : Cloud Temple | **Version** : 0.20.1
