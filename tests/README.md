# 🧪 Tests — MCP Vault

> Guide d'exécution des tests pour auditeurs et développeurs.

## Vue d'ensemble

MCP Vault dispose de **4 niveaux de tests**, couvrant de la cryptographie bas-niveau jusqu'au cycle complet CLI → MCP → OpenBao → S3.

| Script                   | Tests    | Serveur requis  | Durée | Quoi                                |
| ------------------------ | -------- | --------------- | ----- | ----------------------------------- |
| `tests/test_cli_all.py`  | **197**  | ❌ Non          | ~2s   | Parsing CLI Click + affichage Rich  |
| `tests/test_cli_live.py` | **79**   | ✅ Oui          | ~10s  | Cycle complet live (8 sections)     |
| `tests/test_e2e.py`      | **~290** | ✅ Oui (Docker) | ~5s   | Tous les outils MCP (14 catégories) |
| `tests/test_crypto.py`   | **9**    | ❌ Non          | <1s   | Chiffrement AES-256-GCM             |

---

## 1. Tests CLI — Parsing et affichage (sans serveur)

Valide que **toutes les commandes Click** parsent correctement les arguments et affichent les résultats comme attendu. Aucun serveur nécessaire.

```bash
# Tous les groupes (197 tests)
python tests/test_cli_all.py

# Un seul groupe
python tests/test_cli_all.py --only policy
python tests/test_cli_all.py --only vault
python tests/test_cli_all.py --only token

# Lister les groupes
python tests/test_cli_all.py --list
```

### Groupes disponibles

| Groupe   | Commandes testées                                       |
| -------- | ------------------------------------------------------- |
| `system` | health, about, whoami                                   |
| `vault`  | create, list, info, update, delete                      |
| `secret` | write, read, list, delete, types, password              |
| `ssh`    | setup, sign, ca-key, roles, role-info                   |
| `policy` | create (+ `--path-rules` JSON), list, get, delete       |
| `token`  | create (+ `--policy`), list, update, revoke             |
| `audit`  | filtres (--limit, --client, --vault, --status, --since) |

### Ce qui est validé

- ✅ Aide `--help` de chaque commande (contenu pédagogique)
- ✅ Modèle de sécurité à 3 couches expliqué dans l'aide
- ✅ Parsing JSON `--path-rules` (invalide, pas tableau, valide, complexe)
- ✅ Validation `--data` JSON sur secret write
- ✅ Affichage Rich : tableaux, panneaux, colonnes (Owner, Policy, Vaults)
- ✅ Terminologie "Vaults" (plus "Spaces") dans tous les affichages

---

## 2. Tests CLI Live — Cycle complet (serveur réel)

Exécute les commandes **contre un serveur MCP Vault en cours d'exécution**. Teste le cycle complet : CLI → MCP Protocol → OpenBao → S3 → Réponse.

```bash
# Via le WAF (port 8085) depuis la machine hôte
MCP_URL=http://localhost:8085 \
MCP_TOKEN=<votre_bootstrap_key> \
python tests/test_cli_live.py

# Ou dans le conteneur Docker
docker compose exec mcp-vault python tests/test_cli_live.py
```

### Scénario complet (8 sections)

1. **Système** — health, about, whoami (vérification connexion)
2. **Vault CRUD** — create 2 vaults, list, info, update description, delete
3. **Secrets** — write 3 types (login, database, custom), read, list, delete, password CSPRNG
4. **Policy + Paths** — create avec `path_rules` + `allowed_paths`, get (vérification structure), list
5. **Token + Policy** — create avec `--policy`, enforcement path-level (`shared/*` OK, `web/*` DENIED), enforcement tool-level (`vault_delete` DENIED), retrait policy, vérification accès restauré
6. **SSH CA** — setup rôle, list roles, role-info, ca-key, sign clé ed25519
7. **Audit** — consultation log, filtres (denied, vault, stats)
8. **Nettoyage** — suppression de tous les objets de test (secrets, vaults, token, policy)

### Traçabilité

Chaque test affiche la **commande CLI équivalente** avant exécution :

```
  ── 5d. Enforcement path-level — web/* REFUSÉ ──
    $ mcp-vault --token <agent> secret read clitest-prod web/github
    ✅ Lecture web/github → DENIED
    ✅ Message mentionne le chemin
    → Path enforcement OK !
```

---

## 3. Tests End-to-End — Protocole MCP complet (Docker)

Teste **tous les outils MCP** (24) avec un OpenBao réel, sans mocking. C'est la suite de tests la plus complète.

```bash
# Build et exécution
docker compose exec mcp-vault python tests/test_e2e.py

# Un seul groupe
docker compose exec mcp-vault python tests/test_e2e.py --test policies
docker compose exec mcp-vault python tests/test_e2e.py --test enforcement

# Mode démo (lent, pour visualiser /admin en temps réel)
docker compose exec mcp-vault python tests/test_e2e.py --demo
```

### 14 catégories

| #   | Catégorie   | Tests | Description                          |
| --- | ----------- | ----- | ------------------------------------ |
| 1   | Système     | ~7    | health, about, services              |
| 2   | Vaults      | ~12   | CRUD, erreurs, idempotence           |
| 3   | Secrets     | ~24   | 14 types, write/read/list/delete     |
| 4   | Versioning  | ~8    | Multi-versions, rotation             |
| 5   | Password    | ~14   | CSPRNG, longueurs, exclusions        |
| 6   | Isolation   | ~7    | Cloisonnement inter-vaults           |
| 7   | Erreurs     | ~7    | Edge cases, données invalides        |
| 8   | S3 Sync     | ~3    | Archives, HEAD bucket                |
| 9   | SSH CA      | ~30   | Setup, sign, rôles, isolation        |
| 10  | Types       | ~16   | 14 types validés individuellement    |
| 11  | Admin API   | ~15   | Health, whoami, password gen         |
| 12  | Policies    | ~43   | CRUD, wildcards, path_rules          |
| 13  | Enforcement | ~56   | Owner-based, vault-level, path-level |
| 14  | Audit       | ~31   | Events, filtres, stats, denied       |

---

## 4. Tests Cryptographie (sans serveur)

Valide le module de chiffrement AES-256-GCM utilisé pour sécuriser les clés unseal.

```bash
python tests/test_crypto.py
```

---

## Structure des fichiers

```
tests/
├── README.md                  ← ce fichier
├── TEST_CATALOG.md            ← catalogue détaillé pour auditeurs
├── __init__.py
│
├── test_cli_all.py            ← 197 tests CLI parsing (sans serveur)
├── test_cli_live.py           ← 79 tests CLI live (serveur réel)
├── test_e2e.py                ← ~290 tests MCP complets (Docker)
├── test_crypto.py             ← 9 tests AES-256-GCM
├── test_integration.py        ← tests d'intégration S3/Auth
├── test_service.py            ← tests de service
│
└── cli/                       ← tests CLI découpés par groupe
    ├── __init__.py             ← helpers partagés (check, run_cli, banner)
    ├── test_system.py          ← health, about, whoami
    ├── test_vault.py           ← vault CRUD
    ├── test_secret.py          ← secret CRUD + types + password
    ├── test_ssh.py             ← SSH CA
    ├── test_policy.py          ← policy + path_rules
    ├── test_token.py           ← token + --policy
    └── test_audit.py           ← audit filtres
```

---

## Modèle de sécurité testé

Les tests valident les **3 couches d'isolation** :

```
┌─────────────────────────────────────────────┐
│  Couche 1 — Owner-based (par défaut)        │
│  allowed_resources=[] → seuls MES vaults    │
│                                             │
│  ┌─────────────────────────────────────┐    │
│  │  Couche 2 — Vault-level             │    │
│  │  allowed_resources=[prod, staging]   │    │
│  │                                     │    │
│  │  ┌─────────────────────────────┐    │    │
│  │  │  Couche 3 — Path-level     │    │    │
│  │  │  allowed_paths=[shared/*]   │    │    │
│  │  │  → web/* BLOQUÉ            │    │    │
│  │  └─────────────────────────────┘    │    │
│  └─────────────────────────────────────┘    │
└─────────────────────────────────────────────┘
```

**Les denied_tools sont TOUJOURS prioritaires** sur les allowed_tools.

---

## Résumé pour l'auditeur

| Métrique                 | Valeur                                                 |
| ------------------------ | ------------------------------------------------------ |
| Tests CLI parsing        | **197** (sans serveur)                                 |
| Tests CLI live           | **79** (serveur réel)                                  |
| Tests e2e MCP            | **~290** (OpenBao + S3 réel)                           |
| Tests crypto             | **9**                                                  |
| **Total**                | **~575 tests**                                         |
| Couverture fonctionnelle | 24 outils MCP, 14 types secrets                        |
| Couverture sécurité      | 3 couches isolation, enforcement tool + path           |
| Mocking                  | **Zéro** — tous les tests utilisent des services réels |
