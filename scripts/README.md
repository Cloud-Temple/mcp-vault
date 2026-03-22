# 🖥️ MCP Vault CLI

> CLI complet pour interagir avec le serveur MCP Vault — Click + Rich + shell interactif.

---

## ⚡ Utilisation rapide

```bash
# Depuis le conteneur Docker
docker compose exec mcp-vault python scripts/mcp_cli.py --help

# Ou en local (avec les dépendances installées)
python scripts/mcp_cli.py --help
```

### Variables d'environnement

| Variable              | Défaut                         | Description                  |
| --------------------- | ------------------------------ | ---------------------------- |
| `MCP_URL`             | `http://localhost:8085`        | URL du serveur MCP (via WAF) |
| `MCP_TOKEN`           | *(depuis ADMIN_BOOTSTRAP_KEY)* | Token d'authentification     |
| `ADMIN_BOOTSTRAP_KEY` | *(dans .env)*                  | Fallback si MCP_TOKEN absent |

Le CLI charge automatiquement le fichier `.env` à la racine du projet.

---

## 📋 Commandes

### Système

```bash
# État de santé (OpenBao + S3)
python scripts/mcp_cli.py health

# Informations service
python scripts/mcp_cli.py about

# Identité du token courant
python scripts/mcp_cli.py whoami

# Sortie JSON brute (toutes les commandes)
python scripts/mcp_cli.py health --json
```

### Vaults (coffres de secrets)

```bash
# Créer un vault
python scripts/mcp_cli.py vault create serveurs-prod -d "Clés SSH production"
python scripts/mcp_cli.py vault create bdd-staging

# Lister les vaults
python scripts/mcp_cli.py vault list

# Détails d'un vault
python scripts/mcp_cli.py vault info serveurs-prod

# Modifier la description d'un vault
python scripts/mcp_cli.py vault update serveurs-prod -d "Clés SSH production v2"

# Supprimer un vault (⚠️ irréversible)
python scripts/mcp_cli.py vault delete serveurs-prod -y
```

### Secrets

```bash
# Écrire un secret typé
python scripts/mcp_cli.py secret write serveurs-prod web/github \
  -d '{"username":"clesur","password":"TopSecret!","url":"https://github.com"}' \
  -t login

python scripts/mcp_cli.py secret write serveurs-prod db/postgres \
  -d '{"host":"db.ct.com","username":"admin","password":"pw","port":"5432"}' \
  -t database

# Lire un secret
python scripts/mcp_cli.py secret read serveurs-prod web/github

# Lire une version spécifique
python scripts/mcp_cli.py secret read serveurs-prod web/github -v 1

# Lister les secrets d'un vault
python scripts/mcp_cli.py secret list serveurs-prod
python scripts/mcp_cli.py secret list serveurs-prod --prefix db/

# Supprimer un secret
python scripts/mcp_cli.py secret delete serveurs-prod web/github -y

# Lister les 14 types de secrets
python scripts/mcp_cli.py secret types

# Générer un mot de passe
python scripts/mcp_cli.py secret password
python scripts/mcp_cli.py secret password -l 32
python scripts/mcp_cli.py secret password -l 16 --no-symbols
python scripts/mcp_cli.py secret password -l 24 --exclude "lI10O"
```

### SSH Certificate Authority

```bash
# Configurer un rôle SSH CA
python scripts/mcp_cli.py ssh setup mon-vault sre-role --users deploy,admin --ttl 15m

# Signer une clé publique
python scripts/mcp_cli.py ssh sign mon-vault sre-role -k ~/.ssh/id_ed25519.pub
python scripts/mcp_cli.py ssh sign mon-vault sre-role --key-data "ssh-ed25519 AAAA..."

# Récupérer la clé publique CA
python scripts/mcp_cli.py ssh ca-key mon-vault

# Lister les rôles SSH CA d'un vault
python scripts/mcp_cli.py ssh roles mon-vault

# Détails d'un rôle SSH CA
python scripts/mcp_cli.py ssh role-info mon-vault sre-role
```

### Tokens (admin)

```bash
# Créer un token
python scripts/mcp_cli.py token create agent-sre --permissions read --vaults serveurs-prod
python scripts/mcp_cli.py token create admin-user --permissions admin --expires 365
python scripts/mcp_cli.py token create ci-cd --email ci@company.com

# Lister les tokens
python scripts/mcp_cli.py token list

# Modifier un token (policy, permissions, vaults)
python scripts/mcp_cli.py token update <hash_prefix> --policy readonly
python scripts/mcp_cli.py token update <hash_prefix> --permissions read --vaults prod-servers
python scripts/mcp_cli.py token update <hash_prefix> --policy _remove

# Révoquer un token
python scripts/mcp_cli.py token revoke <hash_prefix>
```

### Policies (admin — contrôle d'accès granulaire)

```bash
# Créer une policy
python scripts/mcp_cli.py policy create readonly -d "Lecture seule" \
  --allowed "system_*,vault_list,secret_read,secret_list"

python scripts/mcp_cli.py policy create no-ssh -d "Pas de SSH" --denied "ssh_*"

# Lister les policies
python scripts/mcp_cli.py policy list

# Détails d'une policy
python scripts/mcp_cli.py policy get readonly

# Supprimer une policy
python scripts/mcp_cli.py policy delete readonly -y
```

### Audit (journal d'activité)

```bash
# 50 derniers événements
python scripts/mcp_cli.py audit

# Filtrer par statut (denied = refus de policy)
python scripts/mcp_cli.py audit --status denied

# Filtrer par catégorie et client
python scripts/mcp_cli.py audit --category secret --client agent-sre -n 20

# Filtrer par plage de temps
python scripts/mcp_cli.py audit --since 2026-03-22T15:00:00

# Combiner les filtres + sortie JSON
python scripts/mcp_cli.py audit --vault prod --status denied --json
```

---

## 🐚 Shell interactif

```bash
python scripts/mcp_cli.py shell
```

```
🐚 MCP Vault Shell — connecté à http://localhost:8085
Tapez 'help' pour l'aide, 'quit' pour quitter.

mcp-vault> health
mcp-vault> vault list
mcp-vault> vault create demo --desc "Test"
mcp-vault> secret write demo test/key --data '{"value":"hello"}' --type custom
mcp-vault> secret read demo test/key
mcp-vault> secret list demo
mcp-vault> password 32
mcp-vault> types
mcp-vault> token list
mcp-vault> quit
```

**Fonctionnalités** : historique (↑↓), auto-complétion (Tab), `--json` sur toutes les commandes.

---

## 📁 Structure

```
scripts/
├── mcp_cli.py        # Point d'entrée (lance cli.commands.cli)
├── README.md         # Ce fichier
└── cli/
    ├── __init__.py   # Config : charge .env, expose BASE_URL et TOKEN
    ├── client.py     # MCPClient : Streamable HTTP via SDK MCP
    ├── commands.py   # 7 groupes Click : health, about, vault, secret, ssh, token, shell
    ├── display.py    # Affichage Rich : panels, tables, syntax highlighting
    └── shell.py      # Shell interactif : prompt-toolkit, history, auto-complete
```

---

## 🔧 Dépendances

| Package          | Rôle                                        |
| ---------------- | ------------------------------------------- |
| `click`          | CLI framework                               |
| `rich`           | Affichage terminal (tables, panels, syntax) |
| `prompt-toolkit` | Shell interactif (history, completion)      |
| `python-dotenv`  | Chargement .env                             |
| `mcp[cli]`       | SDK MCP (Streamable HTTP client)            |
| `httpx`          | Appels REST (health, tokens admin)          |
