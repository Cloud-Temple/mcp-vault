# 🖥️ MCP Vault CLI

> CLI complet pour interagir avec le serveur MCP Vault — Click + Rich.

> 💡 **Console web** : l'essentiel des fonctionnalités du CLI est également disponible dans la **console admin SPA** accessible à `/admin` (dashboard, vaults, secrets, SSH CA, PKI/TLS, policies, tokens, audit, générateur de mot de passe, référence des 14 types). L'interface guide l'utilisateur avec des tooltips et de l'aide contextuelle.
>
> Restent propres au CLI : le parcours JIT `secret wrap` / `secret consume` et le
> groupe `mission-binding`, absents de la console.

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

#### JIT Wrap Broker + consommation médiée — C18 *(contrat mcp-mission, admin)*

Outils machine-to-machine du `CredentialBrokerService`, exposés au CLI pour le debug, la révocation et les tests de contrat. Les tokens sensibles passent par variables d'environnement.

```bash
# Créer un wrap token single-use (retourne un wrap_token SENSIBLE)
# ⚠️ HORS MODE DURCI uniquement : si ENFORCE_MISSION_TOKEN_VALIDATION=true, cet
# appel est REFUSÉ (binding_incomplete) — --tenant-id devient obligatoire (#78).
python scripts/mcp_cli.py secret wrap prod db/postgres \
  --mission-id m-42 --operation-id op-1 --ttl 600

# Binding C18 complet (tenant_id + audience attendue) — forme EXIGÉE en mode durci.
# --expected-aud est complétée par le serveur si omise ; en fournir une qui désigne
# une AUTRE instance est refusé (binding_mismatch : le wrap serait inconsommable).
python scripts/mcp_cli.py secret wrap prod db/pg \
  --mission-id m-42 --operation-id op-1 \
  --tenant-id t-7 --expected-aud mcp-vault:prod

# ⚠️ wrap-lookup et wrap-status exigent --mission-id : un operation_id n'est pas
# unique entre missions. Sans lui, la compensation d'un orphelin révoquait la
# provision VIVANTE d'une autre mission, et la lecture d'état la divulguait.
python scripts/mcp_cli.py secret wrap-lookup op-1 --mission-id m-42
python scripts/mcp_cli.py secret wrap-status op-1 --mission-id m-42

# Révoquer un wrap (idempotent — introuvable = succès)
# Révocation idempotente : introuvable DANS UN REGISTRE DISPONIBLE = succès.
# Registre non initialisé → error/registry_unavailable (#120) : rien n'a été tenté.
python scripts/mcp_cli.py secret revoke-wrap <accessor>

# Retrouver/révoquer les wraps d'un couple (operation_id, mission_id) — compensation
# orphelins. ⚠️ --mission-id est OBLIGATOIRE : sans lui, cette commande révoquait
# la provision VIVANTE d'une autre mission partageant l'operation_id (#cloisonnement).
python scripts/mcp_cli.py secret wrap-lookup op-1 --mission-id m-42

# Consommer un wrap (validation JWT C18) — tokens via env
VAULT_WRAP_TOKEN=hvs.CAES... VAULT_MISSION_TOKEN=eyJ... \
  python scripts/mcp_cli.py secret consume op-1
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

#### Demande JIT opérateur *(v0.9.0)*

Ces commandes utilisent le parcours fermé : le serveur fixe le coffre CA, le
rôle, le principal, la cible et le TTL. Le token doit être nominatif,
non-admin, limité au coffre du profil et porter une policy autorisant seulement
les deux outils JIT.

```bash
# Voir les profils utilisables par l'identité courante
python scripts/mcp_cli.py ssh profiles

# Demander un certificat lié à la clé publique pré-enrôlée
python scripts/mcp_cli.py ssh request bastion-prod \
  --key ~/.ssh/id_ed25519.pub \
  --reason "INC-230 maintenance bastion"

# Variante : clé fournie en ligne plutôt que par fichier
python scripts/mcp_cli.py ssh request bastion-prod \
  --key-data 'ssh-ed25519 AAAA...' \
  --reason 'INC-230 maintenance bastion'
```

La réponse contient le certificat public signé. Aucune clé privée n'est lue ou
écrite par MCP Vault. `ssh sign` reste une commande d'administration générique
et ne doit pas être accordée à la policy opérateur JIT.

### PKI — Autorité de Certification interne *(v0.5.0, admin)*

```bash
# Initialiser la PKI (CA racine + intermédiaire + serveur ACME)
python scripts/mcp_cli.py pki setup --lab --domains '*.lesur.lan,lesur.lan'
python scripts/mcp_cli.py pki setup --prod --domains 'mcp.cloud-temple.app' --ttl 720h

# Consulter l'état et la CA racine
python scripts/mcp_cli.py pki ca-key         # PEM + SHA-256 + URL stable
python scripts/mcp_cli.py pki roles          # Rôles ACME configurés
python scripts/mcp_cli.py pki role-info acme-servers

# Inventaire des certificats émis
python scripts/mcp_cli.py pki certs
python scripts/mcp_cli.py pki certs --limit 20

# Émettre un certificat manuellement (hors ACME) — la clé privée s'affiche UNE FOIS
python scripts/mcp_cli.py pki issue www.cloud-temple.app
python scripts/mcp_cli.py pki issue api.cloud-temple.app --ttl 2160h --alt-names api2.cloud-temple.app
python scripts/mcp_cli.py pki issue node1.cloud-temple.app --ip-sans 10.0.0.4

# Révoquer un certificat
python scripts/mcp_cli.py pki revoke 12:34:ab:cd:ef:12:34:56

# Rotation de la CA intermédiaire sans coupure
python scripts/mcp_cli.py pki rotate
python scripts/mcp_cli.py pki rotate --no-keep-old
```

> Les WAF Caddy s'enrôlent via `acme_ca https://vault.example.com/acme/directory`.
> La racine de confiance est disponible à `/pki/ca/root.pem` (non-auth).

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

## ⚠️ Opérations irréversibles — les purges

Deux commandes suppriment définitivement des enregistrements :

```bash
python scripts/mcp_cli.py token purge-revoked --older-than 30
python scripts/mcp_cli.py mission-binding purge --older-than 30
```

Le déroulé est identique pour les deux, et il est protégé à trois niveaux :

1. **Aperçu systématique.** Un premier appel en `dry_run` compte les candidats.
   Si cet aperçu échoue, ou si son décompte n'est pas un entier strictement
   positif, la purge n'est jamais tentée — on ne supprime pas sur la foi d'un
   décompte qu'on n'a pas su lire.

   > **Limite à connaître.** L'aperçu est **indicatif**, pas contractuel : la
   > purge ne transmet que la durée de rétention, et le serveur **recalcule** la
   > sélection. Un enregistrement devenu éligible entre l'aperçu et la
   > confirmation sera supprimé sans avoir figuré dans l'aperçu. Fermer cette
   > fenêtre demanderait que la purge porte l'empreinte de l'aperçu — cela relève
   > du serveur, pas du client.
2. **Confirmation.** Sans `--yes`, la commande demande une confirmation explicite
   et s'interrompt si vous refusez.
3. **Rétention bornée.** `--older-than` vaut 30 jours par défaut. `0` purge
   **sans condition d'âge** — c'est un choix explicite, toujours soumis à
   l'aperçu et à la confirmation. Une valeur négative est **refusée** : avec la
   sémantique « plus de N jours », elle sélectionnerait tout et contournerait la
   rétention demandée.

`--dry-run` s'arrête après l'aperçu, même combiné à `--yes`.

Ces trois garanties sont verrouillées par `tests/cli/test_purge_destructive.py`,
dont chaque protection est prouvée par une mutation mesurée.

---

## 🐚 Confort d'utilisation

Le **shell interactif a été supprimé** (issue #128). Son analyseur d'arguments
était écrit à la main, commande par commande, et **ignorait silencieusement tout
jeton non reconnu** : une faute de frappe ne produisait pas une erreur, mais une
opération différente de celle demandée. Click refuse ces saisies et propose même
la correction :

```
$ python scripts/mcp_cli.py token create agent --permission read
Error: No such option: --permission  Did you mean --permissions?
```

Pour retrouver le confort d'une session interactive :

```bash
# Raccourci — évite de retaper le préfixe
alias vault='python /chemin/vers/mcp-vault/scripts/mcp_cli.py'
vault vault list
```

L'historique et l'édition de ligne sont ceux de votre terminal. Pour la
complétion, Click sait générer un script dédié — elle cible l'exécutable
`mcp_cli.py` et suppose donc qu'il soit installé ou présent dans le `PATH` ; elle
ne s'applique pas à un simple alias.

---

## 📁 Structure

```
scripts/
├── mcp_cli.py        # Point d'entrée (lance cli.commands.cli)
├── README.md         # Ce fichier
└── cli/
    ├── __init__.py   # Config : charge .env, expose BASE_URL et TOKEN
    ├── client.py     # MCPClient : Streamable HTTP via SDK MCP
    ├── commands.py   # Groupes Click : vault, secret, ssh, pki, policy, token, mission-binding
    └── display.py    # Affichage Rich : panels, tables, syntax highlighting
```

---

## 🔧 Dépendances

| Package          | Rôle                                        |
| ---------------- | ------------------------------------------- |
| `click`          | CLI framework — analyse et VALIDE les arguments |
| `rich`           | Affichage terminal (tables, panels, syntax) |
| `python-dotenv`  | Chargement .env                             |
| `mcp[cli]`       | SDK MCP (Streamable HTTP client)            |
| `httpx`          | Appels REST (health, tokens admin)          |
