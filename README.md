# 🔐 MCP Vault

> Coffre-fort de secrets pour agents IA, fondé sur OpenBao et exposé via le Model Context Protocol (MCP).

> 🇬🇧 [English version](README.en.md)

MCP Vault centralise les secrets, les politiques d’accès et les accès temporaires dont ont besoin des agents IA. Il embarque [OpenBao](https://openbao.org/) pour le chiffrement et le stockage, ajoute une API MCP protégée par authentification et politiques, puis fournit une console d’administration et une CLI.

**Version** : 0.20.1 · **Licence** : [Apache-2.0](LICENSE)

> [!IMPORTANT]
> MCP Vault est un composant de sécurité à exploiter dans un environnement maîtrisé. Lisez le [modèle de sécurité](#modèle-de-sécurité) et le [rapport d’audit](DESIGN/mcp-vault/SECURITY_AUDIT.md) avant toute mise en production.

## Console d’administration

| Dashboard | Vaults et secrets | Audit et alertes |
| :---: | :---: | :---: |
| ![Dashboard de MCP Vault](screenshoots/screen1.png) | ![Gestion des vaults et secrets](screenshoots/screen2.png) | ![Audit et alertes](screenshoots/screen3.png) |

## Fonctionnalités

- Coffres isolés et secrets versionnés dans OpenBao KV v2.
- Authentification bearer obligatoire par défaut, politiques par outil, coffre et chemin.
- Mode Mission JWT optionnel avec validation du jeton, binding local et refus *fail-close*.
- Accès temporaires : wrapping à usage unique, certificats SSH et PKI interne.
- Console web, CLI et journal d’audit JSONL.
- WAF Caddy/Coraza fourni par Docker Compose.
- Persistance locale avec synchronisation vers un stockage S3 compatible.

## Architecture

```text
Client MCP / CLI / navigateur
              │
              ▼
       Caddy + Coraza WAF
              │
              ▼
     MCP Vault (ASGI / MCP)
       │       │        │
       │       │        └── Authentification, politiques et audit
       │       └─────────── Console d’administration
       └─────────────────── OpenBao embarqué (KV, SSH, PKI)
                                  │
                                  ├── Volume Docker local
                                  └── Synchronisation S3
```

Le conteneur applicatif n’est pas publié directement par la configuration Docker Compose : le trafic passe par le WAF. L’architecture complète et les contrats d’exploitation sont décrits dans [ARCHITECTURE.md](DESIGN/mcp-vault/ARCHITECTURE.md).

## Démarrage rapide

### Prérequis

- Docker avec le plugin Compose ;
- un stockage S3 compatible ;
- une clé bootstrap d’administration générée et conservée comme un secret.

### Installation

```bash
git clone https://github.com/Cloud-Temple/mcp-vault.git
cd mcp-vault
cp .env.example .env
```

Avant de démarrer, renseignez au minimum dans `.env` :

- `ADMIN_BOOTSTRAP_KEY` avec une valeur aléatoire forte conforme aux exigences documentées dans `.env.example` ;
- `S3_ENDPOINT_URL`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_BUCKET_NAME` et `S3_REGION_NAME` ;
- les noms d’hôte autorisés si le service est exposé derrière votre propre domaine.

Ne commitez jamais le fichier `.env`.

```bash
docker compose up -d --build

# Liveness du processus
curl -fsS http://localhost:8085/healthz

# Disponibilité du coffre et readiness
curl -fsS http://localhost:8085/health
curl -fsS http://localhost:8085/ready
```

Points d’entrée par défaut :

| Interface | URL | Protection |
| --- | --- | --- |
| MCP Streamable HTTP | `http://localhost:8085/mcp` | Bearer requis |
| Console | `http://localhost:8085/admin` | API d’administration authentifiée |
| Santé | `/healthz`, `/health`, `/ready` | Réponses publiques sans détail sensible |

La CLI et ses prérequis Python locaux sont documentés dans
[scripts/README.md](scripts/README.md).

## Outils MCP

La version actuelle expose **39 outils MCP**. Le [catalogue canonique](src/mcp_vault/tool_catalog.py) est contrôlé automatiquement contre les outils enregistrés par le serveur.

| Domaine | Nombre | Capacités principales |
| --- | ---: | --- |
| Système | 2 | Informations de service et état de santé |
| Vaults | 5 | Création, inventaire, métadonnées et suppression |
| Secrets | 6 | Écriture, lecture, inventaire, suppression, types et génération |
| Wrapping JIT | 5 | Livraison à usage unique, consommation, état et révocation |
| SSH | 7 | CA SSH, rôles, signature et accès opérateur temporaire |
| Politiques | 4 | Création, lecture, inventaire et suppression |
| Tokens | 1 | Cycle de vie d’un token |
| PKI | 8 | CA, rôles, émission, inventaire, révocation et rotation |
| Audit | 1 | Consultation filtrée du journal d’audit |

> [!CAUTION]
> `secret_wrap_lookup` n’est pas une simple consultation : cette compensation peut **révoquer** les wraps correspondants, tandis que certains états peuvent rester non révoqués ou indéterminés. Utilisez `secret_wrap_status` pour une inspection sans révocation.

## Modèle de sécurité

- Les secrets sont chiffrés au repos par la barrière cryptographique d’OpenBao.
- Le matériel d’unseal est chiffré en AES-256-GCM avant son stockage sur S3 ; la clé bootstrap reste séparée.
- Le mode `bearer` exige un jeton valide. Les modes Mission JWT et dual-stack sont disponibles pour les intégrations qui appliquent leur contrat complet.
- Les politiques limitent les outils, les vaults et les chemins accessibles.
- Les magasins de policies, de bindings Mission et de wraps refusent les décisions fondées sur un instantané périmé lorsque S3 ne permet plus leur rafraîchissement. Exception documentée : le Token Store peut continuer à authentifier son cache bearer périmé, tandis que `/health` et `/ready` signalent l’instance indisponible.
- Le WAF filtre l’entrée HTTP, mais ne remplace ni la segmentation réseau ni la gestion des secrets d’infrastructure.

### Limites à connaître

- **Déploiement mono-instance** : OpenBao est embarqué et la synchronisation S3 est de type *last-write-wins*. MCP Vault n’est pas un cluster active-active et ne doit pas être répliqué horizontalement tel quel.
- **Durabilité asynchrone** : le volume local est la copie active ; S3 sert à la restauration et à la synchronisation. Un arrêt brutal peut laisser la dernière copie distante en retard.
- **Audit local** : le journal JSONL vit sur un volume local. Il n’est ni synchronisé vers S3, ni immuable, ni WORM. Exportez-le vers votre système de journalisation si ces propriétés sont requises.
- **Wrapping** : le TTL borne l’enveloppe de livraison, pas la durée de vie du credential externe qu’elle contient.
- **Mémoire et réponses** : un secret autorisé existe nécessairement en clair dans la mémoire du processus et dans la réponse remise au client autorisé.
- **Clé bootstrap** : présentée au service, elle donne un accès d’administration total ; sa compromission est déjà un incident majeur. Combinée à celle du stockage S3, elle compromet aussi la protection des données persistées et du matériel d’unseal.

Consultez le [rapport d’audit](DESIGN/mcp-vault/SECURITY_AUDIT.md) pour les risques résiduels et les mesures de réduction associées.

## Configuration

Le fichier [`.env.example`](.env.example) est la référence exhaustive et testée. Les principaux groupes sont :

| Groupe | Rôle |
| --- | --- |
| Bootstrap | Protection du matériel d’unseal et administration initiale |
| S3 | Persistance, restauration et magasins d’autorisation |
| Réseau et WAF | Port public, hôtes autorisés, TLS et filtrage HTTP |
| Authentification | Bearer opaque, Mission JWT ou transition dual-stack |
| OpenBao | Processus embarqué, stockage local et cycle de vie |
| SSH / PKI / wrapping | Accès temporaires et autorités de certification |
| Audit et rétention | Journalisation et purge des objets révoqués ou expirés |

Les valeurs sensibles doivent être injectées au déploiement, jamais intégrées dans une image ni commitées dans Git.

## Développement et tests

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest -q
```

Certaines suites d’intégration nécessitent Docker, S3 et un serveur en fonctionnement. Le [guide des tests](tests/README.md) décrit les niveaux, prérequis et commandes ciblées ; le [catalogue E2E](tests/TEST_CATALOG.md) documente les scénarios couverts.

## Documentation

| Document | Contenu |
| --- | --- |
| [Architecture](DESIGN/mcp-vault/ARCHITECTURE.md) | Architecture, persistance, sécurité et contrats détaillés |
| [Documentation technique](DESIGN/mcp-vault/TECHNICAL.md) | Modules, dépendances, déploiement et maintenance |
| [Audit de sécurité](DESIGN/mcp-vault/SECURITY_AUDIT.md) | Constats consolidés, corrections et risques résiduels |
| [Guide CLI](scripts/README.md) | Commandes d’administration et d’exploitation |
| [Guide des tests](tests/README.md) | Exécution locale, live et Docker |
| [Changelog](CHANGELOG.md) | Historique des versions |

## Licence

MCP Vault est distribué sous licence [Apache License 2.0](LICENSE).
