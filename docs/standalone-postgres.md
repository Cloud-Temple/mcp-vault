# PostgreSQL standalone : installation et retour contrôlés

Ce guide traite [#187](https://github.com/Cloud-Temple/mcp-vault/issues/187), issu de
l'inventaire [#186](https://github.com/Cloud-Temple/mcp-vault/issues/186), dans
[l'EPIC #824](https://github.com/Cloud-Temple/mcp-mission/issues/824). Les contrats
PG et audit sont ceux de [#178](https://github.com/Cloud-Temple/mcp-vault/issues/178)
et [#179](https://github.com/Cloud-Temple/mcp-vault/issues/179). Voir aussi
[le contrat opérateur existant](postgres-metadata.md) et
[la version anglaise](standalone-postgres.en.md).

**État de preuve : outillage logiciel local uniquement.** Aucun serveur PG, TLS,
Bao, auth native, build d'image ou dump/restore réel n'est qualifié par ces tests.
Le serveur historiquement qualifié reste **INCONNU**. Le tag de recette
`postgres:16`, le client `pg_dump` installé par apt et la version libpq chargée
par psycopg sont trois informations différentes. Ne pas déduire la version du
serveur de libpq. L'opérateur mesure `server_version_num` avant toute DDL ; la
syntaxe de membership employée exige PG16 ou ultérieur réellement observé.
L’image `pg-operator` fournit par défaut **pg_dump16 et pg_restore16** pour la
cible PG16. Un autre majeur exige une paire de son majeur fournie par le contexte
opérateur et une qualification distincte ; la connexion libpq seule ne la prouve pas.

## Quatre parcours, un produit

| Exécution | PG | Fichiers et prérequis |
| --- | --- | --- |
| Compose | local | Base + `docker-compose.postgres.yml`, un moteur privé et un volume `standalone-pg-data` |
| Compose | externe dédié ou partagé | Base seule ; serveur TLS, contrôle DB/roles préparé par son opérateur |
| Python | local | Même source et verrou, Bao dans PATH ; un moteur local préparé séparément |
| Python | externe dédié ou partagé | Même processus Python ; endpoint PG et contrôle DB préparés séparément |

API REST/MCP/CLI, schémas, image `production`, scopes, TTL, secrets et S3 restent
les mêmes. Le target `pg-operator` ajoute seulement les scripts et les outils
clients PG ; il ne remplace pas l'image applicative. OpenBao embarqué, son unseal
et S3 restent l'autorité interne. Le mode sans S3 de
[#102](https://github.com/Cloud-Temple/mcp-vault/issues/102) et la configuration
WAF de [#105](https://github.com/Cloud-Temple/mcp-vault/issues/105) restent des
sujets distincts. Aucune factory, migration automatique, provider SQL, HA ou
PITR n'est ajouté. Un starter kit peut être copié manuellement plus tard ; il
n'est pas une dépendance de l'installation.

## Préparer un domaine neuf

Utiliser une copie privée de [l'exemple opérateur](examples/standalone-operator.json).
Choisir `context` explicitement : `source_fresh`, `copy` ou `return`. Le document
fermé refuse les champs inconnus, les bases en collision et les chemins réutilisés.
Tous les credentials Source, Copy et Return, y compris infra, backup et restore,
restent dans **un seul mount technique M**, `METADATA_PG_VAULT_ID`. Seuls leurs
chemins KV canoniques changent. Changer M laisserait l'ancien mount accessible
aux routes métier ; cette variante est interdite. Les credentials ne passent
ni par un DSN ni par des variables SQL de l'application.

Les répertoires privés ont le mode 0700 ; JSON, tokens, Settings, archives et
carriers ont le mode 0600, sans lien symbolique. Ne pas les placer dans le
contexte de build ou Git. Les scripts n'impriment ni secrets ni exceptions
backend. Aucun shell SQL libre n'est proposé.

Créer les six fichiers d'intention `infra.json`, `app.json`, `provisioner.json`,
`maintenance.json`, `backup.json`, `restore.json` dans un répertoire privé. Chacun
contient exactement cinq chaînes non vides : `host`, `port`, `dbname`, `user`,
`password`. Infra pointe sur une **base de contrôle différente** des trois bases
du domaine, par exemple `postgres`, avec un droit CONNECT préparé explicitement.
Les cinq autres pointent sur la base du contexte. Le host doit correspondre au
SAN du certificat. Ces fichiers servent à l'installation CAS 0 ; toute connexion
ultérieure relit M après auth native Bao, même pour une sonde ou un dump.

Infra est LOGIN, NON superuser, CREATEDB/CREATEROLE, sans replication ni bypass
RLS. Ces deux autorités sont **au niveau cluster** : elles ne constituent pas
une isolation contre une infra compromise. Les droits ADMIN obtenus sur les
rôles qu'elle crée restent documentés ; aucun membership voisin n'est admis.
Un domaine B témoin doit exister avec son propre opérateur : relever ses ACL,
catalogues et lecture métier avant/après, sans donner B à infra A.

Les six rôles A sont distincts : owner NOLOGIN ; app, provisioner, maintenance,
backup, restore LOGIN NOINHERIT, sans privilèges dangereux. Seuls provisioner,
backup et restore peuvent SET ROLE owner, avec ADMIN FALSE et INHERIT FALSE.
App et maintenance n'ont aucun membership. Backup/restore peuvent exercer les
droits du propriétaire A : ce ne sont pas des comptes de lecture métier.

Configurer les **vraies Settings applicatives**, à partir de `.env.example` :
`METADATA_BACKEND=postgres`, identités et chemins A, CA PG, durabilité standalone,
maintenance, `METADATA_OPERATOR_MODE=install`, S3/bootstrap/Bao habituels. Le
script charge le même fichier et le même `get_settings` que l'application. Le
mode natif `token_file` n'a aucun fallback. `existing_bootstrap` utilise le
chargeur chiffré existant depuis le cwd de ces Settings, avec environnement
nettoyé ; seul root_token survit en mémoire, keys/keys_base64 sont jetées
immédiatement. Aucun init, unseal, migration legacy ou `set_hvac_client` n'est
appelé par ce chargeur opérateur. Bao doit déjà être unsealed et lookup-self
doit réussir **avant toute SQL**, y compris provision, sonde, dump ou restore.

Bao écoute HTTP loopback avec TLS désactivé. `vault_ca_file` est sans effet en
HTTP ; il ne fournit aucune sécurité TLS native. Ne pas publier son port. La
CA HTTPS produit et la CA PG `verify-full` ont des usages distincts.

## Fichiers, Compose et Python

`prepare-files` génère un jeu TLS neuf, avec SAN du host déclaré, clé serveur
0600 et UID/GID PG explicitement mesurés sur l'image retenue. Ne pas supposer
UID 999. Installer la CA en lecture seule pour l'UID applicatif ; ne jamais
monter la clé CA dans l'application ou le moteur.

```sh
python scripts/standalone_pg.py prepare-files --config /srv/vault/operator.json
```

Compose lit deux configurations différentes. `--env-file compose.env` sert à
l'interpolation (`VAULT_ENV_FILE`, `PG_CA_FILE`, `OPERATOR_DIRECTORY`, et pour le
local `PG_TLS_DIRECTORY`, `PG_ENGINE_DIRECTORY`). Le fichier `VAULT_ENV_FILE`
est celui des Settings ; `METADATA_PG_CA_FILE=/run/pg-ca.crt` y désigne le montage
CA lecteur. Le montage par défaut `certs/README.md` conserve le mode S3 ; il
n'est jamais une CA PG. Ne pas placer les variables Caddy/Compose dans Settings
si son parseur ne les accepte pas : `SITE_ADDRESS` et `WAF_TLS_DIRECTIVE` sont
des variables d'interpolation WAF, distinctes du port WAF déclaré par Settings.

Démarrer d'abord **Vault/Bao seul, sous accès privé**, sans exposer WAF ni
démarrer PG par dépendance implicite. Le script ne gère pas les services.
Installer les credentials, puis préparer le moteur local si nécessaire :

```sh
python scripts/standalone_pg.py install --config /srv/vault/operator.json --credentials-dir /srv/vault/credentials
python scripts/standalone_pg.py prepare-engine --config /srv/vault/operator.json --engine-dir /srv/vault/engine
```

`prepare-engine` est réservé au local neuf : après auth Bao, il écrit une init
finie pour l'infra NON superuser et un mot de passe engine privé séparé. Ce
dernier n'est jamais distribué à l'app ou utilisé comme fallback opérateur.
Le HBA généré refuse les connexions TCP sans TLS et exige SCRAM sous TLS ;
le bootstrap Unix reste privé au conteneur moteur. Aucun socket Unix moteur
n'est monté dans l'application.
Démarrer ensuite le seul moteur PG, avec les fichiers préparés et son volume
persistant. Sur serveur externe, cette préparation appartient à son opérateur.
Les fichiers init ne sont pas une migration d'un volume existant.

Depuis Compose, l'outil est accessible dans le target dédié, sans listener Bao
public ni dépendance PG implicite :

```sh
docker compose --env-file /srv/vault/compose.env --profile operator run --rm --no-deps pg-operator status --config /operator/operator.json
# Local uniquement : ajouter -f docker-compose.yml -f docker-compose.postgres.yml.
```

Adapter les chemins du JSON à ceux du conteneur, y compris Settings, tokens et
CA. Ne pas réutiliser aveuglément les chemins host de l'exemple Python. Ce
target est non root ; monter des fichiers lisibles par son UID mesuré.

En Python, utiliser Python 3.12 et un venv isolé, installer `requirements.lock`,
puis lancer `python -m mcp_vault` depuis le cwd privé de Settings, avec
`PYTHONPATH` pointant sur `src`. Bao doit être dans PATH ; préparer ses chemins
data/config/logs et ses droits. L'endpoint local est par défaut 8030 ; préparer
la façade TLS et ses allowlists avant exposition. Aucun cluster Mission privé
n'est requis pour le profil standalone v2.

Le fichier effectif doit se nommer `.env` : c'est le nom lu par le vrai
`get_settings` dans le cwd serveur. Lancer le serveur avec un environnement
nettoyé pour qu'aucune ancienne variable Settings ne supplante ce fichier :

```sh
cd /srv/vault
env -i PATH=/srv/vault/venv/bin:/usr/lib/postgresql/16/bin:/usr/local/bin:/usr/bin PYTHONPATH=/opt/mcp-vault/src /srv/vault/venv/bin/python -m mcp_vault
```

Ces chemins sont des exemples publics à adapter. Inclure le répertoire du
binaire Bao dans PATH. Compose utilise le même `.env` via VAULT_ENV_FILE ;
son fichier d'interpolation reste distinct. Un seul opérateur exécute une
action à la fois ; les carriers ne fournissent pas de service de verrouillage.

## Schéma, readiness et maintenance

### Prérequis opérateur concrets avant une exploitation réelle

`prepare-files` laisse `ca.crt` en 0600 au nom de l'opérateur : sa seule
génération ne démontre pas que l'UID `mcp` peut le lire. Mesurer séparément les
UID/GID de l'app, de l'outil et de PG, y compris leur mapping sur l'hôte. Installer
une **copie de la CA publique** dans un répertoire de confiance distinct, avec
un propriétaire/mode permettant la lecture par l'app (par exemple fichier 0400
appartenant à son UID), puis la monter RO à `/run/pg-ca.crt`. Vérifier aussi la
lecture par les clients opérateur/backup/restore avec leur mapping propre. La
clé serveur reste 0600 pour PG. Déplacer la clé privée `ca.key` dans un répertoire
PKI hors ligne 0700, fichier 0600, **hors** `OPERATOR_DIRECTORY`, des montages app
et des montages PG. Ne jamais rendre toute l'arborescence TLS lisible à l'app
pour résoudre un défaut d'accès à la CA. Les installations/chown nécessaires
relèvent de l'opérateur hôte autorisé, pas d'une élévation implicite du script.

Pour Compose, définir explicitement `OPERATOR_DIRECTORY` vers un répertoire
privé 0700, détenu par l'UID effectif de l'outil, et adapter tous les chemins
conteneur du JSON et du même `.env`. Le défaut `./certs` est un emplacement de
substitution du dépôt, **non qualifié** ; il n'est pas un répertoire de secrets
prêt à l'emploi et les gardes le refusent si ses droits ne conviennent pas.

Le HBA local contient exactement `local all all trust` pour le socket Unix du
conteneur moteur : tout processus admis dans ce conteneur peut donc usurper une
identité PG, y compris bootstrap. Cet accès moteur est réservé à l'opérateur PG
de confiance ; aucun socket n'est partagé avec l'app. `init.sql` contient le mot
de passe infra **en clair**, en fichier 0600 appartenant à l'UID PG, comme
`engine.password` et le HBA généré. Le répertoire hôte est privé ; seuls les
fichiers moteur nécessaires sont montés RO dans PG, jamais dans l'app. Ne pas
afficher, tracer, joindre ou copier leur contenu dans des logs/rapports. Cette
préparation du moteur ne crée aucun fallback superuser pour l'outil SQL.

Les certificats générés, CA **et** serveur, expirent à T0 + 365 jours. Enregistrer
leurs dates UTC `notAfter` et le responsable du calendrier avant production.
Une preuve TLS sur quelques jours ne démontre pas leur maintien pendant un an.
Le script n'alerte ni ne renouvelle. Plan manuel à dater et réserver :

1. À T0 + 300 jours au plus, inventorier CA, SAN, clés et tous les lecteurs ;
   préparer hors ligne une nouvelle CA et un certificat serveur pour le même
   host. Avec la CA générée elle aussi à 365 jours, réémettre seulement le serveur
   sous l'ancienne CA ne prolonge pas la chaîne après cette échéance.
2. Avant T0 + 330 jours, répéter la rotation sur une cible jetable admise. Préparer
   un bundle public ancienne + nouvelle CA, lisible aux UID réels, et un nouveau
   jeu serveur privé. Conserver les anciennes clés seulement sous contrôle PKI.
3. Avant T0 + 335 jours, pendant une fenêtre réservée, remplacer le trust bundle
   des lecteurs et charger le nouveau certificat/clé PG par redémarrage contrôlé.
   Recréer les lecteurs qui montent un fichier bind : un renommage atomique sur
   l'hôte ne garantit pas la mise à jour de l'inode déjà monté. Arrêter Vault/Bao
   ensemble et reprendre leur volume courant avec un seul processus.
4. Reconfirmer auth native avant toute sonde SQL ; constater TLS/readiness, droits
   et contrats A/B avec chaque identité prévue. Retirer l'ancienne CA des lecteurs
   seulement après confirmation de tous les clients, en rechargeant réellement
   les montages/processus. En cas d'échec, conserver les preuves et arrêter la
   bascule ; ne pas attendre l'expiration ni inventer un retour de données.

Cette procédure PKI reste manuelle, à qualifier dans la fenêtre native future ;
elle n'ajoute ni framework ni API. Une CA externe de plus longue durée peut
permettre une réémission serveur sous la même CA, mais sa date d'expiration
reste la borne ; ce n'est pas la situation du jeu généré par défaut.

Les connexions de fingerprint ont `statement_timeout=5000` : **5 s par
instruction**, pas un budget global de lecture. Dump et restore ont chacun une
borne de processus de **120 s**. Avant de geler une Source réelle, mesurer dans
la fenêtre native admise les lectures complètes, incluant audit/ACL/séquences,
et dump/restore sur un volume représentatif, avec marge sous ces bornes. Aucune
taille maximale en lignes/Go n'est qualifiée ici, et l'outil ne prévalide pas la
volumétrie. Une expiration peut survenir après REVOKE mais avant l'ACK du gel :
l'état reste UNKNOWN. Préserver les bases et carriers, arrêter sans rejeu ni
réouverture automatique ; un fichier manquant ne donne aucun rollback zéro.

Enfin, garder les sondes et le trafic Source quiescents pendant
`reopen-source-zero`, y compris les healthchecks SQL. Une connexion entre le
re-GRANT et sa lecture de contrôle peut produire un UNKNOWN conservateur. Ne
pas le transformer en succès ni en autorisation de rejouer. Le helper historique
valide certains rôles seulement en aval de son parser ; fournir les identités
canoniques du nouveau CLI, sans confondre cette limite ergonomique avec un droit
SQL supplémentaire.

Le contrôle de memberships lit les OID/noms réels et chaque grantor. L'identité
système bootstrap PG16 (OID 10, même si renommée) est relue dans `pg_roles` avec
son attribut superuser ; aucun nom/ID bootstrap n'est fourni par configuration.
Pour chacun des six rôles A, la ligne bootstrap ADMIN TRUE / INHERIT FALSE /
SET FALSE doit coexister avec le self-grant infra ADMIN FALSE / INHERIT FALSE /
SET TRUE. Le contrôle exige les capacités SET effectives d'infra, interdit SET
owner pour app/maintenance et refuse tout grant/member/grantor étranger. Ces
vérifications logicielles ne sont pas encore une mesure de catalogue PG réel.

Pour un PG externe (C-E ou P-E), l'infra doit être préparée sans membership
entrant provenant d'un créateur CREATEROLE tiers non superuser. PG16 ajoute dans
ce cas une ligne vers infra, grantor bootstrap ; la garde la refuse comme
étrangère. Faire préparer une identité compatible par l'opérateur externe,
sans supprimer ni tolérer cette ligne automatiquement. Le paramètre de session
`createrole_self_grant` doit rester à sa valeur canonique vide avant création
des rôles A. Une autre valeur ou un graphe différent impose STOP et diagnostic,
sans assouplissement de la garde ni adaptation automatique du SQL.

```sh
python scripts/standalone_pg.py provision-fresh --config /srv/vault/operator.json
python scripts/standalone_pg.py verify --config /srv/vault/operator.json
```

Le provisionnement valide les cinq credentials avant connexion, mesure PG,
refuse toute collision de rôle/base, prépare les six rôles et les DBACL, puis
appelle explicitement `schema-init` et `initial-admin`. Aucun init au démarrage
app, retry DDL, upgrade ou autorepair n'est ajouté. Une intention sans ACK arrête
le parcours ; conserver les carriers et consulter les reçus existants sans
rejouer seed/DDL. `verify` valide les connexions KV ; cela ne suffit pas à
prouver la readiness SQL. Après redémarrage en DISABLED, `verify-disabled`
exige le refus opérateur canonique et `/health` 200 avant qualification publique.

Choisir le profil **à l'installation** : défaut v2, flag
`AUDIT_MISSION_RETENTION_ENABLED=true` pour v3, puis commande opérateur existante
`audit-retirement-upgrade` explicite depuis v3 pour v4. Changer le flag après une
installation v2 n'effectue aucune migration et peut fermer la readiness. Les
TTL, auth, rétentions et secrets restent inchangés. La maintenance conserve
seulement les droits audit prévus par #179, sans DML métier ou SET ROLE owner.
Conserver les probes et suites #178/#179, ainsi que les preuves de batch,
grant/revoke, export audit et refus d'un voisin ; 503 ne prouve pas l'isolation.

## Copie, archive admissible et rollback

Arrêter Source Vault **et** son Bao ensemble ; reprendre le même volume Bao
courant avec **un seul processus Copy privé**. Dans ses Settings, garder M,
owner et instance, sélectionner A_copy et de nouveaux chemins. Les credentials
gardent host/user/password ; seul dbname change. Installer Copy en INSTALL : le
dispatcher n'appelle que `connections` et `audit-maintenance-connection`, puis
CAS 0 des identités opérateur dans M. Ne jamais appeler `install-vault`,
`schema-init`, `initial-admin` ou un upgrade sur Copy. Cette restriction est
celle du **script** : le produit brut permet encore ces actes en INSTALL.

Redémarrer Copy en RESTORE, reconfirmer auth native avant SQL. Ne faire aucun
appel métier privé ou public, même un refus pouvant écrire un audit, avant la
décision et l'intention dirty.

```sh
python scripts/standalone_pg.py create-copy --config /srv/vault/copy.json
python scripts/standalone_pg.py freeze-source --config /srv/vault/copy.json
python scripts/standalone_pg.py dump-frozen --config /srv/vault/copy.json --archive /srv/vault/domain.dump
python scripts/standalone_pg.py seal-source --config /srv/vault/copy.json
python scripts/standalone_pg.py restore-frozen --config /srv/vault/copy.json --archive /srv/vault/domain.dump
python scripts/standalone_pg.py verify-copy --config /srv/vault/copy.json
```

Copy est une base absente, TEMPLATE template0, owner A, sans PUBLIC, avec CONNECT
initial limité à infra/backup/restore. Le custom dump sans `--create` ne transporte
pas les ACL CONNECT au niveau base : elles sont préparées explicitement, sous le
même grantor owner pour GRANT et REVOKE, puis **datacl et droits effectifs** sont
relus. Les ACL d'objets, schéma et seed viennent de l'archive, sans réinstallation.

SourceFrozen révoque CONNECT métier et restore, draine les sessions A exactes,
refuse de signaler une session étrangère et conserve backup jusqu'à la fin du
dump. Seule une archive exclusive 0600 créée **après gel confirmé**, avec Source
stable avant/après, code 0 et hash vérifié, est admissible. SourceSealed retire
ensuite CONNECT backup/infra et passe ALLOW_CONNECTIONS false, sessions zéro.
Avant create-copy, gel, dump et restore, le CLI authentifie Bao, relit KV puis
mesure le serveur et les deux outils résolus sur PATH, **avant l’intention
mutative**. Leurs majeures doivent correspondre au serveur ; des correctifs
mineurs différents sont admis. Les mêmes chemins absolus sont exécutés. Python
utilise le PATH16 ci-dessus, pas une nouvelle variable `.env` ; le target
opérateur prépare ses clients16 via PGDG signé. apt peut résoudre une **libpq5
système différente** : relever sa version séparément de la libpq embarquée par
psycopg-binary, dont le verrou Python ne change pas.

Les versions productrices sont dans une clé sœur de `archive` de l’ACK dump,
sans modifier son hash/taille. Avant restore, le CLI vérifie cette provenance,
l’égalité stricte du hash et `pg_restore --list` sans connexion DB. Aucune ancienne
preuve n’est complétée automatiquement. `verify*`, `decide-copy` et
`reopen-source-zero` ne requièrent pas les outils dump ; leurs autres prédicats
restent inchangés. Un UNKNOWN existant ne devient pas rejouable après installation
d’un nouveau client. Ne pas filtrer l’archive ou ignorer une erreur GUC/ACL.

Le restore est mono-transaction, exit-on-error, rôle owner, sans changement de
roles ni remapping. OID, chemins, M, configuration, ACL, archive et états sont
liés par les carriers ; ceux-ci ne remplacent jamais les observations réelles.

Deux scénarios sont distincts :

* **Zéro mutation Copy réellement prouvée** : baseline identique, ACL fermées,
  aucune session, aucun appel/exposition ni intention dirty. `decide-copy
  --decision rollback-zero`, puis `reopen-source-zero` ferme Copy et restaure
  exactement les ACL/ALLOW de Source. Pour cette dernière action, reprendre les
  Settings Source en RESTORE avec le même Bao courant, toujours un seul
  processus privé. Redémarrer ensuite Source en DISABLED et vérifier avant
  exposition. Un restore échoué/UNKNOWN n'autorise cette branche que si la
  transaction annulée ou le résultat complet stable est réellement constaté,
  avec **tous** les autres prédicats zéro. Un fichier absent ne suffit jamais.
* **Essai métier ou mutation Copy** : appeler `record-copy-mutation` **avant**
  tout appel, même en lecture/refus, puis `open-copy-private`. L'ancienne Source
  est désormais interdite. Après essais positifs, révocation et audit, geler
  Copy, produire un **nouveau dump frais**, sceller Copy et restaurer dans une
  A_return neuve avec le contexte `return` et de nouveaux carriers. Vérifier le
  témoin muté, la révocation et l'audit avant DISABLED/exposition. Aucun retour
  automatique à l'ancien Source, aucune « réconciliation » d'archives périmées.

Une divergence, une session inconnue, un ACK perdu ou un état incomplet impose
UNKNOWN et préservation des bases fermées. Le journal ne peut prouver l'absence
d'une opération effectuée en dehors de ce protocole : si un opérateur a ouvert
Copy ou utilisé une identité propriétaire hors outil, le zéro est inconnu et
le rollback vers l'ancien Source reste interdit.

## Qualification future et nettoyage

Pour chacun des quatre parcours, réserver un domaine A neuf et un voisin B
témoin ; exécuter les scénarios zéro et mutation sur des domaines différents.
Relever produit/verrou, digests d'images, `server_version`, libpq, `pg_dump` et
`pg_restore`. Utiliser les vrais contrats `tests/postgres/test_public_interfaces.py`
avec admission explicite et un processus neuf pour le contrôle final après
restart/restore. Compléter par SQL/ACL/maintenance/audit, TLS négatif, refus
voisin, fichiers/modes et retours décrits dans [la matrice](standalone-validation.md).
Le journal JSONL applicatif n'est pas couvert par un dump PG : son restore reste
à constater séparément, **INCONNU** tant qu'il n'est pas mesuré.

Conserver volumes, dumps et reçus ; arrêter les seuls services du domaine après
revocations confirmées, sans `down -v` ni suppression de voisin. Une sauvegarde
logique PG avec Bao courant ne constitue ni une restauration historique du
coffre S3 ni du PITR. Les revues indépendantes du plan puis du diff/résultat et
la lecture réelle de la mémoire projet par le relecteur restent requises dans
le cycle de livraison ; aucun succès natif ne découle de ce guide.
