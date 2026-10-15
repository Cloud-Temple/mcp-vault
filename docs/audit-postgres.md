# Audit applicatif PostgreSQL

Avec `METADATA_BACKEND=postgres`, les actions métier MCP et REST utilisent
`vault_metadata.audit_calls` et `audit_events`. L'admission précède l'effet ;
les étapes SQL partagent sa transaction, les étapes OpenBao ont leur propre
observation. Une clôture inconnue masque le résultat sensible et interdit de
déduire un succès complet ou une permission de rejouer. Ce journal ne contient
ni secret, ni clé privée, ni bearer et ne sauvegarde pas les coffres OpenBao.
Les refus sans identité utilisable sont anonymes, visibles uniquement par un
administrateur local. Aucun service Mission n'est nécessaire.

## Installation et lecture

Le schéma v2 s'installe par l'action opérateur `audit-upgrade`, après création
d'un LOGIN maintenance distinct de l'app, du provisionneur et de l'owner
NOLOGIN. Voir [le profil PostgreSQL](postgres-metadata.md). Le rôle maintenance
ne possède aucun droit DML direct : seulement l'exécution de
`vault_metadata.audit_expire(text,integer,boolean)`. L'app possède SELECT/INSERT
sur le journal, aucun UPDATE/DELETE/TRUNCATE, aucun EXECUTE sur l'expiration.
L'upgrade retire également les grants hérités des privilèges par défaut v1.
Le démarrage et les connexions vérifient les droits effectifs et la politique.

`AUDIT_RETENTION_DAYS=365` fixe la conservation des nouvelles admissions.
Le serveur PostgreSQL calcule les dates et les événements gardent l'expiration
de leur admission. Un changement explicite de politique affecte les nouveaux
appels ; il ne prolonge ni ne raccourcit les anciens. Un désaccord entre
configuration et politique SQL refuse le profil.

`audit_log` et `GET /admin/api/audit` partagent la consultation et les curseurs
opaques. L'administrateur local voit son instance. Un auditeur read non admin
doit avoir des coffres explicites et une policy autorisant `audit_log` sur les
coffres entiers ; les restrictions de chemin ne deviennent pas une capacité
de lire leur audit. Entrées, compteurs et statistiques ont le même filtre.
Les événements anonymes et les références Mission ne sont pas révélés à un
token opaque ordinaire. Les lectures d'audit ne s'auto-journalisent pas.

Une révision SQL lie les pages d'export. Une insertion, une purge, un changement
de droits ou une erreur peut donner `export_incomplete` : recommencer une
lecture. Seul `complete=true` confirme l'ensemble des pages ; aucune stabilité
historique n'est promise pendant l'activité. Les anciennes pages déjà reçues
ne sont pas révoquées rétroactivement.

## Expiration dédiée

Configurer `AUDIT_MAINTENANCE_ROLE` et le chemin KV natif distinct
`AUDIT_MAINTENANCE_SECRET_PATH=sql/audit-maintenance`. Dans le coffre technique
du profil PostgreSQL, l'action opérateur `audit-maintenance-connection` reçoit
exactement `host`, `port`, `dbname`, `user`, `password` (chaînes), avec la base
du domaine et le LOGIN maintenance. Elle vérifie une valeur existante identique
ou crée une version avec CAS0 ; elle ne remplace pas une connexion différente.
TLS vérifie la CA et le nom du serveur PostgreSQL.

Les actions `audit-maintenance-connection` et `audit-expire` requièrent la clé
bootstrap opérateur et **`METADATA_OPERATOR_MODE=install`**. `disabled` et
`restore` les refusent ; un bearer applicatif ne les autorise pas. Il n'existe
pas de mode `verify`. Ne monter ni clé opérateur ni credential maintenance
dans une application cliente. L'exécution reste explicite, sans worker de
purge automatique au démarrage de Vault.

Exemple de simulation, avec `operator-auth.conf` privé 0600 contenant le header
d'authentification curl et `expire.json` contenant `{"batch":100}` :

```sh
curl --config operator-auth.conf --cacert ca.pem \
  --data-binary @expire.json \
  https://vault.example/admin/api/metadata-operator/audit-expire
```

`dry_run` vaut true par défaut. Pour appliquer, fournir
`{"batch":100,"dry_run":false,"confirm":"audit-expire"}`. La borne est 1..500
appels par transaction. Les enfants et leur admission expirée sont supprimés
ensemble ; les reçus métier, credentials, coffres et bindings restent intacts.
Le journal reçoit un événement d'expiration avec sa propre durée.

Le résultat contient `calls`, `events`, `has_more`, `dry_run` et un `receipt`
lorsqu'une suppression a été confirmée. `confirmed=true` ne sort qu'après
COMMIT. Une annulation ou une perte d'ACK retourne une issue inconnue, jamais
un faux compteur confirmé. Arrêter et observer l'état avant une nouvelle
intention ; aucune boucle de retry n'est incluse. Un planificateur opérateur
distinct peut exécuter des lots et continuer uniquement après confirmation.

## Sauvegarde et limites

Les tables d'audit et leur politique appartiennent au dump de la base du domaine.
Revalider ownership, fonctions et ACL après restauration. Une copie reste fermée
jusqu'à réconciliation des autorisations actuelles ; un ancien bearer révoqué
ne doit pas être réactivé par le backup. Les volumes OpenBao sont indépendants.
Voir la procédure de [reprise logique](postgres-metadata.md#reprise-logique-et-qualification).

`AUDIT_STAGE_SECONDS=30` borne le dispatch des nouvelles étapes d'audit ; ce
réglage ne promet pas une fin globale de drainage. Les workers en vol restent
suivis jusqu'à leur fin. Les tests d'horloge vérifient la politique annuelle,
sans prétendre avoir observé une année calendaire de fonctionnement.
