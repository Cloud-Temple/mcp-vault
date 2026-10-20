# Métadonnées PostgreSQL de MCP Vault

Le [guide standalone](standalone-postgres.md) décrit la préparation opérateur,
les quatre topologies d'exécution et les limites de qualification de #187.

Profil opt-in : tokens hashés, policies, bindings de délégation et registre de
wrapping ont une seule autorité PostgreSQL. Les secrets, clés, unseal et backups
OpenBao gardent leur mécanisme existant. `METADATA_BACKEND=s3` conserve le driver
historique. Aucun import, dual write ni fallback S3 n'est déclenché par le profil
PostgreSQL. Les anciennes données d'un banc jetable ne sont pas migrées.

## Configuration publique

Copier `.env.example`. En PostgreSQL, renseigner l'identité stable de l'instance,
le mount technique KV v2, ses deux chemins distincts, la base, les trois rôles
(owner NOLOGIN, app, provisionneur) et le fichier CA PostgreSQL. Les identités
sont canoniques. Le mount entier, ses versions et les cibles dérivées qui le
recouvrent sont réservés avant toute exception admin/owner/policy. Il ne doit
servir qu'aux connexions SQL **de Vault**. Les credentials des autres applications
restent dans leurs propres coffres métier selon leurs permissions ordinaires.

Chaque secret de connexion contient exactement cinq chaînes : `host`, `port`,
`dbname`, `user`, `password`. Les deux users correspondent aux rôles configurés.
La CA est distribuée séparément ; libpq utilise `sslmode=verify-full`. Ni mot de
passe, DSN complet, secret direct en environnement ni cache périmé ne sert de
repli. Chaque connexion lit d'abord son credential par HTTP/KV2 natif OpenBao,
après restauration/unseal/auth de celui-ci ; elle n'appelle pas sa propre API MCP.

Standalone : PostgreSQL propre au déploiement et OpenBao existant. Externe : un
serveur PostgreSQL partagé explicitement configuré, une base et des rôles propres
par domaine. Les deux topologies exposent les mêmes droits/API. Aucun hub,
Mission, checkout privé, cluster fleet, package privé ou CI externe n'est requis.
Les JWT de délégation restent une option explicitement configurée avec issuer,
audience et clés vérifiables ; aucun header d'identité fourni par le caller ne
remplace l'authentification.

## Installation depuis des volumes vides

1. Installer MCP Vault/OpenBao et son backup existant suivant le README. Restaurer,
   unseal puis authentifier OpenBao **avant** toute opération SQL, même une sonde,
   le provisioning, dump ou restore. L'identité opérateur infrastructure pour
   OpenBao est indépendante de PostgreSQL ; elle n'est pas un bearer métier/JIT.
2. En mode `METADATA_OPERATOR_MODE=install`, la clé bootstrap n'autorise que les
   actions finies du groupe CLI `metadata` et leurs routes REST
   `/admin/api/metadata-operator/`. La readiness métier est encore fermée. Appeler
   `metadata status`, puis `metadata install-vault` : création du mount exact,
   jamais suppression, tuning ou remplacement d'un mount existant.
3. Préparer en fichiers privés mode 0600 les deux connexions app/provisionneur.
   `metadata install-connections --app-file … --provisioner-file …` valide les
   deux intentions avant d'écrire. CAS création ; valeurs existantes identiques
   vérifiées, jamais écrasées. Les résultats expurgés sont distincts par chemin.
   Une réponse perdue n'autorise pas un retry aveugle. Vérifier côté opérateur
   natif avant de compléter seulement le chemin confirmé absent.
4. Par l'identité infrastructure externe, créer les rôles/base et grants décrits
   ci-dessous, avec credentials lus depuis OpenBao. Ce provisioning n'est pas une
   capacité SQL admin du produit. `metadata verify-connections` lit les deux
   credentials sans connexion SQL. `metadata schema-init` ne permet que le DDL
   versionné Vault, via le provisionneur qui peut SET ROLE owner. L'app ne fait
   aucun DDL/réparation. Le COMMIT DDL est borné/capturé ; réponse inconnue =>
   arrêt et constat manuel, aucune relance schema-init.
5. `metadata initial-admin --token-file … --client-name …` écrit un bearer privé,
   son UUID/intention et son ACK append-only avant/après dispatch. Seed, reçu et
   marqueur singleton sont atomiques ; durée maximale 24 h. Aucun token brut
   n'est renvoyé par cette route. Une intention existante interdit une nouvelle
   émission. `metadata installation-result --intent-file …` vérifie le tuple
   seed/instance/UUID/intention ; constate l'effet sans transformer l'ACK unknown
   en succès historique. Conserver ces fichiers hors Git et preuves publiques.
6. Utiliser ce premier bearer par les routes ordinaires pour créer policies,
   tokens/coffres métier et délégations. La clé bootstrap reste refusée sur le
   métier, même quand PostgreSQL est disponible. Désactiver le mode opérateur
   après installation. Le JIT SSH utilise exclusivement les bearers métier.

Mode `restore` : status, verify-connections et résolution du seul seed initial.
Aucune réinstallation mount/credentials/schéma/admin. OpenBao/backup se restaure
avec PostgreSQL arrêté ; aucune connexion PG n'est nécessaire à l'unseal.

## Droits à provisionner séparément

L'owner de schéma est NOLOGIN, NOSUPERUSER, NOCREATEDB, NOCREATEROLE,
NOREPLICATION, NOBYPASSRLS. L'app a les mêmes restrictions et aucun membership,
DDL, CREATE database/schema, TEMP ni SET ROLE owner/provisionneur/voisin. Elle
a CONNECT sur sa seule base, USAGE sur `vault_metadata`, SELECT sur version et
DML sur les tables métier ; reçus et marqueur sont SELECT+INSERT, sans UPDATE/DELETE. Le provisionneur n'est jamais le rôle runtime ; il
peut SET ROLE owner uniquement pour le DDL versionné. Les identités externes de
backup/restore restent distinctes, hors produit.

Révoquer CONNECT/TEMP/CREATE de PUBLIC sur chaque base possédée, CREATE sur le
schéma public et tout grant PUBLIC sur le schéma/objets Vault. Définir les
privilèges par défaut **du rôle qui crée les objets**, pas seulement ceux de
l'opérateur courant. App et voisin ne sont membres d'aucun rôle privilégié.
Ne pas révoquer/modifier les droits de bases étrangères au déploiement. La
readiness vérifie identité, version, droits effectifs et grants PUBLIC ; elle
ne les répare pas. Qualifier séparément les refus cross-domain, SET ROLE, DDL et
les droits/default grants avant d'ouvrir l'app après restauration.

## Interfaces et incertitude

`vault_metadata_batch` (MCP), `vault metadata-batch` (CLI) et
`POST /admin/api/vaults/metadata-batch` (REST, même autorisation que la console) acceptent une
liste explicite bornée, une limite et un curseur lié à la requête/identité. ACL
sur tout le lot avant count/page/read ; metadata seule et source OpenBao,
aucun listing de contenu ni scan global. Absence metadata confirmée ne signifie
jamais coffre libre à créer. Refus backend, corruption et outage ferment la
réponse entière. Les guards sync utilisent les faits frais de la requête,
jamais un miroir owner en PG.

Les réservations couvrent MCP/REST/CLI/console, versions, wrapping/status/consume/
revoke, profils/signature SSH et primitives. Supprimer `prod` prévalide aussi
`ssh-ca-prod` avant cleanup/disable ; le refus cleanup ne permet pas la suite.
Les lectures KV pures conservent leurs cibles réelles.

Chaque mutation possède un UUID interne distinct par phase, acteur, tuple métier
complet et révisions. Le couple operation/mission reste la clé du wrap ; jamais
résolution operation seule. Révisions CAS et reçu sont transactionnels. Notice
COMMIT ou ACK perdu => unknown, aucun replay. `pending` précède wrap externe ;
`consuming` précède unwrap. Une incertitude ne remet jamais consuming en active.
Les reçus décrivent le fait database ; ils ne prouvent pas la réception de l'ACK.
La classification initiale conservée par le caller/preuve privée est immuable.

Bornes : SQL défaut 4 slots, file 1 s, connect 3 s, statement 5 s, lock 2 s,
budget SQL partagé 10 s ; metadata 4 slots, file 1 s, connect 1 s/read 2 s,
deadline 5 s et corps 64 KiB ; batch défaut 50, max configurable 100. Libérer
les slots/verrous après fin réelle des workers. Aucun retry mutatif implicite.

La sonde PG de `/health` et `/ready` partage une seule lecture en cours et
conserve son résultat pendant `METADATA_READINESS_TTL_SECONDS` (défaut 2 s).
Ce cache de disponibilité ne sert jamais aux contrôles d'accès : chaque
requête métier recharge ses faits d'autorisation dans PostgreSQL.

En profil `METADATA_PG_DURABILITY=ha`, les noms de standbys synchrones doivent
être configurés et stables pendant la transaction. Le COMMIT `remote_apply`
attend leur application distante ; aucun droit `pg_read_all_stats` n'est
accordé à l'application. L'attente est annulée côté client à l'échéance du
budget SQL, via libpq 17+ fourni par le verrou `psycopg-binary`. Chaque demande
d'annulation est bornée par `METADATA_SQL_CANCEL_SECONDS` (défaut 2 s).
Une annulation ou un ACK perdu donne un résultat inconnu, jamais un succès ni
une permission de rejouer. Le reçu peut alors être visible sur le primaire
avant réplication : une bascule peut perdre cet état, y compris une révocation.
Conserver l'incertitude et résoudre l'état avant de rouvrir les écrivains.

Si l'enregistrement `active` échoue après création d'un wrap OpenBao, Vault
tente sa révocation native indépendamment de PG. La réponse reste
`wrap_created_revoked` ou `wrap_created_orphaned`, sans token ni accessor.
Une issue SQL inconnue ajoute `metadata_outcome=unknown` et `mutation_id` ;
une révocation OpenBao confirmée ne confirme pas le COMMIT SQL.

## Reprise logique et qualification

Voir `tests/postgres/README.md`. Premier restore : dump logique de **la base du
domaine seul**, dans base/volume neufs. Restaurer rôles, ownership, grants et
privilèges par défaut séparément, avant tout accès applicatif. Secrets/coffres
OpenBao et leur archive existante sont conservés ; aucun mécanisme global de
backup, PITR ou HA n'est introduit. Revalider depuis un processus neuf grant,
revoke, expiration, tombstones et reçus ; observer les voisins avant/après.

Rollback : fermer les écrivains, conserver archives/reçus/unknown et états
finaux ; restaurer Vault/auth d'abord puis le seul domaine PG. L'absence d'un
reçu après rollback ne prouve pas l'absence de l'effet OpenBao. Ne pas rouvrir
les writers tant que permissions et opérations incertaines ne sont pas résolues
ou mises en quarantaine. Aucune restauration automatique du driver S3 métier.
