# Design des données — métadonnées d'accès Vault #178

Statut : design consolidé approuvé au niveau plan ; implémentation et
qualification restent à réaliser. Factory documentaire intégrée sur
`8b69c464d722710ac307d281a2582e2c86fd5e1a` :
[guide public](https://github.com/Cloud-Temple/starter-kit/blob/8b69c464d722710ac307d281a2582e2c86fd5e1a/docs/data-design.md).
Ce document adapte le canevas au produit sans modifier les règles génériques.

## 1. Périmètre et parcours public

Un administrateur octroie un accès, un bearer autorisé lit le coffre et un lot
borné de metadata, puis la révocation ferme les requêtes suivantes, également
après redémarrage. MCP, REST, CLI et console conservent les droits publics
existants. Le batch proposé est accessible aux agents et aux personnes par
MCP/REST/CLI, sans nouvelle page console nécessaire.

Les contrats du produit sont décrits ci-dessous et dans `docs/postgres-metadata.md`.

Hors lot : migration d'un ancien stockage, refonte OpenBao/unseal/PKI/SSH,
nouvelle persistance audit #179, hub #842, LiveMemory/GraphMemory, HA et PITR.

## 2. Inventaire, autorité et invariants

| Données | Autorité | Contrat |
| --- | --- | --- |
| Hashes bearer et allowlists | PostgreSQL du domaine Vault | SHA-256 seulement ; droits validés, révocation/tombstone et expiration |
| Policies et bindings locaux | Même PostgreSQL | Droits existants, policy référencée localement, délégation facultative vérifiée |
| Registre wrap et reçus | Même PostgreSQL | Clé registre instance/opération/mission, transitions CAS, pas de wrap token |
| Secrets, private keys, metadata owner | OpenBao existant | Aucun miroir PG ; owner est `_vault_meta.created_by` |
| Backup des coffres/unseal | Mécanisme existant | Inchangé et indépendant de la disponibilité PG |
| Faits de requête | Mémoire de requête uniquement | Chargement frais borné avant décision synchrone, aucune autorité durable |

Une seule autorité metadata explicitement sélectionnée : `s3` conserve le
profil historique ; `postgres` ne lit/écrit aucun ancien snapshot métier S3.
Aucun fallback, dual write, import privé ou dépendance Mission obligatoire.
Les tables et transactions par lignes de R1, corrigées par R2, font foi.

## 3. Droits et isolation

Auth fraîche PG avant droits métier ; owners et metadata obtenus par lecture
OpenBao ciblée bornée hors boucle ASGI, sans scan global de mounts ni helper
legacy permissif. Absence confirmée, refus backend, corruption et outage sont
distincts. Batch tout ou erreur, ACL avant count/page/read, aucun secret dans
la projection. L'administrateur métier ne reçoit jamais l'autorité SQL.

Le coffre `METADATA_PG_VAULT_ID` entier est réservé, toutes versions comprises.
Chaque opération valide ses cibles logiques **et physiques réellement utilisées**
avant toute lecture/effet OpenBao métier et avant bypass admin/owner/policy.
Une suppression KV `prod` valide `{prod, ssh-ca-prod}` avant cleanup ou disable.
Les primitives `cleanup_ssh_ca`, setup/sign, ca-key/list/info se gardent aussi ;
le refus cleanup ne devient jamais une erreur non bloquante autorisant la suite.

La fiche REST qui enrichit KV avec SSH prévalide les deux mounts avant la
première lecture. Les accès KV purs conservent leur périmètre réel. Les
projections générales filtrent toute cible réservée avant enrichissement/count,
une demande explicite conflictuelle échoue complètement. Les groupes de
mutations valident l'ensemble avant leur premier effet.

Les surfaces JIT `ssh_operator_access_profiles`/`ssh_request_operator_access`,
CLI `ssh profiles`/`ssh request`, REST `ssh/operator-profiles`/`operator-access`
restent métier à bearer PG. Profils serveur réservés exclus avant projection
et count ; cible dérivée contrôlée avant owner/signature et dans `sign_ssh_key`
appelée directement. Aucun caller/header/profile ne permet le bypass. Ce JIT
n'est pas l'opérateur infrastructure autonome. Aucune refonte SSH nécessaire.

Wrap indirect : résolution SQL locale bornée et autorisée de la clé complète,
puis réservation/ACL avant CAS, mutation registre et lookup/revoke/unwrap
OpenBao. Cible ambiguë ou inconnue : fermeture explicite. Les lectures internes
des credentials app sont distinctes des effets métier et comptées séparément.

## 4. Topologies et démarrage

Standalone : sources publiques, PG propre, OpenBao local ou endpoint explicite.
Externe partagé : mêmes API/droits, une base par domaine, rôles et secrets
distincts, aucune infrastructure fleet imposée. Partage physique ne signifie
pas HA. Libpq standard, CA et `sslmode=verify-full`, identité base/rôle/schéma
attendue vérifiée ; aucune API d'orchestrateur obligatoire.

Owner NOLOGIN, app DML seule, provisionneur de schéma et opérateurs externes
backup/restore séparés. App sans DDL, rôle cluster ou membership owner.
L'opérateur configure CONNECT/TEMP/PUBLIC, droits schema et privilèges par
défaut avant la baseline. Deux domaines : accès croisés base/objets/secrets,
SET ROLE et DDL refusés ; voisins et grants inchangés pendant la qualification.
L'app ne répare pas les grants de l'infrastructure.

Provider exact : OpenBao HTTP/KV v2 existant, pas la propre API métier MCP
Vault. Restore/unseal/auth OpenBao avant toute connexion SQL, y compris jobs
opérateur, provisioning et probes. Identité infrastructure indépendante PG et
privée ; aucun credential direct/périmé ou admin métier en fallback.

La clé bootstrap reste une autorité finie R2 sur metadata-operator, refusée
sur le métier en PG. Install : mount configuré create-only, deux chemins
credentials distincts CAS, schema-init par provisionneur, premier hash admin
borné avec marqueur/reçu atomiques. Restore ne réinstalle ni schéma ni seed,
n'écrase pas les credentials. Runtime app seulement. Readiness fermée si
stockage/droits/schéma indisponibles ; liveness et backup OpenBao indépendants.

Bornes R1/R2 : SQL 4 unités, connect 3 s, statement 5 s, lock 2 s, drain 10 s ;
batch défaut 50 IDs ; metadata 4 workers, file 1 s, connect 1 s, read 2 s,
write 1 s, deadline 5 s, corps 64 KiB, drain 8 s. Configuration invalide refusée,
slots libérés après fin réelle, aucun retry implicite ni SQL synchrone en ASGI.

## 5. Concurrence et incertitude

Mutations par lignes, CAS et reçu atomique, acteur revalidé dans la transaction.
Reçu `(instance_id, mutation_id UUID)` corrélé au tuple métier, mission, phase
et révision ; jamais jointure operation_id seul. UUID distinct par phase.
Policy référencée non supprimable, tombstones et marqueur seed préservés.

Politique COMMIT relue dans la transaction ; notices installées avant BEGIN
et capturées jusqu'à fin réelle. Perte ACK, notice COMMIT risquée, deadline ou
coupure : outcome_unknown, aucun replay. Une lecture finale peut constater
l'effet, pas réécrire l'ACK historique. Pending confirmé avant wrap externe,
consuming confirmé avant unwrap ; aucune transition consuming→active.

## 6. Reprise logique et rollback

Première recette opérateur : dump/restore logique du domaine seul, pas de
dumpall global ni nouvelle capacité backup infrastructure. Rôles globaux,
ownership/grants/default privileges restitués séparément ; secrets repris
depuis OpenBao, aucun mot de passe dans manifeste/preuves publics.

Suspendre écrivains, préserver archives/états/reçus, OpenBao/auth d'abord,
restore dans base/volume neuf sans toucher le voisin. Valider les droits avant
toute lecture app, démarrer un process neuf puis relire grant/revoke/expiry
aux seams publics et indépendamment. Comparer le voisin avant/après. Backups
OpenBao existants inchangés ; aucun snapshot atomique SQL/OpenBao promis.

Un reçu absent après rollback n'est pas absence d'effet externe. Maintenir
unknown/quarantaine et fermer l'opération, sans replay wrap/unwrap/revoke.
Rollback conserve la réservation technique, jamais ancien runtime exposant
credentials ni bascule S3. Cleanup propre seulement après lecture indépendante
finale. RTO/RPO mesurés sur l'épreuve, aucune garantie HA/PITR implicite.

## 7. Qualification et état de livraison

Plan consolidé ; aucun comportement PG nouveau qualifié à ce stade. Harnais
public autonome et seams hauts MCP/HTTP/CLI requis, sans chemin privé ou
dépendance Mission. Banc/services/SQL/fault/restore attendent admission root.
CI pertinente groupée après diff stable, puis checks affectés seulement après
findings ; revue indépendante du résultat stable avant publication.

Preuves futures : grant/read/batch/revoke/restart, bootstrap PG down, collisions
prod/ssh-ca-prod et JIT/projections, compteurs effets refusés zéro, credentials
inchangés, deux domaines isolés, COMMIT inconnu inter-missions sans replay,
restore neuf et droits avant app, état persistant final relu avant cleanup.
