# Diagnostics techniques #846 — première tranche

`TECHNICAL_LOG_DIRECTORY` optionnel désigne un répertoire absolu privé du seul
service. Le lifespan ajoute puis retire son handler quotidien UTC ; les logs
existants restent inchangés. Seuls niveau, nom du logger et code d'événement borné
sont retenus, sans arguments, corps ni traceback. Les messages libres deviennent
`event`. Les segments privés600 portent le préfixe propriétaire.

```sh
python -m mcp_vault.technical_logs --directory /private/technical --days 30 --batch 100
```

Ce CLI refuse moins de30jours et retire au plus1000segments clos par passage.
Il préserve les fichiers courants/récents, noms tiers, audit, liens et permissions
incertaines. Une liste trop grande reste incomplète sans suppression. Aucun
nettoyage global des logs Docker/plateforme n'est lancé ; leur collecteur doit
être configuré séparément pour30jours. Aucun TTL de sécurité ni d'audit n'est
modifié. Les tests filesystem/horloge contrôlée ne qualifient pas le banc flotte.

Les protections `audit_mission_holds` optionnelles sont une autre tranche :
v3 SQL a reçu une preuve isolée7groupes, sourcee701, sans callback/JWT public ni
activation. Les dates d'audit d'admission restent immuables et les corrélations
inconnues protègent. Le raccord opérateur de clôture reste à terminer.

La voie metadata-operator existante prépare aussi deux actions POST locales :
`audit-retention-close` (`proof`, `confirm` exact) et `audit-retention-status`
(`proof`). Elles exigent mode install, profil PG/holds et LOGIN de maintenance
séparé. Configurer MISSION_RETENTION_ISSUER, MISSION_RETENTION_AUDIENCE et le
MISSION_JWKS_URL existant sur la même origine HTTPS ; le magasin de confiance
TLS existant (SSL_CERT_FILE pour une CA privée) vaut pour JWKS et callback.
Aucune dépendance Python au package Mission. La preuve ES256 de30s exige owner
Vault/purpose/révision/fin canonique/échéance annuelle/claim exacts. Le contrôle
live est un POST sans redirection et sans bearer réfléchi, puis les échéances
sont revalidées avant le COMMIT local et sous verrous par la routine SQL.

Une clôture confirmée ne vaut PAS retrait complet : inventory_complete et
purge_confirmed restent faux. La projection de statut est observation_only,
jamais une reconstitution d'ACK après timeout. Un COMMIT/close incertain reste
UNKNOWN, avec identifiant de claim et aucune réémission automatique. La suite
bornée de retrait des audits/références reste à implémenter et qualifier avant
reçu final importable dans Mission ; aucun critère n'est écarté par cette tranche.
Le DDL reste octet identique àe701 déjà testé en SQL isolé ; ces raccords publics
n'ont reçu que des tests logiciel/HTTP contrôlé, pas de qualification TLS/flotte.

## Candidat v4 : reçu propriétaire de retrait

La migration `004_retirement.sql` est un **nouveau candidat non qualifié en PG**.
Depuis une installation v3 avec les protections activées, l'opérateur install
peut demander `audit-retirement-upgrade` avec `{"confirm":"audit-retirement-upgrade"}`.
Cette voie utilise le provisioner/owner déjà prévu ; aucune création de rôle,
réparation runtime ou réutilisation d'un ancien banc. La désactivation du flag
ne retire jamais les protections SQL installées.

Après `audit-retention-close` confirmé, trois actions POST locales sont proposées :

- `audit-retention-inventory` : `proof` et `operation_id` UUID canonique. Capture
  durable et complète des références, maximum 100000 références et 16 Mio, puis
  réponse sous la forme agrégée du reçu (voir plus bas) ; ce succès ne vaut pas
  retrait. Un scope non clos, incomplet, un audit non terminal/UNKNOWN ou un wrap
  sans état terminal et provenance confirmée reste protégé.
- `audit-retention-retire` : mêmes paramètres, `batch`1..500 et `confirm` exact.
  Les lots conservent les IDs réellement issus de DELETE RETURNING et leurs
  reçus179 dans la même transaction. Un lot partiel n'est pas importable dans
  Mission. Le reçu final ne sort qu'après COMMIT et fermeture confirmés.
- `audit-retention-receipt` : mêmes paramètres, observation du reçu durable exact
  après incident ; un compteur ou une absence ne recrée jamais un ACK perdu.
  Une opération finale confirmée n'est pas redispatchée. UNKNOWN exige inspection.

L'inventaire stocké dans `vault_metadata.audit_mission_retirements` garde une
ligne par objet : `audit_call` (UUID, révision 0), `audit_event` (`call_uuid:seq`,
révision 0), `binding_reference` (tenant, révision native positive) et
`wrap_reference` (`operation_id:mission_id`, révision native positive). Le contrôle
« inventory changed » de chaque lot compare toujours cette liste complète.

Le reçu remis à Mission est agrégé, car Mission plafonne à 1000 la somme des
références des quatre propriétaires distants. Il contient exactement quatre
références, dans cet ordre : `vault_audit_calls`, `vault_audit_events`,
`vault_binding_references`, `vault_wrap_references`. Pour chacune, `id` vaut
`sha256:` suivi du SHA-256 hexadécimal du texte jsonb du tableau des éléments
`id@revision` de l'inventaire, triés en `COLLATE "C"` ; `revision` est le nombre
d'éléments. Une catégorie vide porte l'empreinte de `[]`
(`sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945`) et
`revision` 0 ; cette empreinte n'est valide pour aucun compte positif.
`vault_audit_events` vaut au moins autant que les appels et reste à 0 sans appel,
`vault_binding_references` au plus 1. Ces objets n'ont pas de racine
Agent native : root_agent_id est vide dans chaque référence, tandis que
l'identité globale conserve la racine canonique du claim. Mission #914 applique
les mêmes règles (copie figée dans `tests/fixtures/mission_owner_receipt_914.py`).

Mission attend un reçu Vault pour toute claim, y compris pour une Mission qui
n'a jamais appelé Vault. En v4, `audit_close_mission` crée la ligne
`audit_mission_holds` si elle manque, sous le verrou de scope partagé avec
l'admission. Ensuite `audit_fill_call` et `audit_wrap_admit` refusent toute
corrélation de ce scope (42501). C'est cette clôture, et non une observation
vide, qui prouve l'absence d'activité. prepare accepte donc un scope clos sans
appel ; le lot final ne supprime rien, n'ajoute ni lot ni reçu audit179 et rend
`lot` nul avec le reçu à comptes nuls. Un scope jamais clos reste protégé.
Le reçu est indépendant du sweep audit179 et conservé au moins365jours après
son COMMIT final ; aucun GC de reçus n'est ajouté ici. Le sweep179 v4 exclut les
appels corrélés pour ne pas effacer leur inventaire avant le reçu coordonné ;
les appels standalone gardent leur contrat.

Bindings, coffres, versions OpenBao, policies et registre de wraps ne sont pas
supprimés par cette maintenance. Libérer la référence historique de A ne retire
pas le binding de son tenant partagé avec B. Les TTL et révocations de sécurité
ne sont pas modifiés. Aucun payload, credential, accessor ou chemin de secret
n'est copié dans le reçu Mission.

Le callback canonique est relu après acquisition des verrous locaux, avant
suppression. Cette préparation n'écrit pas audit_revision et ne modifie pas les
policies/tokens ; la résolution opaque des credentials Mission peut donc écrire
son propre audit non corrélé sans dépendre de ces lignes. Cette absence d'attente
inverse est **à prouver par la recette PG puis TLS réelle**, pas déduite d'un mock.
Callback indisponible ou échéance dépassée sous attente => rollback, jamais
suppression d'un contrôle pour obtenir un succès. Les tests logiciels n'établissent
ni ce parcours TLS ni une année écoulée.
