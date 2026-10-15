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
