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
