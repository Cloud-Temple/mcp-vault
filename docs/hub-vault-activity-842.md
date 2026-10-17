# Lecture propriétaire pour un hub Mission (#842)

Vault fonctionne de façon autonome, sans dépendance au code privé Mission.
`HUB_VAULT_ENABLED=false` par défaut : aucun fetch JWKS ou callback requis.
Le raccord optionnel POST `/internal/hub/vault-activity` est une lecture, sans
création de droit ni copie d'audit. Il nécessite PostgreSQL #178/#179 et l'auth
opaque existante (`bearer` ou `dual-stack`).

Configurer `HUB_VAULT_ISSUER`, `HUB_VAULT_AUDIENCE`, `HUB_VAULT_JWKS_URL`,
`HUB_VAULT_CHECK_URL` (route Mission `/internal/hub/vault-delegation-check`),
`HUB_VAULT_CA_FILE` ; HTTPS uniquement, pas de discovery depuis les claims.
Le champ `owner_id` signé doit égaler `METADATA_INSTANCE_ID`. Cache JWKS existant
`MISSION_JWKS_CACHE_TTL` entre 10 et 60 secondes, sans secours périmé.

## Deux autorités nécessaires

`Authorization: Bearer <opaque local>` conserve les droits locaux. Un lecteur
dédié a exactement `read`, des coffres explicites et une policy permettant
exactement `audit_log` et `vault_metadata_batch`, avec règles couvrant les coffres
entiers. Aucun admin/wrap/secret_read. Le JWT `X-Vault-Hub-Context` ne remplace
jamais ce badge et n'octroie aucun droit de coffre. Le binding actif du tenant
vérifié, de cette instance, est intersecté avec les coffres du badge et les
policies locales. Token, binding et policies sont relus avant/après restitution.

Le contexte ES256/P-256/JWKS exige `purpose=hub-vault-activity-v1`, permission
exacte `["vault.activity.read"]`, issuer/audience/owner épinglés, sujet
`opaque:` ou `oidc:` suivi de 64 hex, tenant/Mission/resources cohérents, jti
32 hex, `iat=nbf`, TTL positif <=30s et `request_sha256` des octets HTTP exacts.
Le registre émetteur est vérifié via callback avant/après la lecture. Un contexte
Agent, Tools ou C18, une révocation, une expiration ou un restart ne sont pas
convertis en accès local. Aucun import Mission privé n'est nécessaire ici.

Corps JSON fermé : `mission_id` (mis_*), `tenant_id`, `limit` 1..100, `cursor`
43 caractères URL-safe facultatif. Aucun nom de coffre, filtre libre ni URL.
Enveloppe fermée : `status`, `source=vault_owner`, `mission_id`, `tenant_id`,
`read_at`, `vaults`, `entries`, `count`, `total`, `complete`, `next_cursor`,
`coverage`. Métadonnées réduites à ID/état/dates UTC ; audit via projection179.
Aucun description, détail libre, bearer, chemin secret ou payload n'est exporté.

Le scope dédié filtre instance/coffres/tenant/Mission/acteur mission_* avant
count/page/stats. Les anciens lecteurs opaques restent limités aux lignes sans
tenant/Mission ; `audit_log` standalone garde son refus mission_jwt. Aucun
rattachement supposé d'anciennes traces à une Mission. Une liste de coffres
accordés par binding ne prouve aucun usage par la Mission.

Curseurs179 à usage unique, RAM120s, liés au sujet stable et aux révisions de
token/policy/binding. Pour ce raccord Mission seulement, la première page fige
la borne `seq` ; les ajouts après cette borne et les événements hors scope ne
modifient pas la lecture. Le total et une empreinte versionnée des `seq` du
scope filtré sont vérifiés dans le snapshot puis après COMMIT. Une suppression,
une expiration ou un changement de cet ensemble donne 409 incomplete, même
si un remplacement conserve le même nombre de lignes. L'empreinte utilise deux
sommes de 64 bits issues de SHA256, calculées en mémoire constante par SQL ; une
collision théorique demeure possible. Aucun journal n'est mémorisé ni copié.
Le lecteur standalone179 conserve sa révision globale stricte, y compris pour
les insertions. Aucun snapshot durable n'est créé.
403 signifie refus local/contexte perdu ; 503 signifie indisponible/indéterminé,
jamais coffre vide. Métadonnées absentes/corrompues ferment toute la réponse.
Aucun nouvel événement récursif n'est créé par le lecteur lui-même.

Bornes par processus : `HUB_VAULT_MAX_INFLIGHT=1`, `MAX_PENDING=4`,
`MAX_RESPONSE_BYTES=1048576`, `TIMEOUT_SECONDS=5`, `TOTAL_SECONDS=20`
(tous préfixés `HUB_VAULT_`). Corps <=8192 octets, contexte <=16384 ; déconnexion
et timeout drainent les workers PG avant libération des admissions.

`tests/test_hub_vault_activity_842.py` exerce AuthMiddleware et le vrai handler,
la signature/JWKS, les scopes avant SQL, les droits locaux et l'expurgation avec
seules les I/O contrôlées. Ce n'est pas une qualification PG/Bao native ; celle-ci
reste une recette séparée revue avant activation avec retour arrière observé.
