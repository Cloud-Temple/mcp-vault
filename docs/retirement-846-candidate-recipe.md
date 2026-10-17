# Recette candidate Vault846 v4 — non exécutée

Source : branche de la Draft184, delta par rapport à a188092b ; choisir le SHA
exact du paquet relu avant dispatch. Cette recette n'autorise aucun effet avant
revue du diff/recette et allocation Root. Aucun banc179/835/842/6028/bd6/844
réutilisé. Aucun token/manager ni clé partagé remis au contrôleur.

## 1. Première preuve SQL isolée

Conteneur **neuf** PG17 sur image déjà épinglée du banc846
`sha256:3645570cccdfa447589da9f57dd740faa29b30938e861289a5574b6ca6b03826`,
networknone,1CPU/768MiB,540s maximum et nettoyage exactCID dans finally.
Le runner propriétaire existant crée le dossier/socket privés et démarre ce seul
PG jetable ; recopier le code produit est interdit, monter le WT du SHA figé RO.
Utiliser le Python propriétaire contenant psycopg, sans installer de dépendance.
Ne pas appeler l'ancienne fixture combinée846 (ses acquis restent historiques).

Premier enfant borné :

```text
python tests/fixtures/retirement_846_pg.py --socket <socket privé PG17 neuf> --report <résultat privé neuf>
```

La fixture refuse un autre major PG ; noms de rôles/DB sont fermés et CREATE,
jamais DROP ni IFNOTEXISTS sur un domaine préexistant. Elle installe v1→v3
par audit_schema.install puis v3→v4 par audit_retirement_schema.install et
verify exact. Avant ce verify, elle capture le vrai catalogue pg_constraint PG17
dans le fichier privé adjacent `.constraints.private.json` : six CHECK, une
PK, une UNIQUE et une FK, toutes validées. Puis elle appelle le vérificateur
produit réel (l’attente8 du prédécesseur156e33e le ferait échouer). Les attributs NOTNULL ne
sont pas comptés comme contraintes PG17. Les dates d'audit anciennes sont un seed synthétique propriétaire,
pas365jours observés. Le contrôle direct des lots SQL n'est pas attribué à un
parcours HTTP/TLS. Capturer résultat/exception privés avant assertion runner,
terminal réel, inspect exit/OOM puis retrait exactCID/absence. Premier écart ou
UNKNOWN arrête cette fixture ; aucune réutilisation du dossier ou double dispatch.

Groupes contenus : installation+verify/ACL, sweep global ne retire pas les
corrélations, préparation d'inventaire, deux vrais COMMIT de lots/IDs RETURNING/
receiptUUID179 et reçu annuel, préservation B et binding partagé, doublon final
refusé, attente advisory réelle→expiry→rollback, audit credential opaque
uncorrelated capable de COMMIT pendant verrous de scope, Mission sans activité
Vault (clôture qui crée le hold puis refuse appel et wrap, reçu à comptes nuls
sans lot ni reçu179, scope non clos refusé), verify final.

Avant adoption, compléter les cas SQL ci-dessous dans une fixture fraîche ou un
delta relu de celle-ci ; aucun booléen logiciel ne les remplace :

- maintenance ne peut pas lire table/metadata ni appeler les routines internes ;
  app ne peut ni expire/close/retire ni modifier les reçus ; PUBLIC exclu ;
- calls/events inconnus/nonterminaux et wraps failed/pending/consuming inconnus
  protègent ; consumed/revoked n'est libérable qu'avec result_revisions et
  database_result committed exacts du propriétaire ; faux tenant ou absent refuse ;
- modification de binding entre lots, admission B concurrente, admission A après
  close, append179 d'une opération encore en cours : état cohérent, pas retrait
  d'un pin B ni permission échue restaurée ;
- opération contradictoire, inventaire1001refs/IDtropgrand, payload malformé,
  rollback après premier DELETE, reçu final annuel protégé du sweep et
  COMMIT/close/NOTICE incertains : références conservées, aucun ACK global.

## 2. Callback canonique : condition de réussite positive à prouver

Le code Mission existant `auth/retention_check.check_persisted_claim` utilise
PostgresMissionRepository._read ; son resolver._read_sync obtient les coordonnées
via SecretRead MCP Vault. Ce chemin doit être testé **avec sa vraie auth opaque**,
pas remplacé par une réponse active stubbée. Le profil app Mission possède
seulement secret_read sur son chemin SQL, aucun outil admin/revoke/write.

Le contrôleur v4 tient scope846/hold/op/binding SHARE/wrap/appels du seul A avant
son second callback. Il n'a encore ni DELETE, ni write audit_revision, ni mutation
policy/token. L'audit Vault de SecretRead opaque est non corrélé (audit_pg.new_call)
et acquiert donc audit_revision sur un autre appel après son INSERT. Il doit
pouvoir finir puis laisser Mission lire son claim READONLY. Les verrous de token/
policy SHARE de cette lecture sont compatibles ; aucune mutation de ces objets
n'est demandée par le retrait. Ce raisonnement source n'est PAS la preuve native.

Domaine TLS neuf consacré846 : config Vault-first réelle et deux processus
Mission/Vault, JWKS/callback exacts, SQL rôle app distinct/maintenance hors ASGI.
Préparer un claim closed A et historique B avec le même binding, reçus/proof ES256
à TTLréel≤30s. En maintenant la préparation locale A, faire un vrai callback
canonique impliquant la lecture du credential dans ce même Vault ; observer les
vraies attentes via pg_stat_activity sur les PIDs propres et conserver les ACKs
SecretRead/audit179 et le callback. Aucun secret/body/header en preuveSAFE.
Le succès positif doit aboutir, pas simplement confirmer un refus permanent.

Puis bloquer réellement le scope A et retirer le claim ou dépasser son échéance
pendant l'attente. Après libération, le second callback doit refuser ou expirer,
avec rollback sans DELETE/lot/reçu final. Panne Vault/Mission, budget dépassé ou
preuve d'une attente inverse => protected et arrêt diagnostic, pas suppression
du callback/du contrôle d'audit ni élargissement des droits pour obtenir un PASS.

## 3. Parcours public et consommateur

Après SQL/ACL et absence d'attente inverse démontrées seulement :
close confirmé → inventory UUID neuf → retire(batch choisi) une commande à la
fois après ACK → receipt exact UUID → import owner par CLI Mission de son
propriétaire. Le dernier retourne l'enveloppe fermée audit179:v1/holds846:v1,
quatre références agrégées vault_audit_calls, vault_audit_events,
vault_binding_references, vault_wrap_references (id sha256:<hex>, revision = compte),
calculées sur l'inventaire exhaustif stocké (voir docs/retention-846.md).
Identité globale du claim exacte, refs sans racine native rootvide, pas payload.
Tester avec le vrai validateur Mission après le delta consommateur de son auteur.
Un lot partiel, un état préparé ou une observation vide n'est pas un ACK final.

Préserver SQL originaux/receipts, versions/coffres/OpenBao et clés ; aucune purge
physique de sécurité ni réattribution de TTL. Mise hors service du flag ferme la
coordination sans supprimer holds/reçus. Cleanup scoped de ce banc neuf seulement,
refus fresh des identités/LOGIN, jobs absents deux fois, rapport des limites. Une
nouvelle recette flotte globale attend encore les autres propriétaires livrés.


Erratum de revue, après première exécution61818 : le catalogue PG17 réel de
`j0/pg846-v004-r1-0f441b1375b7/checks.confirmed.constraints.private.json` contient
neuf contraintes validées : six CHECK (proof_sha256, inventory, state, lots,
identité, étatfinal/annualité), PK, UNIQUE, FK. Le premier constat de revue
attendait à tort cinq CHECK/huit contraintes ; le changement156e33e a donc
introduit un faux refus. Le verdict original et ce premier résultat EXIT1 sont
conservés, sans réattribution. Aucun inventaire/retrait/callback n'avait commencé.
Le candidat DDL004 est inchangé ; attente9 rétablie et fixture6CHECK corrigée
avant nouvelle revue. Aucune seconde exécution PG autorisée par ce document.
