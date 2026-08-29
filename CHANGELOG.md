# Changelog — MCP Vault

## [0.20.1] — 2026-08-29

### Readiness alignée sur les magasins d'autorisation

- `/health` et `/ready` rendent désormais `503 unavailable` lorsqu'au moins un
  magasin configuré n'a jamais été chargé ou que son instantané est périmé.
  Leur lecture reste strictement en mémoire : aucune requête S3 n'est ajoutée à
  ces sondes publiques.
- Les rafraîchisseurs existants peuvent rétablir automatiquement la
  disponibilité après une panne transitoire, sans redémarrage. `/healthz` reste
  une liveness toujours indépendante ; `system_health` reste plus strict et
  vérifie en plus la connectivité S3 courante.
- Une erreur interne de production du rapport de fraîcheur échoue fermée en
  `503`, sans exposer l'exception sur la surface publique.
- Aucun changement de données ni de configuration. Le `HEALTHCHECK` de l'image
  continue de viser `/health` et reflète donc cette indisponibilité ; conserver
  `/healthz` pour les mécanismes d'autoheal qui doivent juger uniquement la
  vie du processus.

## [0.20.0] — 2026-08-29

### Migration maîtrisée vers le SDK MCP Python v2

- Dépendance livrée verrouillée sur `mcp==2.1.1` ; le serveur utilise l'API
  publique `mcp.server.MCPServer` et le CLI le client public v2 avec `httpx2`.
- Le même `/mcp` accepte le protocole moderne `2026-07-28` et les clients
  legacy jusqu'à `2025-11-25`. Un probe versionné installe
  `mcp==1.26.0` dans un environnement temporaire et traverse le WAF réel.
- Le transport HTTP est stateless dans les deux ères. Ce choix ferme aussi un
  héritage d'identité observé sous v1 : une connexion initialisée avec le jeton
  A puis appelée avec B ne peut plus exécuter sous A. Le **transport** n'exige
  plus d'affinité de session. Le produit reste toutefois mono-instance :
  OpenBao embarqué, synchronisation S3 last-write-wins et caches
  d'autorisation ne permettent pas encore un déploiement multi-réplica sûr.
- Les invariants d'authentification, d'entrelacement `ContextVar`, de nettoyage
  après erreur/fermeture et de lifespan réel (`startup` puis
  `shutdown(skip_upload=False)`) sont testés à travers `create_app()`.
- Le contrat historique « paramètre d'outil surnuméraire ignoré » est conservé.
  Le commentaire WAF précise désormais que cette propriété vient du SDK et des
  signatures actuelles, pas du WAF.
- Le CLI ne dépend plus du hook privé de progression v1. Une réponse HTTP 200
  dont le flux SSE se ferme sans résultat terminal rend une erreur bornée, sans
  réémission de méthode ni tempête de reconnexion. Les annulations et
  interruptions sont propagées, y compris lorsqu'un TaskGroup les encapsule.
- La sécurité anti-DNS-rebinding est vérifiée sur la vraie `create_app()` dans
  les deux sens : FQDN public accepté, Host étranger refusé. La grammaire WAF
  du `Content-Type` a été revalidée contre le handler exact du SDK 2.1.1.

Quatre mutations ciblées ont été exécutées sur une copie du dépôt, quatre ont
été détectées : retrait du stateless, retrait de la sécurité transport, retrait
du reset du `ContextVar` et absorption de l'annulation par le CLI.

#### Capability de souscription imposée par le SDK

Le SDK v2 annonce automatiquement `subscriptions/listen`. Cette capability est
**inerte dans MCP Vault** : aucune ressource MCP, aucun appel applicatif de
publication, aucun `EventStore`, aucun replay, transport stateless. Le wire est
testé : l'appel sans bearer est refusé ; pendant une vraie mutation
`vault_create` sous une autre identité, l'appel authentifié reçoit seulement
l'accusé protocolaire et aucun événement applicatif.
Ce résidu doit être réaudité à chaque montée de version du SDK et avant tout
ajout de ressource, publication ou store d'événements.

#### Exploitation, retry et rollback

- Aucune migration de données ni de configuration n'est requise.
- Après une coupure sans réponse terminale, **ne pas réessayer automatiquement
  une mutation** : son effet peut déjà avoir eu lieu. `secret_wrap_lookup` est
  notamment une mutation de révocation malgré son nom.
- Rollback applicatif : redéployer un **artefact v0.19.1 déjà construit** ; ne
  pas reconstruire ce tag, dont le Dockerfile historique ne consommait pas le
  verrou et peut résoudre un SDK incompatible (#125). Les clients legacy
  restent compatibles ; un client ayant adopté exclusivement le protocole
  moderne `2026-07-28` ne pourra plus parler à v0.19.1 et devra repasser en
  mode legacy.
- Aucun journal d'idempotence générique ni vendoring du SDK n'a été ajouté :
  ces couches ne répondent à aucun besoin actuel.

## [0.19.1] — 2026-08-20

### Balayage des `.match()` sur motif ancré — la classe, pas l'occurrence (#160)

**Correctif** — aucun appelant conforme ne casse : `fullmatch` refuse uniquement un saut de
ligne **final**, qu'aucun appelant légitime n'émet. Vérifié : tous les domaines réels de
production, TTL et numéros de série passent **à l'identique**.

#### Origine — un conseil venu d'une autre équipe

`mcp-mission` publie #582 : une garde en `.match()` au lieu de `.fullmatch()`. Leur remède :
« une ligne, **plus balayage des autres `.match()` ancrés** ».

⚠️ **Nous avions rencontré ce défaut un mois plus tôt** (#78/D6, `is_safe_id`), corrigé
l'occurrence… et **jamais balayé**. Le balayage a trouvé **dix sites** d'appel pour sept
motifs, dont quatre sur la **surface ACME non authentifiée**.

#### Ce n'était PAS une faille — mesuré avant d'être qualifié

Sur `^…$` avec `.match()`, Python accepte un `\n` **final** et rien d'autre : `x\r\n` échoue,
`x\nX` échoue. Aucune charge ne peut donc suivre le saut de ligne — **pas d'injection
d'en-tête, pas de découpe de requête**. Et httpx refuse de toute façon une URL contenant un
caractère non imprimable.

#### 🔴 Le résidu RÉEL, et c'est une faute de la famille #78

Une requête **non authentifiée** `GET /acme/directory%0A` (le `path` ASGI est décodé)
franchissait la garde, mourait dans le client HTTP, tombait dans un `except Exception` unique
et recevait **`502 "PKI backend unavailable"`** avec un `ERROR` nommant OpenBao — **alors
qu'OpenBao n'avait jamais été contacté**.

⇒ Une seule requête forgée, sans authentification, faisait émettre à notre service une
**fausse panne de tiers**. Toute supervision branchée sur ce statut ou cette ligne devenait un
générateur d'alarme déclenchable de l'extérieur — l'inverse exact de ce que v0.17.0 a apporté
à `mcp-agent`. Même faute que #86, #152 et #154 : ne jamais présenter un fait sur l'appelant
comme l'indisponibilité d'un tiers.

Désormais : une URL refusée par notre propre client rend **400** ; une panne de connexion rend
toujours **502**.

#### Aussi : le motif de numéro de série était DUPLIQUÉ

`admin/api.py` en portait une copie littérale de celui de `vault/pki_ca.py`. Deux copies d'un
validateur, c'est deux occasions de divergence — **la cause exacte qui avait rouvert #78**
(trois copies d'un motif d'identifiant avaient divergé). Source unique désormais.

#### Tests — 14 neufs, banc de 5 mutations, 5 attrapées

| Mutation | Échecs |
| --- | --- |
| retour au `.match()` sur le chemin ACME | 2 |
| retour au `.match()` sur la query string | 2 |
| branche 400 supprimée (tout redevient 502) | 1 |
| tout devient 400 (le 502 légitime disparaît) | 1 |
| motif de numéro de série de nouveau dupliqué | 2 |

⚠️ **Deux gardes de CLASSE, et ce sont elles qui comptent** — pas les correctifs :

- plus aucun `.match()` sur motif ancré dans `src/` : le test balaie l'arborescence et échoue
  sur le onzième site que quelqu'un ajouterait ;
- le motif de numéro de série n'existe qu'en **un seul** exemplaire.

Trois **gardes-fous inversés** : une requête ACME légitime est toujours proxifiée, les
domaines réels de production passent toujours, et une vraie panne de connexion rend toujours
502 — sans quoi « tout renvoyer en 400 » passerait le test.


## [0.19.0] — 2026-08-20

### Un motif d'outil qui ne désigne rien est refusé à l'écriture — #128

⚠️ **RUPTURE.** `policy_create` (outil MCP) et `POST /admin/api/policies` refusent désormais
tout motif de `allowed_tools` / `denied_tools` qui ne correspond à **aucun** des 39 outils
exposés. Un appelant qui enregistrait un motif fantaisiste reçoit une erreur nommant le motif.

#### Le défaut

La validation vérifiait seulement qu'il s'agissait de **chaînes**. Une faute de frappe —
`ssx_*` au lieu de `ssh_*` — était acceptée, enregistrée, et ne protégeait **rien**. Sans
message. La règle avait l'air d'être là.

⚠️ **Cas réel en production**, trouvé le 19/08 : la policy `judilibre-prod-api-key-readonly`
porte un motif *denied* `token_create`, absent du catalogue — l'outil qui existe,
`token_update`, n'était donc pas couvert. **Aucun dommage** : `token_update` exige la
permission `admin`, contrôlée indépendamment de toute policy. De la chance, pas de la
conception.

⚠️ Une validation **lexicale** ne ferme pas le trou : `ssx_*` est irréprochable et
totalement inopérant. Seule la correspondance au **catalogue réel** l'attrape.

#### L'asymétrie, qui est le cœur du lot

| Moment | Comportement | Pourquoi |
| --- | --- | --- |
| `create()` — écriture | **refus**, motif nommé | un humain est devant son clavier |
| `load()` — chargement | **avertissement seul** | refuser ici ferait d'un renommage d'outil une indisponibilité du Policy Store **au démarrage** — la faute `extra="forbid"` corrigée dans #86 |

⇒ **La policy de production existante continuera de se charger**, avec un avertissement
nommant la policy et le motif. Sa correction est une action d'exploitation, pas un blocage.

#### `tool_catalog.py` — et le risque qu'il porte

Le catalogue est une **liste explicite** : lire les outils depuis `server.py` créerait un
cycle d'import (`auth/policies.py` est importé PAR `server.py`), et `@mcp.tool()` rend la
fonction nue — il n'y a pas d'objet-catalogue à interroger.

⚠️ Une liste tenue à la main **dérive**. C'est le risque réel de ce lot, fermé par un test
qui la compare à l'ensemble des `@mcp.tool()` : un outil absent du catalogue ferait **refuser
des motifs légitimes**, un outil fantôme ferait **accepter des motifs morts**. Les deux sens
échouent.

#### Tests — 27 neufs, banc de 6 mutations, 6 attrapées

| Mutation | Échecs |
| --- | --- |
| garde d'écriture supprimée | 3 |
| seul `allowed_tools` vérifié (`denied_tools` oublié) | 2 |
| le chargement **refuse** au lieu d'avertir | 1 |
| avertissement émis inconditionnellement | 1 |
| catalogue amputé d'un outil réel | 2 |
| catalogue citant un outil fantôme | 4 |

Deux **gardes-fous inversés** : « allow-list vide = tout autorisé » reste accepté (choix
documenté, le refuser casserait toutes les policies existantes sans traiter la cause), et un
chargement sain ne doit émettre **aucun** avertissement — le bruit fait ignorer les vrais.

#### Ce que la revue adversariale a corrigé — dans les TESTS, pas dans le code

Une passe de revue isolée (`scripts/revue_isolee.sh`, copie de travail dédiée, lecture seule)
a rendu **NO_GO**. Elle a confirmé le code de production — aucun chemin d'écriture n'échappe
à la garde (surfaces énumérées : outil MCP, route admin, CLI et console, toutes convergentes
sur `create()` ; aucun `update` ni chemin d'import), aucun scénario où le chargement rend le
store indisponible, convention `fnmatch` identique à celle de la décision d'accès. **Deux
défauts réels, tous deux dans les tests :**

- **le test de dérive lisait `server.py` avec une regex** `@mcp.tool()` + `async def`. Elle ne
  voit ni `@mcp.tool(name=...)`, ni un outil synchrone, ni un décorateur empilé, ni un
  `add_tool()` programmatique : le test restait vert alors qu'un motif légitime serait refusé.
  ⇒ il interroge désormais le **registre réel de FastMCP** (`mcp.list_tools()`), c'est-à-dire
  ce que le serveur expose vraiment. Plus solide qu'une regex élargie ;
- **aucun test ne prouvait que les deux surfaces d'écriture ATTEIGNENT la garde** — je le
  savais en lisant le code, pas en le mesurant. Deux tests de bout en bout ajoutés (outil MCP
  et route admin), vérifiés non complaisants : retirer la garde les fait échouer. ⚠️ C'est
  exactement l'erreur qui m'avait fait rater deux surfaces sur trois au lot précédent.

Trois faiblesses secondaires fermées : les jokers `?` et `[seq]` sont testés (une
implémentation ne gérant que les préfixes passait), le cas « listes vides » prouve désormais
l'**écriture** et pas seulement le code de retour, et le test de silence exige **aucun**
enregistrement au lieu de filtrer sur un libellé — un avertissement reformulé passait.


## [0.18.0] — 2026-08-20

### Aucun défaut silencieux sur l'installation de l'autorité de certification — #128

⚠️ **RUPTURE, sur les TROIS surfaces qui installent l'autorité de certification.**

| Surface | Ce qui change |
| --- | --- |
| outil MCP `pki_ca_setup` | `lab_mode` et `allowed_domains` n'ont plus de défaut ⇒ `required` dans le schéma MCP |
| CLI `pki setup` | `--lab` ou `--prod` **et** `--domains` sont obligatoires |
| route `POST /admin/api/pki/setup` | `lab_mode` (booléen réel) et `allowed_domains` sont obligatoires dans le corps ⇒ **400** sinon |

Un appelant qui les omettait reçoit une erreur : c'est l'effet voulu, et c'est le seul
remède au défaut ci-dessous.

⚠️ **Les trois surfaces ont été trouvées l'une après l'autre**, en cherchant la **classe**
du défaut après chaque occurrence corrigée. La CLI — corrigée en premier — est la seule que
**aucun script du dépôt n'appelle**. L'outil MCP est celui que la plateforme utilise ; la
route HTTP était la plus permissive des trois. La leçon est là : corriger l'occurrence
laisse la classe ouverte.

#### 🔴 Ce que le défaut permettait — mesuré, pas supposé

`lab_mode` ne décide pas d'un détail de laboratoire : il décide de la **politique
d'enrôlement ACME**.

| `lab_mode` | `eab_policy` | Qui obtient un certificat de notre AC |
| --- | --- | --- |
| `True` (ancien défaut) | `not-required` | toute machine passant la vérification de nom |
| `False` | `new-account-required` | seulement sur invitation d'un administrateur |

Or dans `setup_pki_ca`, **les deux écritures sont INCONDITIONNELLES** : le rôle
`roles/acme-servers` (donc `allowed_domains` et `max_ttl`) et `config/acme` (donc
`eab_policy`) sont réécrits depuis les arguments à chaque appel.

⇒ **Un appel `pki_ca_setup()` sans argument — le geste naturel de qui veut « installer la
PKI » — rétrogradait une production saine :**

- `allowed_domains` écrasé par `*.lesur.lan` ⇒ **plus aucun certificat émissible pour les
  vrais domaines** (panne, bruyante) ;
- `eab_policy` passé de `new-account-required` à `not-required` ⇒ **enrôlement ACME ouvert**
  (silencieux) ;
- `max_ttl` du rôle ramené à `720h`.

✅ **La production n'était PAS dans cet état.** Relevé le 20/08/2026 par
`GET /admin/api/pki/status` avec un jeton de **lecture seule** :
`eab_policy=new-account-required`, `eab_required=true`, domaines
`internal.agentic.cloud-temple.app`, 23 certificats. Le correctif est préventif.

#### Le défaut d'analyse d'arguments de la CLI, refermé par le même geste

`pki setup --ttl --prod` : une option à valeur chaîne avale l'option suivante, `--prod`
devient la valeur de `--ttl`, et le drapeau manquant retombait sur son défaut permissif
**sans un mot**. Combiné à des `--domains` fournis à la main, on obtenait la pire
combinaison — de VRAIS domaines et l'enrôlement libre — avec tout qui a l'air correct.

⇒ Le remède n'est pas « un défaut plus sûr », c'est **l'absence de défaut** : rendre le
choix obligatoire transforme l'option avalée en **erreur**. Même principe que #78 : ne
jamais laisser une ignorance se présenter comme une décision.

#### Correction de documentation : l'outil n'est PAS « idempotent »

L'ancienne docstring l'affirmait. C'est vrai de la **création** des autorités (une autorité
existante n'est pas recréée), **faux** du rôle ACME et de la configuration ACME. Un lecteur
qui se fiait au mot pouvait croire qu'un second appel était sans effet. Encore un mot qui
disait autre chose que le fait.

#### La route HTTP était la plus permissive des trois

    lab_mode = data.get("lab_mode", True)        # défaut PERMISSIF
    raw_domains = data.get("allowed_domains")    # absent → None → *.lesur.lan

⇒ **un POST au corps VIDE (`{}`) suffisait à rétrograder la production.** Aucune validation
n'existait : ni corps illisible, ni domaines vides, ni `lab_mode` non booléen.

⚠️ **Le cas le plus sournois : `lab_mode: "false"`**, la CHAÎNE. Une chaîne non vide est
**vraie** en Python : un appelant qui croyait demander la production obtenait l'enrôlement
LIBRE. Un booléen réel est désormais exigé — c'est la seule chose qui ferme ce cas.

La console web envoie toujours les deux champs ; **c'est la route nue qui était exposée**, et
elle n'a pas besoin de la console pour être appelée. Elle reste réservée aux administrateurs
(403 sinon), donc bornée comme l'outil MCP.

Un corps illisible rend maintenant un **400 qui nomme sa cause** plutôt qu'un message de
champ manquant : un corps malformé et un champ absent sont deux faits différents sur
l'appelant, et annoncer l'un pour l'autre envoie l'opérateur corriger la mauvaise chose
(#154, #86).

#### Interface d'administration : révoqué / expiré / valide

Dans l'inventaire des certificats, le badge **« actif » signifiait « non révoqué »**, pas
« valide » : un certificat **expiré** s'affichait en **vert**. Sur un écran de sécurité, un
libellé qui affirme autre chose que le fait peut faire sauter un renouvellement. Trois états
désormais, la révocation primant sur l'expiration.

#### Tests — 47 neufs, et le banc de mutations

`tests/cli/test_pki_setup_mode_explicite.py` (8), `tests/test_pki_ca_setup_sans_defaut.py`
(10) et `tests/test_pki_setup_route_admin_128.py` (29) — un fichier par surface. La propriété
vérifiée n'est pas « un refus se produit » mais **« aucune installation d'AC n'est tentée »**
— un code de retour non nul ne prouverait rien.

| Mutation | Échecs |
| --- | --- |
| ancien défaut `--lab` restauré (CLI) | 3 |
| ancien défaut de domaines restauré (CLI) | 2 |
| garde du mode supprimée (CLI) | 3 |
| garde des domaines supprimée (CLI) | 3 |
| garde du mode écrite `is False` au lieu de `is None` | 5 |
| `strip()` retiré (domaines blancs acceptés) | 1 |
| défaut `allowed_domains` restauré (MCP) | 1 |
| garde des domaines vides supprimée (MCP) | 4 |
| `leaf_ttl` rendu obligatoire (durcissement excessif) | 8 |
| défaut `lab_mode=True` restauré (route HTTP) | 11 |
| `lab_mode` non booléen accepté (route HTTP) | 6 |
| garde des domaines vides supprimée (route HTTP) | 9 |
| le code complète la liste avec un domaine de labo (route HTTP) | 12 |
| corps illisible retombe sur `{}` (route HTTP) | **0 puis 1** |

⚠️ **Une mutation a SURVÉCU au premier jet et il faut le dire** : « corps illisible retombe
sur `{}` ». Indétectable de l'extérieur — la garde sur `lab_mode` renvoie 400 dans les deux
cas, donc la propriété de sécurité tient. Seule la **cause annoncée** changeait. Le test a
été renforcé pour exiger que le message nomme la bonne cause ; le correctif était dans le
test, pas dans le code.

Trois **gardes-fous inversés** verrouillent la propriété réelle plutôt que le symptôme :
aucun domaine de laboratoire ne doit atteindre le réseau sans avoir été tapé, et le code ne
doit jamais compléter la liste fournie. Un test qui vérifierait seulement le refus resterait
vert si un défaut permissif revenait sous un autre nom.

#### Ce qui n'est PAS changé, et pourquoi

- **`setup_pki_ca` garde ses défauts internes.** Ce n'est pas une surface d'appelant : ses
  deux appelants (outil MCP et CLI) passent désormais toujours les valeurs explicitement.
  La classe corrigée est « défaut silencieux sur un paramètre qui décide de la sécurité,
  **à une surface exposée** ».
- **`pki setup --prod --lab` reste « le dernier gagne ».** C'est la sémantique universelle
  des options répétées, et le cas ne relève plus de l'inattention une fois le choix
  obligatoire — il faut taper les deux. Résidu assumé et documenté.
- **Aucun outil de délivrance d'invitation (EAB) n'est ajouté.** La production exige une
  invitation que notre produit ne sait pas émettre : ACME y est donc configuré, strict, et
  inutilisé (aucune ligne ACME dans les journaux du conteneur). Le finir ou l'assumer est
  une décision produit, pas un correctif — et rien ne presse.


## [0.17.0] — 2026-08-19

### Durcissement du PEP mission — #86, findings 4, 5 et 7

⚠️ **MINEURE et non correctif : une configuration qui démarrait hier peut désormais être
REFUSÉE au boot.** `MISSION_JWKS_CACHE_TTL` est borné à `[10,60]` s dès que la validation
mission est active. La production tourne à 60 s : elle n'est pas concernée. Tout autre
déploiement posant une valeur hors bornes devra la corriger.

#### ⚠️ Ce que la fiche #86 réclamait est en grande partie DÉJÀ livré

L'inventaire, refait dans le code et non dans le texte de la fiche : **F1 (config) et F6**
sont livrés (Lot 1, avec leurs tests), **F2** l'est (Lot 2), **F3** l'est (Lot 3), et la
partie « gel de la boucle » de **F4** l'est par #148 (v0.16.1). Il restait le résidu de
F4, F5, et l'arbitrage de F7.

#### 🔴 Le défaut le plus grave n'était pas dans la fiche — trouvé en revue de plan

`secret_consume` fondait **tout** verdict négatif du service de missions en
`mission_inactive`. Or `check_mission_active` distinguait déjà l'indisponibilité
(`service_unavailable`), et le **PEP transport en tenait compte** (503 contre 403) : c'est
`secret_consume` qui était l'exception — exactement l'incohérence entre les deux points
d'application que le finding 2 de #86 dénonçait.

Conséquence : `mcp-agent` lisant tout code ≠ `backend_unavailable` en consommation
incertaine (leur #135), une panne du service de statut **mono-instance** de `mcp-mission`
se lisait chez eux comme une **mission révoquée** ⇒ secret condamné et, depuis leur #49,
arrêt terminal de mission **avec alerte de sécurité**.

⇒ **Troisième occurrence du défaut de #152 et #154 sur un troisième chemin.** Corrigé :
une indisponibilité rend `backend_unavailable` (aucun déballage tenté, re-tentable) ; une
mission réellement hors allow-list reste `mission_inactive`.

#### Taxonomie — un seul cas est un fait sur la mission

| Situation | Motif | Lecture |
| --- | --- | --- |
| 200, état hors allow-list | `mission_inactive` | **fait** attesté par le service de missions |
| 200, état dans l'allow-list | — | mission active |
| **tout non-200** (404 compris), exception réseau | `service_unavailable` | **notre** incapacité à vérifier |

⚠️ **Le 404 est classé indisponibilité, CONTRE l'avis de la revue de plan** qui proposait
« mission inconnue ⇒ inactive ». Nous ne pouvons pas distinguer « la mission n'existe
pas » de « notre URL est fausse » : un proxy mal configuré rend précisément 404 — cas déjà
rencontré en production sur le JWKS de `mcp-mission`. Sous la lecture « inactive », une
erreur de route de **notre** côté condamnerait les secrets de **toutes** les missions.
Sous `service_unavailable`, un `mission_id` forgé obtient un refus re-tentable : le
fail-close tient, seule l'imputation change.

#### F5 — stampede sur le service de statut, mesuré

Onze appelants concurrents sur la **même** mission produisaient **onze appels sortants**
vers un endpoint mono-instance partagé avec l'exécution des missions. Le verrou était pris
pour lire le cache, relâché, puis l'appel HTTP partait hors verrou.

Corrigé par un **single-flight par `mission_id`** :

- ⚠️ **pas** un verrou global tenu pendant l'appel — mesuré : onze missions *différentes*
  se résolvent en 0,30 s, un verrou global les sérialiserait à ~3,3 s et un endpoint lent
  bloquerait **toutes** les missions au lieu d'une ;
- une **tâche** partagée, pas une future portée par le meneur : `mcp-agent` coupe ses
  appels d'outils sur « le budget restant de l'agent », qui peut valoir quelques
  millisecondes. Avec une future, l'annulation d'un seul appelant faisait échouer tous les
  autres. Correction issue de la revue de plan, verrouillée par deux tests d'annulation ;
- registre des appels en vol **auto-nettoyant** (un dictionnaire de verrous par mission ne
  se viderait jamais et déplacerait la fuite d'un cran) ;
- cache **borné** (mesuré avant : 5 000 entrées après 5 000 missions) par purge
  opportuniste des périmées ;
- indisponibilité mise en cache **1 s** seulement, et le cache stocke désormais le
  **motif** : sans lui, une panne ressortait en `mission_inactive_cached`, donc en fait
  sur la mission. Le même mensonge que #152, dans le cache.

#### F4 résiduel — un réglage documenté comme une protection, qui ne fait rien

`MISSION_JWKS_MAX_REFRESH_PER_MIN` était décrit dans `.env.example` et `TECHNICAL.md`
comme un « rate-limit refresh JWKS (anti-DoS) ». Il n'a **jamais** été appliqué : le
validateur l'accepte puis l'ignore. La protection réelle est le throttle des refresh
« kid inconnu » (10 s), le backoff exponentiel, et le déport hors boucle de #148.

⚠️ **Il n'est PAS supprimé, et c'est une divergence assumée avec la revue de plan** qui
demandait son retrait de la surface opérateur : le modèle de configuration refuse les
variables inconnues, donc retirer le champ ferait **échouer le démarrage** de tout
déploiement qui le pose encore — et nous ne pouvons pas lire la configuration de
production. Il est donc conservé, documenté comme inerte partout, et **signalé au
démarrage** s'il est posé (`Settings.reglages_sans_effet()`).

⚠️ **Ne pas le « câbler »** en dérivant `60/valeur` du throttle : ce serait mélanger deux
politiques et retarder l'adoption d'une clé fraîchement rotée.

Et `MISSION_JWKS_CACHE_TTL` est désormais **borné** `[10,60]` : ce n'est pas un réglage de
latence mais la **fenêtre de propagation d'une révocation** de clé de signature. Trop
grand, une clé révoquée reste acceptée ; nul ou négatif, chaque validation peut déclencher
un fetch et fait de nous un amplificateur sur un endpoint mono-instance.

#### F7 — arbitrage de NE PAS corriger, motivé

Le TTL de 300 s du Mission Binding Store ne retarde **pas** une révocation faite par notre
API : les mutations publient l'instantané en mémoire après un `PUT` confirmé, et
`expires_at` est évalué à **chaque** résolution. Il ne retarde qu'une mutation faite hors
de notre API — édition directe du fichier S3, ou une autre réplique. Nous sommes
mono-instance et l'édition directe n'est pas une procédure supportée : **l'exposition est
nulle aujourd'hui**.

Réduire le TTL coûterait des lectures S3 pour un gain nul. Les **déclencheurs** qui
rendraient le compromis réel sont nommés dans le code et renvoyés à **#51** : passage
multi-instance, second writer, ou reconnaissance de l'édition S3 comme procédure
d'exploitation.

#### Restent ouverts, délibérément

- La classification d'un `kid_unknown_or_revoked` **non vérifié** (throttle ou backoff
  ayant empêché la tentative) : attend un contrat de re-tentative avec `mcp-agent`.
- Un client HTTP partagé pour le service de statut : le single-flight supprime déjà le
  coût dominant ; à mesurer avant d'ajouter un cycle de vie.

#### ⚠️ Deux trouvailles de la revue du diff — le lot manquait son propre cas

**Le réglage inerte restait muet quand l'exploitant le posait à sa valeur par défaut.** La
première rédaction comparait la valeur au défaut (`3`) au lieu de vérifier qu'elle avait été
**posée**. Un déploiement écrivant `MISSION_JWKS_MAX_REFRESH_PER_MIN=3` gardait donc la
fausse assurance anti-DoS en silence — exactement le cas que ce lot prétend traiter. Et
**notre propre test verrouillait le trou** : il excluait explicitement la valeur `3`.
Corrigé par `model_fields_set`, qui distingue « fourni par une source » de « non fourni ».

**Le test de branchement ne prouvait pas le signalement.** Il espionnait l'appel à
`reglages_sans_effet()` et s'arrêtait là : il passait même si le résultat était ensuite
ignoré et qu'aucun avertissement n'atteignait le journal. Il vérifie désormais les deux.

**Contrôles négatifs de la revue, pour mémoire** : aucune course sur le single-flight (la
création et l'insertion sont atomiques sous verrou), aucun auto-interblocage (la tâche
enfant ne démarre qu'après la sortie du verrou), aucune fuite quand `cache_ttl <= 0`,
`shield` démontré nécessaire par les tests d'annulation, borne du cache non
auto-référentielle, et le 404 re-tentable reste fail-close sans oracle exploitable — un
appelant ne peut pas atteindre ce contrôle sans un JWT ES256 valide.

**Tests** : 1595 verts, 33 ignorés. **15 mutations, toutes détectées** — dont trois
instructives : une a d'abord **survécu** et révélé un garde-fou **auto-référentiel**
(l'assertion de borne du cache se comparait à la constante qu'elle devait protéger, donc ne
pouvait pas échouer quand on relevait cette constante) ; les deux autres verrouillent
désormais les trouvailles de la revue (retour au critère « différent du défaut », et un
résultat consulté mais jamais journalisé).

## [Non publié]

### Documentation — deux limites qui n'étaient écrites nulle part

⚠️ **Aucun changement de comportement.** Documentation et description d'outil seulement,
donc pas de version dédiée : ces textes partiront avec le prochain lot fonctionnel.

⚠️ **Et la première rédaction de ces textes portait elle-même une affirmation fausse**,
trouvée en revue adversariale : « il reste valide jusqu'à ce que son propriétaire le
réécrive ou le supprime » laissait croire que nos deux verbes suffisent à invalider un
credential. **Ils ne suffisent pas** : `secret_write` **ajoute une version** (la précédente
reste lisible par son numéro, `read_secret(..., version=N)`), et `secret_delete` retire les
versions **du coffre**, pas le mot de passe de la machine ni la clé chez son fournisseur.
Seule une révocation ou rotation **coordonnée chez l'émetteur** invalide effectivement un
credential externe. Corrigé aux trois surfaces avant publication.

**1. `ttl_seconds` ne borne pas la vie du secret livré — #156.** Ni le README ni le contrat
ne le disaient, et la lecture naturelle allait dans le mauvais sens : `mcp-mission` a posé
la question le 19/08, ce qui prouve que le malentendu était atteignable. L'enveloppe est à
usage unique et meurt à son TTL (borné entre 60 s et 3600 s — `mcp-mission` se plafonne à
300 s, ce qui est **son** choix et non notre plafond) ; le secret KV livré n'a **aucune
expiration ni rotation**. Si une mission meurt après un déballage, la durée d'exposition
n'est bornée par personne de notre côté.
Écrit aux trois endroits qui compte : README FR/EN, et la **description de l'outil
`secret_wrap`** — c'est elle que l'appelant lit réellement, pas notre README.

**2. « log warning, continue » était trompeur depuis #154.** Les README FR/EN annonçaient
qu'en `ENFORCE_MISSION_TOKEN_VALIDATION=false` un échec de validation était « journalisé,
puis on continue ». C'est faux à deux titres : la consommation est ensuite **refusée** au
registre (`mission_id` vide ⇒ clé composite sans correspondance), et depuis v0.16.3 ce qui
exprime **notre propre incapacité** est refusé **dans les deux postures**.
⇒ Nous avions corrigé le code sans corriger la phrase qui l'annonçait — la même faute que
#154 réparait, une couche plus haut.


## [0.16.3] — 2026-08-18

### En production, une indisponibilité du service de clés s'annonçait « opération inconnue » — #154

⚠️ **Le correctif de #152 ne couvrait que le chemin dormant.** Il vivait sous la garde
`if enforce:`, alors que la production tourne `ENFORCE_MISSION_TOKEN_VALIDATION=false`
jusqu'à l'activation du PEP (#47). Le chemin **vivant** n'était pas corrigé.

**Mécanisme mesuré** (chaîne réelle, registre contenant une entrée `active`) : la
validation du `mission_token` échoue, `mission_id` reste **vide**, la clé composite
`(operation_id, "")` ne correspond à aucune entrée, et le refus sortait en
**`not_found`** — *« Wrap introuvable (opération inconnue ou expirée) »*.

| Motif | Avant (`ENFORCE=false`) | Après |
| --- | --- | --- |
| `jwks_unavailable` | ⚠️ `not_found` | **`backend_unavailable`** |
| `misconfigured_expected_aud` | ⚠️ `not_found` | **`misconfigured`** |
| `invalid_signature`, `token_expired`, … | `not_found` | `not_found` (inchangé — voir #47) |

⚠️ **`not_found` était pire que le `jwt_invalid` corrigé par #152.** `jwt_invalid`
nommait au moins le bon domaine ; `not_found` **affirme un fait positif et faux sur
l'opération de l'appelant** et envoie chercher un défaut de provisionnement inexistant.
`mcp-agent` lisant tout `error_type` autre que `backend_unavailable` en consommation
incertaine (leur #135), une indisponibilité de l'endpoint JWKS **mono-instance** de
`mcp-mission` produisait chez eux une **fausse alerte de sécurité et un arrêt terminal
de mission** (leur #49).

### La règle posée

> « Je n'ai pas pu vérifier » est un fait sur **notre** capacité, pas une décision de
> politique. `enforce` arbitre si un jeton **invalide** est fatal ; il n'arbitre pas si
> nous disons la vérité sur le motif du refus.

Les motifs qui nomment notre propre incapacité — `jwks_unavailable` et
`misconfigured_expected_aud` — sortent donc de la garde `enforce`. Les autres, qui sont
des **faits sur l'appelant** (jeton forgé, périmé, audience fausse), restent en place :
les transformer en refus explicite changerait la **posture** `ENFORCE=false`, ce qui
relève de #47 et non d'un correctif de libellé.

**Aucun appelant conforme ne perd un succès** : `secret_wrap` refuse un `mission_id`
vide (`is_safe_id` exige 1 caractère, les espaces sont rejetés) et
`get_by_composite_key` compare par égalité stricte sans joker — aucune entrée produite
par le chemin de création ne peut donc être sélectionnée avec un `mission_id` vide. Le
court-circuit retire un mensonge, pas un chemin. Deux tests verrouillent cette prémisse.

> ⚠️ Nuance relevée en revue : `WrapRegistry.load()` ne valide pas les champs de chaque
> entrée, donc une entrée **corrompue ou déposée à la main** avec un `mission_id` vide
> resterait sélectionnable. Le court-circuit ne l'affaiblit pas — il **empêcherait** une
> consommation anormale sur une telle entrée. La formulation « jamais » a été corrigée
> ici en conséquence.

### Deux chemins de plus, trouvés en revue adversariale

Le hissage initial laissait derrière lui deux cas de **même nature**. Les deux sont
corrigés dans ce lot :

- **Le validateur non initialisé** (`validator is None` — lifecycle échoué, ou
  `MISSION_JWKS_URL` ajoutée à chaud) journalisait puis continuait sous `ENFORCE=false`,
  donc `not_found`. C'est la branche **sœur** de celle corrigée : la même erreur, commise
  en la corrigeant — lire une branche sans lire ce qui l'entoure. Et le cas est **plus
  probable** que la panne JWKS, puisqu'il découle d'un échec de démarrage, donc
  persistant. Refus désormais dans les deux postures, en `misconfigured`.
- **Un `kid` inconnu pendant une panne du JWKS.** `JWKSCache.get_key()` déclenche un
  refresh forcé sur un `kid` absent, et **avalait l'échec** de ce refresh : le refus
  sortait en `unknown_kid` — « jeton non authentique ». Un jeton **légitime** issu d'une
  rotation pendant une panne était donc annoncé comme forgé. L'indisponibilité est
  désormais propagée.
  ⚠️ **Seulement quand le refresh a été TENTÉ.** S'il ne l'a pas été (throttle anti-DoS,
  backoff, cache jamais peuplé), le refus reste `unknown_kid` **délibérément** : sinon un
  appelant présentant des `kid` forgés obtiendrait une classe re-tentable au lieu d'un
  refus — une protection retournée en invitation. Un test verrouille cette garde.
  ⇒ Ce lot **réduit** ce que recouvre `kid_unknown_or_revoked` sans le déplacer :
  l'arbitrage ouvert avec `mcp-agent` porte désormais sur le seul cas « non tenté ».

### ⚠️ Pourquoi le défaut avait survécu — un test vert le verrouillait

Le test qui « couvrait » la posture de production affirmait `res["status"] == "ok"`,
mais `res` sortait d'un mock de `consume_wrap_secret` rendant **toujours** `ok`. Le vert
venait du mock, et la docstring en déduisait que « le déballage continue » — d'où
l'affirmation, publiée, que le défaut de #152 n'était pas atteignable en production.

Réparé : `tests/test_indispo_hors_enforce_154.py` mesure la **chaîne réelle** sans mock
de consommation, avec un **témoin** (un jeton vérifié doit consommer l'enveloppe et
faire passer l'entrée `active` → `consumed`) sans lequel aucun refus ne prouverait autre
chose qu'un harnais cassé.

### Aussi

- Le journal opérateur disait `« JWT invalide ignoré — reason=jwks_unavailable »` :
  la même confusion, dans la trace. Il annonce désormais le refus attendu en aval.
- L'étroitesse de `backend_unavailable` est vérifiée aussi **sans enforcement** —
  vocabulaire des motifs énuméré depuis le code (dérivation AST), jamais recopié.

**Tests** : 1551 verts, 33 ignorés. **8 mutations, toutes détectées.** Revue adversariale : NO-GO initial, 2 trouvailles majeures et 2 mineures retenues, 1 majeure écartée avec argument (voir #154).

## [0.16.2] — 2026-08-17

### Une indisponibilité du service de clés n'est plus annoncée comme un jeton invalide — #152

Quand `secret_consume` ne peut pas vérifier l'identité de mission **parce que le
service de clés est hors d'atteinte**, il rendait `error_type: "jwt_invalid"`.

C'est la discipline #78 violée : fondre **un FAIT** sur l'appelant (« le jeton est
invalide ») et **une IGNORANCE** de notre côté (« nous n'avons pas pu le vérifier »)
sous un même nom. Le refus précède tout effet OpenBao — il appartient donc
exactement à la classe publiée **`backend_unavailable`** : aucun effet tenté,
enveloppe intacte, re-tentable.

⚠️ **L'enjeu vient de leur contrat, pas du nôtre.** `mcp-agent` a publié sa table de
décision : tout `error_type` autre que `backend_unavailable` vaut **consommation
incertaine** ⇒ secret condamné, et depuis leur lot #49 **arrêt terminal de mission
avec alerte de sécurité**. Sous `jwt_invalid`, une simple indisponibilité de
l'endpoint JWKS **mono-instance** de `mcp-mission` se lisait chez eux comme un
**incident d'intégrité de credential**. C'est eux qui ont posé la question ; nous
n'avions pas vu la conséquence.

Couvre `JWKSUnavailable` (endpoint injoignable, gelé au-delà du délai, backoff, 304
sans cache, document malformé) **et** `bad_jwk`, que le mapping traduit vers le même
motif : dans les deux cas la clé publique est hors d'atteinte.

⚠️ **`backend_unavailable` n'est PAS élargi au-delà de « aucun effet tenté ».** Sa
valeur pour les trois équipes vient de son étroitesse. Neuf motifs de refus sont
verrouillés par test dans leur classe d'origine, et la mutation qui en fait un
fourre-tout fait rougir huit tests.

⚠️ **Cas laissé ouvert délibérément** : `kid_unknown_or_revoked` reste `jwt_invalid`.
Il recouvre deux situations que nous ne distinguons pas encore — un jeton forgé
(FAIT) et une rotation récente que le throttle anti-DoS nous a empêché d'aller
vérifier (IGNORANCE). Le second est détectable chez nous, mais l'arbitrage appartient
aussi à l'appelant : avis demandé à `mcp-agent`, non reçu à ce jour. Un test
verrouille l'état actuel pour qu'un déplacement futur soit un **choix** et non un
effet de bord.

### ⚠️ Correction d'un recensement FAUX publié le 17/08

Nous avons publié — README FR et EN, CHANGELOG de v0.16.1, commentaires de #148 et
corps de #152, et deux messages aux équipes — que **`secret_wrap` faisait partie des
sites de validation du `mission_token`**.

**C'est faux.** Mesuré : `secret_wrap` **n'a aucun paramètre `mission_token`** et
**n'appelle aucun validateur**. Il ne touche jamais le cache JWKS. Les sites sont
**trois**, pas quatre : le PEP transport, `secret_consume`, et l'endpoint admin de
rechargement.

Origine de l'erreur, écrite pour qu'elle ne se répète pas : un `grep` sur
`ENFORCE_MISSION_TOKEN_VALIDATION` trouve un bloc dans `secret_wrap` dont le
commentaire mentionne `secret_consume`. Nous en avons **inféré** un bloc de
validation. C'en est un de **configuration** et de complétude de binding.

⇒ C'est la deuxième fois dans la même journée que nous **inférons au lieu de
mesurer** sur cette surface : la première nous avait fait annoncer à tort à
`mcp-agent` que le lien mission↔secret n'était pas imposé. Deux tests verrouillent
désormais le fait : `secret_wrap` ne prend pas de `mission_token`, et n'appelle
aucun validateur. S'il en appelait un un jour, il deviendrait soumis au déport de
#148 **et** au mapping de #152 — le banc le dira.

### Ce que ce lot ne change pas

Rien en production. Le défaut n'était atteignable qu'en mode
`ENFORCE_MISSION_TOKEN_VALIDATION=true`, et la production tourne à `false` : l'échec
de validation y est journalisé puis **ignoré**, le déballage continue. Trois tests
verrouillent cette conduite inchangée — non pour l'approuver, mais parce que la
changer serait un autre lot (#47/#86).

### Compatibilité

Aucun appelant conforme ne casse. Un refus qui portait `jwt_invalid` porte désormais
`backend_unavailable` **dans le seul cas où nous n'avons pas pu vérifier** — c'est
précisément la correction demandée par `mcp-agent`, dont la table traite déjà ce
code. Aucune signature, aucun autre code, aucun champ ne change.

## [0.16.1] — 2026-08-17

### Le dernier appel réseau synchrone du chemin d'authentification est fermé — #148

Le rafraîchissement du cache JWKS était un `httpx.get` **synchrone**, atteint
depuis une coroutine sans `await`. Pendant sa durée, l'unique thread qui sert
**toutes** les requêtes était monopolisé — sonde de santé comprise. Même classe de
défaut que #110, sur un autre transport.

**Ce n'était pas une hypothèse.** Relevé en production le 17/08 par la plateforme,
sur le conteneur actif : un `GET` vers l'endpoint JWKS interne de `mcp-mission`
répond en **117,2 ms**. C'était donc 117 ms de gel du service entier par
rafraîchissement, au plus une fois par TTL de 60 s.

**Trois chemins y menaient, tous des coroutines**, et les trois sont désormais
déportés hors boucle par `run_blocking` (la primitive du lot 2 de #110) :

| Site | Ce qui l'active |
| --- | --- |
| PEP transport (`AuthMiddleware._validate_mission_jwt`) | `MCP_AUTH_MODE ∈ {jwt, dual-stack}` |
| **`secret_consume`** | ⚠️ la simple **présence** de `MISSION_JWKS_URL` |
| `POST /admin/api/auth/jwks/reload` | appel opérateur — le plus lent, il force le fetch |

⚠️ **Le troisième site est le plus important, et il a failli être manqué.** En
production, `MCP_AUTH_MODE=bearer` et `ENFORCE_MISSION_TOKEN_VALIDATION=false` :
**aucune des deux portes d'authentification n'est active**, et une lecture par ces
deux réglages aurait conclu « défaut latent, rien à faire ». Or la validation de
`secret_consume` se déclenche sur la **seule présence** de l'URL JWKS — et c'est le
chemin qui déballe **chaque enveloppe de credentials**, `mcp-agent` y présentant un
`mission_token` ES256 à chaque appel (confirmé par eux le 17/08).

### ⚠️ Le déport seul aurait recréé #110 sur l'autre transport

Relevé en revue adversariale, sur un **NO-GO** du premier correctif — et c'est la
partie la plus importante de ce lot.

Déporter sans borner consommait un thread de l'exécuteur **partagé avec les
offloads S3** (#122/#123) par requête mission : chacune prenait un thread, *puis*
attendait le verrou du cache. Sur un endpoint JWKS lent ou tombé, N requêtes
mission y auraient attendu en thread et **les lectures S3 auraient fait la queue
derrière**. On aurait réparé la famine sur un transport en la recréant sur l'autre.

Les résolutions déportées sont donc sérialisées par un **verrou asyncio** porté par
le cache : au plus **un** thread engagé, les autres attendent côté boucle — ce qui
ne coûte aucun thread.

⚠️ **La sérialisation est INCONDITIONNELLE, après DEUX tentatives ratées de
l'éviter.** Les deux voulaient épargner le verrou sur cache frais en constatant
d'abord la fraîcheur depuis la boucle. Les deux étaient fausses **pour la même
raison** : `JWKSCache._lock` est **tenu pendant tout le fetch HTTP**. Donc *toute*
interaction avec ce cache depuis la boucle — **même une lecture** — peut s'y
bloquer, et recréait exactement le gel que ce lot ferme. Une requête rafraîchissait
en thread pendant que la suivante gelait la boucle sur le verrou.

⇒ **Il n'existe pas de « coup d'œil gratuit » sur ce cache.** La seule règle sûre
est : on n'y touche jamais depuis la boucle. Un commentaire le grave à l'endroit où
la tentation reviendra.

Coût de cette inconditionnalité, mesuré et assumé : les validations mission se
sérialisent entre elles. Sur cache frais, chaque tenue vaut une vérification de
signature ES256 — quelques centaines de microsecondes. Pendant un rafraîchissement,
les autres attendent le temps du fetch (117 ms) — mais **côté boucle**, sans occuper
de thread, et sans empêcher `/health`, les outils non-mission ni les lectures S3
d'être servis. C'est exactement l'objet de #148.

⚠️ Troisième défaut, trouvé par le banc et non par la revue : le point d'entrée
reçoit un cache **`None`** quand le validateur existe sans cache (lifecycle non
passé, URL ajoutée à chaud). Le déréférencer transformait un refus explicite de
l'appelé en `AttributeError`, avalée par son `except` générique — donc en
**validation silencieusement sautée**. Traité : on déporte sans verrou, la décision
reste chez l'appelé.

### Ce qui n'a PAS changé, et c'était la condition

⚠️ **`JWKSCache` n'est pas réécrit.** Il est déjà thread-safe (`threading.Lock`) :
plusieurs threads d'exécuteur s'y sérialisent, **un seul** fait le fetch, les
autres trouvent l'instantané frais. C'est ce qui borne à la fois l'usage du pool de
threads et la charge sur l'endpoint de `mcp-mission`. Un test le verrouille avec
huit validations concurrentes et exige **un seul** fetch.

Trois protections distinctes sont intactes, et les déplacer aurait transformé un
gel en martèlement de leur endpoint :

- le **fail-close** — un cache périmé n'est JAMAIS servi ;
- le **backoff** exponentiel avec jitter sur échec de fetch ;
- le **throttle « kid inconnu »** — au plus un rafraîchissement par fenêtre de
  10 s, quel que soit le volume de `kid` inconnus reçus.

⚠️ **`MISSION_JWKS_CACHE_TTL` n'est pas un réglage de latence, et il n'est pas
touché.** `mcp-mission` nous a appris le 17/08 qu'une clé **révoquée disparaît de
leur JWKS** : ce TTL est donc la **fenêtre de propagation d'une révocation de clé
de signature**. Il vaut 60 s, cinq fois plus strict que le `max-age=300` qu'ils
publient. Rendre l'appel non bloquant donne envie de l'allonger pour espacer les
appels — **ce serait allonger la fenêtre de révocation.** Ne pas le faire.

### Ce que le lot ne ferme pas

L'activation du PEP mission JWT (#47, #86) reste ouverte : en production, un jeton
mission **invalide** sur `secret_consume` est journalisé puis **ignoré**. La
médiation anti-confused-deputy est donc exercée mais **pas appliquée** — posture
pré-activation, documentée, et divulguée à `mcp-agent` le 17/08 parce qu'ils
comptaient dessus.

⚠️ **Contrainte d'ordre établie par ce lot** : activer le PEP **avant** ce
correctif aurait transformé un hoquet de 117 ms en dépendance dure — toute
indisponibilité de l'endpoint **mono-instance** de `mcp-mission` refusant *chaque*
déballage de secret. C'est fait dans le bon ordre.

### Vérification

11 tests dédiés. **Cinq mutations injectées, cinq détectées** : remettre l'appel
synchrone à chacun des trois sites fait rougir les tests de ce site — et fait
**pendre** le banc quand la boucle gèle, ce qui est la démonstration la plus
directe du défaut. Les deux autres retirent la borne d'exécuteur et court-circuitent
le constat de fraîcheur.

⚠️ **Le test de la borne a été refait DEUX fois, chaque fois parce qu'il était vert
sans rien prouver.** Version 1 : il affirmait la borne avec un fetch **instantané** —
il ne mesurait ni les threads bloqués ni l'exécuteur. Version 2 : fetch bloquant,
mais son témoin était un drapeau relu **après coup** ; une boucle gelée dix secondes
puis débloquée par le délai de garde du faux fetch le posait quand même. Il durait
10,16 s au lieu de 0,15 s et passait.

Version retenue : le témoin est **échantillonné depuis le thread, à l'instant où il
sort** — le patron `Barriere` de #122, que ce test n'appliquait pas. Il ne dit plus
« le scénario a fini par tourner » mais « le scénario avait déjà libéré quand le
fetch est sorti », ce qui exige une boucle vivante. La mutation qui consulte le
cache depuis la boucle — le défaut relevé en revue — le fait désormais rougir ; elle
échappait aux deux versions précédentes.

⚠️ La durée du banc est elle-même un signal : **1,1 s** contre **11 s** avant
correction du défaut. Un banc qui traîne dix secondes sur un stub à délai de garde
dit qu'une boucle attendait.

⚠️ Aucun test ne mesure une **durée**. Deux formes seulement : un **ORDRE** (le
témoin est échantillonné depuis le thread encore bloqué, harnais `Barriere` de
#122) et une **IDENTITÉ DE THREAD** (le fetch ne doit pas s'exécuter dans le thread
de la boucle). Chaque cas vert exige que le fetch ait réellement eu lieu — sans
appel, il n'y a pas d'identifiant à comparer et l'assertion tombe.

⚠️ Première rédaction du banc corrigée : elle utilisait un jeton factice `"a.b.c"`,
rejeté au parsing d'en-tête **avant** d'atteindre le cache. Le fetch n'avait donc
jamais lieu et le témoin attendait indéfiniment. Les jetons sont désormais de
**vrais JWT ES256** signés par une clé P-256 générée dans le test.

### Compatibilité

Aucun appelant conforme ne casse : aucun code d'erreur, aucune signature, aucun
champ de réponse ne change. Le seul effet observable est qu'une lenteur du JWKS ne
gèle plus que la requête concernée, au lieu du service entier.

## [0.16.0] — 2026-08-17

### Une erreur de stockage mal lue ne rend plus une clé rejouable — #149

Notre garantie publiée est qu'une clé de provisionnement est à **usage unique,
sans condition** — c'est celle sur laquelle `mcp-mission` a bâti son guichet de
credentials. Elle ne vaut que ce que vaut l'instantané que la garde interroge.

Le registre concluait « le fichier n'existe pas encore » dès que le **texte** de
l'erreur de lecture *contenait* « 404 » ou « NoSuchKey » : un identifiant de
requête, un port, un 404 émis par un intermédiaire. Il repartait alors **vide en
se déclarant fiable**. Le refus fail-close de v0.15.0 ne se déclenchait pas — il
ne lit que ce drapeau — la clé déjà engagée paraissait vierge, et un second
secret pouvait être créé dessus.

Désormais, seule une absence **authentifiée par le champ d'erreur structuré**
(`botocore.ClientError` avec `Error.Code == "NoSuchKey"`) vide le registre. Toute
autre erreur est une panne : la création est refusée avec `backend_unavailable`,
sans qu'aucune écriture ni aucun appel OpenBao soit tenté.

**Le défaut avait une seconde porte**, fermée dans le même lot après un NO-GO de
revue adversariale sur le premier correctif. `load()` faisait
`data.get("wraps", [])` : un GET qui **réussit** en renvoyant un JSON valide sans
la clé `wraps` — un `{}`, un corps tronqué, un corps de remplacement d'un
intermédiaire — produisait exactement le même effet, **sans qu'aucune erreur ne
soit levée**. Le document est désormais validé (`{"wraps": [...]}` à la racine)
**avant toute mutation d'état** : un document abîmé ne touche jamais l'instantané
mémoire, et la lecture est classée comme panne. C'est la seconde moitié de la
règle #69, que `PolicyStore` énonce déjà mot pour mot. Un registre
**légitimement** vide (`{"wraps": []}`, l'état du fichier après une première
écriture sans entrée) se charge normalement.

⚠️ **C'est une règle déjà tranchée, que ce magasin n'avait jamais reçue.** La
revue #69 (BLOQUANT-2) l'a établie et les trois magasins d'autorisation
l'appliquent depuis. Le registre wrap était le seul des quatre à en être resté au
test par sous-chaîne.

⚠️ **Observé avant d'être corrigé.** Le 16/08, le faux S3 du banc de qualification
plateforme renvoyait un `404` générique au lieu de `NoSuchKey`. Les trois magasins
stricts ont refusé — c'est ce qui a bloqué la qualification de v0.15.0 et permis
de trouver la cause réelle. Le registre wrap, lui, est passé. Le contraste était
la démonstration du défaut ; il a d'abord été lu comme un détail de banc.

⚠️ **Le premier démarrage reste nominal**, et c'est le risque qu'il fallait ne pas
prendre : rien ne crée le fichier de registre, il naît de la première écriture.
Un `NoSuchKey` authentique vaut donc toujours « registre vide ». L'option d'un
`HEAD` de confirmation a été écartée comme inutile — les trois magasins stricts
fonctionnent en production, ce qui démontre que le stockage nomme correctement
l'absence.

⚠️ **Effet de bord assumé** : derrière un intermédiaire non conforme, le guichet
refusera au lieu de passer silencieusement. C'est la conduite correcte, et c'est
déjà celle des trois autres magasins.

Le contrat publié est corrigé sur un point où il **sous-déclarait** le défaut : il
annonçait « la perte du fichier de registre » comme contournement, alors qu'il
suffisait d'une erreur mal lue, sans aucune perte de donnée.

### La volumétrie du registre est mesurée — sans que la sonde en devienne une cause — #146

Le registre n'a ni purge ni écriture incrémentale : il est réécrit
**intégralement** à chaque transition, donc le coût d'une opération croît avec le
nombre d'entrées. Nous n'avions aucun chiffre, et la montée en charge des missions
à fan-out est devant nous — mesurer après serait découvrir le nombre une fois
qu'il a grossi.

`system_health` publie donc, pour le registre wrap : `entries` (nombre d'entrées)
et `last_write_bytes` (poids du dernier corps écrit, `null` tant qu'aucune
écriture n'a eu lieu depuis le démarrage).

⚠️ **`last_write_bytes` est relevé à l'écriture, jamais calculé à la demande.**
Sérialiser le registre à chaque appel de supervision ferait de la sonde une cause
du problème qu'elle mesure. Un test verrouille cette propriété : la sonde ne doit
appeler aucune sérialisation. `entries` est un simple décompte en mémoire.

Aucun arbitrage de purge n'est engagé ici. Le critère d'entrée de #146 reste
inchangé : la purge se dimensionne sur un **état** (mission terminée ET
réconciliée), pas sur une durée, et rien ne sera codé avant que `mcp-agent#122`
soit en production.

### Compatibilité

Aucun appelant conforme ne casse. `backend_unavailable` est déjà au contrat comme
refus **sans effet et re-tentable**, et les deux champs de `system_health` sont
additifs.

### La règle ne vit plus qu'à un seul endroit — et un cinquième site corrigé

Le premier jet de ce lot laissait le prédicat d'absence **recopié dans quatre
magasins**, avec un test d'alignement pour surveiller la divergence. C'était le
mauvais arbitrage, pour une raison simple : **#149 est né de cette duplication
même**, et un test qui énumère les magasins connus ne protège pas du scénario qui
a produit le défaut — un magasin de PLUS, écrit plus tard, sans la règle.

La règle vit désormais dans `s3_client.objet_absent()`, appelée par les cinq
sites. Deux tests portent sur une propriété de l'**arbre source**, pas sur une
liste de classes, et couvrent donc le magasin qui n'existe pas encore :

- aucun fichier de `src/` ne peut réintroduire `"NoSuchKey" in str(...)` ;
- le prédicat n'a **qu'une seule définition**, et elle est dans `s3_client.py`.

⚠️ **Ce balayage a révélé un cinquième site**, hors des magasins : le
téléchargement des **clés d'unseal** d'OpenBao portait encore le test par
sous-chaîne. Une panne de stockage y devenait « pas de clés sur S3 ».

**Aucune destruction de données n'était possible** : la garde #121
(`_openbao_data_exists`) refuse durement d'initialiser quand le coffre contient
des données, et la restauration depuis S3 échoue déjà en fail-close en amont. Le
dégât était un **diagnostic faux** — on annonçait à l'exploitant « clés
introuvables, restaurez l'objet chiffré » alors que la cause réelle était une
erreur de stockage passagère, ce qui l'envoyait réparer la mauvaise chose. Une
panne remonte désormais telle quelle.

Les mappings d'erreurs **OpenBao** (`"404"` sur `str(e)` dans les chemins de
révocation et de consommation) sont **inchangés** : ils portent sur une autre
surface d'erreur, et #78 les a déjà arbitrés.

## [0.15.0] — 2026-08-16

### Un stockage lent ne gèle plus le service — dernier lot de #110

Un appel S3 bloquant ne gelait pas une requête, il gelait **tout le service**,
sonde de santé comprise : 488 s mesurées en production. Le lot 1 (v0.10.1) a
borné ces appels, le lot 2 (#122) en a sorti cinq de la boucle. Restaient les
**magasins d'autorisation** — les plus fréquents, interrogés à chaque requête
authentifiée, et jusqu'ici appelés depuis des gardes **synchrones**.

**Le point de décision lit désormais la mémoire, jamais le réseau.** Les gardes
lisent un instantané publié ; quatre tâches de fond le renouvellent hors boucle,
à la moitié du TTL, et toutes les 10 s après une panne.

⚠️ **Le fail-close de #86/#69 est conservé À L'IDENTIQUE, avec son périmètre
d'origine** : sur le **Policy Store**, le **Mission Binding Store** et les
décisions du **registre wrap**, un instantané périmé au-delà de son TTL ne sert
plus aucune décision. Seul le mécanisme change — on le **constate** au lieu de le
découvrir en tentant un GET, si bien que le refus ne dépend plus de la
joignabilité de S3.

⚠️ **Le Token Store fait exception, et c'est inchangé** : `available` y reste
DIAGNOSTIQUE, `get_by_hash` ne le consulte pas, et un instantané périmé continue
donc d'authentifier. Fermer ce résidu (deny-all bearer pendant une panne S3) est
un chantier séparé, hors périmètre ici comme il l'était en #86.

### Deux horloges là où il n'y en avait qu'une

`_cache_time` portait deux rôles : dater l'instantané servi, et brider les
re-tentatives après une panne. Une panne les mettait en désaccord — repousser la
date pour ne pas marteler S3 **rajeunissait aussi** un instantané jamais
rechargé. Un magasin en panne restait donc « frais » indéfiniment.

`Freshness` les sépare (`last_success` / `last_attempt`) et passe en temps
**monotone** : un recul d'horloge murale ne peut plus rajeunir un état périmé.
Les expirations **métier** (`expires_at`, rétention de purge) restent en UTC
mural — ce sont des dates, pas des durées.

### Copy-on-write sur les trois magasins d'autorisation

Une mutation construit un candidat, le persiste, et ne publie qu'après
confirmation du PUT. Une garde synchrone — qui ne prend aucun verrou — ne peut
donc plus observer une policy créée mais non persistée, ni une suppression que
l'échec du PUT annulera. Les rollbacks disparaissent, et avec eux le risque d'en
oublier un : c'était le cas le plus critique du Token Store, dont le code portait
le commentaire « une révocation non persistée est CRITIQUE ».

⚠️ **Le registre wrap n'en a délibérément PAS** — condition n°3 de l'arbitrage
de #123. Aucun lecteur synchrone ne l'interroge, et la publication-après-PUT y
détruirait un acquis de v0.14.1 : `mark_entries_revoked` conserve volontairement
en mémoire une révocation confirmée mais non inscrite. Ses cinq points d'entrée
sont en revanche exécutés **en entier** hors boucle, sous le verrou du magasin —
appels OpenBao compris.

### Drainage à l'arrêt

Les rafraîchisseurs sont arrêtés **puis** les verrous drainés, avant le
scellement et l'upload final. L'ordre compte : drainer d'abord laisserait un
rafraîchissement démarrer pendant le drainage, et son écriture atterrirait après
l'archive.

### Observabilité

`system_health` porte la fraîcheur de chaque magasin (`stores`, et
`stores_stale` s'il y a lieu), et passe en `degraded` si l'un est périmé. Sans
cela, un rafraîchisseur mort ne se verrait qu'au premier refus.

### Deux affirmations fausses corrigées au passage

- **Le journal d'audit ne se synchronise PAS sur S3.** `audit.py` l'annonçait
  (« synced S3 avec le volume OpenBao »), recopié dans la documentation
  technique. L'archive ne couvre que `openbao_data_dir` (`/openbao/file`) ;
  `openbao-logs` est un volume DISTINCT. La trace survit à un redémarrage du
  conteneur, pas à la perte de l'hôte — et ce n'est pas la même promesse.
- **`MissionBindingStore.force_reload` n'a aucun appelant** en production (le
  `force_reload` de l'API admin porte sur le cache JWKS). Sa docstring laissait
  croire l'inverse et masquait qu'elle reste un appel S3 synchrone.

### ⚠️ Un appel réseau synchrone SUBSISTE, hors périmètre

Le rafraîchissement du cache JWKS (`mission_jwt.py`) fait un `httpx.get`
**synchrone**, déclenché depuis la validation d'un jeton mission, elle-même
appelée sans `await` dans la coroutine du PEP. Même classe de défaut que #110,
sur un chemin aussi chaud — mais **borné** par son délai d'attente (5 s) et son
backoff, là où les appels S3 d'origine cumulaient plusieurs minutes. Relevé en
préparant ce lot, déclaré au contrat publié, **non corrigé** : #123 ne porte que
sur les magasins S3.

### Ce que ce lot NE ferme pas

La race d'écriture multi-instance (#13/#51). Le dernier écrivain gagne toujours,
et un rafraîchissement de fond **élargit** la fenêtre pendant laquelle deux
instances peuvent diverger sans le savoir. Ne pas présenter ce lot comme
« magasins multi-instance sûrs ».

### Vérification

- **1508 tests collectés — 1475 passent, 33 ignorés** (ces derniers exigent un
  OpenBao réel), dont 27 nouveaux sur le rafraîchissement, et aucune tâche
  asyncio laissée vivante en fin de suite
- **16 mutations injectées, 16 détectées** — dont le retrait de l'offload, le
  retour à l'horloge murale, un échec qui rajeunit l'instantané, la publication
  avant confirmation du PUT, le retrait des gardes fail-close de création et de
  consommation, et le retrait de la barrière de fermeture d'arrêt
- ⚠️ **Quatre trous fermés grâce aux mutations ou à la revue, invisibles à la
  relecture** : un test « aucun appel S3 » qui levait une `AssertionError` — que
  `load()` avalait dans son `except Exception`, si bien qu'il restait vert alors
  que la garde rechargeait ; l'absence totale de couverture sur la fenêtre
  copy-on-write d'une révocation de token ; la sortie `partial_revocation`
  annoncée comme couverte sans l'être ; et la condition n°4 publiée que rien ne
  verrouillait

### La limite de durabilité est ARBITRÉE — elle n'est plus en attente

Le critère porté à #123 par #140 était binaire : soit un effet OpenBao confirmé
survit à une panne du support suivie d'un redémarrage, soit le lot **déclare
l'impossibilité et la publie**. La seconde branche est retenue.

**Le second support ne sera pas construit.** Le tenir exigerait un journal local
rejoué en réconciliation avant de resservir le registre — mécanisme inexistant,
à greffer sur le lot qui réécrit les points d'application des autorisations, et
qui resterait **local à l'instance**, perdu avec l'hôte. Le rapport risque /
bénéfice ne le justifie pas : dans le sous-cas où l'effet est bien intervenu
sans que le nouvel état soit publié, le registre **peut** rester plus prudent
que l'état que le serveur tient pour acquis — il annonce vivante une enveloppe
qu'il tient pour révoquée — et l'appelant reçoit alors le signal au moment même
où cela se produit.

⚠️ Le contrat publié ne dit plus « nous ne pouvons pas encore », il dit
**« nous avons décidé de ne pas »**. Un appelant ne doit pas dimensionner son
contrat en supposant que cette limite disparaîtra.

**Cet arbitrage seul ne change aucun comportement** — c'est une décision écrite,
livrée d'abord en documentation. Il est publié avec 0.15.0 parce qu'il n'avait pas
encore été tagué, non parce qu'il exigerait une version.

### Deux affirmations trop catégoriques corrigées au contrat publié

Relevées en revue adversariale sur le texte même de la limite :

- « au redémarrage l'entrée **réapparaît** non révoquée » → **peut réapparaître**.
  Une exception S3 ne prouve pas que l'écriture n'a pas abouti (un délai d'attente
  peut suivre une écriture acceptée), et le registre est en dernier-écrivain-gagne
  sans verrou. L'appelant ne peut que tenir l'état durable pour **indéterminé** ;
- « une ressource que nous **savons** morte » → **que nous tenons pour** morte.
  Le serveur traite un retour OpenBao sans exception comme une révocation
  confirmée ; il ne relit rien pour l'attester.

✅ **Les mêmes formulations catégoriques sont corrigées dans les `warning`
renvoyés à l'exécution** (`wrapping.py`). Portées en note à #123 lors de
l'arbitrage, elles sont fermées par ce lot — la condition n°4 de cet arbitrage
est désormais verrouillée par deux tests qui interdisent tout futur affirmé.

## [0.14.1] — 2026-08-15

### Une révocation confirmée mais non inscrite ne passe plus en silence

Quand `secret_revoke_wrap` révoque un accessor, la révocation OpenBao est
**acquise**. Si l'écriture du registre échoue ensuite, le retour de `_save()`
était **jeté** : l'appelant recevait un succès muet, clôturait son propre
registre — et au redémarrage l'entrée **ressuscitait non révoquée**, dans un état
que nous venions de lui annoncer révoqué.

La réponse porte désormais `registry_persisted: false` et un `warning`. ⚠️ Le
champ est **absent** du chemin nominal : un champ toujours présent ne signalerait
rien.

**La mémoire n'est PAS restaurée** — contrairement à `mark_active`. Ici elle dit
la vérité (OpenBao a bien révoqué) ; c'est le support durable qui est en retard.
La ramener à `active` remplacerait un fait exact par une prudence inexacte.

⚠️ **Ce lot ne rend PAS le fait durable, et ne prétend pas fermer #140.**
Inscrire un effet confirmé exige un support disponible au moment précis où le
support habituel ne l'est pas. Avec un seul support durable, il n'y en a pas.
Ce lot fait la seule chose possible sans second support : **le dire**. La limite
est désormais au contrat publié (README FR et EN), comme la fiche l'exigeait.

Le critère d'acceptation est porté à **#123** : soit un effet confirmé survit à
une panne du support suivie d'un redémarrage, soit le lot déclare explicitement
l'impossibilité. Sans ce critère, « on le traitera avec #123 » restait une
histoire qu'on se raconte.


## [0.14.0] — 2026-08-15

### ⚠️ RUPTURE — une clé de provisionnement est désormais à USAGE UNIQUE, sans condition

v0.13.0 bloquait le rejeu d'une clé `(operation_id, mission_id)` **sauf** sur
trois états — `revoked`, `consumed`, `unusable` — où le registre tient le jeton
pour mort. Cette libération n'existait que pour préserver la reprise
« révoquer la provision précédente, puis en recréer une » du broker `mcp-mission`.

**Deux faits l'ont rendue inutile le 15/08/2026 :** `mcp-mission` a retiré cette
reprise de sa conception (identifiant neuf par tentative, jamais réutilisé) et
l'a confirmé par lecture de son code ; la plateforme agentique a ensuite lu le
registre de tokens de production et établi qu'**un seul composant** portait un
jeton de permission `wrap`.

⇒ **La moindre entrée pour le couple bloque désormais `secret_wrap`**, quel que
soit son état. Plus rien ne libère une clé.

| Code | Ce qu'il atteste |
| --- | --- |
| `operation_terminated` *(nouveau)* | provision antérieure tenue pour **terminée** par le registre — rien à compenser |
| `registry_inconsistent` *(nouveau sur ce chemin)* | entrée **illisible** — rien ne peut en être déduit |

⚠️ **Une entrée CORROMPUE bloque elle aussi.** La garde de v0.13.0 les écartait
via `_entry_well_formed` : une entrée abîmée rouvrait donc la clé. La sélection
n'exige plus que des `operation_id`/`mission_id` lisibles et égaux — au-delà, une
entrée illisible est une raison de **refuser**, jamais d'autoriser.

### Ce que ça ferme, et ce que ça ne ferme pas

✅ **Le dernier chemin d'exploitation de #140.** Le registre ne stocke jamais le
`wrap_token` : `secret_consume` sélectionne l'entrée par la clé puis déballe le
jeton **présenté**, sans lien entre les deux. Un jeton **étranger** marquait donc
une entrée `unusable` — ce qui **libérait une clé dont le wrap réel vivait
encore**. Ce chemin est fermé. **Sa cause reste ouverte** et documentée à #140 :
la fermer exige de lier le jeton présenté à l'entrée ciblée.

⚠️ **Deux contournements ne sont PAS fermés**, et il ne faut pas les croire
emportés par ce lot : la perte du fichier de registre (registre vide = toutes les
clés redeviennent vierges) et la course entre deux instances, faute de CAS/ETag
(**#51**). Ce ne sont pas des libérations métier, mais l'unicité n'est pas
absolue pour autant.

### La garde ne porte QUE sur la création — et c'est verrouillé

`secret_revoke_wrap`, `secret_wrap_status` et `secret_wrap_lookup` restent
ouverts sur une clé engagée. C'est la condition posée par `mcp-mission` : sans
elle, ils seraient enfermés avec des ressources qu'ils ne pourraient plus ni voir
ni couper.

**Un test compte les appelants de la garde dans le code de production et échoue
s'il en apparaît un second** — sans quoi un lot futur pourrait fermer un de ces
trois verbes sans que personne ne s'en aperçoive avant l'incident.

### ⚠️ Pour qui c'est une rupture

Tout appelant qui **réutilisait un `operation_id` après une révocation** est
désormais refusé. Au recensement du 15/08/2026, aucun composant ne le faisait.
⚠️ La permission `admin` court-circuite la garde `wrap` : un porteur de jeton
`admin` peut appeler `secret_wrap` sans figurer dans un recensement des porteurs
`wrap`. L'impact est celui d'un opérateur humain — reprendre une clé neuve devant
un refus — mais il est réel.


## [0.13.0] — 2026-08-15

### ⚠️ RUPTURE — une clé de provisionnement déjà engagée n'est plus jamais rejouable

Quand un appel OpenBao échoue **après** avoir possiblement créé le wrap (délai
dépassé, coupure réseau, réponse incomplète), l'intention passe `failed` **sans
accessor** : la ressource éventuelle est innommable, donc non révocable.

Jusqu'en v0.12.1 la garde ne bloquait que `pending` — la clé
`(operation_id, mission_id)` **redevenait rejouable**. Un retry créait alors une
**seconde enveloppe pendant que la première pouvait vivre**, ce qui viole
l'invariant « au plus une enveloppe active par identifiant » sur lequel
`mcp-mission` s'est engagé le 15/08/2026.

`failed` bloque désormais la clé, avec un code **distinct** — les deux états
portent des informations différentes, et les fondre reproduirait le défaut #78
(un fait et une ignorance sous un même nom) :

| Code | Ce qu'il atteste | Appel OpenBao |
| --- | --- | --- |
| `operation_pending` | une intention est en cours | **inconnu** |
| `operation_failed` *(nouveau)* | une tentative a échoué après un appel possible ; une ressource peut subsister sans accessor | **a eu lieu** |
| `operation_revocable` *(nouveau)* | une provision antérieure subsiste et porte un accessor : elle **est** révocable | **a réussi** |

⚠️ **`active` était le pire cas laissé passer** : une provision VIVANTE et
NOMMABLE, dont le rejeu produisait deux enveloppes sous une même clé.

**La règle est écrite à l'envers, et c'est délibéré : on bloque SAUF si rien ne
peut survivre.** Seuls `revoked`, `consumed` et `unusable` libèrent la clé — les
trois états où le registre **tient le jeton pour mort**. Tout le reste bloque, y
compris un état que nous ajouterions plus tard : un oubli échoue alors du côté
prudent au lieu d'ouvrir un trou en silence.

⚠️ **« Tient pour mort » n'est pas « prouvé mort », et le trou n'est pas
entièrement fermé.** Le registre ne stocke jamais le `wrap_token`, seulement
l'accessor : `secret_consume` sélectionne l'entrée par
`(operation_id, mission_id)` puis déballe le jeton **présenté**. Un jeton bidon
marque donc l'entrée `unusable` alors que son wrap réel est intact. Et `revoked`
est posé dès qu'une exception OpenBao porte un 400/404 — de l'idempotence, pas
une attestation. **Ce lot RÉDUIT le trou** — avant, tout sauf `pending` libérait
la clé — **sans le fermer** : le fermer exige de lier le jeton présenté à
l'entrée ciblée. Résidu antérieur à ce lot, versé à #140.

⚠️ **`consume_outcome_unknown` BLOQUE**, malgré son rangement parmi les états
terminaux de consommation : OpenBao a pu consommer le jeton avant que la réponse
ne se perde, donc le jeton **peut encore vivre**. L'entrée conserve son accessor.

✅ **La reprise nominale reste possible** — révoquer la provision précédente
(elle passe `revoked`), puis en recréer une. Bloquer plus large aurait échangé
une double provision contre un déni de service : un test épingle ce garde-fou
inverse, et un autre vérifie que la liste libératoire n'accueille pas d'état
supplémentaire.

`operation_revocable` est nommé d'après **la conduite attendue**, pas d'après un
état de registre : le nommer `operation_active` aurait menti sur
`consume_outcome_unknown`, où la ressource n'est que *possiblement* vivante.

⚠️ **Le blocage est DÉFINITIF** — rien ne libère une clé. C'est l'échange assumé :
une clé morte contre une double provision. Il ne coûte rien aux appelants connus,
qui frappent un nouvel `operation_id` à chaque tentative — `mcp-mission` l'a
établi par lecture de son code, puis a rendu ce cas terminal dans son propre
contrat. **Reprise = nouvel `operation_id`, dans tous les cas.**

⚠️ **Version mineure et non correctif** : un appel aujourd'hui accepté devient
refusé. Aucune signature ne change, aucun champ ne disparaît, mais la conduite
d'un appelant qui rejouait change — d'où le bump.

### Le registre publie enfin ce qu'il PROUVE, et ce qu'il ne prouve pas

`secret_wrap_status` lit un instantané du registre : **aucun client OpenBao n'est
appelé**. Le contrat publié ne le disait nulle part, et deux équipes clientes
construisaient une procédure de décision sur ses réponses comme sur des constats.
Le README (FR et EN) porte désormais trois précisions absentes :

- **chaque réponse est une croyance datée** — `active` ne prouve pas qu'un wrap
  vive, `consuming` est persisté **avant** l'appel d'unwrap, et `consumed` /
  `revoked` / `unusable` ne parlent que d'**une** entrée : le verrou de clé ne
  regardant que `pending`, plusieurs entrées peuvent coexister pour un même
  couple, et un état terminal sur l'une ne dit rien des autres ;
- **`ambiguous` de `secret_wrap_status` n'est pas celui de `secret_wrap_lookup`** :
  le premier est pur, le second **révoque les entrées actives**. Appeler le lookup
  pour « comprendre » un `ambiguous` détruit ce qu'on cherche à diagnostiquer ;
- **une table « quand peut-on recréer »** après `secret_revoke_wrap`.

⚠️ **Une formulation trompeuse corrigée** : le README annonçait pour
`secret_revoke_wrap` qu'un accessor « introuvable dans un registre disponible =
succès ». C'est un **succès d'appel**, pas une révocation — `ok/not_found`
signifie qu'aucun appel OpenBao n'a été tenté. Un appelant pouvait y lire une
neutralisation et recréer par-dessus une ressource encore vivante.

Documentation seule : aucun changement de code, de signature ni de comportement.

## [0.12.1] — 2026-08-14

### Un code d'erreur qui annonçait « rien n'a été créé » alors qu'un wrap existait

`secret_wrap` rendait `registry_unavailable` sur **trois** situations. Ce code
promet à l'appelant qu'aucune ressource n'a été créée, et c'est vrai de deux
d'entre elles : registre non configuré, intention non enregistrable. **La
troisième survient APRÈS qu'OpenBao a créé le wrap** — l'échec de `mark_active`.
Le broker y lisait « provisionnement propre, rien à compenser » alors qu'un jeton
pouvait rester actif jusqu'à son TTL, sans qu'il en ait l'accessor.

Ce chemin rend désormais **deux codes distincts**, et la frontière est l'issue de
la **révocation d'urgence** — la seule chose qui décide s'il reste quelque chose à
compenser :

| Code | Ce qu'il atteste | Conduite appelant |
| --- | --- | --- |
| `wrap_created_revoked` | wrap créé, **révocation confirmée** | rien à compenser ; ne pas rejouer cette clé |
| `wrap_created_orphaned` | wrap créé, **révocation NON confirmée** | ressource possiblement active jusqu'au TTL, **non compensable** (aucun accessor n'est exposé) ; ne pas rejouer cette clé |

Cette information n'existait que dans un log serveur : les deux équipes clientes
devaient traiter tout échec comme une fuite de provision possible. Défaut relevé
en produisant la **matrice d'effet externe** demandée par `mcp-mission` et
`mcp-agent`, désormais publiée au README.

⚠️ **Rupture de valeur, non de forme** : un appelant qui filtrait `registry_unavailable`
sur ce chemin voit deux valeurs neuves. Aucune signature ne change, aucun champ ne
disparaît, et les deux nouveaux codes **échouent plus prudemment** que celui qu'ils
remplacent — d'où un correctif de patch et non une version mineure.

### Des refus rendaient une enveloppe d'erreur sans `error_type`

`ttl_seconds` hors de la plage 60–3600, et **tous les refus des gardes
d'autorisation partagées**, rendaient `{"status": "error", "message": …}` sans
code. Un appelant qui clé sur `error_type` y lisait `None`. Ils portent désormais
un code d'une taxonomie fermée : `unauthenticated`, `permission_denied`,
`access_denied`, `invalid_input`, `invalid_token`, `policy_store_unavailable`.

⚠️ **Portée bornée, à ne pas surestimer** : la promesse couvre les gardes de
`auth/context.py`. Des refus de **validation** propres à des outils hors périmètre
wrapping (`secret_list`, surfaces `/admin/api`) en sortent encore sans code.
**Testez `status` avant `error_type`.**

### Un défaut de rejeu documenté, PAS corrigé

Quand `secret_wrap` échoue **après** l'appel OpenBao — `backend_error` sur
coupure réseau, ou réponse sans `wrap_info` exploitable — l'intention passe
`failed` **si sa persistance aboutit**, et la clé `(operation_id, mission_id)`
**redevient alors rejouable** alors qu'un wrap a pu être créé sans que nous en
ayons l'accessor. Un rejeu automatique y créerait un **second** wrap, le premier
restant orphelin. ⚠️ Si cette persistance échoue à son tour, l'entrée revient
`pending` et la clé est au contraire **bloquée** (`operation_pending`) : les deux
issues existent, et l'appelant ne peut pas les prévoir.

Le comportement est **exercé par deux tests** — le rejeu effectif, et la
compensation — et signalé aux deux équipes clientes avec la seule protection
disponible : **ne pas rejouer la même clé, repartir sur un nouvel
`operation_id`**.

⚠️ **Un mensonge de contrat corrigé sur ce même chemin.** Une entrée `failed` est
précisément celle que l'appelant rencontre en compensant — et
`secret_wrap_lookup` lui répondait `already_revoked` : il **affirmait une
révocation qui n'avait jamais eu lieu**, alors qu'un wrap peut être vivant et
inconnu. Elle rend désormais `found_unattached` (aucun accessor, aucune
révocation possible, seul le TTL borne la ressource) — même famille de mensonge
que celle fermée par #78 pour les états terminaux de consommation, restée ouverte
ici. Le nouveau verdict est **pessimiste** quand OpenBao avait réellement refusé
la lecture : il annonce une ressource possible là où il n'y en a aucune. Une
prudence inutile coûte moins qu'une fausse assurance.

Il n'est pas fermé dans ce lot, et c'est un arbitrage explicite : bloquer la clé
la bloquerait **définitivement** — rien ne libère une clé chez nous, et une
libération par échéance créerait une seconde entrée `pending`, donc une ambiguïté.
On échangerait un incident rare (panne exactement après création) contre un
incident fréquent (toute coupure réseau condamne la clé). La reprise correcte
exige une transition persistée : lot distinct, et une question posée à
`mcp-mission` — repartent-ils déjà avec un nouvel identifiant après un échec ?

### Le contrat des signatures d'outils devient démontrable, plus seulement mesuré

L'ordre de déploiement de v0.12.0 communiqué à `agentic-platform` et à
`mcp-mission` — **Mission d'abord, Vault ensuite, sans fenêtre de maintenance** —
repose sur une propriété **observée et verrouillée de notre pile MCP/FastMCP**
(`mcp==1.26.0`), et non sur une garantie normative du protocole : un paramètre **surnuméraire est
ignoré**, un paramètre **requis manquant est refusé**. Une release Mission qui
envoie toujours `mission_id` fonctionne donc contre v0.11.0 comme contre v0.12.0.

Cette propriété n'était établie que par une **mesure manuelle**. La plateforme l'a
relevé et a demandé à `mcp-mission` de produire le test durable, faute de l'avoir
chez nous. C'était notre affirmation, sur notre couche : `tests/test_contrat_mcp_signatures.py`
la ramène de notre côté.

Le banc fige aussi le **contrat publié** de nos cinq outils du chemin wrap
(paramètres requis exacts, listes figées à la main) et deux propriétés de sécurité :
`secret_wrap_lookup` / `secret_wrap_status` exigent `mission_id` — le rendre
optionnel rouvrirait la révocation inter-missions comme comportement par défaut —
et **`secret_consume` ne l'expose PAS** en paramètre : la mission reste extraite du
claim du jeton, donc prouvée et non déclarée. ⚠️ Formulation resserrée en revue :
l'ajouter ne créerait pas mécaniquement un contournement du binding C18 — le
handler continuerait de lire le claim — mais une **double source d'identité** dans
le contrat, dont un appelant pourrait croire que la sienne fait foi. C'est cette
ambiguïté que le test interdit.

Le banc exerce le **vrai chemin protocolaire** — une session client MCP en mémoire
émet un `tools/call` réel — et lit les schémas par l'**API publique** `list_tools()`,
donc la surface effectivement annoncée aux appelants.

⚠️ Si une montée de version de `mcp` changeait la tolérance aux paramètres, ces
tests échoueront — et **la séquence de déploiement annoncée à deux équipes
deviendrait fausse**. La conséquence n'est pas locale, d'où le banc. En revanche ils
ne couvrent **pas** les ruptures de transport ou de version de protocole : une
montée qui changerait la négociation, la sérialisation ou le cadrage des erreurs
peut casser la compatibilité sans les faire échouer.

**Tests** : `tests/test_contrat_mcp_signatures.py` (10 tests). **3 mutations
mesurées, 3 détectées** (`mission_id` rendu optionnel sur chacun des deux outils,
et ajouté en paramètre de `secret_consume`).

### Deux affirmations de la section v0.12.0 étaient plus fortes que la réalité

Relevées en auditant nos propres commentaires. Elles figurent aussi dans les
messages de commit et les demandes de fusion correspondantes ; nous les corrigeons
ici plutôt que de les laisser courir.

1. **« Le chemin de repli existait sans jamais servir »** (à propos de
   `mark_active` et de la révocation d'urgence). **Faux** : en v0.11.0,
   `mark_active` finissait par `return self._save()` — un échec S3 rendait donc
   déjà `False` et déclenchait bien la révocation d'urgence. Ce que v0.12.0
   ajoute est plus étroit : `False` lorsque **aucune entrée `pending` unique** ne
   correspond au couple.

2. **« La classification passe par la classe d'exception, plus par une recherche
   de sous-chaîne »**. **Trop fort** : elle exige la classe `InvalidRequest`
   **puis** cherche le motif OpenBao exact dans `errors` et `str(exc)`.
   L'amélioration est réelle — l'ancien mapping cherchait « 403 »/« 404 » sans
   contrainte de classe — mais le texte de l'exception n'a pas disparu du
   raisonnement : c'est le texte **seul** qui ne décide plus rien.

### Correction documentaire

`scripts/README.md` portait encore un exemple `secret wrap-lookup op-1` **sans**
`--mission-id`, livré tel quel dans v0.12.0. Signalé de nous-mêmes à la
plateforme, corrigé ici.

## [0.12.0] — 2026-08-14

> ### ⚠️ À FAIRE AVANT DE DÉPLOYER
>
> Cette version porte **cinq ruptures**, toutes dans le domaine du *wrapping*
> (livraison de secrets à usage unique aux missions). Elle ne touche à rien
> d'autre.
>
> **1. Variables d'environnement : AUCUN CHANGEMENT.** Ni ajout, ni retrait, ni
> renommage. Le contrat `.env.example` reste à **46 clés — 23 actives et
> 23 commentées**. Rien à faire côté configuration.
>
> **2. Deux outils MCP changent de signature** — c'est la rupture qui casse un
> appelant au démarrage :
>
> | Outil | Avant | Après |
> | --- | --- | --- |
> | `secret_wrap_lookup` | `(operation_id)` | `(operation_id, mission_id)` |
> | `secret_wrap_status` | `(operation_id)` | `(operation_id, mission_id)` |
>
> ⚠️ **`mcp-mission` est concerné** : son *CredentialBrokerService* appelle ces
> deux outils. **Déployer cette version sans mettre à jour son broker casse sa
> compensation d'orphelins et son diagnostic.** Aucun contournement n'est prévu :
> un paramètre optionnel aurait laissé la révocation inter-missions comme
> comportement **par défaut** sur un outil destructif. Les commandes CLI
> `secret wrap-lookup` et `secret wrap-status` exigent aussi `--mission-id`.
>
> **3. Le contrat d'erreurs de `secret_consume` évolue** — trois changements. Les
> codes `wrap_unusable`, `consume_outcome_unknown` et `empty_secret` sont
> **non réessayables** : provisionner un nouveau wrap si l'accès reste
> nécessaire. `secret_wrap_lookup` peut désormais répondre `status: "error"` avec
> `consume_terminal` — un appelant qui assimile `status: "ok"` à « compensation
> achevée » doit être adapté. Nouveau code `operation_pending` : ne pas rejouer
> une clé `(operation_id, mission_id)` déjà en cours, repartir avec un nouvel
> `operation_id`.
>
> **3 bis. En mode durci uniquement** (`ENFORCE_MISSION_TOKEN_VALIDATION=true`
> — porte **indépendante** du mode d'authentification, elle peut être active en
> `bearer`) :
>
> - **`secret_wrap` exige `tenant_id`**. Le serveur ne peut pas le déduire : un
>   locataire inventé serait un faux binding. Il refuse aussi une audience
>   désignant une AUTRE instance (`binding_mismatch`), et une configuration
>   incohérente (`misconfigured`) ;
> - ⚠️ **les wraps historiques au binding incomplet deviennent inconsommables**
>   (`binding_incomplete`). Personne ne peut leur ajouter le binding manquant
>   après coup : il faut les **reprovisionner** ou les laisser expirer. Hors mode
>   durci, ils restent consommables — comportement inchangé.
>
> **3 ter. `secret_wrap_status` peut rendre deux états de plus** : `unusable` et
> `consume_outcome_unknown`. Ils ne portent **pas** `expires_at` — il n'a de sens
> que pour un état vivant. Un consommateur qui énumère les statuts, ou qui
> suppose ce champ présent, doit être adapté.
>
> **4. Ce que cette version CORRIGE en production**, et qui justifie de ne pas
> attendre :
>
> - **un défaut destructif** : compenser un accès abandonné d'une mission
>   révoquait l'accès **vivant** d'une autre mission partageant l'identifiant
>   d'opération ;
> - **un succès mensonger** : un secret sans contenu exploitable était rendu avec
>   `status: "ok"` et aucun credential ;
> - **un registre qui mentait** : après un échange interrompu, un jeton
>   peut-être déjà consommé était réinscrit comme disponible.
>
> **5. Contrôle post-déploiement** : viser `/health` et attendre **200** (pas
> `/healthz`, qui répond 200 même coffre indisponible — voir v0.11.0).


### RUPTURE — cloisonnement inter-missions du registre de wraps

**Un `operation_id` n'est PAS unique entre missions.** C'est le couple
`(operation_id, mission_id)` qui identifie une provision — la consommation et les
transitions terminales l'utilisaient depuis toujours, **quatre autres chemins
non**.

**Le plus grave est destructif et était atteignable en mono-instance**, après deux
provisions séquentielles partageant l'identifiant : la compensation d'un orphelin
(`secret_wrap_lookup`) sélectionnait par `operation_id` seul, puis **révoquait**.
Compenser un orphelin de la mission A **détruisait la provision VIVANTE de la
mission B**.

⚠️ Le filtre d'identité de #115 ne protégeait pas : le broker porte **un seul
jeton pour toutes les missions**, donc toutes les entrées lui sont visibles. C'est
la cause du fail-close sur `ambiguous` qu'`mcp-mission` avait dû adopter, au prix
d'orphelins non compensés.

#### Ce qui change — deux outils MCP prennent un paramètre REQUIS

| Outil | Avant | Après |
| --- | --- | --- |
| `secret_wrap_lookup` | `(operation_id)` | `(operation_id, mission_id)` |
| `secret_wrap_status` | `(operation_id)` | `(operation_id, mission_id)` |

Un paramètre **optionnel** aurait laissé la révocation inter-missions comme
comportement **par défaut** sur un outil destructif : la rupture est assumée. Les
commandes CLI `secret wrap-lookup` et `secret wrap-status` exigent désormais
`--mission-id`.

`secret_wrap_status` cloisonné ferme aussi une **divulgation** : une mission
lisait l'existence, l'état et la durée de vie restante des provisions d'une autre.

#### Transitions de provisionnement

`mark_active` et `mark_failed` prenaient « la dernière entrée `pending` de cet
`operation_id` » : le succès OpenBao de A pouvait écrire l'accessor de A sur
l'entrée de B, laissant celle de A `pending` pour toujours. Elles sélectionnent
désormais le couple, et l'ambiguïté est traitée comme une absence — on ne devine
pas laquelle est la bonne.

#### Deux défauts d'honnêteté fermés au passage

- **`mark_active` ne peut plus mentir** : elle rendait le résultat de `_save()`
  seul, donc « succès » même sans aucune entrée mise à jour — l'appelant en
  concluait que la provision était corrélée et compensable. Elle rend désormais
  `False`, et `wrap_secret` emprunte enfin son chemin de repli (révocation
  d'urgence de l'accessor), qui existait sans jamais servir ;
- **plus aucune sauvegarde no-op** : absence ou ambiguïté n'écrivent plus rien.
  Une écriture no-op réécrit l'état mémoire par-dessus une version S3 possiblement
  plus récente d'une autre instance (last-write-wins, pas de CAS — #51). Et si la
  sauvegarde d'une transition échoue, l'état mémoire est **restauré** : plus
  d'`active` fantôme qu'une écriture ultérieure aurait persisté.

#### Nouveau code d'erreur `operation_pending`

Rejouer une clé `(operation_id, mission_id)` dont une provision est encore
`pending` est refusé **avant toute écriture et avant tout appel OpenBao**. Après
un plantage on ne sait pas si un wrap a déjà été créé ; en rattacher un second
rendrait le premier orphelin **et** non compensable. Un retry après `failed` reste
permis, et le `pending` d'une **autre** mission ne bloque rien.

> ⚠️ **Reprise après un `pending` bloqué** : elle se fait avec un **nouvel
> `operation_id`**, pas par attente — le message le prescrit. Deux causes, et la
> seconde n'exige **aucun plantage** : un arrêt brutal entre l'enregistrement de
> l'intention et sa résolution, **ou une indisponibilité S3 pendant cette
> résolution** — `mark_active`/`mark_failed` restaurent alors l'état mémoire, donc
> l'entrée redevient `pending`. L'appel de résolution a bien lieu ; c'est sa
> PERSISTANCE qui n'est pas garantie. La restauration reste le bon comportement :
> laisser un `active` en mémoire alors que S3 porte `pending` serait un mensonge
> d'état. Une libération
> automatique par échéance a été écrite puis **retirée** après revue : elle ne
> suffisait pas (la nouvelle intention créait une seconde entrée `pending`, donc
> une ambiguïté, donc un refus plus loin), le plafond de TTL « dur à 300 s »
> qu'elle invoquait est celui du broker `mcp-mission` et **non le nôtre**
> (`secret_wrap` accepte 60–3600 s), et `expires_at` est calculé AVANT l'appel
> OpenBao — il ne borne donc pas la durée de vie réelle du wrap. Une reprise
> correcte demande une transition persistée et une échéance qui borne vraiment :
> lot distinct, à instruire.

> ⚠️ **Résidu assumé** : ce refus n'est PAS une garantie d'unicité distribuée.
> Sans CAS/ETag S3 (#51), deux instances peuvent lire l'absence puis écrire toutes
> les deux. Il ferme le rejeu séquentiel, pas la course.

#### Variables d'environnement

**Aucun changement** — le contrat `.env.example` reste à **46 clés (23 actives,
23 commentées)**.

**Tests** : `tests/test_cloisonnement_missions.py` (32 tests), plus la surface
CLI et les bancs opt-in OpenBao réels (7 tests rejoués contre OpenBao 2.5.1).
**8 mutations mesurées, 8 détectées** — dont le défaut destructif, attrapé par
5 tests. Suite : 1363 passed / 33 skipped / 0 failed.

### RUPTURE de contrat d'erreurs — la consommation d'un wrap ne peut plus mentir (issue #78, findings 2 et 3)

**Ce qui était faux.** `secret_consume` passe l'entrée du registre de `active` à
`consuming`, puis demande à OpenBao de déballer le secret. Sur **toute** erreur,
l'ancien code remettait l'entrée à `active` et répondait
`backend_error` — « Erreur lors de l'unwrap (**réessayer**) ».

Deux défauts, dont c'est l'effet **combiné** qui compte :

- **le retour à `active` est indémontrable** : une fois l'appel parti, OpenBao a
  pu consommer le jeton avant que la réponse ne se perde. Le registre annonçait
  alors « disponible » une provision peut-être définitivement brûlée ;
- **la classification était aveugle au cas réel** : elle cherchait « 403 » ou
  « 404 » dans le texte de l'exception, alors qu'OpenBao répond **400**
  (« wrapping token is not valid or does not exist ») pour un jeton invalide,
  expiré ou déjà consommé. `invalid_wrap_token` et `wrap_expired` étaient donc
  inatteignables sur ce chemin.

Ensemble : un jeton **mort** produisait « réessayer » **et** un registre qui le
déclarait actif. Soit une boucle de retry sur un jeton qui ne pourra jamais
aboutir, cautionnée par le registre. Relevé par l'équipe `mcp-mission`, qui
avait déjà payé un incident voisin sur ce périmètre.

#### Ce qui change

**Après le passage en `consuming`, plus aucun retour à `active`.** Deux états
terminaux, et deux `error_type` correspondants, tous deux **non réessayables** :

| État de registre | `error_type` | Quand |
| --- | --- | --- |
| `unusable` | `wrap_unusable` | **seul cas** : OpenBao répond `400` avec son motif exact (« wrapping token is not valid or does not exist ») |
| `consume_outcome_unknown` | `consume_outcome_unknown` | délai dépassé, réseau, 5xx, ou 400 inattendu — l'issue n'est pas établie |

**La classification passe par la classe d'exception hvac**, plus par une
recherche de sous-chaîne dans `str(e)`. Et elle est volontairement **étroite** :
un `400` sans le motif exact reste indéterminé, et **`403`/`404` aussi**. Ces
deux codes ne prouvent que la réponse HTTP, pas le sort du jeton — un proxy, un
routage erroné ou un refus d'infrastructure les produit avec un wrap encore
vivant. Le faux « indéterminé » coûte un reprovisionnement ; le faux « mort »
ferait jeter une provision valide.

**Un `consuming` résiduel n'est plus banalisé.** Si la transition terminale n'a
pas pu être persistée, ou si une tentative a été interrompue, l'entrée reste
`consuming` sur S3. Un appel suivant répond désormais `consume_outcome_unknown`
et non `already_consuming` : l'issue est réellement inconnue, pas une
concurrence passagère.

**`empty_secret` n'est plus un retour arrière.** Si OpenBao a répondu, le jeton a
été présenté et traité : l'entrée est marquée `consumed`, et l'erreur est
non réessayable. L'ancien code y faisait un rollback vers `active` — doublement
faux.

**Le retour arrière AVANT l'appel reste, lui, légitime** : si la persistance du
passage en `consuming` échoue, rien n'a été envoyé à OpenBao et le wrap est
réellement toujours disponible. Cette distinction est verrouillée par un test.

**Deux surfaces de lecture s'alignent** : `secret_wrap_status` restitue les deux
nouveaux états (sans `expires_at`, qui n'a de sens que pour un état vivant), et
`secret_wrap_lookup` rend `consume_terminal` au lieu d'`already_revoked` — parce
qu'un état terminal de consommation **n'est pas une révocation attestée**.

> ⚠️ **Deux contrats évoluent, pas un.** Outre les `error_type` de
> `secret_consume`, `secret_wrap_lookup` peut désormais répondre
> `status: "error"` avec `error_type: "consume_terminal"`. C'est **délibérément
> une erreur et non un succès** : un appelant existant qui assimile tout
> `status: "ok"` à « compensation achevée » conclurait à tort que la ressource
> est neutralisée, alors qu'aucune révocation n'est attestée. Le rendre en
> erreur protège le consommateur qui n'a pas encore été adapté. Cela vaut aussi
> quand d'autres entrées ont réellement été révoquées : une seule entrée non
> attestée interdit d'affirmer que tout l'a été.

### RUPTURE — un secret vide ne sortait pas en erreur mais en SUCCÈS (issue #78)

**Défaut découvert en rendant les simulacres de test fidèles**, et **reproduit
contre un OpenBao 2.5.1 réel** — la version en production.

`secret_wrap` enveloppe une lecture KV v2, et `hvac.sys.unwrap()` **n'aplatit
pas** la réponse : la forme réelle est `{"data": {"data": <paires>, "metadata":
{…}}}`. Le secret en clair est donc à `data.data`. Or la garde « secret vide »
testait l'enveloppe **externe**, qui porte **toujours** `metadata` et n'est donc
**jamais** vide. La garde était **morte en production**.

Conséquence mesurée : un secret sans aucune paire exploitable sortait en

```
{"status": "ok", "data": {"data": {}, "metadata": {…}}}
```

L'appelant lisait « succès » et n'avait **aucun credential**. C'est la même
famille de défaut que le finding 3 — une garde écrite contre une forme
qu'OpenBao ne produit pas.

**Ce qui change.** `empty_secret` conserve son nom mais sa condition est
redéfinie : sont refusées l'enveloppe absente, mal formée, ou dont `data.data`
n'est pas un dictionnaire non vide. Une réponse qui n'est **pas** un
dictionnaire est désormais elle aussi **terminale** (`empty_secret`) et non
« indéterminée » : OpenBao **a répondu**, donc le jeton à usage unique est brûlé
— l'issue est connue, c'est la réponse qui est inutilisable. Dans tous ces cas
l'entrée est marquée `consumed`, non réessayable.

**La forme de sortie du cas nominal NE change PAS** : `result["data"]` reste
l'enveloppe complète (`data` + `metadata`), contrat déjà communiqué à
`mcp-agent`. Un test d'intégration contre OpenBao réel le verrouille, pour qu'un
futur durcissement ne l'aplatisse pas au passage.

### RUPTURE en mode durci — le binding de mission exigé aux DEUX bouts (issue #78, finding 4)

Le binding anti-confused-deputy repose sur **deux** champs : `tenant_id` (quel
locataire) et `expected_aud` (quelle instance de coffre). En mode durci
(`ENFORCE_MISSION_TOKEN_VALIDATION=true`), seul `expected_aud` était exigé — le
contrôle d'appartenance au locataire ne s'appliquait donc que lorsque le champ
était présent, c'est-à-dire **jamais quand il manquait**.

**Ce qui change**, symétriquement :

- **à la consommation** : en mode durci, une entrée sans `tenant_id` **ou** sans
  `expected_aud` est refusée (`binding_incomplete`), **avant** `try_mark_consuming`
  et avant tout appel à OpenBao — le wrap n'est donc **pas brûlé** et aucun état
  `consuming` orphelin n'est laissé. ⚠️ Il n'est pas pour autant rattrapable :
  personne ne peut ajouter après coup un binding manquant. Une entrée historique
  incomplète doit être **reprovisionnée** (ou laissée expirer) ; le message le dit
  explicitement. Ce contrôle passe **avant** la comparaison de binding, sinon un
  champ d'espaces blancs sortait en `binding_mismatch` — diagnostic trompeur qui
  envoyait chercher une erreur d'appel là où il faut reprovisionner ;
- **à la création** : `secret_wrap` refuse en mode durci un appel sans
  `tenant_id`. Le serveur complète `expected_aud` depuis sa configuration, mais
  **il n'a aucune source pour le locataire** : le déduire serait un **faux
  binding**, attestant une appartenance inventée. Sans ce refus, le coffre
  fabriquait des provisions qu'il rejette ensuite à la consommation — l'incident
  se découvrant au pire moment, quand la mission réclame son credential.

**Les espaces blancs ne valent pas un binding**, mais le traitement diffère selon
le champ, et cette asymétrie est délibérée : un `tenant_id` blanc est **refusé**
(aucune source serveur ne peut le suppléer), tandis qu'une `expected_aud` blanche
est traitée comme **absente et enrichie** depuis la configuration. Avant, elle
était stockée telle quelle et rendait le wrap inconsommable à la consommation —
la même provision vouée à l'échec, par l'autre champ.

**Et une audience qui désigne une AUTRE instance est désormais refusée à la
création** (`binding_mismatch`). `secret_consume` compare toujours l'audience
stockée à celle de **cette** instance — l'appelant ne choisit pas la valeur
comparée. Une audience non blanche différente produisait donc un wrap
**définitivement inconsommable**. La refuser est le seul comportement honnête :
l'écraser silencieusement serait pire, le coffre attesterait une audience que
l'appelant n'a jamais demandée. En mode durci, une audience non résoluble côté
serveur reste `misconfigured`.

**Et le mode durci ne peut plus être contourné par une configuration
incomplète.** La porte du durcissement était `ENFORCE=true` **et** JWKS
configuré. Avec `ENFORCE=true` et JWKS vide, tout le contrôle était donc sauté à
la création — alors que `secret_consume` refuse **systématiquement** dans cette
configuration (`misconfigured`). Le coffre fabriquait une provision morte-née à
chaque appel. La porte est désormais `ENFORCE=true` **seul**, et les causes de
configuration (`MISSION_JWKS_URL` vide, audience non résoluble) sont évaluées
**avant** les paramètres de l'appelant : inutile de l'envoyer vérifier son appel
quand c'est le serveur qui est incohérent. Les deux surfaces rendent désormais le
même verdict.

> ⚠️ **Mode durci uniquement.** Hors `enforce`, le comportement est **inchangé**
> et les wraps historiques sans binding restent consommables (rétrocompatibilité
> assumée). ⚠️ `ENFORCE_MISSION_TOKEN_VALIDATION` est une porte **indépendante**
> du PEP transport : elle peut être active en mode d'authentification `bearer`.
> Ne pas déduire de « la production tourne en bearer » que ce chemin dort.

**CLI** : l'aide de `secret wrap` annonce désormais `--tenant-id` comme
obligatoire en mode durci ; elle le présentait comme « optionnel » sans nuance.

#### Pour les appelants

`wrap_unusable`, `consume_outcome_unknown` et `empty_secret` **ne doivent pas
être réessayés** : dans les trois cas le jeton à usage unique est perdu. Si
l'accès reste nécessaire, provisionner un nouveau wrap. Le contrat d'erreurs de
`secret_consume` était explicitement annoncé comme « à versionner à l'issue de ce
durcissement » (#78) : c'est cette version.

En mode durci, **fournir `tenant_id` à `secret_wrap`**.

#### Variables d'environnement

**Aucun changement** : aucune variable ajoutée, retirée ni renommée. Le contrat
`.env.example` reste à **46 clés — 23 actives et 23 commentées** (décomposition
donnée explicitement : le pipeline de qualification d'`agentic-platform` contrôle
le NOMBRE de variables, et un total re-dérivé autrement diverge).

**Tests** : `tests/test_consume_outcome_78.py` (56 tests, dont un contrat de
forme d'enveloppe figé à la main), `tests/test_binding_enforce_78.py`
(19 tests, les deux bouts), et `tests/test_consume_openbao_78.py` — **4 tests
d'intégration contre un OpenBao 2.5.1 réel** (opt-in, `MCP_VAULT_TEST_OPENBAO_ADDR`
+ `_TOKEN`). Le défaut de forme a été prouvé **rouge sans le correctif contre le
moteur réel**, pas seulement contre des simulacres. **16 mutations mesurées sur
les gardes de ce lot, toutes détectées** (instrument validant `ast.parse` avant
chaque essai et vérifiant que la mutation mord). Suite : 1331 passed /
33 skipped / 0 failed.

## [0.11.0] — 2026-08-13

> ### ⚠️ À FAIRE AVANT DE DÉPLOYER
>
> Cette version porte **trois ruptures**. Chacune a un chemin de migration ; les
> ignorer casse des appelants en service.
>
> 1. **Authentification** — le mode `bearer` (le **défaut**) exige désormais un
>    jeton valide. Vérifiez que **chaque appelant de `/mcp` porte un bearer
>    valide**. Si vous découvrez un client sans jeton et que vous ne pouvez pas
>    le migrer tout de suite, posez `MCP_AUTH_MODE=bearer-anonymous` — mode
>    d'exception **temporaire** qui rouvre délibérément la divulgation corrigée
>    par #116, et qui émet un `CRITICAL` au démarrage.
> 2. **CLI** — le shell interactif est supprimé. **Recensez vos scripts** qui
>    l'utilisent et migrez-les vers les commandes Click ; les 50 opérations ont
>    toutes un équivalent, mais la syntaxe change (tableau plus bas).
> 3. **Sondes de santé** — `/health` et `/ready` renvoient maintenant **503**
>    quand le coffre ne peut pas servir. **Ne basculez pas mécaniquement vos
>    sondes vers `/healthz`** : choisissez selon la question posée.
>    - « le coffre est-il **utilisable** ? » (déploiement, readiness, contrôle
>      post-déploiement) → **`/health` ou `/ready`, attendre `200`** ;
>    - « le processus **vit-il** ? » (liveness, autoheal) → **`/healthz`**.
>
> Après un démarrage non abouti, l'état de disponibilité est **latché** : le
> signal ne repasse pas au vert tout seul, un redémarrage est requis.

### RUPTURE — les sondes de santé disent la vérité (issue #103)

**Ce qui était faux.** `/health` renvoyait le littéral
`{"status": "healthy", ...}`. Il ne consultait **rien**. Un conteneur démarré en
mode dégradé — qui journalise pourtant « ⚠️ Démarrage en mode dégradé (OpenBao
indisponible) » — répondait donc `healthy` au `HEALTHCHECK` Docker, qui le
rapportait sain. L'information existait, elle n'était simplement pas propagée au
signal de santé. `/admin/api/health` avait le même défaut (`"status": "ok"` en
dur), et mentait donc aussi à la console d'administration.

Conséquences : un rolling update pouvait retirer l'instance saine et garder la
dégradée, puisque les deux se déclaraient saines ; aucune alerte fondée sur
`/health` ne se déclenchait ; le diagnostic était reporté au premier appel métier
échoué, loin de la cause.

**Deux questions distinctes, deux contrats.**

| Endpoint | Question | Sain | Dégradé |
| --- | --- | --- | --- |
| `/healthz` | *liveness* — le processus répond-il ? | `200` `alive` | **`200` `alive`** |
| `/health`, `/ready` | *disponibilité* — le coffre peut-il servir ? | `200` `healthy` | **`503`** |

`/healthz` ne sonde **jamais** OpenBao. C'est délibéré : rendre la *liveness*
rouge sur une dépendance indisponible ferait redémarrer en boucle un coffre
**scellé** par un autoheal ou une sonde Kubernetes — et redémarrer ne descelle
pas, cela aggrave l'incident. Branchez la liveness sur `/healthz`, la
disponibilité sur `/health`.

**Un coffre scellé est identifiable de l'extérieur**, sans divulgation. `status`
appartient à une **énumération fermée**, une par question — `healthy`, `sealed`,
`unavailable` pour la disponibilité, `alive` pour la liveness — et rien d'autre
ne peut sortir : aucun message d'exception, aucune adresse, aucune version
d'OpenBao, aucun texte libre. Le diagnostic reste dans les journaux et sur
`/admin/api/health`, qui exige un bearer valide (route « tout token », pas
réservée aux admins) et porte désormais `availability` et `availability_detail`.

La **console d'administration accepte l'état dégradé** : elle refusait tout
`status` différent de `ok`, ce qui aurait enfermé l'exploitant dehors au moment
précis où la console sert à diagnostiquer et à desceller.

Les réponses dégradées sont journalisées **sur transition**, pas par requête :
`/health` étant public, une ligne par appel offrirait un levier d'amplification
de journal (famille #111).

**La disponibilité exige deux termes réunis** : la séquence de démarrage doit
avoir abouti **et** la sonde courante doit voir OpenBao initialisé et descellé.
Une sonde verte seule ne suffit pas — le démarrage comprend aussi la restauration
S3 et le chargement des magasins. L'état est **latché** : après un démarrage non
abouti, le signal ne repasse pas au vert tout seul, un redémarrage est requis.
C'est exact dans le cas d'une restauration S3 ambiguë, où `vault_startup()`
renvoie `False` **avant** de démarrer OpenBao — qui n'est donc jamais lancé.

**La sonde ne peut pas geler le service.** L'appel hvac était synchrone et sans
timeout ; le brancher tel quel sur un endpoint public aurait recréé le défaut de
disponibilité de #110. Il est désormais offloadé hors de la boucle d'événements,
borné par `OPENBAO_HEALTH_TIMEOUT` (défaut 2 s, une valeur ≤ 0 refuse le
démarrage), et **single-flight** : une seule sonde réelle en vol, quelle que soit
la rafale de requêtes sur cet endpoint public. Aucun cache — un cache permettrait
de répondre « disponible » après la panne.

#### Ce qui change pour l'exploitation

- Le `HEALTHCHECK` du conteneur vise `/health` : un coffre indisponible apparaît
  maintenant `unhealthy` dans `docker ps`. C'est l'objet de la correction.
- **Choisissez l'endpoint selon la question posée — ne basculez pas
  mécaniquement vers `/healthz`.**

  | Ce que fait votre sonde ou votre script | Endpoint | Attendu |
  | --- | --- | --- |
  | Attendre que le coffre soit **utilisable** (script de déploiement, readiness, contrôle post-déploiement) | `/health` ou `/ready` | **`200`** — continuez d'attendre tant que c'est `503` |
  | Vérifier que le **processus vit** (liveness, autoheal, redémarrage automatique) | `/healthz` | `200` |

  ⚠️ `/healthz` répond `200` **même quand le coffre est indisponible** : y
  basculer un script d'attente de démarrage le ferait poursuivre sur un coffre
  qui ne peut servir aucun secret. À l'inverse, brancher un autoheal sur
  `/health` redémarrerait en boucle un coffre **scellé** — ce qui ne le
  descelle pas.
- L'étape de CI qui exigeait `200` sur `/health` avec un S3 mort encodait
  exactement le défaut corrigé ici ; elle exige désormais `503` et
  `status: unavailable`. Elle attend le démarrage sur `/healthz` parce qu'elle
  vérifie précisément un mode dégradé — ce n'est **pas** un modèle à recopier
  pour un déploiement.

Enfin, `sealed` n'est affirmé que s'il est **explicitement présent** dans la
réponse de santé. À défaut, une réponse incomplète est classée `unavailable` :
déduire le scellement d'une valeur par défaut ferait annoncer « descellez-moi »
sur une réponse qui ne le dit pas.

**Tests** : `tests/test_health_honesty_103.py` — 43 tests ; contrat frontend
`tests/js/health_login_contract.test.js` — 14 cas sous Node. **13 mutations
mesurées, toutes détectées** : littéral `healthy` réintroduit, 2ᵉ terme du
prédicat retiré, `sealed` fondu dans `unavailable`, timeout hvac retiré,
single-flight cassé, offload retiré, `/healthz` mis à sonder, diagnostic recopié
dans le corps public, cache réintroduit, réponse inexploitable promue en sain,
`sealed` déduit d'un défaut, console refusant de nouveau l'état dégradé, journal
par requête.

Suite : 1255 passed / 29 skipped / 0 failed.

### RUPTURE — le mode `bearer` exige désormais un jeton valide (issue #116)

**Ce qui était ouvert.** `bearer` est le mode par **défaut**. Une requête sans
en-tête `Authorization` — ou avec un jeton invalide — atteignait les outils.
Relevé par un tiers sur une instance en service, avec `curl` seul :
`initialize`, `tools/list`, `system_about`, `system_health`, `vault_list`, les
quatre outils PKI de lecture, `secret_types` et `secret_generate_password`
répondaient à un appelant **anonyme**.

**Aucun secret n'était lisible** — `secret_read` et `secret_list` passent par
`check_access`, qui refuse sans identité. Le défaut est une **divulgation** :
inventaire des coffres, **certificats émis (donc les noms de domaine et adresses
du parc)**, nom du bucket S3, adresse interne d'OpenBao, versions.

**Pourquoi c'est arrivé.** Les protections existent et fonctionnent. Elles
répondent à « *cette* identité a-t-elle le droit ? ». Les gardes des outils
**alors exposés** ne posaient jamais « y a-t-il seulement une identité ? » :
`get_listing_filter(None)` rend `visible: True` et `check_policy(None)` rend
« autorisé ». `check_access`, lui, refuse bien sans identité — c'est
précisément pourquoi les secrets sont restés protégés.

**Le correctif est au middleware, pas dans les outils.** Refuser à l'entrée
ferme la surface des outils MCP d'un seul geste — `initialize` et `tools/list`
compris, et donc **aussi tout outil ajouté plus tard**. Une correction outil par
outil aurait rouvert le trou au prochain ajout.

**Ce qui reste joignable sans jeton**, par conception — aucune de ces surfaces
n'expose d'outil MCP : `/acme/*` et `/v1/_sys_pki_int/acme/*` (protocole ACME),
`/pki/ca/*.pem` (chaîne de confiance publique), `/admin` et ses fichiers
statiques ainsi que le préflight `OPTIONS /admin/api/*` — **l'API
`/admin/api/*` exige toujours un jeton valide**, l'autorisation dépendant
ensuite de la route (lecture, `write`, ou `admin`) —, `/health`, `/healthz`,
`/ready`, `/` (sondes) et `/favicon.ico`. La clé `ADMIN_BOOTSTRAP_KEY` reste
acceptée (break-glass).

#### Si un client sans jeton se casse — contournement

`MCP_AUTH_MODE=bearer-anonymous` reproduit **exactement** l'ancien comportement.

> ⚠️ **Mode d'exception dangereux**, jamais un défaut. Il émet un `CRITICAL` au
> démarrage nommant ce qu'il expose, et n'exige **aucun** paramètre mission
> (JWKS, audience) — pour rester utilisable en urgence. À n'employer que le
> temps de faire migrer le client concerné.

#### Correction d'un piège latent

`MCP_AUTH_MODE != "bearer"` servait à décider « le PEP mission est-il actif ? »
en trois endroits. Cette formulation range du côté « PEP actif » **tout** mode
qui n'est pas exactement `bearer` : le mode de repli aurait exigé un JWKS et une
audience, donc aurait été inutilisable au moment précis où on en a besoin.
Remplacé par une propriété explicite `Settings.mission_pep_active`
(appartenance à `{jwt, dual-stack}`), qui ferme le piège pour tout mode futur.

**Tests** : `tests/test_bearer_auth_116.py` — 24 tests. 8 mutations mesurées,
toutes détectées. Suite : 1211 passed / 29 skipped / 0 failed.


### Disponibilité — la sauvegarde S3 ne gèle plus le coffre (issue #122, lot 2 de #110)

**Ce qui changeait pour l'exploitation.** Les appels S3 sont synchrones.
Exécutés dans la boucle d'événements, ils monopolisaient l'unique fil qui sert
**toutes** les requêtes : pendant un ralentissement du stockage, le coffre
entier ne répondait plus — la sonde de santé comprise, ce qui déclenchait des
redémarrages en cascade. L'incident de référence a duré **488 secondes**. Le
lot 1 (v0.10.1) avait ramené ce gel à quelques dizaines de secondes en bornant
les appels ; **ce lot le supprime sur les cinq chemins traités**.

Ces cinq points d'appel sont désormais exécutés hors de la boucle : la
sauvegarde (construction de l'archive **et** envoi), la restauration au
démarrage, la sonde de connectivité, et les deux opérations sur les clés
chiffrées d'OpenBao (qui portent aussi une dérivation PBKDF2 de 600 000
itérations, bloquante même quand le réseau va bien).

> ⚠️ **Le gel n'est pas éliminé partout.** Les magasins d'autorisation —
> jetons, policies, liaisons de mission, registre de wrapping — appellent
> toujours S3 de façon synchrone dans la boucle. Un stockage lent sur ces
> chemins **peut encore figer le coffre** jusqu'au lot 3 (issue #123).

**La sonde de santé ne part plus en rafale.** `system_health` déclenchait un
appel S3 à chaque invocation ; pendant une panne, chaque vérification ajoutait
un blocage. Une seule sonde réelle est maintenant en vol à la fois, les
appelants suivants s'y raccrochent, et chacun attend avec sa propre échéance.
**Aucun cache de résultat n'a été ajouté** : `system_health` doit refléter
l'état observé, pas un état vieux de quelques secondes.

**Arrêt : drainage, jamais d'annulation.** Annuler une tâche qui porte une
sauvegarde S3 en vol ne l'interrompt pas — le travail continue et peut se
terminer *après* la sauvegarde finale, publiant alors un état **plus ancien**.
L'arrêt demande donc à la boucle de sync de sortir, puis l'attend (budget de
30 s). Si le drainage n'aboutit pas, la sauvegarde finale est **abandonnée** et
un message CRITICAL le signale.

> **Perte de durabilité assumée.** Dans ce cas, la copie S3 peut rester
> périmée. Le coffre n'est pas perdu — le volume local reste l'autorité de
> reprise — mais la sauvegarde distante n'est pas à jour. C'est le prix de
> l'invariant « ne jamais écraser une archive plus récente par une plus
> ancienne ».

**Correction d'une affirmation antérieure.** Le commentaire de
`stop_grace_period` présentait 120 s comme un budget d'arrêt *couvert*. C'était
faux : quatre étapes du chemin d'arrêt n'ont aucune borne — construction de
l'archive, `seal_vault()` (appel hvac synchrone sans timeout), `stop_openbao()`
(`kill()` puis attente non bornée) et l'acquisition du verrou de sauvegarde
quand une opération PKI le détient. Le backoff botocore avec jitter n'est pas
déterministe non plus. La valeur reste un **dimensionnement**, désormais
présenté comme tel ; un dépassement — donc un arrêt forcé par Docker — reste
possible. Aucune variable d'environnement n'a été ajoutée : un validateur de
budget aurait produit une assurance fausse.

**Limite connue, non fermée.** Une opération PKI qui détient le verrou de
sauvegarde au moment de l'arrêt allonge le chemin critique au-delà du budget de
drainage, et peut donc être interrompue par Docker. Documenté plutôt que
masqué : une borne à cet endroit n'écourterait rien, puisque l'attente ne rend
la main qu'à la fin réelle du travail.

**Hors périmètre**, traité au lot 3 (issue #123) : les appels S3 des magasins
d'autorisation (jetons, policies, liaisons de mission, registre de wrapping).
Les appels **hvac** synchrones d'`initialize_vault`/`unseal_vault` restent
également hors périmètre.

**Une fois la sync arrêtée, elle ne redémarre pas avant un nouveau cycle de
vie complet.** Le
risque est toujours le même : une boucle que l'arrêt ne voit pas. Il conclurait
« tout est drainé », la sauvegarde finale partirait, et cette boucle pourrait
écrire **après** elle. Or l'arrêt du coffre ne s'achève pas avec le drainage —
viennent ensuite le seal puis la sauvegarde finale, pendant lesquels le service
rend la main. Le verrouillage est donc **définitif** et non le temps du seul
drainage. Un même processus pouvant enchaîner deux cycles de vie (scénario déjà
supporté), c'est le démarrage du coffre — et lui seul — qui rouvre la sync. Si
une boucle du cycle précédent vit encore, **le nouveau démarrage est refusé**
avant même de relancer OpenBao : cette boucle pourrait publier un état antérieur
par-dessus les écritures du nouveau cycle. Symétriquement, **un démarrage
pendant un arrêt en cours est refusé** : l'arrêt se poursuit après le drainage,
et un nouveau cycle y créerait une boucle qu'il ne drainerait jamais. La référence d'une
boucle non drainée est par ailleurs conservée : la perdre effacerait la seule
trace d'un travail encore capable d'écrire.

**Tests** : `tests/test_s3_offload_122.py` — 27 tests, preuve déterministe par
barrières (aucun seuil de performance, donc rien de fragile en CI), plus un
**contrôle de l'instrument** qui exige que le témoin détecte bien un appel resté
dans la boucle. 24 mutations mesurées, toutes détectées. Quatre tests ajoutés à
`tests/test_lifecycle.py` pour le câblage du drainage.

### RUPTURE — le shell interactif est supprimé (issue #128)

`python scripts/mcp_cli.py shell` n'existe plus. Le mode Click
(`python scripts/mcp_cli.py <commande>`) devient la **seule** surface CLI.

**Pourquoi.** Le shell analysait ses arguments à la main, seize boucles
indépendantes, une par opération. Quinze finissaient par `else: i += 1` : tout
jeton non reconnu était **ignoré en silence**. Une faute de frappe ne produisait
donc pas une erreur, mais **une opération différente de celle demandée** — sans
erreur ni avertissement. Dix défauts ont été mesurés, dont trois de sécurité :

| Saisie | Ce qui était réellement exécuté |
| --- | --- |
| `ssh setup v role --ttl "15"m --user deploy` | `allowed_users="*"` — rôle autorisant tous les principals SSH |
| `policy create no-ssh --denied ssh_*'` | motif inopérant ; liste d'autorisation vide = tout autoriser → la policy « no-ssh » autorise SSH |
| `pki setup --domains exemple.fr --prod'` | `lab_mode=True` → politique d'enrôlement ACME `not-required` au lieu de `new-account-required` |

Une tentative de correctif incrémental a été conduite puis abandonnée : neuf
tours de revue adversariale, et à chaque tour de nouveaux contournements de la
même famille. Le détail complet, les sondes et les mesures sont dans l'issue #128.

**Ce que Click apporte, mesuré sur 8.3.1** : options inconnues refusées avec
suggestion d'orthographe (`Did you mean --permissions?`), arité des positionnels
déclarés contrôlée, types validés, valeurs citées et JSON correctement transmis.
Disparaissent ainsi les défauts liés aux options non reconnues, aux valeurs
citées, au JSON en valeur et aux options placées avant les positionnels. Les
trois qui subsistent sont listés juste après — ils existent aussi sur la surface
Click, et sont suivis dans #128.

**Ce que Click n'apporte PAS** — à traiter séparément, ces défauts existent aussi
sur la surface Click : `pki setup --ttl --prod` (option consommée comme valeur),
`policy create --denied ssh_*'` (grammaire des motifs, à valider côté serveur),
`pki setup --prod --lab` (exclusion mutuelle non déclarée). Suivi dans #128.

**Aucune perte fonctionnelle** : les 50 opérations du shell ont toutes un
équivalent Click. Seules disparaissent les méta-commandes `help` et `quit`.

**Ruptures de syntaxe** — le mode Click a ses propres noms d'options :

| Shell (supprimé) | Click |
| --- | --- |
| `vault create v --desc 'X'` | `vault create v --description 'X'` |
| `secret list v prefixe` | `secret list v --prefix prefixe` |
| `password 32` | `secret password --length 32` |
| `types` | `secret types` |
| `secret wrap v p mission op 600` | `secret wrap v p --mission-id mission --operation-id op --ttl 600` |

Click est par ailleurs **plus prudent** : `vault delete`, `secret delete` et
`policy delete` demandent une confirmation, là où le shell supprimait directement.

**Confort d'utilisation** : voir `scripts/README.md`. Un alias remplace le
préfixe ; l'historique et l'édition de ligne sont ceux du terminal.

### Tests — invariants de sécurité portés, aucun perdu

Vingt-trois tests étaient propres au shell — 7 purge token, 6 purge binding,
9 expiration, 1 SSH. Chaque invariant a été vérifié avant suppression, dans le
CODE et pas seulement dans les tests :

- **`token create --expires` (contrat #65)** — la protection vit déjà côté Click
  (`_ExpiresDaysType`, un `click.ParamType` sans coercition). Trois cas
  n'étaient couverts que par le shell : valeur absente, borne valide réellement
  transmise, défaut implicite de 90 jours. **Ajoutés** à `tests/cli/test_token.py`.
- **`ssh request`** — le contrat fermé (aucun attribut de certificat libre
  transmis) est déjà verrouillé par `tests/cli/test_ssh.py` côté Click. Rien à
  porter.
- **`token purge-revoked` et `mission-binding purge`** — le code Click faisait
  bien l'aperçu avant toute purge, mais **aucun test ne le couvrait**. Les treize
  invariants sont portés dans `tests/cli/test_purge_destructive.py`, paramétrés
  sur les deux commandes.

> Une erreur relevée pendant ce portage mérite d'être consignée : le premier
> simulacre de refus de confirmation renvoyait `False`, et le test ÉCHOUAIT. Le
> code n'examine pas la valeur de retour — c'est `abort=True` qui interrompt, par
> exception. Un simulacre approximatif aurait laissé croire la purge protégée.

### Correctif au passage : `--older-than` n'accepte plus de valeur négative

`token purge-revoked --older-than -1` et son équivalent `mission-binding purge`
étaient acceptés (`type=int` sans borne). Avec la sémantique « purger ce qui est
plus vieux que N jours », une valeur négative sélectionne **tout** et contourne
la rétention demandée — l'inverse de l'intention. Les deux options sont bornées
à `>= 0`. Zéro reste accepté : c'est un choix explicite (« sans condition
d'âge »), une valeur négative n'en est pas un.

Dette préexistante, relevée pendant le portage des tests. Elle n'était couverte
par aucune surface, ni le shell ni Click.

Deux autres gardes ont été ajoutées au même endroit : le décompte de l'aperçu
doit être un **entier strictement positif** (`-1`, `True` et `"0"` passaient tous
l'ancien `if n == 0` et déclenchaient une suppression), et un échec réseau de la
purge n'est **jamais** suivi d'une reprise — après un délai d'attente ambigu, la
première requête peut déjà avoir été appliquée.

> **Limite qui demeure, à traiter côté serveur.** L'aperçu est indicatif : la
> purge ne transmet que la durée de rétention et le serveur recalcule la
> sélection. Un enregistrement devenu éligible entre l'aperçu et la confirmation
> est supprimé sans avoir été présenté. Aucune garde côté client ne ferme cette
> fenêtre ; il faudrait que la purge porte l'empreinte de l'aperçu.

### Dépendances

`prompt-toolkit` retiré de `requirements.txt`, `prompt_toolkit` et sa transitive
`wcwidth` retirées de `requirements.lock`. Vérifié : le shell en était le seul
consommateur, et aucune autre dépendance du verrou ne requiert `wcwidth`.
`typer` et `shellingham` sont **conservés** — ils viennent de `mcp[cli]`.

## [0.10.2] — 2026-08-11

### Correctif : l'image ne démarrait plus après reconstruction (issue #125)

`src/mcp_vault/server.py` importe `mcp.server.fastmcp.FastMCP`. Le Dockerfile
n'installait que `requirements.txt`, où MCP est déclaré par un **plancher**
(`mcp[cli]>=1.23.0`). Quand `mcp 2.0.0` est paru en amont — sans ce module —
toute construction fraîche a cessé de démarrer :

```
ModuleNotFoundError: No module named 'mcp.server.fastmcp'
```

Le dépôt livrait déjà `requirements.lock` (`mcp==1.26.0`), mais **aucun stage du
Dockerfile ne le consommait**.

> **Ce défaut n'a pas été introduit par la v0.10.1.** La ligne est non bornée
> depuis la v0.4.5, commit où `requirements.lock` a précisément été ajouté sans
> jamais être branché. Toute version depuis la v0.4.5, reconstruite après la
> publication de `mcp 2.0.0`, échoue à l'identique. Le déclencheur est externe.

**Correctif**

- Le **verrou fait foi** pour les versions installées : la cible `production`
  installe `requirements.lock` seul ; la cible `test` reçoit le verrou **et**
  `requirements.txt` en une invocation pip, parce que le verrou ne contient pas
  l'outillage de test (`pytest`, `pytest-asyncio`). L'image de production reste
  donc exempte de dépendances de test (durcissement P2-8 préservé).
- **Garde à la construction** : `RUN python -c "from mcp.server.fastmcp import
  FastMCP"` dans les deux stages. Une résolution incompatible fait désormais
  échouer le `build`, au lieu de se découvrir au démarrage en production.
- **Borne haute** `mcp[cli]>=1.23.0,<2` dans `requirements.txt` : le verrou
  protège l'image, cette borne protège l'installation hors Docker (venv de
  développement, où la suite est jouée avant chaque livraison). Le passage à MCP 2.x est une migration à
  part entière.
- `requirements.lock` ajouté à l'allowlist `.dockerignore` (sans quoi le `COPY`
  échouerait). Les trois dépendances qui flottaient encore, relevées en revue,
  sont épinglées : `python-dateutil` au verrou (dépendance d'exécution de
  botocore), `pluggy` et `iniconfig` dans `requirements.txt` (transitives de
  pytest). « Le verrou fait foi » ne souffre plus d'exception silencieuse, et la
  chaîne de test qui garde la release est reproductible en entier.
- Le workflow de release **dépend désormais de la CI** (`needs: verify`) :
  aucun tag ni aucune release ne sort sans validation préalable. C'est la seule
  garde technique du dépôt — `main` n'a ni protection de branche ni ruleset.
- `docker-compose.yml` et les README sont copiés dans l'image de test : le test
  de `stop_grace_period` livré en v0.10.1 n'avait jamais pu s'y exécuter.

### Intégration continue : la suite s'exécute enfin automatiquement (issue #113)

Le dépôt n'exécutait **aucun test en CI** : la qualité des releases reposait sur
des exécutions locales. Cette lacune a laissé passer deux défauts documentés —
des tests rouges vivant plusieurs versions (#98) et une image ne démarrant pas
(#125).

Nouveau workflow `.github/workflows/ci.yml`, déclenché sur `pull_request` et
appelable par `release.yml` : il construit **l'image de production livrée**,
vérifie qu'elle porte bien les versions verrouillées et qu'elle importe son
framework, **démarre le conteneur et vérifie que `/health` répond en annonçant
la version du dépôt** (critère d'acceptation de #125 : S3 injoignable, le coffre
démarre en mode dégradé, ce qui exerce au passage le chemin de lifespan rétabli
au lot 1 de #110), puis exécute la suite dans l'**image de test** — un stage
distinct, non livré, mais qui partage le même verrou et les mêmes sources. Les tests e2e
(stack complète avec WAF et S3 de recette) restent opt-in et hors CI.

Le workflow n'a délibérément **pas** de déclencheur `push: main` : il partagerait
alors son groupe de concurrence avec l'exécution appelée par la release, qui
pourrait être annulée par elle — une garde non déterministe. La publication
reste protégée par le `needs: verify` de `release.yml`, qui s'applique quel que
soit le chemin par lequel le commit est arrivé sur `main`.

### Correctif de test : le stub `hvac` divergeait de la vraie signature (issue #98)

Les exceptions du stub `hvac` (`tests/conftest.py`) étaient des `Exception`
nues, alors que le vrai `hvac.exceptions.VaultError` accepte `errors=[...]` et
expose `.errors` — attribut que la production **lit** pour distinguer un conflit
CAS d'un 400 générique (`vault/secrets.py::_is_cas_conflict`). Deux tests de #92
étaient donc rouges hors Docker, et la couverture du mapping CAS n'était jamais
exercée. Le constructeur de `VaultError` est désormais reproduit à l'identique.

### Tests

`tests/test_packaging_contract_125.py` (6 tests, sans Docker) verrouille le
contrat de reproductibilité : chaque `pip install` du Dockerfile consomme le
verrou, `requirements.txt` borne MCP sous le majeur cassant, le garde d'import
existe dans chaque stage installant des dépendances, la production n'embarque
pas l'outillage de test — et, réciproquement, **le verrou respecte toutes les
contraintes déclarées** (planchers, mais aussi la borne haute `<2` et l'égalité
`uvicorn==0.42.0`). Ce dernier point protège les garanties durement acquises
au lot 1 : `boto3>=1.38.43` porte `PutObject.IfMatch` (#121), `uvicorn==0.42.0`
porte la ré-émission du SIGTERM dont dépend le chemin d'arrêt du coffre (#110).

## [0.10.1] — 2026-08-11

### Sécurité : stabilité d'`ADMIN_BOOTSTRAP_KEY` — plus jamais d'invitation au geste irréversible (issue #121)

`ADMIN_BOOTSTRAP_KEY` chiffre l'objet S3 contenant les clés d'unseal d'OpenBao.
Deux situations à ne pas confondre :

| Situation | Récupérable ? |
|---|---|
| Mauvaise clé + objet chiffré **intact** | ✅ oui — restaurer l'ancienne clé |
| Mauvaise clé + objet chiffré **réécrit** | ❌ non — définitif |

On passait de la première à la seconde par un seul geste humain, que le produit
**suggérait lui-même** : le message « Clés unseal introuvables — Initialiser
d'abord avec `initialize_vault()` » est correct sur une installation neuve, mais
détruit l'accès aux données sur un coffre existant (l'initialisation génère de
nouvelles clés d'unseal et écrase l'objet chiffré).

- **Plus aucune invitation à initialiser quand des données existent** : le
  chemin vérifie le file backend et, s'il contient des données, refuse en
  disant explicitement quoi **ne pas** faire (ne pas initialiser, ne pas
  effacer le volume). Sonde fail-close : en cas de doute, on suppose qu'il y a
  des données.
- **Échec BRUYANT** (`UnsealKeysUnrecoverable`) au lieu du mode dégradé : un
  coffre qui ne peut pas s'ouvrir n'accepte plus de trafic, et le diagnostic
  n'est plus retardé. L'exception traverse le lifespan → uvicorn refuse de
  démarrer.
- **Message actionnable** : cause la plus probable nommée
  (`ADMIN_BOOTSTRAP_KEY` a changé), interdits explicites, indication que les
  **file backend n'a pas été modifié**, la récupération exigeant une ancienne clé correspondante **et** une copie/version intacte de l'objet chiffré (« clé incorrecte **ou** objet corrompu »),
  et renvoi vers la procédure outillée.
- **Rotation SCRIPTÉE** : `scripts/rotate_bootstrap_key.py` (avec `--dry-run`)
  exécute la seule séquence sûre — sauvegarde locale, déchiffrement avec
  l'ancienne clé, re-chiffrement, **vérification avant toute écriture**, copie
  de retour arrière horodatée sur S3, écriture, relecture et re-vérification.
  Les clés passent par l'environnement, jamais par la ligne de commande.
  L'écriture de l'objet courant est **conditionnelle** (`If-Match` sur
  l'ETag) : une modification concurrente fait échouer le PUT au lieu
  d'écraser une version plus récente. La rotation est refusée si le
  stockage ne fournit pas d'ETag ou si le SDK n'expose pas l'écriture
  conditionnelle (plancher `boto3>=1.38.43`). Le script impose le
  **test de redémarrage à froid** comme validation finale.
- Le comportement sûr existant (aucune réécriture automatique de l'objet
  chiffré après un échec de déchiffrement) est désormais **verrouillé par un
  test** — il n'était garanti par rien.

Tests : `tests/test_bootstrap_key_stability_121.py` (23 cas) — dont la
séquence du script EXERCÉE contre un faux S3 (dry-run qui n'écrit rien, ordre
copie de retour arrière → objet courant, abandon sur mauvaise ancienne clé,
abandon sur modification concurrente, échec de chaque écriture) et un
`vault_startup()` réellement traversé jusqu'à l'échec d'unseal. Les estampilles
de version des documents sont désormais liées mécaniquement à `VERSION` par
`tests/test_env_example_contract.py`.

### Contrat : `secret_revoke_wrap` ne masque plus un registre indisponible (issue #120)

Signalé par mcp-mission (leur issue #507). Quand le WrapRegistry n'est **pas
initialisé** (S3 non configuré), `secret_revoke_wrap` répondait
`{"status": "ok", "state": "not_found"}` — alors qu'**aucune révocation n'avait
été tentée**. Le contrat documentant « introuvable = succès idempotent », un
client pouvait créditer à tort une révocation ; seule une `note` non
contractuelle distinguait les deux cas.

L'outil renvoie désormais `{"status": "error",
"error_type": "registry_unavailable"}`, aligné sur `secret_wrap` et
`secret_consume` qui traitaient déjà ce cas comme une erreur. `not_found` reste
réservé au registre **consulté** (accessor inconnu ou hors périmètre, #115).
Docstrings et contrat précisés : « introuvable **dans un registre disponible**
= succès ». Comportement préexistant (≤ 0.9.2), pas une régression.


### Disponibilité : bornes réseau S3 et chemin d'arrêt réellement exécuté (issue #110, lot 1)

Premier lot du chantier #110 (« un appel S3 bloquant gèle tout le coffre,
488 s mesurées »). Ce lot **borne** l'incident et corrige un défaut d'arrêt
découvert en revue ; le retrait des appels S3 de la boucle événementielle est
traité dans les lots suivants (issues dédiées).

**1. Le chemin d'arrêt ne s'exécutait jamais sur `docker stop`**

`vault_shutdown()` (arrêt de la sync, seal OpenBao, effacement des clés
d'unseal en mémoire, sauvegarde finale S3) était appelé **après**
`server.serve()`. uvicorn ré-émet le SIGTERM qu'il a capturé une fois son
arrêt interne terminé : le code placé après l'`await` ne s'exécutait donc pas.
Conséquence en production : aucune sauvegarde finale et aucun seal explicite à
chaque arrêt ou redéploiement (l'archive S3 datait du dernier cycle
périodique, ≤ 60 s).

- L'arrêt est désormais porté par le **lifespan ASGI**, exécuté pendant la
  phase de shutdown d'uvicorn — donc avant la ré-émission du signal.
- Le lifespan est **composé** autour de celui de FastMCP
  (`session_manager.run()`), jamais remplacé : ordre
  `vault_startup → FastMCP → service → FastMCP → vault_shutdown`. Sans cette
  composition, toute requête MCP échouerait sur « Task group is not
  initialized ».
- Mode dégradé **inchangé** : `vault_startup()` qui lève ou retourne `False`
  laisse le service démarrer et force `skip_upload=True` (invariant #94 : un
  démarrage non abouti n'écrase jamais la sauvegarde S3).
- `vault_shutdown()` devient **idempotent** ; `server.main()` conserve un appel
  de secours si le lifespan n'a pas pu s'exécuter.
- `uvicorn` **épinglé** à 0.42.0 (le comportement de ré-émission du signal
  conditionne ce correctif) et `timeout_graceful_shutdown` borné
  (`UVICORN_GRACEFUL_TIMEOUT`, défaut 10 s) pour que le pré-drain des
  connexions ne consomme pas le budget d'arrêt du coffre.

**2. Appels S3 bornés**

Les deux clients boto3 étaient créés **sans timeout** (défauts : 60 s
connexion + 60 s lecture, retries « adaptive ») — c'est ce qui transformait une
lenteur S3 en gel de plusieurs minutes.

- Nouvelles clés : `S3_CONNECT_TIMEOUT` (5 s), `S3_READ_TIMEOUT` (30 s),
  `S3_MAX_ATTEMPTS` (2) — valeurs en configuration, jamais en dur ; refus de
  démarrer si une borne est nulle ou négative.
- `total_max_attempts` et non `max_attempts` : botocore compte `max_attempts`
  comme des retries **après** la tentative initiale — `S3_MAX_ATTEMPTS=2`
  signifie donc bien 2 appels réseau au total.
- Mode `standard` au lieu d'`adaptive` : sans régulation adaptative côté
  client, donc plus prévisible pendant une panne (le backoff avec jitter,
  lui, subsiste).
- Fabrique de configuration **unique** : `create_s3_clients()` (non-singleton)
  passe par le même chemin — aucun client ne peut repartir sans bornes.

**3. Délai de grâce Docker**

`stop_grace_period: 120s` déclaré explicitement pour `mcp-vault` : le défaut
Docker (10 s) tuait le processus avant le seal et la sauvegarde finale,
maintenant que l'arrêt s'exécute réellement. Le budget couvre le pré-drain
uvicorn, l'arrêt de la sync, le seal, l'effacement des clés, la sauvegarde
finale bornée et l'arrêt d'OpenBao — vérifié par un test statique du Compose.

**Effet attendu** : une panne S3 ne peut plus geler le coffre plusieurs
minutes ; l'attente est plafonnée et l'arrêt propre est restauré. Le gel
résiduel (le temps d'un appel borné) est traité par les lots 2 (#122) et
3 (#123).

⚠️ `S3_READ_TIMEOUT` est un délai d'**inactivité socket**, pas une durée
totale de transfert : une archive de plusieurs Mo n'échoue pas parce que son
transfert dépasse 30 s tant que les données progressent. Les valeurs livrées
ne constituent donc pas une borne murale stricte (le backoff des tentatives et
la compression locale ne sont pas inclus) — c'est un plafond opérationnel.

Tests : `tests/test_s3_bounds_shutdown_110.py` (20 cas — bornes des deux
clients, `total_max_attempts`, validation au boot, lifespan piloté sur la VRAIE
stack via le protocole ASGI, ordre startup/shutdown, mode dégradé, idempotence
rejouable après annulation, réarmement au nouveau cycle, délai de grâce du
Compose). Preuve RED : 20/20 échouent sur l'état pré-correctif. Suite
complète : 1122 passed / 14 skipped / 2 failed préexistants (#98).

## [0.10.0] — 2026-08-11

### Sécurité : permission dédiée non-admin `wrap` pour le broker JIT mcp-mission (issue #115)

En v0.9.2, les quatre outils du broker JIT (`secret_wrap`, `secret_revoke_wrap`,
`secret_wrap_lookup`, `secret_wrap_status`) exigeaient la permission `admin`.
Déployer le broker mcp-mission imposait donc soit un jeton administrateur global
(le flag `admin` court-circuite policies et chemins partout), soit rien. Le
correctif introduit un **quatrième flag de permission `wrap`**, non hiérarchique
et à moindre privilège strict.

**Modèle d'autorisation (nouveau)**

- Les 4 outils wrap exigent `wrap` **ou** `admin` (rétrocompatibilité : les
  jetons admin existants sont inchangés, y compris avec une policy qui ne liste
  pas ces outils — bypass admin de `check_policy` préservé).
- Chaque outil évalue désormais `check_policy(<tool>)` **avant** la permission :
  une policy applicative peut scoper les outils wrap (`allowed_tools` /
  `denied_tools`), et les identités mission JWT restent refusées
  (deny-by-default matérialisé).
- **Provisioning obligatoire pour un jeton `wrap` non-admin** (invariant
  exécutable au runtime, pas documentaire) : `allowed_resources` **non vide**
  (aucun fallback owner-based) **et** `policy_id` **non vide**, dont la policy
  porte des `allowed_tools` **explicites**. Une policy « vide » (permissive par
  défaut via `is_tool_allowed`) est refusée.
- **Évaluation stricte des chemins** pour les identités wrap non-admin
  (`PolicyStore.is_wrap_path_strictly_allowed`) : même parcours
  first-match-wins que `is_path_allowed`, mais **pas de règle matchante = refus**
  et **`allowed_paths` vide = refus**. `secret_wrap` conserve `check_access` +
  cette évaluation stricte en lieu et place du contrôle lax.
- **Verrou wrap-only** : un jeton portant `wrap` sans read/write/admin est
  confiné aux 4 outils du broker — refus sur tous les autres outils MCP
  (y compris `system_health`, `system_about`, `secret_types`,
  `secret_generate_password` et `secret_consume`) et **403 uniforme sur tout
  `/admin/api/*`** (y compris les routes historiquement « tout token » :
  health, whoami, generate-password, pki/status, pki/roles). Un composite
  (ex. `read,wrap`) n'est pas wrap-only et conserve ses droits — la SPA
  avertit explicitement à la création/édition.
- **Scoping du registre de wraps** (garde dans les primitives) :
  `secret_revoke_wrap`/`secret_wrap_lookup`/`secret_wrap_status` ne voient,
  ne comptent et ne révoquent que les entrées du périmètre de l'appelant
  (vault **et** chemins, symétrique de la création). Hors scope = `not_found`
  (aucune fuite d'existence inter-tenant), aucun appel OpenBao. La sélection
  est défensive : une entrée de registre malformée ne produit jamais
  d'exception, est invisible pour un non-admin, et n'est **jamais mutée** même
  si elle partage un accessor avec une entrée visible
  (`mark_entries_revoked` remplace `mark_revoked` sur ces chemins).
- SPA admin : la permission `read` devient décochable à la création (un jeton
  `["wrap"]` seul est créable) ; checkbox `wrap` + avertissement composite.
  CLI : aides et docstrings alignées.

**Provisioning cible du broker** (déploiement KOM-DOCKER01) :
`token create mcp-mission-broker --permissions wrap --vaults mcp-mission
--policy broker-jit`, avec une policy `broker-jit` déclarant
`allowed_tools=["secret_wrap","secret_revoke_wrap","secret_wrap_lookup",
"secret_wrap_status"]` et une `path_rule` `{vault_pattern:"mcp-mission",
permissions:["read"], allowed_paths:[<chemins provisionnés>]}`.

**⚠️ Migration / downgrade**

- Migration montante : aucun impact — les `tokens.json` existants restent
  valides, aucun jeton `wrap` n'existe avant cette version.
- **Downgrade vers ≤ 0.9.2 : un `tokens.json` contenant un jeton `wrap` est
  rejeté ATOMIQUEMENT** par la whitelist de l'ancienne version (fail-close) :
  après redémarrage, **tous les bearers sont inutilisables** (seule la clé
  bootstrap admin survit). Procédure de downgrade : **révoquer puis purger les
  jetons `wrap`**, vérifier `_system/tokens.json`, et seulement ensuite
  redéployer l'ancienne version. À chaud, l'ancienne version conserve son
  cache mémoire précédent après invalidation (limitation existante,
  documentée — pas un fail-close absolu).

Complément (revue pré-commit) : **fail-close destructif du registre** — après
un refresh S3 en échec, `secret_revoke_wrap`/`secret_wrap_lookup` refusent
(`backend_unavailable`, le broker retente) au lieu d'opérer sur un cache
ambigu dont le `_save` last-write-wins écraserait un état S3 plus récent
(durcit un comportement préexistant) ; verrou wrap-only étendu aux deux outils
SSH opérateur (`ssh_operator_access_profiles`, `ssh_request_operator_access`)
en défense à la porte.

Tests : `tests/test_wrap_permission_115.py` (matrice permissions × policy ×
scoping registre × REST, 49 cas collectés), harnais historiques adaptés
(identité admin explicite via ContextVar — un contexte absent n'est JAMAIS
traité comme admin). Preuve RED rejouée : 41 cas échouent sur l'état
pré-correctif, 8 tests de non-régression passent, 49/49 verts avec le fix.

## [0.9.2] — 2026-07-27

### WAF : faux positif CRS 930120 sur `POST /mcp` (issue #107)

Signalé en production sur la v0.8.6 (`ebcfd35`) : un `secret_write` légitime émis
par un client Codex recevait `HTTP 403` **avant** le handler MCP. Aucune trace
dans l'audit Vault, aucun refus d'authentification ni de policy — le blocage
venait entièrement de Coraza, sur la règle CRS 930120 « OS File Access Attempt ».

**La cause racine n'était pas celle supposée.** Le signalement initial attribuait
le `.env` détecté dans `ARGS_NAMES` à l'aplatissement des métadonnées Codex
(`params._meta.x-codex-turn-metadata`). L'observation était juste, l'explication
non. Reproduction sur Coraza 3.3.3 / CRS 4.7.0 réel : **Coraza ne parsait pas du
tout le corps JSON**. Faute de `ctl:requestBodyProcessor=JSON`, le processeur
`URLENCODED` s'appliquait au JSON-RPC et le **corps entier** devenait **une seule
variable**, à la fois nom et valeur :

```
ARGS_NAMES:{"jsonrpc": "2.0", "method": "tools/call", "params": {…}}
```

Mesuré à exactement **1** `ARGS_NAMES` et **1** `ARGS` pour tout le corps. Deux
conséquences :

1. **Faux positifs massifs.** Toute chaîne de `lfi-os-files.data` présente
   *n'importe où* dans le corps — y compris dans une **valeur de secret** —
   déclenchait 930120 (score 5) puis 949110. `.env` figure ligne 36 de ce
   fichier. Le blocage n'avait donc rien à voir avec Codex : le déclencheur était
   la note `« Bucket à confirmer avant matérialisation du .env. »` dans le
   payload. Corollaire : le type de secret **`env_file`** (« Fichier .env ») était
   structurellement inutilisable à travers le WAF.
2. **Aucun scoping fin possible.** Avec une seule cible, on ne peut pas
   distinguer un nom d'argument d'une valeur — toute exclusion aurait été large.

**Correctifs (`waf/coraza.conf`)**

- **Règle 10008** — active le parseur JSON, chaîné sur `POST` + chemin ancré
  `^/mcp(?:[/?]|$)` + `Content-Type` `(?:^|,)[ \t]*application/json[ \t]*(?:[;,]|$)`, avec
  `ctl:requestBodyLimit=65536` pour borner le coût du parseur. Restaure la granularité réelle
  (`json.params.arguments.data.notes`, `json.params.arguments.path`, …) et
  **renforce** la détection : 930100/930110 (path traversal) se déclenchent
  désormais sur `path`, ce qui n'était pas le cas auparavant. `/admin/api`, PKI
  et ACME conservent exactement leur comportement (corps non parsé).
- **`SecRuleUpdateTargetById 930120 "!ARGS_NAMES:/^json\.params\._meta\./"`** —
  l'aplatissement JSON de Coraza concatène les clés avec un point : une clé
  `environment` produit donc `.env` dans le *nom* d'argument
  (`…x-codex-turn-metadata.environment.cwd`). Ce faux positif n'existait pas
  avant l'activation du parseur ; il est corrigé en même temps. Portée : les
  **noms** seuls — les valeurs sous `_meta` restent inspectées.
- **`SecRuleUpdateTargetById 930120 "!ARGS:/^json\.params\.arguments\.data\./"`** —
  `secret_write(data: dict)` est aujourd'hui le seul outil MCP recevant une
  charge opaque. Ce contenu est transmis à OpenBao, qui le chiffre **au repos** ;
  mcp-vault ne l'interprète jamais comme chemin, requête SQL ou commande. Portée :
  les **valeurs** de ce sous-arbre seulement.
  *Honnêteté du scoping* : le WAF ne connaît pas le schéma des outils. Le
  sélecteur porte sur le chemin JSON `params.arguments.data.*`, **pas** sur
  `params.name == "secret_write"`. La propriété repose donc sur l'état actuel des
  signatures d'outils, pas sur une garantie du WAF.

**Sémantique de placement.** Les deux mécanismes sont inverses et les confondre
rend l'exclusion silencieusement inopérante : `ctl:ruleRemoveById` agit sur la
transaction et doit **précéder** l'Include CRS (leçon de #42) ;
`SecRuleUpdateTargetById` modifie la définition de la règle et doit donc la
**suivre**. `ctl:ruleRemoveTargetById`, qui aurait permis un scoping par URI, a
été écarté : vérifié sur Coraza 3.3.3, sa forme **regex** de cible n'est pas
supportée, et les clés de métadonnées client sont arbitraires.

### Anti-évasion des exclusions `json.*` — corrigé après revue indépendante

La première version de ce correctif affirmait que les exclusions statiques
étaient « limitées à `POST /mcp` par construction, puisque les variables `json.*`
n'existent que là où le parseur JSON a tourné ». **Cette affirmation était
fausse**, et la revue adversariale l'a relevée comme bloquante.

`ARGS` et `ARGS_NAMES` agrègent aussi les paramètres de **query string** et de
**formulaire**, dont le nom est choisi par le client. Mesuré sur Coraza réel avant
correction :

```
GET /health?json.params.arguments.data.x=.env   → 200   ← évasion
GET /health?legit=.env                          → 403   ← témoin
POST /admin/api (formulaire, nom forgé)         → 200   ← évasion
```

Autrement dit, n'importe qui pouvait neutraliser la règle 930120 **sur tous les
endpoints** en nommant son paramètre `json.params.arguments.data.<quelconque>`.

Deux gardes rendent désormais le préfixe **inatteignable** au lieu de le supposer :

- **10009** refuse tout nom de paramètre préfixé `json.` en query string, sur
  tous les endpoints — aucun client légitime n'en produit (le transport MCP
  Streamable HTTP place tout dans le corps, et l'authentification est Bearer-only).
- **10010** refuse tout nom `json.*` lorsque le corps n'a **pas** été analysé en
  JSON, via un drapeau `tx.mcp_json_body` posé côté serveur — donc non forgeable.

Deux pièges rencontrés et corrigés au passage :

- une `SecRule TX:<var>` dont la variable **n'existe pas** ne s'évalue pas du tout
  (aucune variable à tester → aucun match → la chaîne ne se termine jamais). Sans
  initialisation explicite du drapeau à `0`, la garde 10010 était silencieusement
  inopérante — constaté par mesure, pas par relecture ;
- `@beginsWith /mcp` matcherait aussi `/mcpfoo`. Le déclencheur du parseur est
  désormais ancré (`^/mcp(?:[/?]|$)`) et son `Content-Type` aligné sur ce que
  FastMCP accepte réellement.

`SecRequestBodyLimitAction Reject` est rendu explicite : un corps dépassant la
limite est refusé, jamais analysé partiellement — une analyse partielle laisserait
sa fin non inspectée, risque accru depuis l'activation du parseur.

### Montée du WAF exigée par le correctif — coraza-caddy v2.2.0 → v2.5.0

Le correctif ne peut pas être livré sur le WAF précédent. L'activation du parseur
JSON — indispensable au scoping fin — exposait un **DoS critique non authentifié**
sur `POST /mcp`. Le parseur de coraza 3.3.3
(`internal/bodyprocessors/json.go`, `readItems()`) récurse **sans plafond de
profondeur**, avec un « TODO add some anti DOS protection » en commentaire, et
alloue une clé de map par niveau : coût quadratique.

Mesures sur conteneur aux limites de production (512 Mo / 1 CPU), corps
`[`×N + `0` + `]`×N — JSON valide, **2 octets par niveau** :

| Corps | `HEAD` (sans parseur) | coraza 3.3.3 + parseur | coraza 3.7.0 + limites |
| --- | --- | --- | --- |
| 3,9 Ko (prof. 2 000) | 39 ms | **24 035 ms** | 400 en 11 ms |
| 15,6 Ko (prof. 8 000) | 82 ms | **timeout > 60 s** | 400 en 6 ms |
| 31,3 Ko (prof. 16 000) | 162 ms | connexion coupée | 400 en 5 ms |
| 64,0 Ko (prof. 32 767) | 323 ms | connexion réinitialisée | 400 en 10 ms |
| **État du WAF** | vivant | **`OOMKilled: true`** | vivant |

Une requête **non authentifiée de 15 Ko** suffisait à éteindre le WAF — et quand
le WAF tombe, le coffre devient inaccessible. Attribution vérifiée : le même
vecteur coûte 39 à 323 ms sur `HEAD`, sans aucun OOM.

Contre-mesures évaluées et écartées, toutes mesurées :

- `ctl:requestBodyLimit=65536` (borne en **octets**, supportée en 3.3.3) :
  inopérante, le vecteur tient intégralement sous 64 Ko ;
- filtrage du corps **avant** le parseur : impossible en seclang, le corps n'est
  disponible qu'en phase 2, après traitement ;
- `ctl:ruleRemoveTargetById=930120;ARGS` + `;ARGS_NAMES` **sans** parseur JSON :
  ne corrige pas le faux positif — la forme « collection nue » n'est pas prise en
  compte, comme la forme regex.

`SecRequestBodyJsonDepthLimit` n'existe qu'à partir de **coraza v3.4.0**. D'où la
montée dans `waf/Dockerfile` : `coraza-caddy/v2@v2.2.0` → **`v2.5.0`**, qui
embarque **coraza v3.7.0**. L'image de build épinglée fournit Go 1.26.1, au-delà
du Go 1.25.0 requis. CRS reste en 4.7.0 pour borner le périmètre.

### Le piège : la limite de profondeur seule crée une évasion silencieuse

`SecRequestBodyJsonDepthLimit 32` supprime le DoS, mais **échange un défaut contre
un autre** si elle est posée seule. Au-delà du seuil, coraza cesse d'alimenter
`ARGS` et le corps n'est plus inspecté du tout. Mesuré avec la seule limite :

| Charge enfouie à 40 niveaux | Sans la règle 10011 | Avec la règle 10011 |
| --- | --- | --- |
| LFI `../../etc/passwd` | **200 — passe** | 400 |
| SQLi `1 OR 1=1 --` | **200 — passe** | 400 |
| XSS `<script>alert(1)</script>` | **200 — passe** | 400 |
| RCE `; cat /etc/passwd` | **200 — passe** | 400 |
| Les mêmes à 31 niveaux | 403 | 403 |

Autrement dit, la limite seule offrait à un attaquant une primitive d'évasion
totale : imbriquer sa charge au-delà du seuil. coraza 3.7.0 expose heureusement la
condition — `REQBODY_ERROR=1`, message « JSON: max recursion reached while reading
json object ». La **règle 10011** refuse donc explicitement (400) tout corps que le
WAF déclare non analysable, sur la seule surface concernée (`tx.mcp_json_body`).

Un corps JSON qu'un WAF ne peut pas inspecter n'atteint pas l'application. Note
d'honnêteté : cette règle avait été proposée dès le premier round de revue puis
écartée sur mesure, parce que coraza 3.3.3 ne levait **jamais** `REQBODY_ERROR`.
L'intuition était juste pour la configuration montée, pas pour l'ancienne.

### ⚠️ Nouvelle limite de compatibilité — profondeur d'imbrication d'un secret

Le seuil de 32 est très large au regard de l'enveloppe MCP : la plus profonde
légitime atteint 5 niveaux (`params._meta.x-codex-turn-metadata.environment.cwd`)
et le payload de secret 4 (`params.arguments.data.<champ>`).

Il constitue néanmoins un **changement de contrat visible** : `secret_write(data: dict)`
acceptait côté application une imbrication arbitraire. Un secret dont la valeur est
elle-même une structure JSON dépassant ~28 niveaux d'imbrication interne reçoit
désormais **HTTP 400** au niveau du WAF. Testé aux deux bords : `data` imbriqué à
20 niveaux passe, à 60 niveaux est refusé.

Aucun usage connu n'approche cette profondeur — les types de secrets du produit
sont des dictionnaires plats de champs texte. La limite est documentée ici parce
qu'elle est arbitrable : elle se règle par `SecRequestBodyJsonDepthLimit` dans
`waf/coraza.conf`, et la relever réaugmente proportionnellement le coût plafond du
parseur.

`ctl:requestBodyLimit=65536` et `SecRequestBodyLimitAction Reject` sont conservés :
ils bornent le coût de l'évaluation CRS sur les gros corps, indépendamment de la
profondeur. Un corps MCP au-delà de 64 Ko reçoit un **413** en 1-3 ms. 64 Ko est
généreux — un `secret_write` portant un certificat TLS avec sa chaîne et sa clé
privée pèse ~10-15 Ko, un contenu `env_file` quelques Ko, une clé publique SSH
moins d'1 Ko.

### Défaut préexistant, tracé séparément

Le DoS par **gros corps** est antérieur au correctif et concerne **toutes** les
surfaces : sur la configuration actuellement en production, sans aucun parseur
JSON, une seule requête de 2,9 Mo coûte **20,4 s** de CPU en évaluation CRS.
`SecRequestBodyLimit` vaut 10 Mo, valeur inadaptée à ce produit. Hors périmètre de
cette issue.

**Ce qui reste bloqué** (vérifié par test, non par raisonnement) : `.env` dans
`path`, dans `tags`, dans le nom d'outil, et dans une **valeur** sous `_meta` ;
traversal dans une valeur **et** dans un nom sous `data.*` ; noms `json.*` forgés
en query string ou en formulaire ; corps JSON tronqué ou très imbriqué contenant
une LFI. Exclure 930120 des valeurs de `data.*` n'ouvre pas de LFI : 930100,
930110 et 932160 y restent actives. En revanche un simple nom de fichier sensible
**sans** traversal n'y est plus détecté : c'est l'effet recherché.

**Constat contraire à une hypothèse de revue** : la revue suspectait qu'une erreur
du parseur JSON crée un angle mort non bloquant (`REQBODY_ERROR`). Mesure sur
Coraza 3.3.3 : aucune variable `REQBODY_ERROR` n'est levée sur JSON malformé. Le parseur est
**permissif** (`gjson.Parse` ne remonte pas d'erreur de syntaxe) : un corps
tronqué est partiellement extrait et la détection subsiste — un corps tronqué
contenant `/etc/passwd` est toujours refusé (403). Le mécanisme redouté n'existe pas dans
cette version ; aucune règle n'a été ajoutée pour une condition inatteignable, et
la propriété qui compte est verrouillée par test.

> **Note de comptage.** Les README annonçaient « 312 assertions e2e » ; le décompte
> réel avant ce correctif était de **304** : le chiffre documenté était donc déjà inexact.
> Il est corrigé à **349** (304 + 45), et le total de la section 15 passe de **17 à 62**. Méthode reproductible : comptage AST des appels à
> `check` / `check_true` / `check_value` / `check_traversed` dans les fonctions `test_*`,
> avec expansion des boucles littérales, les helpers locaux étant comptés à l'appel.

### ⚠️ Correction d'un piège de conception dans les tests eux-mêmes

Le premier jet de cette suite comportait un défaut que seule l'exécution sur la
stack complète a révélé : trois assertions différentielles **passaient au vert sans
rien vérifier**.

Le mécanisme : sur la stack réelle, un `POST /mcp` hors session MCP reçoit **400**
de l'application (« Missing session ID ») — et la nouvelle règle WAF 10011 refuse
elle aussi en **400**. Comparer « déclencheur == référence » avec les deux à 400
revenait donc à comparer deux échecs et à conclure au succès. L'exclusion des
erreurs réseau et des 5xx ne couvrait pas ce cas, qui est précisément le cas réel.

Correction : un discriminateur `waf_blocked(status, corps)` tranche sur le **corps**
et non sur le code seul — un blocage Coraza renvoie un corps **vide** sans
`Content-Type`, l'application répond toujours en JSON. Le même code 400 donne
désormais deux verdicts opposés, ce qui prouve que l'assertion travaille :

```
Secret 'data' imbriqué à 20 niveaux : non bloqué par le WAF — status=400, bloqué WAF=False
Secret 'data' imbriqué à 60 niveaux : bloqué par le WAF     — status=400, bloqué WAF=True
```

Deux autres assertions étaient fausses par hypothèse : elles attendaient **200** sur
`/pki/ca/root.pem` et `/acme/directory`, alors qu'un coffre dont la PKI n'est pas
initialisée renvoie légitimement **403** applicatif. Elles vérifient maintenant
l'absence de blocage WAF, pas un code de retour.

Enfin, la preuve du faux positif ne repose plus seulement sur des POST bruts : elle
passe par une **vraie session MCP** reproduisant l'appel refusé en production.

**Tests** — 45 vérifications ajoutées au test WAF e2e (`test_15_waf_security`,
sections 15a / 15h / 15h-bis / 15h-quater / 15h-quinquies / 15h-sexies /
15h-septies / 15h-ter), portant la section de **17 à 62 assertions**, toutes exécutées à travers Caddy + Coraza. Le cœur est un **test
différentiel** : deux requêtes ne différant que par la présence de `.env` doivent
recevoir un traitement identique, non-403, non-erreur réseau et non-5xx — la
triple exclusion évite qu'une égalité obtenue par double échec ne soit prise pour
un succès. Rejoué contre `HEAD` pré-correctif : 16 PASS / 2 FAIL. Après
correctif : 18 PASS / 0 FAIL. Banc étendu : 33/33 sondes conformes, et les deux
vecteurs d'évasion ci-dessus passés de 200 à 403.

## [0.9.1] — 2026-07-25

### Contrat `.env.example` réparé et rendu déterministe (issue #100)

La v0.9.0 publiait un `.env.example` dont la ligne 46 contenait littéralement
`***REMOVED***` : séquelle d'une réécriture d'historique `git-filter-repo`
(incident d'exposition de credentials) qui avait détruit l'assignation
`ADMIN_BOOTSTRAP_KEY=` en laissant orphelin son bloc de documentation. Une
plateforme de déploiement externe a refusé de builder la release — à juste titre,
le fichier n'était pas un contrat dotenv exploitable.

**Pourquoi le défaut a survécu huit versions.** Il ne produisait aucun crash
visible : `python-dotenv` accepte `***REMOVED***` comme un *nom de clé* (son motif
est `([^=\#\s]+)`, sans exigence POSIX) avec la valeur `None`, et
`pydantic-settings` absorbe ensuite l'entrée via son filtre de valeurs falsy.
Aucune `ValidationError` n'était donc levée en local. Côté consommateur, les deux
rendus possibles cassent pourtant le déploiement : rendre l'entrée avec une valeur
non vide déclenche `extra_forbidden` (`Settings` est en `extra="forbid"`), et ne
pas la rendre laisse `ADMIN_BOOTSTRAP_KEY` à son défaut `change_me_in_production`,
que `validate_bootstrap_key()` rejette — le service fait alors `sys.exit(1)`.

- **`ADMIN_BOOTSTRAP_KEY=REQUIRED`** remplace la ligne détruite. L'identification
  ne repose pas sur une supposition : c'est la seule variable du groupe
  « Authentification », le seul champ de `Settings` dont le défaut interdit le
  démarrage, et un blob `.env.example` d'avant la réécriture (encore présent dans
  l'historique non atteignable) porte la ligne intacte avec le même bloc de
  commentaire. Le marqueur `REQUIRED` échoue **volontairement** la validation : une
  plateforme qui livrerait le contrat sans substitution obtient un refus de
  démarrage explicite et actionnable, jamais une clé faible acceptée en silence.
- **Contrat désormais exhaustif dans les deux sens** : 18 assignations actives
  + 23 déclarations commentées = **41 clés, exactement les 41 champs de
  `Settings`**. `MCP_SERVER_DEBUG`, qui n'avait jamais été documentée, est ajoutée.
- **Déterminisme en clés ET en valeurs.** Le fichier était lu différemment selon
  la permissivité de l'extracteur, et de deux façons distinctes.
  - *Clés fantômes* : de la prose comme `# Vide = ...`, `# jwt = ...`,
    `# true = ...` était lue comme une assignation par un extracteur tolérant
    (clés inexistantes `Vide`, `jwt`, `true`) ; `(leeway=0)` et `ENFORCE=true` par
    un extracteur naïf (`leeway`, `ENFORCE`). Rendues avec une valeur non vide,
    ces clés font échouer le démarrage.
  - *Valeurs contradictoires* — plus insidieux, car le jeu de clés restait
    correct : de vraies clés apparaissaient aussi en milieu de phrase avec une
    autre valeur. `ENFORCE_MISSION_TOKEN_VALIDATION=true` (2 occurrences) alors
    que la déclaration documentée porte `false`, et `MCP_AUTH_MODE=jwt/dual-stack`
    (2 occurrences), qui n'est même pas une valeur valide. Un extracteur
    « dernier gagnant » **activait donc l'enforcement JWT au lieu du défaut**.
  Les onze occurrences sont reformulées (citation d'une variable sans le signe
  égal). Les trois variantes d'extracteur renvoient maintenant les mêmes 41 clés
  **avec les mêmes valeurs**, chaque clé n'étant extractible qu'une seule fois.
- **Variables CLI retirées du contrat.** `VAULT_WRAP_TOKEN` et
  `VAULT_MISSION_TOKEN` ne sont pas des champs de `Settings` : les déclarer, même
  commentées, exposait un extracteur à les activer et à casser le démarrage. Le
  groupe 8 devient de la documentation pure, sans aucune assignation, et renvoie
  vers `scripts/README.md`.
- **En-tête corrigé** : il annonçait 7 groupes alors que le corps en comptait 8
  depuis l'insertion du groupe WAF, avec une numérotation décalée d'un cran. Un
  bloc « Contrat dotenv » documente désormais explicitement les conventions
  (marqueur `REQUIRED`, sens des lignes commentées, effet de `extra="forbid"`).

### Sécurité — valeur de bootstrap key exploitable publiée dans la documentation

`DESIGN/mcp-vault/ARCHITECTURE.md` §9 proposait, pour `ADMIN_BOOTSTRAP_KEY`, une
valeur d'exemple de 40 caractères (`change_me_to_a_strong_random_key_64chars`) qui
**passe** `validate_bootstrap_key()` : un opérateur qui copiait le bloc démarrait
un vault de production dont la clé de chiffrement des clés unseal est publiée dans
le dépôt, sans que le fail-fast ne le protège. Le bloc §9 était
par ailleurs un instantané périmé de 27 clés dont **9 inexistantes** dans
`Settings` (`OPENBAO_BINARY`, `OPENBAO_LISTEN_ADDRESS`, `OPENBAO_LOG_LEVEL`,
`S3_SYNC_INTERVAL`, `S3_SYNC_STRATEGY`, `S3_SYNC_ON_SHUTDOWN`, `SSH_CA_ENABLED`,
`SSH_CA_DEFAULT_TTL`, `SSH_CA_MAX_TTL`) — le copier produisait un `.env` refusé au
démarrage. C'est la même classe de défaut que la ligne 46, dans un autre fichier.

- Bloc §9 remplacé par un exemple **minimal et correct** (17 clés, toutes
  réelles, `ADMIN_BOOTSTRAP_KEY=REQUIRED`), précédé d'un encadré désignant
  `.env.example` comme **source unique** du contrat. Le duplicata qui dérivait
  est supprimé plutôt que resynchronisé.

### `.dockerignore` — le contexte de build n'expose plus le `.env` de l'opérateur

Le dépôt n'avait aucun `.dockerignore`. Le service `mcp-vault` construit avec
`context: .` : l'intégralité du répertoire, **`.env` réel inclus**, était
transmise au démon Docker. `.gitignore` ne protège que Git, pas le contexte de
build.

Ajout d'un `.dockerignore` construit en **allowlist** : tout est exclu par `*`,
puis seuls les chemins réellement copiés par le Dockerfile sont ré-inclus
nominativement. Une denylist aurait dû énumérer ce qui est dangereux et laissé
passer tout l'imprévu — un `id_rsa`, un `.ssh/`, un `.aws/credentials`, un secret
sans extension. Avec une allowlist, oublier une entrée fait échouer le build,
bruyamment : c'est le bon sens de l'erreur. Un test verrouille cette forme, pas
seulement la présence du fichier.

Vérification du contexte réellement transmis au démon (et non du seul contenu de
l'image, qui ne prouve pas la même chose) : il contient exactement les dix chemins
de l'allowlist, et la recherche de `.env`, `*.pem`, `*.key`, `id_rsa*`, `.ssh`,
`.aws` et `.git` y revient vide.

### Tests — la classe de défaut est fermée, pas seulement le symptôme

Nouveau fichier `tests/test_env_example_contract.py`, **25 tests non
complaisants**. Aucun test n'exerçait `.env.example` jusqu'ici, ce qui explique
que la dérive n'ait jamais été détectée.

- parsabilité stricte intégrale (0 ligne malformée) ;
- **validité du classificateur lui-même** — un classificateur laxiste rendrait le
  test précédent vert à vide ; il doit rejeter `***REMOVED***`, `export KEY=x`,
  `1BAD=x`, `KEY =x`, `CLÉ=x`, `"KEY"=x`, `=orphan`, `KEY : x` ;
- bijection stricte entre clés documentées et champs de `Settings`, dans les deux
  sens, avec vérification préalable de l'absence d'alias et d'`env_prefix` ;
- ligne littérale `ADMIN_BOOTSTRAP_KEY=REQUIRED` épinglée, et refus de toute
  double déclaration ;
- **unicité d'extraction** : chaque clé n'apparaît qu'une fois sous une forme
  extractible — y compris en milieu de phrase, angle que la première version de ce
  fichier manquait puisque son motif était ancré en début de ligne ;
- absence de clé fantôme sous extracteur tolérant **et** naïf ;
- `validate_bootstrap_key("REQUIRED")` doit rester **False** avec un message
  citant la longueur minimale, **et `create_app()` doit lever `RuntimeError`** sur
  le marqueur non substitué — le validateur seul ne prouvait pas que le vrai point
  d'entrée refuse de démarrer. Ce test porte sa contre-épreuve : avec une clé forte
  substituée, `create_app()` doit réussir, sinon il passerait pour de mauvaises
  raisons ;
- absence de matière secrète : valeurs littérales des clés sensibles épinglées,
  liste de préfixes fournisseur (`hvs.`, `hvb.`, `AKIA`, `ASIA`, `-----BEGIN`), et
  heuristique de forme à trois motifs — casse mixte, hexadécimal long, et token
  long à casse unique. Les deux derniers motifs viennent d'un constat de revue :
  une clé hex de 64 caractères n'a que deux classes et échappait au premier. Le
  test du détecteur épingle explicitement la **complémentarité** des mécanismes,
  aucun ne suffisant seul ;
- portabilité d'encodage (BOM, CRLF, tabulations, newline finale, espaces de fin) ;
- **rendu exécutable** : le contrat est rendu depuis la sortie du classificateur
  strict, le marqueur substitué, puis chargé dans `Settings` — et le test échoue
  si une ligne malformée subsiste, pour que supprimer la ligne 46 ne suffise pas
  à le rendre vert. Ce test prouve la *chargeabilité*, pas le démarrage : la
  preuve de démarrage est le test Docker `/health` ;
- refus d'une clé inconnue à valeur non vide — avec la nuance mesurée : une clé
  inconnue à valeur **vide** passe, ce qui est précisément pourquoi
  `***REMOVED***` restait invisible ;
- aucun bloc de configuration de la documentation ne déclare de variable
  inexistante, et aucune valeur de bootstrap key publiée dans la documentation ne
  passe la validation. Le périmètre est dérivé de l'arborescence plutôt que d'une
  liste codée en dur — est étranger tout `DESIGN/<service>/` dont le nom n'est pas
  `mcp-vault` —, si bien qu'un nouveau document mcp-vault est couvert
  automatiquement et qu'un nouveau service est exclu automatiquement ;
- **forme du `.dockerignore`** : la première règle effective doit être `*` (donc
  une allowlist), et chaque chemin copié par le Dockerfile — extrait du Dockerfile
  lui-même, pour que la liste ne puisse pas se désynchroniser — doit être
  ré-inclus ;
- cohérence du `LABEL version` du Dockerfile avec `VERSION`, et présence d'une
  section CHANGELOG non vide pour la version courante (la CI de release en extrait
  les notes ; un en-tête mal formé produisait des notes dégradées en silence).

### Corrections de cohérence de version et de documentation

- **`Dockerfile`** : `LABEL version` était figé à `0.8.0` depuis sept versions —
  les métadonnées de l'image de production mentaient sur la version livrée.
  Désormais aligné sur `VERSION` et verrouillé par un test.
- **Stage `test` du Dockerfile** : copie `.env.example` et `DESIGN/`, nécessaires
  aux tests de contrat, pour qu'ils soient exécutables en conteneur comme sur
  l'hôte.
- **Tableaux des variables d'environnement des deux README** : ils omettaient 9
  champs (`MCP_SERVER_HOST`, `MCP_SERVER_DEBUG`, `MCP_ALLOWED_ORIGINS`,
  `WAF_PORT`, `OPENBAO_DATA_DIR`, `OPENBAO_CONFIG_DIR`,
  `MISSION_JWKS_MAX_REFRESH_PER_MIN`, `MISSION_TOKEN_LEEWAY_SECONDS`,
  `MISSION_STATUS_CACHE_TTL`) et qualifiaient S3 et OpenBao d'« obligatoires »
  alors que toutes ces variables ont un défaut. Les 41 variables sont désormais
  listées, et la seule réellement obligatoire au démarrage —
  `ADMIN_BOOTSTRAP_KEY` — est identifiée comme telle. La ligne S3 énonce la
  conséquence réelle, mesurée pendant la qualification de cette release : le
  processus démarre sans S3, mais en **mode dégradé** — les stores restent en
  mémoire et, sur un volume vierge, la tentative de restauration échoue de façon
  ambiguë, ce qui empêche OpenBao de démarrer. S3 est donc requis pour un
  déploiement fonctionnel, ce que la formulation précédente (« Obligatoire :
  Oui », sans explication) n'expliquait pas et que la première rédaction de ce
  correctif énonçait de façon incomplète.
- **`TECHNICAL.md`** : l'entrée `ADMIN_BOOTSTRAP_KEY` du tableau annonçait
  `change_me_in_production` comme défaut, sans dire que cette valeur est
  explicitement rejetée au démarrage.

**Périmètre du changement** : aucune modification de `src/`, donc **aucun
changement de logique métier**. Changent en revanche — et il serait malhonnête de
l'écrire autrement : la version exposée par `/health` et par la bannière de
démarrage (`0.9.0` → `0.9.1`, lue depuis `VERSION` à l'exécution), les métadonnées
`LABEL` de l'image, le périmètre du contexte de build, et le contenu de l'image de
test.

## [0.9.0] — 2026-07-23

### Bearer opérateur SSH JIT à durée bornée (issue #96, 2026-07-23, suite revue round 8)

Suite au retrait de l'exigence FIDO2 (entrée ci-dessous), le bearer token
devient la SEULE autorité d'émission de ce parcours. La revue adversariale
Codex a jugé, à raison, que rien ne bornait techniquement sa durée de vie —
`TokenStore` supporte explicitement `expires_in_days=0` (jamais expirer,
fonctionnalité assumée, issue #65), et aucun garde ne l'interdisait pour ce
parcours privilégié. Décision de Christophe : une expiration bornée est un
compromis acceptable, on reste simple pour la v1.

- **Nouveau plafond** : `SSH_OPERATOR_JIT_MAX_BEARER_EXPIRES_DAYS` (défaut 1
  jour — la plus petite granularité que `TokenStore.create()` puisse
  exprimer, conforme à la recommandation de la revue). Un bearer sans
  expiration, ou dont le temps restant avant expiration dépasse ce plafond,
  est refusé sur ce parcours — quelles que soient ses autres permissions.
  Contrôlé au point d'usage (`ssh_operator.py::_current_operator_identity()`),
  pas seulement à la création : `TokenStore.update()` ne peut de toute façon
  pas modifier l'expiration d'un token existant (immuable après création),
  donc ce contrôle ferme le trou quel que soit le moment où la policy
  `operator-ssh-jit` a été attachée au bearer.
- **Révocation multi-instance — limitation assumée, pas fermée dans ce lot** :
  la revue a aussi relevé que le cache TokenStore (300s) peut rendre une
  révocation invisible sur une autre instance jusqu'au prochain rafraîchissement.
  Ce projet a déjà, à deux reprises (PolicyStore Lot 3, TokenStore hardening),
  traité les races multi-instance sur les stores S3 comme une limitation
  connue et différée (#51/#13) plutôt que de construire une synchronisation
  distribuée. Décision : même doctrine ici, pour une première mise en
  production **mono-instance** — c'est explicitement l'alternative proposée
  par la revue elle-même (« mono-instance stricte OU révocation distribuée
  fiable »). Aucun nouveau code de cache-invalidation inter-instances n'est
  ajouté ; ce choix est documenté ici et dans `ARCHITECTURE.md` §6.3b plutôt
  que laissé implicite.
- **Nettoyage** : 3 vestiges du format de clé FIDO2 (`sk-*@openssh.com`) que
  le premier balayage terminologique avait ratés car ils ne contenaient pas
  le mot « FIDO2 » — une section de `TECHNICAL.md` distincte de §3.10b,
  un second message d'aide dans `scripts/cli/shell.py`, et les chaînes
  d'exemple de `tests/js/operator_ssh_jit_contract.test.js` et
  `tests/cli/test_ssh.py`.
- **Tests** : 3 nouveaux tests non-complaisants (bearer sans expiration
  refusé, bearer au-delà du plafond refusé, bearer exactement au plafond
  accepté), 2 sabotages RED→GREEN.
- **Revue Codex round 9 (commit `05b8240`) : GO**, avec 2 findings BASSE
  corrigés dans la foulée :
  - Le garde d'expiration ne se fiait qu'implicitement au fait que
    `TokenStore.get_by_hash()` fail-close déjà sur un bearer expiré/à
    l'horodatage naïf en amont — un `expires_at` sans fuseau levait
    `TypeError` au lieu d'un refus propre, et une date déjà passée
    n'était pas revalidée si un contexte était injecté directement (pas
    de chemin d'exploitation distant identifié, mais défense en
    profondeur incomplète). Corrigé : le garde revalide lui-même
    `tzinfo` et la non-péremption, indépendamment de TokenStore.
  - Le test « exactement au plafond » n'était PAS probant : il comparait
    quelques microsecondes après avoir calculé l'échéance, donc le temps
    restant au moment du contrôle était déjà légèrement inférieur au
    plafond — un sabotage indépendant (`>` muté en `>=`) laissait les 3
    tests verts, ce que Codex a démontré. Corrigé avec une horloge figée
    (`datetime.now()` patché sur une référence fixe), qui distingue
    réellement `>` (accepté) de `>=` (refusé) — reconfirmé par le même
    sabotage, désormais rouge.
  - **Avis de la revue sur le choix mono-instance** : « défendable pour
    une v1 strictement mono-instance, mais seulement si cette contrainte
    est réellement imposée en exploitation — le dépôt ne contient aucun
    verrou de topologie ; un second replica, un HPA, un blue/green ou un
    rolling update avec chevauchement réactive le problème. NO-GO si
    multi-instance possible. » Conditions posées avant production :
    imposer et auditer le mono-instance strict y compris pendant les
    déploiements, documenter/runbooker la fenêtre résiduelle.
  - **Décision Christophe (2026-07-23)** : condition notée, on avance —
    cette instance de MCP Vault tourne en mono-instance à ce jour, le
    compromis s'applique donc tel quel. À réévaluer explicitement avant
    tout passage à plusieurs réplicas ou rolling update avec chevauchement.
  - Suite complète après correctifs : 1013 passed/43 skipped/0 failed,
    contrat JS inchangé (OK).

### Retrait de l'exigence FIDO2 du parcours SSH JIT opérateur (issue #96, 2026-07-23)

Décision produit, prise avant toute mise en production de ce parcours : plus
de dispositif matériel (clé de sécurité FIDO2) exigé pour l'opérateur humain.
MCP Vault est avant tout un serveur MCP — l'identité de l'opérateur repose
désormais uniquement sur le même mécanisme que le reste du système (bearer
token nominatif, scopé par une policy dédiée), sans cérémonie matérielle par
personne. Un HSM Thales Luna, prévu ultérieurement pour cette instance,
répond à un problème différent — protéger la clé privée de la CA elle-même
au niveau infrastructure — et n'est pas substituable à une preuve de
présence physique individuelle : les deux ne se remplacent pas l'un l'autre.

- **Ce qui change** : les clés acceptées sont désormais des clés OpenSSH
  standard (`ssh-ed25519`, `ecdsa-sha2-nistp256`) au lieu des variantes `-sk`
  FIDO2 (`sk-ssh-ed25519@openssh.com`/`sk-ecdsa-sha2-nistp256@openssh.com`).
  Le certificat émis n'impose plus l'option critique `verify-required`
  (spécifique aux clés de sécurité matérielle — l'imposer sur une clé
  standard aurait cassé la connexion côté client, qui ne peut pas la
  satisfaire).
- **Ce qui ne change PAS** : l'enrôlement par empreinte reste obligatoire
  (seule une clé publique spécifiquement approuvée par profil est utilisable,
  même avec un bearer valide) ; l'identité bearer nominative non-admin, la
  policy exacte à 2 outils, le coffre/rôle/principal/cible/TTL imposés côté
  serveur, la réservation de coffre entier contre le signer générique
  (rounds 1-5 ci-dessous), l'absence de diagnostic OpenBao brut et l'audit
  sans matériau de clé — tout ce modèle de sécurité, construit et vérifié sur
  5 rounds de revue adversariale, reste intact et pleinement d'actualité. Les
  mentions de FIDO2/`verify-required` dans les rounds ci-dessous restent
  exactes pour l'époque où elles ont été écrites et ne sont pas réécrites :
  elles documentent un travail de durcissement toujours valable, seul le
  format de clé qu'elles décrivent a changé depuis.
- **Tests** : fixtures et cas FIDO2-spécifiques remplacés par leurs
  équivalents en clé standard ; nouveau test de non-régression prouvant
  qu'une clé au format FIDO2 historique (`sk-*@openssh.com`) est désormais
  rejetée comme type de clé inconnu (pas de réintroduction accidentelle par
  élargissement futur de l'algorithme accepté).
- **Documentation et terminologie** : `ARCHITECTURE.md` §6.3b et
  `TECHNICAL.md` §3.10b mis à jour pour décrire le comportement actuel ;
  `README.md`/`README.en.md`, `.env.example`, l'aide CLI (`scripts/`), la
  console Admin (`static/admin.html`, `static/js/vaults.js`) et les
  commentaires de code alignés sur le nouveau vocabulaire (« clé publique
  pré-enrôlée » plutôt que FIDO2/clé matérielle).

### Accès SSH JIT opérateur lié à une clé FIDO2

- **Parcours dédié** : les outils MCP `ssh_operator_access_profiles` et
  `ssh_request_operator_access` exposent une demande opérateur fermée. Le client
  ne transmet que le profil, sa clé publique FIDO2 et un motif ; le coffre CA,
  le rôle OpenBao, le principal, la cible et le TTL sont imposés côté serveur.
- **Identité et moindre privilège** : seul un bearer nominatif non-admin, lié à
  la policy exacte du profil et au coffre CA attendu, est admis. Bootstrap,
  token admin et Mission JWT sont refusés. Une policy qui autorise également
  `ssh_sign_key` ou `ssh_ca_setup` est rejetée comme trop large.
- **MFA effectif à la connexion** : seules les clés OpenSSH
  `sk-ssh-ed25519@openssh.com` et `sk-ecdsa-sha2-nistp256@openssh.com`
  pré-enrôlées sont acceptées. Le certificat impose l'option critique
  `verify-required`, le principal et un `key_id` unique ; la clé privée demeure
  dans le dispositif FIDO2.
- **Quatre canaux, une autorité** : le même contrat est disponible dans la
  console Web, l'API REST, le CLI Click et le shell interactif. Ces surfaces ne
  choisissent aucun attribut de sécurité et restent subordonnées à la policy
  Vault.
- **Fail-close** : profils JSON stricts, bornes de taille et de TTL validées au
  démarrage, parsing du wire format FIDO2, contrôle du point ECDSA P-256,
  canonicalisation avant OpenBao et refus explicite si le PolicyStore est
  indisponible.
- **Déploiement `.env` strict** : le même document de profils peut être fourni
  en Base64 URL-safe via `SSH_OPERATOR_PROFILES_B64`, sans élargir l'alphabet
  accepté par les renderers. JSON direct et Base64 sont exclusifs, bornés et
  validés fail-fast.
- **Audit sans matériau de clé** : identité, profil, cible, principal,
  empreinte, motif et résultat sont corrélés ; la clé publique complète n'est
  pas journalisée.
- **Séparation du secours** : ce parcours nominal ne lit ni ne modifie le
  credential breaking-glass externe.
- **Base à jour** : `v0.9.0` inclut intégralement le correctif de synchronisation
  S3 conditionnelle et de restauration fail-closed publié en `v0.8.6`.
- **Durcissements post-revue adversariale, 3 rounds (4 + 2 + 1 findings
  bloquants corrigés avant intégration)** :
  - **Round 1** : `ssh_sign_key`/`ssh_ca_setup` génériques (MCP et REST Admin)
    refusaient l'émission sur le rôle exact réservé par un profil opérateur
    JIT — fermait un contournement du parcours FIDO2 par un bearer write
    ordinaire scopé au même coffre.
  - **Round 2 (le round 1 était insuffisant)** : la CA SSH OpenBao étant
    partagée par mount (un seul mount par coffre), le même bearer pouvait
    créer un rôle **alternatif** dans le même mount et le signer
    génériquement, contournant toujours FIDO2. Le garde bloque désormais le
    **coffre entier** dès qu'il héberge un profil opérateur JIT, quel que
    soit le rôle (existant ou à créer) — pas seulement le rôle exact.
  - Ce parcours refuse explicitement l'accès si le Token Store est
    diagnostiqué indisponible, au lieu de servir un bearer depuis un cache
    potentiellement périmé (spécifique à ce parcours, ne change pas le
    comportement diagnostique global du Token Store).
  - `sign_ssh_key()`/`setup_ssh_ca()` (round 1) puis `get_ca_public_key()`,
    `list_ssh_roles()`, `get_ssh_role_info()` (round 2) ne journalisent/
    retournent plus jamais le message brut d'une exception OpenBao — le
    round 1 n'avait couvert que le chemin d'écriture, round 2 a étendu le
    même correctif aux trois fonctions de lecture qui présentaient le même
    défaut sur des routes tout aussi publiques.
  - Garde d'identité (`auth_type`) désormais prouvé par des tests
    mutationnels dédiés (bootstrap/mission JWT/absent, RED sans le garde).
  - Audit de succès enrichi : `key_id` et `serial` OpenBao désormais
    corrélés, en plus du profil/cible/principal/empreinte/motif déjà présents.
  - Enrôlement des empreintes FIDO2 : reste volontairement statique (config +
    redéploiement, cohérent avec `MissionBindingStore`) — décision assumée,
    documentée, suivi séparé à ouvrir si une surface d'administration live est
    souhaitée. Évaluée par la revue comme raisonnable pour une première
    production sous conditions (config GitOps protégée, SLA de redéploiement
    inférieur au TTL des certificats, révocation immédiate du bearer en cas
    de compromission).
  - **Round 3** : un `vault_id` non canonique (slash final) échappait au
    garde par comparaison de chaîne exacte tout en désignant le même mount
    OpenBao après normalisation `hvac` — bug pré-existant plus large que ce
    parcours SSH (`check_vault_owner()`/`vault/spaces.py` et sa duplication
    dans `_check_vault_access()`/`admin/api.py`, affectant potentiellement
    tout outil vault-scoped pour un bearer owner-based). Corrigé à la racine
    dans un module dédié (`vault_ids.py`, validation centralisée avant toute
    décision d'autorisation) plutôt que rapiécé localement.
  - **Frontière structurelle** : après 3 contournements sur un garde placé
    uniquement aux points d'entrée, l'invariant vit désormais dans la
    primitive elle-même (`sign_ssh_key_generic()`/`setup_ssh_ca_generic()`) —
    un futur point d'entrée hérite du garde par construction.
  - **Round 4** : la route REST Admin appelait encore les primitives brutes
    avec un garde dupliqué en ligne (le round 3 n'avait migré que les tools
    MCP vers les wrappers `_generic`, invalidant la prétention structurelle
    pour cette surface). Corrigé : les 4 points d'entrée génériques (MCP ×2,
    REST ×2) appellent tous les wrappers. Un test structurel (analyse AST)
    vérifie qu'aucun autre module n'appelle directement les primitives
    brutes. `role_name` durci en `fullmatch` (même piège `\n` final que
    `vault_id`), message d'erreur sans écho de la valeur brute.
  - **Round 5 (BLOQUANT)** : un bearer **admin légitime** contournait
    complètement FIDO2/`verify-required` via le même slash final —
    `check_access()`/`_check_vault_access()` autorisent l'admin avant toute
    validation de `vault_id`, format que le garde de réservation ne
    revalidait pas lui-même. Corrigé : le garde de réservation valide
    désormais `vault_id` en toute autonomie, indépendamment de ce que
    l'appelant a déjà validé. Le test structurel round 4 était lui-même
    contournable par aliasing d'import (`import ... as x`) — corrigé en
    résolvant les alias avant comparaison.
- **Tests** : 1007 tests passés, 43 ignorés (964 + 43 nouveaux tests
  mutation-proven sur les durcissements ci-dessus, chacun confirmé RED sans le
  correctif puis GREEN avec — y compris la reproduction exacte des
  contournements round 2 (rôle alternatif), round 3 (vault_id non
  canonique, bout en bout), round 4 (test structurel) et round 5 (bypass
  admin, MCP et REST). Le contrat UI
  couvre notamment le refus de policy JIT sans casser la fiche Vault
  standard (RED puis GREEN).

## [0.8.7] — 2026-07-23

### Correction critique — contournement de l'isolation owner-based par `vault_id` non canonique

Découvert en cours de revue adversariale sur un chantier séparé (issue #96,
accès SSH JIT opérateur), sans lien fonctionnel avec SSH — un bug transverse
à tout outil vault-scoped pour un bearer owner-based.

- **Vulnérabilité** : `check_vault_owner()` (`vault/spaces.py`) et sa
  duplication dans `_check_vault_access()` (`admin/api.py`) traitent un
  `vault_id` non canonique (ex. `"agentic-platform/"`, slash final) comme
  « le vault n'existe pas » — la règle « vault inexistant → accès autorisé »
  (pensée pour la création) se retrouve alors détournée pour donner accès à
  un vault EXISTANT dont le bearer n'est PAS propriétaire, dès lors
  qu'OpenBao/hvac normalisent ce même `vault_id` vers le même mount réel que
  sa forme canonique. Contournement complet de l'isolation cross-tenant
  owner-based, sans exécution de code, sur tout bearer `allowed_resources=[]`.
- **Correctif** : nouveau module feuille sans dépendance `vault_ids.py`
  (`is_valid_vault_id()`, ancré par `fullmatch` — pas `match`, pour fermer le
  piège classique d'un `\n` final), consommé systématiquement avant toute
  décision d'autorisation par `check_access()` (`auth/context.py`),
  `_check_vault_access()` (`admin/api.py`), `_validate_vault_id()`
  (`vault/spaces.py`), `validate_tenant_id()`/`validate_allowed_resources()`
  (`auth/mission_bindings.py`), `_validate_inputs()` (`vault/wrapping.py`),
  `_validate_role_name()` (`vault/ssh_ca.py`).
- **Revue** : 4 rounds de revue adversariale indépendante (Codex, mandat
  offensif) → **GO**. Chaque round a reproduit puis fermé une variante
  distincte du contournement (slash final, double slash, encodage URL,
  bearer admin légitime inclus — un token admin ne bénéficiait d'aucun
  court-circuit protecteur ici, le bug touchait le chemin owner-based
  générique quel que soit le niveau de permission).
- **Tests** : 385 lignes de tests non-complaisants nouveaux
  (`tests/test_vault_id_canonicalization_owner_bypass.py`), sabotages
  RED→GREEN documentés. Suite complète : 939 passed / 43 skipped / 0 failed.
- **Documentation** : `ARCHITECTURE.md` §6.1b (nouveau), `TECHNICAL.md` §3.4
  mis à jour.
- **Aucun changement de comportement** pour un `vault_id` déjà canonique.

## [0.8.6] — 2026-07-22

### Correction — explosion du nombre de versions S3 (sync périodique inconditionnelle)

Incident constaté en production : le bucket `agentic-platform-mcp-vault-prod` a le versioning S3 activé, sans lifecycle. `upload_to_s3()` était appelé toutes les 60s par la boucle de sync périodique **sans condition** — un PUT (donc une nouvelle version S3) à chaque cycle, même en l'absence de toute écriture OpenBao. Résultat : 6000+ versions et 600+ Mo accumulés en quelques jours pour un seul objet (`_storage/openbao-data.tar.gz`).

- **PUT conditionnel sur la boucle périodique uniquement** : `upload_to_s3(skip_if_unchanged: bool = False)`. Seule `_periodic_sync_tick()` (le vrai point d'entrée de la boucle de fond) passe `True`. Tous les autres appelants — upload final à l'arrêt (`lifecycle.py::vault_shutdown()`) et les 4 sync forcées après opérations PKI (setup CA, émission/révocation/rotation de certificat) — conservent le défaut `False` : ils uploadent **toujours**, comportement strictement inchangé.
- **Empreinte construite dans la même passe que l'archive** (`_snapshot_and_archive()`) : chemins relatifs triés, contenu des fichiers, type (fichier/répertoire/symlink) et cible pour les symlinks — **jamais** un hash du tar.gz généré lui-même (ses métadonnées gzip/mtime varient sans changement métier). Pour un fichier régulier, contenu ET métadonnées archivés viennent du **même descripteur ouvert** (`open()`+`fstat(fd)`+`read()`), jamais d'un second stat par chemin séparé — ferme un bloquant trouvé en **revue de diff** (pas seulement en revue de plan) : une version intermédiaire combinait `lstat()` + `tar.gettarinfo(chemin)` + `read_bytes()`, trois observations séparées du même chemin, capable de produire une archive et une empreinte construites à partir d'états différents de la même entrée si celle-ci changeait de type entre-temps (reproduit empiriquement par le reviewer). Résidu assumé et documenté (non exploitable avec l'usage réel du file backend OpenBao) : la décision de branchement fichier/répertoire/symlink repose sur un seul `lstat()` initial.
- **Rejeu garanti sur échec** : la référence n'avance qu'après un PUT confirmé réussi. Un échec — y compris **ambigu** (ex. timeout après l'envoi, où l'objet a pu être écrit côté S3 malgré l'exception locale) — place l'état interne en incertitude : aucun skip n'est plus autorisé tant qu'un PUT n'a pas explicitement réussi ensuite, même si le contenu local redevient identique à l'ancienne référence.
- **Durcissement de la restauration au démarrage** (`download_from_s3()` retourne désormais `RestoreResult.RESTORED` / `CONFIRMED_ABSENT` / `FAILED` au lieu d'un booléen) : seule une absence **confirmée** par S3 (404/`NoSuchKey`, détection structurée via `response.Error.Code`, plus de correspondance sur `str(exception)`) autorise une initialisation à vide. Un échec ambigu (réseau, archive corrompue) fait désormais échouer `vault_startup()` (retour `False`) au lieu d'initialiser silencieusement un coffre vide qui écraserait ensuite une sauvegarde distante potentiellement valide.
- **Restauration extraite hors de `data_dir`** (1er bloquant restauration, trouvé en revue de diff) : l'extraction se fait dans un répertoire de staging (à l'intérieur de `data_dir`, garanti même filesystem — le volume Docker est monté exactement sur `data_dir`, pas sur son parent) avant toute promotion par renommages individuels. Sans ce staging, une archive dont l'extraction échouait APRÈS avoir déjà écrit certains membres (corruption, ou membre rejeté par `filter='data'` après des membres valides) laissait ces membres directement dans `data_dir` malgré l'échec global.
- **Marqueur durable de restauration incomplète** (2e bloquant restauration, trouvé dans un round de revue de diff ultérieur) : la PROMOTION elle-même (renommages individuels du staging vers `data_dir`) n'est **pas** transactionnelle — chaque `rename()` est atomique unitairement, mais la boucle qui les enchaîne ne l'est pas. Une erreur I/O ou un crash au milieu laissait `data_dir` dans un état MIXTE (certaines entrées promues, d'autres non), qu'aucun test de présence de fichiers ne pouvait distinguer d'une « vraie » donnée locale — `has_local_data` l'acceptait silencieusement au redémarrage suivant, court-circuitant toute nouvelle tentative de restauration S3. Fermé par un marqueur durable (`_RESTORE_MARKER_FILENAME`), posé AVANT tout nettoyage/extraction et retiré SEULEMENT après une promotion intégralement réussie ou une absence confirmée. `lifecycle.py::_check_local_data_status()` (extrait de `vault_startup()` en fonction testable isolément) traite sa seule présence comme autoritaire, indépendamment du contenu physique de `data_dir`.
- **La levée du marqueur sur absence confirmée purge désormais le résidu préexistant** (3e bloquant restauration, trouvé dans un round de revue de diff encore ultérieur) : une absence CONFIRMÉE par S3 (404/`NoSuchKey`) ne rend PAS fiable un résidu de promotion PARTIELLE d'une tentative précédente ratée — ex. l'objet S3 supprimé entre deux tentatives fait retomber en `CONFIRMED_ABSENT` alors qu'une entrée orpheline traîne encore dans `data_dir` depuis l'échec précédent. Retirer le marqueur sans purger cette entrée la faisait réapparaître comme donnée locale « valide » au prochain calcul de `_check_local_data_status`, rouvrant exactement l'invariant du bloquant précédent par un chemin différent. Fermé par `_clear_data_dir_leftovers()` (helper partagé avec le nettoyage pré-promotion), appelé AVANT de lever le marqueur sur ce chemin aussi ; si cette purge échoue, le marqueur reste (fail-closed).
- **Un staging de restauration durablement non supprimable ne peut plus jamais compter comme donnée locale** (4e bloquant restauration, trouvé dans un round de revue de diff encore ultérieur, reproduit par le reviewer avec un vrai répertoire en lecture seule) : si le nettoyage du staging échoue de façon PERSISTANTE (permission, erreur I/O durable — pas un simple glitch), il pouvait survivre physiquement au retrait du marqueur et être ensuite compté comme « donnée locale valide » par `_check_local_data_status`, alors qu'il ne s'agit que d'un artefact de bookkeeping interne, jamais une vraie donnée OpenBao. Fermé à deux niveaux : (1) `_check_local_data_status()` exclut désormais TOUJOURS le staging de son test de contenu réel — la protection PRINCIPALE, qui tient même si le nettoyage échoue ; (2) `_clear_data_dir_leftovers(data_dir, include_staging=True)` purge aussi le staging depuis le chemin `CONFIRMED_ABSENT` (où aucune session de staging n'est active dans cet appel — tout staging y est nécessairement le résidu d'une tentative précédente et différente), en complément.
- **L'upload final à l'arrêt n'est plus inconditionnel dans TOUS les cas** (bloquant le plus sérieux, trouvé en revue de diff) : `vault_shutdown(skip_upload: bool = False)`. `server.py` calcule désormais `skip_upload=not ok` à partir du même booléen que `vault_startup()` retourne déjà. Sans cette garde, le fail-closed de restauration ci-dessus était **cosmétique** : un `vault_startup()` en échec ne stoppe pas le processus (`server.py` continue en « mode dégradé », comportement préexistant non modifié ici) et l'ancien upload final inconditionnel à l'arrêt pouvait malgré tout écraser une sauvegarde S3 valide avec l'état local incomplet ou jamais initialisé issu de ce démarrage raté.
- **`_is_confirmed_absent()` durci** contre un `ClientError` malformé (`response={"Error": None}`) qui levait `AttributeError` au lieu de retourner `False` proprement.
- **Aucun secret, contenu OpenBao, clé S3 ou chemin interne dans les logs** de ce flux : les messages d'erreur journalisent le type d'exception (`type(e).__name__`), jamais `str(e)` (qui peut contenir bucket/clé/endpoint), ni la clé S3 de l'archive, ni le chemin local du volume.
- **Tests** — `tests/test_s3_sync.py` (46 cas) + `tests/test_lifecycle.py` (13 cas, première couverture de `lifecycle.py`), 59 cas non-complaisants au total : 2 cycles sans modification ⇒ exactement 1 PUT ; modification d'un octet / ajout / suppression de fichier ⇒ chacun exactement 1 PUT ; mtime/permissions seuls ⇒ aucun PUT (le bruit exact à l'origine de l'incident) ; upload échoué ⇒ référence non avancée, rejeu prouvé ; échec ambigu ⇒ skip interdit jusqu'à confirmation ; redémarrage simulé ⇒ jamais de skip au premier cycle ; upload forcé ⇒ jamais sauté, et pose une référence valide pour le tick périodique suivant ; restauration aux 3 états (dont un vrai `botocore.exceptions.ClientError`) ; extraction partiellement échouée ⇒ `data_dir` intact, aucun résidu ; promotion partiellement échouée (rename() en erreur au milieu de la boucle) ⇒ marqueur reste en place, `_check_local_data_status` refuse l'état mixte résultant ; absence confirmée consécutive à une promotion partielle ⇒ résidu orphelin purgé avant de lever le marqueur ; **staging résiduel non vide, y compris en simulant un nettoyage qui ne supprime physiquement rien ⇒ jamais compté comme donnée locale, purgé aussi depuis le chemin absence confirmée** ; métadonnées archivées d'un fichier prouvées venir du descripteur ouvert (pas d'un second stat par chemin) ; `vault_shutdown(skip_upload=True)` n'appelle jamais l'upload mais scelle/arrête toujours OpenBao ; sensibilité de l'empreinte (renommage, répertoire vide, symlink, échange de contenu) ; aucune fuite dans les logs. **9 sabotages adversariaux confirmés RED puis restaurés GREEN** (dont 2 par le reviewer lui-même, indépendamment) : garde anti-PUT-redondant, garde `skip_upload`, staging de restauration, observation unique par fichier (2 variantes), garde du marqueur de restauration incomplète, purge avant absence confirmée, exclusion du staging dans `_check_local_data_status`, purge du staging avec `include_staging=True`.
- **Revue adversariale en 5 passes** : revue de PLAN (6 bloquants, tous corrigés) puis 4 revues de DIFF successives dans un worktree jetable où le reviewer a exécuté lui-même la suite et ses propres reproductions à chaque round (round 1 : 3 bloquants — TOCTOU intra-entrée, restauration écrivant hors staging, fail-closed contourné par l'upload inconditionnel du shutdown ; round 2 : confirmation des précédents + 1 bloquant — promotion non transactionnelle ; round 3 : confirmation des précédents + 1 bloquant — absence confirmée ne purgeant pas un résidu de promotion partielle ; round 4 : confirmation des précédents + 1 bloquant — staging durablement non supprimable compté comme donnée locale, reproduit avec un vrai répertoire en lecture seule). Nouvelle revue de diff en attente sur l'état corrigé (round 5).
- **Hors scope explicite (documenté, pas fermé par ce lot)** : la race d'écriture multi-instance générale sur la clé S3 (dernier writer gagne si deux processus mcp-vault écrivent le même préfixe sans CAS/verrou) — même limite déjà documentée pour PolicyStore/TokenStore (#51/#13). Le coût CPU du hachage SHA-256 du backend à chaque cycle (même quand le PUT est sauté) reste synchrone, comme l'était déjà la construction du tar.gz historique — non isolé dans un thread/executor séparé (jugé disproportionné ; à réévaluer si le volume de données devient significatif). Le câblage `server.py` (skip_upload=not ok) est vérifié par lecture directe, pas par un test automatisé dédié — aucune infrastructure de test n'existe pour `server.py::main()`/`serve_with_lifecycle` (closure imbriquée liée à une vraie instance `uvicorn.Server`), et en créer une pour ce seul câblage mécanique (3 lignes) a été jugé disproportionné pour ce correctif.
- **Documentation** : `DESIGN/mcp-vault/TECHNICAL.md` §3.3 et `DESIGN/mcp-vault/ARCHITECTURE.md` §4.3/§4.4 mis à jour pour refléter le mécanisme réellement implémenté (l'ancien §4.4 décrivait un design jamais codé — comparaison de timestamps, `sync_marker`, `sync_meta.json` — remplacé par le comportement effectif) ; `README.md`/`README.en.md` mis à jour.

## [0.8.5] — 2026-07-20

### Migration de custody — écriture create-only atomique et erreurs REST fiables

Prérequis de la migration des credentials Agentic Platform vers son Vault interne : le POST Admin historique effectuait un upsert. Un migrateur faisant d'abord un GET puis un POST pouvait donc écraser un secret créé dans l'intervalle ; de plus, toute erreur de lecture OpenBao était exposée comme un 404, impossible à distinguer d'une vraie absence.

- **Création atomique opt-in** : `POST /admin/api/vaults/{id}/secrets` accepte `create_only: true`. MCP Vault transmet alors `cas=0` à OpenBao KV v2 ; une première création réussit et un chemin déjà présent retourne HTTP **409**, sans retry ni écrasement.
- **Compatibilité préservée** : `create_only` vaut `false` par défaut. Les appels existants continuent d'effectuer l'upsert historique et aucun paramètre CAS ne leur est ajouté. Le contrat de l'outil MCP `secret_write` ne change pas.
- **404 fiable et fail-close** : un `InvalidPath` n'est classé `not_found` que si le mount demandé est attesté comme KV v2. Mount absent, preuve impossible, refus ou panne backend retournent HTTP **503**, jamais un faux 404 exploitable par un migrateur.
- **Validation stricte du POST** : JSON objet obligatoire ; `path`, `data`, `type`, `tags` et `create_only` sont typés avant tout appel OpenBao. Les erreurs backend d'écriture retournent également 503.
- **Attestation du token source** : `GET /admin/api/whoami` expose désormais l'horodatage non secret `expires_at` des tokens S3. Un migrateur peut donc exiger un token read-only, limité à un coffre et réellement temporaire, sans disposer d'un droit admin de listing des tokens.
- **Pas de fuite de diagnostic** : les réponses et logs n'exposent plus le message brut d'une exception OpenBao ; seuls le contexte non secret et le nom de classe sont journalisés.
- **Tests** : 21 régressions ciblées couvrent CAS, conflit strict, upsert historique, 404/503, validation du payload, absence de fuite et exposition de l'expiration. Suite complète : 860 tests passés, 43 ignorés. Revue indépendante : GO pré-commit, aucun finding P0/P1.

## [0.8.4] — 2026-07-20

### Correction sécurité — masquage réel des secrets sensibles dans la console Admin

Bug remonté par un client (Agentic Platform) : dans la fiche détail d'un secret (`toggleSecret()`, console Admin web), le code identifiait certains champs sensibles (`password`, `private_key`, `secret`, `cvv`, `seed_phrase`) mais ne faisait que colorer leur valeur en orange — la valeur brute restait injectée en clair dans le DOM dès l'ouverture de la fiche, et y restait après repli (simple `display:none`, jamais retirée). Une ouverture de fiche exposait donc immédiatement tous les secrets à l'écran et les conservait inspectables en DevTools indéfiniment.

- **Masquage réel par défaut** : placeholder fixe (`••••••••`, ne fuite pas la longueur réelle) affiché à la place de la valeur pour tout champ détecté sensible. Rendu par nœuds DOM réels (`createElement`/`textContent`), plus par `innerHTML` : la valeur brute ne transite plus jamais par une chaîne HTML, elle vit uniquement dans une fermeture JS capturée par les boutons d'action — structurellement à l'abri d'une injection HTML/JS, sans avoir besoin de faire confiance à `esc()` pour ces valeurs précises (qui reste utilisée partout ailleurs dans le fichier).
- **Actions explicites par champ sensible** : bouton "Afficher/Masquer" (révèle la valeur réelle et complète, jamais tronquée, uniquement ce champ) et bouton "Copier" (copie la valeur ciblée dans le presse-papier, jamais de copie automatique).
- **Purge complète au repli** : replier la fiche retire tout le sous-arbre DOM (`replaceChildren()`), y compris toute valeur précédemment révélée — plus de résidu masqué en CSS mais toujours présent en mémoire DOM.
- **Détection centralisée des champs sensibles** (`isSensitiveField()`), traitant au minimum (insensible à la casse) : `password`, `secret`, `private_key`, `passphrase`, `token`, `access_token`, `api_key`, `totp_secret`, `cvv`, `seed_phrase`, `connection_string`, `key` (correspondance exacte, masqué quel que soit le type — introduit pour le champ `key` du type `api_key`, mais s'applique à tout secret ayant un champ nommé littéralement `key` ; léger sur-masquage UX possible pour un `custom` avec un champ `key` non sensible, jamais une fuite ; ne masque jamais `public_key`, correspondance exacte et non un suffixe), et une petite table dépendant du type de secret (`_type`, déjà renvoyé par l'API de lecture) pour les champs génériques ambigus hors contexte : `secure_note.content`, `env_file.content`, `credit_card.number`. Jamais masqué inutilement : `public_key`, `endpoint`, `url`, certificats publics.
- **Garde de concurrence** (trouvée en revue de plan Codex) : un compteur de génération par élément empêche qu'une réponse réseau tardive ne repeuple une fiche que l'utilisateur a déjà repliée (ou rouverte) entre-temps — sans cette garde, la réponse tardive aurait réintroduit exactement l'exposition qu'on vient de corriger.
- **Page Tokens** : ajout d'un texte explicatif sur la colonne "Hash" (empreinte, non utilisable pour se connecter). Comportement déjà correct par ailleurs : seul `hash_prefix` est affiché dans la liste, le token brut n'est montré qu'une fois à sa création — vérifié, non modifié.
- **Champ de connexion admin** (`api.js`/`doLogin()`) : le champ de saisie du token est désormais vidé au succès de la connexion (pas seulement à la déconnexion), réduisant sa persistance dans le DOM. Le token reste par ailleurs en clair dans `sessionStorage` pour l'auto-login — un choix de conception déjà documenté et accepté (`SECURITY_AUDIT.md`, V2-I15).
- **Limite explicite** : ce correctif réduit l'exposition dans le DOM ; il n'empêche pas un détenteur autorisé de voir la réponse réseau brute (onglet Réseau des DevTools) — ce n'est pas son objectif, la lecture du secret reste gouvernée par les policies existantes (`check_policy`/`check_path_policy`).
- **Tests** — nouveau fichier `tests/js/secret_visibility_contract.test.js` (46 cas non-complaisants, exécutés sous Node, aucune nouvelle dépendance npm) : couvre `isSensitiveField()`, `renderSecretFieldsInto()` ET `toggleSecret()` elle-même (via un faux DOM + un faux `api()` injectés), y compris la garde de concurrence (réponse tardive après repli, puis après réouverture) et une preuve historique figée (`tests/js/fixtures/legacy_toggle_secret_snippet.js`, chargée via `vm`) démontrant que l'ancien code fuitait bien la valeur en clair. 3 sabotages adversariaux confirmés RED sans le correctif (purge au repli, garde de génération, détection de `key`) puis restaurés GREEN.
- **Pas de changement de contrat API, pas de migration OpenBao, pas de décodage du format applicatif Agentic Platform, pas de nouvelle dépendance.**

## [0.8.3] — 2026-07-20

### Correction critique — élévation de privilège via le Token Store (issue #86, extension Lot 3)

Découvert en creusant la revue adversariale du Lot 3 (Policy Store) : le Token Store présentait le même défaut de validation que celui déjà corrigé sur les policies, mais avec un impact bien plus grave — un token pouvait être élevé en accès **administrateur total**.

- **Faille corrigée (CVE interne, non exposée sans accès admin préalable)** : `TokenStore.update()` validait `permissions` par simple itération (`all(isinstance(p, str) and p in VALID_PERMISSIONS for p in permissions)`) **sans vérifier au préalable que la valeur était une liste**. Un `dict` `{"permissions": {"admin": true}}` envoyé via `PUT /admin/api/tokens/{hash}` itère sur ses clés (`"admin"`, une chaîne valide) et passait donc la validation, stocké tel quel. Au moment de la décision d'autorisation (`"admin" in token_info["permissions"]`), tester l'appartenance d'une **clé de dict** retournait `True` : le token devenait admin total. Un `tokens.json` corrompu avec `permissions: "admin"` (chaîne) produisait le même contournement via un test de sous-chaîne. Exploitable uniquement par un compte ayant déjà accès à la console d'administration — pas un vecteur externe, mais un risque sérieux d'erreur opérationnelle ou d'escalade en cas de compromission d'un compte admin.
- **`allowed_resources` non validé du tout dans `update()`** — `{"allowed_resources": false}` était accepté et basculait le token en mode "tous les vaults possédés" (le comportement le plus permissif déjà prévu pour ce champ, pas une élévation au-delà de l'existant, mais une confusion de type à corriger). `create()` avait le même défaut (`allowed_resources or []` masquait toute valeur non-liste).
- **Validation centralisée** : `create()`, `update()` et `load()` partagent désormais les mêmes fonctions de validation (`_validate_permissions`, `_validate_allowed_resources`) — plus de resaisie locale divergente entre les trois points d'entrée.
- **`load()` durci** : chaque token lu depuis S3 est validé (schéma, format du hash, `permissions`/`allowed_resources`/`policy_id`/`revoked`/`expires_at`) ; un seul token non conforme invalide tout le chargement (tout-ou-rien, cohérent avec le Policy Store), le cache précédent est conservé. Compatibilité préservée : `policy_id` absent (tokens antérieurs à l'introduction des policies) est normalisé à `""`.
- **`update()` valide désormais tous ses paramètres avant tout effet de bord** (rafraîchissement du cache, résolution du token) — un appel invalide n'a plus aucune conséquence.
- **Hors scope explicite (documenté, pas fermé)** : le Token Store ne fait pas de fail-close sur panne S3 pour l'authentification par bearer token — après une panne détectée, l'ancien cache continue d'être servi, y compris pour un token récemment révoqué. Ce résidu, à impact opérationnel plus large (blocage de tous les clients bearer pendant une panne), reste un chantier séparé.
- **Tests** — nouveau fichier `tests/test_token_store_hardening.py` (40 cas non-complaisants) : reproduction exacte de la faille (`{"admin": true}` rejeté), non-régression des mises à jour légitimes, tout-ou-rien au chargement, compatibilité `policy_id` historique. 2 régressions confirmées par sabotage adversarial (élévation de privilège, chargement partiel).

### Durcissement PEP mission JWT — Policy Store fail-close (issue #86, Lot 3)

Suite à la revue Codex pré-canari #47 (verdict NO-GO — issue #86), lot 3 : ferme le finding ÉLEVÉ 3. Après expiration du TTL (5 min), une panne ou une corruption S3 du Policy Store faisait continuer silencieusement à servir les dernières policies connues en cache (`load()` journalisait l'erreur sans jamais invalider le cache) — un droit retiré par un admin juste avant la panne restait donc appliqué tant que S3 restait indisponible.

- **État observable `available`/`last_error`** (même pattern que `MissionBindingStore`, #69) : après TTL, une panne S3 ou un JSON/schéma de policy corrompu marque le store INDISPONIBLE plutôt que de servir le cache périmé. `is_tool_allowed()`, `is_path_allowed()`, `get()`, `list_all()`, `get_vault_permissions()` lèvent désormais `PolicyStoreUnavailable` (jamais un fail-open silencieux) ; `create()`/`delete()` refusent toute mutation AVANT tentative si le store est déjà connu indisponible. Retry accéléré 10s (borné par processus) tant que le store est invalide, sinon TTL normal 300s.
- **Validation stricte, non permissive par défaut** — une policy structurellement incomplète ou corrompue ne devient jamais permissive : `allowed_tools`/`denied_tools`/`path_rules` doivent être présents, chaque `path_rule` exige un `vault_pattern` non vide, et des `permissions` absentes se normalisent explicitement à `["read"]` **seul** — corrige un défaut historique de `is_path_allowed()` qui accordait silencieusement `["read","write","admin"]` sur une règle sans `permissions`. Un `policy_id` dupliqué dans le fichier S3 invalide tout le chargement (au lieu d'être silencieusement écrasé). Chargement et création partagent la même validation (`create()` refusait déjà certaines formes invalides mais avec une logique dupliquée et incomplète).
- **Contrat d'erreur unifié `policy_store_unavailable`** — REST admin : un helper centralisé mappe ce contrat en HTTP 503 sur les ~18 sites `check_policy()`/`check_path_policy()`, distinct d'un refus de policy ordinaire (403). MCP : dict d'erreur structuré, cohérent entre lectures et mutations.
- **Bug fail-open corrigé sur la référence `policy_id`** — la création/modification d'un token (REST et MCP `token_update`) ou d'un mission binding acceptait silencieusement un `policy_id` non vérifié lorsque le Policy Store était absent (`if pstore and ...` court-circuitait sur `pstore=None`). Refus explicite désormais dans les deux cas (store absent ou indisponible).
- **`get_vault_permissions()` conservée** (aucun appelant applicatif connu, mais documentée) plutôt que supprimée — propage désormais `PolicyStoreUnavailable` comme les autres lectures.
- **Corrections de documentation** — `is_path_allowed()` et `policy_delete` décrivaient un comportement inverse du fail-close réel (une policy absente **bloque** le token, elle ne l'« autorise » ni ne le rend non-restreint).
- **HORS SCOPE explicite** (documenté, pas fermé) : la race d'écriture multi-instance générale — deux instances qui écrivent concurremment sans aucune panne (last-write-wins structurel sur le fichier unique partagé, issue #51/#13, nécessite un vrai CAS/ETag S3). `TokenStore` partage la même limitation non traitée.
- **Tests** — nouveau fichier `tests/test_policy_store_availability.py` (55 cas non-complaisants) : POC exact du finding (panne détectée après TTL → jamais l'ancienne policy servie) ; TOCTOU éliminé (`is_tool_allowed`/`is_path_allowed` ne rappellent jamais `get()`) ; régression du défaut permissif (`permissions` absente → `["read"]`, jamais `write`/`admin` — confirmée par sabotage adversarial) ; distinction `NoSuchKey` vs vraie panne ; tout-ou-rien au chargement ; rollback mémoire sur échec `_save()` ; distinction erreur de sérialisation locale vs panne S3 réelle ; garde `policy_id` non vérifiable sur les 4 sites concernés. 4 rounds de revue Codex (2 rounds de plan bloqués sur un dilemme de scope architectural résolu par le project owner, 2 rounds d'ajustements techniques).

### Durcissement PEP mission JWT — fail-fast de configuration (issue #86, Lot 1)

Suite à une revue adversariale Codex du PEP mission JWT (#47) préalable à son activation en production (verdict NO-GO, 7 findings bloquants — issue #86). Premier lot : ferme le finding CRITIQUE (partie configuration) et le finding sur la révocation mission non bornée. Les lots suivants (alignement C18/PEP, Policy Store fail-close, durcissement async JWKS, TTL binding) restent à faire sur #86.

- **`ENFORCE_MISSION_TOKEN_VALIDATION` désormais obligatoire (fail-fast au boot)** dès que la validation mission_token est active — que ce soit via le PEP transport (`MCP_AUTH_MODE=jwt`/`dual-stack`) ou via l'enforcement C18 seul en mode `bearer` (mécanisme historique #26). Avant ce correctif, activer le PEP `/mcp` n'empêchait pas `secret_consume` de rester en mode permissif par défaut : une mission abortée passée en paramètre `mission_token` pouvait encore obtenir la libération d'un secret.
- **`MISSION_STATUS_URL` désormais obligatoire** dans les mêmes conditions — sans elle, une mission abortée conservait l'accès jusqu'à expiration du `mission_token` (jusqu'à 1h). L'URL doit en outre contenir le placeholder littéral `{mission_id}` (fail-fast si absent) : une URL statique aurait pu valider silencieusement n'importe quelle mission comme active.
- **`MISSION_STATUS_CACHE_TTL` désormais borné à `[0,30]` secondes** (0 = pas de cache) dans les mêmes conditions — une valeur hors bornes retardait arbitrairement la détection d'une mission abortée.
- **Code mort retiré** — les avertissements `logger.warning` devenus inatteignables (le fail-fast de configuration s'exécute avant) ont été supprimés de `create_app()` et `main()`.
- **Tests** — `tests/test_mission_jwt.py::TestMissionPepConfig` (13 nouveaux cas non-complaisants : chaque nouvelle règle testée en échec ET en succès, y compris le cas bearer + enforcement C18 seul) ; `tests/test_jwt_validator.py` (test de bout en bout prouvant qu'une mission confirmée inactive dans le paramètre `mission_token` est bloquée avant tout appel à `consume_wrap_secret`, quelle que soit l'identité active sur le transport). Revue de plan Codex adversariale avant implémentation (a trouvé l'angle mort du mode bearer + enforcement C18 seul, absent du plan initial).

### Durcissement PEP mission JWT — alignement C18/PEP (issue #86, Lot 2)

Suite à la revue Codex pré-canari #47 (verdict NO-GO — issue #86), lot 2 : ferme le finding ÉLEVÉ 2. `MissionTokenValidator` (utilisé par `secret_consume`, issue #26) dupliquait sa propre logique de validation JWT, en retard sur `AuthMiddleware` (le PEP `/mcp`, issue #47) — `iat`, `jti`, `tenant_id`, `scope` n'étaient pas vérifiés, et surtout `component_id` pas vérifié du tout. Un mission_token authentique avec `aud` multiple (contenant l'instance courante ET une autre) mais `component_id` pointant vers l'autre instance passait `secret_consume` alors que le PEP l'aurait refusé — confusion inter-instances (confused-deputy).

- **`MissionTokenValidator.validate()` délègue désormais à `mission_jwt.validate_mission_token()`** — la même fonction que le PEP `/mcp`. Mêmes claims requis (`exp`, `iat`, `iss`, `aud`, `mission_id`, `jti`, `scope`, `tenant_id`), même vérification `component_id[MCP_COMPONENT_KIND] == audience`. `exp` devient strict (leeway=0, comme le PEP) ; `MISSION_TOKEN_LEEWAY_SECONDS` ne s'applique plus qu'à `iat` (anti-skew futur) — avant ce lot, ce réglage était déjà silencieusement ignoré par PyJWT côté `secret_consume` (placé dans `options` au lieu du paramètre top-level attendu), le leeway effectif sur `exp` était donc déjà 0 de fait ; ce lot rend ce comportement explicite.
- **Nouveau paramètre `component_kind`** sur `MissionTokenValidator`/`init_mission_token_validator()`, aligné sur `MCP_COMPONENT_KIND` (défaut `"vault"`, comme le PEP).
- **Audience vide = rejet explicite** (`misconfigured_expected_aud`) plutôt qu'un ancien mode permissif où la vérification `aud` était silencieusement désactivée — cet ancien mode ne protégeait de toute façon déjà plus les vrais mission_token (qui portent toujours un `aud`, systématiquement rejeté par PyJWT avec une audience attendue vide).
- **`expected_iss` non configurable** — le contrat mcp-mission fixe l'issuer à `"mcp-mission"` ; un override est désormais refusé à la construction plutôt que silencieusement sans effet.
- Le vocabulaire des codes d'erreur internes (`reason`, jamais exposé au client — `secret_consume` renvoie toujours `error_type="jwt_invalid"` générique) reste **le vocabulaire historique C18** pour les cas déjà couverts avant ce lot (`invalid_signature`, `token_expired`, `invalid_issuer`, `invalid_audience`, `unsupported_algorithm`, `kid_unknown_or_revoked`, `jwks_unavailable`, `invalid_token_format`, `validation_failed`). Les nouveaux contrôles reçoivent des codes stables inédits : `iat_future`, `bad_mission_id`, `bad_jti`, `bad_tenant_id`, `bad_scope`, `component_id_mismatch`.
- **Tests** — 12 nouveaux cas non-complaisants dans `tests/test_jwt_validator.py`, dont le test de régression exact du finding (aud multiple + `component_id` vers une autre instance → rejeté ; confirmé par sabotage adversarial : la vérification `component_id` neutralisée fait échouer ce test). Helper `_make_token()` enrichi de claims complets par défaut (le token de test doit être complet puis privé d'*exactement* un claim pour tester son absence, jamais construit incomplet à la main).

Ce lot ferme le finding 2 **une fois C18 enforced et correctement configuré** (Lot 1, indépendant) : avec `ENFORCE_MISSION_TOKEN_VALIDATION=false` (mode permissif assumé, migration progressive), `secret_consume` continue volontairement après un JWT invalide, alors que le PEP actif refuse toujours — asymétrie intentionnelle, pas une parité universelle.

### Broker de secrets — consultation d'état en lecture seule (issue #77)

`secret_wrap_lookup` **révoque** volontairement les wraps (compensation des provisions orphelines #74), mais son nom laissait croire à une consultation : un consommateur vérifiant l'état d'un wrap le **révoquait** (piège d'intégration remonté par mcp-mission au pré-canari). Aucun moyen de lire l'état sans effet de bord n'existait.

- **Nouvel outil MCP `secret_wrap_status(operation_id)` (lecture seule)** — retourne l'état d'un wrap (`not_found | pending | active | consuming | consumed | revoked | failed | ambiguous | registry_inconsistent`, ou `backend_unavailable`) **sans révocation ni écriture durable**. Contrat = **instantané best-effort** du registre (cache court, S3 *last-write-wins*) : `active` signifie « actif dans l'instantané », **pas** une garantie de consommabilité (un wrap expiré côté OpenBao peut encore ressortir `active`). Ne renvoie **jamais** l'`accessor` ni le `wrap_token` (projection neuve — aucune mutation d'une référence vivante du registre). **Admin-only** (V1) ; l'ouverture aux identités mission relève de #78 Lot C.
- **`secret_wrap_lookup` clarifié** — docstring corrigée : avertissement explicite qu'il **RÉVOQUE**, renvoi vers `secret_wrap_status` ; l'état `found_unattached` est décrit correctement (provision orpheline sans accessor, **non** révoquée). Comportement **inchangé** (#74 intact).
- **Parité CLI** — `secret wrap-status <operation_id>` (miroir lecture seule de `secret wrap-lookup`).
- **Tests** — `tests/test_wrap_status_77.py` : classification de chaque état sans effet de bord, non-mutation de la référence registre, non-exposition `accessor`/`wrap_token`, admin-only, validation `operation_id` ; intégration OpenBao réel (`wrap → status → consume` **réussit**, prouvant l'absence de révocation ; contraste avec `secret_wrap_lookup` qui révoque).

## [0.8.2] — 2026-07-17

### Console admin — navigation par dossier des secrets (KV v2) + durcissements (issue #81)

Correctif du bug d'affichage : dans la console `/admin`, un vault contenant des **dossiers** KV v2 (préfixes, ex. `bootstrap/`, `mcp-teleport/`) affichait « Secret non trouvé » au clic, car l'UI tentait de **lire** un dossier comme un secret. La navigation par dossier manquait côté console — elle existait déjà côté agent MCP (`secret_list(vault_id, prefix)`). Plan validé par revue adversariale (Codex, OpenBao réel).

- **Navigation par dossier (console + API admin)** — `GET /admin/api/vaults/{id}/secrets?prefix=<sous-dossier>` liste le contenu d'un niveau ; l'UI distingue **dossier** (suffixe `/`, dépliable) et **feuille** (secret, lisible), avec expansion niveau par niveau. Les clés listées étant relatives au préfixe, l'UI reconstruit le chemin complet.
- **Moindre privilège sur le contenu (defense-in-depth)** — plus aucune surface ne divulgue le contenu d'un vault (noms **ou** simple cardinalité) à une identité sans droit de **lister** :
  - la fiche d'un vault (`GET /admin/api/vaults/{id}`) ne renvoie plus les noms (`secret_keys` retiré) ni de compteur (`get_space_info(count=False)`, aucun `list` indirect) ; la console affiche le nombre d'entrées à partir du **listing contrôlé** ;
  - le listing (racine incluse) passe **toujours** par `check_policy("secret_list")` + `check_path_policy` ;
  - la **cardinalité** (`root_entries_count`/`secrets_count`) exposée par le tableau des vaults, le tableau de bord et l'outil agent `vault_info` est désormais **conditionnée au droit de lister** (`can_read_vault_content`, test **silencieux** — pas de faux `denied`). Une identité autorisée conserve le compteur (contrat inchangé) ; sinon il est **omis** (UI : « — »).
- **Contournement de policy fermé (« validate vs use »)** — le préfixe de listing est **canonicalisé avant** `check_path_policy` (`normalize_list_path`, côté console **et** agent MCP), pour que le contrôle de droits et l'appel OpenBao portent sur la **même** valeur. Sinon `?prefix=%2F` (→ `/`), autorisé par une policy sur `/`, listait la racine (`""`). Le préfixe `/` seul est rejeté.
- **Compteur honnête** — l'ancien « Secrets : N » comptait en réalité les **entrées de premier niveau** (dossiers compris). Libellé corrigé en « Entrées » ; nouveau champ `root_entries_count` (sémantique explicite, sans parcours récursif). Une **erreur backend** n'est plus présentée comme « 0 » : la cardinalité inconnue est **omise** (UI : « — »), distincte d'un vault vide (0). `secrets_count` conservé (compat MCP `vault_info` / CLI), même valeur, sémantique documentée (entrées, pas feuilles).
- **Validation de chemin canonique (anti-traversal, cohérent #78)** — `_validate_secret_path` valide désormais **par segments** : rejet des segments vides (`//`, slash terminal), de `.` et `..`, contrôle de type, et **message constant** (la valeur rejetée n'est plus réinjectée dans la réponse ni dans l'audit MCP → vecteur d'injection de journal fermé). `list_secrets` applique cette validation **avant** tout appel OpenBao (elle en était dépourvue), ce qui durcit aussi l'outil MCP `secret_list`.
- **Routage admin durci** — le segment `/secrets` est reconnu exactement (écarte `/secretsfoo`) et les doubles slashs ne sont plus masqués silencieusement.
- **UI** — identifiants d'éléments dépliables rendus bijectifs (hex UTF-8) pour éviter la collision `a/b` vs `a_b`.
- **Tests** — `tests/test_secrets_folder_nav_81.py` (28 tests unitaires : validation canonique, canonicalisation `normalize_list_path` + non-contournement `?prefix=/`, routage, fuite noms **et** cardinalité, gating moindre-privilège `can_read_vault_content` (admin/mission/token/policy) sans faux audit, comptage `count=False`/erreur≠0, `domId` bijectif et somme `sumRootEntries` du dashboard exécutés sous Node) + `tests/test_secrets_folder_nav_openbao_81.py` (5 tests d'intégration OpenBao réel : dossiers/feuilles, clés relatives, collision feuille+dossier, lecture d'un dossier, préfixes piégés rejetés). Non-complaisance vérifiée par sabotage (4 rounds de revue adversariale Codex sur OpenBao + PolicyStore réels).

## [0.8.1] — 2026-07-15

### Durcissement `secret_consume` — hygiène & anti-injection de journal (issue #78, Lot A)

Premier lot du durcissement de `secret_consume`, issu d'une revue adversariale (5 rounds, OpenBao réel) du contrat de sortie du broker de secrets. Correctifs **autonomes**, **sans impact sur le contrat de succès**. Les lots B (états terminaux + HMAC anti-DoS sur l'unwrap) et C (autorisation consommateur / cohérence mode `jwt`) suivront.

- **Validation stricte des identifiants (`fullmatch`)** — `_SAFE_ID_RE.match()` acceptait une fin de ligne (`op\n` : le `$` matche avant un `\n` final), laissant passer une injection de saut de ligne dans les journaux. Nouveau validateur centralisé `is_safe_id()` (`fullmatch` + refus des non-`str`, fail-close), appliqué à `secret_consume` (qui ne validait pas `operation_id`), `secret_wrap`, `secret_revoke_wrap`, `secret_wrap_lookup` et au cœur `_validate_inputs` (dont `vault_id`/`secret_path`) — **avant tout audit**. `secret_revoke_wrap` ne reflète plus un `lease_id` non validé.
- **Défense centrale d'audit** — `AuditStore` neutralise les caractères de contrôle (C0 + DEL + C1 dont U+0085 NEL + séparateurs Unicode U+2028/U+2029) sur tous les champs, à l'**écriture** et au **rechargement** (`load_recent`) ; `sanitize_audit_field()` (publique) est robuste sur les valeurs non-`str`.
- **Codes d'erreur fermés (anti-reflection)** — les `reason` qui interpolaient une valeur non vérifiée ne le font plus : `unsupported_algorithm:{alg}` → `unsupported_algorithm` ; `mission_status:{state}` / `mission_status_http:{code}` → `mission_inactive` / `mission_status_error` ; `jwks_http_{status}` → `jwks_http_error`. Les valeurs brutes restent en log serveur, **jamais** renvoyées au client ni versées à l'audit humain. `service_unavailable` (logique 503 du middleware) préservé.
- **Messages client génériques** — `secret_consume` ne renvoie plus le `reason`/`status_reason` détaillé (`"Mission token invalide"`, `"Mission non active"`).
- **Journaux serveur anti-injection** — les valeurs externes (claims du refus PEP sur `stderr`, état de mission, `operation_id`/`mission_id`/`vault_id`/`secret_path` issus du registre ou d'un claim) sont sanitisées ou journalisées via `repr`.
- **Tests** — nouveau `tests/test_consume_hygiene_78.py` (23 tests non-complaisants : `fullmatch`, sanitisation d'audit + rechargement + C1/Unicode, non-reflection des `reason`, non-injection `stderr` PEP, log du broker) + renforcement des tests d'injection existants.

### Fiabilité du harnais de test (issue #64)

Durcissement **test-only** (aucun code de production) mergé après la 0.8.0 : stub `hvac` déterministe fail-close, `sys.path` centralisé, markers `needs_server`/`needs_s3` + opt-in `MCP_VAULT_E2E`, fixtures anti-complaisance (`assert FAIL == 0`), migration du contrat `space_ids` → `allowed_resources`. Fiabilise la suite de tests sans changer le comportement produit.

## [0.8.0] — 2026-07-10

### PEP mission JWT — durcissement de la porte /mcp (issue #47, PR1)

Second point d'application (PEP) pour les `mission_token` JWT ES256 émis par mcp-mission, **à l'entrée `/mcp`** — complémentaire du PEP existant à la consommation (`secret_consume`, C18 #26/#29). Contrat validé factuellement contre le code émetteur mcp-mission v0.5.0 (le token ne porte **aucune** autorisation vault : `aud`=liste de refs d'instance, `component_id={kind:ref}`, `tenant_id`/`mission_id`/`jti`/`scope` opaque ; **pas** de claims `vaults`/`permissions`).

**Périmètre PR1 (durcissement + authN)** : une identité mission JWT est authentifiée et liée à l'instance, mais n'a **aucun accès vault** (deny-by-default). L'octroi d'un périmètre vault local (MissionBindingStore keyé par `tenant_id`) est livré en PR2.

- Nouveau `mcp_auth_mode` (`bearer` par défaut — **zéro impact** — / `jwt` / `dual-stack`), `mcp_instance_id`, `mcp_component_kind` + `resolved_mission_aud` (source unique d'audience) + `check_mission_pep_config()` **fail-fast au boot** (jwks_url/audience requis en mode ≠ bearer ; refus si `mcp_instance_id`/`mission_token_aud` divergent).
- **`AuthMiddleware`** = unique lecteur du header et writer du contextvar sur `/mcp`, avec **refus ACTIF** au middleware : `401` (token absent/opaque/JWT invalide), `403` (`aud`/`component_id` ≠ instance, mission inactive), `503` (JWKS indisponible — fail-close). Bootstrap key admin acceptée en break-glass (testée en constant-time **avant** tout dispatch JWT). En `dual-stack`, un JWT invalide **ne retombe jamais** sur le chemin bearer (pas de fallback silencieux). Détection JWT **structurelle** (anti alg-confusion : un compact `alg=none`/`HS256` → 401, jamais bearer).
- **Cache JWKS unique** du processus (`auth/mission_jwt.py` : backoff exponentiel + jitter, ETag/`If-None-Match`→304, **fail-close** — un cache expiré n'est jamais servi). `MissionTokenValidator` (secret_consume) y délègue désormais sa résolution de clé : plus de second cache/rate-limit divergent.
- **Autorisation locale deny-by-default** pour `auth_type="mission_jwt"` : `check_access` refuse sans périmètre explicite (jamais d'owner-based) ; `get_listing_filter()` centralise le filtrage de `vault_list` (0 vault visible pour une identité mission non provisionnée) ; `enforce_mission_jwt_tool()` restreint les outils à une allowlist data-plane + utilitaires publics — `system_health`/`system_about` (métadonnées d'infra) et l'inventaire PKI sont **refusés** aux identités mission.
- **Vérification mission active** en allow-list `{RUNNING, WAITING_HUMAN, PAUSED}` (fail-close : un état inconnu = inactif — corrige l'ancienne deny-list ; `PAUSED` reçoit des tokens re-signés côté mcp-mission).
- **Endpoint admin** `POST /admin/api/auth/jwks/reload` (admin only) pour propager une révocation de `kid` sans attendre le TTL. L'Admin API reste **bearer/bootstrap-only** : un mission JWT y est refusé (401) sur toute la surface `/admin/api/*`.
- **Audit** immuable de chaque refus PEP (`decision_id` local + `decision_id` émetteur via `provenance` pour corrélation E2E, `tenant_id`, `mission_id`, `reason_code`) — **jamais** le token ni un secret.
- **Durcissement fail-close aligné MCP ↔ Admin REST** : `check_access`/`get_listing_filter` (MCP) et `_check_vault_access`/`GET /admin/api/vaults` (Admin REST) typent désormais `allowed_resources` en liste (un token mal formé ne peut plus provoquer un test de sous-chaîne) et refusent une identité incomplète (`client_name` vide) au lieu de lister tous les vaults. Anti-DoS sur le JWKS : throttle des refresh déclenchés par un `kid` inconnu (au plus un fetch réseau par fenêtre, quel que soit le volume).

### PEP mission JWT — octroi de périmètre vault local / MissionBindingStore (issue #69, PR2)

Suite de #47 (PR1). L'identité mission JWT, jusqu'ici authentifiée mais **sans aucun accès vault** (deny-by-default), peut désormais se voir **octroyer un périmètre vault provisionné localement** — mcp-vault jouant le rôle de **PDP local** (le `mission_token` ne porte aucune autorisation vault). L'octroi est indexé par `tenant_id` (claim stable) et reste **deny-by-default** : sans octroi, aucun accès.

- **Nouveau `MissionBindingStore`** (`auth/mission_bindings.py`) — store S3 **un fichier par instance** (`_system/mission_bindings/{encoded_instance_id}.json`, réduit le last-write-wins cross-instance), cache TTL 5 min, calqué sur PolicyStore/TokenStore. Un binding = `{tenant_id, allowed_resources:[vault…], permissions, policy_id?, enabled, expires_at?}`.
- **Contrat permissions STRICT** : un octroi vaut exactement `["read"]` ou `["read","write"]` — `["write"]` seul, `[]` et `admin` sont **refusés** (il n'existe pas de contrôle de lecture séparé : garantir `read` empêche qu'un octroi mal formé laisse lire).
- **Data-plane strict** : une identité mission ne peut faire que du data-plane secrets (`vault_list/info`, `secret_read/list/write/delete`). L'admin-plane (`vault_create/update/delete`, `ssh_*`) est **retiré de l'allow-list mission** — réservé aux bearers admin. Une mission ne se voit **jamais** déléguer de surface d'administration.
- **Résolution à la porte `/mcp`** (`AuthMiddleware`) : après validation JWT + mission active, `MissionBindingStore.resolve(tenant_id)` peuple `allowed_resources`/`permissions`/`policy_id`. Absent/désactivé/expiré → deny-all préservé. **Store indisponible/corrompu → `503 binding_store_unavailable`** (refus observable audité, jamais un deny silencieux ; état `available/invalid` explicite, aucune écriture destructrice sur un fichier corrompu).
- **CRUD admin** `GET/POST /admin/api/mission-bindings`, `GET/DELETE /admin/api/mission-bindings/{tenant_id}`, `POST .../purge` (bearer/bootstrap-only, **jamais** via mission JWT) + **parité CLI/shell** (`mission-binding create|list|get|delete|purge`). Purge des bindings expirés au-delà d'une rétention (fail-close sur date corrompue).
- **Validations défensives** : `tenant_id` URL-safe (segment `purge` réservé), `allowed_resources` = vrais `vault_id` (regex, non vides, dédupliqués, pas de `*`, taille bornée), intégrité référentielle du `policy_id` (refus si inexistant).
- **Granularité tenant-wide (assumée)** : toutes les missions actives d'un tenant partagent le périmètre octroyé. Le grain par mission existe déjà à la consommation (`secret_consume`/C18) ; le grain par mission sur ce chemin direct est une évolution future.
- **Audit** des mutations d'octroi (create/delete/purge) avec `decision_id` en tête du détail — jamais de secret. Le provisioning agentic (#62) écrira dans ce store (créer un binding tenant→coffres au lieu d'un bearer manuel).

### Correction fail-open `dry_run` — purge des tokens révoqués (dette task_a5346701)

Jumeau de la faille fermée en #69 (purge de bindings). `POST /admin/api/tokens/purge` faisait `dry_run = bool(data.get("dry_run", False))` : une valeur falsy **non booléenne** (`[]`, `0`, `""`, `null`) était coercée en `False` → déclenchant une purge **réelle** (destructive) qu'on croyait simuler.

- `dry_run` est désormais validé **strictement** (`isinstance(..., bool)`) : toute valeur non booléenne → `400`, **aucun appel** au store — alignement exact sur `_api_purge_mission_bindings` (le pattern déjà durci en #69).
- Tests de non-régression red-team : `dry_run ∈ {[], 0, "", null, "true", "false", 1, 1.0, {}, [1]}` → `400` sans purge (ni audit) ; régression inverse vérifiée (un vrai `True` simule encore, un vrai `False` purge bien).

### Validation de l'expiration des tokens à la création (issue #65)

La création de token gérait mal `expires_in_days`, des **deux côtés** : le frontend admin (`parseInt(v) || 90`) écrasait un `0` (illimité voulu) en 90 jours — l'UI ne pouvait **pas** créer de token sans expiration ; le backend, lui, ne validait rien — `null`/`-1`/`""` créaient un token **illimité par accident** et `"0"` (string) provoquait un `TypeError` → **HTTP 500**.

Décision : **tokens illimités autorisés mais EXPLICITES**. Contrat unique de `expires_in_days` sur tous les chemins : champ omis → `90` (défaut sûr) ; `0` → jamais expirer (illimité explicite) ; entier `[1, 36500]` → durée en jours ; **tout le reste rejeté** (négatif, hors borne, `bool`, `float`, string, `null`).

- **Source unique** `TokenStore.validate_expires_in_days()` (constante `MAX_EXPIRES_IN_DAYS = 36500`, borne de politique cohérente avec la purge), appelée par le **store** (défense en profondeur) et par la **frontière REST** `POST /admin/api/tokens` (→ `400`, plus jamais de `500`).
- **Frontend** : module isolé `static/js/expires.js` (`parseExpiresInDays`) — validation stricte sans coercition (`"1.5"`/`"1abc"`/`"0.0"` → erreur UI, **aucun envoi**), `0` honoré. Testé sous Node (`tests/js/expires_contract.test.js`).
- **CLI** : `--expires` en `IntRange(0, 36500)` (Click) ; **shell** : parse fail-close (`--expires` non entier / négatif / hors borne / manquant → aucune création).
- ⚠️ **Changement de contrat** : `POST /admin/api/tokens` **rejette désormais** `expires_in_days` envoyé en **string** (ex. `"90"`) ou toute valeur non entière. Un appelant qui envoyait une string doit envoyer un entier JSON.
- Hors périmètre (documenté) : les tokens **déjà** créés en illimité par accident restent inchangés (repérables via `token list`, colonne « jamais ») ; `token_update` ne gère pas l'expiration (inchangé).

### Observabilité AuditStore (issue #61)

`AuditStore.log()` avalait silencieusement toute erreur d'écriture du fichier JSONL (`except Exception: pass`). En cas de panne disque, répertoire absent ou problème de permission, aucune trace n'était produite.

- `AuditStore.log()` logue désormais sur `stderr` chaque échec d'écriture avec le chemin, le type d'exception et le message.
- Nouveau compteur `_write_errors` incrémenté à chaque échec.
- `get_stats()` expose `write_errors` dans tous les cas de retour (buffer vide inclus) — visible via l'outil MCP `audit_log` et l'API admin `/admin/api/audit`.
- Dead code `self._file = None` supprimé.

### Correction asymétrie vault_create MCP/REST — contrôle d'accès vault-level (issue #58)

`POST /admin/api/vaults` ne vérifiait pas l'accès vault-level (`check_access`) avant de créer un vault, contrairement au chemin MCP `vault_create`. Un token scopé (ex. `allowed_resources=["vault-a"]`) pouvait créer n'importe quel vault via l'API REST.

- **`_api_create_vault`** reçoit désormais `token_info` et appelle `_check_vault_access(token_info, vault_id)` après validation de `vault_id` — retourne 403 si le token n'est pas autorisé sur ce vault.
- Cohérent avec `_api_update_vault` / `_api_delete_vault` qui appliquaient déjà ce contrôle au routeur (vault_id dans l'URL).
- Pas de régression admin : un token admin passe toujours.
- Pas de régression owner-based : `check_vault_owner` retourne `True` pour un vault inexistant (création autorisée pour le créateur).

### CI — tag + GitHub Release automatiques au bump de VERSION (issue #56)

Premier workflow GitHub Actions du dépôt (`.github/workflows/release.yml`). Au merge sur `main` modifiant `VERSION`, crée automatiquement le tag annoté `vX.Y.Z` + la GitHub Release (notes = section correspondante du CHANGELOG). Idempotent et re-run safe (tag et release gérés indépendamment ; tag existant vérifié contre `GITHUB_SHA`) ; validation stricte de `VERSION` (`X.Y.Z`) ; `actions/checkout` épinglé par SHA. Corrige la cause de l'oubli du tag v0.7.0 (déploiement « par commit nu »).

### Cohérence documentaire + parité CLI (issue #59)

- README (fr + en) et DESIGN (ARCHITECTURE/TECHNICAL) alignés sur v0.7.0 : purge des tokens révoqués (#50) et audit du cycle de vie des accès (#49) documentés ; routes `/admin/api/*` à jour ; compteur d'endpoints périmé corrigé.
- Nouvelle commande CLI **`logs`** (click + shell) → `GET /admin/api/logs`, pour aligner le CLI sur la console admin ; aide PKI du shell complétée (`issue`).

## [0.7.0] — 2026-06-22

Milestone **« Durcissement auth & conformité »** : traçabilité d'audit du plan de contrôle d'accès (SecNumCloud/HDS), purge des tokens révoqués, et défense en profondeur sur la création de tokens.

### Purge des tokens révoqués (issue #50)

Opération admin pour purger les tokens révoqués accumulés dans `_system/tokens.json` (aucune GC n'existait). Exposée dans `/admin` et `mcpcli.py` (commande click + shell).

- **`TokenStore.purge_revoked(older_than_days=30, dry_run=False)`** : ne supprime que les tokens **révoqués** dont `revoked_at` est antérieur à la rétention (défaut 30 j ; la valeur est bornée `[0, 36500]` par la route REST). **Fail-close** : un token révoqué sans `revoked_at` parseable (absent / corrompu / sans fuseau) n'est jamais purgé. Discipline `_save()` + **rollback complet** si S3 indisponible (aucun token perdu).
- **N'affecte jamais** un token actif, ni un token **expiré mais non révoqué** — ce dernier doit rester visible (on a besoin de savoir qu'un token est expiré, quitte à le révoquer ensuite).
- **Route `POST /admin/api/tokens/purge`** réservée admin ; `dry_run` retourne le décompte des candidats sans rien supprimer.
- **Audit** : chaque token réellement purgé + un récapitulatif sont journalisés (`token_purge`). La trace vit dans `audit-mcp.jsonl`, indépendant de `tokens.json` → elle **survit** à la purge. Échec de persistance → 503 + audit `error`. Jamais de secret dans le détail.
- **dry-run + confirmation** : SPA (dry-run → confirmation du décompte → exécution), CLI click (`--older-than`, `--dry-run`, `--yes`), shell (exige `--yes` ; **fail-close** sur `--older-than` invalide/incomplet ou dry-run en échec).

### Traçabilité d'audit du cycle de vie des accès (issue #49)

Les mutations du plan de contrôle d'accès via l'API REST admin n'étaient **pas** journalisées (`log_audit` jamais appelé dans `admin/api.py`) — écart de traçabilité SecNumCloud/HDS.

- **REST** : audit ajouté sur `_api_create_token` (`token_create`), `_api_update_token` (`token_update`), `_api_revoke_token` (`token_revoke` — succès **et** échec de persistance), `_api_create_policy` (`policy_create`), `_api_delete_policy` (`policy_delete` — succès + échec).
- **MCP** : `policy_create` et `token_update` passent désormais par le helper `_r()` (comme `policy_delete`) ; `policy_delete` trace aussi le chemin « suppression non persistée ».
- Jamais le token brut dans le détail. La trace est physiquement indépendante de `tokens.json`.

### Validation des permissions à la création de token — défense en profondeur (issue #48)

- `TokenStore.create()` valide désormais les permissions (rejet : liste vide, non-liste, flag hors `{read, write, admin}`, élément non-hashable) **avant** toute écriture S3. Le point d'entrée HTTP validait déjà type et flags (V3-03) mais pas la liste vide ; ce correctif sécurise le store lui-même (liste vide incluse) quel que soit l'appelant.
- Source unique de vérité `TokenStore.VALID_PERMISSIONS` (frozenset), réutilisée par `create()`, `update()` et `admin/api.py` (suppression de 3 copies dupliquées).

### Tests

- `tests/test_token_permissions.py`, `tests/test_audit_lifecycle.py`, `tests/test_purge_revoked.py`, `tests/cli/test_purge_shell.py` — tests offline **non-complaisants** : garde admin 403, fail-close, rollback S3, audit par opération, token brut jamais exposé, fail-close du shell.

### Revue

Chaque lot a passé une revue **Codex** (read-only) jusqu'à `APPROUVÉ` ; #50 a aussi fait l'objet d'une **revue adversariale multi-agents**.

> **Note dette** : `AuditStore.log()` avale silencieusement les erreurs d'écriture JSONL (`except: pass`) — préexistant, à corriger séparément.

## [0.6.8] — 2026-06-11

### PKI/ACME — enrollment end-to-end fonctionnel (issue #41)

Première validation **réelle** de l'enrollment ACME de bout en bout : un WAF Caddy obtient un certificat TLS depuis la PKI interne (challenge tls-alpn-01 → finalize → cert émis), à travers le WAF en HTTPS. Le test révèle et corrige une cascade de blocages jusqu'alors invisibles (tests mockés + T1/T7 jamais exécutés en conditions réelles).

#### WAF (`waf/coraza.conf`)
- **920420** « Request content type not allowed » : exclu sur les paths ACME — ACME utilise `Content-Type: application/jose+json` (JWS, RFC 8555), non autorisé par le CRS par défaut.
- **Regex d'exclusion ACME élargie** au sous-arbre complet (`^/acme/[a-zA-Z0-9/_\-]{1,256}$` et `/v1/_sys_pki_int/acme/...`) : couvre les endpoints dynamiques `authorization/<id>`, `order/<id>`, `order/<id>/finalize`, `challenge/<id>`, `certificate/<id>` — auparavant 403. Anti-traversal assuré en amont par `PkiMiddleware`.

#### Rôle ACME (`vault/pki_ca.py`)
- `key_type` `rsa` → **`any`** : les clients ACME (Caddy) génèrent des clés EC par défaut ; imposer RSA causait `badCSR - requires rsa`.
- **`allow_bare_domains=True`** : émettre pour les domaines exactement listés (sinon `rejectedIdentifier` sur le FQDN nominal).
- **`allow_glob_domains=True`** : support des patterns `*.domain` dans `allowed_domains`.

#### WAF TLS paramétrable (`waf/Caddyfile`, `docker-compose.yml`)
- `WAF_TLS_DIRECTIVE` (vide par défaut = prod inchangée) : permet d'activer `tls internal` pour servir le directory ACME en HTTPS (Caddy refuse l'ACME sur une CA HTTP).

#### Infra de test E2E (`tests/pki/`)
- `docker-compose.test-tls.yml` (override TLS), alias réseau `test.lesur.lan`, Caddyfile pointant le directory HTTPS. Procédure documentée pour rejouer l'enrollment complet.

> **Prérequis de déploiement** : l'image mcp-vault doit être rebuildée (le tuning `allowed_response_headers` de #32, requis pour le header `Replay-Nonce`, n'était pas dans les images < v0.6.4).

## [0.6.7] — 2026-06-11

### Fix WAF — exclusions CRS inopérantes en phase:1 (issue #42, BLOQUANT prod)

Le fix #37 (v0.6.4) était **déployé mais inopérant** : `/pki/ca/*.pem` répondait toujours **403** à travers le WAF.

#### Cause racine
`ctl:ruleRemoveById` ne retire qu'une règle **pas encore évaluée** dans la transaction. Coraza évalue les règles d'une phase dans l'ordre du fichier. Les exclusions (`10001`-`10007`) étaient placées **après** l'`Include` du CRS ; or 920440 et 920540 sont en **phase:1** → elles s'exécutaient et scoraient **avant** le `ctl` → blocage en phase:2 (949110) sur le score accumulé. Seul 932120 (phase:2) était effectivement neutralisé.

#### Fix
`waf/coraza.conf` : bloc d'exclusions déplacé **AVANT l'`Include` du CRS** (pattern CRS standard « exclusions before CRS »). Les `ctl:ruleRemoveById` en phase:1 retirent alors les règles ciblées avant leur évaluation — phase:1 comprise. Régularise aussi 920540 (v0.5.1, inopérante depuis l'origine).

#### Validation — test d'intégration réel à travers le WAF (non négociable)
Rebuild WAF + `curl http://localhost:8085` :
- `/pki/ca/root.pem` · `/chain.pem` · `/crl.pem` → **200** (PEM valide)
- `/pki/ca/evil.pem` · `/test.pem` → **403** (920440 actif, exclusion strictement scopée)
- SQLi · XSS → **403** (WAF protège toujours) ; `/acme/directory` → **200** ; `/health` → **200**
- Test négatif **T3d** ajouté à `tests/pki/test_pki_integration.sh` (scoping strict).

Aucun impact CLI/SPA (conf Coraza transparente). Codex APPROUVÉ.

## [0.6.6] — 2026-06-11

### Génération de certificat depuis /admin + CLI (issue #41, partie 2/2)

Nouvel outil `pki_issue_cert` (36 outils MCP) : émission manuelle d'un certificat serveur signé par la CA intermédiaire, hors ACME — pour le debug, l'exploitation et les cas sans enrôlement automatique.

#### Backend (`vault/pki_ca.py`, `server.py`, `admin/api.py`)
- `pki_issue_cert(common_name, ttl?, alt_names?, ip_sans?)` (admin).
- **Rôle dédié `manual-servers`** (création idempotente) : `allow_ip_sans=True`, `no_store=False` (inventaire), wildcards refusés — distinct du rôle ACME (reco Codex).
- **Validation locale** avant émission : CN + SANs DNS contre les `allowed_domains` de la PKI, IP via `ipaddress`, format **et borne max** du TTL (vs `max_ttl` du rôle), wildcard interdit.
- **Clé privée one-shot** : retournée une seule fois, jamais stockée côté Vault, jamais journalisée ni auditée (audit filtre `private_key`/`certificate`/`ca_chain`).
- Route REST `POST /admin/api/pki/issue` (admin, codes 400/500).

#### CLI (`pki issue`)
- Click + shell : `pki issue <common_name> [--ttl] [--alt-names] [--ip-sans]`.
- Affichage avec alerte **SENSIBLE** sur la clé privée.

#### SPA `/admin`
- Bouton « Générer un certificat » + modale `modalPkiIssue`.
- Clé privée affichée via `textarea.value` (jamais `innerHTML`), **sans copie automatique** au presse-papier (décision Codex).

#### Tests
- `tests/test_pki.py::TestIssueCertificate` (9 tests) : nominal, domaine refusé, wildcard, TTL format + borne max, IP invalide, alt_name validé, `allowed_domains` en CSV, clé privée absente de l'audit. `tests/cli/test_pki.py` : `pki issue`. 44/44 PKI verts.

> Partie 1/2 (#41) livrée en v0.6.5 (refonte CSS du panneau PKI).

## [0.6.5] — 2026-06-11

### UI — panneau PKI /admin lisible (issue #41, partie 1/2)

Le panneau PKI s'affichait cassé : `pki.js` utilisait des classes CSS jamais définies dans `admin.css` (labels collés aux valeurs, pas de grille de cartes).

- `admin.css` : ajout (patch additif ciblé, recommandation Codex) des classes `card-grid`, `card-label/value/value-big/sub`, `section-title`, `url-list/row/label/value`, `btn-copy`, `btn-warn`, `badge-danger`, `mono-tiny/small`, `table-wrapper`, `empty-row`, `page-header`, `error-banner`, `success-banner`, `loading` — cohérentes avec le design system Cloud Temple.
- Responsive : `.table-wrapper` scroll horizontal, lignes URL empilées + header en colonne sur mobile.
- Aucune classe existante modifiée (hors spécialisation `.card-grid .card`).

> Partie 2/2 (issue #41) : génération de certificat `pki_issue_cert` (backend + CLI + modale) — PR séparée.

## [0.6.4] — 2026-06-11

### Fixes PKI prod — distribution CA/CRL + inventaire vide (issues #37, #38)

Deux correctifs bloquants/trompeurs détectés lors de l'audit prod v0.6.2 (suite #32).

#### #37 — WAF bloquait la distribution CA/CRL (BLOQUANT)
- `waf/coraza.conf` : la règle d'exclusion `10005` ne retirait pas la règle CRS **920440** (« URL file extension is restricted »), qui bloque l'extension `.pem`. Résultat : `/pki/ca/root.pem`, `/chain.pem`, `/crl.pem` répondaient **403** à travers le WAF (l'app les servait pourtant en 200).
- Correctif : ajout de `ctl:ruleRemoveById=920440`, **restreint aux 3 fichiers** `^/pki/ca/(root|chain|crl)\.pem$` (pas d'ouverture WAF sur d'autres paths).
- Sans CA/chain téléchargeables ni CRL accessible, aucun client ne pouvait établir la confiance — la distribution PKI n'avait jamais fonctionné via le WAF.

#### #38 — Inventaire PKI/SSH vide affiché comme erreur
- `hvac client.list()` retourne `None` sur un chemin vide (PKI/SSH fraîchement initialisée — état nominal) → `AttributeError: 'NoneType' object has no attribute 'get'`, affichée en bandeau rouge dans `/admin`.
- Helper commun `vault/_hvac_utils.py::safe_list_keys()` appliqué à 3 call-sites : `list_issued_certs`, `list_pki_roles` (pki_ca.py), `list_ssh_roles` (ssh_ca.py).
- Une PKI/SSH vierge retourne désormais `ok` / `total=0`.

#### Tests
- `tests/test_pki.py::TestEmptyInventoryNoneSafe` : helper + PKI vierge + rôles PKI/SSH vierges → `ok`, pas d'erreur.
- À valider en Docker (#37) : `curl http://waf:8085/pki/ca/root.pem` → 200 (test d'intégration à travers le WAF).

## [0.6.3] — 2026-06-11

### Synchronisation des surfaces — affichage EAB + JIT broker au CLI (issue #34)

Alignement des surfaces (SPA `/admin`, CLI Click, shell) sur le backend, suite à l'audit post-v0.6.2. Aucun changement de comportement serveur.

#### SPA `/admin`
- `pki.js` : le statut PKI affiche désormais l'état **EAB** (`eab_required` + `eab_policy`) dans une carte dédiée — un admin voit si l'enrôlement ACME est protégé (`esc()` appliqué, pas de régression XSS).

#### CLI — affichage
- `display.py` `show_pki_result()` : ajout de la ligne `eab_policy` (diagnostic `not-required` / `new-account-required`).

#### CLI — JIT Wrap Broker exposé (Click + shell)
- Nouvelles commandes `secret wrap`, `secret revoke-wrap`, `secret wrap-lookup` (contrat M2M mcp-mission), pour le debug, la révocation et les tests de contrat.
- `secret wrap` supporte le binding C18 (`--tenant-id`, `--expected-aud`) en Click **et** en shell (parité).
- `show_wrap_result()` : affiche le `wrap_token` avec alerte **SENSIBLE** et remonte toujours la `note` (ex. registry indisponible) en warning.
- **Décision (Codex)** : le broker n'est **pas** exposé en SPA (surface XSS / fuite presse-papier sur les wrap tokens).

#### Tests
- Tests CLI non-complaisant (`tests/cli/test_secret.py`) : vérifient les appels MCP réels (`secret_wrap`/`revoke_wrap`/`wrap_lookup`), le binding C18 transmis, et l'alerte SENSIBLE.

> **Note** : `secret_wrap`/`secret_revoke_wrap`/`secret_wrap_lookup` existaient depuis v0.4.13 (JIT broker, issue #7) mais n'étaient exposés sur aucune surface humaine. Couverture CLI désormais complète.

## [0.6.2] — 2026-06-11

### Fix PKI mode Prod — eab_policy invalide (issue #32)

L'initialisation de la PKI interne en mode **Prod** (`lab_mode=False`) échouait systématiquement à l'étape `config/acme`.

#### Bug bloquant
- `vault/pki_ca.py` : `eab_policy="required"` **n'existe pas** dans OpenBao (valeurs valides : `not-required`, `new-account-required`, `always-required`). Tout setup prod échouait avec `invalid eab policy name provided`.
- Correctif : `eab_policy = "not-required"` (lab) / `"new-account-required"` (prod) — l'EAB est exigé à la création de compte ACME, ce qui bloque l'enrôlement public non authentifié sans casser les comptes existants.

#### Bugs secondaires (cohérence status)
- `eab_required` était calculé via `eab_policy == "required"` (jamais vrai) → helper `_eab_required()` (`new-account-required`/`always-required` → True).
- `eab_policy` désormais exposé dans les retours `setup_pki_ca()` et `get_pki_status()`.

#### Réserves ACME traitées
- **`allowed_response_headers`** : le mount intermédiaire est tuné pour autoriser les headers ACME (`Replay-Nonce`, `Link`, `Location`) — sinon OpenBao les strippe et l'enrôlement ACME réel (T1/T7) échoue.
- **`sign-intermediate`** : `issuer_ref` déplacé du body vers le path `/issuer/mcp-vault-root/sign-intermediate` (forme documentée OpenBao).

#### Tests
- 8 tests non-complaisant (`tests/test_pki.py::TestEabPolicyProd`) : inspection du payload réel `config/acme`, helper `_eab_required`, tuning headers (+ fail-hard si KO), path sign-intermediate (setup + rotation). 43/43 tests PKI verts.

> **Note de remédiation prod** : l'échec laissait un état partiel (root + intermédiaire + rôle ACME créés, `config/acme` manquant). Le setup étant idempotent, un simple retry après ce fix termine l'initialisation — aucun nettoyage requis.

## [0.6.1] — 2026-06-11

### Hardening C18 — singleton JWT + binding complet tenant_id/aud (issue #29)

Corrections de sécurité post-audit Codex v0.6.0. Aucun changement d'interface publique.

#### P0 — MissionTokenValidator singleton process-wide
`secret_consume` réinstanciait `MissionTokenValidator` à chaque appel : le cache JWKS (60s) et le rate-limit (3 refreshes/min) étaient donc par-requête et non globaux.

- `auth/jwt_validator.py` : `init_mission_token_validator()` + `get_mission_token_validator()` — singleton module-level
- `lifecycle.py` : initialisation au startup (step 1e) — un seul validateur partagé pour tout le processus
- `server.py` : `secret_consume` utilise le singleton. Fail-close si singleton absent + `ENFORCE=true` (erreur `misconfigured`)

#### P1 — Binding C18 complet : tenant_id + expected_aud propagés
`tenant_id` et `expected_aud` étaient stockés dans le registry mais jamais renseignés par le flux réel (`secret_wrap` → `wrap_secret` → `register_pending` ne les passait pas) : le binding dans `consume_wrap_secret` était donc systématiquement ignoré en production.

- `vault/wrapping.py` : `wrap_secret()` + `register_pending()` acceptent `tenant_id` et `expected_aud`
- `server.py` : `secret_wrap` MCP accepte `tenant_id` et `expected_aud` (optionnels, rétrocompat)
- `server.py` : `expected_aud_from_jwt = settings.mission_token_aud` (audience validée par PyJWT, pas `jwt_claims["aud"]` qui peut être une liste non-ordonnée)
- Messages d'erreur `binding_mismatch` rendus génériques (ne révèlent plus le champ en échec)

#### Corrections additionnelles (3ème+4ème passe Codex)
- `secret_wrap` : en mode `ENFORCE=true` + JWKS, impose `expected_aud = settings.mission_token_aud` automatiquement si non fourni (wraps toujours bindés en mode enforced). Erreur `misconfigured` si `MISSION_TOKEN_AUD` est vide.
- `consume_wrap_secret` : en mode `enforce=True`, rejette les wraps sans `expected_aud` avec `binding_incomplete` (protège contre les wraps legacy en mode enforced)
- `expected_aud_from_jwt` dans `secret_consume` utilise `settings.mission_token_aud` (audience validée par PyJWT, pas `jwt_claims["aud"]` qui peut être une liste)

#### Tests non-complaisant ajoutés (10 tests)
- Singleton réutilisé entre appels (pas réinstancié)
- Fail-close si singleton absent + ENFORCE=true
- `secret_wrap` enrichit `expected_aud` automatiquement en mode ENFORCE=true
- `tenant_id` mismatch → rejeté avant `try_mark_consuming` (pas d'état orphelin)
- `expected_aud` mismatch → confused-deputy bloqué (message générique)
- Wrap legacy sans `expected_aud` → `binding_incomplete` en mode enforced
- Binding correct → consume nominal
- Rétrocompatibilité : champs vides dans le registry → binding ignoré (mode standalone)
- Propagation `tenant_id`/`expected_aud` de `wrap_secret` vers le registry
- Vérification que `try_mark_consuming` n'est pas appelé si binding mismatch

### Fichiers modifiés
- `src/mcp_vault/auth/jwt_validator.py` — singleton
- `src/mcp_vault/lifecycle.py` — init singleton au startup
- `src/mcp_vault/server.py` — secret_wrap + secret_consume
- `src/mcp_vault/vault/wrapping.py` — wrap_secret + consume_wrap_secret
- `tests/test_jwt_validator.py` — +2 tests non-complaisant
- `tests/test_wrap.py` — +6 tests non-complaisant

## [0.6.0] — 2026-06-10

### Anti-confused-deputy C18 — validation JWT mission_token ES256/JWKS (issue #26)

Alignement de mcp-vault sur la matrice E2E C18 : comme mcp-teleport, mcp-vault valide désormais l'identité de mission avant de libérer un secret. Purement additif — zéro impact sur les déploiements standalone (sans mcp-mission).

#### Nouvel outil MCP `secret_consume` (35 outils total)
```
secret_consume(wrap_token, operation_id, mission_token) → secret_data
```
- Valide le JWT mission_token ES256 (JWKS public mcp-mission)
- Vérifie les bindings registry : mission_id, tenant_id, aud (anti-confused-deputy)
- Vérifie la mission active côté mcp-mission (cache 5s, fail-close)
- Unwrap OpenBao cubbyhole + anti-replay (status: "consumed")
- Audit log sans données sensibles (wrap_token et mission_token jamais loggués)

#### `auth/jwt_validator.py` (nouveau module)
- `MissionTokenValidator` : cache JWKS TTL-borné (60s), refresh sur kid inconnu, rate-limit (3/min), détection kid révoqué post-refresh, thread-safe (threading.Lock)
- `MissionTokenError` : reason code machine, jamais le token compact dans le message
- Algorithme : ES256 uniquement

#### `vault/wrapping.py` — extensions C18
- `register_pending()` : +`tenant_id`, +`expected_aud` optionnels (binding JWT)
- `get_by_composite_key(operation_id, mission_id)` : lookup anti-collision (clé composite)
- `try_mark_consuming()` : atomic compare-and-swap "active" → "consuming" (anti-replay)
- `mark_consumed()` : "consuming" → "consumed" après succès OpenBao
- `rollback_consuming()` : "consuming" → "active" si OpenBao échoue
- Statuts étendus : `consuming`, `consumed`
- `consume_wrap_secret()` : unwrap médié complet

#### Nouveaux settings (8)
| Variable | Défaut | Description |
|----------|--------|-------------|
| `ENFORCE_MISSION_TOKEN_VALIDATION` | `false` | Hard-reject. False = log warning (migration) |
| `MISSION_JWKS_URL` | *(vide)* | JWKS public mcp-mission. Vide = validation désactivée |
| `MISSION_TOKEN_AUD` | *(vide)* | Audience vault_ref (anti-confused-deputy) |
| `MISSION_JWKS_CACHE_TTL` | `60` | TTL cache JWKS en secondes |
| `MISSION_JWKS_MAX_REFRESH_PER_MIN` | `3` | Rate-limit refresh JWKS |
| `MISSION_TOKEN_LEEWAY_SECONDS` | `10` | Tolérance clock skew |
| `MISSION_STATUS_URL` | *(vide)* | Vérification mission active (template {mission_id}) |
| `MISSION_STATUS_CACHE_TTL` | `5` | TTL cache statut mission (court — fail-close rapide) |

#### Corrections Codex (CRITIQUE×2 + ÉLEVÉ×1)
- thread-safety rate-limit JWKS (appelé sous threading.Lock par construction)
- `_mission_status_lock` créé au niveau module (anti-race création lazy)
- `rollback_consuming()` retourne bool + log si S3 fail

#### CLI — tokens sensibles via variables d'environnement
`secret consume` passe `wrap_token` et `mission_token` via `VAULT_WRAP_TOKEN` et
`VAULT_MISSION_TOKEN` (pas en arguments positionnels — évite l'exposition dans
`~/.bash_history`). Pattern identique à `MCP_TOKEN`/`ADMIN_BOOTSTRAP_KEY`.
`.env.example` documenté avec les 8 groupes de variables.

```bash
VAULT_WRAP_TOKEN=hvs.CAES... VAULT_MISSION_TOKEN=eyJ... \
mcp-vault secret consume op-123
```

#### Tests non-complaisant
- `tests/test_jwt_validator.py` (24 tests) : contrôle positif + 11 variantes C18 rejetées (signature, exp, iss, aud, mission_id, algo, kid révoqué, token compact jamais divulgué, malformé) + cache/rate-limit + WrapRegistry extensions + secret_consume standalone/enforce

### Fichiers modifiés
- `src/mcp_vault/auth/jwt_validator.py` *(nouveau)*
- `src/mcp_vault/vault/wrapping.py` — extensions C18
- `src/mcp_vault/server.py` — secret_consume + _check_mission_active
- `src/mcp_vault/config.py` — 8 settings JWT
- `requirements.txt` — PyJWT>=2.10.0
- `tests/test_jwt_validator.py` *(nouveau)* — 24 tests

## [0.5.1] — 2026-06-10

### Correctifs PKI ACME — validation en conditions réelles Docker (issue #15 T0-T10)

Tests d'intégration réels : **13/13 PASS** (T0, T3a/b/c, ACME directory, T5, T6a/b/c, T9a/b, T10).
T1/T7 (enrollment ACME) : nécessitent HTTPS sur le cluster path — fonctionnel en production avec WAF TLS.

#### Fixes bloquants
- **cluster path OpenBao ACME** : `config/cluster` désormais configuré avant `config/acme`. Appel via `client._adapter.post()` (hvac.write() a une collision de paramètre nommé `path`)
- **WAF bloquait `/pki/ca/*.pem`** : Coraza CRS retournait 403. Exclusions ajoutées avec regex stricte (seulement les 3 fichiers PEM/CRL connus + endpoints ACME normalisés RFC 8555)
- **CRL format** : proxy `/pki/ca/crl.pem` → `/v1/_sys_pki_int/crl/pem` (DER vs PEM)
- **setup_pki_ca idempotent** : `try/except "issuer name already in use"` exact pour root ET intermédiaire — évite de masquer d'autres erreurs
- **`PKI_BASE_URL` setting** : variable d'env pour override l'URL de base PKI (test Docker : `http://mcp-vault:8030`) avec validation anti-MITM

#### Nouveaux endpoints admin REST
- `GET /admin/api/pki/roles` — liste des rôles d'émission ACME
- `GET /admin/api/pki/roles/{role_name}` — détails d'un rôle (allow_any_name, domaines, TTL)

#### SPA /admin
- Section PKI : ajout du panneau "Rôles ACME" avec détails du rôle par défaut (`acme-servers`)

#### Proxy ACME étendu
- `PkiMiddleware` gère désormais aussi `/v1/_sys_pki_int/acme/*` (URL longue générée par OpenBao dans les réponses ACME directory)

#### Infrastructure de test
- `tests/pki/` : `docker-compose.test-pki.yml`, `docker-compose.fresh-start.yml`, `test_pki_integration.sh` (T0-T10 complets)

#### Corrections Codex (HAUT×3)
- `"already in use"` restreint à `"issuer name already in use"` exact
- WAF : `ruleEngine=Off` → `ruleRemoveById` ciblé sur regex stricte
- `pki_base_url_validated` : ValueError si non `http(s)://` (protection MITM ACME)

### Fichiers modifiés
- `src/mcp_vault/vault/pki_ca.py` — cluster path, idempotence, `PKI_BASE_URL`
- `src/mcp_vault/pki_middleware.py` — proxy long-path, CRL PEM
- `src/mcp_vault/admin/api.py` — routes `/pki/roles*`
- `src/mcp_vault/config.py` — `pki_base_url` setting validé
- `waf/coraza.conf` — exclusions PKI/ACME regex stricte
- `src/mcp_vault/static/js/pki.js` — panneau rôles ACME
- `tests/pki/` *(nouveau)* — infrastructure de test T0-T10

## [0.5.0] — 2026-06-10

### PKI interne — CA OpenBao + serveur ACME (issue #15)

Première release majeure post-v0.4.x : MCP Vault est désormais une **autorité de certification interne** pour l'écosystème Cloud Temple. Les WAF Caddy peuvent obtenir leurs certificats TLS via le protocole ACME standard, sans dépendance Internet ni CA publique.

#### Architecture PKI (PR #16)
- **`vault/pki_ca.py`** : CA racine + intermédiaire (OpenBao PKI engine), serveur ACME sur CA intermédiaire, rotation sans coupure (`rotate_intermediate`), révocation + CRL, inventaire paginé des certificats émis
- **`pki_middleware.py`** : middleware ASGI couche externe non-auth — proxy transparent `/acme/*` → OpenBao + distribution CA (`/pki/ca/root.pem`, `/pki/ca/chain.pem`, `/pki/ca/crl.pem`)
- **Mounts réservés** : `_sys_pki_root/` et `_sys_pki_int/` protégés contre `vault_delete` (double guard `spaces.py` + `server.py`, audit log)
- **Sync S3 forcée** après `setup_pki_ca`, `revoke_cert`, `rotate_intermediate` (durabilité critique)
- **Stack ASGI** : 6 couches — `PkiMiddleware → AdminMiddleware → HealthCheckMiddleware → AuthMiddleware → LoggingMiddleware → FastMCP`

#### Sécurité PKI (corrections Codex)
- Anti-traversal sur les paths ACME (`/../..` bloqué), validation `query_string`, `follow_redirects=False` (pas de SSRF)
- Validation regex `serial_number` (`^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2})+$`) dans `revoke_cert`
- `asyncio.Lock` sur `setup_pki_ca` (race condition multi-appel)
- Validation format FQDN/wildcard des `allowed_domains`
- Vérification retour `upload_to_s3()` (bool) sur toutes les mutations critiques

#### 7 nouveaux outils MCP (PR #16)
- `pki_ca_setup(lab_mode, allowed_domains, leaf_ttl)` — admin
- `pki_ca_public_key()` — CA racine PEM + SHA-256
- `pki_ca_list_roles()` — liste des rôles ACME
- `pki_ca_role_info(role_name)` — détails rôle
- `pki_list_certs(limit, offset)` — inventaire paginé
- `pki_revoke_cert(serial_number)` — admin
- `pki_ca_rotate_intermediate(keep_old_issuer, overlap_ttl)` — admin

Total outils MCP : **24 → 31**

#### Admin SPA /admin — section PKI (PR #17)
- Nouvelles routes REST : `GET /admin/api/pki/status`, `POST /admin/api/pki/setup`, `GET /admin/api/pki/certs`, `POST /admin/api/pki/certs/{serial}/revoke`, `POST /admin/api/pki/ca/rotate`
- Sidebar "PKI / TLS" (admins uniquement)
- Page PKI : statut CA (expiration racine/intermédiaire, empreinte SHA-256, ACME on/off), URLs de distribution copiables, inventaire certs avec révocation, modal setup
- Sécurité XSS : `JSON.stringify()` sur onclick serial et URL (pas de `esc()` insuffisant)
- `/pki/certs` requiert `is_admin` (inventaire = données sensibles)

#### CLI groupe `pki` (PR #18, `Closes #15`)
- **Click** : `pki setup`, `pki ca-key`, `pki roles`, `pki role-info <role>`, `pki certs`, `pki revoke <serial>`, `pki rotate`
- **Shell interactif** : `cmd_pki()` + `SHELL_COMMANDS["pki"]`
- **Display** : `show_pki_result()` affichage adaptatif (setup, ca-key, roles, inventaire, révocation, rotation)
- Options typées (`type=int` sur `--limit`/`--offset`), robustesse arg manquant

### Maintenance & Qualité (issues #12, #13, #14)

**#12 Tests comportementaux** (PR #19) : `TestAdminApiCodeStructure` — 3 tests à recherche textuelle réécrits en tests ASGI comportementaux :
- `test_whoami_returns_injected_client_name` : GET /whoami prouve l'injection ContextVar à l'exécution
- `test_contextvar_reset_after_request` : ContextVar resetté après requête (prouve le `finally`)
- `test_create_policy_created_by_uses_token_client_name` : mock store.create, vérifie `created_by=client_name`

**#14 Dashboard SPA** (PR #20) : compteur de tokens actifs excluait les révoqués mais pas les expirés. Fix : `.filter(t => !t.revoked && !t.expired)`.

**#13 Race S3** (PR #21) : limitation last-write-wins documentée dans `_save()` de `TokenStore` et `PolicyStore` (acceptable V1, single-instance). V2 : S3 conditional write ETag/CAS.

### Fichiers modifiés (résumé)
- `src/mcp_vault/vault/pki_ca.py` *(nouveau)*
- `src/mcp_vault/pki_middleware.py` *(nouveau)*
- `src/mcp_vault/server.py` — +7 outils MCP PKI + PkiMiddleware + guard vault_delete
- `src/mcp_vault/admin/api.py` — +5 routes REST PKI
- `src/mcp_vault/vault/spaces.py` — guard is_reserved_mount
- `src/mcp_vault/lifecycle.py` — check PKI au démarrage
- `src/mcp_vault/auth/token_store.py` — LIMITATION V1 documentée
- `src/mcp_vault/auth/policies.py` — LIMITATION V1 documentée
- `src/mcp_vault/static/admin.html` — page PKI + modal
- `src/mcp_vault/static/js/app.js` — sidebar PKI + routing
- `src/mcp_vault/static/js/pki.js` *(nouveau)*
- `src/mcp_vault/static/js/dashboard.js` — filtre tokens expirés
- `scripts/cli/commands.py` — groupe pki (7 commandes)
- `scripts/cli/shell.py` — cmd_pki + dispatcher
- `scripts/cli/display.py` — show_pki_result
- `tests/test_pki.py` *(nouveau)* — 22 tests
- `tests/test_pki_admin.py` *(nouveau)* — 12 tests
- `tests/cli/test_pki.py` *(nouveau)* — tests aide + rendus
- `tests/test_admin_context.py` — réécriture TestAdminApiCodeStructure

## [0.4.16] — 2026-06-08

### Tests & Security — Résiduels finaux (suite de l'audit complet)

#### Tests non-complaisant — test_admin_context.py (HAUT)
`test_admin_api_injects_contextvar` et `test_admin_api_bootstrap_token_contextvar` réécrits :
appellent maintenant `handle_admin_api()` via scope ASGI fake + patch `_get_token_info` + spy `_json_response`.
Capturent `get_current_client_name()` pendant la requête → non-complaisant.
Si l'injection ContextVar était supprimée d'`api.py`, les tests échoueraient.

#### Sécurité — `policies.py _save()` silencieux (même pattern que TokenStore)
- `_save()` retourne `bool` + `logger.error`
- `create()` : rollback `del` si S3 KO
- `delete()` retourne `True` / `False` / `"storage_error"` pour distinguer les 3 cas
- `admin/api.py` : HTTP 503 si `storage_error` sur create/delete policy
- `server.py policy_delete` : retourne `error_type=storage_unavailable`

#### Sécurité — `create_app()` fail-fast bootstrap key
`create_app()` valide maintenant `ADMIN_BOOTSTRAP_KEY` et lève `RuntimeError` si faible/par défaut.
Protège les déploiements ASGI directs (`uvicorn factory`) hors `server.main()`.

#### Correction clés de test
`test_admin_context.py` et `test_openbao_config.py` : clé de test `test-bootstrap-key-for-unit-tests` (2 classes de caractères → invalide) remplacée par `Test-Bootstrap-Key-2026-Pour-Tests!!`.

#### Mise à jour .clinerules
Règle ajoutée : revue Codex obligatoire avant tout merge (procédure explicite).

### Fichiers modifiés
- `src/mcp_vault/auth/policies.py` — _save bool + rollbacks + delete 3-valued
- `src/mcp_vault/server.py` — create_app fail-fast + policy_delete storage_error
- `src/mcp_vault/admin/api.py` — HTTP 503 create/delete policy + revoke 400/503
- `tests/test_admin_context.py` — réécriture ASGI non-complaisant + clé test forte
- `tests/test_openbao_config.py` — clé test forte

## [0.4.15] — 2026-06-07

### Security & Tests — Audit complet non-complaisance + résiduels auth

#### Sécurité auth — 3 correctifs

**hash_prefix non validé** (`token_store.py`) : `update()` et `revoke()` acceptaient un préfixe vide ou d'un seul caractère, matchant le premier token de la liste. Ajout de `_validate_hash_prefix()` (minimum 12 chars, hexadécimal, non ambigu) et `_resolve_hash()` (erreur si 0 ou plusieurs matchs). `revoke()` appelait maintenant `_maybe_refresh()`.

**`TokenStore._save()` silencieux** : les exceptions S3 étaient avalées → `create/update/revoke` annonçaient succès sans persistance. `_save()` retourne maintenant `bool`, les appelants font un rollback mémoire et retournent une erreur HTTP 503-like si S3 indisponible. Une révocation non persistée est une faille critique.

**Tokens expirés affichés "actifs"** : `get_by_hash()` rejetait déjà les tokens expirés, mais `list_all()` et `count()` ne calculaient pas l'expiration. Ajout du helper `_is_expired(token)`, utilisé par `get_by_hash`, `list_all` (nouveau champ `expired: bool`) et `count` (exclut les expirés). Affichage "EXPIRÉ" en SPA (badge jaune) et CLI.

#### Tests — Correction du défaut structurel CLI et réécriture des tests complaisant

**Défaut structurel CLI (HAUT)** : `tests/cli/__init__.py` — `check()` ne levait jamais d'exception → pytest considérait tous les tests CLI comme réussis. Fix : `tests/cli/conftest.py` avec fixture `@pytest.fixture(autouse=True)` qui reset les compteurs avant et assert `FAIL == 0` après chaque test.

**`tests/test_admin_path_policy.py`** : réécriture complète. Les 3 tests (recherches textuelles dans le source) remplacés par 4 tests comportementaux ASGI qui appellent réellement `handle_admin_api()` et vérifient que `check_path_policy` est appelé et bloque avec HTTP 403.

**`tests/test_openbao_manager.py`** : réécriture complète. Les 2 tests (recherches textuelles) remplacés par des tests comportementaux : `start_openbao()` ne lance pas `Popen` si OpenBao est reachable, et redirige bien stdout/stderr vers des fichiers (pas `subprocess.PIPE`).

**`tests/test_crypto.py` — `test_aad_context_binding`** : réécrit pour passer par les fonctions publiques `encrypt/decrypt_with_bootstrap_key()`. L'ancienne version testait `AESGCM` directement et aurait passé même si `_AAD` était retiré de la production.

### Fichiers modifiés
- `src/mcp_vault/auth/token_store.py` — hash_prefix validation, _save fail-closed, _is_expired
- `scripts/cli/display.py` — affichage EXPIRÉ
- `src/mcp_vault/static/js/tokens.js` — badge "expiré" (jaune)
- `tests/cli/conftest.py` — NOUVEAU : fixture autouse CLI
- `tests/test_admin_path_policy.py` — réécriture comportementale
- `tests/test_openbao_manager.py` — réécriture comportementale
- `tests/test_crypto.py` — test_aad_context_binding non-complaisant

## [0.4.14] — 2026-06-07

### Security — Correctifs auth CRITIQUE + ÉLEVÉ (audit codex)

#### CRITIQUE — `ssh_sign_key` ne vérifiait pas la permission `write`
Un token `read` ayant accès au vault pouvait signer des clés SSH (opération d'émission de credential).
**Correctif** : `check_write_permission()` ajouté dans `ssh_sign_key` ([server.py](src/mcp_vault/server.py)), cohérent avec `ssh_ca_setup`.

#### ÉLEVÉ — Policy enforcement fail-open si `PolicyStore` absent
`check_policy()` et `check_path_policy()` retournaient `None` si le PolicyStore était absent, même si le token portait un `policy_id` — bypass complet des restrictions.
**Correctif** : fail-close avec audit explicite si `policy_id` présent sans PolicyStore disponible ([context.py](src/mcp_vault/auth/context.py)).

#### ÉLEVÉ — `GET /admin/api/vaults/{vault_id}` sans `check_policy()`
La route de détail vault listait tous les secrets/rôles SSH sans vérification de policy — bypass enumération pour tokens avec `path_rules`.
**Correctif** : `check_policy("vault_info")` ajouté avant `_api_vault_detail()`.

#### ÉLEVÉ — Routes REST SSH read (`ca-key`, `roles`, `role-info`) sans `check_policy()`
Incohérence avec les outils MCP équivalents qui appellent bien `check_policy()`.
**Correctif** : `check_policy("ssh_ca_public_key/list_roles/role_info")` ajoutés sur les 3 routes GET SSH.

#### Complément — `GET /admin/api/vaults` sans `check_policy("vault_list")`
Manquait pour compléter la parité REST/MCP sur la liste des vaults.
**Correctif** : `check_policy("vault_list")` ajouté.

### Revue codex
APPROUVÉ — tous les noms d'outils vérifiés cohérents avec `_TOOL_LABELS` et outils MCP.

### Fichiers modifiés
- `src/mcp_vault/server.py` — `ssh_sign_key` : check_write_permission
- `src/mcp_vault/auth/context.py` — check_policy + check_path_policy : fail-close PolicyStore absent
- `src/mcp_vault/admin/api.py` — check_policy sur vault_list, vault_info, SSH read routes

## [0.4.13] — 2026-06-07

### Feature — JIT Wrap Broker pour mcp-mission V1 (issue #7)

Implémentation du contrat `VaultClient` attendu par `mcp-mission/CredentialBrokerService` (#110, #72, #74).

#### 3 nouveaux outils MCP (accès admin requis)

| Outil | Contrat |
|---|---|
| `secret_wrap(vault_id, secret_path, mission_id, operation_id, ttl_seconds)` | Crée un wrap token single-use OpenBao (cubbyhole) scopé à la mission. Retourne `{wrap_token, secret_id, accessor, vault_url, expires_at, intended_use}`. |
| `secret_revoke_wrap(lease_id)` | Révoque un wrap token — **idempotent** : `not_found` / `already_revoked` → status OK. Erreur réseau → erreur réelle. |
| `secret_wrap_lookup(operation_id)` | Retrouve et révoque les wraps orphelins par `operation_id`. États : `not_found` \| `found_unattached` \| `already_revoked` \| `revoked` \| `ambiguous`. |

#### Architecture write-ahead (compensation #74)

Le `WrapRegistry` (S3 `_system/wrap_registry.json`) implémente un write-ahead strict :
1. Enregistrement `"pending"` **avant** l'appel OpenBao
2. Passage `"active"` avec l'accessor **après** succès
3. Si crash entre 1 et 2 → `lookup` retourne `"found_unattached"` ; le TTL Vault gérera l'expiration

#### Invariants de sécurité

- `wrap_token` jamais loggué, stocké dans le registry, ni inclus dans les erreurs
- Registry ne stocke que l'`accessor` (non utilisable seul pour unwrap)
- `revoke_wrap` refuse tout accessor absent du registry (pas de révocation hors scope)
- `wrap_secret` fail-close si registry S3 indisponible (compensation impossible)
- `mark_active` en échec → révocation immédiate de l'accessor + erreur
- `check_access` + `check_path_policy` appliqués avant wrap

#### Limitations V1 documentées

- WrapRegistry : last-write-wins (pas de CAS S3) → single broker en V1
- `found_unattached` : pas de révocation possible sans accessor (TTL 300s max)

#### Tests

- `tests/test_wrap.py` — **15 tests** (15/15) : write-ahead, idempotence revoke, états lookup, anti-fuite, rollback registry, fail-close registry=None, chemins réservés, validation server

#### Revues codex

5 passes itératives → APPROUVÉ. 10 findings traités (2 CRITICAL, 5 HIGH, 3 MEDIUM).

### Fichiers modifiés
- `src/mcp_vault/vault/wrapping.py` — NOUVEAU (WrapRegistry + wrap/revoke/lookup)
- `src/mcp_vault/server.py` — 3 outils MCP (secret_wrap, secret_revoke_wrap, secret_wrap_lookup)
- `src/mcp_vault/lifecycle.py` — init_wrap_registry au startup
- `tests/test_wrap.py` — NOUVEAU (15 tests)

## [0.4.12] — 2026-06-07

### Security — Résultats de l'audit de synchronisation CLI/Shell/Admin

#### BLOQUANT 1 — API REST admin contournait les policies tool-level (F1)
Les outils MCP appelaient `check_policy()` avant chaque action, mais les routes REST `/admin/api` ne le faisaient pas. Un token `write` avec une policy interdisant `secret_write` ou `vault_create` pouvait contourner la restriction via l'interface `/admin`.

**Correctif** : `check_policy("vault_create")`, `check_policy("vault_update")`, `check_policy("vault_delete")`, `check_policy("secret_list")`, `check_policy("secret_read")`, `check_policy("secret_write")`, `check_policy("secret_delete")`, `check_policy("ssh_ca_setup")`, `check_policy("ssh_sign_key")` ajoutés dans `admin/api.py` sur toutes les routes CRUD correspondantes. Les tokens admin contournent toujours les policies (comportement inchangé).

#### BLOQUANT 2 — `path_rules.permissions` stockées mais jamais appliquées (F2)
Le modèle de policy acceptait `read/write/admin` par chemin de secret, mais `check_path_policy()` ne vérifiait que les `allowed_paths`. Un token avec `permissions: ["read"]` pouvait écrire/supprimer dans les chemins autorisés.

**Correctif** :
- `is_path_allowed()` (`policies.py`) : nouveau paramètre `required_permission` vérifié contre `rule["permissions"]` ("write" couvre delete, "admin" couvre tout).
- `check_path_policy()` (`context.py`) : propagation du `required_permission` ("read", "write").
- Tous les appelants MCP et REST admin mis à jour avec la permission appropriée.

#### MOYEN 5 — Policy inexistante acceptée par l'API REST (F5)
L'API admin REST pouvait créer/modifier un token avec un `policy_id` invalide (alors que l'outil MCP `token_update` validait l'existence). Résultat : token bloqué fail-close.

**Correctif** : validation de l'existence de la policy dans `_api_create_token()` et `_api_update_token()`.

### Fichiers modifiés
- `src/mcp_vault/admin/api.py` — F1 (check_policy) + F5 (validation policy)
- `src/mcp_vault/auth/policies.py` — F2 (is_path_allowed avec required_permission)
- `src/mcp_vault/auth/context.py` — F2 (check_path_policy avec required_permission)
- `src/mcp_vault/server.py` — F2 (appelants MCP avec permission explicite)

## [0.4.11] — 2026-06-07

### Fix — Sentinel `_remove` stocké littéralement dans la policy des tokens (/admin)

**Bug** : dans l'interface `/admin`, modifier ou retirer la policy d'un token stockait la chaîne `_remove` comme valeur de `policy_id` au lieu de `""`. La policy enforcement cherchait alors une policy nommée `_remove` (inexistante) et bloquait tous les accès du token (fail-close).

**Cause** : `doUpdateToken()` dans `tokens.js` envoyait le sentinel MCP `_remove` à l'API REST `/admin/api/tokens/{hash}`, qui ne le gère pas (contrairement à l'outil MCP `token_update`).

**Deuxième bug** : ouvrir le modal d'édition pour un token sans policy affichait la policy sélectionnée lors du précédent appel (le `select` n'était réinitialisé à `""` que si `policyId` était truthy).

**Correctifs** :
- `tokens.js` — `doUpdateToken()` : envoie `policy_id: ""` au lieu de `"_remove"` pour retirer la policy.
- `tokens.js` — `openEditToken()` : le `select` est toujours réinitialisé à la valeur du token courant (`""` si aucune policy), même si `policyId` est vide.
- `token_store.py` — `update()` : le sentinel `_remove` est converti en `""` (robustesse vis-à-vis de l'outil MCP).
- `token_store.py` — `load()` : migration auto des valeurs `"_remove"` stockées → `""` au prochain rechargement du Token Store.
- `admin.html` : tooltip corrigé (suppression de la mention de `_remove` qui ne s'applique qu'à la CLI MCP).

### Fichiers modifiés
- `src/mcp_vault/static/js/tokens.js`
- `src/mcp_vault/auth/token_store.py`
- `src/mcp_vault/static/admin.html`

## [0.4.10] — 2026-06-07

### Fix — `/mcp` renvoie HTTP 421 « Invalid Host header » sur le FQDN public (issue #3)

**Bug bloquant** : aucun client MCP (Claude Code, Codex, …) ne pouvait se connecter via `https://vault.mcp.cloud-temple.app/mcp` — l'endpoint répondait `HTTP 421 Invalid Host header` **avant** la couche d'authentification.

**Cause racine** : `FastMCP()` était instancié sans paramètre `host`. Le SDK MCP (≥1.x) auto-active alors la protection anti-DNS-rebinding avec pour seuls hosts autorisés le loopback (`127.0.0.1`, `localhost`, `[::1]`). Tout `Host` correspondant au FQDN public était donc rejeté par le `TransportSecurityMiddleware`.

**Correctif** :
- `_build_transport_security()` (`server.py`) construit explicitement les `TransportSecuritySettings` : protection **maintenue active**, loopback **toujours** autorisé (health checks, tests e2e via WAF localhost) + FQDN publics issus de la config.
- Nouveaux réglages `MCP_ALLOWED_HOSTS` / `MCP_ALLOWED_ORIGINS` (`config.py`), défaut = `vault.mcp.cloud-temple.app,my.vault.mcp.cloud-temple.app`, surchargeables par variable d'environnement (liste CSV).
- Normalisation des FQDN en minuscules (DNS insensible à la casse) + déduplication ; dérivation automatique de l'origin `https://<fqdn>` et de la variante avec port (`<fqdn>:*`).

### Security — Durcissements complémentaires
- **Fail-fast `ADMIN_BOOTSTRAP_KEY`** (`server.py`) : le service refuse désormais de démarrer si la bootstrap key est vide / par défaut / faible (auparavant simple warning). Cette clé chiffre les clés unseal et sert de credential admin de secours.
- **`Settings` strict** (`config.py`) : champ `waf_port` déclaré explicitement (variable partagée avec docker-compose) ; `extra="forbid"` conservé → toute variable inconnue (typo de config) lève une erreur explicite au lieu d'être silencieusement ignorée.

### Tests
- `tests/test_transport_security.py` — 11 tests (FQDN acceptés, loopback, casse, dédup, IPv6 `[::1]`, host inconnu rejeté, protection active, override env).

### Fichiers modifiés
- `src/mcp_vault/server.py` — `_build_transport_security()` + `FastMCP(transport_security=…)` + fail-fast bootstrap key
- `src/mcp_vault/config.py` — `MCP_ALLOWED_HOSTS` / `MCP_ALLOWED_ORIGINS` / `waf_port`, normalisation CSV
- `src/mcp_vault/lifecycle.py` — validation bootstrap key en défense en profondeur
- `.env.example` — documentation des nouvelles variables
- `tests/test_transport_security.py` — nouveau

### Validation
- Revue de code complète (codex, 2 passes) → APPROUVÉ.
- 11/11 transport_security + 18/18 crypto.

## [0.4.9] — 2026-04-25

### Security — Enforcement `path_rules` sur l'API REST admin (PR #2)

**Faille corrigée** : les `allowed_paths` des policies étaient appliquées sur les outils MCP (`server.py`) mais **pas** sur les routes REST admin `/admin/api/vaults/{vault}/secrets/*`. Un token non-admin avec `allowed_paths: ["app/creds"]` pouvait lire `other/secret` via l'API REST.

**Correctifs (`admin/api.py`)** :
- `check_path_policy()` ajouté sur les 4 routes REST secrets : GET list, GET read, POST write, DELETE
- Ajout de `try/except json.JSONDecodeError` sur le POST (meilleure gestion du body invalide)
- Aligne le comportement REST admin avec les outils MCP (qui avaient déjà ces checks)

**Hardening OpenBao (`openbao/config.py`)** :
- L'adresse listener HCL est désormais dérivée de `OPENBAO_ADDR` au lieu d'être hardcodée `127.0.0.1:8200`
- Permet les environnements de test avec port custom

**Robustesse startup (`openbao/manager.py`)** :
- `start_openbao()` est idempotent : si OpenBao est déjà accessible, réutilise l'instance
- stdout/stderr redirigés vers des fichiers log (`/openbao/logs/`)
- Détection de crash immédiat avec affichage des 40 dernières lignes stderr

### Tests
- `tests/test_admin_path_policy.py` — 3 tests (vérification de l'import et de l'application de `check_path_policy`)
- `tests/test_openbao_config.py` — 2 tests fonctionnels (`_compute_openbao_listen_addr` port défaut + custom)
- `tests/test_openbao_manager.py` — 2 tests (redirection logs + réutilisation instance)

### Fichiers modifiés (6)
- `src/mcp_vault/admin/api.py` — enforcement `check_path_policy()` sur 4 routes secrets
- `src/mcp_vault/openbao/config.py` — listener dynamique via `_compute_openbao_listen_addr()`
- `src/mcp_vault/openbao/manager.py` — idempotency, logs fichiers, détection crash
- `tests/test_admin_path_policy.py` — nouveau
- `tests/test_openbao_config.py` — nouveau
- `tests/test_openbao_manager.py` — nouveau

### Audit Review — 3 findings non-bloquants documentés
- **F7** : Si `OPENBAO_ADDR=http://0.0.0.0:8200`, listener ouvert (mitigé : port non exposé dans Docker)
- **F9** : Réutilisation d'instance sans vérification d'identité (mitigé : réseau Docker isolé)
- **F10** : `_process=None` après réutilisation → `stop_openbao()` no-op (impact limité)

### Contributeur
- PR #2 par [@camilleein](https://github.com/camilleein)

---

## [0.4.8] — 2026-04-25

### Bugfix — Contexte d'authentification dans l'Admin API (PR #1)

Le `created_by` des vaults et policies créés via `/admin/api/*` était toujours `anonymous` au lieu du vrai `client_name` du token Bearer.

**Cause racine :**
- `AdminMiddleware` court-circuite la stack ASGI avant `AuthMiddleware`, donc la `ContextVar` `current_token_info` n'était jamais peuplée pour les requêtes admin API.

**Correctifs :**
- `handle_admin_api()` injecte désormais `current_token_info` (même pattern que `AuthMiddleware`) avec `try/finally/reset`
- Logique de routage extraite dans `_handle_admin_routes()` pour un scoping propre
- `_api_create_policy()` utilise `get_current_client_name()` au lieu de `'admin'` hardcodé

### Tests
- Nouveau `tests/test_admin_context.py` (15 tests, 0 dépendance S3/OpenBao)
  - `TestAdminApiContextVar` : injection, bootstrap, anonymous, isolation
  - `TestAuthContextPermissions` : access, write, admin, client_name
  - `TestAdminApiCodeStructure` : vérification AST du fix

### Fichiers modifiés (3)
- `src/mcp_vault/admin/api.py` — injection ContextVar dans handle_admin_api()
- `tests/test_admin_context.py` — nouvelle suite de 15 tests
- `.gitignore` — ajout d'entrée

### Contributeur
- PR #1 par [@camilleein](https://github.com/camilleein)

---

## [0.4.7] — 2026-03-31

### Bugfix — Affichage du token créé dans /admin + dates dans toutes les interfaces

#### 🔴 Token non affiché après création dans /admin SPA

Le token créé via la console `/admin` n'était **jamais affiché** à l'utilisateur — impossible de le copier.

**Triple cause racine :**
1. `tokens.js` vérifiait `data.token` alors que l'API retourne `data.raw_token` → condition toujours fausse
2. `loadTokens()` était appelé **après** l'affichage du token, recréant le DOM et écrasant le résultat
3. Aucun scroll vers le token affiché

**Correctifs :**
- `data.token` → `data.raw_token` dans la condition d'affichage
- `await loadTokens()` appelé **avant** l'affichage du token (le div `newTokenResult` est recréé par `loadTokens`, puis rempli)
- Ajout de `scrollIntoView()` pour garantir la visibilité du token
- Affichage enrichi : hash tronqué, date d'expiration, policy associée

#### 🟡 Dates de création et de révocation manquantes

Les dates de création et de révocation des tokens n'étaient pas visibles dans aucune des 3 interfaces (SPA, CLI Click, Shell interactif).

**Correctifs backend (`token_store.py`) :**
- `list_all()` retourne désormais `created_at` et `revoked_at`
- `revoke()` stocke `revoked_at` avec timestamp ISO UTC

**Correctifs SPA `/admin` (`tokens.js`) :**
- Nouvelle colonne **Créé le** (date + heure formatées en `fr-FR`)
- Colonne **Statut** enrichie : affiche la date de révocation sous le badge "révoqué"

**Correctifs CLI Click + Shell (`display.py`) :**
- Nouvelle colonne **Créé le** (date ISO tronquée `YYYY-MM-DD`)
- Colonne **Statut** unifiée : `actif → YYYY-MM-DD` (expiration) ou `RÉVOQUÉ YYYY-MM-DD`

### Fichiers modifiés (4)
- `src/mcp_vault/auth/token_store.py` — `list_all()` + `revoke()` enrichis
- `src/mcp_vault/static/js/tokens.js` — fix affichage token + colonnes dates
- `scripts/cli/display.py` — colonnes Créé le / Statut dans `show_token_result()`
- `VERSION` — 0.4.6 → 0.4.7

### Tests
- **18/18 tests crypto** — zéro régression
- **197/197 tests CLI** — zéro régression

---

## [0.4.6] — 2026-03-26

### Bugfix — Suppression de `disable_mlock` (crash OpenBao au démarrage)

OpenBao ≥2.0 a supprimé le support du paramètre `disable_mlock` ([RFC mlock-removal](https://openbao.org/docs/rfcs/mlock-removal/)). Sa présence dans la config HCL générée provoquait un crash systématique au démarrage : `error loading configuration from /openbao/config/server.hcl: OpenBao has dropped support for mlock`.

#### Correctif

- **`src/mcp_vault/openbao/config.py`** : suppression totale de la ligne `disable_mlock = false` et du commentaire associé dans `HCL_TEMPLATE`. La protection mémoire est désormais gérée au niveau OS (swap désactivé dans le conteneur Docker).

#### Tests

- **`tests/test_integration.py`** : assertion mise à jour — vérifie que `disable_mlock` n'apparaît **plus** dans la config HCL générée (`assert "disable_mlock" not in content`).

#### Documentation mise à jour (5 fichiers)

- `DESIGN/mcp-vault/TECHNICAL.md` — exemple HCL §3.13 nettoyé, description config.py mise à jour
- `DESIGN/mcp-vault/ARCHITECTURE.md` — exemple HCL §4.5 nettoyé
- `DESIGN/mcp-vault/SECURITY_AUDIT.md` — V3-05 mis à jour (remédiation finale v0.4.6, lien RFC)

#### Fichiers modifiés (6)
- `src/mcp_vault/openbao/config.py` — suppression `disable_mlock`
- `tests/test_integration.py` — assertion inversée
- `DESIGN/mcp-vault/TECHNICAL.md` — doc HCL + description
- `DESIGN/mcp-vault/ARCHITECTURE.md` — doc HCL
- `DESIGN/mcp-vault/SECURITY_AUDIT.md` — V3-05 mise à jour
- `VERSION` — 0.4.5 → 0.4.6

---

## [0.4.5] — 2026-03-26

### Security — Hardening P2 : 8 correctifs de durcissement

Suite à l'audit de sécurité V2.1 (60 findings), après la remédiation P0 (4 élevés) et P1 (9 moyens) de la v0.4.0, cette release applique les **8 correctifs P2 (hardening)** restants.

#### 🟡 Corrections moyennes et durcissement (8)

- **V2-12 — Docker images pinnées par digest** (`Dockerfile`, `waf/Dockerfile`) : toutes les images base (python:3.12-slim, alpine:3.20, caddy:2-builder, caddy:2-alpine) sont désormais pinnées par SHA256 digest au lieu de tags mutables, protégeant contre les attaques supply chain par remplacement d'image.

- **V2-16 — Plugins Caddy pinnés en version** (`waf/Dockerfile`) : `coraza-caddy/v2@v2.2.0` et `caddy-ratelimit@v0.1.0` sont désormais pinnés en version exacte dans le build xcaddy, empêchant l'intégration silencieuse de versions non testées.

- **V3-08 — Lock file Python** (`requirements.lock`, nouveau) : fichier de dépendances avec versions exactes (`==`) généré depuis l'image Docker de production. Garantit des builds reproductibles et protège contre le typosquatting et le version hijacking.

- **V3-04 — AES-GCM AAD** (`openbao/crypto.py`) : ajout d'Associated Authenticated Data (`mcp-vault:unseal-keys:v1`) dans le chiffrement AES-256-GCM des clés unseal. Empêche la réutilisation d'un blob chiffré dans un contexte différent. Migration backward-compatible : le déchiffrement tente d'abord avec AAD, puis fallback sans AAD pour les données pré-v0.4.5.

- **V2-13 — HSTS** (`waf/Caddyfile`) : ajout du header `Strict-Transport-Security: max-age=31536000; includeSubDomains` pour forcer HTTPS sur tous les sous-domaines en production.

- **P2-6 — CORS preflight restrictif** (`waf/Caddyfile`) : les requêtes OPTIONS sont désormais gérées explicitement par le WAF avec des méthodes et headers restreints, sans `Access-Control-Allow-Origin` (bloque toute origine cross-origin).

- **P2-7 — Docker hardening** (`docker-compose.yml`) : ajout de `security_opt: [no-new-privileges:true]` sur tous les services, `read_only: true` pour le WAF avec tmpfs pour les chemins writable, et `tmpfs: /tmp` pour mcp-vault.

- **P2-8 — Tests hors image production** (`Dockerfile`, `docker-compose.yml`) : l'image production ne contient plus `tests/` ni `scripts/`. Un stage Docker dédié `test` (stage 3) est utilisé pour les tests d'intégration, réduisant la surface d'attaque de l'image de production.

#### 🧪 Tests

- **18/18 tests crypto** passent (16 existants + 2 nouveaux AAD : `test_aad_legacy_fallback`, `test_aad_context_binding`)
- Tests e2e : validation post-build requise (docker compose)

### Documentation

- **SECURITY_AUDIT.md réécrit** : consolidation des 3 audits (v0.2.0, v0.3.3, V2.1 externe) en un document unique avec V2.1 comme source de vérité. 60 findings cross-référencés : 28 corrigés, 13 résiduels documentés avec justification, 18 informationnels. Statuts vérifiés dans le code source.
- **README.md mis à jour** : version 0.4.5, tests 312/15 catégories, table docs enrichie (SECURITY_AUDIT.md), roadmap sécurité corrigée, structure projet avec requirements.lock.
- **TECHNICAL.md mis à jour** : header v0.4.5, statut Production-ready, suppression fallback `?token=`, correction `disable_mlock=false`, référence audit V2.1, roadmap enrichie (Phase 8e, 9, 10).
- **requirements.lock nettoyé** : suppression des dépendances de test (pytest, pytest-asyncio) — production-only conformément au stage Docker séparé (P2-8).

### Risques résiduels documentés (non corrigés)

- **CSP unsafe-inline** (§5.2) : le SPA admin utilise des scripts inline — refonte avec nonces/hashes CSP planifiée mais reportée (effort significatif).
- **Race conditions S3** (§5.4) : last-writer-wins en single-instance — risque faible, asyncio.Lock reporté.
- **Clés str en mémoire** (§5.5) : limitation fondamentale Python — les strings sont immuables et non-effaçables.

### Fichiers modifiés (8)
- `Dockerfile` — V2-12 (digests), P2-8 (stage test séparé), version label 0.4.5
- `waf/Dockerfile` — V2-12 (digests), V2-16 (plugins pinnés)
- `waf/Caddyfile` — V2-13 (HSTS), P2-6 (CORS preflight)
- `docker-compose.yml` — P2-7 (hardening), P2-8 (target stages)
- `src/mcp_vault/openbao/crypto.py` — V3-04 (AAD)
- `tests/test_crypto.py` — 2 tests AAD ajoutés (18 total)
- `requirements.lock` — **nouveau** (V3-08)
- `VERSION` — 0.4.0 → 0.4.5

---

## [0.4.0] — 2026-03-24

### Security — Audit complet v0.3.3 et correctifs majeurs

Suite à un **audit de sécurité complet** (19 fichiers analysés, 18 vulnérabilités identifiées), 7 correctifs de sécurité sont appliqués dans cette release majeure.

Rapport complet : [SECURITY_AUDIT.md](DESIGN/mcp-vault/SECURITY_AUDIT.md)

#### 🔴 Corrections critiques (3)

- **Admin API bypass des contrôles d'accès vault** (`admin/api.py`) : les routes `/admin/api/vaults/{id}`, `/admin/api/vaults/{id}/secrets/*` et `/admin/api/vaults/{id}/ssh/*` ne vérifiaient pas `check_access()`. Un token non-admin pouvait accéder à **tous** les vaults via l'API admin, contournant l'isolation owner-based et `allowed_resources`. Corrigé avec `_check_vault_access()` appliqué sur les 3 groupes de routes (vault detail, SSH CA, secrets).

- **Timing attack sur la bootstrap key** (`auth/middleware.py`, `admin/api.py`) : la comparaison `==` de la bootstrap key n'était pas constant-time. Remplacée par `hmac.compare_digest()` dans les 3 occurrences.

- **Path traversal via tarfile** (`s3_sync.py`) : `tar.extractall()` sans filtre permettait l'écriture de fichiers arbitraires via une archive S3 malveillante (CVE-2007-4559). Corrigé avec `filter='data'` (Python 3.12+).

#### 🟠 Corrections élevées (4)

- **CORS wildcard supprimé** (`admin/api.py`) : le header `Access-Control-Allow-Origin: *` a été retiré de toutes les réponses API admin. Les requêtes cross-origin depuis des domaines tiers sont désormais bloquées.

- **Fail-close sur policies supprimées** (`auth/policies.py`) : `is_tool_allowed()` retournait `True` si la policy référencée n'existait plus (fail-open). Désormais retourne `False` (fail-close) — un token dont la policy a été supprimée est bloqué.

- **Limite de taille du body HTTP** (`admin/api.py`) : `_read_body()` est désormais plafonné à 10 MB pour prévenir les attaques OOM (Out Of Memory).

- **Validation vault_id** (`vault/spaces.py`) : ajout de la validation du format vault_id (alphanumérique + tirets, 1-64 chars) avant passage à OpenBao, bloquant les injections de mount path.

- **Rate limiting WAF** (`waf/Caddyfile`) : ajout du plugin `caddy-rate-limit` avec limitation à 100 req/s par IP sur tous les endpoints. Protection contre le brute-force et le DoS applicatif.

#### 🟡 Corrections moyennes

- **Docker resource limits** (`docker-compose.yml`) : ajout de `mem_limit: 2g` et `cpus: 2.0` pour les services mcp-vault et waf.

### Fichiers modifiés (8)
- `src/mcp_vault/admin/api.py` — C1 (vault access), C2 (timing), E1 (CORS), E4 (body limit)
- `src/mcp_vault/auth/middleware.py` — C2 (timing attack)
- `src/mcp_vault/auth/policies.py` — E3 (fail-close)
- `src/mcp_vault/s3_sync.py` — C3 (tarfile filter)
- `src/mcp_vault/vault/spaces.py` — M1 (vault_id validation)
- `waf/Caddyfile` — E2 (rate limiting)
- `docker-compose.yml` — M3 (resource limits)
- `DESIGN/mcp-vault/SECURITY_AUDIT.md` — rapport complet v0.3.3

---

## [0.3.3] — 2026-03-23

### Documentation WAF complète (ARCHITECTURE.md §11.6)

Ajout de 9 sous-sections documentant en détail l'architecture du WAF Coraza :
- Architecture (Caddy v2.11.2 + coraza-caddy v2.2.0 + CRS v4.7.0), build multi-stage
- 19 règles CRS chargées (tableau complet REQUEST + RESPONSE)
- Mode anomaly scoring (fonctionnement, seuil de blocage)
- 4 exclusions ciblées documentées (920540 Unicode, 932120 PowerShell) avec motifs et risques
- Headers de sécurité (CSP, X-Frame-Options, nosniff...) avec valeurs et justifications
- Configuration réseau et timeouts
- Procédure de diagnostic pas-à-pas pour identifier et résoudre les faux positifs WAF

### Tests e2e WAF dédiés (TEST 15 — `--test waf_security`)

Nouveau groupe de tests (17 assertions) validant le WAF Coraza en mode blocking :
- **LFI** : 3 attaques path traversal → 403
- **SQLi** : 3 injections SQL → 403
- **XSS** : 2 cross-site scripting → 403
- **RCE** : 3 remote code execution → 403
- **Scanner** : 2 détections (Nikto, sqlmap) → 403
- **Non-régression** : 4 requêtes légitimes (health, MCP, Unicode, test-path) → 200
- Auto-skip si MCP_URL pointe vers `:8030` (sans WAF)

### Métriques

- **312/312 tests e2e** via WAF (15 catégories, ~15s)
- **197 tests CLI** inchangés
- **16 tests crypto** inchangés

### Fichiers modifiés (3)
- `DESIGN/mcp-vault/ARCHITECTURE.md` — section §11.6 WAF (9 sous-sections)
- `tests/test_e2e.py` — TEST 15 waf_security (17 assertions)
- `VERSION` — 0.3.2 → 0.3.3

---

## [0.3.2] — 2026-03-23

### WAF — Mode Blocking complet

Le WAF Coraza passe de **DetectionOnly** à **Blocking complet** sur tous les endpoints, y compris `/mcp` (JSON-RPC) et `/admin/api` (REST). Toutes les requêtes sont désormais inspectées et bloquées si elles dépassent le seuil d'anomalie CRS.

#### Fine-tuning des règles OWASP CRS

Méthodologie : suppression du mode DetectionOnly → exécution des 295 tests e2e → analyse des logs Coraza → exclusions chirurgicales.

- **230/262 tests** passaient sans aucune exclusion (88% de compatibilité native)
- **2 faux positifs identifiés** via les logs Coraza (`docker-compose logs waf`) :

| Règle CRS | Description | Cause du faux positif |
|-----------|-------------|----------------------|
| **920540** | Unicode character bypass | Les descriptions françaises en JSON contiennent `\u00e9`, `\u00e8`, `\u2014` — encodage Unicode standard |
| **932120** | Windows PowerShell RCE | Le policy_id `test-path-restrict` contient `test-path` → matche le cmdlet PowerShell `Test-Path` |

- **Exclusions ciblées** (SecRule id:10001-10004) : `ruleRemoveById` pour les 2 règles, **uniquement** sur `/mcp` et `/admin/api`. Les chemins publics (`/health`, `/admin/static`) gardent la protection complète.

#### Vérification post-tuning

- ✅ **295/295 tests e2e** passent en mode blocking complet
- ✅ **LFI** (`../../etc/passwd`) → 403
- ✅ **SQLi** (`OR 1=1`) → 403
- ✅ **XSS** (`<script>alert(1)</script>`) → 403
- ✅ **RCE** (`test-path` sur `/health`) → 403 (exclusion active uniquement sur les APIs)
- ✅ Trafic MCP légitime → 200/202

### Alignement `/health` sur le standard MCP Cloud Temple

Le endpoint `/health` retourne désormais le même format que Live Memory et MCP Tools :

```json
{"status": "healthy", "service": "mcp-vault", "version": "0.3.2", "transport": "streamable-http"}
```

Alignement avec :
- Live Memory : `{"status": "healthy", "service": "live-memory", "version": "0.9.0", "transport": "streamable-http"}`
- MCP Tools : `{"status": "healthy", "service": "mcp-tools", "version": "0.1.8", "transport": "streamable-http"}`

### Fichiers modifiés (3)
- `waf/coraza.conf` — mode Blocking complet + 4 exclusions documentées (suppression DetectionOnly)
- `src/mcp_vault/auth/middleware.py` — nouvelle méthode `_health_response()` dans `HealthCheckMiddleware`
- `VERSION` — 0.3.1 → 0.3.2

---

## [0.3.1] — 2026-03-23

### Security — Audit & Correctifs critiques

Suite à un **audit de sécurité complet** ([SECURITY_AUDIT.md](DESIGN/mcp-vault/SECURITY_AUDIT.md)), 5 vulnérabilités ont été identifiées et corrigées dans cette release.

#### 🔴 Corrections critiques

- **Arbitrary File Read (LFI)** dans `admin/middleware.py` : la route `/admin/static/` permettait de lire n'importe quel fichier du système via un chemin absolu (ex: `/admin/static//etc/passwd`). Corrigé avec `Path.resolve()` + vérification de parenté avec `static_dir` + rejet des chemins absolus et `..`.

- **WAF Coraza réel** : le Dockerfile WAF utilisait `caddy:2-alpine` brut sans Coraza. Reconstruit avec un **build multi-stage** :
  - Stage 1 : compilation Caddy + `coraza-caddy v2.2.0` via `xcaddy`
  - Stage 2 : téléchargement **OWASP CoreRuleSet v4.7.0** (24 fichiers de règles)
  - Stage 3 : image Alpine minimale avec config Coraza
  - Nouveau fichier `waf/coraza.conf` avec stratégie WAF documentée
  - Mode **Blocking** pour les chemins non-authentifiés
  - Mode **DetectionOnly** pour les APIs authentifiées (`/mcp`, `/admin/api`)
  - Headers de sécurité : CSP, X-Frame-Options DENY, X-XSS-Protection, nosniff

#### 🟠 Corrections moyennes

- **Auth par query string supprimée** : le fallback `?token=` dans `auth/middleware.py` a été supprimé. Seul le header `Authorization: Bearer <token>` est désormais accepté, éliminant le risque de fuite de tokens dans les logs HTTP, proxies et historiques navigateur.

- **Validation de l'entropie de la bootstrap key** : nouvelle fonction `validate_bootstrap_key()` dans `crypto.py` avec vérification au démarrage dans `lifecycle.py`. Exigences : ≥32 caractères, 3+ classes de caractères (majuscules, minuscules, chiffres, symboles), détection de la valeur par défaut et des patterns faibles (répétitions).

- **Zeroing mémoire des clés dérivées** : `_derive_key()` retourne un `bytearray` (mutable) au lieu de `bytes`. Nouvelle fonction `_zero_fill()` efface les clés dans les blocs `finally` après chaque opération crypto, limitant la fenêtre d'exposition en RAM.

### Tests

- **295/295 tests e2e** passent (dans le conteneur et via le WAF)
- **16/16 tests crypto** (anciennement 9) — 7 nouveaux tests de sécurité :
  - `validate_bootstrap_key` (clés valides, défaut rejeté, trop courte, faible diversité, répétitive)
  - `_zero_fill` (effacement mémoire)
  - `_derive_key` (retourne bytearray)
- **197/197 tests CLI** — zéro régression

### Fichiers modifiés (8)
- `src/mcp_vault/admin/middleware.py` — fix LFI (resolve + parenté)
- `src/mcp_vault/auth/middleware.py` — suppression `?token=`
- `src/mcp_vault/openbao/crypto.py` — validate_bootstrap_key, bytearray, _zero_fill
- `src/mcp_vault/lifecycle.py` — validation bootstrap key au startup
- `waf/Dockerfile` — multi-stage xcaddy + CRS v4.7.0
- `waf/Caddyfile` — `order coraza_waf first`, headers CSP, admin off
- `waf/coraza.conf` — **nouveau** (config Coraza + CRS + exceptions MCP)
- `tests/test_crypto.py` — 16 tests (7 nouveaux)

---

## [0.3.0] — 2026-03-23

### Console Admin SPA — Parité complète avec le CLI

La console web `/admin` atteint la **parité fonctionnelle totale** avec le CLI. Chaque fonctionnalité testée dans `tests/cli/` est désormais accessible visuellement dans l'interface web.

#### Nouvel onglet Policies (CRUD complet)
- **Liste des policies** : tableau avec colonnes (ID, Description, Mode allow/deny, Outils, Path Rules)
- **Détail d'une policy** : panneau avec outils autorisés/refusés, `path_rules` avec patterns `fnmatch` formatés
- **Création de policy** : modal guidé avec mode allow/deny, checkboxes des outils MCP catégorisés (Système, Vaults, Secrets, SSH CA, Policies, Tokens, Audit), ajout dynamique de règles de chemin
- **Suppression** avec confirmation
- Nouveau fichier : `static/js/policies.js`

#### SSH CA dans la SPA (5 opérations)
- **Setup SSH CA** : modal pour créer une CA + rôle (nom, utilisateur par défaut, TTL, utilisateurs autorisés)
- **Signer une clé SSH** : modal pour coller une clé publique et recevoir le certificat signé avec bouton copier
- **Clé publique CA** : affichage inline avec bouton copier et instructions serveur
- **Liste des rôles** : section dans le détail vault avec détail au clic (key_type, TTL, users)
- **5 nouveaux endpoints admin API** : `POST .../ssh/setup`, `POST .../ssh/sign`, `GET .../ssh/ca-key`, `GET .../ssh/roles`, `GET .../ssh/roles/{name}`

#### Tokens enrichis
- **Colonne Policy** dans le tableau des tokens (badge cliquable → navigation vers la policy)
- **Select `policy_id` dynamique** dans les modals de création et édition (chargé depuis l'API)
- Envoi du `policy_id` à la création du token
- Indication `owner` quand les vaults autorisés sont vides

#### Vaults enrichis
- **Vue tableau** avec 5 colonnes : Vault, Description, Secrets, Owner, Créé le
- **Badges Owner** : 👤 vert = propriétaire, 👥 bleu = partagé
- **Section SSH CA** dans le détail vault avec boutons setup, signer, clé CA

#### Dashboard enrichi
- **Compteur Policies** (admin) + cards cliquables vers les pages correspondantes
- **Générateur de mot de passe standalone** : CSPRNG 24 caractères avec bouton copier
- **Référence des 14 types de secrets** : grille avec champs requis/optionnels par type

#### UX Guidance
- **Tooltips ⓘ** sur tous les champs sensibles (permissions, vaults autorisés, policy, path_rules)
- **Help-text** sous chaque champ (ex: "Vide = accès uniquement aux vaults créés par ce token")
- **Descriptions des permissions** au survol (read/write/admin)
- **Aide contextuelle** pour les patterns fnmatch dans les path_rules

### Bug fixes
- **CORS middleware** : ajout de `PUT` dans `access-control-allow-methods` (manquait pour token update cross-origin)
- **Routage API** : fix du matching vault detail vs SSH routes (`/ssh/` exclu du routage vault)

### Fichiers modifiés (10)
- `static/js/policies.js` (nouveau — 310 lignes)
- `static/admin.html` (3 modals ajoutés, champs enrichis)
- `static/js/app.js` (sidebar + navigation policies)
- `static/js/tokens.js` (colonne Policy, select dynamique)
- `static/js/vaults.js` (tableau Owner, section SSH CA, 7 nouvelles fonctions)
- `static/js/dashboard.js` (compteur policies, générateur MdP, référence types)
- `static/css/admin.css` (styles help, tooltips, tools checklist, path rules)
- `admin/api.py` (5 endpoints SSH CA + fix routage)
- `admin/middleware.py` (CORS PUT)
- `VERSION` (0.2.0 → 0.3.0)

### Bilan SPA
- **25+ endpoints admin API** (Système 5, Vaults 5, Secrets 4, SSH CA 5, Policies 4, Tokens 4)
- **11 fichiers JS** (config, api, app, dashboard, vaults, tokens, policies, activity)
- **7 modals** (vault, secret, token create, token edit, policy, SSH setup, SSH sign)
- **Parité CLI 100%** : chaque commande testée dans `tests/cli/` a son équivalent SPA

---

## [0.2.0] — 2026-03-23

### Security — 3 couches d'isolation

#### Owner-based vault isolation (Phase 8d)
- **BREAKING**: `allowed_resources=[]` → accès uniquement aux vaults créés par le token (`created_by`), et non plus à tous les vaults
- **Fix**: Bug `vault_ids` → `allowed_resources` — les restrictions de vaults ne s'appliquaient jamais côté MCP tools
- `check_vault_owner()` vérifie `_vault_meta.created_by` pour l'isolation par propriétaire
- `list_spaces(owner_filter)` filtre les vaults par créateur

#### Path-level enforcement (Phase 8e)
- **Nouveau** : `allowed_paths` dans les `path_rules` des policies — contrôle d'accès au niveau secret individuel
- `is_path_allowed(policy_id, vault_id, path)` dans PolicyStore — matching fnmatch sur les chemins
- `check_path_policy(vault_id, path)` dans context.py — appelé par `secret_read`, `secret_write`, `secret_delete`
- Scénario testé : Alice/Bob partagent un vault, mais seuls les chemins `shared/*` sont accessibles — `private/*` est bloqué

### Features
- **SPA**: Modal d'édition des tokens (permissions, vaults autorisés, policy_id)
- **SPA**: Bouton Modifier sur chaque token
- Label "vide = tous" → "vide = mes vaults" partout

### CLI — Mise à jour complète

#### Nouvelles options
- **`policy create --path-rules/-R`** : création de policies avec restriction par chemin (JSON, fnmatch wildcards)
- **`token create --policy`** : assignation d'une policy dès la création du token

#### Affichage amélioré (display.py)
- **Policy get** : affichage détaillé des `allowed_paths` par path_rule (vault_pattern → permissions → chemins)
- **Token list** : colonnes `Vaults` + `Policy` (remplacent `Spaces` + `Email`)
- **Token create** : affiche policy_id assignée, "(tous — isolation par propriétaire)" si vaults vides
- **Vault list** : colonnes `Vault ID` + `Owner` (remplacent `Space ID`)
- **Whoami** : affiche la policy assignée au token

#### Aide pédagogique
- Aide racine : explication du modèle de sécurité à 3 couches (owner → vault → path)
- Aide vault : explique l'isolation owner-based
- Aide policy : explique la priorité denied > allowed, documention des path_rules avec exemples
- Aide token : explique le comportement par défaut (owner-based) et le rôle de --policy

### 🧪 Tests
- **~290 tests e2e** répartis en 14 catégories (anciennement 276)
- **TEST 13 réécrit** : owner-based isolation, cross-user Alice/Bob (vault-level + path-level), policy enforcement
- **197 tests CLI parsing** (`tests/test_cli_all.py`) : validation hors-ligne de TOUTES les commandes Click (aide, arguments, JSON, affichage Rich)
- **79 tests CLI live** (`tests/test_cli_live.py`) : cycle complet contre serveur réel (vault CRUD, secrets, policies+paths, tokens+enforcement, SSH CA, audit)
- **Tests CLI découpés** en 7 fichiers (`tests/cli/test_{system,vault,secret,ssh,policy,token,audit}.py`)
- Nouveau : `tests/TEST_CATALOG.md` — catalogue complet des tests pour auditeurs (19 sections avec objectifs)
- Nouveau : `tests/README.md` — guide d'exécution des tests pour auditeurs
- Environnement de recette isolé : bucket S3 `MCP-RECETTE` dédié aux tests

### Documentation
- `tests/README.md` : guide d'exécution de tous les tests (parsing, live, e2e)
- `tests/TEST_CATALOG.md` : catalogue d'audit des ~290 tests avec objectif par section
- DESIGN docs mis à jour (v0.2.0, owner isolation, path-level enforcement)

## [0.1.0] — 2026-03-22

### Added
- **24 outils MCP** : vaults (5), secrets (6), SSH CA (5), policies (4), token_update, audit_log, system (2)
- **14 types de secrets** style 1Password : login, password, api_key, database, server, certificate, etc.
- **SSH Certificate Authority** : CA isolée par vault, signature de clés éphémères ed25519
- **Policies MCP** : contrôle d'accès granulaire avec wildcards (fnmatch), path_rules par vault
- **Audit log** : ring buffer 5000 entrées + JSONL persistant, filtres combinables (category, status, since, tool, client)
- **Console admin SPA** (`/admin`) : dashboard, vaults, tokens, activité avec timeline, filtres et alertes
- **CLI complet** : Click + Rich + shell interactif (prompt-toolkit), 9 groupes de commandes
- **Route `GET /`** : status JSON public (nom, version, endpoints)
- **Mode `--demo`** : scénario réaliste avec tokens, policies, tentatives denied, SSH CA
- **276 tests e2e** répartis en 14 catégories (OpenBao réel, zéro mocking)
- **Sécurité Option C** : clés unseal chiffrées AES-256-GCM (PBKDF2 600k), stockées S3, mémoire seule au runtime
- **S3 sync** : périodique (60s), crash recovery via Docker volume, Dell ECS SigV2/SigV4
- **WAF** : Caddy reverse proxy + headers sécurité (port 8085)
- **Docker** : multi-stage (OpenBao 2.5.1 ARM64/x86_64 + Python 3.12), IPC_LOCK
- **Licence** : Apache 2.0, Cloud Temple

### Architecture
- Stack ASGI 5 couches : Admin → Health → Auth → Logging → FastMCP
- OpenBao embedded (localhost:8200, file backend, XChaCha20-Poly1305)
- Token Store S3 avec cache TTL 5 min
- Policy Store S3 avec cache TTL 5 min
- Audit Store : cache mémoire (ring buffer, volatile) + JSONL, **seul support persistant**

### Documentation
- ARCHITECTURE.md v0.2.2-draft : spécification complète
- TECHNICAL.md v0.2.0 : 14 modules source documentés
- scripts/README.md : guide CLI complet
