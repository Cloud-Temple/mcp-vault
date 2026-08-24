# Registre wrap partitionné — étude de conception (#146)

> **Statut** : ⚠️ **ÉTUDE — v2, après revue adversariale (NO_GO sur la v1)** | 2026-08-24
> **Ne pas implémenter** : le §3 porte un fait non mesuré qui conditionne tout, et il
> concerne **une garantie de production déjà en place**, indépendamment de ce sujet.

---

## 1. Le problème, mesuré

`WrapRegistry._save()` sérialise **tout** le registre (`_system/wrap_registry.json`) et le
réécrit à **chaque transition d'état**.

### Relevés de production (`system_health.stores.wrap_registry`)

| Date | Entrées | Octets | Octets/entrée |
| --- | --- | --- | --- |
| 20/08 12h40 | 219 | 101 195 | 462,08 |
| 20/08 13h27 | 220 | 101 658 | 462,08 |
| 21/08 21h40 | 221 | 102 121 | 462,09 |
| 23/08 13h00 | 243 | 112 307 | 462,17 |
| **24/08 ~09h** | **486** | **224 816** *(219,5 Kio)* | **462,58** |

**+243 entrées en une nuit** (banc de 20 runs `mcp-mission`, 12 ouvriers par run) : le
registre a **doublé**.

⚠️ **Précisions imposées par la revue — la v1 de ce document arrondissait trop vite :**
- la moyenne va de **462,08 à 462,58** o/entrée. Les *incréments* observés valent exactement
  463, mais **sur ce corpus homogène uniquement** : ce n'est pas une borne générale ;
- 🔴 **les champs ne sont PAS de taille bornée.** `operation_id`, `mission_id`,
  `secret_path`, `accessor` peuvent atteindre des centaines de caractères, et `tenant_id`
  n'est contrôlé que comme non blanc (`server.py:631`). ⇒ **Tout seuil exprimé en « nombre
  d'entrées » est faux. Un seuil doit être exprimé en OCTETS.**

### La forme du coût

Réécrire Θ(N) octets à chacune de N transitions ⇒ **O(N²)** cumulé. **Structurel, indépendant
de toute mesure de latence.**

**Mesures locales de sérialisation** (corpus synthétique, 5 répétitions — ⚠️ synthétique,
d'où l'écart avec les 219,5 Kio de production à 486 entrées : les deux chiffres ne se
réconcilient pas et ne doivent pas être présentés côte à côte comme une même mesure) :

| Entrées | `indent=2` | compact | compact+gzip | gain gzip |
| --- | --- | --- | --- | --- |
| 486 | 234 Ko / 0,8 ms | 191 Ko | 9 Ko / 1,8 ms | ×26,0 / ×21,2 |
| 5 000 | 2,4 Mo / 5,9 ms | 2,0 Mo | 92 Ko / 10,7 ms | ×26,3 / ×21,5 |
| 50 000 | 24 Mo / 58 ms | 20 Mo | 906 Ko / 113 ms | ×26,5 / ×22,1 |

⚠️ Le « facteur 25 » de la v1 n'est vrai **que contre le format indenté actuel** (26,0–26,5) ;
contre du compact il vaut 21,2–22,1. Et **« le processeur est hors sujet » était trop
affirmatif** : 113 ms à 50 000 extrapole à ~2,26 s de gzip à 1 000 000 — **sous le verrou qui
sérialise les opérations wrap** (#123). Ce n'est plus négligeable.

### Pourquoi c'est un sujet de sécurité

`secret_consume` réécrit le registre **sur le chemin critique**, et OpenBao a un **point de
non-retour** : une lenteur après le déballage perd le secret **définitivement**.

⚠️ **Nous n'avons AUCUNE mesure de la latence d'écriture S3 de la production.** La v1 de ce
document invoquait des défaillances « mesurées » : **elles portaient sur le bucket
`MCP-RECETTE` depuis un poste de travail** (endpoint `takinc5acc…`, actuellement injoignable
d'ici — DNS résolu, TCP en échec), alors que la production écrit sur
`agentic-platform-mcp-vault-prod` depuis l'intérieur de la plateforme. **Deux chemins sans
rapport.** Argument retiré ; le trou de mesure est listé en §9.

---

## 2. Ce que dit la littérature — et quel compromis nous choisissons

Le problème est résolu ailleurs. Le cadre qui le **juge** est la conjecture RUM : on ne peut
pas minimiser simultanément les trois amplifications.

| Amplification | Définition | Notre situation aujourd'hui |
| --- | --- | --- |
| **Écriture** | octets réécrits par octet muté | 🔴 **catastrophique** : tout le registre par transition |
| **Lecture** | objets à consulter pour répondre | ✅ optimale : 1 objet, et les décisions lisent la **mémoire** (`store_refresh.py`) |
| **Espace** | octets stockés / octets utiles | ✅ optimale : aucune duplication |

⇒ **Nous sommes au coin « lecture et espace optimaux, écriture catastrophique ».** Partitionner
échange de l'amplification d'écriture contre de l'amplification de lecture. **C'est le
compromis, et il faut l'assumer explicitement** — c'est ce que la v1 ne faisait pas.

| Élément retenu | Source | Ce qu'on en prend |
| --- | --- | --- |
| Échange atomique de pointeur + concurrence optimiste (lire, écrire, CAS, le perdant reprend) | spécification Iceberg | le patron de mutation sans verrou distribué |
| Écritures conditionnelles S3 (`If-Match`, `If-None-Match: *`) depuis nov. 2024 ; Dell ECS les expose | AWS, doc Dell | le CAS que #123 déclarait indisponible |
| **Problème des petits fichiers / manifestes fragmentés** : des centaines de GET là où quelques lectures suffiraient ; exige compaction | communauté Iceberg | 🔴 **c'est le prix du découpage**, à payer explicitement (§5) |
| Segments immuables + compaction périodique ; **tiering vs leveling** | survol LSM, arXiv 2507.09642 | la compaction n'est pas une option, c'est une composante |
| Filtre de Bloom : **jamais de faux négatif** | littérature classique | asymétrie exploitable, mais **inutile ici** (§6.4) |
| Hachage cohérent « jump » ; doublement ⇒ migration de 1/2 | arXiv 1406.2294, DxHash | ⚠️ **écarté en v1** (§5.3) |

⚠️ **Ce que la littérature ne donne pas** : nos contraintes de sécurité — garde d'usage unique
**par présence d'entrée et définitive**, refus de purger, fail-close sur instantané ambigu.
Aucun format de table ne les porte.

---

## 3. 🔴 Un fait non mesuré qui DÉPASSE ce sujet

**Nous dépendons DÉJÀ du CAS en production, et personne ne l'a vérifié.**

`scripts/rotate_bootstrap_key.py:247` écrit la clé de chiffrement racine avec `IfMatch`, et
le commentaire dit explicitement pourquoi : *« `IfMatch` rend la vérification ATOMIQUE côté
stockage : la relecture de l'étape 7 ne ferme pas à elle seule la fenêtre entre le contrôle
et l'écriture (TOCTOU) »*.

⚠️ **Si le stockage ignore silencieusement `IfMatch`, cette fenêtre TOCTOU est OUVERTE** — sur
l'objet le plus critique du produit, celui dont la corruption rend le coffre définitivement
illisible. Le commentaire devient une fausse assurance.

### 🔴 Et la documentation de référence dit que ça NE DEVRAIT PAS marcher

> « **To use conditional writes, you must use AWS Signature Version 4 to sign the request.** »
> — documentation AWS S3, *conditional writes*

Or notre client de **données** est **SigV2** — délibérément : `s3_client.py` documente une
configuration **hybride**, *« SigV2 pour les opérations de données (PUT/GET/DELETE), SigV4
pour les métadonnées (HEAD/LIST) »*, avec le commentaire `# SigV2 legacy — requis par Dell
ECS`.

⚠️ **Et `rotate_bootstrap_key.py` utilise `get_s3_data_client()`**, donc **SigV2**, pour son
`IfMatch`. ⇒ Sur l'implémentation de référence, cette écriture conditionnelle serait
**inopérante**. Reste à savoir ce que fait ECS : l'honorer sous SigV2, la refuser, ou —
le pire — **l'ignorer en silence**.

### Calibrage honnête de la gravité — ce n'est PAS une alarme

Vérifié dans le script : `IfMatch` n'est **pas la seule barrière**. Trois couches protègent
cette rotation :

| # | Barrière | État |
| --- | --- | --- |
| 1 | **Quiescence opérationnelle** : « ARRÊTER TOUTES LES INSTANCES » — dans la docstring, affiché au lancement (« EXÉCUTION EXCLUSIVE REQUISE »), et remède de tous les messages de conflit | intacte |
| 2 | **Relecture avant écriture** (étape 7) : contenu **et** ETag comparés, abandon sur divergence | intacte |
| 3 | `IfMatch` : ferme la fenêtre résiduelle **entre** l'étape 7 et l'écriture | ⚠️ **peut-être inopérante** |

⇒ **Une couche de défense en profondeur possiblement muette**, sur l'objet dont la corruption
rend le coffre définitivement illisible. À mesurer et à signaler — **pas à dramatiser**.

⇒ **Mais la conséquence pour ce sujet est brutale** : la conception du §4 ferait du CAS la
**SEULE** barrière — sans quiescence, sans relecture. Si le CAS n'est pas honoré sur le chemin
de données, **le §4 est mort**, et #51 reste ouvert.

⇒ **Ce relevé doit être demandé indépendamment de #146.**

### La sonde — ce qu'il faut, et pourquoi la mienne ne valait rien

Tentée le 24/08 depuis un poste : **échec sur délai de connexion**, et elle visait le bucket
de **recette** avec un client **SigV4 par défaut**. Or le client de données de production est
**SigV2, path-style** (`s3_client.py`, `get_s3_data_client`). ⇒ **Sonde nulle et non avenue.**

Une sonde **négative** (les 4 requêtes séquentielles : création `If-None-Match:*`, re-création
refusée 412, `If-Match` bon etag accepté, mauvais etag refusé 412) suffit à conclure « pas de
CAS ». Une sonde **positive ne prouve rien** sans, au minimum :

1. **le client exact de production** — SigV2, path-style, même bucket ;
2. **deux PUT réellement concurrents** avec le même ETag, depuis deux connexions
   indépendantes : exactement **un** succès, **un** 412, contenu final = celui du gagnant ;
3. le même test concurrent sur `If-None-Match: *` ;
4. des répétitions **traversant les différents nœuds** derrière le point d'accès ECS ;
5. la vérification **read-after-write** de l'ETag après conflit ;
6. ⚠️ le cas **réponse perdue** : un PUT accepté puis coupé doit être reconnu comme
   « mutation déjà appliquée », **jamais rejoué aveuglément**.

**Sémantique documentée à implémenter telle quelle** (doc AWS) — trois codes, trois
conduites différentes, et les confondre serait la faute du #78 :

| Code | Cause | Conduite |
| --- | --- | --- |
| **412** Precondition Failed | la précondition est fausse : quelqu'un a écrit avant nous | **recharger et rejouer la mutation** |
| **409** Conflict | requêtes concurrentes ; ou une suppression a gagné | **re-tentable** pour `PutObject` (documenté) |
| **404** Not Found | avec `If-Match`, une suppression concurrente a gagné, ou l'objet n'existe pas | **ré-écrire** — ce n'est pas un conflit de version |

⚠️ Et `If-None-Match: *` attend **littéralement `*`**, jamais un ETag.

---

## 4. La conception retenue — partitionner l'ÉCRITURE seulement

Issue de la revue adversariale, qui a écarté la mienne. **Le point que j'avais manqué : les
décisions ne lisent pas le réseau, elles lisent la mémoire.** Le partitionnement n'a donc à
servir que l'**écriture**.

```
_system/wrap_registry/g001/shard-0000.json   ← préfixe VERSIONNÉ par génération
_system/wrap_registry/g001/shard-0001.json
...
_system/wrap_registry.json                  ← legacy, lu tant que R3 n'est pas atteint
```

| Élément | Décision |
| --- | --- |
| **K** | **FIXE par version**, dimensionné en **octets** sur un horizon mesuré. Jamais dynamique (§5.3) |
| Clé de partition | `(operation_id, mission_id)` — **le couple dont dispose la création**, seul appelant de la garde d'usage unique (`wrapping.py:401` : *« cette garde n'est appelée QUE par `wrap_secret` »*) |
| Toutes les lectures | **l'instantané complet en mémoire**, comme aujourd'hui — inchangé |
| Index par accessor | **en mémoire uniquement**, reconstruit par le rafraîchisseur. ⚠️ **Aucun index durable** |
| Écriture | CAS sur **le seul tiroir muté** ; `If-None-Match: *` si le tiroir n'existe pas encore |
| Re-partitionnement | **absent de la v1** |

### Ce que cela préserve, vérifié dans le code

- **la garde d'usage unique** : la création dispose du couple, donc du tiroir. Inchangée ;
- **`secret_revoke_wrap(lease_id)`** : ne dispose que de l'accessor — mais il lit la
  **mémoire**, où l'instantané est complet. **Le problème des « deux clés » de la v1
  disparaît** ;
- **`registry_inconsistent`** : `saw_malformed` signale une entrée malformée *n'importe où*.
  Le chargement complet voyant toujours tous les tiroirs, **le contrat est préservé** ;
- **aucune purge**, **une seule technologie durable**, **le verrou de #123 intact**.

### Et cela FERME #51 au lieu de le reporter

Deux instances mutant des clés différentes ne se croisent plus. Sur la même clé, le CAS
sérialise. Le `last-write-wins` disparaît — **sous réserve du §3**.

---

## 5. 🔴 Les coûts et les pièges, nommés

### 5.1 🔴 Le rafraîchissement devient K requêtes — et il est sur le CHEMIN CHAUD

⚠️ **Correction à ma propre formulation** : j'écrivais « le rafraîchisseur de fond fera K
requêtes ». **Faux — les chemins de décision appellent `registry._maybe_refresh()`
SYNCHRONEMENT** : vérifié à `wrapping.py` dans `_revoke_wrap_blocking`,
`_status_by_operation_id_blocking` et `_consume_wrap_secret_blocking`.

⇒ Quand l'instantané est périmé (après une erreur, ou une inactivité), **c'est l'appelant qui
paie le rechargement** — donc, en partitionné, LIST + n GET **sur le chemin critique**, celui
où un dépassement de délai perd le secret. Le rafraîchisseur de fond ne fait que rendre ce
cas rare ; il ne l'élimine pas.

**La parade**

C'est l'amplification de lecture qu'on achète. **Parade** : le rafraîchisseur fait un
`list_objects_v2` (1 requête par 1000 clés) qui rend les **ETags**, compare avec ce qu'il
détient, et ne fait un GET que sur les tiroirs **changés**. En régime établi, peu de tiroirs
changent entre deux rafraîchissements.

⚠️ **À mesurer, pas à supposer** : coût réel d'un LIST + n GET depuis la production. C'est le
trou de mesure qui décide de K.

⚠️ **Et le LIST est sous SigV4** (client métadonnées) tandis que les GET/PUT sont sous SigV2
(client données) : la parade mélange donc les deux clients. À vérifier — pagination
(1000 clés par page), cohérence du listing, et ETag des objets multipart (qui n'est pas un
MD5 simple).

### 5.2 🔴 La sémantique de fraîcheur doit être ÉCLATÉE

Aujourd'hui `_save()` réussi remet `_last_load_ok = True` — un PUT prouve que S3 répond.
⚠️ **En partitionné, c'est FAUX** : un PUT réussi sur le tiroir A remettrait le registre au
vert alors que le tiroir B est resté inconnu.

Quatre notions à séparer, contre une aujourd'hui :
1. fraîcheur du dernier **instantané global** ;
2. fraîcheur des **tiroirs requis par une décision** ;
3. succès de la **dernière écriture** ;
4. **poids** du dernier tiroir écrit *versus* poids logique **total**.

⚠️ Cela change le contrat d'erreur `backend_unavailable` que nos appelants **viennent
d'apprendre** (`mcp-mission` v0.8.30, taxonomie `backend:`/`transport:`). À leur annoncer,
pas à leur imposer.

### 5.3 Pourquoi PAS de re-partitionnement dynamique en v1

Scénario démontré en revue : l'administration copie K→2K ; une instance encore en K écrit une
intention **après** la copie ; le manifeste bascule ; l'intention **n'existe pas** en
génération 2K ; **la clé paraît vierge et un second wrap devient possible.**

⇒ Un re-partitionnement sûr exige : noms **versionnés par génération**, construction **hors
ligne**, basculement atomique, et **fencing** des écrivains. La génération dans un manifeste
ne suffit pas. ⇒ **Hors v1.** Changer K = migration administrative avec quiescence (§7).

### 5.4 Ce que le CAS ne couvre pas

Le CAS porte sur **un objet**. Toute conception exigeant deux objets mutés atomiquement est
hors d'atteinte — **c'est pourquoi l'index durable de la v1 est abandonné** (§6.1).

---

## 6. Alternatives évaluées — et pourquoi elles sont écartées

### 6.1 Index secondaire durable (ma v1) — 🔴 rédhibitoire

Un index orphelin bloque la clé, ce qui est fail-close et **correct**. Mais il la bloque
**pour toujours** : rien ne libère une clé (`wrapping.py:401`). Et la réconciliation ne peut
pas trancher, car deux cas sont **indiscernables** sans phase transactionnelle durable :
- un plantage avant OpenBao ⇒ supprimer l'index serait sûr ;
- la perte ultérieure de l'entrée d'un wrap **réellement créé** ⇒ supprimer **rouvrirait une
  clé utilisée**.

De plus, au moment d'écrire l'index, **l'accessor n'existe pas encore**. ⇒ Abandonné.

### 6.2 Purge des entrées terminales — écartée, mais la v1 la rejetait pour une raison FAUSSE

La v1 écrivait *« le sujet était le poids, pas le nombre »*. **Faux dans ma propre
conception** : le nombre détermine K, donc le nombre de GET, la durée du verrou, le coût
d'intégrité et la migration.

La bonne raison de l'écarter : la garde d'usage unique est **définitive et par présence**.
La revue proposait une variante : purger la **charge lourde** en gardant un **tombstone
compact**, en estimant le gain à ~100 octets contre 462, soit ×4,6. Je l'ai reprise comme
« potentiellement la meilleure première étape ».

### 🔴 MESURÉE, elle ne tient pas — et l'estimation ×4,6 est fausse

Champs réellement imposés par les contrats existants : `_entry_well_formed`
(`wrapping.py:1057`) exige `operation_id`, `vault_id`, `secret_path`, `status` en `str`, et
`accessor` en `str` **ou** `None` ; `_visible_entries` consomme `vault_id` **et**
`secret_path`. Un tombstone ne peut donc lâcher que `created_at`, `expires_at`, `tenant_id`,
`expected_aud` — et, au prix d'un contrat, `accessor`.

**Mesure sur 5 000 entrées :**

| Variante | brut/entrée | **gzip/entrée** | gain brut | **gain gzip** |
| --- | --- | --- | --- | --- |
| entrée pleine (actuel) | 403,8 o | 11,8 o | 1,00× | 1,00× |
| tombstone **avec** accessor | 265,8 o | **11,9 o** | 1,52× | **0,99× — aucun gain** |
| tombstone **sans** accessor | 227,8 o | 8,6 o | 1,77× | **1,37× seulement** |

⚠️ **Explication, et c'est la leçon générale de tout ce sujet** : les champs qu'un tombstone
supprime (`created_at`, `expires_at`, `tenant_id`, `expected_aud`) sont **très répétitifs
d'une entrée à l'autre** — la compression les élimine déjà presque entièrement. Ce qui reste
est **la haute entropie** : identifiants et chemins. **Exactement ce qu'aucune compression ne
réduit.**

⇒ **Une fois compressé, purger la charge lourde ne gagne rien** (×0,99 avec accessor, ×1,37
sans). Et « sans accessor » coûte un contrat : `secret_revoke_wrap(lease_id)` cherche **par
accessor**. Sans lui sur les entrées terminales, une ré-révocation répondrait `not_found` au
lieu de `already_revoked` — sur un chemin que `mcp-mission` appelle **onze fois par clôture**.

### ⇒ La conclusion de l'étude, maintenant mesurée

Le poids du registre est dominé par des **identifiants irréductibles**.

1. la compression retire l'échafaudage répétitif — **gain unique de ×21 à ×26** ;
2. après quoi le poids est ∝ (nombre d'entrées × entropie des identifiants) ;
3. ⇒ **seuls deux leviers changent la FORME** : écrire moins d'octets par transition
   (partitionner) ou avoir moins d'entrées (supprimer). **Et supprimer est interdit** par la
   garde d'usage unique, définitive et par présence.

**Donc le partitionnement n'est pas un choix parmi d'autres : c'est le seul levier de forme
disponible.** Et sa viabilité tient entièrement à la question du §3 (CAS sous SigV2). ⇒
**Variante tombstone ÉCARTÉE, sur mesure et non sur argument.**

### 6.3 Séparation chaud/froid — écartée en l'état

Objet chaud borné par la **concurrence** (les enveloppes en vol : quelques dizaines, TTL
≤ 300 s), archive pour les terminales.

🔴 **Réserve dirimante de la revue** : une archive **unique réécrite à chaque terminaison**
reste **O(N²)**, et cette écriture est **sur le chemin critique** (la terminaison suit le
déballage). Ne vaut que si l'archive est **append-only ou écrite par lots**, avec tombestones
durables et transition idempotente — c'est-à-dire si l'on construit un LSM. ⇒ Pas plus simple.

### 6.4 Filtre de Bloom — inutile ici

Avec l'instantané complet en mémoire, la garde n'a besoin d'aucun filtre.

Pour mémoire, la formulation exacte (ma v1 l'avait inversée) : un filtre **prouve l'absence**
(aucun faux négatif) et **ne prouve jamais la présence**.

| Réponse | Conclusion | Usage légitime |
| --- | --- | --- |
| « absent » | **certaine** | ✅ autoriser sans lire |
| « peut-être présent » | aucune | ❌ ne jamais refuser dessus — lire |

---

## 7. 🔴 Migration : PAS de déploiement progressif

| Étape | La version… | Retour arrière |
| --- | --- | --- |
| **R1** | lit legacy **et** tiroirs ; écrit **legacy** | sûr |
| **R2** | écrit **tiroirs** | ⚠️ **uniquement avec quiescence** |
| **R3** | ne lit plus le legacy | irréversible |

⚠️ **La v1 affirmait « R2 sûr vers R1 ». FAUX**, démontré en revue :
- **instances mélangées** : une R2 écrit la clé dans les tiroirs, une R1 (cache frais mais
  antérieur) ne la voit pas et l'écrit dans le legacy. **Les deux écritures ne visent pas le
  même objet : aucun CAS ne les met en concurrence ⇒ deux wraps possibles.** « Le legacy reste
  figé » est faux tant qu'une R1 tourne ;
- **retour arrière** : une entrée `active` au legacy, consommée par R2, devient `consumed`
  dans un tiroir ; le legacy reste `active`. Après retour à R1, deux états contradictoires —
  et **le schéma n'a ni `updated_at`, ni version logique, ni règle de précédence**
  (`wrapping.py:148`).

⇒ **R1→R2 et R2→R1 exigent l'arrêt des écrivains**, la matérialisation vérifiée de l'état, puis
le redémarrage. **Un déploiement progressif est interdit.** À écrire dans la procédure, pas
seulement ici.

⚠️ **Et la compression seule a le même problème** : `load()` fait
`json.loads(resp["Body"].read().decode())` sans détection de format (`wrapping.py:245`). Une
version antérieure confrontée à du gzip tombe en **panne de registre**. ⇒ Elle exige aussi
lecteur double **puis** activation différée. **Elle n'est donc pas « gratuite ».**
Seul le retrait de `indent=2` l'est : cela reste du JSON, lisible par les deux versions.

---

## 8. Ce que cette étude ne fait pas

- ne désérialise rien (le verrou de #123 protège l'atomicité, pas le débit) ;
- n'introduit **pas** de seconde source de vérité : même technologie, un seul registre
  logique. ⚠️ **C'est une LECTURE de l'arbitrage #123** (« un seul support durable ») comme
  portant sur la technologie et non sur le nombre d'objets. **Si cette lecture est fausse, le
  §4 tombe.** À confirmer par le propriétaire de l'arbitrage ;
- ne purge rien **en v1** (mais §6.2 mérite instruction) ;
- ne propose aucun calendrier.

---

## 9. Questions ouvertes — à trancher avant toute ligne de code

1. 🔴 **Le CAS est-il honoré SOUS SigV2** ? La documentation AWS exige SigV4 ; notre client de
   données est SigV2 « requis par Dell ECS ». ⇒ Soit ECS l'honore quand même, soit il faut
   passer ce chemin en SigV4 (et savoir POURQUOI il est en SigV2), soit le §4 est mort.
   **Relevé à demander à la plateforme, et il concerne d'abord la rotation de la clé racine.**
2. 🔴 **Coût réel d'un rafraîchissement LIST + n GET** depuis la production (§5.1) : c'est lui
   qui dimensionne K.
3. **Latence d'écriture S3 réelle de la production** — aucune mesure à ce jour (§1).
4. La lecture de l'arbitrage #123 (§8) est-elle la bonne ?
5. L'éclatement de la sémantique de fraîcheur (§5.2) est-il acceptable pour nos appelants, qui
   viennent d'apprendre le contrat actuel ?
6. ✅ **RÉPONDU (§6.2) — la variante tombstone est écartée, mesurée à ×0,99 avec accessor et
   ×1,37 sans.** Le poids est dominé par des identifiants que rien ne comprime.
7. Distribution des états en production — n'est **plus** un préalable (elle ne servait qu'à
   dimensionner la variante tombstone, désormais écartée). Reste utile au diagnostic.
