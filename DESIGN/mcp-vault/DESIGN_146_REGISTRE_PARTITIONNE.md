# Registre wrap partitionné — étude de conception (#146)

> **Statut** : ⚠️ **ÉTUDE, aucune décision** | **Date** : 2026-08-24 | **Auteur** : Cloud Temple
> **Ne pas implémenter sur la base de ce document** : le §3 porte un fait non encore mesuré
> qui départage deux conceptions incompatibles.

---

## 1. Le problème, mesuré

Le registre wrap est **un fichier JSON unique** (`_system/wrap_registry.json`) que
`WrapRegistry._save()` **réécrit intégralement à chaque transition d'état**.

| Relevé (production `vault-01`) | Entrées | Octets | Octets/entrée |
| --- | --- | --- | --- |
| 20/08 12h40 | 219 | 101 195 | 462,1 |
| 20/08 13h27 | 220 | 101 658 | 462,1 |
| 21/08 21h40 | 221 | 102 121 | 462,1 |
| 23/08 13h00 | 243 | 112 307 | 462,2 |
| **24/08 ~09h** | **486** | **224 816** | **462,6** |

**463 octets par entrée, stable sur cinq points, strictement linéaire.** La nuit du
23 au 24/08, un banc de 20 runs de `mcp-mission` a **doublé le registre** (+243 entrées,
soit ~12 par run — un run mobilise 12 ouvriers, chacun tirant une enveloppe).

### La forme du coût

Réécrire un fichier de taille ∝ N à chacune de N opérations coûte **O(N²)** en octets
transférés cumulés. Ce n'est pas un facteur constant : c'est la forme qui est fautive.

**Mesures locales** (`json.dumps` + gzip, 5 répétitions) :

| Entrées | `indent=2` (actuel) | compact | compact + gzip |
| --- | --- | --- | --- |
| 486 | 234 Ko / 0,8 ms | 191 Ko | **9 Ko** / 1,8 ms |
| 5 000 | 2,4 Mo / 5,9 ms | 2,0 Mo | 92 Ko / 10,7 ms |
| 50 000 | 24 Mo / 58 ms | 20 Mo | 906 Ko / 113 ms |

⇒ **Le processeur n'est pas le sujet** (58 ms à 50 000 entrées). Le coût est le **transfert**.

⚠️ **La compression est un facteur, pas une forme.** À 200 000 entrées on réécrit encore
3,5 Mo compressés par opération ; à 1 000 000, 17,8 Mo. Elle achète du temps — au rythme
mesuré, 5 000 entrées sont atteintes en ~21 nuits de banc — elle ne résout rien.

### Pourquoi c'est un sujet de sécurité et pas de performance

`secret_consume` réécrit le registre **sur le chemin critique**, et OpenBao a un **point de
non-retour** : un dépassement de délai après le déballage perd le secret **définitivement**.
Or la latence de ce stockage est mesurément imprévisible — défaillances non déterministes
relevées les 20/08 et 23/08, et un PUT+GET de 1 Mo mesuré à **124 s** le 24/08 dans une
fenêtre dégradée. **La charge utile est la seule variable que nous contrôlons.**

---

## 2. Ce que dit la littérature

Le problème « registre clé-valeur mutable sur stockage objet » est résolu, et son patron
canonique est celui des formats de table (Iceberg, Delta Lake, Hudi).

| Élément retenu | Source | Ce qu'on en prend |
| --- | --- | --- |
| **Échange atomique de pointeur + concurrence optimiste** : lire le pointeur, écrire le nouveau contenu, `compare-and-swap` sur le pointeur, le perdant reprend sur le nouvel instantané | spécification Iceberg | c'est **exactement** notre besoin : un registre mutable sans verrou distribué |
| **Écritures conditionnelles S3** (`If-Match` sur l'ETag, `If-None-Match: *`) disponibles depuis nov. 2024 | AWS | fournit le CAS que #123 déclarait indisponible |
| **Hachage cohérent « jump »** (Lamping & Veach) — sans état, ~5 lignes, buckets numérotés séquentiellement | arXiv 1406.2294 | assignation d'un couple `(operation_id, mission_id)` à un tiroir, avec déplacement minimal quand K change |
| **Doublement de l'échelle** ⇒ migration de **1/2** des données (DxHash) | arXiv | borne le coût d'un re-partitionnement |
| **Filtre de Bloom : jamais de faux négatif**, seulement des faux positifs | littérature classique | ⚠️ l'asymétrie est **dans notre sens** (§5.3) |
| ⚠️ **Problème des petits fichiers / manifestes fragmentés** : des centaines de GET là où quelques lectures larges suffiraient ; nécessite compaction | communauté Iceberg | c'est **le coût** du découpage, et il faut le payer explicitement (§5.2) |

⚠️ **Ce que la littérature ne nous donne pas** : nos contraintes de sécurité (garde d'usage
unique par présence d'entrée, refus de purger, fail-close sur instantané ambigu) sont
propres à notre produit. Aucun format de table ne les porte.

---

## 3. ⚠️ LE FAIT QUI DÉPARTAGE — non encore mesuré

**Notre stockage (Dell ECS) honore-t-il les écritures conditionnelles ?**

La documentation Dell expose `If-Match` / `If-None-Match` sur `PutObject`. **La documentation
n'est pas une mesure** : la version déployée peut l'ignorer silencieusement — et un CAS
silencieusement ignoré est **pire que pas de CAS**, parce que le code croirait avoir une
garantie qu'il n'a pas.

**Sonde à exécuter** (en cours au moment de la rédaction), sous le préfixe `_test/` déjà
utilisé par la suite d'intégration, objet supprimé après :

| # | Requête | Attendu si le CAS est honoré |
| --- | --- | --- |
| 1 | `PUT If-None-Match: *` sur objet absent | ACCEPTÉ |
| 2 | `PUT If-None-Match: *` sur objet présent | **REFUSÉ 412** |
| 3 | `PUT If-Match: <bon etag>` | ACCEPTÉ |
| 4 | `PUT If-Match: <mauvais etag>` | **REFUSÉ 412** |

⚠️ **Si 2 et 4 sont ACCEPTÉS, le CAS n'existe pas** et la conception B (§5) est la seule
recevable. Si un client lève avant l'envoi (paramètre inconnu de la version botocore), le
résultat est *indéterminé*, pas négatif : à retester autrement.

---

## 4. Conception A — avec CAS (préférée si le §3 est positif)

### 4.1 Disposition

```
_system/wrap_registry/manifest.json     ← minuscule, muté sous CAS
_system/wrap_registry/shard-0000.json   ← entrées du tiroir 0
_system/wrap_registry/shard-0001.json
...
_system/wrap_registry.json              ← LEGACY, conservé en lecture (§6)
```

Le manifeste porte **K** (nombre de tiroirs), la génération, et **rien d'autre qui change à
chaque écriture** (voir §4.3 — c'est un point de conception, pas un détail).

### 4.2 Assignation

`tiroir = jump_consistent_hash(h64(operation_id + "\x00" + mission_id), K)`

- déterministe et sans état : **la garde d'usage unique est préservée** — on sait toujours
  dans quel tiroir chercher une clé, ce que la piste « purge » aurait détruit ;
- `h64` = 8 premiers octets de SHA-256 (pas de `hash()` Python : non stable entre processus).

### 4.3 ⚠️ Le manifeste ne doit PAS être muté à chaque écriture

Tentation naturelle : y maintenir les compteurs (total, par tiroir) pour que `system_health`
lise un seul petit objet. **Refusé** : cela ferait du manifeste un **point de sérialisation
global**, chaque écriture le mettant en concurrence avec toutes les autres — on remplacerait
un coût de taille par un coût de contention, et sous CAS cela produirait des reprises en
cascade.

⇒ **Le manifeste ne change que lors d'un re-partitionnement.** Le compteur total exposé par
`system_health` vient du dernier chargement complet du rafraîchisseur de fond — qui
**expose déjà son âge** (`age_seconds`). Le chiffre devient donc explicitement *« à cette
date »*, ce qui est honnête et déjà le cas aujourd'hui.

### 4.4 Écriture d'une transition

1. charger le tiroir de la clé (avec son ETag) ;
2. muter l'entrée en mémoire ;
3. `PUT If-Match: <etag>` sur le tiroir ;
4. sur **412** : recharger le tiroir, **rejouer la mutation**, réessayer (borné, avec
   attente croissante).

⇒ **Coût d'écriture : un tiroir.** Mesuré à ~400 entrées par tiroir : **7 Ko compressés,
plat, quelle que soit la taille de l'histoire** — 486 entrées ou 1 000 000.

⚠️ **Et cela FERME #51**, la course d'écriture multi-instance, au lieu de la reporter : deux
instances qui mutent des clés différentes ne se croisent plus (tiroirs distincts) ; deux
instances sur la même clé sont sérialisées par le CAS. Le `last-write-wins` disparaît.

### 4.5 Re-partitionnement

Déclenché quand un tiroir dépasse un seuil de taille (proposition : 400 entrées).
**Doublement de K** ⇒ ~1/2 des entrées changent de tiroir. Opération d'administration
explicite, jamais sur le chemin critique, sous CAS du manifeste, et **idempotente**.

---

## 5. ⚠️ Les parties difficiles — nommées, non résolues

### 5.1 Le rafraîchisseur de fond devient K requêtes

C'est **le coût du découpage**, et la littérature le nomme (problème des petits fichiers).
Aujourd'hui : 1 GET par rafraîchissement. Avec K = N/400, à 200 000 entrées : **500 GET**.

Piste : rendre le rafraîchissement **paresseux par tiroir** — le chemin de décision n'a
besoin de la fraîcheur que du tiroir qu'il touche.

⚠️ **Mais cela touche la garde de fail-close** dont nous venons de discuter avec
`mcp-mission` (23/08) : aujourd'hui `_last_load_ok` est **global**. Par tiroir, la sémantique
devient « ce tiroir est-il frais ? », ce qui est plus juste **mais change le contrat
d'erreur** (`backend_unavailable`) que nos appelants viennent d'apprendre. **À instruire, pas
à trancher ici.**

### 5.2 Compaction

Des tiroirs trop petits reproduisent le problème des petits fichiers à l'envers. Un seuil
bas de re-partitionnement produirait des centaines de tiroirs quasi vides. La compaction
(fusion de tiroirs quand K décroît) n'est **pas** traitée dans cette étude.

### 5.3 Filtre de Bloom : utile, mais pas nécessaire ici

Avec l'assignation déterministe (§4.2), la garde d'usage unique n'a besoin que **d'un**
tiroir : le filtre de Bloom ne sert à rien. Il ne redeviendrait utile que si l'on voulait
éviter le GET du tiroir dans le cas « clé jamais vue ».

⚠️ Si un jour on l'introduit, la formulation exacte compte — ma première rédaction était
confuse, je la corrige ici. Un filtre de Bloom **prouve l'absence** (aucun faux négatif) et
**ne prouve jamais la présence** (faux positifs possibles). Donc :

| Réponse du filtre | Ce qu'on peut en conclure | Usage légitime |
| --- | --- | --- |
| « absent » | **certain** : cette clé n'a jamais été vue | ✅ **autoriser sans lire le tiroir** |
| « peut-être présent » | rien | ❌ ne jamais refuser sur cette base — **lire le tiroir** |

⇒ L'asymétrie est **dans notre sens** : le seul coût d'un faux positif est une lecture de
plus, jamais une mauvaise décision de sécurité. Ce qui serait une faute, c'est de **refuser**
sur un « peut-être » — cela produirait des refus de demandes légitimes.

### 5.4 🔴 DEUX clés de recherche, pas une — la version naïve du §4 est FAUSSE

Vérifié dans le code (`server.py`, `_select_wrap_entries` à `wrapping.py:1069`) :

| Point d'entrée | Clé disponible à l'appel |
| --- | --- |
| `secret_revoke_wrap(lease_id)` | **l'accessor SEUL** |
| `secret_wrap_status(operation_id, mission_id)` | le couple |
| `secret_wrap_lookup(operation_id, mission_id)` | le couple |
| `secret_consume(wrap_token, operation_id, …)` | `operation_id` |
| `secret_wrap(…)` (création) | le couple |

⇒ **Ranger les tiroirs par `(operation_id, mission_id)` rend `secret_revoke_wrap` coûteux :
sans le couple, il faudrait balayer les K tiroirs.** Et c'est le chemin le plus chaud que
nous connaissions — `mcp-mission` l'appelle **onze fois par clôture de mission**.

Ranger par accessor inverse le problème : la garde d'usage unique, qui interroge par couple,
devient O(K).

**Résolution proposée — l'index secondaire, patron standard :** deux structures partitionnées.

| Structure | Clé de partition | Sert |
| --- | --- | --- |
| **entrées** | `accessor` | `secret_revoke_wrap` |
| **index** | `(operation_id, mission_id)` → accessor(s) | garde d'usage unique, `status`, `lookup`, `consume` |

Chaque chemin chaud ne touche **qu'un tiroir de la bonne structure**. L'index est minuscule
(clé → clé, ~100 octets contre 463).

⚠️ **Mais une création touche alors DEUX objets** (une entrée + son index), et le CAS ne
porte que sur **un** objet : un état partiel est donc possible — index écrit sans entrée, ou
l'inverse.

⇒ Ce n'est pas rédhibitoire, parce que **nous avons déjà ce patron** : `register_pending`
écrit l'intention *avant* l'appel OpenBao et l'ordre write-ahead est délibéré. La même
discipline s'applique : écrire l'index d'abord (un index sans entrée = une clé réservée,
donc **fail-close**, l'inverse serait un trou), et prévoir la réconciliation.

**Non tranché** : l'ordre exact, la détection et la reprise d'un état partiel. C'est le
vrai chantier de ce sujet.

### 5.5 🔴 `registry_inconsistent` repose sur un balayage GLOBAL

`_select_wrap_entries` positionne `saw_malformed` sur une entrée inexploitable **n'importe
où dans le registre**, matchante ou non — la docstring le dit explicitement, et
`status_by_operation_id` s'en sert pour rendre `registry_inconsistent` à l'administration.

⇒ **Partitionner rétrécit cette garantie** : une entrée malformée dans un autre tiroir ne
serait plus vue. Ce n'est pas un détail d'implémentation, c'est **un contrat d'erreur qui
change** — et nos appelants viennent d'apprendre le vocabulaire actuel (dossier du 23/08,
taxonomie `backend:`/`transport:` de `mcp-mission` v0.8.30).

Deux voies, aucune décidée : accepter le rétrécissement en le **documentant** (la détection
devient « dans le tiroir consulté »), ou déplacer cette détection vers une **vérification
d'intégrité périodique** hors chemin critique.

⚠️ **Ce point est arrivé par la lecture du code, pas par la conception.** Il illustre le
risque principal de ce sujet : le registre porte des contrats implicites qu'un découpage
casse silencieusement.

---

## 6. Migration et retour arrière

| Étape | Ce que la version fait | Retour arrière |
| --- | --- | --- |
| **R1** | **lit** les deux dispositions (legacy + tiroirs), **écrit** en legacy | sûr |
| **R2** | écrit en tiroirs ; le legacy reste, figé, jamais réécrit | sûr vers R1 |
| **R3** (bien plus tard) | le legacy n'est plus lu | ⚠️ irréversible |

⚠️ **Sans R1, R2 est un aller sans retour** : une version antérieure ne saurait pas lire les
tiroirs. C'est le même piège que la compression, et la même parade.

⚠️ **Rien n'est supprimé** : l'objet legacy est conservé. Notre refus de purger reste entier,
et la tension avec #156 ne s'ouvre pas.

---

## 7. Ce que cette étude ne fait PAS

- **Ne désérialise pas les opérations wrap.** Le verrou de #123 protège l'atomicité vis-à-vis
  du rafraîchisseur, pas le débit. Le découpage réduit la *taille* écrite, pas le nombre
  d'opérations sérialisées.
- **N'introduit pas de seconde source de vérité.** Même stockage, même technologie durable,
  un seul registre logique. ⚠️ **C'est une LECTURE de l'arbitrage de #123** (« un seul
  support durable ») : nous la lisons comme portant sur la technologie, pas sur le nombre
  d'objets. **Si cette lecture est fausse, la conception A tombe entièrement.** À confirmer
  par le propriétaire de l'arbitrage.
- **Ne purge rien.** La mesure rend la purge inutile : le sujet était le poids, pas le nombre.
- **Ne propose pas de calendrier.**

---

## 8. Conception B — si le §3 est négatif

Sans CAS, deux écritures concurrentes sur le même tiroir s'écrasent : on **retrouve #51**,
mais sur un périmètre **réduit** (un tiroir au lieu du registre entier). Ce n'est pas une
solution, c'est une atténuation.

⇒ Dans ce cas, la seule chose défendable à court terme est la **compression** (facteur 25,
aucun changement de disposition), et le découpage devient un chantier **subordonné** à
l'obtention d'un CAS — par une version d'ECS le supportant, ou un service de verrous, ce qui
rouvrirait la question de la seconde source de vérité (§7).

---

## 9. Questions ouvertes — à trancher avant toute ligne de code

1. **Le §3** : le CAS est-il honoré ? *(sonde en cours)*
2. **La lecture de l'arbitrage #123** (§7) est-elle la bonne ?
3. ✅ **RÉPONDU (§5.4) — et la réponse casse la conception naïve** : il y a **deux clés de
   recherche**. Reste à trancher l'ordre d'écriture des deux structures et la reprise d'un
   état partiel.
6. Le rétrécissement de `registry_inconsistent` (§5.5) est-il acceptable, ou faut-il une
   vérification d'intégrité séparée ?
4. Le passage du fail-close **global** à **par tiroir** (§5.1) est-il acceptable pour nos
   appelants, qui viennent d'apprendre le contrat actuel ?
5. Seuil de tiroir, et politique de compaction (§5.2).
