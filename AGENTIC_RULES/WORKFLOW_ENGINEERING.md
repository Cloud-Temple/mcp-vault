# Discipline d'ingénierie

Ce fichier définit les contrôles techniques. L'autorisation humaine est définie
uniquement dans `MAIN_RULES.md` ; Git et les releases ont leurs propres fichiers.

## Cycle proportionné au risque

Comprendre le besoin et lire les éléments concernés, faire la modification
minimale, vérifier le résultat, revoir le diff final, puis livrer dans le cadre
du workflow applicable. Adapter les contrôles à l'effet réel de la modification :

| Changement | Vérification et revue |
| --- | --- |
| Texte ou présentation sans effet de comportement | Relecture locale et contrôle du rendu ou des liens concernés. |
| Comportement applicatif courant | Tests pertinents et une revue indépendante du diff final. |
| Données persistées, autorisations, secrets, CI, suppression, migration, production, contrat public ou règles de pilotage | Revue indépendante du plan avant exécution, puis du résultat ; vérification des invariants et du retour arrière. |

Une correction de faute dans une règle reste éditoriale. Un changement de
configuration qui modifie l'exécution ne l'est pas. En cas de doute sur l'impact,
examiner le composant concerné avant de choisir les contrôles.

Ne pas dupliquer la même revue avant et après commit : associer la revue à une
révision précise, par SHA ou diff conservé. Après une modification, revoir le
delta et relancer les contrôles qu'il affecte. Un simple changement de SHA sans
changement de contenu n'impose pas de répéter toute la revue ; la validité des
contrôles d'intégration doit néanmoins être vérifiée.

## Revue indépendante

Le pilote produit le changement ; le relecteur le conteste dans une session
distincte, en lecture seule. Le relecteur est un autre modèle que le pilote.
`REVIEWERS.md` donne le modèle à employer pour chaque fournisseur disponible et
les contraintes d'invocation ; `review.reviewer_provider` de `project.config.yml`
désigne celui que ce dépôt utilise. Ne pas présenter une auto-relecture comme une
validation indépendante, ni affirmer une diversité de modèles non vérifiée.

Fournir au relecteur le besoin, le plan ou le diff réel, les éléments de contexte
nécessaires, les vérifications effectuées et les risques à challenger. Pour une
tâche déléguée, vérifier aussi que le livrable répond au mandat initial.

Conserver le verdict original avec l'identité effectivement fournie par l'outil,
la révision, les constats, leur gravité et les limites de la revue. Vérifier les
constats contre les faits ; corriger les blocages ou expliquer avec preuves
pourquoi ils ne s'appliquent pas. Une préférence de style ne devient pas un blocage.

Le relecteur et sa commande proviennent d'une configuration vérifiée. Ne pas
déduire le modèle exécuté d'un nom écrit dans ces règles. Employer une invocation
non interactive et bornée ; ne pas contourner un refus d'outil ou de confidentialité.

Si la revue indépendante est indisponible, le signaler et poursuivre la
préparation locale réversible avec une auto-relecture déclarée, uniquement si
le prérequis mémoire de `MAIN_RULES.md` est satisfait. Les changements
qui exigent une revue indépendante restent non prêts au merge ou à l'exécution
sur un système partagé tant que cette revue manque. Aucun verdict ne s'invente.

## Tests utiles

- Pour un défaut de comportement, reproduire l'échec puis montrer la réussite
  avec la correction. Si le test avant correction n'est pas réalisable, expliquer
  pourquoi et fournir la meilleure preuve disponible ; ne pas inventer un RED.
- Tester le résultat métier, les limites, les erreurs et les autorisations
  pertinentes. Pour l'état persistant, vérifier l'état final, pas seulement le
  code de retour. Un test qui passe sans la correction n'en prouve pas l'efficacité.
- Réutiliser les tests, fixtures et contrôles CI existants. Respecter les contrôles
  requis sans ajouter un dispositif de couverture pour satisfaire ces règles.
- Ne pas affaiblir un test ou un contrôle pour masquer une régression. Une évolution
  légitime du contrat doit être justifiée et revue avec les attentes correspondantes.
- Pour une modification documentaire, vérifier le contenu, les liens et les exemples
  concernés. Ne pas écrire de tests logiciels sans comportement à protéger.
- Rapporter les contrôles exécutés et leurs résultats réels. Après leur réussite,
  élargir les vérifications seulement si un changement ou un doute le justifie.

## État persistant et exploitation

- Une suppression ou un retrait d'état exige une intention explicite et une preuve
  provenant de l'autorité pertinente. Un accès refusé, un timeout ou une liste
  partielle ne prouve pas une absence. En cas d'incertitude, préserver l'état et
  produire un diagnostic exploitable, sans annoncer un succès trompeur.
- Distinguer une valeur non renseignée d'une valeur explicitement demandée.
  Ne pas laisser le mapping ou la sérialisation décider d'une suppression sur
  la base d'un signal ambigu.
- Avant une mutation importante, identifier la cible, les préconditions, l'impact,
  la vérification et le retour arrière possible. Vérifier l'état réel après
  l'action. Après un échec partiel ou un timeout, le relire avant de réessayer.
- Réutiliser les procédures d'exploitation existantes. Sur un système partagé,
  borner les sondes et arrêter une action si elle dégrade le service. Ne pas
  improviser de boucle de charge sur la production.
- Tracer une mutation réelle dans le journal opérationnel existant : date UTC,
  cible, action, résultat, preuve, impact résiduel et rollback ou suivi. Une
  préparation locale ou une inspection n'est pas une mutation de production.

Mettre à jour les documents affectés : README pour l'usage et l'installation,
DESIGN pour l'architecture et les contrats, changelog pour les changements
livrés. Lors d'une livraison, aligner VERSION, les exemples et les métadonnées
concernées. Distinguer version préparée, commit intégré, tag créé et release
effectivement publiée ; ne jamais annoncer l'un comme preuve de l'autre.
Ne pas ajouter automatiquement de signature d'outil ou de coauteur artificiel.
