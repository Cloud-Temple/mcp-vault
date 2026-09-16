# Relecteurs

Ce fichier donne le modèle à employer pour la revue indépendante définie dans
`WORKFLOW_ENGINEERING.md`. Il fait partie du corpus : son contenu est identique
dans tous les dépôts. Le dépôt choisit seulement le fournisseur qu'il utilise,
par la clé `review.reviewer_provider` de `project.config.yml`.

## Un modèle par fournisseur

| Clé | Fournisseur | Modèle | Contrainte d'invocation |
| --- | --- | --- | --- |
| `claude` | Anthropic | `claude-sonnet-5` | Session distincte, lecture seule, invocation non interactive et bornée. |
| `codex` | OpenAI | `gpt-5.6-terra` | `reasoning_effort: "none"` obligatoire dès que des function tools sont présents ; toute autre valeur renvoie un HTTP 400. |
| `llmaas` | Cloud Temple LLMaaS (SecNumCloud) | `qwen3.8:27b` | Alias appelable du modèle `Qwen/Qwen3.8-27B-FP8`, endpoint `api.ai.cloud-temple.com`. |

Aucun niveau de raisonnement, aucun tier et aucune variante ne sont déclarés ici.
Un seul modèle par fournisseur, pour que la revue soit reproductible et que deux
dépôts ne produisent pas des verdicts issus de configurations différentes.

## Règles d'emploi

- Le relecteur est un modèle différent du pilote. Si le pilote et le relecteur
  configuré désignent le même modèle, la revue n'est pas indépendante : changer
  de fournisseur ou signaler la revue comme indisponible.
- Le modèle réellement exécuté provient de la configuration de l'outil, pas de
  ce tableau. Vérifier l'identité retournée par l'outil et la conserver avec le
  verdict. Ne jamais déduire le modèle exécuté du nom écrit ici.
- Un fournisseur absent de la configuration locale n'est pas un fournisseur
  indisponible tant que cela n'a pas été vérifié. Une indisponibilité constatée
  se signale, elle ne se contourne pas par une auto-relecture présentée comme
  indépendante.

## Mise à jour

Les modèles évoluent souvent. Ce fichier change par une PR sur ce dépôt, suivie
d'un tag. Les dépôts consommateurs reçoivent le changement par le script de mise
à jour ; leur job de conformité signale l'écart tant qu'ils ne l'ont pas pris.
Ne pas modifier ce tableau dans un dépôt consommateur : la modification locale
sera détectée comme une dérive et écrasée à la mise à jour suivante.
