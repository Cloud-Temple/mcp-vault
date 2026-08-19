#!/usr/bin/env bash
# Lance une revue adversariale `codex exec` dans une COPIE DE TRAVAIL DÉDIÉE.
#
# ⚠️ POURQUOI CE SCRIPT EXISTE (19/08/2026). Lancée dans l'arbre de travail vivant, la
# revue a annulé deux fois des modifications non commitées et fait disparaître un fichier
# de test non suivi — un processus resté actif après la fin de son appel. Le diagnostic a
# coûté plus de temps que la revue n'en a fait gagner. `-s read-only` borne les écritures
# de l'outil, pas les commandes git qu'il choisit d'exécuter.
#
# ⚠️ Cadre également le prompt : la revue doit rester une revue de CODE. Sans borne, elle
# lit les règles agentiques du dépôt et épuise son budget sans rendre de verdict — arrivé
# une fois, sur #86.
#
# Usage : scripts/revue_isolee.sh <fichier-de-prompt> [<ref-git>]
#   <ref-git> par défaut : HEAD.
set -euo pipefail

PROMPT="${1:?usage: revue_isolee.sh <fichier-de-prompt> [<ref-git>]}"
REF="${2:-HEAD}"
[[ -r "$PROMPT" ]] || { echo "prompt illisible : $PROMPT" >&2; exit 2; }

RACINE="$(git rev-parse --show-toplevel)"
BASE="${TMPDIR:-/tmp}/revue-isolee-$$"
SHA="$(git -C "$RACINE" rev-parse --short "$REF")"

git -C "$RACINE" worktree prune
git -C "$RACINE" worktree add --detach "$BASE" "$REF" >/dev/null
echo "→ revue isolée sur $SHA dans $BASE"

nettoyer() {
    git -C "$RACINE" worktree remove --force "$BASE" 2>/dev/null || true
    git -C "$RACINE" worktree prune
    echo "→ copie de travail retirée"
}
trap nettoyer EXIT INT TERM

# `cd` dans la copie : la revue ne voit que celle-là. Le `</dev/null` évite qu'elle
# attende une entrée, et le timeout borne un run qui partirait en dérive.
cd "$BASE"
codex exec -s read-only -c model_reasoning_effort=xhigh "$(cat "$PROMPT")" </dev/null
