#!/usr/bin/env bash
# Fonctions communes aux contrôles source et consommateur. Aucun accès réseau.

# Valeurs de la configuration, commentaires exclus. Le contrôle ne doit jamais
# se déclencher sur un marqueur cité dans un commentaire.
config_values() {
  sed -e 's/[[:space:]]#.*$//' -e 's/^[[:space:]]*#.*$//' "$1" | grep -v '^[[:space:]]*$'
}

# Valeur d'une clé de la configuration, désignée par son chemin complet, par
# exemple project.instructions_file. Le chemin est obligatoire : le schéma
# réutilise des noms terminaux d'une section à l'autre, ainsi `server` sous
# memory.live et sous memory.graph, et chercher le seul nom terminal rendrait
# la valeur de la mauvaise section. Rend une chaîne vide si la clé est absente.
config_value() {
  config_values "$1" | awk -v want="$2" -v presence="${3:-}" '
    {
      line = $0
      sub(/^[[:space:]]*-.*$/, "", line)
      if (line ~ /^[[:space:]]*$/) next
      if (line !~ /:/) next
      match(line, /^[[:space:]]*/); ind = RLENGTH
      key = line; sub(/^[[:space:]]*/, "", key)
      val = key
      sub(/^[^:]*:[[:space:]]*/, "", val)
      sub(/:.*$/, "", key)
      while (n > 0 && depth[n] >= ind) n--
      n++; depth[n] = ind; name[n] = key
      path = name[1]
      for (i = 2; i <= n; i++) path = path "." name[i]
      if (path == want) { found = val; seen = 1 }
    }
    END { if (seen) print (presence == "present" ? "present" : found) }' \
    | sed -e 's/^["'"'"']//' -e 's/["'"'"']$//' -e 's/[[:space:]]*$//'
}

# Chemin réel d'un fichier, liens symboliques résolus, sans dépendre de
# `readlink -f` qui n'existe pas partout. Rend un échec si le répertoire
# conteneur n'existe pas.
#
# Le plafond de 40 itérations et l'échec qui le suit sont une défense en
# profondeur qu'aucun test n'atteint, et c'est assumé : le seul appelant vérifie
# `-f` avant d'appeler, or le noyau rend déjà ELOOP au-delà de sa propre limite
# de liens. Fabriquer un test qui force cet état serait du théâtre. Les deux
# restent parce que la fonction peut être appelée ailleurs un jour, et parce
# qu'un chemin à demi résolu se trouve parfois dans le dépôt alors que la cible
# réelle est dehors.
resolve_path() {
  local p="$1" t d b n=0
  while [ -L "$p" ] && [ "$n" -lt 40 ]; do
    t="$(readlink "$p")" || return 1
    case "$t" in
      /*) p="$t" ;;
      *) p="$(dirname "$p")/$t" ;;
    esac
    n=$((n + 1))
  done
  # Plafond atteint sans avoir fini de dérouler : rendre un échec, jamais un
  # chemin partiellement résolu. Un chemin à mi-parcours peut être à l'intérieur
  # du dépôt alors que la cible réelle est dehors, et l'appelant conclurait à
  # une conformité qui n'existe pas.
  [ -L "$p" ] && return 1
  d="$(dirname "$p")"; b="$(basename "$p")"
  d="$(cd "$d" 2>/dev/null && pwd -P)" || return 1
  printf '%s/%s\n' "$d" "$b"
}

# Contrôle du format local, sans prétendre vérifier le connecteur ou ses droits.
# Le lecteur couvre le YAML de mappings scalaires utilisé par nos exemples ;
# il ne traite pas les ancres, les listes ni une configuration MCP complète.
config_validate() {
  local file="$1" target="$2" rc=0 schema flat=0 key value server space interval
  if [ ! -f "$file" ]; then
    printf 'MANQUANT   %s\n' "$file"
    return 1
  fi
  if config_values "$file" | grep -q 'TO_FILL'; then
    printf 'A RENSEIGNER %s contient encore des TO_FILL\n' "$file"; rc=1
  fi
  schema="$(config_value "$file" schema_version)"
  # Une configuration historique sans génération explicite n'acquiert pas
  # implicitement les champs du nouveau modèle.
  [ -n "$schema" ] || schema=1
  case "$schema" in
    1|2|3|4) ;;
    *) printf 'SCHEMA INVALIDE schema_version doit valoir 1, 2, 3 ou 4\n'; rc=1 ;;
  esac
  for key in server space_id consolidation_check_interval_hours; do
    [ "$(config_value "$file" "memory.$key" present)" != present ] || flat=1
  done
  if [ "$schema" = 4 ] || [ "$flat" -eq 1 ]; then
    if [ "$schema" != 4 ]; then
      printf 'SCHEMA MEMOIRE le format Hivemind plat exige schema_version: 4\n'; rc=1
    fi
    if [ "$(config_value "$file" memory.live present)" = present ] \
      || [ "$(config_value "$file" memory.graph present)" = present ]; then
      printf 'MEMOIRE AMBIGUE ne pas melanger memory.server/space_id et memory.live/graph\n'; rc=1
    fi
    server="$(config_value "$file" memory.server)"
    space="$(config_value "$file" memory.space_id)"
    interval="$(config_value "$file" memory.consolidation_check_interval_hours)"
  else
    server="$(config_value "$file" memory.live.server)"
    space="$(config_value "$file" memory.live.space_id)"
    interval="$(config_value "$file" memory.live.consolidation_check_interval_hours)"
    # La clé a été introduite en schéma 3 : absente avant, elle est disabled.
    if [ -z "$interval" ] && { [ "$schema" = 1 ] || [ "$schema" = 2 ]; }; then
      interval=disabled
    fi
  fi
  case "$server" in
    ''|disabled|TO_FILL) printf 'MEMOIRE NON RENSEIGNEE connecteur serveur requis\n'; rc=1 ;;
    *://*|*[[:space:]]*) printf 'SERVEUR INVALIDE utiliser un alias MCP, pas une URL ou une phrase\n'; rc=1 ;;
  esac
  case "$space" in
    ''|disabled|TO_FILL) printf 'MEMOIRE NON RENSEIGNEE space_id requis\n'; rc=1 ;;
    [-_]*) printf 'ESPACE INVALIDE space_id doit commencer par une lettre ou un chiffre\n'; rc=1 ;;
    *[!A-Za-z0-9_-]*) printf 'ESPACE INVALIDE space_id doit contenir lettres, chiffres, tirets ou underscores\n'; rc=1 ;;
    *) [ "${#space}" -le 64 ] || { printf 'ESPACE INVALIDE space_id depasse 64 caracteres\n'; rc=1; } ;;
  esac
  case "$interval" in
    disabled) ;;
    ''|*[!0-9]*|0) printf 'INTERVALLE INVALIDE entier strictement positif ou disabled requis\n'; rc=1 ;;
    *)
      # Ne pas convertir en entier shell : pas d'overflow ni d'octal implicite.
      case "$interval" in *[1-9]*) ;; *) printf 'INTERVALLE INVALIDE zero n est pas une echeance\n'; rc=1 ;; esac ;;
  esac

  # Préserver le contrôle de frontière du document d'instructions du projet.
  local notes root real
  notes="$(config_value "$file" project.instructions_file)"
  case "$notes" in
    ''|disabled|TO_FILL) ;;
    /*) printf 'CHEMIN ABSOLU instructions_file doit être relatif à la racine : %s\n' "$notes"; rc=1 ;;
    *)
      if [ ! -f "$target/$notes" ]; then
        if [ -L "$target/$notes" ] && [ ! -e "$target/$notes" ]; then
          printf 'LIEN CASSE instructions_file désigne %s, dont la cible est introuvable\n' "$notes"
        elif [ -e "$target/$notes" ]; then
          printf 'PAS UN FICHIER instructions_file désigne %s, qui n est pas un fichier régulier\n' "$notes"
        else
          printf 'POINTEUR MORT instructions_file désigne %s, qui n existe pas\n' "$notes"
        fi
        rc=1
      else
        root="$(cd "$target" && pwd -P)"
        if real="$(resolve_path "$target/$notes")"; then
          case "$real" in
            "$root"/*) ;;
            *) printf 'HORS DEPOT instructions_file désigne %s, qui mène à %s\n' "$notes" "$real"; rc=1 ;;
          esac
        else
          printf 'CHEMIN IRRESOLU instructions_file désigne %s\n' "$notes"; rc=1
        fi
      fi ;;
  esac
  return "$rc"
}
