#!/usr/bin/env bash
# Corpus de règles agentiques Cloud Temple : installation, mise à jour et
# contrôle de conformité dans un dépôt consommateur.
#
#   agentic-rules.sh install <cible> [--ref <tag>] [--source <chemin|url>] [--force]
#   agentic-rules.sh update  <cible> [--ref <tag>] [--source <chemin|url>]
#   agentic-rules.sh check   <cible> [--remote] [--source <chemin|url>]
#
# Ce script est distribué avec le corpus, sous AGENTIC_RULES/. Un dépôt
# consommateur le vérifie donc sans accès sortant, et son empreinte est
# elle-même couverte par la provenance.
set -euo pipefail

DEFAULT_SOURCE="https://github.com/Cloud-Temple/agentic-rules.git"
RULES_DIR="AGENTIC_RULES"
MANIFEST="$RULES_DIR/MANIFEST"
PROVENANCE="$RULES_DIR/.provenance"
CONFIG="$RULES_DIR/project.config.yml"
CONFIG_EXAMPLE="$RULES_DIR/project.config.example.yml"
UNSET_MARKER="TO_FILL"

TMPROOT="$(mktemp -d)"
cleanup() { [ -n "$TMPROOT" ] && rm -rf "$TMPROOT"; return 0; }
trap cleanup EXIT INT TERM

die() { printf 'erreur: %s\n' "$*" >&2; exit 1; }
info() { printf '%s\n' "$*"; }

tmpdir() { mktemp -d "$TMPROOT/XXXXXX"; }

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
  else die "ni sha256sum ni shasum disponible"; fi
}

# Chemins de la charge utile, lus dans le MANIFEST d'un arbre donné.
read_manifest() {
  local tree="$1"
  [ -f "$tree/$MANIFEST" ] || die "MANIFEST absent de $tree"
  local line
  while IFS= read -r line; do
    case "$line" in
      /*) die "chemin absolu interdit dans le MANIFEST : $line" ;;
    esac
    case "/$line/" in
      */../*) die "chemin remontant interdit dans le MANIFEST : $line" ;;
    esac
    printf '%s\n' "$line"
  done <<< "$(grep -v '^[[:space:]]*#' "$tree/$MANIFEST" | grep -v '^[[:space:]]*$')"
}

fetch_source() {
  local source="$1" ref="$2" dir
  dir="$(tmpdir)/src"
  if [ -d "$source/.git" ]; then
    git clone --quiet --shared "$source" "$dir" 2>/dev/null || die "clone local impossible depuis $source"
  else
    git clone --quiet "$source" "$dir" 2>/dev/null || die "clone impossible depuis $source"
  fi
  if [ -n "$ref" ]; then
    git -C "$dir" checkout --quiet "$ref" 2>/dev/null || die "référence introuvable dans la source : $ref"
  fi
  printf '%s\n' "$dir"
}

# Prépare la charge utile complète dans un répertoire d'attente, puis la bascule
# d'un seul mouvement. Un échec de copie ne laisse donc pas un corpus hybride.
stage_payload() {
  local src="$1" stage="$2" f payload
  payload="$(read_manifest "$src")"
  [ -n "$payload" ] || die "MANIFEST vide dans $src"
  while IFS= read -r f; do
    [ -f "$src/$f" ] || die "fichier annoncé au MANIFEST mais absent de la source : $f"
    mkdir -p "$stage/$(dirname "$f")"
    cp "$src/$f" "$stage/$f" || die "copie impossible : $f"
  done <<< "$payload"
}

commit_payload() {
  local src="$1" stage="$2" target="$3" f payload backup done_list=""
  payload="$(read_manifest "$src")"
  backup="$(tmpdir)/backup"
  while IFS= read -r f; do
    if ! mkdir -p "$target/$(dirname "$f")" 2>/dev/null; then
      rollback_payload "$target" "$backup" "$done_list"
      die "répertoire parent impossible pour $f, cible remise en l'état"
    fi
    # mv déplacerait le fichier à l'intérieur d'un répertoire homonyme au lieu
    # d'échouer : refuser explicitement plutôt que produire un corpus imbriqué.
    if [ -d "$target/$f" ] && [ ! -L "$target/$f" ]; then
      rollback_payload "$target" "$backup" "$done_list"
      die "un répertoire occupe le chemin $f, cible remise en l'état"
    fi
    if [ -e "$target/$f" ]; then
      mkdir -p "$backup/$(dirname "$f")"
      cp -p "$target/$f" "$backup/$f"
    fi
    if ! mv "$stage/$f" "$target/$f" 2>/dev/null; then
      rollback_payload "$target" "$backup" "$done_list"
      die "installation impossible sur $f, cible remise en l'état"
    fi
    done_list="$done_list$f"$'\n'
  done <<< "$payload"
  [ -f "$target/$RULES_DIR/agentic-rules.sh" ] && chmod +x "$target/$RULES_DIR/agentic-rules.sh"
  return 0
}

rollback_payload() {
  local target="$1" backup="$2" done_list="$3" f
  [ -n "$done_list" ] || return 0
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if [ -e "$backup/$f" ]; then mv "$backup/$f" "$target/$f"
    else rm -f "$target/$f"; fi
  done <<< "$done_list"
}

write_provenance() {
  local src="$1" target="$2" stage="$3" ref commit f payload
  payload="$(read_manifest "$src")"
  commit="$(git -C "$src" rev-parse HEAD)"
  ref="$(git -C "$src" describe --tags --exact-match 2>/dev/null || echo "sans-tag")"
  {
    printf '# Provenance du corpus de règles agentiques. Fichier généré, ne pas éditer.\n'
    printf 'source_repo=%s\n' "$(git -C "$src" remote get-url origin 2>/dev/null || echo "$DEFAULT_SOURCE")"
    printf 'tag=%s\n' "$ref"
    printf 'commit=%s\n' "$commit"
    printf 'installed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    while IFS= read -r f; do
      printf 'sha256 %s %s\n' "$f" "$(sha256 "$target/$f")"
    done <<< "$payload"
  } > "$stage/provenance"
  mv "$stage/provenance" "$target/$PROVENANCE"
}

# Valeurs de la configuration, commentaires exclus. Le contrôle ne doit jamais
# se déclencher sur un marqueur cité dans un commentaire.
config_values() {
  sed -e 's/[[:space:]]#.*$//' -e 's/^[[:space:]]*#.*$//' "$1" | grep -v '^[[:space:]]*$'
}

cmd_install() {
  local target="$1" ref="$2" source="$3" force="$4" src stage f conflicts=""
  [ -d "$target" ] || die "cible inexistante : $target"
  [ -e "$target/$PROVENANCE" ] && die "corpus déjà installé dans $target, utiliser update"
  src="$(fetch_source "$source" "$ref")"

  local payload
  payload="$(read_manifest "$src")"
  while IFS= read -r f; do
    if [ -e "$target/$f" ]; then conflicts="$conflicts  $f"$'\n'; fi
  done <<< "$payload"
  if [ -n "$conflicts" ] && [ "$force" != "yes" ]; then
    printf 'fichiers déjà présents dans la cible, aucune installation :\n%s' "$conflicts" >&2
    die "sauvegarder ou retirer ces fichiers, ou relancer avec --force"
  fi

  stage="$(tmpdir)/stage"
  stage_payload "$src" "$stage"
  commit_payload "$src" "$stage" "$target"
  write_provenance "$src" "$target" "$stage"
  if [ ! -e "$target/$CONFIG" ]; then
    cp "$target/$CONFIG_EXAMPLE" "$target/$CONFIG"
    info "configuration créée : $CONFIG, renseigner les champs $UNSET_MARKER"
  fi
  info "corpus installé dans $target depuis $(grep '^tag=' "$target/$PROVENANCE" | cut -d= -f2)"
}

cmd_update() {
  local target="$1" ref="$2" source="$3" src stage before after
  [ -e "$target/$PROVENANCE" ] || die "aucun corpus installé dans $target, utiliser install"
  before="$(grep '^commit=' "$target/$PROVENANCE" | cut -d= -f2)"
  src="$(fetch_source "$source" "$ref")"
  stage="$(tmpdir)/stage"
  stage_payload "$src" "$stage"

  local f new old
  new="$(read_manifest "$src")"
  old="$(read_manifest "$target")"

  commit_payload "$src" "$stage" "$target"

  # Les fichiers sortis de la charge utile ne partent qu'une fois la nouvelle
  # en place : un échec de bascule ne doit rien détruire.
  while IFS= read -r f; do
    printf '%s\n' "$new" | grep -qx "$f" || { rm -f "$target/$f"; info "retiré du corpus : $f"; }
  done <<< "$old"
  write_provenance "$src" "$target" "$stage"
  after="$(grep '^commit=' "$target/$PROVENANCE" | cut -d= -f2)"
  if [ "$before" = "$after" ]; then info "corpus déjà à jour sur $after"
  else info "corpus mis à jour : $before -> $after"; fi
  [ -e "$target/$CONFIG" ] || info "attention : $CONFIG absent, le copier depuis $CONFIG_EXAMPLE"
}

cmd_check() {
  local target="$1" remote="$2" source="$3" rc=0 path expected actual f entry
  [ -e "$target/$PROVENANCE" ] || die "aucun corpus installé dans $target"
  [ -f "$target/$MANIFEST" ] || die "MANIFEST absent de $target, corpus incomplet"

  local payload
  payload="$(read_manifest "$target")"
  [ -n "$payload" ] || { printf 'MANIFEST vide\n'; return 1; }

  local hashed_count
  hashed_count="$(grep -c '^sha256 ' "$target/$PROVENANCE" || true)"
  [ "$hashed_count" -gt 0 ] || { printf 'PROVENANCE ne contient aucune empreinte\n'; return 1; }

  # 1. Chaque fichier du MANIFEST est empreinté et intact.
  while IFS= read -r f; do
    entry="$(grep "^sha256 $f " "$target/$PROVENANCE" || true)"
    if [ -z "$entry" ]; then
      printf 'NON EMPREINTE %s\n' "$f"; rc=1; continue
    fi
    if [ ! -f "$target/$f" ]; then
      printf 'MANQUANT   %s\n' "$f"; rc=1; continue
    fi
    expected="$(printf '%s' "$entry" | awk '{print $3}')"
    actual="$(sha256 "$target/$f")"
    [ "$actual" = "$expected" ] || { printf 'MODIFIE    %s\n' "$f"; rc=1; }
  done <<< "$payload"

  # 2. Aucune empreinte orpheline : retirer une ligne du MANIFEST ne suffit pas
  #    à sortir un fichier du contrôle.
  while read -r _ path _; do
    printf '%s\n' "$payload" | grep -qx "$path" \
      || { printf 'HORS MANIFEST %s est empreinté mais absent du MANIFEST\n' "$path"; rc=1; }
  done <<< "$(grep '^sha256 ' "$target/$PROVENANCE")"

  # 3. Aucun fichier local ajouté dans le répertoire des règles.
  local allowed base
  while IFS= read -r f; do
    case "$f" in "$RULES_DIR"/*) allowed="${allowed:-}${f#"$RULES_DIR"/}"$'\n' ;; esac
  done <<< "$payload"
  allowed="${allowed:-}.provenance"$'\n'"project.config.yml"$'\n'
  while IFS= read -r base; do
    printf '%s' "$allowed" | grep -qx "$base" \
      || { printf 'AJOUT LOCAL %s/%s ne fait pas partie du corpus\n' "$RULES_DIR" "$base"; rc=1; }
  done <<< "$(cd "$target/$RULES_DIR" && find . -mindepth 1 -printf '%P\n' | sort)"

  # 4. Configuration présente et réellement renseignée.
  if [ -e "$target/$CONFIG" ]; then
    config_values "$target/$CONFIG" | grep -q "$UNSET_MARKER" \
      && { printf 'A RENSEIGNER %s contient encore des %s\n' "$CONFIG" "$UNSET_MARKER"; rc=1; }
  else
    printf 'MANQUANT   %s\n' "$CONFIG"; rc=1
  fi

  # 5. Comparaison à la source, seule vérification qui ne dépend pas d'un
  #    fichier que le dépôt contrôle lui-même.
  if [ "$remote" = "yes" ]; then
    local tag src
    tag="$(grep '^tag=' "$target/$PROVENANCE" | cut -d= -f2)"
    [ "$tag" = "sans-tag" ] && tag="$(grep '^commit=' "$target/$PROVENANCE" | cut -d= -f2)"
    if src="$(fetch_source "$source" "$tag" 2>/dev/null)"; then
      while IFS= read -r f; do
        if [ ! -f "$src/$f" ]; then
          printf 'ABSENT A LA SOURCE %s\n' "$f"; rc=1; continue
        fi
        [ "$(sha256 "$target/$f")" = "$(sha256 "$src/$f")" ] \
          || { printf 'DIFFERENT DE LA SOURCE %s\n' "$f"; rc=1; }
      done <<< "$payload"
      local latest
      latest="$(git -C "$src" ls-remote --tags --refs origin 2>/dev/null \
        | awk -F/ '{print $NF}' | sort -V | tail -1 || true)"
      [ -n "$latest" ] && [ "$latest" != "$tag" ] \
        && printf 'AVERTISSEMENT corpus sur %s, dernier tag publié %s\n' "$tag" "$latest"
    else
      printf 'SOURCE INJOIGNABLE la comparaison demandée n a pas eu lieu\n'; rc=1
    fi
  fi

  [ "$rc" -eq 0 ] && info "conforme" || info "non conforme"
  return "$rc"
}

main() {
  [ $# -ge 2 ] || die "usage: $0 {install|update|check} <cible> [options]"
  local cmd="$1" target="$2"; shift 2
  local ref="" source="$DEFAULT_SOURCE" remote="no" force="no"
  while [ $# -gt 0 ]; do
    case "$1" in
      --ref) ref="${2:-}"; shift 2 ;;
      --source) source="${2:-}"; shift 2 ;;
      --remote) remote="yes"; shift ;;
      --force) force="yes"; shift ;;
      *) die "option inconnue : $1" ;;
    esac
  done
  case "$cmd" in
    install) cmd_install "$target" "$ref" "$source" "$force" ;;
    update)  cmd_update  "$target" "$ref" "$source" ;;
    check)   cmd_check   "$target" "$remote" "$source" ;;
    *) die "commande inconnue : $cmd" ;;
  esac
}

main "$@"
