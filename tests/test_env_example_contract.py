# -*- coding: utf-8 -*-
"""
Tests de contrat du fichier `.env.example` — issue #100.

CONTEXTE
--------
La release v0.9.0 publiait un `.env.example` dont la ligne 46 contenait
littéralement `***REMOVED***` : séquelle d'une réécriture d'historique
`git-filter-repo` qui avait détruit l'assignation `ADMIN_BOOTSTRAP_KEY=`, en
laissant orphelin son bloc de documentation. Une plateforme de déploiement
externe a refusé de builder la release, à juste titre : le fichier n'était pas
un contrat dotenv exploitable.

Le défaut ne provoquait aucun crash visible, ce qui explique qu'il ait survécu
huit versions :

  - `python-dotenv` ne signale rien — son motif de clé est `([^=\\#\\s]+)`, donc
    il accepte `***REMOVED***` comme un NOM DE CLÉ, avec la valeur `None` ;
  - `pydantic-settings` absorbe ensuite cette entrée via son filtre de valeurs
    falsy, si bien qu'aucune `ValidationError` n'est levée.

Mais côté consommateur, les deux rendus possibles cassent le déploiement :
rendre l'entrée avec une valeur non vide déclenche `extra_forbidden`
(`Settings` est en `extra="forbid"`), et ne pas la rendre du tout laisse
`ADMIN_BOOTSTRAP_KEY` à son défaut `change_me_in_production`, que
`validate_bootstrap_key()` rejette — le serveur fait alors `sys.exit(1)`.

CE QUE CES TESTS VERROUILLENT
----------------------------
Ils ne se contentent pas de vérifier que la ligne 46 est réparée : ils épinglent
l'invariant qui rend le fichier exploitable sans heuristique par un tiers.

  - toute ligne est vide, commentaire, ou assignation stricte ;
  - le classificateur lui-même rejette bien les formes malformées (sans ce test,
    le précédent pourrait passer à vide) ;
  - les clés documentées correspondent EXACTEMENT aux champs de `Settings`,
    dans les deux sens ;
  - aucun motif `CLÉ=VALEUR` ne traîne dans la prose des commentaires, où un
    extracteur inventerait des clés fantômes qui font échouer le démarrage ;
  - aucune matière secrète n'est présente ;
  - le marqueur `REQUIRED` ne peut jamais devenir une clé de chiffrement.
"""

from __future__ import annotations

import os
import re
import string
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
ENV_EXAMPLE = REPO_ROOT / ".env.example"

sys.path.insert(0, str(REPO_ROOT / "src"))

from mcp_vault.config import Settings  # noqa: E402
from mcp_vault.openbao.crypto import validate_bootstrap_key  # noqa: E402

# Nom de clé dotenv conforme POSIX. Volontairement plus strict que python-dotenv,
# qui accepte tout token sans '=', '#' ni espace — c'est précisément ce laxisme
# qui a laissé passer `***REMOVED***`.
_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Déclaration commentée d'une variable optionnelle : `# CLE=valeur`.
_COMMENTED_DECL_RE = re.compile(r"^#\s?([A-Za-z_][A-Za-z0-9_]*)=")

# Deux variantes d'extracteur plus permissives que la nôtre, utilisées pour
# prouver qu'aucune clé fantôme ne peut être inventée depuis la prose.
_TOLERANT_RE = re.compile(r"^\s*#\s*([A-Za-z_][A-Za-z0-9_]*)\s*=")
_NAIVE_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=")

# Valeurs EXACTES attendues pour les clés qui porteraient un secret en production.
# Épingler la valeur littérale (et non un motif) est ce qui fait échouer le test
# si un vrai credential est collé à la place d'un placeholder.
_SENSITIVE_EXPECTED = {
    "ADMIN_BOOTSTRAP_KEY": "REQUIRED",
    "S3_ACCESS_KEY_ID": "your_access_key_here",
    "S3_SECRET_ACCESS_KEY": "your_secret_key_here",
    "S3_ENDPOINT_URL": "https://your-s3-endpoint.example.com",
    "S3_BUCKET_NAME": "your-bucket-name",
}

# Variables lues UNIQUEMENT par le CLI (scripts/cli/). Elles ne sont pas des
# champs de Settings : les déclarer dans .env.example — même commentées — expose
# un extracteur à les activer, ce qui ferait échouer le démarrage du serveur.
_CLI_ONLY_KEYS = ("VAULT_WRAP_TOKEN", "VAULT_MISSION_TOKEN")

# Marqueur d'une variable sans défaut utilisable.
_REQUIRED_MARKER = "REQUIRED"

# Préfixes de credentials à fournisseur identifiable. Ils complètent l'heuristique
# d'entropie : une clé d'accès AWS (`AKIA…`) est en MAJUSCULES et chiffres
# uniquement, donc invisible pour une heuristique qui exige un mélange de casses.
# Les deux mécanismes sont nécessaires, aucun ne suffit seul.
_CREDENTIAL_MARKERS = ("hvs.", "hvb.", "-----BEGIN", "AKIA", "ASIA")


# ─────────────────────────────────────────────────────────────────────────────
# Outillage
# ─────────────────────────────────────────────────────────────────────────────

def classify(line: str) -> tuple[str, str | None, str | None]:
    """
    Classe une ligne dotenv. Retourne (catégorie, clé, valeur).

    Catégories : "blank", "comment", "assignment", "malformed".
    Aucune ligne n'échappe au classement — c'est ce qui rend le décompte
    exhaustif vérifiable.
    """
    if line.strip() == "":
        return ("blank", None, None)
    if line.lstrip().startswith("#"):
        return ("comment", None, None)
    if "=" not in line:
        return ("malformed", None, None)
    key, value = line.split("=", 1)
    if not _KEY_RE.match(key):
        return ("malformed", None, None)
    return ("assignment", key, value)


def env_example_lines() -> list[str]:
    """Lignes réelles du fichier, sans l'élément vide produit par la newline finale."""
    lines = ENV_EXAMPLE.read_text(encoding="utf-8").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def settings_env_names() -> set[str]:
    """Noms de variables d'environnement réellement consommés par Settings."""
    return {name.upper() for name in Settings.model_fields}


def active_assignments() -> dict[str, str]:
    out: dict[str, str] = {}
    for line in env_example_lines():
        category, key, value = classify(line)
        if category == "assignment":
            assert key is not None and value is not None
            out[key] = value
    return out


def commented_declarations() -> dict[str, int]:
    out: dict[str, int] = {}
    for number, line in enumerate(env_example_lines(), start=1):
        match = _COMMENTED_DECL_RE.match(line)
        if match:
            out.setdefault(match.group(1), number)
    return out


# Token candidat : caractères d'un alphabet base64 URL-safe, avec padding final
# optionnel. Le '=' n'est PAS dans le corps du motif — sinon une ligne
# `S3_ACCESS_KEY_ID=your_access_key_here` serait avalée comme un seul token, dont
# les majuscules viendraient de la clé et les minuscules de la valeur : un faux
# positif systématique.
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_-]+={0,2}")


# Valeurs littérales connues du dépôt, exemptées de l'heuristique de forme. Toute
# valeur qui n'est pas dans cette liste et qui a l'allure d'un credential fait
# échouer le test — c'est ce qui rend l'exemption sûre plutôt que permissive.
_KNOWN_PLACEHOLDERS = frozenset({
    "REQUIRED",
    "your_access_key_here",
    "your_secret_key_here",
    "your-bucket-name",
    "change_me_in_production",
    "BASE64_URLSAFE_SANS_RETOUR_LIGNE",
    "BASE64_URLSAFE_DU_JSON",
})


def _looks_like_a_credential(token: str) -> bool:
    """
    Heuristique de FORME sur un token déjà isolé. Ce n'est pas un scanner de
    secrets : c'est un garde-fou qui attrape les formes de credential les plus
    courantes. La garantie forte vient des valeurs littérales épinglées par
    `test_sensitive_keys_carry_only_placeholders` et de la liste de préfixes
    fournisseur ; cette heuristique est le troisième filet.

    Trois motifs, parce qu'un seul en laissait passer (constat de revue) :
      - ≥32 caractères mêlant majuscules, minuscules ET chiffres
        (forme `secrets.token_urlsafe`, clé secrète S3) ;
      - ≥32 caractères hexadécimaux — une clé hex de 64 caractères n'a que
        2 classes et échappait au premier motif ;
      - ≥40 caractères d'alphabet base64 avec au moins 2 classes — attrape un
        token long à casse unique, également invisible pour le premier motif.
    """
    if token in _KNOWN_PLACEHOLDERS or len(token) < 32:
        return False

    has_upper = any(c in string.ascii_uppercase for c in token)
    has_lower = any(c in string.ascii_lowercase for c in token)
    has_digit = any(c in string.digits for c in token)

    if has_upper and has_lower and has_digit:
        return True
    if len(token) >= 32 and all(c in string.hexdigits for c in token) and has_digit:
        return True
    if len(token) >= 40 and sum([has_upper, has_lower, has_digit]) >= 2:
        return True
    return False


def _scannable_payload(line: str) -> str:
    """
    Partie d'une ligne susceptible de porter un secret : la VALEUR pour une
    assignation, le texte pour un commentaire. Scanner la ligne entière
    mélangerait le nom de la clé et sa valeur.
    """
    category, _, value = classify(line)
    if category == "assignment":
        assert value is not None
        return value
    if category == "comment":
        return line.lstrip().lstrip("#")
    return line


# ─────────────────────────────────────────────────────────────────────────────
# 1 & 2 — Parsabilité stricte, et validité du classificateur lui-même
# ─────────────────────────────────────────────────────────────────────────────

def test_every_line_is_blank_comment_or_valid_assignment() -> None:
    """
    RED sur v0.9.0 : la ligne 46 (`***REMOVED***`) est classée "malformed".

    C'est le test qui reproduit le défaut signalé par la plateforme.
    """
    malformed = [
        (number, line)
        for number, line in enumerate(env_example_lines(), start=1)
        if classify(line)[0] == "malformed"
    ]
    assert malformed == [], (
        ".env.example contient des lignes qui ne sont ni vides, ni des "
        f"commentaires, ni des assignations dotenv valides : {malformed}"
    )


def test_classifier_rejects_malformed_lines() -> None:
    """
    Protège le test précédent contre la vacuité.

    Un classificateur laxiste (qui rangerait l'inconnu en "comment") rendrait
    `test_every_line_is_blank_comment_or_valid_assignment` vert sans que le
    fichier soit correct. On épingle donc le comportement du classificateur sur
    la forme réellement rencontrée en v0.9.0 et sur ses voisines.
    """
    must_be_malformed = [
        "***REMOVED***",          # la forme exacte du défaut v0.9.0
        "ADMIN_BOOTSTRAP_KEY",    # clé sans '='
        "1BAD=x",                 # identifiant commençant par un chiffre
        "KEY WITH SPACE=x",       # espaces dans la clé
        "=orphan",                # valeur sans clé
        "export KEY=x",           # préfixe shell : pas du dotenv pur
        "KEY : x",                # séparateur YAML
        "CLÉ=x",                  # caractère non-ASCII dans la clé
        '"KEY"=x',                # clé entre guillemets
        "KEY =x",                 # espace avant le '='
    ]
    for line in must_be_malformed:
        assert classify(line)[0] == "malformed", (
            f"le classificateur accepte à tort la ligne malformée {line!r}"
        )

    must_be_valid = ["A=1", "_A=1", "KEY=", "KEY=a=b", "MCP_SERVER_PORT=8030"]
    for line in must_be_valid:
        assert classify(line)[0] == "assignment", (
            f"le classificateur rejette à tort l'assignation valide {line!r}"
        )

    assert classify("")[0] == "blank"
    assert classify("   ")[0] == "blank"
    assert classify("# commentaire")[0] == "comment"
    assert classify("   # commentaire indenté")[0] == "comment"


# ─────────────────────────────────────────────────────────────────────────────
# 3 & 4 — Le contrat documenté == le contrat consommé, dans les deux sens
# ─────────────────────────────────────────────────────────────────────────────

def test_settings_has_no_alias_and_no_env_prefix() -> None:
    """
    Prérequis des deux tests suivants : si `Settings` utilisait un alias ou un
    `env_prefix`, la correspondance « nom de champ en majuscules == nom de
    variable » serait fausse et les comparaisons de clés seraient invalides.
    """
    assert Settings.model_config.get("env_prefix", "") == ""
    aliased = [
        name for name, field in Settings.model_fields.items()
        if getattr(field, "alias", None) or getattr(field, "validation_alias", None)
    ]
    assert aliased == [], f"champs avec alias, la comparaison de clés est invalide : {aliased}"


def test_active_keys_are_all_settings_fields() -> None:
    """
    Copier `.env.example` en `.env` ne doit pas empêcher le démarrage.

    `Settings` est en `extra="forbid"` : une clé active absente de `Settings`
    lèverait `ValidationError` dès le chargement du fichier.
    """
    unknown = sorted(set(active_assignments()) - settings_env_names())
    assert unknown == [], (
        "clés actives de .env.example absentes de Settings — un .env copié "
        f"depuis l'exemple ferait échouer le démarrage (extra=forbid) : {unknown}"
    )


def test_all_settings_fields_are_documented() -> None:
    """
    RED sur v0.9.0 : `ADMIN_BOOTSTRAP_KEY` (détruite par la réécriture) et
    `MCP_SERVER_DEBUG` (jamais documentée) manquaient.

    Sans ce test, un champ ajouté à `Settings` sans entrée dans `.env.example`
    resterait invisible pour toute plateforme de déploiement.
    """
    documented = set(active_assignments()) | set(commented_declarations())
    undocumented = sorted(settings_env_names() - documented)
    assert undocumented == [], (
        "champs de Settings absents de .env.example — une plateforme ne peut "
        f"pas les découvrir : {undocumented}"
    )


def test_documented_keys_are_exactly_the_settings_contract() -> None:
    """
    Bijection stricte. Interdit les deux dérives : documenter une clé qui
    n'existe pas (piège `extra_forbidden`) et omettre un champ réel.
    """
    documented = set(active_assignments()) | set(commented_declarations())
    assert documented == settings_env_names(), {
        "documentées_en_trop": sorted(documented - settings_env_names()),
        "champs_manquants": sorted(settings_env_names() - documented),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 5 & 6 — La déclaration obligatoire, et l'absence des variables CLI-only
# ─────────────────────────────────────────────────────────────────────────────

def test_admin_bootstrap_key_is_declared_active_and_required() -> None:
    """
    Épingle la ligne littérale, pas seulement la présence de la clé.

    `ADMIN_BOOTSTRAP_KEY` doit être une assignation ACTIVE (une plateforme qui
    n'extrait que les lignes actives doit la voir) et porter le marqueur
    `REQUIRED` (le serveur n'a pas de défaut utilisable).
    """
    active = active_assignments()
    assert "ADMIN_BOOTSTRAP_KEY" in active, (
        "ADMIN_BOOTSTRAP_KEY doit être une assignation ACTIVE : c'est la seule "
        "variable sans défaut utilisable, une plateforme doit la voir"
    )
    assert active["ADMIN_BOOTSTRAP_KEY"] == _REQUIRED_MARKER, (
        f"attendu ADMIN_BOOTSTRAP_KEY={_REQUIRED_MARKER}, "
        f"trouvé {active['ADMIN_BOOTSTRAP_KEY']!r}"
    )
    assert "ADMIN_BOOTSTRAP_KEY" not in commented_declarations(), (
        "ADMIN_BOOTSTRAP_KEY ne doit pas aussi apparaître en déclaration "
        "commentée : deux déclarations rendraient l'extraction ambiguë"
    )


def test_required_marker_is_never_a_usable_key() -> None:
    """
    Le marqueur doit échouer la validation du serveur.

    C'est ce qui garantit qu'une plateforme livrant le contrat sans
    substitution obtient un refus de démarrage explicite, et non un vault de
    production chiffré avec une valeur publiée dans le dépôt.
    """
    is_valid, message = validate_bootstrap_key(_REQUIRED_MARKER)
    assert is_valid is False, (
        f"le marqueur {_REQUIRED_MARKER!r} passe la validation de la bootstrap "
        "key : il pourrait devenir une clé de chiffrement réelle"
    )
    assert "32" in message, (
        "le message de refus doit rester actionnable (longueur minimale citée), "
        f"trouvé : {message!r}"
    )


def test_cli_only_keys_are_absent_but_still_documented_elsewhere() -> None:
    """
    Les variables sensibles du CLI ne doivent apparaître sous AUCUNE forme
    d'assignation dans `.env.example` — ni active, ni commentée, ni en exemple
    d'usage dans la prose. Un extracteur qui les activerait produirait un `.env`
    refusé au démarrage, puisqu'elles ne sont pas des champs de `Settings`.

    Leur documentation doit rester accessible ailleurs : le test échoue aussi si
    elle a simplement disparu.
    """
    for key in _CLI_ONLY_KEYS:
        assert key not in settings_env_names(), (
            f"{key} est devenue un champ de Settings : ce test doit être revu"
        )

    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    for key in _CLI_ONLY_KEYS:
        assert f"{key}=" not in text, (
            f"{key}= apparaît dans .env.example : un extracteur pourrait "
            "l'activer et faire échouer le démarrage du serveur"
        )
        assert key in text, (
            f"{key} doit rester mentionné en prose dans .env.example pour que "
            "l'opérateur sache pourquoi elle n'y est pas déclarée"
        )

    cli_readme = (REPO_ROOT / "scripts" / "README.md").read_text(encoding="utf-8")
    for key in _CLI_ONLY_KEYS:
        assert key in cli_readme, (
            f"{key} n'est plus documentée dans scripts/README.md : la retirer de "
            ".env.example ne doit pas faire disparaître sa documentation"
        )


# ─────────────────────────────────────────────────────────────────────────────
# 7 — Aucune clé fantôme extractible depuis la prose
# ─────────────────────────────────────────────────────────────────────────────

def test_no_phantom_key_can_be_extracted_from_prose() -> None:
    """
    Une plateforme doit obtenir le MÊME jeu de clés quelle que soit la
    permissivité de son extracteur.

    En v0.9.0, de la prose comme `# Vide = validation JWT désactivée` ou
    `# true           = hard-reject ...` produisait les clés fantômes `Vide` et
    `true` pour un extracteur tolérant, et `(leeway=0)` / `ENFORCE=true`
    produisaient `leeway` et `ENFORCE` pour un extracteur naïf. Rendues avec une
    valeur non vide, ces clés font échouer le démarrage (`extra_forbidden`).

    PÉRIMÈTRE — ce test ne regarde que les clés INCONNUES. Une VRAIE clé citée en
    prose avec une valeur contradictoire lui échappe par construction : c'est le
    travail de `test_each_key_is_extractable_exactly_once_with_one_value`. Les deux
    sont nécessaires, et un sabotage qui réintroduit `MCP_AUTH_MODE=…` en prose doit
    faire rougir le second, pas celui-ci.
    """
    known = settings_env_names()
    tolerant_ghosts: dict[str, int] = {}
    naive_ghosts: dict[str, int] = {}

    for number, line in enumerate(env_example_lines(), start=1):
        category, _, _ = classify(line)
        if category != "comment":
            continue
        match = _TOLERANT_RE.match(line)
        if match and match.group(1) not in known:
            tolerant_ghosts.setdefault(match.group(1), number)
        for match in _NAIVE_RE.finditer(line):
            if match.group(1) not in known:
                naive_ghosts.setdefault(match.group(1), number)

    assert tolerant_ghosts == {}, (
        "prose lue comme une assignation par un extracteur tolérant "
        f"(clé -> ligne) : {tolerant_ghosts}"
    )
    assert naive_ghosts == {}, (
        "prose lue comme une assignation par un extracteur naïf "
        f"(clé -> ligne) : {naive_ghosts}"
    )


def _extractable_occurrences() -> dict[str, list[tuple[int, str]]]:
    """
    Toutes les occurrences d'une clé sous une forme qu'un extracteur pourrait
    prendre pour une assignation, quelle que soit sa permissivité : ligne active,
    déclaration commentée, ou **milieu de phrase**. Retourne clé -> [(ligne, valeur)].

    Le milieu de phrase est la partie que la première version de ce test
    manquait : `_TOLERANT_RE` est ancré en début de ligne, donc une prose comme
    « dès que MCP_AUTH_MODE=jwt/dual-stack » lui échappait.
    """
    found: dict[str, list[tuple[int, str]]] = {}
    for number, line in enumerate(env_example_lines(), start=1):
        category, key, value = classify(line)
        if category == "assignment":
            assert key is not None and value is not None
            found.setdefault(key, []).append((number, value))
            continue
        if category != "comment":
            continue
        for match in _NAIVE_RE.finditer(line):
            rest = line[match.end():]
            captured = rest.split()[0] if rest.split() else ""
            found.setdefault(match.group(1), []).append((number, captured))
    return found


def test_each_key_is_extractable_exactly_once_with_one_value() -> None:
    """
    Le contrat doit être déterministe en CLÉS **et en VALEURS**.

    Vérifier l'absence de clé fantôme ne suffit pas : en v0.9.0, de vraies clés
    apparaissaient aussi en milieu de phrase avec une valeur contradictoire —
    `ENFORCE_MISSION_TOKEN_VALIDATION=true` (L156, L217) alors que la déclaration
    documentée porte `false`, et `MCP_AUTH_MODE=jwt/dual-stack` (L177, L217) qui
    n'est même pas une valeur valide. Un extracteur « dernier gagnant » activait
    donc l'enforcement JWT au lieu du défaut, et retenait un mode invalide.

    Le jeu de clés restait pourtant correct, et les tests de fantômes restaient
    verts : ils ignorent par construction les clés connues. D'où ce test, qui
    exige une occurrence UNIQUE par clé.
    """
    duplicates = {
        key: occurrences
        for key, occurrences in _extractable_occurrences().items()
        if len(occurrences) > 1
    }
    assert duplicates == {}, (
        "clés extractibles plusieurs fois — la valeur retenue dépendrait de "
        f"l'ordre de lecture de l'extracteur (clé -> [(ligne, valeur)]) : {duplicates}"
    )


def test_every_extractable_key_is_a_settings_field() -> None:
    """
    Complément du test précédent, dans l'autre sens : toute clé extractible sous
    une forme quelconque — y compris en milieu de phrase — doit être un champ de
    `Settings`. Ce test et le précédent, pris ensemble, garantissent que les trois
    variantes d'extracteur (stricte, tolérante, naïve) renvoient exactement les
    mêmes 41 clés avec les mêmes valeurs.
    """
    unknown = sorted(set(_extractable_occurrences()) - settings_env_names())
    assert unknown == [], (
        "clés extractibles absentes de Settings — rendues avec une valeur non "
        f"vide, elles feraient échouer le démarrage : {unknown}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 8 — Aucune matière secrète
# ─────────────────────────────────────────────────────────────────────────────

def test_sensitive_keys_carry_only_placeholders() -> None:
    """Valeurs littérales épinglées : un vrai credential collé fait échouer le test."""
    active = active_assignments()
    for key, expected in _SENSITIVE_EXPECTED.items():
        assert key in active, f"{key} doit rester une assignation active du contrat"
        assert active[key] == expected, (
            f"{key} ne porte plus son placeholder attendu. Attendu {expected!r}, "
            f"trouvé une valeur de {len(active[key])} caractères. Si un secret "
            "réel a été commité, il doit être révoqué avant toute correction."
        )


def test_no_credential_shaped_token_anywhere_in_the_file() -> None:
    """
    Balayage de TOUT le fichier, commentaires inclus : un secret collé dans un
    exemple de prose est aussi grave que dans une assignation.
    """
    text = ENV_EXAMPLE.read_text(encoding="utf-8")

    for marker in _CREDENTIAL_MARKERS:
        assert marker not in text, (
            f"motif de credential {marker!r} présent dans .env.example"
        )

    suspicious: dict[int, int] = {}
    for number, line in enumerate(env_example_lines(), start=1):
        for match in _TOKEN_RE.finditer(_scannable_payload(line)):
            if _looks_like_a_credential(match.group(0)):
                suspicious[number] = len(match.group(0))
    assert suspicious == {}, (
        "tokens de forte entropie apparente (≥32 caractères mêlant majuscules, "
        f"minuscules et chiffres) — ligne -> longueur : {suspicious}"
    )


def test_the_credential_detector_actually_detects() -> None:
    """
    Protège le test précédent contre la vacuité — même logique que pour le
    classificateur.

    Le détecteur doit reconnaître une clé réelle et ignorer les placeholders du
    dépôt. Sans ce test, une heuristique cassée — par exemple un motif de token
    qui avale la ligne entière `CLÉ=valeur`, ou un seuil de longueur jamais
    atteint — laisserait passer un secret réel sans que rien ne devienne rouge.

    Le test épingle aussi la RÉPARTITION des deux mécanismes : l'heuristique
    d'entropie couvre les tokens à casse mixte, la liste de préfixes couvre les
    credentials à fournisseur identifiable. Une clé d'accès AWS est en majuscules
    et chiffres uniquement : elle échappe volontairement à l'heuristique et n'est
    attrapée que par le préfixe. Aucun des deux mécanismes ne suffit seul.
    """
    must_detect = [
        "kQ7mZp2Rt9Wx4Bv6Ny1Ld8Hs3Fj5Gc0Aq7Ue2Ik4Om6Pr",  # forme token_urlsafe(48)
        "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY123",      # forme clé secrète S3
        "a3f5c81e9b74d260af18e35c9d70b4a2"                # hex 32 : 2 classes
        "e6c19f83b52d47a0c8e13f96b7d24501",                # → hex 64, cas de revue
        "abcdefghijklmnopqrstuvwxyz0123456789abcdefgh",    # 44 car., casse unique
    ]
    for token in must_detect:
        assert _looks_like_a_credential(token), (
            f"le détecteur laisse passer un token de forme credential : {token[:16]}… "
            f"({len(token)} caractères)"
        )

    # Complémentarité : hors de portée de l'heuristique, dans le filet des préfixes.
    aws_key_id = "AKIAIOSFODNN7EXAMPLE"
    assert not _looks_like_a_credential(aws_key_id), (
        "cas de référence de la complémentarité : une clé d'accès AWS de 20 "
        "caractères est trop courte pour l'heuristique de forme"
    )
    assert any(aws_key_id.startswith(marker) for marker in _CREDENTIAL_MARKERS), (
        "une clé d'accès AWS doit être couverte par la liste de préfixes, "
        "puisque l'heuristique de forme ne la voit pas"
    )

    must_ignore = [
        "REQUIRED",
        "your_access_key_here",
        "your_secret_key_here",
        "change_me_in_production",
        "BASE64_URLSAFE_SANS_RETOUR_LIGNE",   # 32 car., mais 2 classes seulement
        "mcp-vault",
        "_storage",
        "vault.mcp.cloud-temple.app",
    ]
    for token in must_ignore:
        assert not _looks_like_a_credential(token), (
            f"le détecteur produit un faux positif sur le placeholder {token!r}"
        )

    # Le piège réel rencontré en écrivant ce test : la ligne entière ne doit
    # jamais être analysée d'un bloc, sinon la casse de la clé et celle de la
    # valeur se combinent en un faux positif systématique.
    assert _scannable_payload("S3_ACCESS_KEY_ID=your_access_key_here") == "your_access_key_here"
    assert not _looks_like_a_credential(
        _scannable_payload("S3_ACCESS_KEY_ID=your_access_key_here")
    )


# ─────────────────────────────────────────────────────────────────────────────
# 9 — Portabilité de l'encodage pour un parseur externe
# ─────────────────────────────────────────────────────────────────────────────

def test_file_encoding_is_portable() -> None:
    raw = ENV_EXAMPLE.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf"), "BOM UTF-8 présent"
    assert b"\r\n" not in raw, "fins de ligne CRLF présentes"
    assert b"\r" not in raw, "retour chariot isolé présent"
    assert b"\t" not in raw, "tabulation présente"
    assert raw.endswith(b"\n"), "newline finale absente"
    for number, line in enumerate(env_example_lines(), start=1):
        assert line == line.rstrip(), f"espaces en fin de ligne, ligne {number}"


# ─────────────────────────────────────────────────────────────────────────────
# 10 — Le contrat rendu est réellement chargeable par l'application
# ─────────────────────────────────────────────────────────────────────────────

def test_rendered_contract_loads_into_settings(tmp_path, monkeypatch) -> None:
    """
    Simule ce que fait une plateforme externe : rendre un `.env` à partir des
    seules assignations actives, en substituant le marqueur `REQUIRED`, puis
    charger la configuration.

    Le rendu part de la sortie du classificateur strict ET échoue si une ligne
    malformée subsiste — sinon supprimer la ligne 46 suffirait à rendre ce test
    vert. Ce test prouve la CHARGEABILITÉ du contrat ; la preuve de démarrage
    réel du service relève du test Docker (`/health`).
    """
    lines = env_example_lines()
    malformed = [n for n, line in enumerate(lines, start=1) if classify(line)[0] == "malformed"]
    assert malformed == [], f"contrat non rendable, lignes malformées : {malformed}"

    strong_key = "Qualif-Contrat-2026-" + "x7K9m2Pq4Rt8Wz3Nv6Ly1Hd5" + "!"
    assert validate_bootstrap_key(strong_key)[0] is True, "la clé de test doit être forte"

    rendered = []
    for line in lines:
        category, key, value = classify(line)
        if category != "assignment":
            continue
        assert key is not None and value is not None
        if value == _REQUIRED_MARKER:
            value = strong_key if key == "ADMIN_BOOTSTRAP_KEY" else "valeur-substituee"
        rendered.append(f"{key}={value}")

    assert any(line.startswith("ADMIN_BOOTSTRAP_KEY=") for line in rendered)

    # Les variables d'env du processus de test primeraient sur le fichier
    # (précédence pydantic-settings) et masqueraient ce qu'on veut mesurer.
    for name in settings_env_names():
        monkeypatch.delenv(name, raising=False)

    env_file = tmp_path / ".env"
    env_file.write_text("\n".join(rendered) + "\n", encoding="utf-8")

    settings = Settings(_env_file=str(env_file))

    assert settings.admin_bootstrap_key == strong_key
    assert validate_bootstrap_key(settings.admin_bootstrap_key)[0] is True
    assert settings.mcp_server_port == 8030


def test_unsubstituted_required_marker_is_refused_at_boot(tmp_path, monkeypatch) -> None:
    """
    Le pendant du test précédent : une plateforme qui livre le contrat SANS
    substituer le marqueur doit obtenir un refus explicite, pas un démarrage
    silencieux. On vérifie que le marqueur traverse bien `Settings` puis échoue
    au contrôle que `server.py` applique avant tout démarrage.
    """
    for name in settings_env_names():
        monkeypatch.delenv(name, raising=False)

    env_file = tmp_path / ".env"
    env_file.write_text(f"ADMIN_BOOTSTRAP_KEY={_REQUIRED_MARKER}\n", encoding="utf-8")

    settings = Settings(_env_file=str(env_file))
    assert settings.admin_bootstrap_key == _REQUIRED_MARKER

    is_valid, message = validate_bootstrap_key(settings.admin_bootstrap_key)
    assert is_valid is False
    assert "ADMIN_BOOTSTRAP_KEY" in message


def test_create_app_refuses_to_start_with_the_unsubstituted_marker() -> None:
    """
    Preuve sur le VRAI point d'entrée, pas seulement sur le validateur.

    Les tests précédents montrent que `validate_bootstrap_key("REQUIRED")` est
    False. Cela ne prouve pas que le service refuse effectivement de démarrer :
    il faut exercer le chemin de production. `create_app()` applique le même
    fail-fast que `main()` (`server.py`), et c'est lui que tout hébergeur ASGI
    appelle.

    Motif d'isolation repris de `tests/test_mission_jwt.py` : le singleton
    `settings` est muté puis restauré, `create_app()` doit lever `RuntimeError`.
    """
    from mcp_vault.server import create_app, settings

    saved = settings.admin_bootstrap_key
    try:
        object.__setattr__(settings, "admin_bootstrap_key", _REQUIRED_MARKER)
        with pytest.raises(RuntimeError) as excinfo:
            create_app()
        assert "ADMIN_BOOTSTRAP_KEY" in str(excinfo.value), (
            "le refus doit nommer la variable fautive pour être actionnable, "
            f"trouvé : {excinfo.value}"
        )
    finally:
        object.__setattr__(settings, "admin_bootstrap_key", saved)

    # Contre-épreuve : avec une clé forte substituée, ce fail-fast ne bloque plus.
    # Sans elle, le test passerait même si create_app() refusait TOUJOURS de
    # démarrer, pour n'importe quelle raison.
    strong = "Qualif-Contrat-2026-x7K9m2Pq4Rt8Wz3Nv6Ly1Hd5!"
    assert validate_bootstrap_key(strong)[0] is True
    try:
        object.__setattr__(settings, "admin_bootstrap_key", strong)
        create_app()
    finally:
        object.__setattr__(settings, "admin_bootstrap_key", saved)


def test_unknown_key_with_a_value_is_refused(tmp_path, monkeypatch) -> None:
    """
    Épingle le mécanisme qui justifie la bijection stricte du contrat.

    Prouve aussi la nuance mesurée pendant le diagnostic : seule une valeur NON
    VIDE déclenche `extra_forbidden`. C'est pour cela que `***REMOVED***` (valeur
    `None`) passait inaperçu, alors qu'un rendu `***REMOVED***=None` casse.
    """
    for name in settings_env_names():
        monkeypatch.delenv(name, raising=False)

    strong = "Qualif-Contrat-2026-x7K9m2Pq4Rt8Wz3Nv6Ly1Hd5!"

    with_value = tmp_path / ".env_with_value"
    with_value.write_text(
        f"ADMIN_BOOTSTRAP_KEY={strong}\nCLE_TOTALEMENT_INCONNUE=x\n", encoding="utf-8"
    )
    with pytest.raises(Exception) as excinfo:
        Settings(_env_file=str(with_value))
    assert "extra" in str(excinfo.value).lower() or "not permitted" in str(excinfo.value).lower()

    empty_value = tmp_path / ".env_empty_value"
    empty_value.write_text(
        f"ADMIN_BOOTSTRAP_KEY={strong}\nCLE_TOTALEMENT_INCONNUE=\n", encoding="utf-8"
    )
    Settings(_env_file=str(empty_value))  # ne lève pas : filtre de valeurs falsy


# ─────────────────────────────────────────────────────────────────────────────
# 11 — La documentation de déploiement ne réintroduit pas le défaut
# ─────────────────────────────────────────────────────────────────────────────

_SKIPPED_DIRS = (".git", "node_modules", ".venv", "venv", ".pytest_cache")

# Balises de bloc acceptées comme « bloc de configuration ». On n'inclut
# volontairement PAS `bash` / `sh` : ces blocs contiennent légitimement des
# invocations comme `VAULT_WRAP_TOKEN=hvs.… mcp-vault secret consume`, qui ne sont
# pas des déclarations de contrat. La limite est assumée : elle est compensée par
# `test_documentation_never_publishes_a_usable_bootstrap_key`, qui balaie TOUTES
# les lignes de TOUS les documents, quelle que soit la balise.
_ENV_FENCES = ("env", "dotenv", "ini", "properties")


def _is_foreign_design_doc(path: Path) -> bool:
    """
    `DESIGN/` héberge aussi les spécifications d'AUTRES services de la suite
    (live-mem, graph-mem, mcp-agent, mcp-mission, mcp-tools). Leurs blocs de
    configuration déclarent légitimement leurs propres variables
    (`LLMAAS_API_KEY`, `SMTP_PASSWORD`, `MCP_AGENT_URL`…), qui n'ont aucune raison
    d'être des champs du `Settings` de mcp-vault.

    Règle volontairement dérivée de l'arborescence, et non d'une liste de noms :
    est étranger tout document sous un `DESIGN/<service>/` dont `<service>` n'est
    pas `mcp-vault`. Un nouveau service ajouté à `DESIGN/` est donc exclu
    automatiquement, et un nouveau document mcp-vault couvert automatiquement —
    aucune liste à maintenir, donc rien qui pourrisse en silence.
    """
    parts = path.relative_to(REPO_ROOT).parts
    return len(parts) > 2 and parts[0] == "DESIGN" and parts[1] != "mcp-vault"


def markdown_files() -> list[Path]:
    """
    Documents Markdown décrivant CE service.

    Balayer l'arborescence — plutôt qu'une liste figée de fichiers — ferme le
    contournement relevé en revue : ajouter un nouveau document de déploiement
    hors d'une liste codée en dur échappait au contrôle.
    """
    return sorted(
        path
        for path in REPO_ROOT.rglob("*.md")
        if not any(part in _SKIPPED_DIRS for part in path.parts)
        and not _is_foreign_design_doc(path)
    )


def _env_blocks(text: str) -> list[list[str]]:
    """Blocs de code balisés comme de la configuration (cf. `_ENV_FENCES`)."""
    blocks: list[list[str]] = []
    current: list[str] | None = None
    for line in text.split("\n"):
        stripped = line.strip()
        if current is None and stripped.startswith("```"):
            if stripped[3:].strip().lower() in _ENV_FENCES:
                current = []
        elif current is not None and stripped == "```":
            blocks.append(current)
            current = None
        elif current is not None:
            current.append(line)
    return blocks


def test_documentation_env_blocks_declare_only_real_variables() -> None:
    """
    Même classe de défaut que la ligne 46, dans un autre fichier.

    `ARCHITECTURE.md` §9 publiait un bloc `.env` de 27 clés dont 9 inexistantes
    dans `Settings` (`OPENBAO_BINARY`, `S3_SYNC_STRATEGY`, `SSH_CA_ENABLED`…) :
    un opérateur qui le copiait obtenait un `.env` refusé au démarrage. Ce test
    empêche qu'un bloc de configuration de la documentation redérive.
    """
    known = settings_env_names()
    offenders: dict[str, list[str]] = {}
    blocks_seen = 0

    for path in markdown_files():
        for block in _env_blocks(path.read_text(encoding="utf-8")):
            blocks_seen += 1
            for line in block:
                category, key, _ = classify(line)
                if category == "assignment" and key not in known:
                    relative = path.relative_to(REPO_ROOT).as_posix()
                    offenders.setdefault(relative, []).append(key or "?")

    assert offenders == {}, (
        "blocs de configuration de la documentation déclarant des variables "
        "inexistantes dans Settings — un opérateur qui les copie ne peut pas "
        f"démarrer : {offenders}"
    )
    assert blocks_seen > 0, (
        "aucun bloc de configuration trouvé dans la documentation du dépôt : ce "
        "test ne garantit plus rien, vérifier _ENV_FENCES et markdown_files()"
    )


def test_documentation_never_publishes_a_usable_bootstrap_key() -> None:
    """
    `ARCHITECTURE.md:1659` proposait pour cette variable une valeur d'exemple de
    40 caractères qui PASSE `validate_bootstrap_key()`. Un opérateur qui copiait
    le bloc démarrait un vault de production dont la clé de chiffrement des clés
    unseal est publiée dans le dépôt : le fail-fast ne le protégeait pas.

    Toute valeur de bootstrap key publiée dans la documentation doit donc être
    REFUSÉE par le validateur. Le balayage porte sur TOUS les documents Markdown
    du dépôt et sur toutes leurs lignes, quelle que soit la balise de bloc — c'est
    le filet le plus large de ce fichier, et il compense la limite assumée de
    `_ENV_FENCES`.
    """
    published: dict[str, str] = {}
    for path in markdown_files():
        relative = path.relative_to(REPO_ROOT).as_posix()
        for number, line in enumerate(path.read_text(encoding="utf-8").split("\n"), start=1):
            match = re.search(r"ADMIN_BOOTSTRAP_KEY=(\S+)", line)
            if match:
                published[f"{relative}:{number}"] = match.group(1)

    usable = {
        where: len(value)
        for where, value in published.items()
        if validate_bootstrap_key(value.strip("`\"'"))[0]
    }
    assert usable == {}, (
        "la documentation publie une valeur de ADMIN_BOOTSTRAP_KEY qui passe la "
        f"validation — emplacement -> longueur : {usable}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 12 — Cohérence de version de la release
# ─────────────────────────────────────────────────────────────────────────────

def test_dockerignore_is_an_allowlist_covering_every_copied_path() -> None:
    """
    Le dépôt n'avait aucun `.dockerignore` : le service construit avec
    `context: .`, donc l'intégralité du répertoire — **`.env` réel inclus** —
    partait vers le démon Docker.

    Ce test verrouille la FORME de la protection, pas seulement sa présence. Une
    denylist doit énumérer ce qui est dangereux et laisse passer tout ce qu'elle
    n'a pas prévu (`id_rsa`, `.ssh/`, `.aws/credentials`, un secret sans
    extension) — constat de revue. Seule une allowlist est sûre par défaut.

    Il vérifie aussi la réciproque : chaque chemin réellement copié par le
    Dockerfile doit être ré-inclus, sinon le build casse. Les deux assertions
    ensemble empêchent la dérive dans les deux sens.
    """
    dockerignore = REPO_ROOT / ".dockerignore"
    assert dockerignore.exists(), ".dockerignore absent : le contexte de build n'est pas borné"

    lines = [
        line.strip()
        for line in dockerignore.read_text(encoding="utf-8").split("\n")
        if line.strip() and not line.strip().startswith("#")
    ]
    assert lines and lines[0] == "*", (
        "la première règle effective doit être `*` (tout exclure). Sans elle, le "
        f"fichier est une denylist et laisse passer l'imprévu. Trouvé : {lines[0]!r}"
    )

    reincluded = {line[1:].rstrip("/") for line in lines if line.startswith("!")}

    # Chemins que le Dockerfile copie, extraits du Dockerfile lui-même : la liste
    # ne peut donc pas se désynchroniser silencieusement.
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    copied: set[str] = set()
    for match in re.finditer(r"^COPY\s+(?!--from)(.+?)\s+\S+\s*$", dockerfile, re.M):
        for source in match.group(1).split():
            copied.add(source.rstrip("/"))

    assert copied, "aucune instruction COPY trouvée dans le Dockerfile : test à revoir"
    missing = sorted(source for source in copied if source not in reincluded)
    assert missing == [], (
        "chemins copiés par le Dockerfile mais non ré-inclus dans .dockerignore — "
        f"le build échouera : {missing}"
    )

    assert ".env" not in reincluded, ".env ne doit JAMAIS être ré-inclus dans le contexte"


def test_dockerfile_label_matches_version_file() -> None:
    """
    Le LABEL du Dockerfile est resté figé à 0.8.0 pendant sept versions : les
    métadonnées de l'image de production mentaient sur la version livrée.
    """
    version = (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    assert re.fullmatch(r"\d+\.\d+\.\d+", version), f"VERSION mal formé : {version!r}"

    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    labels = re.findall(r'version="([^"]+)"', dockerfile)
    assert labels, "aucun LABEL version trouvé dans le Dockerfile"
    assert set(labels) == {version}, (
        f"LABEL version du Dockerfile {labels} != VERSION {version!r}"
    )


def test_changelog_documents_the_current_version() -> None:
    """
    La CI de release extrait les notes du bloc `## [VERSION]` du CHANGELOG. Un
    en-tête absent ou mal formé produit des notes dégradées, en silence.
    """
    version = (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    header = f"## [{version}]"
    assert header in changelog, f"CHANGELOG.md n'a pas de section {header!r}"

    lines = changelog.split("\n")
    start = next(i for i, line in enumerate(lines) if line.startswith(header))
    body = []
    for line in lines[start + 1:]:
        if line.startswith("## ["):
            break
        body.append(line)
    assert any(line.strip() for line in body), (
        f"la section {header!r} du CHANGELOG est vide : les notes de release "
        "publiées seraient dégradées"
    )

# ── Estampilles de version des documents (reco revue #110/#121) ──────────────
# La dérive « docs restées à la version précédente » a été relevée DEUX fois en
# revue. Ce test lie mécaniquement les mentions de version COURANTE au fichier
# VERSION, pour qu'un oubli devienne rouge au lieu d'être trouvé en relecture.

def test_current_version_stamps_match_VERSION_file() -> None:
    import re as _re

    root = os.path.join(os.path.dirname(__file__), "..")
    version = open(os.path.join(root, "VERSION")).read().strip()

    checks = {
        "README.md": [r"\*\*Version\*\* : ([0-9.]+)"],
        "README.en.md": [r"\*\*Version\*\*: ([0-9.]+)"],
        "DESIGN/mcp-vault/ARCHITECTURE.md": [r"> \*\*Version\*\* : ([0-9.]+)"],
        "DESIGN/mcp-vault/TECHNICAL.md": [r"> \*\*Version\*\* : ([0-9.]+)"],
        "tests/TEST_CATALOG.md": [r"> \*\*Version\*\* : v?([0-9.]+)"],
    }
    for rel, patterns in checks.items():
        content = open(os.path.join(root, rel), encoding="utf-8").read()
        for pattern in patterns:
            found = _re.search(pattern, content)
            assert found, f"{rel} : estampille de version introuvable ({pattern})"
            assert found.group(1) == version, (
                f"{rel} annonce la version {found.group(1)} alors que VERSION "
                f"vaut {version} — aligner avant merge")
